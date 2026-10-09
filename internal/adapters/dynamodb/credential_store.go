package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/ZeroVerify/issuer-lambda/internal/domain"
)

// issuanceLockSortKey is the sort key of the per-subject lock row. It lives in the credentials table so it needs no new
// resource. The row has no status attribute, so FindActiveBySubjectID never returns it, and free-lambda ignores its
// INSERT and non-TTL REMOVE stream events (a TTL REMOVE has no revocation_index and is skipped).
const issuanceLockSortKey = "LOCK#issuance"

// CredentialStore reads and writes the primary region only. The dedup check must see the latest write, and a
// replica in another region can lag it, so there is deliberately no local-region read client.
type CredentialStore struct {
	client    *dynamodb.Client
	tableName string
}

func NewCredentialStore(_ aws.Config, primaryCfg aws.Config, tableName string) *CredentialStore {
	return &CredentialStore{
		client:    dynamodb.NewFromConfig(primaryCfg),
		tableName: tableName,
	}
}

// AcquireIssuanceLock serialises issuance for one subject. Two simultaneous requests for the same person used to both
// pass the read-then-write duplicate check; with the lock only one proceeds and the other gets ErrDuplicateCredential.
// A lock whose expires_at has passed (a crashed Lambda) is taken over.
func (s *CredentialStore) AcquireIssuanceLock(ctx context.Context, subjectID, owner string, ttl time.Duration) error {
	now := time.Now()
	_, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item: map[string]types.AttributeValue{
			"subject_id":    &types.AttributeValueMemberS{Value: subjectID},
			"credential_id": &types.AttributeValueMemberS{Value: issuanceLockSortKey},
			"locked_by":     &types.AttributeValueMemberS{Value: owner},
			"expires_at":    &types.AttributeValueMemberN{Value: strconv.FormatInt(now.Add(ttl).Unix(), 10)},
		},
		ConditionExpression: aws.String("attribute_not_exists(subject_id) OR expires_at < :now"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":now": &types.AttributeValueMemberN{Value: strconv.FormatInt(now.Unix(), 10)},
		},
	})
	if err != nil {
		var ccfe *types.ConditionalCheckFailedException
		if errors.As(err, &ccfe) {
			return domain.ErrDuplicateCredential
		}
		return fmt.Errorf("acquiring issuance lock: %w", err)
	}
	return nil
}

// ReleaseIssuanceLock expires the lock if this owner still holds it. It updates instead of deleting because the issuer's
// IAM role has no dynamodb:DeleteItem; an expired lock is taken over by the next request and removed by the table TTL.
func (s *CredentialStore) ReleaseIssuanceLock(ctx context.Context, subjectID, owner string) error {
	_, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"subject_id":    &types.AttributeValueMemberS{Value: subjectID},
			"credential_id": &types.AttributeValueMemberS{Value: issuanceLockSortKey},
		},
		UpdateExpression:    aws.String("SET expires_at = :past"),
		ConditionExpression: aws.String("locked_by = :owner"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":owner": &types.AttributeValueMemberS{Value: owner},
			":past":  &types.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Add(-time.Second).Unix(), 10)},
		},
	})
	if err != nil {
		var ccfe *types.ConditionalCheckFailedException
		if errors.As(err, &ccfe) {
			return nil
		}
		return fmt.Errorf("releasing issuance lock: %w", err)
	}
	return nil
}

type credentialItem struct {
	SubjectID       string `dynamodbav:"subject_id"`
	CredentialID    string `dynamodbav:"credential_id"`
	CredentialType  string `dynamodbav:"credential_type"`
	IssuedAt        int64  `dynamodbav:"issued_at"`
	ExpiresAt       int64  `dynamodbav:"expires_at"`
	RevocationIndex int    `dynamodbav:"revocation_index"`
	Status          string `dynamodbav:"status"`
}

func (s *CredentialStore) FindActiveBySubjectID(
	ctx context.Context,
	subjectID string,
	issuedAfter time.Time,
) (*domain.CredentialRecord, error) {
	out, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		ConsistentRead:         aws.Bool(true),
		KeyConditionExpression: aws.String("subject_id = :sid"),
		FilterExpression:       aws.String("#st = :active AND expires_at > :now AND issued_at > :issuedAfter"),
		ExpressionAttributeNames: map[string]string{
			"#st": "status",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":sid":         &types.AttributeValueMemberS{Value: subjectID},
			":active":      &types.AttributeValueMemberS{Value: string(domain.StatusActive)},
			":now":         &types.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Unix(), 10)},
			":issuedAfter": &types.AttributeValueMemberN{Value: strconv.FormatInt(issuedAfter.Unix(), 10)},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("querying credentials for subject %q: %w", subjectID, err)
	}

	if len(out.Items) == 0 {
		return nil, nil
	}

	var ci credentialItem
	if err := attributevalue.UnmarshalMap(out.Items[0], &ci); err != nil {
		return nil, fmt.Errorf("unmarshalling credential item: %w", err)
	}

	return itemToRecord(ci), nil
}

func (s *CredentialStore) Insert(ctx context.Context, record *domain.CredentialRecord) error {
	item := credentialItem{
		SubjectID:       record.SubjectID,
		CredentialID:    record.CredentialID,
		CredentialType:  string(record.CredentialType),
		IssuedAt:        record.IssuedAt.Unix(),
		ExpiresAt:       record.ExpiresAt.Unix(),
		RevocationIndex: record.RevocationIndex,
		Status:          string(record.Status),
	}

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("marshalling credential record: %w", err)
	}

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item:      av,
	})
	if err != nil {
		return fmt.Errorf("inserting credential record: %w", err)
	}

	return nil
}

func itemToRecord(ci credentialItem) *domain.CredentialRecord {
	return &domain.CredentialRecord{
		SubjectID:       ci.SubjectID,
		CredentialID:    ci.CredentialID,
		CredentialType:  domain.CredentialType(ci.CredentialType),
		IssuedAt:        time.Unix(ci.IssuedAt, 0).UTC(),
		ExpiresAt:       time.Unix(ci.ExpiresAt, 0).UTC(),
		RevocationIndex: ci.RevocationIndex,
		Status:          domain.CredentialStatus(ci.Status),
	}
}
