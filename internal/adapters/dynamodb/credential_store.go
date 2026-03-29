package dynamodb

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/ZeroVerify/issuer-lambda/internal/domain"
)

type CredentialStore struct {
	readClient  *dynamodb.Client
	writeClient *dynamodb.Client
	tableName   string
}

func NewCredentialStore(localCfg, primaryCfg aws.Config, tableName string) *CredentialStore {
	return &CredentialStore{
		readClient:  dynamodb.NewFromConfig(localCfg),
		writeClient: dynamodb.NewFromConfig(primaryCfg),
		tableName:   tableName,
	}
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
	out, err := s.readClient.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		KeyConditionExpression: aws.String("subject_id = :sid"),
		FilterExpression: aws.String("#st = :active AND expires_at > :now AND issued_at > :issuedAfter"),
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

	_, err = s.writeClient.PutItem(ctx, &dynamodb.PutItemInput{
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
