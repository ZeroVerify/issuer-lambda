package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/ZeroVerify/issuer-lambda/internal/domain"
)

type BitIndexStore struct {
	readClient  *dynamodb.Client
	writeClient *dynamodb.Client
	tableName   string
}

func NewBitIndexStore(localCfg, primaryCfg aws.Config, tableName string) *BitIndexStore {
	return &BitIndexStore{
		readClient:  dynamodb.NewFromConfig(localCfg),
		writeClient: dynamodb.NewFromConfig(primaryCfg),
		tableName:   tableName,
	}
}

type bitIndexItem struct {
	BitIndex     int    `dynamodbav:"bit_index"`
	Status       string `dynamodbav:"status"`
	CredentialID string `dynamodbav:"credential_id"`
	ClaimedAt    string `dynamodbav:"claimed_at"`
	Version      int    `dynamodbav:"version"`
}

func (s *BitIndexStore) ClaimFreeIndex(ctx context.Context, credentialID string, maxRetries int) (int, error) {
	freeBits, err := s.scanFreeBits(ctx)
	if err != nil {
		return 0, err
	}

	for attempt := 0; attempt < maxRetries && len(freeBits) > 0; attempt++ {
		candidate := freeBits[rand.Intn(len(freeBits))]

		claimed, err := s.tryClaimBit(ctx, candidate, credentialID)
		if err != nil {
			return 0, err
		}
		if claimed {
			return candidate.BitIndex, nil
		}

		freeBits = removeBit(freeBits, candidate.BitIndex)
		if len(freeBits) == 0 {
			freeBits, err = s.scanFreeBits(ctx)
			if err != nil {
				return 0, err
			}
		}
	}

	newIndex, err := s.appendAndClaimNewBit(ctx, credentialID)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", domain.ErrBitIndexExhausted, err)
	}
	return newIndex, nil
}

func (s *BitIndexStore) scanFreeBits(ctx context.Context) ([]bitIndexItem, error) {
	out, err := s.readClient.Scan(ctx, &dynamodb.ScanInput{
		TableName:        aws.String(s.tableName),
		FilterExpression: aws.String("#st = :free"),
		Limit:            aws.Int32(100),
		ExpressionAttributeNames: map[string]string{
			"#st": "status",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":free": &types.AttributeValueMemberS{Value: string(domain.BitFree)},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("scanning free bit indices: %w", err)
	}

	items := make([]bitIndexItem, 0, len(out.Items))
	for _, item := range out.Items {
		var bi bitIndexItem
		if err := unmarshalBitItem(item, &bi); err != nil {
			continue
		}
		items = append(items, bi)
	}
	return items, nil
}

func (s *BitIndexStore) tryClaimBit(ctx context.Context, item bitIndexItem, credentialID string) (bool, error) {
	_, err := s.writeClient.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"bit_index": &types.AttributeValueMemberN{Value: strconv.Itoa(item.BitIndex)},
		},
		ConditionExpression: aws.String("#st = :free AND version = :v"),
		UpdateExpression:    aws.String("SET #st = :claimed, credential_id = :cid, claimed_at = :ts, version = :newv"),
		ExpressionAttributeNames: map[string]string{
			"#st": "status",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":free":    &types.AttributeValueMemberS{Value: string(domain.BitFree)},
			":claimed": &types.AttributeValueMemberS{Value: string(domain.BitClaimed)},
			":v":       &types.AttributeValueMemberN{Value: strconv.Itoa(item.Version)},
			":cid":     &types.AttributeValueMemberS{Value: credentialID},
			":ts":      &types.AttributeValueMemberS{Value: time.Now().UTC().Format(time.RFC3339)},
			":newv":    &types.AttributeValueMemberN{Value: strconv.Itoa(item.Version + 1)},
		},
	})
	if err != nil {
		var ccfe *types.ConditionalCheckFailedException
		if errors.As(err, &ccfe) {
			return false, nil
		}
		return false, fmt.Errorf("claiming bit index %d: %w", item.BitIndex, err)
	}
	return true, nil
}

func (s *BitIndexStore) appendAndClaimNewBit(ctx context.Context, credentialID string) (int, error) {
	maxIndex, err := s.findMaxBitIndex(ctx)
	if err != nil {
		return 0, err
	}
	newIndex := maxIndex + 1

	_, err = s.writeClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item: map[string]types.AttributeValue{
			"bit_index":     &types.AttributeValueMemberN{Value: strconv.Itoa(newIndex)},
			"status":        &types.AttributeValueMemberS{Value: string(domain.BitClaimed)},
			"credential_id": &types.AttributeValueMemberS{Value: credentialID},
			"claimed_at":    &types.AttributeValueMemberS{Value: time.Now().UTC().Format(time.RFC3339)},
			"version":       &types.AttributeValueMemberN{Value: "1"},
		},
		ConditionExpression: aws.String("attribute_not_exists(bit_index)"),
	})
	if err != nil {
		var ccfe *types.ConditionalCheckFailedException
		if errors.As(err, &ccfe) {
			return s.appendAndClaimNewBit(ctx, credentialID)
		}
		return 0, fmt.Errorf("inserting new bit index %d: %w", newIndex, err)
	}
	return newIndex, nil
}

func (s *BitIndexStore) findMaxBitIndex(ctx context.Context) (int, error) {
	out, err := s.readClient.Scan(ctx, &dynamodb.ScanInput{
		TableName:            aws.String(s.tableName),
		ProjectionExpression: aws.String("bit_index"),
	})
	if err != nil {
		return 0, fmt.Errorf("scanning bit indices for max: %w", err)
	}

	max := -1
	for _, item := range out.Items {
		if v, ok := item["bit_index"].(*types.AttributeValueMemberN); ok {
			n, err := strconv.Atoi(v.Value)
			if err == nil && n > max {
				max = n
			}
		}
	}
	return max, nil
}

func unmarshalBitItem(item map[string]types.AttributeValue, out *bitIndexItem) error {
	if v, ok := item["bit_index"].(*types.AttributeValueMemberN); ok {
		n, err := strconv.Atoi(v.Value)
		if err != nil {
			return err
		}
		out.BitIndex = n
	}
	if v, ok := item["status"].(*types.AttributeValueMemberS); ok {
		out.Status = v.Value
	}
	if v, ok := item["credential_id"].(*types.AttributeValueMemberS); ok {
		out.CredentialID = v.Value
	}
	if v, ok := item["claimed_at"].(*types.AttributeValueMemberS); ok {
		out.ClaimedAt = v.Value
	}
	if v, ok := item["version"].(*types.AttributeValueMemberN); ok {
		n, _ := strconv.Atoi(v.Value)
		out.Version = n
	}
	return nil
}

func removeBit(items []bitIndexItem, index int) []bitIndexItem {
	result := make([]bitIndexItem, 0, len(items)-1)
	for _, item := range items {
		if item.BitIndex != index {
			result = append(result, item)
		}
	}
	return result
}
