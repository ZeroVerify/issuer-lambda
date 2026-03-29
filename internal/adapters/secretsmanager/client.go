package secretsmanager

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type Client struct {
	sm           *secretsmanager.Client
	hmacKeyName  string
	eddsaKeyName string

	mu       sync.Mutex
	hmacKey  []byte
	eddsaKey []byte
}

func New(cfg aws.Config, hmacKeyName, eddsaKeyName string) *Client {
	return &Client{
		sm:           secretsmanager.NewFromConfig(cfg),
		hmacKeyName:  hmacKeyName,
		eddsaKeyName: eddsaKeyName,
	}
}

func (c *Client) GetHMACKey(ctx context.Context) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.hmacKey != nil {
		return c.hmacKey, nil
	}

	key, err := c.fetchSecret(ctx, c.hmacKeyName)
	if err != nil {
		return nil, err
	}
	c.hmacKey = key
	return key, nil
}

func (c *Client) GetEdDSAPrivateKey(ctx context.Context) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.eddsaKey != nil {
		return c.eddsaKey, nil
	}

	key, err := c.fetchSecret(ctx, c.eddsaKeyName)
	if err != nil {
		return nil, err
	}
	c.eddsaKey = key
	return key, nil
}

func (c *Client) fetchSecret(ctx context.Context, name string) ([]byte, error) {
	out, err := c.sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(name),
	})
	if err != nil {
		return nil, fmt.Errorf("fetching secret %q: %w", name, err)
	}
	if out.SecretBinary != nil {
		return out.SecretBinary, nil
	}
	if out.SecretString != nil {
		return []byte(*out.SecretString), nil
	}
	return nil, fmt.Errorf("secret %q has no value", name)
}
