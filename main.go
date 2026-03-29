package main

import (
	"context"
	"log"

	"github.com/aws/aws-lambda-go/lambda"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/ZeroVerify/issuer-lambda/internal/adapters/dynamodb"
	"github.com/ZeroVerify/issuer-lambda/internal/adapters/keycloak"
	"github.com/ZeroVerify/issuer-lambda/internal/adapters/secretsmanager"
	"github.com/ZeroVerify/issuer-lambda/internal/config"
	"github.com/ZeroVerify/issuer-lambda/internal/handler"
	"github.com/ZeroVerify/issuer-lambda/internal/service"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	ctx := context.Background()

	localAwsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.AWSRegion),
	)
	if err != nil {
		log.Fatalf("loading local AWS config: %v", err)
	}

	primaryAwsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.PrimaryRegion),
	)
	if err != nil {
		log.Fatalf("loading primary AWS config: %v", err)
	}

	oidcClient := keycloak.New(cfg.KeycloakTokenURL, cfg.KeycloakClientID, cfg.OAuthRedirectURI)
	secretsClient := secretsmanager.New(localAwsCfg, cfg.SecretNameHMACKey, cfg.SecretNameEdDSAKey)
	credStore := dynamodb.NewCredentialStore(localAwsCfg, primaryAwsCfg, cfg.CredentialsTable)
	bitIndexStore := dynamodb.NewBitIndexStore(localAwsCfg, primaryAwsCfg, cfg.BitIndicesTable)

	svc := service.New(oidcClient, secretsClient, credStore, bitIndexStore, cfg)

	lambda.Start(handler.New(svc).Handle)
}
