package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	KeycloakTokenURL string
	KeycloakClientID string
	OAuthRedirectURI string

	AWSRegion     string
	PrimaryRegion string

	SecretNameHMACKey  string
	SecretNameEdDSAKey string

	CredentialsTable string
	BitIndicesTable  string

	CredentialTTLDays       int
	DeduplicationWindowDays int
	BitIndexMaxRetries      int
	IssuerDID               string
}

func Load() (*Config, error) {
	cfg := &Config{
		KeycloakTokenURL: os.Getenv("KEYCLOAK_TOKEN_URL"),
		KeycloakClientID: os.Getenv("KEYCLOAK_CLIENT_ID"),
		OAuthRedirectURI: os.Getenv("OAUTH_REDIRECT_URI"),

		AWSRegion:     getEnvWithDefault("AWS_REGION", "us-east-1"),
		PrimaryRegion: getEnvWithDefault("PRIMARY_REGION", "us-east-1"),

		SecretNameHMACKey:  os.Getenv("SECRET_NAME_HMAC_KEY"),
		SecretNameEdDSAKey: os.Getenv("SECRET_NAME_EDDSA_KEY"),

		CredentialsTable: os.Getenv("DYNAMODB_CREDENTIALS_TABLE"),
		BitIndicesTable:  os.Getenv("DYNAMODB_BIT_INDICES_TABLE"),

		IssuerDID: getEnvWithDefault("ISSUER_DID", "did:web:api.zeroverify.net"),

		CredentialTTLDays:       getEnvInt("CREDENTIAL_TTL_DAYS", 30),
		DeduplicationWindowDays: getEnvInt("DEDUP_WINDOW_DAYS", 14),
		BitIndexMaxRetries:      getEnvInt("BIT_INDEX_MAX_RETRIES", 5),
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) validate() error {
	required := map[string]string{
		"KEYCLOAK_TOKEN_URL":         c.KeycloakTokenURL,
		"KEYCLOAK_CLIENT_ID":         c.KeycloakClientID,
		"OAUTH_REDIRECT_URI":         c.OAuthRedirectURI,
		"SECRET_NAME_HMAC_KEY":       c.SecretNameHMACKey,
		"SECRET_NAME_EDDSA_KEY":      c.SecretNameEdDSAKey,
		"DYNAMODB_CREDENTIALS_TABLE": c.CredentialsTable,
		"DYNAMODB_BIT_INDICES_TABLE": c.BitIndicesTable,
	}
	for name, val := range required {
		if val == "" {
			return fmt.Errorf("required environment variable %s is not set", name)
		}
	}
	return nil
}

func getEnvWithDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultVal
}
