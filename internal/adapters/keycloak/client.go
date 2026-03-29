package keycloak

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ZeroVerify/issuer-lambda/internal/domain"
)

type Client struct {
	tokenURL    string
	clientID    string
	redirectURI string
	http        *http.Client
}

func New(tokenURL, clientID, redirectURI string) *Client {
	return &Client{
		tokenURL:    tokenURL,
		clientID:    clientID,
		redirectURI: redirectURI,
		http:        &http.Client{Timeout: 10 * time.Second},
	}
}

type tokenResponse struct {
	IDToken   string `json:"id_token"`
	Error     string `json:"error"`
	ErrorDesc string `json:"error_description"`
}

type idTokenClaims struct {
	PreferredUsername string `json:"preferred_username"`
	IdentityProvider  string `json:"identity_provider"`
	Email             string `json:"email"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	CustomClaims      struct {
		EnrollmentStatus string `json:"enrollment_status"`
	} `json:"custom_claims"`
}

func (c *Client) ExchangeCode(ctx context.Context, code, codeVerifier string) (*domain.OIDCToken, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.redirectURI},
		"client_id":     {c.clientID},
		"code_verifier": {codeVerifier},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building keycloak request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrIdPUnavailable, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading keycloak response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusBadRequest:
		var tr tokenResponse
		_ = json.Unmarshal(body, &tr)
		if tr.Error == "invalid_grant" {
			return nil, domain.ErrInvalidAuthCode
		}
		return nil, fmt.Errorf("%w: %s", domain.ErrInvalidAuthCode, tr.ErrorDesc)
	default:
		return nil, fmt.Errorf("%w: keycloak returned status %d", domain.ErrIdPUnavailable, resp.StatusCode)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("parsing keycloak token response: %w", err)
	}

	claims, err := decodeIDTokenPayload(tr.IDToken)
	if err != nil {
		return nil, fmt.Errorf("decoding id token: %w", err)
	}

	return &domain.OIDCToken{
		Username:         claims.PreferredUsername,
		IdPID:            claims.IdentityProvider,
		Email:            claims.Email,
		GivenName:        claims.GivenName,
		FamilyName:       claims.FamilyName,
		EnrollmentStatus: claims.CustomClaims.EnrollmentStatus,
	}, nil
}

func decodeIDTokenPayload(idToken string) (*idTokenClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWT: expected 3 parts, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("base64-decoding JWT payload: %w", err)
	}

	var claims idTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing JWT claims: %w", err)
	}

	if claims.PreferredUsername == "" {
		return nil, fmt.Errorf("JWT missing required claim: sub")
	}

	return &claims, nil
}
