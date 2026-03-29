package domain

import "errors"

var (
	ErrDuplicateCredential = errors.New("active credential already exists within deduplication window")

	ErrInvalidAuthCode = errors.New("invalid or expired authorization code")

	ErrIdPUnavailable = errors.New("identity provider unavailable")

	ErrInvalidClaims = errors.New("OIDC token missing required claims")

	ErrBitIndexExhausted = errors.New("no free revocation bit index available after max retries")

	ErrSignatureFailed = errors.New("credential signing failed")
)
