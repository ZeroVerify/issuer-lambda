package service

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/ZeroVerify/issuer-lambda/internal/adapters/dynamodb"
	"github.com/ZeroVerify/issuer-lambda/internal/adapters/keycloak"
	"github.com/ZeroVerify/issuer-lambda/internal/adapters/secretsmanager"
	"github.com/ZeroVerify/issuer-lambda/internal/config"
	"github.com/ZeroVerify/issuer-lambda/internal/domain"
)

type CredentialService struct {
	oidc    *keycloak.Client
	secrets *secretsmanager.Client
	creds   *dynamodb.CredentialStore
	bits    *dynamodb.BitIndexStore
	cfg     *config.Config
}

func New(
	oidc *keycloak.Client,
	secrets *secretsmanager.Client,
	creds *dynamodb.CredentialStore,
	bits *dynamodb.BitIndexStore,
	cfg *config.Config,
) *CredentialService {
	return &CredentialService{
		oidc:    oidc,
		secrets: secrets,
		creds:   creds,
		bits:    bits,
		cfg:     cfg,
	}
}

func (s *CredentialService) IssueCredential(
	ctx context.Context,
	code, codeVerifier string,
) (*domain.VerifiableCredential, error) {
	token, err := s.oidc.ExchangeCode(ctx, code, codeVerifier)
	if err != nil {
		return nil, err
	}

	if token.Username == "" || token.IdPID == "" || token.EnrollmentStatus == "" {
		return nil, domain.ErrInvalidClaims
	}

	hmacKey, err := s.secrets.GetHMACKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching HMAC key: %w", err)
	}
	subjectID := domain.ComputePseudonymousSubjectID(token.IdPID, token.Username, hmacKey)

	dedupWindow := time.Duration(s.cfg.DeduplicationWindowDays) * 24 * time.Hour
	existing, err := s.creds.FindActiveBySubjectID(ctx, subjectID, time.Now().Add(-dedupWindow))
	if err != nil {
		return nil, fmt.Errorf("checking existing credentials: %w", err)
	}
	if existing != nil {
		return nil, domain.ErrDuplicateCredential
	}

	privKeyBytes, err := s.secrets.GetEdDSAPrivateKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching EdDSA key: %w", err)
	}
	signer, err := domain.NewBabyJubJubSigner(privKeyBytes)
	if err != nil {
		return nil, err
	}

	credentialID := uuid.New().String()
	revocationIndex, err := s.bits.ClaimFreeIndex(ctx, credentialID, s.cfg.BitIndexMaxRetries)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	expiresAt := now.AddDate(0, 0, s.cfg.CredentialTTLDays)

	vc, err := buildCredential(credentialID, s.cfg.IssuerDID, subjectID, token, revocationIndex, signer, now, expiresAt)
	if err != nil {
		return nil, err
	}

	record := &domain.CredentialRecord{
		SubjectID:       subjectID,
		CredentialID:    credentialID,
		CredentialType:  domain.StudentCredential,
		IssuedAt:        now,
		ExpiresAt:       expiresAt,
		RevocationIndex: revocationIndex,
		Status:          domain.StatusActive,
	}
	if err := s.creds.Insert(ctx, record); err != nil {
		return nil, fmt.Errorf("persisting credential metadata: %w", err)
	}

	return vc, nil
}

func buildCredential(
	credentialID, issuerDID, subjectID string,
	token *domain.OIDCToken,
	revocationIndex int,
	signer *domain.BabyJubJubSigner,
	issuedAt, expiresAt time.Time,
) (*domain.VerifiableCredential, error) {
	fields := map[string]string{
		"given_name":        token.GivenName,
		"family_name":       token.FamilyName,
		"email":             token.Email,
		"enrollment_status": token.EnrollmentStatus,
	}

	fieldSigs := make(map[string]string, len(fields))
	for name, value := range fields {
		sig, err := signer.SignField(value)
		if err != nil {
			return nil, fmt.Errorf("signing field %q: %w", name, err)
		}
		fieldSigs[name] = sig
	}

	bitstringBase := "https://s3.amazonaws.com/zeroverify-metadata/bitstring/v1/bitstring.gz"

	vc := &domain.VerifiableCredential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
		},
		ID:             fmt.Sprintf("urn:uuid:%s", credentialID),
		Type:           []string{"VerifiableCredential", "StudentCredential"},
		Issuer:         issuerDID,
		IssuanceDate:   issuedAt.Format(time.RFC3339),
		ExpirationDate: expiresAt.Format(time.RFC3339),
		CredentialSubject: domain.CredentialSubject{
			ID:               subjectID,
			GivenName:        token.GivenName,
			FamilyName:       token.FamilyName,
			Email:            token.Email,
			EnrollmentStatus: token.EnrollmentStatus,
		},
		CredentialStatus: domain.StatusEntry{
			ID:                   fmt.Sprintf("%s#%s", bitstringBase, strconv.Itoa(revocationIndex)),
			Type:                 "BitstringStatusListEntry",
			StatusListIndex:      strconv.Itoa(revocationIndex),
			StatusListCredential: bitstringBase,
		},
		Proof: domain.Proof{
			Type:               "BabyJubJubSignature2024",
			Created:            issuedAt.Format(time.RFC3339),
			VerificationMethod: fmt.Sprintf("%s#babyjubjub-key-1", issuerDID),
			ProofPurpose:       "assertionMethod",
			FieldSignatures:    fieldSigs,
		},
	}

	return vc, nil
}
