package domain

import "time"

type CredentialType string

const (
	StudentCredential    CredentialType = "StudentCredential"
	EmploymentCredential CredentialType = "EmploymentCredential"
	AgeCredential        CredentialType = "AgeCredential"
)

type CredentialStatus string

const (
	StatusActive  CredentialStatus = "ACTIVE"
	StatusRevoked CredentialStatus = "REVOKED"
)

type BitIndexStatus string

const (
	BitFree    BitIndexStatus = "FREE"
	BitClaimed BitIndexStatus = "CLAIMED"
	BitRevoked BitIndexStatus = "REVOKED"
)

type CredentialRecord struct {
	SubjectID       string
	CredentialID    string
	CredentialType  CredentialType
	IssuedAt        time.Time
	ExpiresAt       time.Time
	RevocationIndex int
	Status          CredentialStatus
}

type VerifiableCredential struct {
	Context           []string          `json:"@context"`
	ID                string            `json:"id"`
	Type              []string          `json:"type"`
	Issuer            string            `json:"issuer"`
	IssuanceDate      string            `json:"issuanceDate"`
	ExpirationDate    string            `json:"expirationDate"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
	CredentialStatus  StatusEntry       `json:"credentialStatus"`
	Proof             Proof             `json:"proof"`
}

type CredentialSubject struct {
	ID               string `json:"id"`
	GivenName        string `json:"given_name"`
	FamilyName       string `json:"family_name"`
	Email            string `json:"email"`
	EnrollmentStatus string `json:"enrollment_status"`
}

type StatusEntry struct {
	ID                   string `json:"id"`
	Type                 string `json:"type"`
	StatusListIndex      string `json:"statusListIndex"`
	StatusListCredential string `json:"statusListCredential"`
}

type Proof struct {
	Type               string            `json:"type"`
	Created            string            `json:"created"`
	VerificationMethod string            `json:"verificationMethod"`
	ProofPurpose       string            `json:"proofPurpose"`
	FieldSignatures    map[string]string `json:"fieldSignatures"`
}
