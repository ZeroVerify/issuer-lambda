package models

import "github.com/ZeroVerify/issuer-lambda/internal/domain"

type IssueCredentialResponse struct {
	Credential *domain.VerifiableCredential `json:"credential"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
