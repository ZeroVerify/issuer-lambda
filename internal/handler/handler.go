package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/aws/aws-lambda-go/events"

	"github.com/ZeroVerify/issuer-lambda/internal/domain"
	"github.com/ZeroVerify/issuer-lambda/internal/models"
	"github.com/ZeroVerify/issuer-lambda/internal/service"
)

type Handler struct {
	svc *service.CredentialService
}

func New(svc *service.CredentialService) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) Handle(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	if req.HTTPMethod != http.MethodPost || req.Path != "/api/v1/credentials/issue" {
		return errResponse(http.StatusNotFound, "not_found", "endpoint not found"), nil
	}

	var body models.IssueCredentialRequest
	if err := json.Unmarshal([]byte(req.Body), &body); err != nil {
		return errResponse(http.StatusBadRequest, "invalid_request", "request body is not valid JSON"), nil
	}

	if body.AuthorizationCode == "" || body.CodeVerifier == "" {
		return errResponse(http.StatusBadRequest, "invalid_request", "authorization_code and code_verifier are required"), nil
	}

	vc, err := h.svc.IssueCredential(ctx, body.AuthorizationCode, body.CodeVerifier)
	if err != nil {
		return h.mapError(err), nil
	}

	return jsonResponse(http.StatusCreated, models.IssueCredentialResponse{Credential: vc}), nil
}

func (h *Handler) mapError(err error) events.APIGatewayProxyResponse {
	switch {
	case errors.Is(err, domain.ErrDuplicateCredential):
		return errResponse(http.StatusConflict, "duplicate_credential",
			"an active credential was issued recently, please wait before requesting a new one")
	case errors.Is(err, domain.ErrInvalidAuthCode):
		return errResponse(http.StatusUnauthorized, "invalid_auth_code",
			"authentication failed, please try again")
	case errors.Is(err, domain.ErrInvalidClaims):
		return errResponse(http.StatusBadRequest, "invalid_claims",
			"identity provider did not return required attributes")
	case errors.Is(err, domain.ErrIdPUnavailable):
		return errResponse(http.StatusServiceUnavailable, "idp_unavailable",
			"university login service unavailable, try again later")
	case errors.Is(err, domain.ErrBitIndexExhausted):
		return errResponse(http.StatusServiceUnavailable, "service_unavailable",
			"credential issuance temporarily unavailable, try again later")
	default:
		return errResponse(http.StatusInternalServerError, "internal_error",
			"an unexpected error occurred")
	}
}

func jsonResponse(statusCode int, body any) events.APIGatewayProxyResponse {
	b, _ := json.Marshal(body)
	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(b),
	}
}

func errResponse(statusCode int, errCode, message string) events.APIGatewayProxyResponse {
	return jsonResponse(statusCode, models.ErrorResponse{
		Error:   errCode,
		Message: message,
	})
}
