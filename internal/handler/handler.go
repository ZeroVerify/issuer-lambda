package handler

import (
	"context"

	"github.com/aws/aws-lambda-go/events"
)

type Handler struct {
}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) Handle(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       `{"message": "Hello from handler"}`,
	}, nil
}
