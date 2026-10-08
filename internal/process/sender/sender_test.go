package sender_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"vpsmonitoring-agent/internal/process/models"
	"vpsmonitoring-agent/internal/process/sender"
)

// mockHTTPClient simulates the backend process ingestion endpoint
type mockHTTPClient struct {
	statusCode int
	err        error
	response   sender.Response

	// Captures for verification
	lastEndpoint    string
	lastBearerToken string
	lastReqBody     models.ProcessPayload
}

func (m *mockHTTPClient) PostJSON(ctx context.Context, endpoint string, bearerToken string, reqBody any, respBody any) (int, error) {
	m.lastEndpoint = endpoint
	m.lastBearerToken = bearerToken

	if reqBody != nil {
		if payload, ok := reqBody.(models.ProcessPayload); ok {
			m.lastReqBody = payload
		}
	}

	if m.err != nil {
		return 0, m.err
	}

	if respBody != nil {
		// Simulate decoding the response body by marshaling and unmarshaling
		b, _ := json.Marshal(m.response)
		_ = json.Unmarshal(b, respBody)
	}

	return m.statusCode, nil
}

// mockCollector provides a deterministic process snapshot for testing
type mockCollector struct {
	snapshot models.ProcessPayload
}

func (m *mockCollector) Collect(ctx context.Context, totalMemBytes uint64) models.ProcessPayload {
	return m.snapshot
}

func validSnapshot() models.ProcessPayload {
	return models.ProcessPayload{
		CollectedAt: time.Now().UTC(),
		Processes: []models.ProcessSnapshot{
			{PID: 1, Name: "init"},
		},
	}
}

// TEST 1 — Successful collection + POST (HTTP 202)
func TestClient_Send_Success(t *testing.T) {
	mockClient := &mockHTTPClient{
		statusCode: http.StatusAccepted,
		response: sender.Response{
			Data: &struct {
				Received int `json:"received"`
			}{Received: 1},
		},
	}
	mockCol := &mockCollector{snapshot: validSnapshot()}

	client := sender.NewClient(mockClient, mockCol)
	resp, err := client.Send(context.Background(), "agent-123", "secret", 1024)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Data == nil || resp.Data.Received != 1 {
		t.Errorf("expected received=1, got %+v", resp.Data)
	}
	if mockClient.lastEndpoint != "/api/v1/agents/agent-123/processes" {
		t.Errorf("unexpected endpoint: %s", mockClient.lastEndpoint)
	}
	if mockClient.lastBearerToken != "secret" {
		t.Errorf("unexpected token: %s", mockClient.lastBearerToken)
	}
	if len(mockClient.lastReqBody.Processes) != 1 {
		t.Errorf("expected 1 process in request body")
	}
}

// TEST 2 — HTTP 400 Validation Error
func TestClient_Send_BadRequest(t *testing.T) {
	mockClient := &mockHTTPClient{
		statusCode: http.StatusBadRequest,
	}
	mockClient.response.Error = &struct {
		Message string `json:"message"`
	}{Message: "invalid snapshot"}

	mockCol := &mockCollector{snapshot: validSnapshot()}
	client := sender.NewClient(mockClient, mockCol)
	_, err := client.Send(context.Background(), "agent-123", "secret", 1024)

	if !errors.Is(err, sender.ErrInvalidPayload) {
		t.Errorf("expected ErrInvalidPayload, got %v", err)
	}
}

// TEST 3 — HTTP 401 Unauthorized
func TestClient_Send_Unauthorized(t *testing.T) {
	mockClient := &mockHTTPClient{
		statusCode: http.StatusUnauthorized,
	}
	mockCol := &mockCollector{snapshot: validSnapshot()}
	client := sender.NewClient(mockClient, mockCol)
	_, err := client.Send(context.Background(), "agent-123", "secret", 1024)

	if !errors.Is(err, sender.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized, got %v", err)
	}
}

// TEST 4 — HTTP 413 Payload Too Large
func TestClient_Send_PayloadTooLarge(t *testing.T) {
	mockClient := &mockHTTPClient{
		statusCode: http.StatusRequestEntityTooLarge,
	}
	mockCol := &mockCollector{snapshot: validSnapshot()}
	client := sender.NewClient(mockClient, mockCol)
	_, err := client.Send(context.Background(), "agent-123", "secret", 1024)

	if !errors.Is(err, sender.ErrPayloadTooLarge) {
		t.Errorf("expected ErrPayloadTooLarge, got %v", err)
	}
}

// TEST 5 — Missing credentials
func TestClient_Send_MissingCredentials(t *testing.T) {
	mockClient := &mockHTTPClient{}
	mockCol := &mockCollector{snapshot: validSnapshot()}
	client := sender.NewClient(mockClient, mockCol)

	_, err := client.Send(context.Background(), "agent-123", "", 1024)
	if err == nil || err.Error() != "missing agent credential" {
		t.Errorf("expected missing credential error, got %v", err)
	}

	_, err = client.Send(context.Background(), "", "secret", 1024)
	if err == nil || err.Error() != "missing agent ID" {
		t.Errorf("expected missing agent ID error, got %v", err)
	}
}

// TEST 6 — Runner execution
func TestRunner_Execution(t *testing.T) {
	mockClient := &mockHTTPClient{
		statusCode: http.StatusAccepted,
		response: sender.Response{
			Data: &struct {
				Received int `json:"received"`
			}{Received: 1},
		},
	}
	mockCol := &mockCollector{snapshot: validSnapshot()}
	client := sender.NewClient(mockClient, mockCol)

	// Interval is intentionally long; we rely on the initial immediate execution
	runner := sender.NewRunner(client, "agent-123", "secret", 1*time.Hour, 1024)

	// Use a short context to ensure it stops cleanly if something hangs
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	runner.Start(ctx)

	// Wait briefly for the goroutine to run the first collection
	time.Sleep(50 * time.Millisecond)

	runner.Stop()

	// Verify that collection and transmission occurred at least once
	if mockClient.lastEndpoint != "/api/v1/agents/agent-123/processes" {
		t.Errorf("runner did not submit correctly, last endpoint: %s", mockClient.lastEndpoint)
	}
}
