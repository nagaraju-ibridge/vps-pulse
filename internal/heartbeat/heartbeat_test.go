package heartbeat_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"vpsmonitoring-agent/internal/heartbeat"
)

// mockHeartbeatHTTPClient implements client.HTTPClient for testing heartbeat
type mockHeartbeatHTTPClient struct {
	statusCode    int
	respBody      *heartbeat.Response
	err           error
	capturedAuth  string
	capturedReq   any
	postCallCount int
	mu            sync.Mutex
}

func (m *mockHeartbeatHTTPClient) PostJSON(ctx context.Context, endpoint string, bearerToken string, reqBody any, respBody any) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.postCallCount++
	m.capturedAuth = bearerToken
	m.capturedReq = reqBody

	if m.err != nil {
		return 0, m.err
	}

	if m.respBody != nil {
		if target, ok := respBody.(*heartbeat.Response); ok {
			*target = *m.respBody
		}
	}

	return m.statusCode, nil
}

func TestHeartbeat_Client(t *testing.T) {
	ctx := context.Background()

	t.Run("Send without credential returns error", func(t *testing.T) {
		client := heartbeat.NewClient(&mockHeartbeatHTTPClient{})
		_, err := client.Send(ctx, "")
		if err == nil {
			t.Error("expected error for empty credential")
		}
	})

	t.Run("Send attaches Authorization Bearer credential", func(t *testing.T) {
		mockResp := &heartbeat.Response{}
		mockResp.Data.AgentID = "agent-123"
		mockResp.Data.ServerID = 10
		mockResp.Data.Status = "ONLINE"
		mockResp.Data.LastSeen = "2026-09-29T06:10:00Z"

		mockHTTP := &mockHeartbeatHTTPClient{
			statusCode: http.StatusOK,
			respBody:   mockResp,
		}

		client := heartbeat.NewClient(mockHTTP)
		resp, err := client.Send(ctx, "secret-agent-credential-456")
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}

		if resp.Data.Status != "ONLINE" || resp.Data.ServerID != 10 {
			t.Errorf("unexpected response: %+v", resp)
		}

		if mockHTTP.capturedAuth != "secret-agent-credential-456" {
			t.Errorf("expected bearer token to be passed, got %s", mockHTTP.capturedAuth)
		}
	})

	t.Run("HTTP 401 returns ErrUnauthorized without leaking details", func(t *testing.T) {
		mockHTTP := &mockHeartbeatHTTPClient{
			statusCode: http.StatusUnauthorized,
		}

		client := heartbeat.NewClient(mockHTTP)
		_, err := client.Send(ctx, "invalid-cred")
		if !errors.Is(err, heartbeat.ErrUnauthorized) {
			t.Errorf("expected ErrUnauthorized, got %v", err)
		}
	})

	t.Run("Network failure returns error without panic", func(t *testing.T) {
		mockHTTP := &mockHeartbeatHTTPClient{
			err: errors.New("network dial timeout"),
		}

		client := heartbeat.NewClient(mockHTTP)
		_, err := client.Send(ctx, "some-cred")
		if err == nil {
			t.Error("expected network error, got nil")
		}
	})
}

func TestHeartbeat_Runner(t *testing.T) {
	mockResp := &heartbeat.Response{}
	mockResp.Data.Status = "ONLINE"

	mockHTTP := &mockHeartbeatHTTPClient{
		statusCode: http.StatusOK,
		respBody:   mockResp,
	}

	client := heartbeat.NewClient(mockHTTP)
	// Fast interval for testing
	runner := heartbeat.NewRunner(client, "test-credential", 15*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	runner.Start(ctx)

	// Wait for immediate call + at least 1 tick
	time.Sleep(40 * time.Millisecond)

	runner.Stop()
	cancel()

	mockHTTP.mu.Lock()
	calls := mockHTTP.postCallCount
	mockHTTP.mu.Unlock()

	if calls < 2 {
		t.Errorf("expected at least 2 heartbeat dispatches (startup + interval), got %d", calls)
	}
}
