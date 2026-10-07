package sender

import (
	"context"
	"testing"
	"time"

	"vpsmonitoring-agent/internal/health/collector"
)

type mockHTTPClient struct {
	postJSONFunc func(ctx context.Context, endpoint string, bearerToken string, reqBody any, respBody any) (int, error)
	reqsCount    int
	lastReqBody  any
}

func (m *mockHTTPClient) PostJSON(ctx context.Context, endpoint string, bearerToken string, reqBody any, respBody any) (int, error) {
	m.reqsCount++
	m.lastReqBody = reqBody
	return m.postJSONFunc(ctx, endpoint, bearerToken, reqBody, respBody)
}

func TestSender_send(t *testing.T) {
	snapshot := collector.NewResultSnapshot()

	t.Run("empty snapshot skipped", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			postJSONFunc: func(ctx context.Context, endpoint string, bearerToken string, reqBody any, respBody any) (int, error) {
				return 200, nil
			},
		}

		snd := NewSender(mockClient, snapshot, time.Second, "token", "agent-1")
		snd.send()

		if mockClient.reqsCount != 0 {
			t.Errorf("expected 0 requests for empty snapshot, got %d", mockClient.reqsCount)
		}
	})

	t.Run("results sent", func(t *testing.T) {
		snapshot.Set(collector.HealthResult{
			ConfigID:    1,
			URL:         "http://example.com",
			StatusCode:  200,
			LatencyMs:   45,
			IsAvailable: true,
			ErrorClass:  collector.ErrClassNone,
			CollectedAt: time.Now(),
		})

		mockClient := &mockHTTPClient{
			postJSONFunc: func(ctx context.Context, endpoint string, bearerToken string, reqBody any, respBody any) (int, error) {
				return 200, nil
			},
		}

		snd := NewSender(mockClient, snapshot, time.Second, "token", "agent-1")
		snd.send()

		if mockClient.reqsCount != 1 {
			t.Errorf("expected 1 request, got %d", mockClient.reqsCount)
		}

		if mockClient.lastReqBody == nil {
			t.Fatal("expected request body, got empty")
		}

		payload, ok := mockClient.lastReqBody.(agentHealthCheckPayload)
		if !ok {
			t.Fatalf("failed to parse payload type")
		}

		if len(payload.Checks) != 1 || payload.Checks[0].ConfigID != 1 {
			t.Errorf("expected 1 check with config 1, got %v", payload.Checks)
		}
	})

	t.Run("backend error logged", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			postJSONFunc: func(ctx context.Context, endpoint string, bearerToken string, reqBody any, respBody any) (int, error) {
				return 500, nil
			},
		}

		snd := NewSender(mockClient, snapshot, time.Second, "token", "agent-1")
		snd.send()

		if mockClient.reqsCount != 1 {
			t.Errorf("expected 1 request, got %d", mockClient.reqsCount)
		}
		// Sender doesn't crash or panic, gracefully logs error.
	})
}

func TestSender_Start(t *testing.T) {
	snapshot := collector.NewResultSnapshot()

	mockClient := &mockHTTPClient{
		postJSONFunc: func(ctx context.Context, endpoint string, bearerToken string, reqBody any, respBody any) (int, error) {
			return 200, nil
		},
	}

	snd := NewSender(mockClient, snapshot, 50*time.Millisecond, "token", "agent-1")

	ctx, cancel := context.WithCancel(context.Background())

	// Add data so it attempts to send
	snapshot.Set(collector.HealthResult{
		ConfigID: 1, URL: "test",
	})

	done := make(chan struct{})
	go func() {
		snd.Start(ctx)
		close(done)
	}()

	time.Sleep(150 * time.Millisecond) // Let it run a few cycles
	cancel()

	<-done

	if mockClient.reqsCount < 2 {
		t.Errorf("expected at least 2 sends, got %d", mockClient.reqsCount)
	}
}
