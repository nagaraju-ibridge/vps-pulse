package sender

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vpsmonitoring-agent/internal/client"
	"vpsmonitoring-agent/internal/systemd/models"
)

type mockCollector struct{}

func (m *mockCollector) Collect(ctx context.Context) models.ServicePayload {
	return models.ServicePayload{
		CollectedAt: time.Now(),
		Services:    []models.ServiceSnapshot{{Name: "nginx.service"}},
	}
}

func TestSystemdSender_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"received": 1}`))
	}))
	defer ts.Close()

	httpClient := client.NewClient(ts.URL, 5*time.Second)
	senderClient := NewClient(httpClient, &mockCollector{})

	resp, err := senderClient.Send(context.Background(), "agent-123", "test-token")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if resp.Received != 1 {
		t.Errorf("expected 1 received, got %d", resp.Received)
	}
}

func TestSystemdSender_Failure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	httpClient := client.NewClient(ts.URL, 5*time.Second)
	senderClient := NewClient(httpClient, &mockCollector{})

	_, err := senderClient.Send(context.Background(), "agent-123", "test-token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
