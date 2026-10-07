package sender_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vpsmonitoring-agent/internal/client"
	"vpsmonitoring-agent/internal/metrics/models"
	"vpsmonitoring-agent/internal/metrics/sender"
)

type mockSnapshotCollector struct {
	snapshot models.MetricSnapshot
}

func (m *mockSnapshotCollector) CollectSnapshot(ctx context.Context) models.MetricSnapshot {
	return m.snapshot
}

func TestMetricSender_Client(t *testing.T) {
	sampleSnapshot := models.MetricSnapshot{
		Timestamp: time.Now().UTC(),
		CPU: models.CPUMetrics{
			UsagePercent: 32.5,
			Cores:        4,
			Load1:        0.5,
		},
		Memory: models.MemoryMetrics{
			Total:        8000000,
			Used:         4000000,
			UsagePercent: 50.0,
		},
		Disk: models.DiskMetrics{
			MountPoints: []models.MountPoint{
				{Path: "/", UsagePercent: 40.0},
			},
		},
	}

	t.Run("Successful metric submission transmits JSON, Bearer auth, and handles 200 OK", func(t *testing.T) {
		var receivedAuth string
		var receivedContentType string
		var receivedBody []byte

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/agent/metrics" {
				t.Errorf("expected path /api/v1/agent/metrics, got %s", r.URL.Path)
			}
			if r.Method != http.MethodPost {
				t.Errorf("expected method POST, got %s", r.Method)
			}

			receivedAuth = r.Header.Get("Authorization")
			receivedContentType = r.Header.Get("Content-Type")
			receivedBody, _ = io.ReadAll(r.Body)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"success":true,"metric_id":"m-123","server_id":10,"received_at":"2026-09-29T07:00:00Z"}}`))
		}))
		defer ts.Close()

		httpClient := client.NewClient(ts.URL, 5*time.Second)
		collector := &mockSnapshotCollector{snapshot: sampleSnapshot}
		metricClient := sender.NewClient(httpClient, collector)

		resp, err := metricClient.Send(context.Background(), "test-agent-cred-secret")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if receivedAuth != "Bearer test-agent-cred-secret" {
			t.Errorf("expected 'Bearer test-agent-cred-secret', got '%s'", receivedAuth)
		}
		if receivedContentType != "application/json" {
			t.Errorf("expected application/json content-type, got '%s'", receivedContentType)
		}

		var parsed models.MetricSnapshot
		if err := json.Unmarshal(receivedBody, &parsed); err != nil {
			t.Fatalf("failed to parse transmitted body: %v", err)
		}
		if parsed.CPU.UsagePercent != 32.5 {
			t.Errorf("expected CPU usage 32.5, got %f", parsed.CPU.UsagePercent)
		}

		if resp.Data.MetricID != "m-123" || resp.Data.ServerID != 10 {
			t.Errorf("unexpected response: %+v", resp.Data)
		}
	})

	t.Run("Missing credential returns error before network dispatch", func(t *testing.T) {
		httpClient := client.NewClient("http://localhost", 1*time.Second)
		metricClient := sender.NewClient(httpClient, &mockSnapshotCollector{})

		_, err := metricClient.Send(context.Background(), "")
		if err == nil {
			t.Errorf("expected error when credential is empty")
		}
	})

	t.Run("401 Unauthorized maps to ErrUnauthorized without leaking credentials", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"message":"invalid credential"}}`))
		}))
		defer ts.Close()

		httpClient := client.NewClient(ts.URL, 5*time.Second)
		metricClient := sender.NewClient(httpClient, &mockSnapshotCollector{snapshot: sampleSnapshot})

		_, err := metricClient.Send(context.Background(), "my-secret-credential")
		if err == nil || err != sender.ErrUnauthorized {
			t.Fatalf("expected ErrUnauthorized, got %v", err)
		}
		if strings.Contains(err.Error(), "my-secret-credential") {
			t.Errorf("credential leaked in error message")
		}
	})

	t.Run("400 Bad Request maps to ErrInvalidPayload", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"invalid metric timestamp"}}`))
		}))
		defer ts.Close()

		httpClient := client.NewClient(ts.URL, 5*time.Second)
		metricClient := sender.NewClient(httpClient, &mockSnapshotCollector{snapshot: sampleSnapshot})

		_, err := metricClient.Send(context.Background(), "my-secret")
		if err == nil || !strings.Contains(err.Error(), "invalid payload") {
			t.Fatalf("expected invalid payload error, got %v", err)
		}
	})

	t.Run("500 Internal Error handled gracefully without panic", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"message":"database down"}}`))
		}))
		defer ts.Close()

		httpClient := client.NewClient(ts.URL, 5*time.Second)
		metricClient := sender.NewClient(httpClient, &mockSnapshotCollector{snapshot: sampleSnapshot})

		_, err := metricClient.Send(context.Background(), "my-secret")
		if err == nil {
			t.Fatalf("expected error on 500, got nil")
		}
	})

	t.Run("Network failure handled cleanly without panic", func(t *testing.T) {
		// Non-existent port
		httpClient := client.NewClient("http://127.0.0.1:54321", 500*time.Millisecond)
		metricClient := sender.NewClient(httpClient, &mockSnapshotCollector{snapshot: sampleSnapshot})

		_, err := metricClient.Send(context.Background(), "my-secret")
		if err == nil {
			t.Fatalf("expected network failure error, got nil")
		}
	})
}

func TestMetricSender_Runner(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"success":true}}`))
	}))
	defer ts.Close()

	httpClient := client.NewClient(ts.URL, 5*time.Second)
	metricClient := sender.NewClient(httpClient, &mockSnapshotCollector{})

	runner := sender.NewRunner(metricClient, "valid-cred", 20*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runner.Start(ctx)

	// Allow several cycles
	time.Sleep(70 * time.Millisecond)

	runner.Stop()
}
