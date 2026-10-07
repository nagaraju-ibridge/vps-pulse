package sender_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vpsmonitoring-agent/internal/client"
	"vpsmonitoring-agent/internal/discovery/models"
	"vpsmonitoring-agent/internal/discovery/sender"
)

type mockCollector struct {
	payload models.DiscoveryPayload
	calls   atomic.Int32
}

func (m *mockCollector) Collect(ctx context.Context) models.DiscoveryPayload {
	m.calls.Add(1)
	return m.payload
}

func samplePayload() models.DiscoveryPayload {
	now := time.Now().UTC()
	pid := int64(123)
	return models.DiscoveryPayload{
		CollectedAt: now,
		Applications: []models.ApplicationCandidate{
			{
				ID:                  "app-123-nodejs",
				Runtime:             models.RuntimeNodeJS,
				RuntimeConfidence:   models.ConfidenceHigh,
				Framework:           models.FrameworkNextJS,
				FrameworkConfidence: models.ConfidenceHigh,
				Process: models.ProcessMetadata{
					PID:             pid,
					Name:            "node",
					CmdlineRedacted: "node node_modules/.bin/next start --token=[REDACTED]",
				},
				Ports: []models.Listener{{Protocol: "tcp", LocalAddress: "0.0.0.0", LocalPort: 3000, Scope: models.PortScopeUnspecified, PID: &pid}},
				Evidence: []models.Evidence{
					{Kind: "process_name", Value: "node"},
					{Kind: "command", Value: "next start"},
				},
			},
		},
		Services:  []models.ServiceCandidate{},
		Listeners: []models.Listener{{Protocol: "tcp", LocalAddress: "0.0.0.0", LocalPort: 3000, Scope: models.PortScopeUnspecified, PID: &pid, ProcessName: "node"}},
	}
}

func TestClientSendSuccess(t *testing.T) {
	var method, path, auth string
	var received models.DiscoveryPayload

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		path = r.URL.Path
		auth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"success","received":{"applications":1,"services":0,"listeners":1}}`))
	}))
	defer server.Close()

	httpClient := client.NewClient(server.URL, 2*time.Second)
	collector := &mockCollector{payload: samplePayload()}
	discoveryClient := sender.NewClient(httpClient, collector)

	resp, err := discoveryClient.Send(context.Background(), "agent-123", "credential-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if method != http.MethodPost {
		t.Fatalf("expected POST, got %s", method)
	}
	if path != "/api/v1/agents/agent-123/discovery" {
		t.Fatalf("unexpected path: %s", path)
	}
	if auth != "Bearer credential-secret" {
		t.Fatalf("expected bearer auth to be attached")
	}
	if resp.Received.Applications != 1 || resp.Received.Listeners != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if len(received.Applications) != 1 || received.Applications[0].Runtime != models.RuntimeNodeJS {
		t.Fatalf("payload was not sent correctly: %+v", received)
	}
}

func TestClientSendPayloadUsesProvidedAgentID(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	discoveryClient := sender.NewClient(client.NewClient(server.URL, time.Second), &mockCollector{})
	_, err := discoveryClient.SendPayload(context.Background(), "configured-agent", "secret", samplePayload())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(path, "payload-agent") || path != "/api/v1/agents/configured-agent/discovery" {
		t.Fatalf("sender did not use configured agent ID path: %s", path)
	}
}

func TestClientSendNon2xxResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"message":"temporary backend failure"}}`))
	}))
	defer server.Close()

	discoveryClient := sender.NewClient(client.NewClient(server.URL, time.Second), &mockCollector{payload: samplePayload()})
	_, err := discoveryClient.Send(context.Background(), "agent-123", "secret")
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("expected non-2xx error, got %v", err)
	}
}

func TestClientSendNetworkFailure(t *testing.T) {
	discoveryClient := sender.NewClient(client.NewClient("http://127.0.0.1:1", 100*time.Millisecond), &mockCollector{payload: samplePayload()})
	_, err := discoveryClient.Send(context.Background(), "agent-123", "secret")
	if err == nil {
		t.Fatal("expected network failure")
	}
}

func TestClientSendTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	discoveryClient := sender.NewClient(client.NewClient(server.URL, 50*time.Millisecond), &mockCollector{payload: samplePayload()})
	_, err := discoveryClient.Send(context.Background(), "agent-123", "secret")
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestClientSendEmptyPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var received models.DiscoveryPayload
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}
		if len(received.Applications) != 0 || len(received.Services) != 0 || len(received.Listeners) != 0 {
			t.Fatalf("expected empty payload, got %+v", received)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"success","received":{"applications":0,"services":0,"listeners":0}}`))
	}))
	defer server.Close()

	payload := models.DiscoveryPayload{
		CollectedAt:  time.Now().UTC(),
		Applications: []models.ApplicationCandidate{},
		Services:     []models.ServiceCandidate{},
		Listeners:    []models.Listener{},
	}
	discoveryClient := sender.NewClient(client.NewClient(server.URL, time.Second), &mockCollector{payload: payload})
	_, err := discoveryClient.Send(context.Background(), "agent-123", "secret")
	if err != nil {
		t.Fatalf("empty valid payload should be sent: %v", err)
	}
}

func TestClientSendErrorMapping(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		want       error
	}{
		{name: "bad request", statusCode: http.StatusBadRequest, want: sender.ErrInvalidPayload},
		{name: "unauthorized", statusCode: http.StatusUnauthorized, want: sender.ErrUnauthorized},
		{name: "forbidden", statusCode: http.StatusForbidden, want: sender.ErrUnauthorized},
		{name: "payload too large", statusCode: http.StatusRequestEntityTooLarge, want: sender.ErrPayloadTooLarge},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
			}))
			defer server.Close()

			discoveryClient := sender.NewClient(client.NewClient(server.URL, time.Second), &mockCollector{payload: samplePayload()})
			_, err := discoveryClient.Send(context.Background(), "agent-123", "secret")
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

func TestRunnerCollectorFailureStylePayloadDoesNotPanicAndStops(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"success","received":{"applications":0,"services":0,"listeners":0}}`))
	}))
	defer server.Close()

	collector := &mockCollector{payload: models.DiscoveryPayload{
		CollectedAt:  time.Now().UTC(),
		Applications: []models.ApplicationCandidate{},
		Services:     []models.ServiceCandidate{},
		Listeners:    []models.Listener{},
		Warnings:     []string{"process enumeration failed"},
	}}
	discoveryClient := sender.NewClient(client.NewClient(server.URL, time.Second), collector)
	runner := sender.NewRunner(discoveryClient, "agent-123", "secret", time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	runner.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	runner.Stop()

	if collector.calls.Load() == 0 {
		t.Fatal("expected runner to invoke collector")
	}
}

func TestRunnerLogsDoNotExposeSecrets(t *testing.T) {
	var buf bytes.Buffer
	originalWriter := log.Writer()
	originalFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(originalWriter)
		log.SetFlags(originalFlags)
	}()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	payload := samplePayload()
	payload.Applications[0].Process.CmdlineRedacted = "app --password=[REDACTED] --token=[REDACTED]"
	discoveryClient := sender.NewClient(client.NewClient(server.URL, time.Second), &mockCollector{payload: payload})
	runner := sender.NewRunner(discoveryClient, "agent-123", "super-secret-token", time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	runner.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	runner.Stop()

	logs := buf.String()
	for _, forbidden := range []string{"super-secret-token", "Authorization", "password=actual", "token=actual"} {
		if strings.Contains(logs, forbidden) {
			t.Fatalf("logs exposed sensitive value %q: %s", forbidden, logs)
		}
	}
}
