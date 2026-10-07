package syncer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"vpsmonitoring-agent/internal/application/config"
	agentConfig "vpsmonitoring-agent/internal/config"
)

func TestSyncer_Success(t *testing.T) {
	mockData := map[string]any{
		"data": map[string]any{
			"data": []config.ApplicationConfig{
				{ID: 1, Name: "App 1", IsEnabled: true, MatchType: "systemd_unit", MatchValue: "app1.service"},
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(mockData)
	}))
	defer ts.Close()

	cfg := &agentConfig.Config{BackendURL: ts.URL, AgentID: "test-agent"}
	snapshot := config.NewSnapshot()
	syncer := NewSyncer(cfg, snapshot)
	syncer.httpClient = ts.Client()

	syncer.fetchConfig(context.Background())

	apps := snapshot.Get()
	if len(apps) != 1 {
		t.Fatalf("expected 1 app, got %d", len(apps))
	}
	if apps[0].Name != "App 1" {
		t.Errorf("expected App 1, got %s", apps[0].Name)
	}
}

func TestSyncer_FailurePreservesSnapshot(t *testing.T) {
	// First successful sync
	mockData := map[string]any{
		"data": map[string]any{
			"data": []config.ApplicationConfig{
				{ID: 1, Name: "App 1", IsEnabled: true, MatchType: "systemd_unit", MatchValue: "app1.service"},
			},
		},
	}
	tsSuccess := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(mockData)
	}))

	cfg := &agentConfig.Config{BackendURL: tsSuccess.URL, AgentID: "test-agent"}
	snapshot := config.NewSnapshot()
	syncer := NewSyncer(cfg, snapshot)
	syncer.httpClient = tsSuccess.Client()

	syncer.fetchConfig(context.Background())
	tsSuccess.Close() // Close success server

	apps := snapshot.Get()
	if len(apps) != 1 {
		t.Fatalf("expected 1 app initially, got %d", len(apps))
	}

	// Now fail
	tsFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer tsFail.Close()

	syncer.cfg.BackendURL = tsFail.URL
	syncer.httpClient = tsFail.Client()

	syncer.fetchConfig(context.Background())

	// Snapshot should be preserved
	appsAfterFail := snapshot.Get()
	if len(appsAfterFail) != 1 {
		t.Fatalf("expected snapshot to be preserved with 1 app, got %d", len(appsAfterFail))
	}
}

func TestSyncer_EmptyConfig(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": []config.ApplicationConfig{}}})
	}))
	defer ts.Close()

	cfg := &agentConfig.Config{BackendURL: ts.URL, AgentID: "test-agent"}
	snapshot := config.NewSnapshot()

	// Pre-populate with something
	snapshot.Set([]config.ApplicationConfig{{ID: 99, Name: "Dummy"}})

	syncer := NewSyncer(cfg, snapshot)
	syncer.httpClient = ts.Client()

	syncer.fetchConfig(context.Background())

	apps := snapshot.Get()
	if len(apps) != 0 {
		t.Fatalf("expected 0 apps, got %d", len(apps))
	}
}

func TestSyncer_InvalidDataRejected(t *testing.T) {
	mockData := map[string]any{
		"data": map[string]any{
			"data": []config.ApplicationConfig{
				{ID: 1, Name: "App 1", IsEnabled: true, MatchType: "invalid_type", MatchValue: "app1.service"}, // invalid
				{ID: 2, Name: "App 2", IsEnabled: true, MatchType: "systemd_unit", MatchValue: ""},             // empty match value
				{ID: 3, Name: "App 3", IsEnabled: true, MatchType: "exe_path", MatchValue: "/bin/test"},        // valid
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(mockData)
	}))
	defer ts.Close()

	cfg := &agentConfig.Config{BackendURL: ts.URL, AgentID: "test-agent"}
	snapshot := config.NewSnapshot()
	syncer := NewSyncer(cfg, snapshot)
	syncer.httpClient = ts.Client()

	syncer.fetchConfig(context.Background())

	apps := snapshot.Get()
	if len(apps) != 1 {
		t.Fatalf("expected 1 valid app, got %d", len(apps))
	}
	if apps[0].ID != 3 {
		t.Errorf("expected App 3, got ID %d", apps[0].ID)
	}
}
