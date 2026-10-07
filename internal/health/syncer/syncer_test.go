package syncer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vpsmonitoring-agent/internal/config"
	healthConfig "vpsmonitoring-agent/internal/health/config"
)

func TestSyncer(t *testing.T) {
	t.Run("wrapped successful response replaces snapshot", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if auth := r.Header.Get("Authorization"); auth != "Bearer secret123" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if !strings.Contains(r.URL.Path, "agent-123") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":[{"id": 1, "url": "http://test1.com", "interval_sec": 60, "is_active": true}, {"id": 2, "url": "http://test2.com", "interval_sec": 30, "is_active": true}]}`))
		}))
		defer ts.Close()

		cfg := &config.Config{BackendURL: ts.URL, AgentID: "agent-123", AgentCredential: "secret123"}
		snapshot := healthConfig.NewSnapshot()
		// pre-populate with old data
		snapshot.Set([]healthConfig.HttpHealthConfig{{ConfigID: 99, URL: "old", IsActive: true}})

		syncer := NewSyncer(cfg, snapshot)
		syncer.fetchConfig(context.Background())

		res := snapshot.Get()
		if len(res) != 2 {
			t.Fatalf("expected 2 configs, got %d", len(res))
		}
		if res[0].ConfigID != 1 || res[1].ConfigID != 2 {
			t.Errorf("unexpected config IDs: %v", res)
		}
	})

	t.Run("inactive configurations are filtered out", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":[{"id": 1, "url": "http://test1.com", "is_active": true}, {"id": 2, "url": "http://test2.com", "is_active": false}]}`))
		}))
		defer ts.Close()

		cfg := &config.Config{BackendURL: ts.URL, AgentID: "agent-123", AgentCredential: "secret"}
		snapshot := healthConfig.NewSnapshot()
		syncer := NewSyncer(cfg, snapshot)
		syncer.fetchConfig(context.Background())

		res := snapshot.Get()
		if len(res) != 1 || res[0].ConfigID != 1 {
			t.Fatalf("expected 1 active config, got %v", res)
		}
	})

	t.Run("wrapped empty response clears snapshot safely", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":[]}`))
		}))
		defer ts.Close()

		cfg := &config.Config{BackendURL: ts.URL, AgentID: "agent-123", AgentCredential: "secret"}
		snapshot := healthConfig.NewSnapshot()
		snapshot.Set([]healthConfig.HttpHealthConfig{{ConfigID: 1, IsActive: true}})

		syncer := NewSyncer(cfg, snapshot)
		syncer.fetchConfig(context.Background())

		res := snapshot.Get()
		if len(res) != 0 {
			t.Fatalf("expected empty configs, got %d", len(res))
		}
	})

	t.Run("HTTP failure retains previous snapshot", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()

		cfg := &config.Config{BackendURL: ts.URL, AgentID: "agent-123", AgentCredential: "secret"}
		snapshot := healthConfig.NewSnapshot()
		oldConfigs := []healthConfig.HttpHealthConfig{{ConfigID: 1, IsActive: true}}
		snapshot.Set(oldConfigs)

		syncer := NewSyncer(cfg, snapshot)
		syncer.fetchConfig(context.Background())

		res := snapshot.Get()
		if len(res) != 1 || res[0].ConfigID != 1 {
			t.Fatalf("expected previous config to be retained")
		}
	})

	t.Run("malformed response retains previous snapshot", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`not json`))
		}))
		defer ts.Close()

		cfg := &config.Config{BackendURL: ts.URL, AgentID: "agent-123", AgentCredential: "secret"}
		snapshot := healthConfig.NewSnapshot()
		oldConfigs := []healthConfig.HttpHealthConfig{{ConfigID: 1, IsActive: true}}
		snapshot.Set(oldConfigs)

		syncer := NewSyncer(cfg, snapshot)
		syncer.fetchConfig(context.Background())

		res := snapshot.Get()
		if len(res) != 1 || res[0].ConfigID != 1 {
			t.Fatalf("expected previous config to be retained")
		}
	})

	t.Run("backend unavailable retains previous snapshot", func(t *testing.T) {
		cfg := &config.Config{BackendURL: "http://127.0.0.1:0", AgentID: "agent-123", AgentCredential: "secret"}
		snapshot := healthConfig.NewSnapshot()
		oldConfigs := []healthConfig.HttpHealthConfig{{ConfigID: 1, IsActive: true}}
		snapshot.Set(oldConfigs)

		syncer := NewSyncer(cfg, snapshot)
		syncer.fetchConfig(context.Background())

		res := snapshot.Get()
		if len(res) != 1 || res[0].ConfigID != 1 {
			t.Fatalf("expected previous config to be retained")
		}
	})

	t.Run("duplicate configs handle safely", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":[{"id": 1, "is_active": true}, {"id": 1, "is_active": true}]}`))
		}))
		defer ts.Close()

		cfg := &config.Config{BackendURL: ts.URL, AgentID: "agent-123", AgentCredential: "secret"}
		snapshot := healthConfig.NewSnapshot()

		syncer := NewSyncer(cfg, snapshot)
		syncer.fetchConfig(context.Background())

		res := snapshot.Get()
		if len(res) != 1 {
			t.Fatalf("expected 1 deduplicated config, got %d", len(res))
		}
	})
}
