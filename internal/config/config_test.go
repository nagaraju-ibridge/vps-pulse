package config_test

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpsmonitoring-agent/internal/config"
)

func TestConfig_Load(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "agent.json")

	t.Run("Missing VPSMONITOR_BACKEND_URL returns error", func(t *testing.T) {
		os.Unsetenv("VPSMONITOR_BACKEND_URL")
		_, err := config.Load()
		if err == nil {
			t.Error("expected error for missing backend URL")
		}
	})

	t.Run("Missing token and credential returns error", func(t *testing.T) {
		t.Setenv("VPSMONITOR_BACKEND_URL", "http://localhost:8080")
		t.Setenv("VPSMONITOR_STATE_FILE", filepath.Join(tmpDir, "nonexistent.json"))
		os.Unsetenv("VPSMONITOR_INSTALLATION_TOKEN")
		os.Unsetenv("VPSMONITOR_AGENT_CREDENTIAL")

		_, err := config.Load()
		if err == nil {
			t.Error("expected error when neither token nor credential is provided")
		}
	})

	t.Run("Loads with installation token when no credential exists", func(t *testing.T) {
		t.Setenv("VPSMONITOR_BACKEND_URL", "http://localhost:8080")
		t.Setenv("VPSMONITOR_INSTALLATION_TOKEN", "tok-12345")
		t.Setenv("VPSMONITOR_STATE_FILE", stateFile)
		os.Unsetenv("VPSMONITOR_AGENT_CREDENTIAL")

		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.BackendURL != "http://localhost:8080" {
			t.Errorf("expected backend URL http://localhost:8080, got %s", cfg.BackendURL)
		}
		if cfg.InstallationToken != "tok-12345" {
			t.Errorf("expected installation token tok-12345, got %s", cfg.InstallationToken)
		}
		if cfg.HeartbeatInterval != 30*time.Second {
			t.Errorf("expected default 30s heartbeat interval, got %v", cfg.HeartbeatInterval)
		}
		if cfg.DiscoveryInterval != 5*time.Minute {
			t.Errorf("expected default 5m discovery interval, got %v", cfg.DiscoveryInterval)
		}
	})

	t.Run("Loads agent credential from environment directly", func(t *testing.T) {
		t.Setenv("VPSMONITOR_BACKEND_URL", "http://localhost:8080")
		t.Setenv("VPSMONITOR_AGENT_CREDENTIAL", "cred-from-env")
		t.Setenv("VPSMONITOR_HEARTBEAT_INTERVAL_SECONDS", "45")
		t.Setenv("VPSMONITOR_DISCOVERY_INTERVAL_SECONDS", "300")

		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.AgentCredential != "cred-from-env" {
			t.Errorf("expected credential from env, got %s", cfg.AgentCredential)
		}
		if cfg.HeartbeatInterval != 45*time.Second {
			t.Errorf("expected 45s heartbeat interval, got %v", cfg.HeartbeatInterval)
		}
		if cfg.DiscoveryInterval != 5*time.Minute {
			t.Errorf("expected 5m discovery interval, got %v", cfg.DiscoveryInterval)
		}
	})

	t.Run("Loads agent credential from state file", func(t *testing.T) {
		// Write state file
		initialState := &config.AgentState{
			AgentID:         "agent-uuid-persisted",
			ServerID:        123,
			AgentCredential: "cred-from-file-abc",
		}
		if err := config.SaveState(stateFile, initialState); err != nil {
			t.Fatalf("failed to save state: %v", err)
		}

		t.Setenv("VPSMONITOR_BACKEND_URL", "http://localhost:8080")
		t.Setenv("VPSMONITOR_STATE_FILE", stateFile)
		os.Unsetenv("VPSMONITOR_INSTALLATION_TOKEN")
		os.Unsetenv("VPSMONITOR_AGENT_CREDENTIAL")

		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.AgentCredential != "cred-from-file-abc" {
			t.Errorf("expected credential from file, got %s", cfg.AgentCredential)
		}
	})
}

func TestConfig_StatePersistence(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "nested", "agent.json")

	state := &config.AgentState{
		AgentID:         "test-agent-99",
		ServerID:        456,
		AgentCredential: "secret-cred-xyz",
	}

	// 1. Save state
	if err := config.SaveState(statePath, state); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	// 2. Read state
	loaded, err := config.LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}

	if loaded.AgentID != "test-agent-99" || loaded.ServerID != 456 || loaded.AgentCredential != "secret-cred-xyz" {
		t.Errorf("loaded state does not match: %+v", loaded)
	}

	// 3. Verify file permissions
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("failed to stat file: %v", err)
	}
	// On Unix-like environments, check mode. On Windows, file permissions mask may differ.
	if os.PathSeparator == '/' && info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600 permissions, got %v", info.Mode().Perm())
	}
}

func TestConfig_DiscoveryInterval(t *testing.T) {
	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "agent.json")

	tests := []struct {
		name      string
		value     *string
		want      time.Duration
		wantWarn  bool
		warnMatch string
	}{
		{name: "unset uses default", value: nil, want: 5 * time.Minute},
		{name: "300 seconds accepted", value: strPtr("300"), want: 5 * time.Minute},
		{name: "60 seconds accepted", value: strPtr("60"), want: 60 * time.Second},
		{name: "59 seconds rejected", value: strPtr("59"), want: 5 * time.Minute, wantWarn: true, warnMatch: "below minimum or invalid"},
		{name: "1 second rejected", value: strPtr("1"), want: 5 * time.Minute, wantWarn: true, warnMatch: "below minimum or invalid"},
		{name: "0 rejected", value: strPtr("0"), want: 5 * time.Minute, wantWarn: true, warnMatch: "invalid discovery interval"},
		{name: "negative rejected", value: strPtr("-1"), want: 5 * time.Minute, wantWarn: true, warnMatch: "invalid discovery interval"},
		{name: "non numeric rejected", value: strPtr("abc"), want: 5 * time.Minute, wantWarn: true, warnMatch: "invalid discovery interval"},
		{name: "whitespace invalid rejected", value: strPtr("   abc   "), want: 5 * time.Minute, wantWarn: true, warnMatch: "invalid discovery interval"},
		{name: "very large numeric rejected", value: strPtr("9223372036854775807"), want: 5 * time.Minute, wantWarn: true, warnMatch: "below minimum or invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuffer bytes.Buffer
			originalWriter := log.Writer()
			originalFlags := log.Flags()
			log.SetOutput(&logBuffer)
			log.SetFlags(0)
			defer func() {
				log.SetOutput(originalWriter)
				log.SetFlags(originalFlags)
			}()

			t.Setenv("VPSMONITOR_BACKEND_URL", "http://localhost:8080")
			t.Setenv("VPSMONITOR_AGENT_CREDENTIAL", "cred-from-env")
			t.Setenv("VPSMONITOR_STATE_FILE", stateFile)
			if tt.value == nil {
				os.Unsetenv("VPSMONITOR_DISCOVERY_INTERVAL_SECONDS")
			} else {
				t.Setenv("VPSMONITOR_DISCOVERY_INTERVAL_SECONDS", *tt.value)
			}

			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.DiscoveryInterval != tt.want {
				t.Fatalf("expected discovery interval %v, got %v", tt.want, cfg.DiscoveryInterval)
			}

			logs := logBuffer.String()
			if tt.wantWarn && !strings.Contains(logs, tt.warnMatch) {
				t.Fatalf("expected warning containing %q, got %q", tt.warnMatch, logs)
			}
			if !tt.wantWarn && logs != "" {
				t.Fatalf("expected no warning, got %q", logs)
			}
			for _, forbidden := range []string{"cred-from-env", "Authorization", "Bearer"} {
				if strings.Contains(logs, forbidden) {
					t.Fatalf("warning log exposed sensitive value %q: %s", forbidden, logs)
				}
			}
		})
	}
}

func strPtr(value string) *string {
	return &value
}
