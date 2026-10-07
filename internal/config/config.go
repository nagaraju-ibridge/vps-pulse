package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// AgentVersion defines the current semver release of the agent daemon
	AgentVersion = "0.1.0"

	// DefaultHeartbeatInterval is the default period between heartbeat signals
	DefaultHeartbeatInterval = 30 * time.Second

	// DefaultMetricInterval is the default period between metric reports
	DefaultMetricInterval = 60 * time.Second

	// DefaultDiscoveryInterval is the default period between discovery reports
	DefaultDiscoveryInterval = 5 * time.Minute

	// MinDiscoveryInterval is the minimum allowed discovery reporting interval
	MinDiscoveryInterval = 60 * time.Second

	// DefaultStateFileLinux is the default location for persisting agent credentials on Linux
	DefaultStateFileLinux = "/var/lib/vpsmonitoring-agent/agent.json"
)

// AgentState represents locally persisted credentials and identity
type AgentState struct {
	AgentID         string `json:"agent_id"`
	ServerID        int64  `json:"server_id"`
	AgentCredential string `json:"agent_credential"`
}

// Config represents the runtime configuration for the agent daemon
type Config struct {
	BackendURL        string
	InstallationToken string
	AgentCredential   string
	AgentID           string // Added for Phase 3.4B.3 (process snapshots require agentId in URL)
	HeartbeatInterval time.Duration
	MetricInterval    time.Duration
	DiscoveryInterval time.Duration
	StateFilePath     string
}

// Load loads configuration from environment variables and local state file.
func Load() (*Config, error) {
	backendURL := strings.TrimRight(strings.TrimSpace(os.Getenv("VPSMONITOR_BACKEND_URL")), "/")
	if backendURL == "" {
		return nil, errors.New("VPSMONITOR_BACKEND_URL is required")
	}

	stateFile := strings.TrimSpace(os.Getenv("VPSMONITOR_STATE_FILE"))
	if stateFile == "" {
		// Use user config/home directory fallback if /var/lib is not writable or on Windows/local dev
		stateFile = defaultStateFilePath()
	}

	interval := DefaultHeartbeatInterval
	if intervalStr := strings.TrimSpace(os.Getenv("VPSMONITOR_HEARTBEAT_INTERVAL_SECONDS")); intervalStr != "" {
		if sec, err := strconv.Atoi(intervalStr); err == nil && sec > 0 {
			interval = time.Duration(sec) * time.Second
		}
	}

	metricInterval := DefaultMetricInterval
	if metricIntervalStr := strings.TrimSpace(os.Getenv("VPSMONITOR_METRIC_INTERVAL_SECONDS")); metricIntervalStr != "" {
		if sec, err := strconv.Atoi(metricIntervalStr); err == nil && sec > 0 {
			metricInterval = time.Duration(sec) * time.Second
		}
	}

	discoveryInterval := DefaultDiscoveryInterval
	if discoveryIntervalStr := strings.TrimSpace(os.Getenv("VPSMONITOR_DISCOVERY_INTERVAL_SECONDS")); discoveryIntervalStr != "" {
		if sec, err := strconv.ParseInt(discoveryIntervalStr, 10, 64); err != nil || sec <= 0 {
			log.Printf("[WARN] invalid discovery interval configured; using safe default %s", DefaultDiscoveryInterval)
		} else {
			intervalCandidate := time.Duration(sec) * time.Second
			if intervalCandidate/time.Second != time.Duration(sec) || intervalCandidate < MinDiscoveryInterval {
				log.Printf("[WARN] discovery interval below minimum or invalid; using safe default %s", DefaultDiscoveryInterval)
			} else {
				discoveryInterval = intervalCandidate
			}
		}
	}

	cfg := &Config{
		BackendURL:        backendURL,
		InstallationToken: strings.TrimSpace(os.Getenv("VPSMONITOR_INSTALLATION_TOKEN")),
		AgentCredential:   strings.TrimSpace(os.Getenv("VPSMONITOR_AGENT_CREDENTIAL")),
		AgentID:           strings.TrimSpace(os.Getenv("VPSMONITOR_AGENT_ID")),
		HeartbeatInterval: interval,
		MetricInterval:    metricInterval,
		DiscoveryInterval: discoveryInterval,
		StateFilePath:     stateFile,
	}

	// If credential or agent ID is not in environment, attempt to read from state file
	if cfg.AgentCredential == "" || cfg.AgentID == "" {
		state, err := LoadState(cfg.StateFilePath)
		if err == nil && state != nil {
			if cfg.AgentCredential == "" && state.AgentCredential != "" {
				cfg.AgentCredential = state.AgentCredential
			}
			if cfg.AgentID == "" && state.AgentID != "" {
				cfg.AgentID = state.AgentID
			}
		}
	}

	// If still no credential and no installation token, return configuration error
	if cfg.AgentCredential == "" && cfg.InstallationToken == "" {
		return nil, errors.New("neither agent credential nor installation token was found; provide VPSMONITOR_INSTALLATION_TOKEN for first-time registration")
	}

	return cfg, nil
}

// defaultStateFilePath returns an appropriate default state file path depending on OS / environment
func defaultStateFilePath() string {
	// First, check if the state file already exists in known locations
	home, err := os.UserHomeDir()
	var homePath string
	if err == nil && home != "" {
		homePath = filepath.Join(home, ".vpsmonitoring-agent", "agent.json")
	}

	paths := []string{
		"/var/lib/vpsmonitoring-agent/agent.json",
	}
	if homePath != "" {
		paths = append(paths, homePath)
	}
	paths = append(paths, "./agent.json")

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// If no existing file found, fallback to default creation logic
	if _, err := os.Stat("/var/lib"); err == nil {
		testDir := "/var/lib/vpsmonitoring-agent"
		if err := os.MkdirAll(testDir, 0700); err == nil {
			return filepath.Join(testDir, "agent.json")
		}
	}

	if homePath != "" {
		return homePath
	}

	return "./agent.json"
}

// LoadState reads persistent AgentState from a local file
func LoadState(filePath string) (*AgentState, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var state AgentState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse state file: %w", err)
	}

	return &state, nil
}

// SaveState atomically writes AgentState to disk with restrictive 0600 file permissions
func SaveState(filePath string, state *AgentState) error {
	if state == nil {
		return errors.New("cannot save nil state")
	}

	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory for state file: %w", err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode state: %w", err)
	}

	// Write atomically using temporary file
	tmpFile := fmt.Sprintf("%s.tmp.%d", filePath, time.Now().UnixNano())
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write temporary state file: %w", err)
	}

	if err := os.Rename(tmpFile, filePath); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to commit state file: %w", err)
	}

	return nil
}
