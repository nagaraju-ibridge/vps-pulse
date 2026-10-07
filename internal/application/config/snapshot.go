package config

import (
	"sync"
)

// ApplicationConfig represents the configuration payload returned by the backend.
type ApplicationConfig struct {
	ID             int64   `json:"id"`
	Name           string  `json:"name"`
	IsEnabled      bool    `json:"is_enabled"`
	MatchType      string  `json:"match_type"`
	MatchValue     string  `json:"match_value"`
	MonitorPort    *int    `json:"monitor_port,omitempty"`
	MonitorHttpUrl *string `json:"monitor_http_url,omitempty"`
	LogSourceType  *string `json:"log_source_type,omitempty"`
	LogSourcePath  *string `json:"log_source_path,omitempty"`
}

// Snapshot provides thread-safe access to the current active application monitoring configurations.
type Snapshot struct {
	mu      sync.RWMutex
	configs []ApplicationConfig
}

// NewSnapshot initializes a new configuration snapshot.
func NewSnapshot() *Snapshot {
	return &Snapshot{
		configs: []ApplicationConfig{},
	}
}

// Set replaces the entire configuration atomically.
func (s *Snapshot) Set(configs []ApplicationConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if configs == nil {
		s.configs = []ApplicationConfig{}
	} else {
		s.configs = configs
	}
}

// Get returns the current active configuration snapshot.
func (s *Snapshot) Get() []ApplicationConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.configs
}
