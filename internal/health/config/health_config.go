package config

import (
	"sync/atomic"
)

// HttpHealthConfig represents the agent-side configuration for a single HTTP health check.
type HttpHealthConfig struct {
	ConfigID    int64  `json:"id"`
	URL         string `json:"url"`
	IntervalSec int    `json:"interval_sec"`
	IsActive    bool   `json:"is_active"`
}

// Snapshot safely stores a thread-safe atomic reference to the latest health configurations.
type Snapshot struct {
	configs atomic.Value
}

// NewSnapshot initializes a new empty configuration snapshot.
func NewSnapshot() *Snapshot {
	s := &Snapshot{}
	s.configs.Store([]HttpHealthConfig{})
	return s
}

// Get returns the current configuration slice in a thread-safe manner.
func (s *Snapshot) Get() []HttpHealthConfig {
	val := s.configs.Load()
	if val == nil {
		return []HttpHealthConfig{}
	}
	return val.([]HttpHealthConfig)
}

// Set atomically replaces the entire configuration slice.
func (s *Snapshot) Set(configs []HttpHealthConfig) {
	if configs == nil {
		configs = []HttpHealthConfig{}
	}
	s.configs.Store(configs)
}
