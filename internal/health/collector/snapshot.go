package collector

import "sync"

// ResultSnapshot maintains a thread-safe latest health result for each config.
type ResultSnapshot struct {
	mu      sync.RWMutex
	results map[int64]HealthResult
}

// NewResultSnapshot creates a new result snapshot.
func NewResultSnapshot() *ResultSnapshot {
	return &ResultSnapshot{
		results: make(map[int64]HealthResult),
	}
}

// Set stores the result of a health check.
func (s *ResultSnapshot) Set(result HealthResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[result.ConfigID] = result
}

// GetAll returns a copy of all current health results.
func (s *ResultSnapshot) GetAll() []HealthResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []HealthResult
	for _, res := range s.results {
		out = append(out, res)
	}
	return out
}
