package collector

import (
	"context"
	"log"
	"time"

	healthConfig "vpsmonitoring-agent/internal/health/config"
)

// Scheduler manages the periodic execution of HTTP health checks.
type Scheduler struct {
	configSnapshot *healthConfig.Snapshot
	resultSnapshot *ResultSnapshot
	collector      *HTTPCollector
}

// NewScheduler creates a new health check scheduler.
func NewScheduler(configSnapshot *healthConfig.Snapshot, resultSnapshot *ResultSnapshot) *Scheduler {
	return &Scheduler{
		configSnapshot: configSnapshot,
		resultSnapshot: resultSnapshot,
		collector:      NewHTTPCollector(),
	}
}

// Start begins a continuous loop that evaluates configuration and runs checks.
func (s *Scheduler) Start(ctx context.Context) {
	log.Println("[INFO] Starting HTTP health check scheduler")

	// We'll use a simple loop that ticks every second to evaluate what needs to run.
	// This avoids creating/destroying goroutines per config dynamically, keeping it robust.
	// We bound concurrency using a semaphore (channel).
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Concurrency bound (max 10 concurrent health checks as per requirements)
	concurrencyLimit := make(chan struct{}, 10)

	// Keep track of the last run time for each config ID
	lastRun := make(map[int64]time.Time)

	for {
		select {
		case <-ctx.Done():
			log.Println("[INFO] HTTP health check scheduler stopped")
			return
		case <-ticker.C:
			configs := s.configSnapshot.Get()
			now := time.Now()

			// Clean up removed configs from lastRun
			activeIDs := make(map[int64]bool)
			for _, c := range configs {
				activeIDs[c.ConfigID] = true
			}
			for id := range lastRun {
				if !activeIDs[id] {
					delete(lastRun, id)
				}
			}

			// Evaluate each config
			for _, cfg := range configs {
				if !cfg.IsActive {
					continue
				}

				interval := time.Duration(cfg.IntervalSec) * time.Second
				if interval < 10*time.Second {
					interval = 10 * time.Second // safety floor
				}

				last, exists := lastRun[cfg.ConfigID]

				// Time to run?
				if !exists || now.Sub(last) >= interval {
					// Mark as running immediately so we don't trigger it again next second
					lastRun[cfg.ConfigID] = now

					// Non-blocking attempt to acquire semaphore
					select {
					case concurrencyLimit <- struct{}{}:
						// Launch execution in a bounded goroutine
						go func(c healthConfig.HttpHealthConfig) {
							defer func() { <-concurrencyLimit }()

							// Execute check
							result := s.collector.Execute(ctx, c)

							// Save to thread-safe snapshot
							s.resultSnapshot.Set(result)

						}(cfg)
					default:
						// Concurrency limit reached, skip this interval or wait.
						// By skipping, we'll try again next second if the time difference still holds.
						// But we marked it as run. Let's revert the lastRun so it tries again next second.
						delete(lastRun, cfg.ConfigID)
						log.Printf("[WARN] Health check concurrency limit reached, delaying check for config %d", cfg.ConfigID)
					}
				}
			}
		}
	}
}
