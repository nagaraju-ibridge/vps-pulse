package collector

import (
	"context"
	"testing"
	"time"

	healthConfig "vpsmonitoring-agent/internal/health/config"
)

func TestScheduler_Start(t *testing.T) {
	cfgSnap := healthConfig.NewSnapshot()
	resSnap := NewResultSnapshot()

	sched := NewScheduler(cfgSnap, resSnap)

	cfgSnap.Set([]healthConfig.HttpHealthConfig{
		{ConfigID: 1, URL: "http://127.0.0.1", IntervalSec: 1, IsActive: true},  // will fail SSRF quickly
		{ConfigID: 2, URL: "http://127.0.0.1", IntervalSec: 1, IsActive: false}, // inactive, should not run
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go sched.Start(ctx)

	// Wait for the scheduler to tick and execute at least once
	time.Sleep(2 * time.Second)

	results := resSnap.GetAll()
	if len(results) != 1 {
		t.Fatalf("expected 1 result from active config, got %d", len(results))
	}
	if results[0].ConfigID != 1 {
		t.Errorf("expected config ID 1 to run, got %d", results[0].ConfigID)
	}
	if results[0].IsAvailable != false {
		t.Errorf("expected 127.0.0.1 to fail SSRF and be unavailable")
	}
}

func TestScheduler_ConcurrencyLimit(t *testing.T) {
	cfgSnap := healthConfig.NewSnapshot()
	resSnap := NewResultSnapshot()
	sched := NewScheduler(cfgSnap, resSnap)

	// Add 15 configs, limit is 10.
	var configs []healthConfig.HttpHealthConfig
	for i := int64(1); i <= 15; i++ {
		configs = append(configs, healthConfig.HttpHealthConfig{
			ConfigID:    i,
			URL:         "http://127.0.0.1", // fails fast
			IntervalSec: 1,
			IsActive:    true,
		})
	}
	cfgSnap.Set(configs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go sched.Start(ctx)

	// Because they fail fast, it's hard to catch the concurrency limit hitting,
	// but we can at least ensure all 15 run eventually without deadlocking.
	time.Sleep(3 * time.Second)

	results := resSnap.GetAll()
	if len(results) != 15 {
		t.Errorf("expected all 15 configs to run eventually, got %d", len(results))
	}
}
