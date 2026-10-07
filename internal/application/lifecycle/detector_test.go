package lifecycle

import (
	"context"
	"testing"
	"time"

	"vpsmonitoring-agent/internal/application/metrics"
)

func TestDetector_InitialObservation(t *testing.T) {
	detector := NewDetector()

	now := time.Now()
	metricsInput := []metrics.ApplicationProcessMetrics{
		{
			ApplicationID: 1,
			CollectedAt:   now,
			State:         metrics.StateMatched,
			PIDs:          []int64{123},
			ProcessStartTimes: map[int64]time.Time{
				123: now.Add(-time.Hour),
			},
		},
	}

	events := detector.Detect(context.Background(), metricsInput)
	if len(events) != 0 {
		t.Fatalf("expected 0 events for initial observation, got %d", len(events))
	}
}

func TestDetector_SameProcess(t *testing.T) {
	detector := NewDetector()

	now := time.Now()
	start := now.Add(-time.Hour)
	metricsInput := []metrics.ApplicationProcessMetrics{
		{
			ApplicationID:     1,
			CollectedAt:       now,
			State:             metrics.StateMatched,
			PIDs:              []int64{123},
			ProcessStartTimes: map[int64]time.Time{123: start},
		},
	}

	_ = detector.Detect(context.Background(), metricsInput) // init

	events := detector.Detect(context.Background(), metricsInput) // cycle 2
	if len(events) != 0 {
		t.Fatalf("expected 0 events for unchanged process")
	}
}

func TestDetector_Disappearance(t *testing.T) {
	detector := NewDetector()

	now := time.Now()
	start := now.Add(-time.Hour)

	_ = detector.Detect(context.Background(), []metrics.ApplicationProcessMetrics{
		{
			ApplicationID:     1,
			CollectedAt:       now,
			State:             metrics.StateMatched,
			PIDs:              []int64{123},
			ProcessStartTimes: map[int64]time.Time{123: start},
		},
	})

	// Cycle 2: Disappears
	events := detector.Detect(context.Background(), []metrics.ApplicationProcessMetrics{
		{
			ApplicationID:     1,
			CollectedAt:       now.Add(time.Minute),
			State:             metrics.StateNotMatched,
			PIDs:              []int64{},
			ProcessStartTimes: map[int64]time.Time{},
		},
	})

	if len(events) != 1 {
		t.Fatalf("expected 1 event")
	}
	if events[0].EventType != EventProcessDisappeared {
		t.Errorf("expected process_disappeared, got %s", events[0].EventType)
	}
	if *events[0].OldPID != 123 {
		t.Errorf("expected old PID 123")
	}

	// Cycle 3: Still absent (deduplication)
	events2 := detector.Detect(context.Background(), []metrics.ApplicationProcessMetrics{
		{
			ApplicationID:     1,
			CollectedAt:       now.Add(2 * time.Minute),
			State:             metrics.StateNotMatched,
			PIDs:              []int64{},
			ProcessStartTimes: map[int64]time.Time{},
		},
	})
	if len(events2) != 0 {
		t.Fatalf("expected 0 events on repeated absence")
	}
}

func TestDetector_RestartDetected(t *testing.T) {
	detector := NewDetector()

	now := time.Now()
	start1 := now.Add(-time.Hour)
	start2 := now.Add(-time.Minute)

	_ = detector.Detect(context.Background(), []metrics.ApplicationProcessMetrics{
		{
			ApplicationID:     1,
			CollectedAt:       now,
			State:             metrics.StateMatched,
			PIDs:              []int64{123},
			ProcessStartTimes: map[int64]time.Time{123: start1},
		},
	})

	events := detector.Detect(context.Background(), []metrics.ApplicationProcessMetrics{
		{
			ApplicationID:     1,
			CollectedAt:       now.Add(time.Minute),
			State:             metrics.StateMatched,
			PIDs:              []int64{456},
			ProcessStartTimes: map[int64]time.Time{456: start2},
		},
	})

	if len(events) != 1 {
		t.Fatalf("expected 1 event")
	}
	if events[0].EventType != EventRestartDetected {
		t.Errorf("expected restart_detected")
	}
	if *events[0].OldPID != 123 || *events[0].NewPID != 456 {
		t.Errorf("PIDs incorrect")
	}
}

func TestDetector_IdentityChanged(t *testing.T) {
	detector := NewDetector()

	now := time.Now()
	start1 := now.Add(-time.Hour)
	start2 := now.Add(-time.Minute)

	_ = detector.Detect(context.Background(), []metrics.ApplicationProcessMetrics{
		{
			ApplicationID:     1,
			CollectedAt:       now,
			State:             metrics.StateMatched,
			PIDs:              []int64{123},
			ProcessStartTimes: map[int64]time.Time{123: start1},
		},
	})

	// Same PID, new start time
	events := detector.Detect(context.Background(), []metrics.ApplicationProcessMetrics{
		{
			ApplicationID:     1,
			CollectedAt:       now.Add(time.Minute),
			State:             metrics.StateMatched,
			PIDs:              []int64{123},
			ProcessStartTimes: map[int64]time.Time{123: start2},
		},
	})

	if len(events) != 1 {
		t.Fatalf("expected 1 event")
	}
	if events[0].EventType != EventProcessIdentityChanged {
		t.Errorf("expected process_identity_changed, got %s", events[0].EventType)
	}
}

func TestDetector_PartialPermissionUnknown(t *testing.T) {
	detector := NewDetector()
	now := time.Now()

	_ = detector.Detect(context.Background(), []metrics.ApplicationProcessMetrics{
		{
			ApplicationID:     1,
			CollectedAt:       now,
			State:             metrics.StateMatched,
			PIDs:              []int64{123},
			ProcessStartTimes: map[int64]time.Time{123: now},
		},
	})

	// StateUnknown should not trigger disappearance
	events := detector.Detect(context.Background(), []metrics.ApplicationProcessMetrics{
		{
			ApplicationID: 1,
			CollectedAt:   now.Add(time.Minute),
			State:         metrics.StateUnknown,
			PIDs:          []int64{},
		},
	})

	if len(events) != 0 {
		t.Fatalf("expected 0 events for Unknown state")
	}
}

func TestDetector_Cleanup(t *testing.T) {
	detector := NewDetector()
	now := time.Now()

	_ = detector.Detect(context.Background(), []metrics.ApplicationProcessMetrics{
		{
			ApplicationID:     1,
			CollectedAt:       now,
			State:             metrics.StateMatched,
			PIDs:              []int64{123},
			ProcessStartTimes: map[int64]time.Time{123: now},
		},
	})

	// Cleanup app 1
	detector.Cleanup(context.Background(), []int64{2})

	// Introduce app 1 again, it should be an initial observation (no events)
	events := detector.Detect(context.Background(), []metrics.ApplicationProcessMetrics{
		{
			ApplicationID:     1,
			CollectedAt:       now.Add(time.Minute),
			State:             metrics.StateMatched,
			PIDs:              []int64{456},
			ProcessStartTimes: map[int64]time.Time{456: now.Add(time.Minute)},
		},
	})

	if len(events) != 0 {
		t.Fatalf("expected 0 events since state was cleaned up")
	}
}
