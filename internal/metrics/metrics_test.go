package metrics_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"vpsmonitoring-agent/internal/metrics/collector"
	"vpsmonitoring-agent/internal/metrics/models"
)

// TEST 1 — CPU collector
func TestCPUCollector(t *testing.T) {
	c := collector.NewCPUCollector()
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error collecting CPU metrics: %v", err)
	}

	if metrics.Cores <= 0 {
		t.Errorf("expected CPU cores > 0, got %d", metrics.Cores)
	}

	if metrics.UsagePercent < 0 || metrics.UsagePercent > 100 {
		t.Errorf("expected CPU usage percent between 0 and 100, got %f", metrics.UsagePercent)
	}

	// Load averages may be 0 on Windows, but should not panic or be negative
	if metrics.Load1 < 0 || metrics.Load5 < 0 || metrics.Load15 < 0 {
		t.Errorf("unexpected negative load average: %+v", metrics)
	}
}

// TEST 2 — Memory collector
func TestMemoryCollector(t *testing.T) {
	c := collector.NewMemoryCollector()
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error collecting memory metrics: %v", err)
	}

	if metrics.Total == 0 {
		t.Errorf("expected Total memory > 0, got %d", metrics.Total)
	}

	if metrics.UsagePercent < 0 || metrics.UsagePercent > 100 {
		t.Errorf("expected memory usage percent between 0 and 100, got %f", metrics.UsagePercent)
	}
}

// TEST 3 — Swap collector
func TestSwapCollector(t *testing.T) {
	c := collector.NewSwapCollector()
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error collecting swap metrics: %v", err)
	}

	// When swap is present
	if metrics.Total > 0 {
		if metrics.UsagePercent < 0 || metrics.UsagePercent > 100 {
			t.Errorf("expected swap usage percent between 0 and 100, got %f", metrics.UsagePercent)
		}
	} else {
		// When swap is disabled or 0, verify safe representation
		if metrics.Total != 0 || metrics.Used != 0 || metrics.Free != 0 || metrics.UsagePercent != 0 {
			t.Errorf("expected safe zero values when swap is 0, got %+v", metrics)
		}
	}
}

// TEST 4 — Disk collector
func TestDiskCollector(t *testing.T) {
	c := collector.NewDiskCollector()
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error collecting disk metrics: %v", err)
	}

	if len(metrics.MountPoints) == 0 {
		t.Log("Note: No non-virtual mount points discovered on this host environment.")
	}

	for _, mp := range metrics.MountPoints {
		if mp.Path == "" {
			t.Errorf("mount point path should not be empty")
		}
		if mp.Total == 0 {
			t.Errorf("mount point %s total space should not be 0", mp.Path)
		}
		if mp.UsagePercent < 0 || mp.UsagePercent > 100 {
			t.Errorf("mount point %s usage percent out of range: %f", mp.Path, mp.UsagePercent)
		}
	}
}

// TEST 5 — Network collector
func TestNetworkCollector(t *testing.T) {
	c := collector.NewNetworkCollector()
	metrics, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error collecting network metrics: %v", err)
	}

	// Basic sanity checks: counters shouldn't cause errors or negative behavior
	t.Logf("Network collected: RXBytes=%d, TXBytes=%d, RXPackets=%d, TXPackets=%d, Errors=%d, Drops=%d",
		metrics.RXBytes, metrics.TXBytes, metrics.RXPackets, metrics.TXPackets, metrics.Errors, metrics.Drops)
}

// TEST 6 — Complete snapshot
func TestCompleteSnapshot(t *testing.T) {
	sc := collector.NewSnapshotCollector()
	snapshot := sc.CollectSnapshot(context.Background())

	if snapshot.Timestamp.IsZero() {
		t.Errorf("expected non-zero timestamp")
	}

	if snapshot.CPU.Cores <= 0 {
		t.Errorf("expected CPU cores > 0 in snapshot, got %d", snapshot.CPU.Cores)
	}

	if snapshot.Memory.Total <= 0 {
		t.Errorf("expected Total memory > 0 in snapshot, got %d", snapshot.Memory.Total)
	}
}

// TEST 7 — Timestamp is UTC
func TestSnapshotTimestampUTC(t *testing.T) {
	sc := collector.NewSnapshotCollector()
	before := time.Now().UTC().Add(-1 * time.Second)
	snapshot := sc.CollectSnapshot(context.Background())
	after := time.Now().UTC().Add(1 * time.Second)

	if snapshot.Timestamp.Location() != time.UTC {
		t.Errorf("expected timestamp in UTC location, got %v", snapshot.Timestamp.Location())
	}

	if snapshot.Timestamp.Before(before) || snapshot.Timestamp.After(after) {
		t.Errorf("snapshot timestamp %v not within expected range [%v, %v]", snapshot.Timestamp, before, after)
	}
}

// TEST 8 — Collector failure handling
type failingCollector struct{}

func (f *failingCollector) Collect(ctx context.Context) (models.CPUMetrics, error) {
	return models.CPUMetrics{}, errors.New("simulated cpu failure")
}

func TestCollectorFailureHandling(t *testing.T) {
	sc := collector.NewCustomSnapshotCollector(
		&failingCollector{},
		collector.NewMemoryCollector(),
		collector.NewSwapCollector(),
		collector.NewDiskCollector(),
		collector.NewNetworkCollector(),
	)

	// Must not panic even if a collector fails
	snapshot := sc.CollectSnapshot(context.Background())

	if len(snapshot.Errors) == 0 {
		t.Errorf("expected error recorded for failing CPU collector, got none")
	}

	// Memory should still succeed despite CPU failure
	if snapshot.Memory.Total == 0 {
		t.Errorf("expected memory collection to succeed despite CPU failure")
	}
}

// TEST 9 — Snapshot consistency
func TestSnapshotConsistency(t *testing.T) {
	sc := collector.NewSnapshotCollector()
	snapshot := sc.CollectSnapshot(context.Background())

	// Memory used + available should be roughly in bounds with total
	if snapshot.Memory.Total > 0 {
		if snapshot.Memory.Used > snapshot.Memory.Total {
			t.Errorf("used memory %d cannot exceed total memory %d", snapshot.Memory.Used, snapshot.Memory.Total)
		}
	}
}
