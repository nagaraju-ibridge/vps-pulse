package collector

import (
	"context"
	"fmt"
	"time"

	"vpsmonitoring-agent/internal/metrics/models"
)

// SnapshotCollector coordinates individual collectors and builds a complete MetricSnapshot.
type SnapshotCollector interface {
	CollectSnapshot(ctx context.Context) models.MetricSnapshot
}

type defaultSnapshotCollector struct {
	cpu     CPUCollector
	memory  MemoryCollector
	swap    SwapCollector
	disk    DiskCollector
	network NetworkCollector
}

// NewSnapshotCollector constructs a SnapshotCollector with the default gopsutil implementations.
func NewSnapshotCollector() SnapshotCollector {
	return &defaultSnapshotCollector{
		cpu:     NewCPUCollector(),
		memory:  NewMemoryCollector(),
		swap:    NewSwapCollector(),
		disk:    NewDiskCollector(),
		network: NewNetworkCollector(),
	}
}

// NewCustomSnapshotCollector constructs a SnapshotCollector with custom or mocked collectors for testability.
func NewCustomSnapshotCollector(
	cpu CPUCollector,
	memory MemoryCollector,
	swap SwapCollector,
	disk DiskCollector,
	network NetworkCollector,
) SnapshotCollector {
	return &defaultSnapshotCollector{
		cpu:     cpu,
		memory:  memory,
		swap:    swap,
		disk:    disk,
		network: network,
	}
}

// CollectSnapshot collects system metrics across all subsystems into a single unified MetricSnapshot.
// Individual failures are recorded in the Errors field without crashing or aborting other collectors.
func (s *defaultSnapshotCollector) CollectSnapshot(ctx context.Context) models.MetricSnapshot {
	snapshot := models.MetricSnapshot{
		Timestamp: time.Now().UTC(),
		Errors:    make([]string, 0),
	}

	// 1. CPU
	if s.cpu != nil {
		cpuMetrics, err := s.cpu.Collect(ctx)
		if err != nil {
			snapshot.Errors = append(snapshot.Errors, fmt.Sprintf("cpu collection: %v", err))
		} else {
			snapshot.CPU = cpuMetrics
		}
	}

	// 2. Memory
	if s.memory != nil {
		memMetrics, err := s.memory.Collect(ctx)
		if err != nil {
			snapshot.Errors = append(snapshot.Errors, fmt.Sprintf("memory collection: %v", err))
		} else {
			snapshot.Memory = memMetrics
		}
	}

	// 3. Swap
	if s.swap != nil {
		swapMetrics, err := s.swap.Collect(ctx)
		if err != nil {
			snapshot.Errors = append(snapshot.Errors, fmt.Sprintf("swap collection: %v", err))
		} else {
			snapshot.Swap = swapMetrics
		}
	}

	// 4. Disk
	if s.disk != nil {
		diskMetrics, err := s.disk.Collect(ctx)
		if err != nil {
			snapshot.Errors = append(snapshot.Errors, fmt.Sprintf("disk collection: %v", err))
		} else {
			snapshot.Disk = diskMetrics
		}
	}

	// 5. Network
	if s.network != nil {
		netMetrics, err := s.network.Collect(ctx)
		if err != nil {
			snapshot.Errors = append(snapshot.Errors, fmt.Sprintf("network collection: %v", err))
		} else {
			snapshot.Network = netMetrics
		}
	}

	return snapshot
}
