package collector

import (
	"context"
	"strings"

	"github.com/shirou/gopsutil/v4/net"

	"vpsmonitoring-agent/internal/metrics/models"
)

// NetworkCollector defines the interface for collecting aggregate network counters.
type NetworkCollector interface {
	Collect(ctx context.Context) (models.NetworkMetrics, error)
}

type defaultNetworkCollector struct{}

// NewNetworkCollector returns a new instance of NetworkCollector using gopsutil.
func NewNetworkCollector() NetworkCollector {
	return &defaultNetworkCollector{}
}

// isIgnoredInterface determines if an interface should be excluded from aggregate counters (e.g. loopback).
func isIgnoredInterface(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, "lo") ||
		strings.Contains(lower, "loopback")
}

func (c *defaultNetworkCollector) Collect(ctx context.Context) (models.NetworkMetrics, error) {
	var metrics models.NetworkMetrics

	// Per-interface stats (pernic=true) to allow filtering loopback
	ioCounters, err := net.IOCountersWithContext(ctx, true)
	if err != nil {
		return metrics, err
	}

	for _, io := range ioCounters {
		if isIgnoredInterface(io.Name) {
			continue
		}

		metrics.RXBytes += io.BytesRecv
		metrics.TXBytes += io.BytesSent
		metrics.RXPackets += io.PacketsRecv
		metrics.TXPackets += io.PacketsSent
		metrics.Errors += (io.Errin + io.Errout)
		metrics.Drops += (io.Dropin + io.Dropout)
	}

	return metrics, nil
}
