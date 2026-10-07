package collector

import (
	"context"

	"github.com/shirou/gopsutil/v4/mem"

	"vpsmonitoring-agent/internal/metrics/models"
)

// MemoryCollector defines the interface for collecting system RAM statistics.
type MemoryCollector interface {
	Collect(ctx context.Context) (models.MemoryMetrics, error)
}

type defaultMemoryCollector struct{}

// NewMemoryCollector returns a new instance of MemoryCollector using gopsutil.
func NewMemoryCollector() MemoryCollector {
	return &defaultMemoryCollector{}
}

func (c *defaultMemoryCollector) Collect(ctx context.Context) (models.MemoryMetrics, error) {
	var metrics models.MemoryMetrics

	vMem, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return metrics, err
	}

	metrics.Total = vMem.Total
	metrics.Used = vMem.Used
	metrics.Available = vMem.Available

	if metrics.Total > 0 {
		// Use calculated used percent from Used/Total or vMem.UsedPercent
		metrics.UsagePercent = (float64(metrics.Used) / float64(metrics.Total)) * 100.0
	}

	return metrics, nil
}
