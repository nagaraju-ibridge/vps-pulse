package collector

import (
	"context"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/load"

	"vpsmonitoring-agent/internal/metrics/models"
)

// CPUCollector defines the interface for collecting CPU statistics.
type CPUCollector interface {
	Collect(ctx context.Context) (models.CPUMetrics, error)
}

type defaultCPUCollector struct{}

// NewCPUCollector returns a new instance of CPUCollector using gopsutil.
func NewCPUCollector() CPUCollector {
	return &defaultCPUCollector{}
}

func (c *defaultCPUCollector) Collect(ctx context.Context) (models.CPUMetrics, error) {
	var metrics models.CPUMetrics

	// Logical core count
	cores, err := cpu.CountsWithContext(ctx, true)
	if err == nil {
		metrics.Cores = cores
	}

	// Overall CPU utilization percentage (0 interval uses last sample / delta calculation without long block)
	// gopsutil cpu.PercentWithContext with interval=0 calculates usage since last call or boot
	percents, err := cpu.PercentWithContext(ctx, 0, false)
	if err == nil && len(percents) > 0 {
		metrics.UsagePercent = percents[0]
	}

	// Load averages (1, 5, 15 min)
	// On Windows, load average is often unsupported by the OS; gopsutil returns error or 0s gracefully
	avg, err := load.AvgWithContext(ctx)
	if err == nil && avg != nil {
		metrics.Load1 = avg.Load1
		metrics.Load5 = avg.Load5
		metrics.Load15 = avg.Load15
	}

	return metrics, nil
}
