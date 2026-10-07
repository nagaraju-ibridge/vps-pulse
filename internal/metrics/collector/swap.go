package collector

import (
	"context"

	"github.com/shirou/gopsutil/v4/mem"

	"vpsmonitoring-agent/internal/metrics/models"
)

// SwapCollector defines the interface for collecting swap memory statistics.
type SwapCollector interface {
	Collect(ctx context.Context) (models.SwapMetrics, error)
}

type defaultSwapCollector struct{}

// NewSwapCollector returns a new instance of SwapCollector using gopsutil.
func NewSwapCollector() SwapCollector {
	return &defaultSwapCollector{}
}

func (c *defaultSwapCollector) Collect(ctx context.Context) (models.SwapMetrics, error) {
	var metrics models.SwapMetrics

	swapMem, err := mem.SwapMemoryWithContext(ctx)
	if err != nil {
		// If swap cannot be inspected or is not present, return safe zero values
		return models.SwapMetrics{
			Total:        0,
			Used:         0,
			Free:         0,
			UsagePercent: 0,
		}, nil
	}

	metrics.Total = swapMem.Total
	metrics.Used = swapMem.Used
	metrics.Free = swapMem.Free

	// Safe handling for systems where swap is disabled or Total == 0
	if metrics.Total > 0 {
		metrics.UsagePercent = (float64(metrics.Used) / float64(metrics.Total)) * 100.0
	} else {
		metrics.UsagePercent = 0.0
	}

	return metrics, nil
}
