package metrics

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/mem"
	gops "github.com/shirou/gopsutil/v4/process"
	"vpsmonitoring-agent/internal/application/matcher"
)

type ProcessMetricsCollector interface {
	Collect(ctx context.Context, matches []matcher.ApplicationProcessMatch) []ApplicationProcessMetrics
}

type osProvider interface {
	TotalMemory(ctx context.Context) (uint64, error)
	ProcessCPU(ctx context.Context, pid int32) (float64, error)
	ProcessRSS(ctx context.Context, pid int32) (uint64, error)
}

type cpuProcess interface {
	PercentWithContext(ctx context.Context, interval time.Duration) (float64, error)
}

type defaultOSProvider struct {
	mu         sync.Mutex
	processes  map[int32]cpuProcess
	newProcess func(context.Context, int32) (cpuProcess, error)
}

func newDefaultOSProvider() *defaultOSProvider {
	return &defaultOSProvider{
		processes: make(map[int32]cpuProcess),
		newProcess: func(ctx context.Context, pid int32) (cpuProcess, error) {
			return gops.NewProcessWithContext(ctx, pid)
		},
	}
}

func (p *defaultOSProvider) TotalMemory(ctx context.Context) (uint64, error) {
	v, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return 0, err
	}
	return v.Total, nil
}

func (p *defaultOSProvider) ProcessCPU(ctx context.Context, pid int32) (float64, error) {
	// gopsutil's non-blocking Percent call compares against state retained on
	// the Process instance. Recreating it for every collection makes every
	// poll a first poll, which always returns zero.
	p.mu.Lock()
	proc, ok := p.processes[pid]
	if !ok {
		var err error
		proc, err = p.newProcess(ctx, pid)
		if err != nil {
			p.mu.Unlock()
			return 0, err
		}
		p.processes[pid] = proc
	}
	p.mu.Unlock()

	percent, err := proc.PercentWithContext(ctx, 0)
	if err != nil {
		// Drop stale state so a disappeared or PID-reused process can be
		// initialized cleanly on the next collection.
		p.mu.Lock()
		if p.processes[pid] == proc {
			delete(p.processes, pid)
		}
		p.mu.Unlock()
	}
	return percent, err
}

func (p *defaultOSProvider) ProcessRSS(ctx context.Context, pid int32) (uint64, error) {
	proc, err := gops.NewProcessWithContext(ctx, pid)
	if err != nil {
		return 0, err
	}
	memInfo, err := proc.MemoryInfoWithContext(ctx)
	if err != nil {
		return 0, err
	}
	return memInfo.RSS, nil
}

type defaultCollector struct {
	os osProvider
}

func NewCollector() ProcessMetricsCollector {
	return &defaultCollector{os: newDefaultOSProvider()}
}

// NewCollectorWithProvider allows test injection
func NewCollectorWithProvider(provider osProvider) ProcessMetricsCollector {
	return &defaultCollector{os: provider}
}

func (c *defaultCollector) Collect(ctx context.Context, matches []matcher.ApplicationProcessMatch) []ApplicationProcessMetrics {
	var totalMem uint64
	if v, err := c.os.TotalMemory(ctx); err == nil {
		totalMem = v
	} else {
		log.Printf("[WARN] application metrics: failed to get system memory: %v", err)
	}

	results := make([]ApplicationProcessMetrics, 0, len(matches))
	now := time.Now().UTC()

	for _, match := range matches {
		appMetrics := ApplicationProcessMetrics{
			ApplicationID:     match.ApplicationID,
			CollectedAt:       now,
			State:             ProcessState(match.State),
			ProcessCount:      0,
			PIDs:              []int64{},
			ProcessStartTimes: make(map[int64]time.Time),
			Warnings:          []string{},
		}

		if match.State != matcher.StateMatched {
			// If not matched or unknown, no process metrics to collect.
			results = append(results, appMetrics)
			continue
		}

		var totalCPU float64
		var totalRSS uint64
		var validCPUCount int
		var validRSSCount int

		for _, proc := range match.Processes {
			pid := int32(proc.PID)
			appMetrics.PIDs = append(appMetrics.PIDs, proc.PID)
			if proc.StartTime != nil {
				appMetrics.ProcessStartTimes[proc.PID] = *proc.StartTime
			}

			// CPU
			cpu, err := c.os.ProcessCPU(ctx, pid)
			if err != nil {
				appMetrics.Warnings = append(appMetrics.Warnings, fmt.Sprintf("failed to read CPU for PID %d", pid))
			} else {
				totalCPU += cpu
				validCPUCount++
			}

			// RSS
			rss, err := c.os.ProcessRSS(ctx, pid)
			if err != nil {
				appMetrics.Warnings = append(appMetrics.Warnings, fmt.Sprintf("failed to read RSS for PID %d", pid))
			} else {
				totalRSS += rss
				validRSSCount++
			}
		}

		appMetrics.ProcessCount = len(match.Processes)

		if validCPUCount > 0 {
			cpuCopy := totalCPU
			appMetrics.CPUPercent = &cpuCopy
		}

		if validRSSCount > 0 {
			rssCopy := totalRSS
			appMetrics.MemoryBytes = &rssCopy

			if totalMem > 0 {
				memPct := (float64(totalRSS) / float64(totalMem)) * 100.0
				appMetrics.MemoryPercent = &memPct
			}
		}

		results = append(results, appMetrics)
	}

	return results
}
