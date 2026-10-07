// Package collector provides a read-only process collector using gopsutil.
//
// Design decisions (Phase 3.4A / 3.4A.1):
//
//   - Maximum 200 processes per collection (MaxProcessCount).
//   - Collection timeout is enforced via the caller-supplied context; a separate
//     2-second sub-context is created internally so the caller always gets a result
//     even if the parent context has a longer deadline.
//   - PID and Name are required fields.  Any process for which either cannot be
//     obtained is silently skipped.
//   - All other fields (CPU %, memory, status, threads, parent PID, start time,
//     uptime) are nullable.  When an individual gopsutil call fails the field is
//     set to nil; the process entry is retained.
//   - CPU percentage is stored raw (may exceed 100 % on multi-core hosts). No
//     clamping is applied.
//   - No cmdline, environ, open files, connections, or any secret data is read.
//   - No process is killed, signalled, or otherwise mutated.
package collector

import (
	"context"
	"log"
	"time"

	gops "github.com/shirou/gopsutil/v4/process"

	"vpsmonitoring-agent/internal/process/models"
)

const (
	// MaxProcessCount is the hard upper bound on the number of processes returned
	// per collection. This bounds both memory usage and payload size.
	MaxProcessCount = 200

	// collectionTimeout is the maximum wall-clock time the collector may spend
	// enumerating processes before returning whatever it has collected so far.
	collectionTimeout = 2 * time.Second
)

// ProcessCollector defines the interface for collecting a process snapshot.
// It is deliberately narrow so that tests can substitute a mock implementation.
type ProcessCollector interface {
	// Collect enumerates running processes and returns a ProcessPayload.
	// The payload always contains a non-nil Processes slice (possibly empty).
	// Errors that affect individual processes are handled internally; the
	// collector never returns a top-level error for partial failures.
	Collect(ctx context.Context, totalMemBytes uint64) models.ProcessPayload
}

// processLister abstracts the gopsutil call so tests can inject a fake.
type processLister func(ctx context.Context) ([]*gops.Process, error)

type defaultProcessCollector struct {
	lister processLister
}

// NewProcessCollector returns a ProcessCollector backed by gopsutil.
func NewProcessCollector() ProcessCollector {
	return &defaultProcessCollector{
		lister: func(ctx context.Context) ([]*gops.Process, error) {
			return gops.ProcessesWithContext(ctx)
		},
	}
}

// NewProcessCollectorWithLister constructs a ProcessCollector that uses the
// supplied lister function instead of gopsutil. This is the testability seam
// that allows unit tests to inject deterministic process lists or error
// conditions without spawning real OS processes.
func NewProcessCollectorWithLister(l func(ctx context.Context) ([]*gops.Process, error)) ProcessCollector {
	return &defaultProcessCollector{lister: l}
}

// Collect enumerates running processes under a bounded 2-second timeout.
//
// totalMemBytes is the system's total physical RAM in bytes, used to compute
// MemoryPercent. Pass 0 if unknown; MemoryPercent will then be nil.
func (c *defaultProcessCollector) Collect(ctx context.Context, totalMemBytes uint64) models.ProcessPayload {
	payload := models.ProcessPayload{
		CollectedAt: time.Now().UTC(),
		Processes:   make([]models.ProcessSnapshot, 0, MaxProcessCount),
	}

	// Enforce a hard collection timeout independently of the parent context.
	collectCtx, cancel := context.WithTimeout(ctx, collectionTimeout)
	defer cancel()

	procs, err := c.lister(collectCtx)
	if err != nil {
		log.Printf("[WARN] process enumeration failed: %v", err)
		return payload
	}
	log.Printf("[DEBUG] ProcessCollector: enumerated %d processes", len(procs))

	now := time.Now().UTC()

	for _, p := range procs {
		// Enforce hard cap to bound memory and payload size.
		if len(payload.Processes) >= MaxProcessCount {
			break
		}

		// Check context deadline: stop early rather than blocking.
		select {
		case <-collectCtx.Done():
			log.Printf("[WARN] process collection timeout reached after %d processes; returning partial snapshot",
				len(payload.Processes))
			return payload
		default:
		}

		snap, ok := collectProcess(collectCtx, p, totalMemBytes, now)
		if !ok {
			// PID or Name unavailable; skip this entry entirely.
			continue
		}

		payload.Processes = append(payload.Processes, snap)
	}

	log.Printf("[DEBUG] ProcessCollector: retained %d processes", len(payload.Processes))
	return payload
}

// collectProcess builds a ProcessSnapshot for a single gopsutil process.
//
// Returns (snapshot, true) when PID and Name are available.
// Returns (zero, false) when either required field cannot be obtained.
// For all optional fields, individual failures result in nil, not an omission.
func collectProcess(ctx context.Context, p *gops.Process, totalMemBytes uint64, now time.Time) (models.ProcessSnapshot, bool) {
	// --- Required: PID --------------------------------------------------
	// gopsutil Process.Pid is a public int32 field; no error is returned.
	pid := int64(p.Pid)

	// --- Required: Name -------------------------------------------------
	name, err := p.NameWithContext(ctx)
	if err != nil {
		log.Printf("[DEBUG] ProcessCollector: PID %d NameWithContext error: %v", pid, err)
	}
	if err != nil || name == "" {
		name = "<unknown>"
	}

	snap := models.ProcessSnapshot{
		PID:  pid,
		Name: name,
	}

	// --- Optional: ParentPID --------------------------------------------
	if ppid, err := p.PpidWithContext(ctx); err == nil {
		v := int64(ppid)
		snap.ParentPID = &v
	}

	// --- Optional: CPUPercent -------------------------------------------
	// Percent(0) returns instantaneous usage since the last call for this
	// PID (or since boot on the first call). Values may exceed 100% on
	// multi-core systems. We do NOT clamp.
	if cpuPct, err := p.PercentWithContext(ctx, 0); err == nil {
		snap.CPUPercent = &cpuPct
	}

	// --- Optional: MemoryBytes + MemoryPercent --------------------------
	if memInfo, err := p.MemoryInfoWithContext(ctx); err == nil && memInfo != nil {
		rss := memInfo.RSS
		snap.MemoryBytes = &rss

		if totalMemBytes > 0 {
			pct := (float64(rss) / float64(totalMemBytes)) * 100.0
			snap.MemoryPercent = &pct
		}
	}

	// --- Optional: Status -----------------------------------------------
	if statuses, err := p.StatusWithContext(ctx); err == nil && len(statuses) > 0 {
		s := statuses[0]
		snap.Status = &s
	}

	// --- Optional: StartTime + UptimeSeconds ----------------------------
	if createMs, err := p.CreateTimeWithContext(ctx); err == nil {
		// gopsutil returns Unix milliseconds.
		startTime := time.UnixMilli(createMs).UTC()
		snap.StartTime = &startTime

		uptimeSec := int64(now.Sub(startTime).Seconds())
		if uptimeSec < 0 {
			uptimeSec = 0 // Guard against clock skew.
		}
		snap.UptimeSeconds = &uptimeSec
	}

	// --- Optional: Threads ----------------------------------------------
	if threads, err := p.NumThreadsWithContext(ctx); err == nil {
		t := int32(threads)
		snap.Threads = &t
	}

	return snap, true
}
