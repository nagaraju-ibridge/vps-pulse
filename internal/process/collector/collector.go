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
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	gops "github.com/shirou/gopsutil/v4/process"

	"vpsmonitoring-agent/internal/process/models"
)

const (
	// MaxProcessCount is the hard upper bound on the number of processes returned
	// per collection. This bounds both memory usage and payload size.
	MaxProcessCount = 500

	// collectionTimeout is the maximum wall-clock time the collector may spend
	// enumerating processes before returning whatever it has collected so far.
	collectionTimeout = 15 * time.Second
)

// fast user cache across process enumeration cycles
var (
	userCache   = make(map[uint32]string)
	userCacheMu sync.RWMutex
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

// Collect enumerates running processes concurrently with a worker pool.
//
// totalMemBytes is the system's total physical RAM in bytes, used to compute
// MemoryPercent. Pass 0 if unknown; MemoryPercent will then be nil.
func (c *defaultProcessCollector) Collect(ctx context.Context, totalMemBytes uint64) models.ProcessPayload {
	payload := models.ProcessPayload{
		CollectedAt: time.Now().UTC(),
		Processes:   make([]models.ProcessSnapshot, 0, MaxProcessCount),
	}

	// Enforce a collection timeout independently of the parent context.
	collectCtx, cancel := context.WithTimeout(ctx, collectionTimeout)
	defer cancel()

	procs, err := c.lister(collectCtx)
	if err != nil {
		log.Printf("[WARN] process enumeration failed: %v", err)
		return payload
	}
	log.Printf("[DEBUG] ProcessCollector: enumerated %d processes", len(procs))

	now := time.Now().UTC()

	numWorkers := 16
	if len(procs) < numWorkers {
		numWorkers = len(procs)
	}
	if numWorkers == 0 {
		return payload
	}

	procChan := make(chan *gops.Process, len(procs))
	for _, p := range procs {
		procChan <- p
	}
	close(procChan)

	var wg sync.WaitGroup
	var mu sync.Mutex
	collected := make([]models.ProcessSnapshot, 0, len(procs))

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range procChan {
				select {
				case <-collectCtx.Done():
					return
				default:
				}

				snap, ok := collectProcess(collectCtx, p, totalMemBytes, now)
				if !ok {
					continue
				}

				mu.Lock()
				if len(collected) < MaxProcessCount {
					collected = append(collected, snap)
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	payload.Processes = collected
	log.Printf("[DEBUG] ProcessCollector: retained %d processes", len(payload.Processes))
	return payload
}

// collectProcess builds a ProcessSnapshot for a single gopsutil process.
func collectProcess(ctx context.Context, p *gops.Process, totalMemBytes uint64, now time.Time) (models.ProcessSnapshot, bool) {
	// --- Required: PID --------------------------------------------------
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
	if cpuPct, err := p.CPUPercentWithContext(ctx); err == nil && cpuPct > 0 {
		snap.CPUPercent = &cpuPct
	} else if cpuPct, err := p.PercentWithContext(ctx, 0); err == nil {
		snap.CPUPercent = &cpuPct
	}

	// --- Optional: User (with high-speed in-memory cache) ----------------
	if uids, err := p.UidsWithContext(ctx); err == nil && len(uids) > 0 {
		uid := uids[0]
		userCacheMu.RLock()
		uName, ok := userCache[uid]
		userCacheMu.RUnlock()
		if ok {
			snap.User = uName
		} else {
			if u, err := user.LookupId(strconv.Itoa(int(uid))); err == nil && u != nil {
				userCacheMu.Lock()
				userCache[uid] = u.Username
				userCacheMu.Unlock()
				snap.User = u.Username
			} else if uname, err := p.UsernameWithContext(ctx); err == nil && uname != "" {
				userCacheMu.Lock()
				userCache[uid] = uname
				userCacheMu.Unlock()
				snap.User = uname
			}
		}
	} else if u, err := p.UsernameWithContext(ctx); err == nil && u != "" {
		snap.User = u
	}

	// --- Optional: MemoryBytes + MemoryPercent + VirtBytes --------------
	if memInfo, err := p.MemoryInfoWithContext(ctx); err == nil && memInfo != nil {
		rss := memInfo.RSS
		snap.MemoryBytes = &rss

		vms := memInfo.VMS
		snap.VirtBytes = &vms

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
		startTime := time.UnixMilli(createMs).UTC()
		snap.StartTime = &startTime

		uptimeSec := int64(now.Sub(startTime).Seconds())
		if uptimeSec < 0 {
			uptimeSec = 0
		}
		snap.UptimeSeconds = &uptimeSec
	}

	// --- Optional: Threads ----------------------------------------------
	if threads, err := p.NumThreadsWithContext(ctx); err == nil {
		t := int32(threads)
		snap.Threads = &t
	}

	// --- Optional: Command Line -----------------------------------------
	if cmd, err := p.CmdlineWithContext(ctx); err == nil && cmd != "" {
		fields := strings.Fields(cmd)
		if len(fields) > 0 {
			snap.Cmdline = filepath.Base(fields[0])
		} else {
			snap.Cmdline = cmd
		}
	} else {
		snap.Cmdline = name
	}

	return snap, true
}
