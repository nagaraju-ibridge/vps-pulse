package matcher

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	gops "github.com/shirou/gopsutil/v4/process"
	"vpsmonitoring-agent/internal/application/config"
)

// ProcessState represents the matched state of a process identity.
type ProcessState string

const (
	StateMatched    ProcessState = "MATCHED"
	StateNotMatched ProcessState = "NOT_MATCHED"
	StateUnknown    ProcessState = "UNKNOWN"
)

// ProcessMatchEvidence represents runtime evidence.
type ProcessMatchEvidence struct {
	PID       int64      `json:"pid"`
	ExePath   string     `json:"exe_path,omitempty"`
	StartTime *time.Time `json:"start_time,omitempty"`
}

// ApplicationProcessMatch represents the result of matching an application config.
type ApplicationProcessMatch struct {
	ApplicationID int64                  `json:"application_id"`
	Name          string                 `json:"name"`
	MatchType     string                 `json:"match_type"`
	MatchValue    string                 `json:"match_value"`
	State         ProcessState           `json:"state"`
	Processes     []ProcessMatchEvidence `json:"processes"`
	Reason        string                 `json:"reason,omitempty"`
}

const (
	MaxProcessCount = 300
	CgroupPathFmt   = "/proc/%d/cgroup"
)

type Matcher struct {
	IndexBuilder func(ctx context.Context) processIndex
}

func NewMatcher() *Matcher {
	return &Matcher{
		IndexBuilder: buildIndex,
	}
}

type processIndex struct {
	byExe   map[string][]ProcessMatchEvidence
	byUnit  map[string][]ProcessMatchEvidence
	unknown bool
}

func (m *Matcher) Match(ctx context.Context, configs []config.ApplicationConfig) []ApplicationProcessMatch {
	idx := m.IndexBuilder(ctx)

	var results []ApplicationProcessMatch

	for _, cfg := range configs {
		if !cfg.IsEnabled {
			continue
		}

		match := ApplicationProcessMatch{
			ApplicationID: cfg.ID,
			Name:          cfg.Name,
			MatchType:     cfg.MatchType,
			MatchValue:    cfg.MatchValue,
			Processes:     []ProcessMatchEvidence{},
		}

		var found []ProcessMatchEvidence

		if cfg.MatchType == "exe_path" {
			if cfg.MatchValue == "" {
				match.State = StateUnknown
				match.Reason = "empty executable path"
			} else {
				found = idx.byExe[cfg.MatchValue]
			}
		} else if cfg.MatchType == "systemd_unit" {
			if cfg.MatchValue == "" {
				match.State = StateUnknown
				match.Reason = "empty systemd unit"
			} else {
				found = idx.byUnit[cfg.MatchValue]
			}
		} else {
			match.State = StateUnknown
			match.Reason = fmt.Sprintf("unsupported match_type: %s", cfg.MatchType)
			results = append(results, match)
			continue
		}

		if match.State != StateUnknown {
			if len(found) > 0 {
				match.State = StateMatched
				match.Processes = found
			} else {
				if idx.unknown {
					// If we had permission errors reading processes, we might have missed it
					match.State = StateUnknown
					match.Reason = "insufficient permissions to enumerate all processes"
				} else {
					match.State = StateNotMatched
					match.Reason = "no matching process found"
				}
			}
		}

		results = append(results, match)
	}

	return results
}

func buildIndex(ctx context.Context) processIndex {
	idx := processIndex{
		byExe:  make(map[string][]ProcessMatchEvidence),
		byUnit: make(map[string][]ProcessMatchEvidence),
	}

	procs, err := gops.ProcessesWithContext(ctx)
	if err != nil {
		log.Printf("[WARN] matcher process enumeration failed: %v", err)
		idx.unknown = true
		return idx
	}

	// Deterministic sorting by PID
	sort.Slice(procs, func(i, j int) bool { return procs[i].Pid < procs[j].Pid })

	count := 0
	for _, p := range procs {
		if count >= MaxProcessCount {
			break
		}

		// We ignore the context for individual getters as they use system files.
		exe, err := p.ExeWithContext(ctx)
		if err != nil {
			// Permission denied is common, don't flag the entire index as unknown just for one process,
			// but we will mark unknown if we are running as an unprivileged user and fail a lot.
			// However, the requirements state: "If executable path cannot be obtained because of permissions:
			// record insufficient-permission/unknown evidence rather than falsely declaring the application DOWN."
			// We flag the global index as having partial visibility.
			idx.unknown = true
		}

		createTime, _ := p.CreateTimeWithContext(ctx)
		var startTime *time.Time
		if createTime > 0 {
			st := time.UnixMilli(createTime).UTC()
			startTime = &st
		}

		ev := ProcessMatchEvidence{
			PID:       int64(p.Pid),
			ExePath:   exe,
			StartTime: startTime,
		}

		if exe != "" {
			idx.byExe[exe] = append(idx.byExe[exe], ev)
		}

		// Attempt to extract systemd unit from cgroup
		unit := extractSystemdUnitFromCgroup(p.Pid)
		if unit != "" {
			idx.byUnit[unit] = append(idx.byUnit[unit], ev)
		}

		count++
	}

	return idx
}

// extractSystemdUnitFromCgroup reads /proc/<pid>/cgroup to find the systemd unit.
func extractSystemdUnitFromCgroup(pid int32) string {
	path := fmt.Sprintf(CgroupPathFmt, pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		// Example cgroup v1: 1:name=systemd:/system.slice/nginx.service
		// Example cgroup v2: 0::/system.slice/nginx.service
		if strings.Contains(line, ".service") {
			parts := strings.Split(line, "/")
			for _, part := range parts {
				if strings.HasSuffix(part, ".service") {
					return part
				}
			}
		}
	}
	return ""
}
