package metrics

import (
	"time"
)

type ProcessState string

const (
	StateMatched    ProcessState = "MATCHED"
	StateNotMatched ProcessState = "NOT_MATCHED"
	StateUnknown    ProcessState = "UNKNOWN"
)

// ApplicationProcessMetrics represents the application's aggregated process metrics.
type ApplicationProcessMetrics struct {
	ApplicationID int64        `json:"application_id"`
	CollectedAt   time.Time    `json:"collected_at"`
	State         ProcessState `json:"state"`
	ProcessCount  int          `json:"process_count"`
	PIDs          []int64      `json:"pids"`
	// ProcessStartTimes stores start times per PID for tracking and restart detection.
	ProcessStartTimes map[int64]time.Time `json:"process_start_times,omitempty"`

	CPUPercent    *float64 `json:"cpu_percent,omitempty"`
	MemoryBytes   *uint64  `json:"memory_bytes,omitempty"`
	MemoryPercent *float64 `json:"memory_percent,omitempty"`

	Warnings []string `json:"warnings,omitempty"`
}
