// Package models defines the data structures for process monitoring snapshots.
//
// Design constraints (Phase 3.4A / 3.4A.1 decisions):
//   - PID and Name are required; all other fields are nullable.
//   - No cmdline, environment variables, open files, sockets, or secrets are collected.
//   - CPU percentage is stored raw and may exceed 100% on multi-core systems.
//   - collected_at is set by the agent at the start of collection (UTC).
//
// omitempty semantics (agent → backend POST):
//
//	Optional fields on ProcessSnapshot use `omitempty`. This means that when
//	a field is nil (e.g. CPUPercent could not be read), it is omitted from
//	the agent POST body rather than serialised as JSON null. This is
//	intentional: it keeps the agent payload compact.
//
//	The backend's user-facing API (GET /processes) must normalise absent
//	optional fields back to explicit JSON null in the user response DTO so
//	that frontend consumers receive a stable, predictable schema regardless
//	of whether the agent omitted a field.
package models

import "time"

// ProcessSnapshot represents a single read-only view of one running process.
//
// Required fields:
//
//	PID  - always present; entry is omitted if PID cannot be read.
//	Name - always present; entry is omitted if Name cannot be read.
//
// Optional fields:
//
//	All remaining fields are pointers. A nil value means the information
//	was unavailable (e.g., permission denied, process disappeared).
//
// CPU semantics:
//
//	CPUPercent is the instantaneous CPU usage from gopsutil Percent(0).
//	On multi-core hosts it may exceed 100%. Values are never clamped.
//	The first reading for a PID may be 0 or unreliable; this is expected.
//
// Memory units:
//
//	MemoryBytes - Resident Set Size (RSS) in bytes.
//	MemoryPercent - (RSS / total RAM) * 100, computed by the collector.
//
// Time units:
//
//	StartTime     - UTC timestamp of process creation.
//	UptimeSeconds - seconds elapsed since StartTime, as an integer.
type ProcessSnapshot struct {
	// PID is the operating-system process identifier. Required.
	PID int64 `json:"pid"`

	// ParentPID is the PID of the parent process. Nil when unavailable.
	ParentPID *int64 `json:"parent_pid,omitempty"`

	// Name is the process executable name (e.g. "nginx"). Required.
	Name string `json:"name"`

	// CPUPercent is the raw CPU usage percentage. Nil when unavailable.
	// Values may exceed 100% on multi-core systems; they are NOT clamped.
	CPUPercent *float64 `json:"cpu_percent,omitempty"`

	// MemoryBytes is the RSS in bytes. Nil when unavailable.
	MemoryBytes *uint64 `json:"memory_bytes,omitempty"`

	// MemoryPercent is (RSS / total RAM) * 100. Nil when unavailable.
	MemoryPercent *float64 `json:"memory_percent,omitempty"`

	// Status is the process state string (e.g. "R", "S", "T"). Nil when unavailable.
	Status *string `json:"status,omitempty"`

	// StartTime is the UTC timestamp at which the process was created. Nil when unavailable.
	StartTime *time.Time `json:"start_time,omitempty"`

	// UptimeSeconds is whole seconds elapsed since StartTime. Nil when unavailable.
	UptimeSeconds *int64 `json:"uptime_seconds,omitempty"`

	// Threads is the number of threads in the process. Nil when unavailable.
	Threads *int32 `json:"threads,omitempty"`

	// User is the operating-system user owning the process (e.g. "vocc", "mysql").
	User string `json:"user,omitempty"`

	// VirtBytes is the virtual memory size in bytes (VIRT in top). Nil when unavailable.
	VirtBytes *uint64 `json:"virt_bytes,omitempty"`

	// Cmdline is the process command / executable name (e.g. "php-fpm8.2", "mariadbd").
	Cmdline string `json:"cmdline,omitempty"`
}

// ProcessPayload is the top-level structure sent by the agent to the backend.
// It wraps a slice of ProcessSnapshot entries together with the collection timestamp.
type ProcessPayload struct {
	// CollectedAt is the UTC timestamp when collection began.
	CollectedAt time.Time `json:"collected_at"`

	// Processes is the list of collected process snapshots (at most MaxProcessCount).
	Processes []ProcessSnapshot `json:"processes"`
}
