package dto

import (
	"encoding/json"
	"time"
)

type ApplicationTelemetryBatch struct {
	CollectedAt  time.Time                   `json:"collected_at" binding:"required"`
	Applications []ApplicationTelemetryEntry `json:"applications" binding:"required,max=15"`
}

type ApplicationTelemetryEntry struct {
	ApplicationID int64 `json:"application_id" binding:"required"`

	// Observation Status: e.g. "UNKNOWN" if permission denied etc.
	ObservationState string `json:"observation_state" binding:"required"`

	// Process Evidence
	ProcessMatched   bool       `json:"process_matched"`
	ProcessCount     int        `json:"process_count"`
	PrimaryPID       *int64     `json:"primary_pid,omitempty"`
	PrimaryStartTime *time.Time `json:"primary_start_time,omitempty"`
	CPUPercent       *float64   `json:"cpu_percent,omitempty"`
	MemoryBytes      *uint64    `json:"memory_bytes,omitempty"`

	// Port Evidence
	PortConfigured bool  `json:"port_configured"`
	PortListening  *bool `json:"port_listening,omitempty"`

	// HTTP Evidence
	HTTPConfigured bool    `json:"http_configured"`
	HTTPAvailable  *bool   `json:"http_available,omitempty"`
	HTTPStatusCode *int    `json:"http_status_code,omitempty"`
	HTTPLatencyMs  *int64  `json:"http_latency_ms,omitempty"`
	HTTPErrorClass *string `json:"http_error_class,omitempty"`

	// Request Rate Evidence
	LogConfigured     bool     `json:"log_configured"`
	LogAvailable      *bool    `json:"log_available,omitempty"`
	LogErrorClass     *string  `json:"log_error_class,omitempty"`
	TotalRequests     *int64   `json:"total_requests,omitempty"`
	RequestsPerSecond *float64 `json:"requests_per_second,omitempty"`
	Status2xx         *int64   `json:"status_2xx,omitempty"`
	Status3xx         *int64   `json:"status_3xx,omitempty"`
	Status4xx         *int64   `json:"status_4xx,omitempty"`
	Status5xx         *int64   `json:"status_5xx,omitempty"`
	StatusOther       *int64   `json:"status_other,omitempty"`

	// Response Time Evidence
	ActiveResponseCount  *int64 `json:"active_response_count,omitempty"`
	ActiveResponseAvgMs  *int64 `json:"active_response_avg_ms,omitempty"`
	PassiveResponseCount *int64 `json:"passive_response_count,omitempty"`
	PassiveResponseAvgMs *int64 `json:"passive_response_avg_ms,omitempty"`

	// Lifecycle Events
	LifecycleEvents []LifecycleEventDTO `json:"lifecycle_events,omitempty" binding:"max=20"`
}

type LifecycleEventDTO struct {
	EventType string          `json:"event_type" binding:"required,oneof=process_started process_disappeared restart_detected process_identity_changed"`
	EventTime time.Time       `json:"event_time" binding:"required"`
	OldPID    *int64          `json:"old_pid,omitempty"`
	NewPID    *int64          `json:"new_pid,omitempty"`
	Details   json.RawMessage `json:"details,omitempty"`
}
