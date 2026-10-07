package http

import (
	"time"
)

// ApplicationHTTPStatus models the result of an HTTP application health check.
type ApplicationHTTPStatus struct {
	ApplicationID int64     `json:"application_id"`
	URL           string    `json:"url"`
	Configured    bool      `json:"configured"`
	Available     bool      `json:"available"`
	StatusCode    *int      `json:"status_code,omitempty"`
	LatencyMs     *int64    `json:"latency_ms,omitempty"`
	ErrorClass    *string   `json:"error_class,omitempty"`
	CollectedAt   time.Time `json:"collected_at"`
	Warning       *string   `json:"warning,omitempty"`
}
