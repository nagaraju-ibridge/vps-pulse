package collector

import "time"

// HealthResult represents the outcome of an HTTP health check execution.
type HealthResult struct {
	ConfigID    int64     `json:"config_id"`
	URL         string    `json:"url"`
	StatusCode  int       `json:"status_code"` // 0 if no response
	LatencyMs   int64     `json:"latency_ms"`
	IsAvailable bool      `json:"is_available"`
	ErrorClass  string    `json:"error_class"` // e.g. dns_resolution_failed, http_error
	CollectedAt time.Time `json:"collected_at"`
}

// Error classes
const (
	ErrClassNone                = ""
	ErrClassDNSResolutionFailed = "dns_resolution_failed"
	ErrClassSSRFBlocked         = "ssrf_blocked"
	ErrClassConnectionRefused   = "connection_refused"
	ErrClassConnectionTimeout   = "connection_timeout"
	ErrClassTLSError            = "tls_error"
	ErrClassRequestTimeout      = "request_timeout"
	ErrClassInvalidURL          = "invalid_url"
	ErrClassHTTPError           = "http_error"
)
