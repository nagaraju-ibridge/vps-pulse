package log

import (
	"time"
)

type ApplicationRequestStats struct {
	ApplicationID     int64     `json:"application_id"`
	Configured        bool      `json:"configured"`
	CollectedAt       time.Time `json:"collected_at"`
	WindowStart       time.Time `json:"window_start"`
	WindowEnd         time.Time `json:"window_end"`
	TotalRequests     int64     `json:"total_requests"`
	RequestsPerSecond *float64  `json:"requests_per_second,omitempty"`
	Status2xx         int64     `json:"status_2xx"`
	Status3xx         int64     `json:"status_3xx"`
	Status4xx         int64     `json:"status_4xx"`
	Status5xx         int64     `json:"status_5xx"`
	StatusOther       int64     `json:"status_other"`
	MalformedLines    int64     `json:"malformed_lines"`
	LogAvailable      bool      `json:"log_available"`
	ErrorClass        *string   `json:"error_class,omitempty"`
}
