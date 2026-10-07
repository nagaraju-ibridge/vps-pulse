package responsetime

import "time"

type Source string

const (
	SourceActiveHTTP Source = "active_http"
	SourceAccessLog  Source = "access_log"
)

type ApplicationResponseTimeStats struct {
	ApplicationID         int64     `json:"application_id"`
	Source                Source    `json:"source"`
	CollectedAt           time.Time `json:"collected_at"`
	WindowStart           time.Time `json:"window_start"`
	WindowEnd             time.Time `json:"window_end"`
	ResponseTimeAvailable bool      `json:"response_time_available"`
	ResponseCount         int64     `json:"response_count"`
	MinMs                 int64     `json:"min_ms"`
	AvgMs                 int64     `json:"avg_ms"`
	MaxMs                 int64     `json:"max_ms"`
}
