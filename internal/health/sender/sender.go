package sender

import (
	"context"
	"fmt"
	"log"
	"time"

	"vpsmonitoring-agent/internal/client"
	"vpsmonitoring-agent/internal/health/collector"
)

// Sender reads the ResultSnapshot and sends it to the backend periodically.
type Sender struct {
	apiClient       client.HTTPClient
	snapshot        *collector.ResultSnapshot
	interval        time.Duration
	agentCredential string
	agentID         string
}

func NewSender(apiClient client.HTTPClient, snapshot *collector.ResultSnapshot, interval time.Duration, agentCredential, agentID string) *Sender {
	return &Sender{
		apiClient:       apiClient,
		snapshot:        snapshot,
		interval:        interval,
		agentCredential: agentCredential,
		agentID:         agentID,
	}
}

func (s *Sender) Start(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[INFO] Health result sender stopped")
			return
		case <-ticker.C:
			s.send()
		}
	}
}

type agentHealthCheckPayload struct {
	CollectedAt time.Time                   `json:"collected_at"`
	Checks      []agentHealthCheckResultDTO `json:"checks"`
}

type agentHealthCheckResultDTO struct {
	ConfigID    int64  `json:"config_id"`
	URL         string `json:"url"`
	StatusCode  int    `json:"status_code"`
	LatencyMs   int64  `json:"latency_ms"`
	IsAvailable bool   `json:"is_available"`
	ErrorClass  string `json:"error_class"`
}

func (s *Sender) send() {
	results := s.snapshot.GetAll()
	if len(results) == 0 {
		return // Empty snapshot is valid, skip sending
	}

	payload := agentHealthCheckPayload{
		CollectedAt: time.Now().UTC(),
		Checks:      make([]agentHealthCheckResultDTO, 0, len(results)),
	}

	for _, res := range results {
		payload.Checks = append(payload.Checks, agentHealthCheckResultDTO{
			ConfigID:    res.ConfigID,
			URL:         res.URL,
			StatusCode:  res.StatusCode,
			LatencyMs:   res.LatencyMs,
			IsAvailable: res.IsAvailable,
			ErrorClass:  string(res.ErrorClass),
		})
	}

	endpoint := fmt.Sprintf("/api/v1/agents/%s/health-checks", s.agentID)

	reqCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	status, err := s.apiClient.PostJSON(reqCtx, endpoint, s.agentCredential, payload, nil)
	if err != nil {
		log.Printf("[ERROR] Failed to send health check results: %v", err)
		return
	}

	if status < 200 || status >= 300 {
		log.Printf("[ERROR] Backend rejected health check results with status: %d", status)
		return
	}

	log.Printf("[DEBUG] Successfully sent %d health check results", len(results))
}
