package sender

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"vpsmonitoring-agent/internal/application/dto"
	agentConfig "vpsmonitoring-agent/internal/config"
)

type Sender interface {
	SendTelemetry(ctx context.Context, batch dto.ApplicationTelemetryBatch) error
}

type sender struct {
	cfg        *agentConfig.Config
	httpClient *http.Client
}

func NewSender(cfg *agentConfig.Config) Sender {
	return &sender{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (s *sender) SendTelemetry(ctx context.Context, batch dto.ApplicationTelemetryBatch) error {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	payload, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("failed to marshal telemetry batch: %w", err)
	}

	// Payloads strictly bound to 15 applications shouldn't exceed reasonable size
	if len(payload) > 5*1024*1024 {
		return fmt.Errorf("telemetry payload exceeds 5MB size limit")
	}

	endpoint := fmt.Sprintf("%s/api/v1/agents/%s/applications/telemetry", s.cfg.BackendURL, s.cfg.AgentID)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create telemetry request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.cfg.AgentCredential)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("telemetry request failed (network error): %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil // Success
	}

	body, _ := io.ReadAll(resp.Body)
	// We read body but avoid logging it completely if it's too large or sensitive.
	// We just log status code.
	log.Printf("[WARN] Telemetry rejected by backend: HTTP %d, %s", resp.StatusCode, string(body))
	return fmt.Errorf("telemetry request failed (HTTP %d)", resp.StatusCode)
}
