package syncer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"vpsmonitoring-agent/internal/config"
	healthConfig "vpsmonitoring-agent/internal/health/config"
)

// Syncer is responsible for periodically fetching HTTP health check configurations from the backend.
type Syncer struct {
	cfg        *config.Config
	snapshot   *healthConfig.Snapshot
	httpClient *http.Client
}

type configResponse struct {
	Data []healthConfig.HttpHealthConfig `json:"data"`
}

// NewSyncer creates a new health configuration syncer.
func NewSyncer(cfg *config.Config, snapshot *healthConfig.Snapshot) *Syncer {
	return &Syncer{
		cfg:      cfg,
		snapshot: snapshot,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Start begins the periodic synchronization loop in a blocking manner.
func (s *Syncer) Start(ctx context.Context, interval time.Duration) {
	log.Printf("[INFO] Starting HTTP health config syncer (interval: %s)", interval)

	// Fetch immediately on startup
	s.fetchConfig(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[INFO] HTTP health config syncer stopped")
			return
		case <-ticker.C:
			s.fetchConfig(ctx)
		}
	}
}

func (s *Syncer) fetchConfig(ctx context.Context) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("%s/api/v1/agents/%s/config", s.cfg.BackendURL, s.cfg.AgentID)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		log.Printf("[ERROR] Failed to create config sync request: %v", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+s.cfg.AgentCredential)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("[ERROR] Config sync failed (network error): %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[ERROR] Config sync failed (HTTP %d)", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read config sync response body: %v", err)
		return
	}

	var response configResponse
	if err := json.Unmarshal(body, &response); err != nil {
		log.Printf("[ERROR] Failed to unmarshal config response: %v", err)
		return
	}

	// Filter out inactive configurations as per requirements (though backend shouldn't send them, better safe).
	// Also deduplicate config IDs safely in case of backend bugs.
	var activeConfigs []healthConfig.HttpHealthConfig
	seenIDs := make(map[int64]bool)

	for _, c := range response.Data {
		if c.IsActive && !seenIDs[c.ConfigID] {
			activeConfigs = append(activeConfigs, c)
			seenIDs[c.ConfigID] = true
		}
	}

	// Atomically replace the local snapshot
	s.snapshot.Set(activeConfigs)
	log.Printf("[DEBUG] Successfully synced HTTP health configs: loaded %d active checks", len(activeConfigs))
}
