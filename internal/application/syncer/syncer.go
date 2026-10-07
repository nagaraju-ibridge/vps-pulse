package syncer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"vpsmonitoring-agent/internal/application/config"
	agentConfig "vpsmonitoring-agent/internal/config"
)

// Syncer periodically fetches Application Configurations from the backend.
type Syncer struct {
	cfg        *agentConfig.Config
	snapshot   *config.Snapshot
	httpClient *http.Client
}

type configResponse struct {
	Data struct {
		Data []config.ApplicationConfig `json:"data"`
	} `json:"data"`
}

// NewSyncer creates a new application configuration syncer.
func NewSyncer(cfg *agentConfig.Config, snapshot *config.Snapshot) *Syncer {
	return &Syncer{
		cfg:      cfg,
		snapshot: snapshot,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Start begins the periodic synchronization loop.
func (s *Syncer) Start(ctx context.Context, interval time.Duration) {
	log.Printf("[INFO] Starting application config syncer (interval: %s)", interval)

	s.fetchConfig(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[INFO] Application config syncer stopped")
			return
		case <-ticker.C:
			s.fetchConfig(ctx)
		}
	}
}

func (s *Syncer) fetchConfig(ctx context.Context) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	endpoint := fmt.Sprintf("%s/api/v1/agents/%s/applications/config", s.cfg.BackendURL, s.cfg.AgentID)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		log.Printf("[ERROR] Failed to create app config sync request: %v", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+s.cfg.AgentCredential)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("[ERROR] App config sync failed (network error): %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[ERROR] App config sync failed (HTTP %d)", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read app config sync response body: %v", err)
		return
	}

	var response configResponse
	if err := json.Unmarshal(body, &response); err != nil {
		log.Printf("[ERROR] Failed to unmarshal app config response: %v", err)
		return
	}

	validConfigs := validateConfigs(response.Data.Data)

	s.snapshot.Set(validConfigs)
	log.Printf("[DEBUG] Successfully synced application configs: loaded %d valid apps", len(validConfigs))
}

func validateConfigs(configs []config.ApplicationConfig) []config.ApplicationConfig {
	var valid []config.ApplicationConfig
	seen := make(map[string]bool) // detect duplicates: match_type + match_value

	for _, c := range configs {
		if !c.IsEnabled {
			continue // the backend should only send enabled ones, but we skip disabled ones just in case
		}

		if c.Name == "" || len(c.Name) > 255 {
			log.Printf("[WARN] Skipping app config ID %d: invalid name", c.ID)
			continue
		}

		if c.MatchType != "systemd_unit" && c.MatchType != "exe_path" {
			log.Printf("[WARN] Skipping app config ID %d: unsupported match_type %s", c.ID, c.MatchType)
			continue
		}

		if c.MatchValue == "" {
			log.Printf("[WARN] Skipping app config ID %d: empty match_value", c.ID)
			continue
		}

		// check duplicate identity
		identityKey := fmt.Sprintf("%s:%s", c.MatchType, c.MatchValue)
		if seen[identityKey] {
			log.Printf("[WARN] Skipping app config ID %d: duplicate identity %s", c.ID, identityKey)
			continue
		}
		seen[identityKey] = true

		if c.MonitorPort != nil {
			p := *c.MonitorPort
			if p < 1 || p > 65535 {
				log.Printf("[WARN] Skipping app config ID %d: invalid port %d", c.ID, p)
				continue
			}
		}

		if c.MonitorHttpUrl != nil && *c.MonitorHttpUrl != "" {
			u, err := url.ParseRequestURI(*c.MonitorHttpUrl)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
				log.Printf("[WARN] Skipping app config ID %d: invalid HTTP URL", c.ID)
				continue
			}
		}

		if c.LogSourceType != nil && *c.LogSourceType != "" {
			if *c.LogSourceType != "nginx_access" && *c.LogSourceType != "apache_access" {
				log.Printf("[WARN] Skipping app config ID %d: unsupported log_source_type", c.ID)
				continue
			}
			// Path is mandatory if type exists
			if c.LogSourcePath == nil || *c.LogSourcePath == "" {
				log.Printf("[WARN] Skipping app config ID %d: missing log_source_path", c.ID)
				continue
			}
		}

		valid = append(valid, c)
	}

	if valid == nil {
		valid = []config.ApplicationConfig{}
	}

	return valid
}
