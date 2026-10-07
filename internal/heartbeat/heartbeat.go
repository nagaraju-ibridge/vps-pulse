package heartbeat

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"vpsmonitoring-agent/internal/client"
	"vpsmonitoring-agent/internal/config"
)

var (
	// ErrUnauthorized indicates the backend rejected the agent credential (HTTP 401)
	ErrUnauthorized = errors.New("agent authentication failed: invalid or revoked credential")
)

// Request matches backend Phase 2C.3 dto.HeartbeatRequest
type Request struct {
	Timestamp    string `json:"timestamp"`
	AgentVersion string `json:"agent_version"`
}

// Response matches backend Phase 2C.3 dto.HeartbeatResponse wrapped in GoFr "data" envelope
type Response struct {
	Data struct {
		AgentID  string `json:"agent_id"`
		ServerID int64  `json:"server_id"`
		Status   string `json:"status"`
		LastSeen string `json:"last_seen"`
	} `json:"data"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Client handles heartbeat dispatch
type Client struct {
	httpClient client.HTTPClient
}

// NewClient initializes a heartbeat Client
func NewClient(httpClient client.HTTPClient) *Client {
	return &Client{
		httpClient: httpClient,
	}
}

// Send emits a single heartbeat ping to POST /api/v1/agent/heartbeat
func (c *Client) Send(ctx context.Context, credential string) (*Response, error) {
	if credential == "" {
		return nil, errors.New("missing agent credential")
	}

	reqBody := Request{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		AgentVersion: config.AgentVersion,
	}

	var resp Response
	statusCode, err := c.httpClient.PostJSON(ctx, "/api/v1/agent/heartbeat", credential, reqBody, &resp)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		return nil, ErrUnauthorized
	}

	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		if resp.Error != nil && resp.Error.Message != "" {
			return nil, fmt.Errorf("heartbeat rejected with status %d: %s", statusCode, resp.Error.Message)
		}
		return nil, fmt.Errorf("heartbeat rejected with status %d", statusCode)
	}

	return &resp, nil
}

// Runner manages the periodic heartbeat execution loop with graceful shutdown support
type Runner struct {
	client     *Client
	credential string
	interval   time.Duration
	stopChan   chan struct{}
	wg         sync.WaitGroup
}

// NewRunner creates a new heartbeat Runner
func NewRunner(client *Client, credential string, interval time.Duration) *Runner {
	if interval <= 0 {
		interval = config.DefaultHeartbeatInterval
	}

	return &Runner{
		client:     client,
		credential: credential,
		interval:   interval,
		stopChan:   make(chan struct{}),
	}
}

// Start launches the periodic heartbeat loop in a background goroutine
func (r *Runner) Start(ctx context.Context) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		log.Println("[INFO] heartbeat service started")

		// 1. Immediate initial heartbeat on startup so backend server status transitions to ONLINE quickly
		r.executeHeartbeat(ctx)

		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Println("[INFO] heartbeat loop stopping via context cancellation")
				return
			case <-r.stopChan:
				log.Println("[INFO] heartbeat loop stopping via stop signal")
				return
			case <-ticker.C:
				r.executeHeartbeat(ctx)
			}
		}
	}()
}

// executeHeartbeat performs a single heartbeat dispatch with resilient error handling
func (r *Runner) executeHeartbeat(ctx context.Context) {
	resp, err := r.client.Send(ctx, r.credential)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			log.Println("[ERROR] agent authentication failed (401 Unauthorized); credential may be invalid or revoked")
		} else {
			log.Printf("[WARN] heartbeat failed: %v", err)
		}
		return
	}

	// Avoid noisy logs every 30s in production; debug/summary log
	log.Printf("[DEBUG] heartbeat succeeded: server_id=%d status=%s", resp.Data.ServerID, resp.Data.Status)
}

// Stop signals the runner loop to terminate and blocks until it exits
func (r *Runner) Stop() {
	close(r.stopChan)
	r.wg.Wait()
	log.Println("[INFO] heartbeat service stopped")
}
