package sender

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"vpsmonitoring-agent/internal/client"
	"vpsmonitoring-agent/internal/metrics/collector"
	"vpsmonitoring-agent/internal/metrics/models"
)

var (
	// ErrUnauthorized indicates the backend rejected the agent credential (HTTP 401)
	ErrUnauthorized = errors.New("agent authentication failed: invalid or revoked credential")
	// ErrInvalidPayload indicates the backend rejected the metric payload as invalid (HTTP 400)
	ErrInvalidPayload = errors.New("backend rejected metric snapshot: invalid payload")
)

// Response matches backend Phase 2C.7 dto.IngestMetricResponse wrapped in GoFr "data" envelope
type Response struct {
	Data struct {
		Success    bool   `json:"success"`
		MetricID   string `json:"metric_id"`
		ServerID   int64  `json:"server_id"`
		ReceivedAt string `json:"received_at"`
	} `json:"data"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Client handles metric transmission to the backend API.
type Client struct {
	httpClient client.HTTPClient
	collector  collector.SnapshotCollector
}

// NewClient creates a new metric Client.
func NewClient(httpClient client.HTTPClient, collector collector.SnapshotCollector) *Client {
	return &Client{
		httpClient: httpClient,
		collector:  collector,
	}
}

// Send collects a fresh MetricSnapshot and transmits it to POST /api/v1/agent/metrics with Bearer authentication.
func (c *Client) Send(ctx context.Context, credential string) (*Response, error) {
	if credential == "" {
		return nil, errors.New("missing agent credential")
	}

	snapshot := c.collector.CollectSnapshot(ctx)

	var resp Response
	statusCode, err := c.httpClient.PostJSON(ctx, "/api/v1/agent/metrics", credential, snapshot, &resp)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		return nil, ErrUnauthorized
	}

	if statusCode == http.StatusBadRequest {
		if resp.Error != nil && resp.Error.Message != "" {
			return nil, fmt.Errorf("%w: %s", ErrInvalidPayload, resp.Error.Message)
		}
		return nil, ErrInvalidPayload
	}

	if statusCode != http.StatusOK && statusCode != http.StatusCreated {
		if resp.Error != nil && resp.Error.Message != "" {
			return nil, fmt.Errorf("metric submission rejected with status %d: %s", statusCode, resp.Error.Message)
		}
		return nil, fmt.Errorf("metric submission rejected with status %d", statusCode)
	}

	return &resp, nil
}

// SendSnapshot transmits a pre-existing MetricSnapshot directly (useful for tests or custom collectors).
func (c *Client) SendSnapshot(ctx context.Context, credential string, snapshot models.MetricSnapshot) (*Response, error) {
	if credential == "" {
		return nil, errors.New("missing agent credential")
	}

	var resp Response
	statusCode, err := c.httpClient.PostJSON(ctx, "/api/v1/agent/metrics", credential, snapshot, &resp)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		return nil, ErrUnauthorized
	}

	if statusCode == http.StatusBadRequest {
		if resp.Error != nil && resp.Error.Message != "" {
			return nil, fmt.Errorf("%w: %s", ErrInvalidPayload, resp.Error.Message)
		}
		return nil, ErrInvalidPayload
	}

	if statusCode != http.StatusOK && statusCode != http.StatusCreated {
		if resp.Error != nil && resp.Error.Message != "" {
			return nil, fmt.Errorf("metric submission rejected with status %d: %s", statusCode, resp.Error.Message)
		}
		return nil, fmt.Errorf("metric submission rejected with status %d", statusCode)
	}

	return &resp, nil
}

// Runner manages the periodic metric collection and transmission loop.
type Runner struct {
	client     *Client
	credential string
	interval   time.Duration
	stopChan   chan struct{}
	wg         sync.WaitGroup
	mu         sync.Mutex // Prevents overlapping submissions
}

// NewRunner creates a new metric collection and submission Runner.
func NewRunner(client *Client, credential string, interval time.Duration) *Runner {
	if interval <= 0 {
		interval = 60 * time.Second
	}

	return &Runner{
		client:     client,
		credential: credential,
		interval:   interval,
		stopChan:   make(chan struct{}),
	}
}

// Start launches the background periodic metric collection and submission loop.
func (r *Runner) Start(ctx context.Context) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		log.Println("[INFO] metric reporting service started")

		// 1. Initial collection and dispatch
		r.executeSubmission(ctx)

		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Println("[INFO] metric reporting loop stopping via context cancellation")
				return
			case <-r.stopChan:
				log.Println("[INFO] metric reporting loop stopping via stop signal")
				return
			case <-ticker.C:
				r.executeSubmission(ctx)
			}
		}
	}()
}

// executeSubmission collects and sends metrics with concurrency protection and safe non-sensitive logging.
func (r *Runner) executeSubmission(ctx context.Context) {
	// Prevent overlapping metric submissions if a previous run is delayed
	if !r.mu.TryLock() {
		log.Println("[WARN] previous metric collection/submission still running; skipping cycle to prevent overlap")
		return
	}
	defer r.mu.Unlock()

	resp, err := r.client.Send(ctx, r.credential)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			log.Println("[ERROR] metric submission unauthorized (401); agent credential invalid or revoked")
		} else if errors.Is(err, ErrInvalidPayload) {
			log.Printf("[WARN] metric submission rejected as invalid: %v", err)
		} else {
			log.Printf("[WARN] metric submission failed: %v", err)
		}
		return
	}

	log.Printf("[DEBUG] metric snapshot submitted: server_id=%d metric_id=%s received_at=%s",
		resp.Data.ServerID, resp.Data.MetricID, resp.Data.ReceivedAt)
}

// Stop signals the runner loop to terminate and blocks until it cleanly exits.
func (r *Runner) Stop() {
	close(r.stopChan)
	r.wg.Wait()
	log.Println("[INFO] metric reporting service stopped")
}
