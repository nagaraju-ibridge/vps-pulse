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
	"vpsmonitoring-agent/internal/process/collector"
	"vpsmonitoring-agent/internal/process/models"

	"github.com/shirou/gopsutil/v4/mem"
)

var (
	// ErrUnauthorized indicates the backend rejected the agent credential (HTTP 401)
	ErrUnauthorized = errors.New("agent authentication failed: invalid or revoked credential")
	// ErrInvalidPayload indicates the backend rejected the process snapshot as invalid (HTTP 400)
	ErrInvalidPayload = errors.New("backend rejected process snapshot: invalid payload")
	// ErrPayloadTooLarge indicates the payload exceeded backend limits (HTTP 413)
	ErrPayloadTooLarge = errors.New("backend rejected process snapshot: payload too large")
)

// Response matches the expected success response from POST /api/v1/agents/{agentId}/processes
type Response struct {
	Data *struct {
		Received int `json:"received"`
	} `json:"data,omitempty"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Client handles process snapshot transmission to the backend API.
type Client struct {
	httpClient client.HTTPClient
	collector  collector.ProcessCollector
}

// NewClient creates a new process snapshot Client.
func NewClient(httpClient client.HTTPClient, collector collector.ProcessCollector) *Client {
	return &Client{
		httpClient: httpClient,
		collector:  collector,
	}
}

// Send collects a fresh ProcessPayload and transmits it to POST /api/v1/agents/{agentId}/processes.
func (c *Client) Send(ctx context.Context, agentID, credential string, totalMemBytes uint64) (*Response, error) {
	if credential == "" {
		return nil, errors.New("missing agent credential")
	}
	if agentID == "" {
		return nil, errors.New("missing agent ID")
	}

	snapshot := c.collector.Collect(ctx, totalMemBytes)

	return c.SendSnapshot(ctx, agentID, credential, snapshot)
}

// SendSnapshot transmits a pre-existing ProcessPayload directly.
func (c *Client) SendSnapshot(ctx context.Context, agentID, credential string, snapshot models.ProcessPayload) (*Response, error) {
	if credential == "" {
		return nil, errors.New("missing agent credential")
	}
	if agentID == "" {
		return nil, errors.New("missing agent ID")
	}

	var resp Response
	endpoint := fmt.Sprintf("/api/v1/agents/%s/processes", agentID)
	statusCode, err := c.httpClient.PostJSON(ctx, endpoint, credential, snapshot, &resp)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		return nil, ErrUnauthorized
	}

	if statusCode == http.StatusRequestEntityTooLarge {
		return nil, ErrPayloadTooLarge
	}

	if statusCode == http.StatusBadRequest {
		if resp.Error != nil && resp.Error.Message != "" {
			return nil, fmt.Errorf("%w: %s", ErrInvalidPayload, resp.Error.Message)
		}
		return nil, ErrInvalidPayload
	}

	if statusCode != http.StatusOK && statusCode != http.StatusCreated && statusCode != http.StatusAccepted {
		if resp.Error != nil && resp.Error.Message != "" {
			return nil, fmt.Errorf("process snapshot rejected with status %d: %s", statusCode, resp.Error.Message)
		}
		return nil, fmt.Errorf("process snapshot rejected with status %d", statusCode)
	}

	return &resp, nil
}

// Runner manages the periodic process collection and transmission loop.
type Runner struct {
	client        *Client
	agentID       string
	credential    string
	interval      time.Duration
	stopChan      chan struct{}
	wg            sync.WaitGroup
	mu            sync.Mutex // Prevents overlapping submissions
	totalMemBytes uint64
}

// NewRunner creates a new process collection and submission Runner.
func NewRunner(client *Client, agentID, credential string, interval time.Duration, totalMemBytes uint64) *Runner {
	if interval <= 0 {
		interval = 60 * time.Second
	}

	return &Runner{
		client:        client,
		agentID:       agentID,
		credential:    credential,
		interval:      interval,
		stopChan:      make(chan struct{}),
		totalMemBytes: totalMemBytes,
	}
}

// Start launches the background periodic process collection and submission loop.
func (r *Runner) Start(ctx context.Context) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		log.Println("[INFO] process reporting service started")

		// 1. Initial collection and dispatch
		r.executeSubmission(ctx)

		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Println("[INFO] process reporting loop stopping via context cancellation")
				return
			case <-r.stopChan:
				log.Println("[INFO] process reporting loop stopping via stop signal")
				return
			case <-ticker.C:
				r.executeSubmission(ctx)
			}
		}
	}()
}

// executeSubmission collects and sends process snapshots with concurrency protection and safe non-sensitive logging.
func (r *Runner) executeSubmission(ctx context.Context) {
	// Prevent overlapping process submissions if a previous run is delayed
	if !r.mu.TryLock() {
		log.Println("[WARN] previous process collection/submission still running; skipping cycle to prevent overlap")
		return
	}
	defer r.mu.Unlock()

	memBytes := r.totalMemBytes
	if memBytes == 0 {
		if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil && vm != nil {
			memBytes = vm.Total
		}
	}

	resp, err := r.client.Send(ctx, r.agentID, r.credential, memBytes)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			log.Println("[ERROR] process submission unauthorized (401); agent credential invalid or revoked")
		} else if errors.Is(err, ErrInvalidPayload) {
			log.Printf("[WARN] process submission rejected as invalid: %v", err)
		} else if errors.Is(err, ErrPayloadTooLarge) {
			log.Printf("[WARN] process submission rejected as payload too large (413)")
		} else {
			log.Printf("[WARN] process submission failed: %v", err)
		}
		return
	}

	receivedCount := 0
	if resp != nil && resp.Data != nil {
		receivedCount = resp.Data.Received
	}
	log.Printf("[DEBUG] process snapshot submitted successfully: received=%d processes", receivedCount)
}

// Stop signals the runner loop to terminate and blocks until it cleanly exits.
func (r *Runner) Stop() {
	close(r.stopChan)
	r.wg.Wait()
	log.Println("[INFO] process reporting service stopped")
}
