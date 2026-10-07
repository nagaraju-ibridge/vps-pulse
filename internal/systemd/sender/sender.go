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
	"vpsmonitoring-agent/internal/systemd/collector"
	"vpsmonitoring-agent/internal/systemd/models"
)

var (
	ErrUnauthorized    = errors.New("agent authentication failed: invalid or revoked credential")
	ErrInvalidPayload  = errors.New("backend rejected systemd snapshot: invalid payload")
	ErrPayloadTooLarge = errors.New("backend rejected systemd snapshot: payload too large")
)

type Response struct {
	Received int `json:"received"`
	Error    *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type Client struct {
	httpClient client.HTTPClient
	collector  collector.SystemdCollector
}

func NewClient(httpClient client.HTTPClient, collector collector.SystemdCollector) *Client {
	return &Client{
		httpClient: httpClient,
		collector:  collector,
	}
}

func (c *Client) Send(ctx context.Context, agentID, credential string) (*Response, error) {
	if credential == "" {
		return nil, errors.New("missing agent credential")
	}
	if agentID == "" {
		return nil, errors.New("missing agent ID")
	}

	snapshot := c.collector.Collect(ctx)
	return c.SendSnapshot(ctx, agentID, credential, snapshot)
}

func (c *Client) SendSnapshot(ctx context.Context, agentID, credential string, snapshot models.ServicePayload) (*Response, error) {
	if credential == "" {
		return nil, errors.New("missing agent credential")
	}
	if agentID == "" {
		return nil, errors.New("missing agent ID")
	}

	var resp Response
	endpoint := fmt.Sprintf("/api/v1/agents/%s/services", agentID)
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
			return nil, fmt.Errorf("systemd snapshot rejected with status %d: %s", statusCode, resp.Error.Message)
		}
		return nil, fmt.Errorf("systemd snapshot rejected with status %d", statusCode)
	}

	return &resp, nil
}

type Runner struct {
	client     *Client
	agentID    string
	credential string
	interval   time.Duration
	stopChan   chan struct{}
	wg         sync.WaitGroup
	mu         sync.Mutex
}

func NewRunner(client *Client, agentID, credential string, interval time.Duration) *Runner {
	if interval <= 0 {
		interval = 60 * time.Second
	}

	return &Runner{
		client:     client,
		agentID:    agentID,
		credential: credential,
		interval:   interval,
		stopChan:   make(chan struct{}),
	}
}

func (r *Runner) Start(ctx context.Context) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		log.Println("[INFO] systemd reporting service started")

		r.executeSubmission(ctx)
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Println("[INFO] systemd reporting loop stopping via context cancellation")
				return
			case <-r.stopChan:
				log.Println("[INFO] systemd reporting loop stopping via stop signal")
				return
			case <-ticker.C:
				r.executeSubmission(ctx)
			}
		}
	}()
}

func (r *Runner) executeSubmission(ctx context.Context) {
	if !r.mu.TryLock() {
		log.Println("[WARN] previous systemd collection/submission still running; skipping cycle to prevent overlap")
		return
	}
	defer r.mu.Unlock()

	resp, err := r.client.Send(ctx, r.agentID, r.credential)
	if err != nil {
		log.Printf("[WARN] systemd submission failed: %v", err)
		return
	}

	log.Printf("[DEBUG] systemd snapshot submitted successfully: received=%d services", resp.Received)
}

func (r *Runner) Stop() {
	close(r.stopChan)
	r.wg.Wait()
	log.Println("[INFO] systemd reporting service stopped")
}
