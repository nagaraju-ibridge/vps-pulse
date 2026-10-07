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
	"vpsmonitoring-agent/internal/config"
	"vpsmonitoring-agent/internal/discovery/collector"
	"vpsmonitoring-agent/internal/discovery/models"
)

var (
	ErrUnauthorized    = errors.New("agent authentication failed: invalid or revoked credential")
	ErrInvalidPayload  = errors.New("backend rejected discovery payload: invalid payload")
	ErrPayloadTooLarge = errors.New("backend rejected discovery payload: payload too large")
)

type Response struct {
	Status   string `json:"status,omitempty"`
	Received struct {
		Applications int `json:"applications"`
		Services     int `json:"services"`
		Listeners    int `json:"listeners"`
	} `json:"received"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type Client struct {
	httpClient client.HTTPClient
	collector  collector.DiscoveryCollector
}

func NewClient(httpClient client.HTTPClient, collector collector.DiscoveryCollector) *Client {
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

	payload := c.collector.Collect(ctx)
	return c.SendPayload(ctx, agentID, credential, payload)
}

func (c *Client) SendPayload(ctx context.Context, agentID, credential string, payload models.DiscoveryPayload) (*Response, error) {
	if credential == "" {
		return nil, errors.New("missing agent credential")
	}
	if agentID == "" {
		return nil, errors.New("missing agent ID")
	}

	var resp Response
	endpoint := fmt.Sprintf("/api/v1/agents/%s/discovery", agentID)
	statusCode, err := c.httpClient.PostJSON(ctx, endpoint, credential, payload, &resp)
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
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		if resp.Error != nil && resp.Error.Message != "" {
			return nil, fmt.Errorf("discovery payload rejected with status %d: %s", statusCode, resp.Error.Message)
		}
		return nil, fmt.Errorf("discovery payload rejected with status %d", statusCode)
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
		interval = config.DefaultDiscoveryInterval
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
		log.Println("[INFO] discovery reporting service started")

		r.executeSubmission(ctx)
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Println("[INFO] discovery reporting loop stopping via context cancellation")
				return
			case <-r.stopChan:
				log.Println("[INFO] discovery reporting loop stopping via stop signal")
				return
			case <-ticker.C:
				r.executeSubmission(ctx)
			}
		}
	}()
}

func (r *Runner) executeSubmission(ctx context.Context) {
	if !r.mu.TryLock() {
		log.Println("[WARN] previous discovery collection/submission still running; skipping cycle to prevent overlap")
		return
	}
	defer r.mu.Unlock()

	resp, err := r.client.Send(ctx, r.agentID, r.credential)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			log.Println("[ERROR] discovery submission unauthorized (401); agent credential invalid or revoked")
		} else if errors.Is(err, ErrInvalidPayload) {
			log.Printf("[WARN] discovery submission rejected as invalid: %v", err)
		} else if errors.Is(err, ErrPayloadTooLarge) {
			log.Println("[WARN] discovery submission rejected as payload too large (413)")
		} else {
			log.Printf("[WARN] discovery submission failed: %v", err)
		}
		return
	}

	log.Printf("[DEBUG] discovery payload submitted successfully: applications=%d services=%d listeners=%d",
		resp.Received.Applications, resp.Received.Services, resp.Received.Listeners)
}

func (r *Runner) Stop() {
	close(r.stopChan)
	r.wg.Wait()
	log.Println("[INFO] discovery reporting service stopped")
}
