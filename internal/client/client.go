package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// DefaultTimeout specifies standard request timeout for agent communications
	DefaultTimeout = 10 * time.Second
)

// HTTPClient defines the client interface used by registration and heartbeat packages
type HTTPClient interface {
	PostJSON(ctx context.Context, endpoint string, bearerToken string, reqBody any, respBody any) (int, error)
}

// Client wraps net/http.Client with base URL and json serialization
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient initializes a Client instance with configured base URL and standard timeouts
func NewClient(baseURL string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// PostJSON performs an HTTP POST request sending and receiving JSON payloads
func (c *Client) PostJSON(ctx context.Context, endpoint string, bearerToken string, reqBody any, respBody any) (int, error) {
	url := fmt.Sprintf("%s%s", c.baseURL, endpoint)

	var bodyReader io.Reader
	if reqBody != nil {
		jsonBytes, err := json.Marshal(reqBody)
		if err != nil {
			return 0, fmt.Errorf("failed to marshal request payload: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBytes)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bodyReader)
	if err != nil {
		return 0, fmt.Errorf("failed to create http request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if bearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return 0, fmt.Errorf("http request failed: %w", err)
	}
	defer httpResp.Body.Close()

	respBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return httpResp.StatusCode, fmt.Errorf("failed to read response body: %w", err)
	}

	if respBody != nil && len(respBytes) > 0 {
		if err := json.Unmarshal(respBytes, respBody); err != nil {
			return httpResp.StatusCode, fmt.Errorf("failed to decode response json (status %d): %w", httpResp.StatusCode, err)
		}
	}

	return httpResp.StatusCode, nil
}
