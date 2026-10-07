package registration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"

	"vpsmonitoring-agent/internal/client"
	"vpsmonitoring-agent/internal/config"
)

// RegisterRequest matches backend Phase 2C.1 dto.RegisterAgentRequest
type RegisterRequest struct {
	InstallationToken string `json:"installation_token"`
	Hostname          string `json:"hostname"`
	IPAddress         string `json:"ip_address"`
	OS                string `json:"os"`
	Architecture      string `json:"architecture"`
	AgentVersion      string `json:"agent_version"`
}

// RegisterResponse matches backend Phase 2C.1 dto.RegisterAgentResponse wrapped in GoFr "data" envelope
type RegisterResponse struct {
	Data struct {
		AgentID    string `json:"agent_id"`
		ServerID   int64  `json:"server_id"`
		Credential string `json:"credential"`
		Status     string `json:"status"`
	} `json:"data"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Client handles onboarding and registration calls
type Client struct {
	httpClient client.HTTPClient
}

// NewClient initializes a registration Client
func NewClient(httpClient client.HTTPClient) *Client {
	return &Client{
		httpClient: httpClient,
	}
}

// Register contacts POST /api/v1/agent/register and returns the persistent agent state
func (c *Client) Register(ctx context.Context, installationToken string) (*config.AgentState, error) {
	if installationToken == "" {
		return nil, errors.New("installation token is required for registration")
	}

	hostname, _ := os.Hostname()
	osName := runtime.GOOS
	arch := runtime.GOARCH

	reqBody := RegisterRequest{
		InstallationToken: installationToken,
		Hostname:          hostname,
		IPAddress:         "", // determined by backend request or local network interface
		OS:                osName,
		Architecture:      arch,
		AgentVersion:      config.AgentVersion,
	}

	var resp RegisterResponse
	statusCode, err := c.httpClient.PostJSON(ctx, "/api/v1/agent/register", "", reqBody, &resp)
	if err != nil {
		return nil, fmt.Errorf("registration request error: %w", err)
	}

	if statusCode != http.StatusOK && statusCode != http.StatusCreated {
		if resp.Error != nil && resp.Error.Message != "" {
			return nil, fmt.Errorf("registration failed with status %d: %s", statusCode, resp.Error.Message)
		}
		return nil, fmt.Errorf("registration failed with unexpected HTTP status %d", statusCode)
	}

	if resp.Data.Credential == "" {
		return nil, errors.New("backend did not return an agent credential")
	}

	return &config.AgentState{
		AgentID:         resp.Data.AgentID,
		ServerID:        resp.Data.ServerID,
		AgentCredential: resp.Data.Credential,
	}, nil
}
