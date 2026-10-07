package registration_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"vpsmonitoring-agent/internal/registration"
)

// mockHTTPClient implements client.HTTPClient for testing registration
type mockHTTPClient struct {
	statusCode  int
	respBody    any
	err         error
	capturedReq any
}

func (m *mockHTTPClient) PostJSON(ctx context.Context, endpoint string, bearerToken string, reqBody any, respBody any) (int, error) {
	m.capturedReq = reqBody
	if m.err != nil {
		return 0, m.err
	}

	if m.respBody != nil {
		switch target := respBody.(type) {
		case *registration.RegisterResponse:
			if src, ok := m.respBody.(*registration.RegisterResponse); ok {
				*target = *src
			}
		}
	}

	return m.statusCode, nil
}

func TestRegistration_Client(t *testing.T) {
	ctx := context.Background()

	t.Run("Empty installation token returns error", func(t *testing.T) {
		client := registration.NewClient(&mockHTTPClient{})
		_, err := client.Register(ctx, "")
		if err == nil || !strings.Contains(err.Error(), "token is required") {
			t.Errorf("expected token required error, got %v", err)
		}
	})

	t.Run("Successful registration returns parsed agent state", func(t *testing.T) {
		mockResp := &registration.RegisterResponse{}
		mockResp.Data.AgentID = "agent-uuid-777"
		mockResp.Data.ServerID = 101
		mockResp.Data.Credential = "cred-secret-777"
		mockResp.Data.Status = "ACTIVE"

		mockHTTP := &mockHTTPClient{
			statusCode: http.StatusOK,
			respBody:   mockResp,
		}

		client := registration.NewClient(mockHTTP)
		state, err := client.Register(ctx, "install-tok-abc")
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}

		if state.AgentID != "agent-uuid-777" || state.ServerID != 101 || state.AgentCredential != "cred-secret-777" {
			t.Errorf("unexpected state: %+v", state)
		}

		// Verify request body sent
		req, ok := mockHTTP.capturedReq.(registration.RegisterRequest)
		if !ok || req.InstallationToken != "install-tok-abc" {
			t.Errorf("expected installation token in request body, got %+v", mockHTTP.capturedReq)
		}
	})

	t.Run("Backend failure returns informative non-sensitive error", func(t *testing.T) {
		mockResp := &registration.RegisterResponse{
			Error: &struct {
				Message string `json:"message"`
			}{Message: "installation token has expired"},
		}

		mockHTTP := &mockHTTPClient{
			statusCode: http.StatusBadRequest,
			respBody:   mockResp,
		}

		client := registration.NewClient(mockHTTP)
		_, err := client.Register(ctx, "expired-tok")
		if err == nil || !strings.Contains(err.Error(), "installation token has expired") {
			t.Errorf("expected expired token message, got %v", err)
		}
	})

	t.Run("Network failure handled cleanly", func(t *testing.T) {
		mockHTTP := &mockHTTPClient{
			err: errors.New("connection refused"),
		}

		client := registration.NewClient(mockHTTP)
		_, err := client.Register(ctx, "tok-any")
		if err == nil || !strings.Contains(err.Error(), "connection refused") {
			t.Errorf("expected connection error, got %v", err)
		}
	})
}
