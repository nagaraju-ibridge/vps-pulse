package http

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vpsmonitoring-agent/internal/application/config"
	"vpsmonitoring-agent/internal/application/responsetime"
)

const (
	MaxRedirects   = 3
	RequestTimeout = 10 * time.Second
)

type HTTPMonitor interface {
	Collect(ctx context.Context, configs []config.ApplicationConfig) ([]ApplicationHTTPStatus, []responsetime.ApplicationResponseTimeStats)
}

type defaultHTTPMonitor struct{}

func NewHTTPMonitor() HTTPMonitor {
	return &defaultHTTPMonitor{}
}

func ptrInt(i int) *int       { return &i }
func ptrInt64(i int64) *int64 { return &i }
func ptrStr(s string) *string { return &s }

func (m *defaultHTTPMonitor) Collect(ctx context.Context, configs []config.ApplicationConfig) ([]ApplicationHTTPStatus, []responsetime.ApplicationResponseTimeStats) {
	var results []ApplicationHTTPStatus
	var rtResults []responsetime.ApplicationResponseTimeStats
	now := time.Now().UTC()

	// Ensure we only process enabled apps that have an HTTP URL.
	// Processing is done synchronously but could be parallelized if needed.
	// For max 15 configs, bounded by 10s timeout each, parallel is better.

	resultCh := make(chan ApplicationHTTPStatus, len(configs))
	var activeCount int

	for _, cfg := range configs {
		if !cfg.IsEnabled {
			continue
		}

		status := ApplicationHTTPStatus{
			ApplicationID: cfg.ID,
			CollectedAt:   now,
			Configured:    false,
		}

		if cfg.MonitorHttpUrl == nil || *cfg.MonitorHttpUrl == "" {
			status.URL = ""
			results = append(results, status)
			continue
		}

		status.Configured = true
		status.URL = *cfg.MonitorHttpUrl

		activeCount++
		go func(cfg config.ApplicationConfig, st ApplicationHTTPStatus) {
			st = m.checkURL(ctx, *cfg.MonitorHttpUrl, st)
			resultCh <- st
		}(cfg, status)
	}

	for i := 0; i < activeCount; i++ {
		st := <-resultCh
		results = append(results, st)

		if st.LatencyMs != nil {
			rtResults = append(rtResults, responsetime.ApplicationResponseTimeStats{
				ApplicationID:         st.ApplicationID,
				Source:                responsetime.SourceActiveHTTP,
				CollectedAt:           now,
				WindowStart:           now,
				WindowEnd:             now,
				ResponseTimeAvailable: true,
				ResponseCount:         1,
				MinMs:                 *st.LatencyMs,
				AvgMs:                 *st.LatencyMs,
				MaxMs:                 *st.LatencyMs,
			})
		}
	}

	return results, rtResults
}

func (m *defaultHTTPMonitor) checkURL(ctx context.Context, targetURL string, status ApplicationHTTPStatus) ApplicationHTTPStatus {
	startTime := time.Now()

	parsed, err := url.Parse(targetURL)
	if err != nil {
		status.Available = false
		status.ErrorClass = ptrStr("invalid_url")
		return status
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		status.Available = false
		status.ErrorClass = ptrStr("unsupported_scheme")
		return status
	}

	hostname := parsed.Hostname()
	allowLoopback := hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1"

	safeDialer := NewApplicationSafeDialer(allowLoopback)

	client := &http.Client{
		Timeout: RequestTimeout,
		Transport: &http.Transport{
			DialContext:           safeDialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       10 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: false}, // NEVER skip verify
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= MaxRedirects {
				return errors.New("redirect_limit_exceeded")
			}
			return nil
		},
	}

	reqCtx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
	if err != nil {
		status.Available = false
		status.ErrorClass = ptrStr("invalid_url")
		return status
	}

	resp, err := client.Do(req)

	status.LatencyMs = ptrInt64(time.Since(startTime).Milliseconds())

	if err != nil {
		status.Available = false
		status.ErrorClass = ptrStr(classifyError(err))
		return status
	}
	defer resp.Body.Close()

	// Discard a bounded amount of body to allow connection reuse, then ignore the rest.
	_, _ = io.CopyN(io.Discard, resp.Body, 64*1024)

	status.Available = true
	status.StatusCode = ptrInt(resp.StatusCode)

	return status
}

func classifyError(err error) string {
	errStr := err.Error()

	if errors.Is(err, ErrSSRFBlocked) || strings.Contains(errStr, "ssrf_blocked") {
		return "ssrf_blocked"
	}
	if strings.Contains(errStr, "redirect_limit_exceeded") {
		return "redirect_limit_exceeded"
	}
	if strings.Contains(errStr, "dns resolution failed") || strings.Contains(errStr, "no such host") {
		return "dns_resolution_failed"
	}
	if strings.Contains(errStr, "connection refused") {
		return "connection_refused"
	}
	if strings.Contains(errStr, "tls: ") || strings.Contains(errStr, "x509: ") || strings.Contains(errStr, "certificate") {
		return "tls_error"
	}
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(errStr, "timeout") {
		return "request_timeout"
	}

	return "network_error"
}
