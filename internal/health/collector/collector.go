package collector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	healthConfig "vpsmonitoring-agent/internal/health/config"
)

// HTTPCollector executes health checks securely.
type HTTPCollector struct {
	client *http.Client
}

// NewHTTPCollector creates a secure HTTP collector with SSRF protections.
func NewHTTPCollector() *HTTPCollector {
	return NewHTTPCollectorWithDialer(NewSafeDialer())
}

// NewHTTPCollectorWithDialer allows injecting a custom dialer (e.g. for testing).
func NewHTTPCollectorWithDialer(safeDialer *SafeDialer) *HTTPCollector {

	transport := &http.Transport{
		DialContext:           safeDialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second, // requirement
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		// Total request timeout enforced via context in Execute()
		Timeout: 0,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("stopped after 3 redirects")
			}

			// Must be http or https
			scheme := strings.ToLower(req.URL.Scheme)
			if scheme != "http" && scheme != "https" {
				return fmt.Errorf("redirect blocked: unsupported scheme %s", scheme)
			}

			// Validate IP of the redirect destination using the same dialer's resolver and validator
			ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
			defer cancel()

			host := req.URL.Hostname()
			ips, err := safeDialer.resolver.LookupIPAddr(ctx, host)
			if err != nil {
				return fmt.Errorf("redirect blocked: dns resolution failed: %w", err)
			}

			if len(ips) == 0 {
				return fmt.Errorf("redirect blocked: no addresses found for %s", host)
			}

			// Require that AT LEAST ONE resolved IP is safe.
			// The actual transport will dial through safeDialer.DialContext which will re-validate.
			// Doing it here just aggressively fails bad redirects early.
			hasSafeIP := false
			for _, ipAddr := range ips {
				if err := safeDialer.validator.ValidateIP(ipAddr.IP); err == nil {
					hasSafeIP = true
					break
				}
			}

			if !hasSafeIP {
				return ErrSSRFBlocked
			}

			return nil
		},
	}

	return &HTTPCollector{
		client: client,
	}
}

// Execute performs a single HTTP GET health check.
func (c *HTTPCollector) Execute(ctx context.Context, config healthConfig.HttpHealthConfig) HealthResult {
	start := time.Now()
	result := HealthResult{
		ConfigID:    config.ConfigID,
		URL:         config.URL,
		CollectedAt: start.UTC(),
		IsAvailable: false, // default
		ErrorClass:  ErrClassNone,
	}

	// 1. Initial URL validation before even trying to connect
	parsedURL, err := url.ParseRequestURI(config.URL)
	if err != nil {
		result.ErrorClass = ErrClassInvalidURL
		return result
	}
	scheme := strings.ToLower(parsedURL.Scheme)
	if scheme != "http" && scheme != "https" {
		result.ErrorClass = ErrClassInvalidURL
		return result
	}
	if parsedURL.Hostname() == "" {
		result.ErrorClass = ErrClassInvalidURL
		return result
	}

	// 2. Set total request timeout (10 seconds as required)
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, config.URL, nil)
	if err != nil {
		result.ErrorClass = ErrClassInvalidURL // fallback class
		return result
	}
	req.Header.Set("User-Agent", "vpspulse-agent/1.0")
	// Ensure body is closed immediately on transport level if possible, though GET usually has no body
	req.Close = true

	// 3. Execute request
	resp, err := c.client.Do(req)

	result.LatencyMs = time.Since(start).Milliseconds()

	if err != nil {
		result.ErrorClass = classifyError(err)
		return result
	}

	// 4. Always close the response body immediately (we don't read it)
	_ = resp.Body.Close()

	result.StatusCode = resp.StatusCode

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		result.IsAvailable = true
		result.ErrorClass = ErrClassNone
	} else {
		result.IsAvailable = false
		result.ErrorClass = ErrClassHTTPError
	}

	return result
}

func classifyError(err error) string {
	if errors.Is(err, ErrSSRFBlocked) {
		return ErrClassSSRFBlocked
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ErrClassDNSResolutionFailed
	}

	// Check context timeouts first (Total Request Timeout)
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrClassRequestTimeout
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		// Could be connection timeout, read timeout, etc.
		return ErrClassConnectionTimeout
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Op == "dial" {
			// If it's a dial error but not a timeout, usually connection refused or unreachable
			if strings.Contains(opErr.Error(), "connection refused") {
				return ErrClassConnectionRefused
			}
			// SSRF blocked might bubble up here if not caught by errors.Is
			if strings.Contains(opErr.Error(), ErrClassSSRFBlocked) {
				return ErrClassSSRFBlocked
			}
			// General dial error
			return ErrClassConnectionRefused
		}
	}

	errStr := err.Error()
	if strings.Contains(errStr, "tls: ") || strings.Contains(errStr, "x509: ") {
		return ErrClassTLSError
	}

	if strings.Contains(errStr, "redirect blocked") {
		return ErrClassSSRFBlocked
	}

	if strings.Contains(errStr, "stopped after 3 redirects") {
		return ErrClassHTTPError // Treat max redirects as an HTTP failure
	}

	// Fallback for unknown network issues
	return ErrClassConnectionRefused
}
