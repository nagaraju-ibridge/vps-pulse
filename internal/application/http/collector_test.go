package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"vpsmonitoring-agent/internal/application/config"
)

func TestHTTPMonitor_BasicConfig(t *testing.T) {
	monitor := NewHTTPMonitor()

	configs := []config.ApplicationConfig{
		{ID: 1, IsEnabled: true, MonitorHttpUrl: nil},
		{ID: 2, IsEnabled: true, MonitorHttpUrl: ptrStr("")},
		{ID: 3, IsEnabled: true, MonitorHttpUrl: ptrStr("ftp://invalid")},
	}

	results, _ := monitor.Collect(context.Background(), configs)
	if len(results) != 3 {
		t.Fatalf("expected 3 results")
	}

	if results[0].Configured {
		t.Errorf("expected app 1 not configured")
	}

	if results[1].Configured {
		t.Errorf("expected app 2 not configured")
	}

	if !results[2].Configured || results[2].Available {
		t.Errorf("expected app 3 configured but unavailable")
	}
	if *results[2].ErrorClass != "unsupported_scheme" {
		t.Errorf("expected unsupported_scheme, got %s", *results[2].ErrorClass)
	}
}

func TestHTTPMonitor_ValidRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	monitor := NewHTTPMonitor()
	configs := []config.ApplicationConfig{
		{ID: 1, IsEnabled: true, MonitorHttpUrl: ptrStr(server.URL)},
	}

	results, _ := monitor.Collect(context.Background(), configs)
	if len(results) != 1 {
		t.Fatalf("expected 1 result")
	}

	res := results[0]
	if !res.Available {
		t.Errorf("expected available")
	}
	if *res.StatusCode != 200 {
		t.Errorf("expected 200, got %d", *res.StatusCode)
	}
	if res.LatencyMs == nil || *res.LatencyMs < 0 {
		t.Errorf("invalid latency")
	}
}

func TestHTTPMonitor_ErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	monitor := NewHTTPMonitor()
	configs := []config.ApplicationConfig{
		{ID: 1, IsEnabled: true, MonitorHttpUrl: ptrStr(server.URL)},
	}

	results, _ := monitor.Collect(context.Background(), configs)
	res := results[0]
	if !res.Available {
		t.Errorf("expected available (we got a response)")
	}
	if *res.StatusCode != 500 {
		t.Errorf("expected 500, got %d", *res.StatusCode)
	}
}

func TestHTTPMonitor_LocalhostException(t *testing.T) {
	// A localhost server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// server.URL is usually http://127.0.0.1:port
	monitor := NewHTTPMonitor()

	// App 1 uses 127.0.0.1 explicitly (loopback allowed)
	configs := []config.ApplicationConfig{
		{ID: 1, IsEnabled: true, MonitorHttpUrl: ptrStr(server.URL)},
	}

	results, _ := monitor.Collect(context.Background(), configs)
	res := results[0]

	if !res.Available {
		t.Errorf("expected localhost explicit URL to be allowed and available")
	}
	if res.ErrorClass != nil && *res.ErrorClass == "ssrf_blocked" {
		t.Errorf("expected no ssrf_blocked for explicit localhost")
	}
}

func TestHTTPMonitor_SSRFProtection(t *testing.T) {
	// Using a fake domain that redirects to loopback or a private IP.
	// But our explicit URL is NOT loopback (e.g. http://my-private-app).

	monitor := NewHTTPMonitor()

	configs := []config.ApplicationConfig{
		// 10.x.x.x is private
		{ID: 1, IsEnabled: true, MonitorHttpUrl: ptrStr("http://10.0.0.1/")},
		// 169.254.x.x is link-local (metadata)
		{ID: 2, IsEnabled: true, MonitorHttpUrl: ptrStr("http://169.254.169.254/")},
	}

	results, _ := monitor.Collect(context.Background(), configs)

	if results[0].Available {
		t.Errorf("expected 10.x to be unavailable")
	}
	if *results[0].ErrorClass != "ssrf_blocked" {
		t.Errorf("expected ssrf_blocked, got %s", *results[0].ErrorClass)
	}

	if results[1].Available {
		t.Errorf("expected metadata to be unavailable")
	}
	if *results[1].ErrorClass != "ssrf_blocked" {
		t.Errorf("expected ssrf_blocked, got %s", *results[1].ErrorClass)
	}
}

func TestHTTPMonitor_RedirectLimit(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, server.URL, http.StatusFound)
	}))
	defer server.Close()

	monitor := NewHTTPMonitor()
	configs := []config.ApplicationConfig{
		{ID: 1, IsEnabled: true, MonitorHttpUrl: ptrStr(server.URL)},
	}

	results, _ := monitor.Collect(context.Background(), configs)
	res := results[0]

	if res.Available {
		t.Errorf("expected unavailable due to redirect loop")
	}
	if *res.ErrorClass != "redirect_limit_exceeded" {
		t.Errorf("expected redirect_limit_exceeded, got %s", *res.ErrorClass)
	}
}
