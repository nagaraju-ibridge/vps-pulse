package log

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vpsmonitoring-agent/internal/application/config"
)

func TestLogMonitor_Configuration(t *testing.T) {
	monitor := NewLogMonitor()

	configs := []config.ApplicationConfig{
		{ID: 1, IsEnabled: true, LogSourceType: ptrStr("null")},
		{ID: 2, IsEnabled: true, LogSourceType: ptrStr("invalid_type")},
		{ID: 3, IsEnabled: true, LogSourceType: ptrStr("nginx_access"), LogSourcePath: ptrStr("")},
	}

	results, _ := monitor.Collect(context.Background(), configs)

	if results[0].Configured {
		t.Errorf("expected null to be unconfigured")
	}
	if *results[1].ErrorClass != "unsupported_log_type" {
		t.Errorf("expected unsupported_log_type")
	}
	if *results[2].ErrorClass != "log_path_invalid" {
		t.Errorf("expected log_path_invalid")
	}
}

func TestLogMonitor_PathValidation(t *testing.T) {
	tempDir := t.TempDir()

	monitor := NewLogMonitorWithPrefixes([]string{tempDir})

	// Escape attempt
	escapePath := filepath.Join(tempDir, "..", "secret.txt")

	configs := []config.ApplicationConfig{
		{ID: 1, IsEnabled: true, LogSourceType: ptrStr("nginx_access"), LogSourcePath: ptrStr(escapePath)},
	}

	results, _ := monitor.Collect(context.Background(), configs)
	if *results[0].ErrorClass != "log_path_invalid" && *results[0].ErrorClass != "log_not_found" {
		// Depends on if it exists. If it doesn't exist, validatePath fails early on IsNotExist during EvalSymlinks.
		// If the parent directory evaluates, it might fail prefix check.
		// As long as it doesn't read successfully.
		if results[0].LogAvailable {
			t.Errorf("should not be available")
		}
	}
}

func TestLogMonitor_ParsingAndRate(t *testing.T) {
	tempDir := t.TempDir()
	monitor := NewLogMonitorWithPrefixes([]string{tempDir})

	logPath := filepath.Join(tempDir, "access.log")
	content := []byte(`1.1.1.1 - - [01/Jan/2026] "GET / HTTP/1.1" 200 123 "-" "-"
2.2.2.2 - - [01/Jan/2026] "POST / HTTP/1.1" 404 12 "-" "-"
3.3.3.3 - - [01/Jan/2026] "GET / HTTP/1.1" 500 12 "-" "-"
malformed line
4.4.4.4 - - [01/Jan/2026] "GET / HTTP/1.1" 301 12 "-" "-"
`)
	_ = os.WriteFile(logPath, content, 0644)

	configs := []config.ApplicationConfig{
		{ID: 1, IsEnabled: true, LogSourceType: ptrStr("nginx_access"), LogSourcePath: ptrStr(logPath)},
	}

	// Force artificial time delay to calculate rate > 0
	monitor.(*defaultLogMonitor).mu.Lock()
	monitor.(*defaultLogMonitor).states[1] = &appLogState{
		lastTime: time.Now().Add(-2 * time.Second),
	}
	monitor.(*defaultLogMonitor).mu.Unlock()

	results, rtResults := monitor.Collect(context.Background(), configs)
	res := results[0]

	if !res.LogAvailable {
		t.Fatalf("expected log to be available")
	}
	if res.TotalRequests != 4 {
		t.Errorf("expected 4 total requests, got %d", res.TotalRequests)
	}
	if res.Status2xx != 1 || res.Status4xx != 1 || res.Status5xx != 1 || res.Status3xx != 1 {
		t.Errorf("status buckets incorrect")
	}
	if res.MalformedLines != 1 {
		t.Errorf("expected 1 malformed line, got %d", res.MalformedLines)
	}
	if res.RequestsPerSecond == nil || *res.RequestsPerSecond <= 0 {
		t.Errorf("expected rate > 0")
	}
	if len(rtResults) != 0 {
		t.Fatalf("standard combined log must leave response time unavailable")
	}

	// 2nd collection should return 0 requests (incremental)
	monitor.(*defaultLogMonitor).mu.Lock()
	monitor.(*defaultLogMonitor).states[1].lastTime = time.Now().Add(-2 * time.Second)
	monitor.(*defaultLogMonitor).mu.Unlock()

	results2, _ := monitor.Collect(context.Background(), configs)
	if results2[0].TotalRequests != 0 {
		t.Errorf("expected 0 requests on second read, got %d", results2[0].TotalRequests)
	}
}

func TestLogMonitor_ResponseTime(t *testing.T) {
	tempDir := t.TempDir()
	monitor := NewLogMonitorWithPrefixes([]string{tempDir})

	logPath := filepath.Join(tempDir, "access_rt.log")
	content := []byte(`1.1.1.1 - - [01/Jan/2026] "GET / HTTP/1.1" 200 123 "-" "-" 0.150
2.2.2.2 - - [01/Jan/2026] "POST / HTTP/1.1" 404 12 "-" "-" 1.500
3.3.3.3 - - [01/Jan/2026] "GET / HTTP/1.1" 500 12 "-" "-" 0.045
malformed line
4.4.4.4 - - [01/Jan/2026] "GET / HTTP/1.1" 301 12 "-" "-" -
`)
	_ = os.WriteFile(logPath, content, 0644)

	configs := []config.ApplicationConfig{
		{ID: 1, IsEnabled: true, LogSourceType: ptrStr("nginx_access"), LogSourcePath: ptrStr(logPath)},
	}

	_, rtResults := monitor.Collect(context.Background(), configs)
	if len(rtResults) != 1 {
		t.Fatalf("expected 1 response time result")
	}

	res := rtResults[0]
	if !res.ResponseTimeAvailable {
		t.Errorf("expected response time available")
	}
	if res.ResponseCount != 3 {
		t.Errorf("expected 3 responses with timing, got %d", res.ResponseCount)
	}
	if res.MinMs != 45 {
		t.Errorf("expected min 45, got %d", res.MinMs)
	}
	if res.MaxMs != 1500 {
		t.Errorf("expected max 1500, got %d", res.MaxMs)
	}
	// avg = (150 + 1500 + 45) / 3 = 565
	if res.AvgMs < 560 || res.AvgMs > 570 {
		t.Errorf("expected avg ~565, got %d", res.AvgMs)
	}
}

func TestLogMonitor_InvalidAndMixedResponseTime(t *testing.T) {
	tempDir := t.TempDir()
	monitor := NewLogMonitorWithPrefixes([]string{tempDir})
	logPath := filepath.Join(tempDir, "access_mixed.log")
	content := []byte(`1.1.1.1 - - [01/Jan/2026] "GET /standard HTTP/1.1" 200 123 "-" "agent"
2.2.2.2 - - [01/Jan/2026] "GET /timed HTTP/1.1" 201 123 "-" "agent" 0.003
3.3.3.3 - - [01/Jan/2026] "GET /invalid HTTP/1.1" 404 12 "-" "agent" invalid
4.4.4.4 - - [01/Jan/2026] "GET /ambiguous HTTP/1.1" 500 12 "-" "agent" 125
`)
	if err := os.WriteFile(logPath, content, 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	configs := []config.ApplicationConfig{{ID: 1, IsEnabled: true, LogSourceType: ptrStr("nginx_access"), LogSourcePath: ptrStr(logPath)}}
	requestResults, rtResults := monitor.Collect(context.Background(), configs)
	requests := requestResults[0]
	if requests.TotalRequests != 4 || requests.Status2xx != 2 || requests.Status4xx != 1 || requests.Status5xx != 1 {
		t.Fatalf("request/status parsing changed: %+v", requests)
	}
	if len(rtResults) != 1 {
		t.Fatalf("expected one response-time aggregate, got %d", len(rtResults))
	}
	timing := rtResults[0]
	if timing.ResponseCount != 1 || timing.MinMs != 3 || timing.AvgMs != 3 || timing.MaxMs != 3 {
		t.Fatalf("expected only 0.003s timing as 3ms, got %+v", timing)
	}
}

func TestLogMonitor_Truncation(t *testing.T) {
	tempDir := t.TempDir()
	monitor := NewLogMonitorWithPrefixes([]string{tempDir})
	logPath := filepath.Join(tempDir, "access.log")

	// First write
	os.WriteFile(logPath, []byte(`1.1.1.1 - - [01/Jan/2026] "GET / HTTP/1.1" 200 123 "-" "-"`+"\n"), 0644)

	configs := []config.ApplicationConfig{
		{ID: 1, IsEnabled: true, LogSourceType: ptrStr("nginx_access"), LogSourcePath: ptrStr(logPath)},
	}

	results, _ := monitor.Collect(context.Background(), configs)
	if results[0].TotalRequests != 1 {
		t.Fatalf("expected 1 request on first read")
	}

	// Truncate and write new (must be shorter to trigger size-based rotation detection easily in test)
	os.WriteFile(logPath, []byte(`2.2.2.2 "GET" 200 123`+"\n"), 0644)

	results2, _ := monitor.Collect(context.Background(), configs)
	if results2[0].ErrorClass == nil || *results2[0].ErrorClass != "file_rotated" {
		t.Errorf("expected file_rotated error class")
	}
	if results2[0].TotalRequests != 1 {
		t.Errorf("expected 1 request after truncation, got %d", results2[0].TotalRequests)
	}
}
