package log

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpsmonitoring-agent/internal/application/config"
	"vpsmonitoring-agent/internal/application/responsetime"
)

// timedCombinedLogPattern recognizes the supported combined-style layout only
// when it has one explicit decimal-seconds field after the user agent, as
// produced by an Nginx format extended with $request_time.
var timedCombinedLogPattern = regexp.MustCompile(`^\S+\s+\S+\s+\S+\s+\[[^\]]+\]\s+"[^"]*"\s+\d{3}\s+\S+\s+"[^"]*"\s+"[^"]*"\s+(\d+\.\d+)\s*$`)

const (
	MaxBytesPerCycle        = 5 * 1024 * 1024 // 5 MB max read per collection
	MaxLineLength           = 8192            // 8 KB max line length
	FirstCollectionMaxBytes = 64 * 1024       // Only 64 KB on very first read
)

type LogMonitor interface {
	Collect(ctx context.Context, configs []config.ApplicationConfig) ([]ApplicationRequestStats, []responsetime.ApplicationResponseTimeStats)
}

type appLogState struct {
	lastOffset int64
	lastTime   time.Time
}

type defaultLogMonitor struct {
	mu              sync.Mutex
	states          map[int64]*appLogState
	allowedPrefixes []string
}

func NewLogMonitor() LogMonitor {
	return &defaultLogMonitor{
		states: make(map[int64]*appLogState),
		allowedPrefixes: []string{
			"/var/log/nginx",
			"/var/log/apache2",
			"/var/log/httpd",
		},
	}
}

// NewLogMonitorWithPrefixes is exposed for testing to allow temp directories.
func NewLogMonitorWithPrefixes(prefixes []string) LogMonitor {
	return &defaultLogMonitor{
		states:          make(map[int64]*appLogState),
		allowedPrefixes: prefixes,
	}
}

func ptrStr(s string) *string { return &s }

func (m *defaultLogMonitor) Collect(ctx context.Context, configs []config.ApplicationConfig) ([]ApplicationRequestStats, []responsetime.ApplicationResponseTimeStats) {
	var results []ApplicationRequestStats
	var rtResults []responsetime.ApplicationResponseTimeStats
	now := time.Now().UTC()

	// Evaluate sequentially in bounded mode; files are read quickly with small max limits.
	for _, cfg := range configs {
		if !cfg.IsEnabled {
			continue
		}

		stats := ApplicationRequestStats{
			ApplicationID: cfg.ID,
			CollectedAt:   now,
			Configured:    false,
		}

		rtStats := responsetime.ApplicationResponseTimeStats{
			ApplicationID:         cfg.ID,
			Source:                responsetime.SourceAccessLog,
			CollectedAt:           now,
			ResponseTimeAvailable: false,
		}

		if cfg.LogSourceType == nil || *cfg.LogSourceType == "null" || *cfg.LogSourceType == "" {
			stats.LogAvailable = false
			stats.ErrorClass = ptrStr("not_configured")
			results = append(results, stats)
			continue
		}

		if *cfg.LogSourceType != "nginx_access" && *cfg.LogSourceType != "apache_access" {
			stats.LogAvailable = false
			stats.ErrorClass = ptrStr("unsupported_log_type")
			stats.Configured = true
			results = append(results, stats)
			continue
		}

		if cfg.LogSourcePath == nil || *cfg.LogSourcePath == "" {
			stats.LogAvailable = false
			stats.ErrorClass = ptrStr("log_path_invalid")
			stats.Configured = true
			results = append(results, stats)
			continue
		}

		stats.Configured = true

		// Load or init state
		m.mu.Lock()
		state, ok := m.states[cfg.ID]
		if !ok {
			state = &appLogState{lastTime: now}
			m.states[cfg.ID] = state
		}
		windowStart := state.lastTime
		m.mu.Unlock()

		stats.WindowStart = windowStart
		stats.WindowEnd = now

		rtStats.WindowStart = windowStart
		rtStats.WindowEnd = now

		m.processLogFile(ctx, *cfg.LogSourcePath, state, &stats, &rtStats)

		// Calculate rate safely
		elapsed := now.Sub(windowStart).Seconds()
		if elapsed > 0 {
			rate := float64(stats.TotalRequests) / elapsed
			stats.RequestsPerSecond = &rate
		} else {
			rate := 0.0
			stats.RequestsPerSecond = &rate
		}

		// Update state time for next cycle
		m.mu.Lock()
		m.states[cfg.ID].lastTime = now
		m.mu.Unlock()

		results = append(results, stats)

		if rtStats.ResponseTimeAvailable {
			rtResults = append(rtResults, rtStats)
		}
	}

	return results, rtResults
}

func (m *defaultLogMonitor) validatePath(rawPath string) (string, error) {
	cleanPath := filepath.Clean(rawPath)
	if !filepath.IsAbs(cleanPath) {
		return "", fmt.Errorf("path must be absolute")
	}

	// Real OS resolution (evaluates symlinks)
	evalPath, err := filepath.EvalSymlinks(cleanPath)
	if err != nil {
		return "", err
	}

	evalPath = filepath.Clean(evalPath)

	// Check against allowlist prefixes
	// Since windows uses backslashes, we normalize for the prefix check
	normEval := filepath.ToSlash(evalPath)

	allowed := false
	for _, prefix := range m.allowedPrefixes {
		normPrefix := filepath.ToSlash(filepath.Clean(prefix))
		if strings.HasPrefix(normEval, normPrefix) {
			allowed = true
			break
		}
	}

	if !allowed {
		return "", fmt.Errorf("path outside supported log directories")
	}

	return evalPath, nil
}

func (m *defaultLogMonitor) processLogFile(ctx context.Context, rawPath string, state *appLogState, stats *ApplicationRequestStats, rtStats *responsetime.ApplicationResponseTimeStats) {
	safePath, err := m.validatePath(rawPath)
	if err != nil {
		if os.IsNotExist(err) {
			stats.ErrorClass = ptrStr("log_not_found")
		} else if strings.Contains(err.Error(), "outside supported log directories") {
			stats.ErrorClass = ptrStr("log_path_invalid")
		} else {
			stats.ErrorClass = ptrStr("permission_denied")
		}
		stats.LogAvailable = false
		return
	}

	file, err := os.Open(safePath)
	if err != nil {
		if os.IsNotExist(err) {
			stats.ErrorClass = ptrStr("log_not_found")
		} else if os.IsPermission(err) {
			stats.ErrorClass = ptrStr("permission_denied")
		} else {
			stats.ErrorClass = ptrStr("log_read_error")
		}
		stats.LogAvailable = false
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		stats.ErrorClass = ptrStr("log_read_error")
		stats.LogAvailable = false
		return
	}

	currentSize := info.Size()

	// Detect Rotation or Truncation
	if currentSize < state.lastOffset {
		state.lastOffset = 0
		stats.ErrorClass = ptrStr("file_rotated")
		// Continue reading from beginning, but limit strictly
	}

	// First collection logic (don't read entire historic log)
	if state.lastOffset == 0 && currentSize > FirstCollectionMaxBytes {
		state.lastOffset = currentSize - FirstCollectionMaxBytes
		// Best effort alignment to newline
		_, _ = file.Seek(state.lastOffset, io.SeekStart)
		buf := make([]byte, 1024)
		n, _ := file.Read(buf)
		idx := bytes.IndexByte(buf[:n], '\n')
		if idx >= 0 {
			state.lastOffset += int64(idx + 1)
		}
	}

	_, err = file.Seek(state.lastOffset, io.SeekStart)
	if err != nil {
		stats.ErrorClass = ptrStr("log_read_error")
		stats.LogAvailable = false
		return
	}

	// Bounded reading
	lr := io.LimitReader(file, MaxBytesPerCycle)
	reader := bufio.NewReader(lr)

	stats.LogAvailable = true
	var bytesRead int64

	for {
		if ctx.Err() != nil {
			break
		}

		line, err := reader.ReadSlice('\n')
		if err != nil {
			// Buffer might be full (line too long), or EOF
			if err == bufio.ErrBufferFull || len(line) > MaxLineLength {
				stats.MalformedLines++
				bytesRead += int64(len(line))
				continue
			}
			if err == io.EOF {
				bytesRead += int64(len(line))
				m.parseLine(line, stats, rtStats)
				break
			}
			break
		}

		bytesRead += int64(len(line))
		m.parseLine(line, stats, rtStats)
	}

	state.lastOffset += bytesRead
}

func (m *defaultLogMonitor) parseLine(line []byte, stats *ApplicationRequestStats, rtStats *responsetime.ApplicationResponseTimeStats) {
	if len(line) == 0 {
		return
	}

	// Simplistic parsing for Nginx/Apache:
	// e.g. 1.1.1.1 - - [date] "GET / HTTP/1.1" 200 123 "-" "-"
	// Or with duration: 1.1.1.1 - - [date] "GET / HTTP/1.1" 200 123 "-" "-" 0.125

	idx := bytes.Index(line, []byte(`" `))
	if idx == -1 {
		stats.MalformedLines++
		return
	}

	// Remainder should start with the status code
	remainder := line[idx+2:]

	// Find next space to isolate status
	spaceIdx := bytes.IndexByte(remainder, ' ')
	if spaceIdx == -1 {
		stats.MalformedLines++
		return
	}

	statusStr := string(remainder[:spaceIdx])
	code, err := strconv.Atoi(statusStr)
	if err != nil {
		stats.MalformedLines++
		return
	}

	stats.TotalRequests++

	switch {
	case code >= 200 && code < 300:
		stats.Status2xx++
	case code >= 300 && code < 400:
		stats.Status3xx++
	case code >= 400 && code < 500:
		stats.Status4xx++
	case code >= 500 && code < 600:
		stats.Status5xx++
	default:
		stats.StatusOther++
	}

	// Do not guess from arbitrary trailing values. Without the explicitly
	// supported timing field, response time remains unavailable.
	matches := timedCombinedLogPattern.FindStringSubmatch(strings.TrimSpace(string(line)))
	if len(matches) != 2 {
		return
	}
	durationSeconds, err := strconv.ParseFloat(matches[1], 64)
	if err != nil || durationSeconds < 0 || durationSeconds >= 86400 {
		return
	}

	ms := int64(durationSeconds * 1000)
	rtStats.ResponseTimeAvailable = true
	if rtStats.ResponseCount == 0 {
		rtStats.MinMs = ms
		rtStats.MaxMs = ms
		rtStats.AvgMs = ms
	} else {
		if ms < rtStats.MinMs {
			rtStats.MinMs = ms
		}
		if ms > rtStats.MaxMs {
			rtStats.MaxMs = ms
		}
		rtStats.AvgMs = rtStats.AvgMs + (ms-rtStats.AvgMs)/(rtStats.ResponseCount+1)
	}
	rtStats.ResponseCount++
}
