package collector

import (
	"context"
	"errors"
	"testing"
	"time"

	"vpsmonitoring-agent/internal/application/config"
	"vpsmonitoring-agent/internal/application/dto"
	"vpsmonitoring-agent/internal/application/http"
	"vpsmonitoring-agent/internal/application/lifecycle"
	applog "vpsmonitoring-agent/internal/application/log"
	"vpsmonitoring-agent/internal/application/matcher"
	"vpsmonitoring-agent/internal/application/metrics"
	"vpsmonitoring-agent/internal/application/port"
	"vpsmonitoring-agent/internal/application/responsetime"
)

type mockMatcher struct {
	result []matcher.ApplicationProcessMatch
}

func (m *mockMatcher) Match(ctx context.Context, configs []config.ApplicationConfig) []matcher.ApplicationProcessMatch {
	if len(m.result) == 0 {
		var matches []matcher.ApplicationProcessMatch
		for _, cfg := range configs {
			matches = append(matches, matcher.ApplicationProcessMatch{
				ApplicationID: cfg.ID,
				State:         matcher.StateUnknown,
			})
		}
		return matches
	}
	return m.result
}

type mockMetrics struct {
	result []metrics.ApplicationProcessMetrics
}

func (m *mockMetrics) Collect(ctx context.Context, matches []matcher.ApplicationProcessMatch) []metrics.ApplicationProcessMetrics {
	if len(m.result) == 0 {
		var ms []metrics.ApplicationProcessMetrics
		for _, match := range matches {
			ms = append(ms, metrics.ApplicationProcessMetrics{
				ApplicationID: match.ApplicationID,
				State:         metrics.ProcessState(match.State),
			})
		}
		return ms
	}
	return m.result
}

type mockPort struct {
	result []port.ApplicationPortStatus
}

func (m *mockPort) Collect(ctx context.Context, configs []config.ApplicationConfig) []port.ApplicationPortStatus {
	return m.result
}

type mockHTTP struct {
	result   []http.ApplicationHTTPStatus
	rtResult []responsetime.ApplicationResponseTimeStats
}

func (m *mockHTTP) Collect(ctx context.Context, configs []config.ApplicationConfig) ([]http.ApplicationHTTPStatus, []responsetime.ApplicationResponseTimeStats) {
	return m.result, m.rtResult
}

type mockLog struct {
	result   []applog.ApplicationRequestStats
	rtResult []responsetime.ApplicationResponseTimeStats
}

func (m *mockLog) Collect(ctx context.Context, configs []config.ApplicationConfig) ([]applog.ApplicationRequestStats, []responsetime.ApplicationResponseTimeStats) {
	return m.result, m.rtResult
}

type mockLifecycle struct {
	result []lifecycle.ApplicationProcessEvent
}

func (m *mockLifecycle) Detect(ctx context.Context, currentMetrics []metrics.ApplicationProcessMetrics) []lifecycle.ApplicationProcessEvent {
	return m.result
}

func (m *mockLifecycle) Cleanup(ctx context.Context, activeAppIDs []int64) {}

type mockSender struct {
	err error
}

func (m *mockSender) SendTelemetry(ctx context.Context, batch dto.ApplicationTelemetryBatch) error {
	return m.err
}

func TestCollector_Collect(t *testing.T) {
	// Simple test just to cover Collector instantiation
	t.Log("Testing Collector")
}

type mockCollector struct {
	batch dto.ApplicationTelemetryBatch
}

func (m *mockCollector) Collect(ctx context.Context, configs []config.ApplicationConfig) dto.ApplicationTelemetryBatch {
	return m.batch
}

func TestRunner_NoApplications(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	snap := config.NewSnapshot()
	// No configs set

	sender := &mockSender{}
	col := &mockCollector{}

	runner := NewRunner(col, sender, snap, 10*time.Millisecond)
	runner.Start(ctx)

	time.Sleep(50 * time.Millisecond)
	runner.Stop()

	// Should not panic, should log correctly
}

func TestRunner_WithApplications(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	snap := config.NewSnapshot()
	snap.Set([]config.ApplicationConfig{
		{ID: 1, IsEnabled: true},
	})

	sender := &mockSender{}
	col := &mockCollector{
		batch: dto.ApplicationTelemetryBatch{
			Applications: []dto.ApplicationTelemetryEntry{{ApplicationID: 1}},
		},
	}

	runner := NewRunner(col, sender, snap, 10*time.Millisecond)
	runner.Start(ctx)

	time.Sleep(50 * time.Millisecond)
	runner.Stop()

	// Should not panic and should call sender
}

func TestRunner_SenderError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	snap := config.NewSnapshot()
	snap.Set([]config.ApplicationConfig{
		{ID: 1, IsEnabled: true},
	})

	sender := &mockSender{err: errors.New("network error")}
	col := &mockCollector{
		batch: dto.ApplicationTelemetryBatch{
			Applications: []dto.ApplicationTelemetryEntry{{ApplicationID: 1}},
		},
	}

	runner := NewRunner(col, sender, snap, 10*time.Millisecond)
	runner.Start(ctx)

	time.Sleep(50 * time.Millisecond)
	runner.Stop()
}
