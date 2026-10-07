package collector

import (
	"context"
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

type Collector interface {
	Collect(ctx context.Context, configs []config.ApplicationConfig) dto.ApplicationTelemetryBatch
}

type defaultCollector struct {
	appMatcher        *matcher.Matcher
	metricsCollector  metrics.ProcessMetricsCollector
	portMonitor       port.PortMonitor
	httpMonitor       http.HTTPMonitor
	logMonitor        applog.LogMonitor
	lifecycleDetector lifecycle.Detector
}

func NewCollector(
	appMatcher *matcher.Matcher,
	metricsCollector metrics.ProcessMetricsCollector,
	portMonitor port.PortMonitor,
	httpMonitor http.HTTPMonitor,
	logMonitor applog.LogMonitor,
	lifecycleDetector lifecycle.Detector,
) Collector {
	return &defaultCollector{
		appMatcher:        appMatcher,
		metricsCollector:  metricsCollector,
		portMonitor:       portMonitor,
		httpMonitor:       httpMonitor,
		logMonitor:        logMonitor,
		lifecycleDetector: lifecycleDetector,
	}
}

func (c *defaultCollector) Collect(ctx context.Context, configs []config.ApplicationConfig) dto.ApplicationTelemetryBatch {
	now := time.Now().UTC()

	var enabledConfigs []config.ApplicationConfig
	var activeAppIDs []int64
	for _, cfg := range configs {
		if cfg.IsEnabled {
			enabledConfigs = append(enabledConfigs, cfg)
			activeAppIDs = append(activeAppIDs, cfg.ID)
		}
	}

	if len(enabledConfigs) > 15 {
		enabledConfigs = enabledConfigs[:15]
	}

	// 1. Process Matching
	matches := c.appMatcher.Match(ctx, enabledConfigs)

	// 2. Process Metrics
	procMetrics := c.metricsCollector.Collect(ctx, matches)

	// 3. Lifecycle Events
	events := c.lifecycleDetector.Detect(ctx, procMetrics)
	c.lifecycleDetector.Cleanup(ctx, activeAppIDs)

	// Group events by appID
	eventsByApp := make(map[int64][]dto.LifecycleEventDTO)
	for _, ev := range events {
		dtoEv := dto.LifecycleEventDTO{
			EventType: string(ev.EventType),
			EventTime: ev.EventTime,
			OldPID:    ev.OldPID,
			NewPID:    ev.NewPID,
			Details:   ev.Details,
		}
		eventsByApp[ev.ApplicationID] = append(eventsByApp[ev.ApplicationID], dtoEv)
	}

	// 4. Port Monitoring
	portStats := c.portMonitor.Collect(ctx, enabledConfigs)
	portByApp := make(map[int64]port.ApplicationPortStatus)
	for _, ps := range portStats {
		portByApp[ps.ApplicationID] = ps
	}

	// 5. HTTP Monitoring
	httpStats, httpRtStats := c.httpMonitor.Collect(ctx, enabledConfigs)
	httpByApp := make(map[int64]http.ApplicationHTTPStatus)
	for _, hs := range httpStats {
		httpByApp[hs.ApplicationID] = hs
	}

	// 6. Access Log Monitoring
	logStats, logRtStats := c.logMonitor.Collect(ctx, enabledConfigs)
	logByApp := make(map[int64]applog.ApplicationRequestStats)
	for _, ls := range logStats {
		logByApp[ls.ApplicationID] = ls
	}

	// Group Response Time Stats
	rtByApp := make(map[int64][]responsetime.ApplicationResponseTimeStats)
	for _, rt := range httpRtStats {
		rtByApp[rt.ApplicationID] = append(rtByApp[rt.ApplicationID], rt)
	}
	for _, rt := range logRtStats {
		rtByApp[rt.ApplicationID] = append(rtByApp[rt.ApplicationID], rt)
	}

	// 7. Build DTO
	batch := dto.ApplicationTelemetryBatch{
		CollectedAt:  now,
		Applications: make([]dto.ApplicationTelemetryEntry, 0, len(enabledConfigs)),
	}

	for i, cfg := range enabledConfigs {
		pm := procMetrics[i]
		appEvents := eventsByApp[cfg.ID]

		// To respect max=20 validation
		if len(appEvents) > 20 {
			appEvents = appEvents[len(appEvents)-20:]
		}

		entry := dto.ApplicationTelemetryEntry{
			ApplicationID:    cfg.ID,
			ObservationState: string(pm.State),
			ProcessMatched:   pm.State == metrics.StateMatched,
			ProcessCount:     pm.ProcessCount,
			CPUPercent:       pm.CPUPercent,
			MemoryBytes:      pm.MemoryBytes,
			LifecycleEvents:  appEvents,
		}

		if len(pm.PIDs) > 0 {
			entry.PrimaryPID = &pm.PIDs[0]
			if st, ok := pm.ProcessStartTimes[pm.PIDs[0]]; ok {
				stCopy := st
				entry.PrimaryStartTime = &stCopy
			}
		}

		if ps, ok := portByApp[cfg.ID]; ok {
			entry.PortConfigured = ps.Configured
			if ps.State == port.PortListening {
				b := true
				entry.PortListening = &b
			} else if ps.State == port.PortNotListening {
				b := false
				entry.PortListening = &b
			}
		}

		if hs, ok := httpByApp[cfg.ID]; ok {
			entry.HTTPConfigured = hs.Configured
			if hs.Configured {
				entry.HTTPAvailable = &hs.Available
				entry.HTTPStatusCode = hs.StatusCode
				entry.HTTPLatencyMs = hs.LatencyMs
				entry.HTTPErrorClass = hs.ErrorClass
			}
		}

		if ls, ok := logByApp[cfg.ID]; ok {
			entry.LogConfigured = ls.Configured
			if ls.Configured {
				entry.LogAvailable = &ls.LogAvailable
				entry.LogErrorClass = ls.ErrorClass
				entry.TotalRequests = ptrInt64Safe(ls.TotalRequests)
				entry.RequestsPerSecond = ls.RequestsPerSecond
				entry.Status2xx = ptrInt64Safe(ls.Status2xx)
				entry.Status3xx = ptrInt64Safe(ls.Status3xx)
				entry.Status4xx = ptrInt64Safe(ls.Status4xx)
				entry.Status5xx = ptrInt64Safe(ls.Status5xx)
				entry.StatusOther = ptrInt64Safe(ls.StatusOther)
			}
		}

		for _, rt := range rtByApp[cfg.ID] {
			if !rt.ResponseTimeAvailable {
				continue
			}
			if rt.Source == responsetime.SourceActiveHTTP {
				entry.ActiveResponseCount = &rt.ResponseCount
				entry.ActiveResponseAvgMs = &rt.AvgMs
			} else if rt.Source == responsetime.SourceAccessLog {
				entry.PassiveResponseCount = &rt.ResponseCount
				entry.PassiveResponseAvgMs = &rt.AvgMs
			}
		}

		batch.Applications = append(batch.Applications, entry)
	}

	return batch
}

func ptrInt64Safe(i int64) *int64 { return &i }
