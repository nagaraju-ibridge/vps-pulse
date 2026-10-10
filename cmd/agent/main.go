package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vpsmonitoring-agent/internal/client"
	"vpsmonitoring-agent/internal/config"
	discoverycollector "vpsmonitoring-agent/internal/discovery/collector"
	discoverysender "vpsmonitoring-agent/internal/discovery/sender"
	healthCollector "vpsmonitoring-agent/internal/health/collector"
	healthConfig "vpsmonitoring-agent/internal/health/config"
	healthSender "vpsmonitoring-agent/internal/health/sender"
	healthSyncer "vpsmonitoring-agent/internal/health/syncer"

	appCollector "vpsmonitoring-agent/internal/application/collector"
	appConfig "vpsmonitoring-agent/internal/application/config"
	appHttp "vpsmonitoring-agent/internal/application/http"
	appLifecycle "vpsmonitoring-agent/internal/application/lifecycle"
	appLog "vpsmonitoring-agent/internal/application/log"
	appMatcher "vpsmonitoring-agent/internal/application/matcher"
	appMetrics "vpsmonitoring-agent/internal/application/metrics"
	appPort "vpsmonitoring-agent/internal/application/port"
	appSender "vpsmonitoring-agent/internal/application/sender"
	appSyncer "vpsmonitoring-agent/internal/application/syncer"

	"vpsmonitoring-agent/internal/heartbeat"
	"vpsmonitoring-agent/internal/metrics/collector"
	"vpsmonitoring-agent/internal/metrics/sender"
	processcollector "vpsmonitoring-agent/internal/process/collector"
	processsender "vpsmonitoring-agent/internal/process/sender"
	"vpsmonitoring-agent/internal/registration"
	systemdcollector "vpsmonitoring-agent/internal/systemd/collector"
	systemdsender "vpsmonitoring-agent/internal/systemd/sender"
)

func main() {
	log.Println("[INFO] starting vpsmonitoring-agent daemon...")

	// 1. Load configuration from environment and state file
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("[FATAL] configuration error: %v", err)
	}

	log.Printf("[INFO] configuration loaded: backend=%s heartbeat_interval=%v metric_interval=%v discovery_interval=%v state_file=%s",
		cfg.BackendURL, cfg.HeartbeatInterval, cfg.MetricInterval, cfg.DiscoveryInterval, cfg.StateFilePath)

	// 2. Setup context listening for process termination (SIGINT, SIGTERM)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 3. Initialize HTTP client
	httpClient := client.NewClient(cfg.BackendURL, client.DefaultTimeout)

	// 4. Registration flow: check if agent credential exists, otherwise register
	agentCredential := cfg.AgentCredential
	agentID := cfg.AgentID
	if agentCredential == "" || agentID == "" {
		log.Println("[INFO] missing local agent credential or ID; registering with backend using installation token...")

		regClient := registration.NewClient(httpClient)
		state, err := regClient.Register(ctx, cfg.InstallationToken)
		if err != nil {
			log.Fatalf("[FATAL] agent registration failed: %v", err)
		}

		log.Printf("[INFO] agent registration successful: agent_id=%s server_id=%d", state.AgentID, state.ServerID)

		// Persist credential to local state file
		if err := config.SaveState(cfg.StateFilePath, state); err != nil {
			log.Printf("[WARN] failed to persist agent credentials to %s: %v", cfg.StateFilePath, err)
		} else {
			log.Printf("[INFO] agent credentials saved to %s", cfg.StateFilePath)
		}

		agentCredential = state.AgentCredential
		agentID = state.AgentID
	} else {
		log.Println("[INFO] valid agent credential and ID loaded; skipping registration")
	}

	// Update cfg struct with credential for downstream components that need *cfg
	cfg.AgentCredential = agentCredential
	cfg.AgentID = agentID

	// 5. Initialize and launch Heartbeat Runner (Phase 2C.5)
	hbClient := heartbeat.NewClient(httpClient)
	hbRunner := heartbeat.NewRunner(hbClient, agentCredential, cfg.HeartbeatInterval)
	hbRunner.Start(ctx)

	// 6. Initialize and launch Metric Sender Runner (Phase 2C.7)
	snapCollector := collector.NewSnapshotCollector()
	metricClient := sender.NewClient(httpClient, snapCollector)
	metricRunner := sender.NewRunner(metricClient, agentCredential, cfg.MetricInterval)
	metricRunner.Start(ctx)

	// 7. Initialize and launch Process Snapshot Runner (Phase 3.4B.3)
	// Process collection should run every 60 seconds (or use MetricInterval for simplicity)
	procCollector := processcollector.NewProcessCollector()
	procClient := processsender.NewClient(httpClient, procCollector)
	// Passing 0 for totalMemBytes for now; memory % will be nil (can be enhanced later)
	procRunner := processsender.NewRunner(procClient, agentID, agentCredential, 60*time.Second, 0)
	procRunner.Start(ctx)

	// 8. Initialize and launch Systemd Snapshot Runner
	sysCollector := systemdcollector.NewSystemdCollector()
	sysClient := systemdsender.NewClient(httpClient, sysCollector)
	sysRunner := systemdsender.NewRunner(sysClient, agentID, agentCredential, 60*time.Second)
	sysRunner.Start(ctx)

	// 9. Initialize and launch HTTP Health Config Syncer and Check Scheduler (Phase 3.5B.2 & 3.5B.3)
	healthConfigSnapshot := healthConfig.NewSnapshot()
	hSyncer := healthSyncer.NewSyncer(cfg, healthConfigSnapshot)
	go hSyncer.Start(ctx, 60*time.Second)

	healthResultSnapshot := healthCollector.NewResultSnapshot()
	hScheduler := healthCollector.NewScheduler(healthConfigSnapshot, healthResultSnapshot)
	go hScheduler.Start(ctx)

	// Phase 3.5B.4: Send health results to backend
	hSender := healthSender.NewSender(httpClient, healthResultSnapshot, 60*time.Second, agentCredential, agentID)
	go hSender.Start(ctx)

	// 10. Initialize and launch Application Discovery Reporting (Phase 3.5C.8)
	discoveryCollector := discoverycollector.NewDiscoveryCollector()
	discoveryHTTPClient := client.NewClient(cfg.BackendURL, 90*time.Second)
	discoveryClient := discoverysender.NewClient(discoveryHTTPClient, discoveryCollector)
	discoveryRunner := discoverysender.NewRunner(discoveryClient, agentID, agentCredential, cfg.DiscoveryInterval)
	discoveryRunner.Start(ctx)

	// Phase 3.6.4: Application Config Syncer
	appConfigSnapshot := appConfig.NewSnapshot()
	applicationSyncer := appSyncer.NewSyncer(cfg, appConfigSnapshot)
	go applicationSyncer.Start(ctx, 60*time.Second)

	// Phase 3.6.12: Application Telemetry Collector and Runner
	applicationSender := appSender.NewSender(cfg)
	applicationCollector := appCollector.NewCollector(
		appMatcher.NewMatcher(),
		appMetrics.NewCollector(),
		appPort.NewPortMonitor(),
		appHttp.NewHTTPMonitor(),
		appLog.NewLogMonitor(),
		appLifecycle.NewDetector(),
	)
	applicationRunner := appCollector.NewRunner(applicationCollector, applicationSender, appConfigSnapshot, 60*time.Second)
	applicationRunner.Start(ctx)

	<-ctx.Done()
	log.Println("[INFO] shutdown signal received; terminating agent daemon...")

	// 11. Gracefully stop workers
	hbRunner.Stop()
	metricRunner.Stop()
	procRunner.Stop()
	sysRunner.Stop()
	discoveryRunner.Stop()
	applicationRunner.Stop()
	log.Println("[INFO] vpsmonitoring-agent stopped cleanly")
}
