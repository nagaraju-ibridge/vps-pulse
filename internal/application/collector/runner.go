package collector

import (
	"context"
	"log"
	"time"

	"vpsmonitoring-agent/internal/application/config"
	"vpsmonitoring-agent/internal/application/sender"
)

type Runner struct {
	collector Collector
	sender    sender.Sender
	snapshot  *config.Snapshot
	interval  time.Duration
	cancel    context.CancelFunc
}

func NewRunner(
	collector Collector,
	sender sender.Sender,
	snapshot *config.Snapshot,
	interval time.Duration,
) *Runner {
	return &Runner{
		collector: collector,
		sender:    sender,
		snapshot:  snapshot,
		interval:  interval,
	}
}

func (r *Runner) Start(ctx context.Context) {
	ctx, r.cancel = context.WithCancel(ctx)

	log.Printf("[INFO] application telemetry runner started (interval=%v)", r.interval)

	go func() {
		// Run initial collection immediately
		r.runCycle(ctx)

		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Println("[INFO] application telemetry runner stopping due to context cancellation")
				return
			case <-ticker.C:
				r.runCycle(ctx)
			}
		}
	}()
}

func (r *Runner) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
}

func (r *Runner) runCycle(ctx context.Context) {
	configs := r.snapshot.Get()

	var enabled int
	for _, cfg := range configs {
		if cfg.IsEnabled {
			enabled++
		}
	}

	if enabled == 0 {
		log.Println("[DEBUG] application telemetry runner: no enabled applications configured, skipping collection")
		return
	}

	batch := r.collector.Collect(ctx, configs)

	err := r.sender.SendTelemetry(ctx, batch)
	if err != nil {
		log.Printf("[WARN] application telemetry send failed: %v", err)
	} else {
		log.Printf("[INFO] application telemetry collected: applications=%d", len(batch.Applications))
	}
}
