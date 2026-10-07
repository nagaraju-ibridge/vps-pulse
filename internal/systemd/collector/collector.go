package collector

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	gops "github.com/shirou/gopsutil/v4/process"
	"vpsmonitoring-agent/internal/systemd/models"
)

const (
	MaxServiceCount   = 100
	collectionTimeout = 2 * time.Second
)

var cgroupPathFmt = "/proc/%d/cgroup"

type SystemdCollector interface {
	Collect(ctx context.Context) models.ServicePayload
}

type processLister func(ctx context.Context) ([]*gops.Process, error)

type defaultSystemdCollector struct {
	lister processLister
}

func NewSystemdCollector() SystemdCollector {
	return &defaultSystemdCollector{
		lister: func(ctx context.Context) ([]*gops.Process, error) {
			return gops.ProcessesWithContext(ctx)
		},
	}
}

func NewSystemdCollectorWithLister(l func(ctx context.Context) ([]*gops.Process, error)) SystemdCollector {
	return &defaultSystemdCollector{lister: l}
}

func (c *defaultSystemdCollector) Collect(ctx context.Context) models.ServicePayload {
	payload := models.ServicePayload{
		CollectedAt: time.Now().UTC(),
		Services:    make([]models.ServiceSnapshot, 0),
	}

	collectCtx, cancel := context.WithTimeout(ctx, collectionTimeout)
	defer cancel()

	procs, err := c.lister(collectCtx)
	if err != nil {
		log.Printf("[WARN] systemd process enumeration failed: %v", err)
		return payload
	}
	log.Printf("[DEBUG] SystemdCollector: enumerated %d processes", len(procs))

	seen := make(map[string]bool)

	for _, p := range procs {
		if len(payload.Services) >= MaxServiceCount {
			break
		}

		select {
		case <-collectCtx.Done():
			log.Printf("[WARN] systemd collection timeout reached")
			return payload
		default:
		}

		unit := extractSystemdUnitFromCgroup(p.Pid)
		if unit == "" || !strings.HasSuffix(unit, ".service") {
			continue
		}

		if seen[unit] {
			continue
		}
		seen[unit] = true

		snap := models.ServiceSnapshot{
			Name:        unit,
			ActiveState: "active",
			SubState:    "running",
			LoadState:   "loaded",
			Description: unit,
			CollectedAt: payload.CollectedAt,
		}

		payload.Services = append(payload.Services, snap)
	}
	
	log.Printf("[DEBUG] SystemdCollector: found %d services", len(payload.Services))

	return payload
}

func extractSystemdUnitFromCgroup(pid int32) string {
	path := fmt.Sprintf(cgroupPathFmt, pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.Contains(line, ".service") {
			parts := strings.Split(line, "/")
			for _, part := range parts {
				if strings.HasSuffix(part, ".service") {
					return part
				}
			}
		}
	}
	return ""
}
