package collector

import (
	"context"
	"strings"

	"github.com/shirou/gopsutil/v4/disk"

	"vpsmonitoring-agent/internal/metrics/models"
)

// DiskCollector defines the interface for collecting mounted filesystem disk usage.
type DiskCollector interface {
	Collect(ctx context.Context) (models.DiskMetrics, error)
}

type defaultDiskCollector struct{}

// NewDiskCollector returns a new instance of DiskCollector using gopsutil.
func NewDiskCollector() DiskCollector {
	return &defaultDiskCollector{}
}

// isVirtualFS checks if the filesystem type or mount path represents a pseudo/virtual filesystem.
func isVirtualFS(fsType, mountpoint string) bool {
	lowerType := strings.ToLower(fsType)
	virtualFSTypes := []string{
		"proc", "sysfs", "devpts", "devtmpfs", "tmpfs", "cgroup",
		"pstore", "bpf", "debugfs", "tracefs", "securityfs",
		"fusectl", "configfs", "autofs", "overlay", "nsfs", "squashfs",
	}

	for _, v := range virtualFSTypes {
		if lowerType == v {
			return true
		}
	}

	// Filter common container / virtual mounts
	if strings.HasPrefix(mountpoint, "/sys") ||
		strings.HasPrefix(mountpoint, "/proc") ||
		strings.HasPrefix(mountpoint, "/dev") {
		return true
	}

	return false
}

func (c *defaultDiskCollector) Collect(ctx context.Context) (models.DiskMetrics, error) {
	metrics := models.DiskMetrics{
		MountPoints: make([]models.MountPoint, 0),
	}

	// partitions(all=false) retrieves physical/real mounted partitions
	partitions, err := disk.PartitionsWithContext(ctx, false)
	if err != nil {
		return metrics, err
	}

	seenPaths := make(map[string]bool)

	for _, p := range partitions {
		if isVirtualFS(p.Fstype, p.Mountpoint) {
			continue
		}

		if seenPaths[p.Mountpoint] {
			continue
		}
		seenPaths[p.Mountpoint] = true

		usage, err := disk.UsageWithContext(ctx, p.Mountpoint)
		if err != nil {
			// If a single partition cannot be read (e.g. permission or unmounted), skip without crashing
			continue
		}

		mp := models.MountPoint{
			Path:         p.Mountpoint,
			FSType:       p.Fstype,
			Total:        usage.Total,
			Used:         usage.Used,
			Free:         usage.Free,
			UsagePercent: usage.UsedPercent,
		}

		metrics.MountPoints = append(metrics.MountPoints, mp)
	}

	return metrics, nil
}
