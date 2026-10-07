package models

import "time"

// MetricSnapshot represents a full snapshot of system metrics collected at a point in time.
type MetricSnapshot struct {
	Timestamp time.Time      `json:"timestamp"`
	CPU       CPUMetrics     `json:"cpu"`
	Memory    MemoryMetrics  `json:"memory"`
	Swap      SwapMetrics    `json:"swap"`
	Disk      DiskMetrics    `json:"disk"`
	Network   NetworkMetrics `json:"network"`
	Errors    []string       `json:"errors,omitempty"`
}

// CPUMetrics contains CPU utilization, core count, and system load averages.
type CPUMetrics struct {
	UsagePercent float64 `json:"usage_percent"`
	Cores        int     `json:"cores"`
	Load1        float64 `json:"load_1"`
	Load5        float64 `json:"load_5"`
	Load15       float64 `json:"load_15"`
}

// MemoryMetrics contains RAM statistics.
type MemoryMetrics struct {
	Total        uint64  `json:"total"`
	Used         uint64  `json:"used"`
	Available    uint64  `json:"available"`
	UsagePercent float64 `json:"usage_percent"`
}

// SwapMetrics contains virtual swap memory statistics.
type SwapMetrics struct {
	Total        uint64  `json:"total"`
	Used         uint64  `json:"used"`
	Free         uint64  `json:"free"`
	UsagePercent float64 `json:"usage_percent"`
}

// MountPoint represents disk space usage on a single mounted filesystem.
type MountPoint struct {
	Path         string  `json:"path"`
	FSType       string  `json:"fs_type,omitempty"`
	Total        uint64  `json:"total"`
	Used         uint64  `json:"used"`
	Free         uint64  `json:"free"`
	UsagePercent float64 `json:"usage_percent"`
}

// DiskMetrics contains disk usage across all relevant mount points.
type DiskMetrics struct {
	MountPoints []MountPoint `json:"mount_points"`
}

// NetworkMetrics contains aggregate network traffic and error counters.
type NetworkMetrics struct {
	RXBytes   uint64 `json:"rx_bytes"`
	TXBytes   uint64 `json:"tx_bytes"`
	RXPackets uint64 `json:"rx_packets"`
	TXPackets uint64 `json:"tx_packets"`
	Errors    uint64 `json:"errors"`
	Drops     uint64 `json:"drops"`
}
