package port

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	gopsnet "github.com/shirou/gopsutil/v4/net"
	"vpsmonitoring-agent/internal/application/config"
)

const (
	DialTimeout = 2 * time.Second
)

type PortMonitor interface {
	Collect(ctx context.Context, configs []config.ApplicationConfig) []ApplicationPortStatus
}

// Dialer interface abstracts network connection for testing
type Dialer interface {
	DialTimeout(network, address string, timeout time.Duration) (net.Conn, error)
}

// ListenerSource abstracts OS socket enumeration
type ListenerSource interface {
	TCPListeners(ctx context.Context) ([]gopsnet.ConnectionStat, error)
}

type defaultDialer struct{}

func (d *defaultDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, address, timeout)
}

type defaultListenerSource struct{}

func (s *defaultListenerSource) TCPListeners(ctx context.Context) ([]gopsnet.ConnectionStat, error) {
	return gopsnet.ConnectionsWithContext(ctx, "tcp")
}

type defaultPortMonitor struct {
	dialer    Dialer
	listeners ListenerSource
}

func NewPortMonitor() PortMonitor {
	return &defaultPortMonitor{
		dialer:    &defaultDialer{},
		listeners: &defaultListenerSource{},
	}
}

func NewPortMonitorWithDeps(d Dialer, l ListenerSource) PortMonitor {
	return &defaultPortMonitor{
		dialer:    d,
		listeners: l,
	}
}

func (m *defaultPortMonitor) Collect(ctx context.Context, configs []config.ApplicationConfig) []ApplicationPortStatus {
	// Build O(1) listener index once per cycle to avoid duplicate expensive OS calls
	portIndex := make(map[uint32]bool)
	conns, err := m.listeners.TCPListeners(ctx)
	if err == nil {
		for _, conn := range conns {
			// LISTEN status
			if conn.Status == "LISTEN" && conn.Laddr.Port > 0 {
				portIndex[conn.Laddr.Port] = true
			}
		}
	} else {
		log.Printf("[WARN] port monitor: failed to enumerate OS listeners (permission denied?): %v", err)
	}

	var results []ApplicationPortStatus
	now := time.Now().UTC()

	for _, cfg := range configs {
		if !cfg.IsEnabled {
			continue
		}

		status := ApplicationPortStatus{
			ApplicationID: cfg.ID,
			CollectedAt:   now,
			Configured:    false,
			State:         PortNotConfigured,
		}

		if cfg.MonitorPort == nil {
			results = append(results, status)
			continue
		}

		port := *cfg.MonitorPort
		status.Port = port
		status.Configured = true

		if port < 1 || port > 65535 {
			status.State = PortUnknown
			status.Warning = "invalid port range"
			results = append(results, status)
			continue
		}

		// 1. Check OS Listener Index first (O(1))
		if portIndex[uint32(port)] {
			status.State = PortListening
			results = append(results, status)
			continue
		}

		// 2. Fallback: Localhost TCP Connection Check (Loopback only)
		// We try IPv4 then IPv6
		state, warning := m.checkLocalhostDial(ctx, port)
		status.State = state
		if warning != "" {
			status.Warning = warning
		}

		results = append(results, status)
	}

	return results
}

func (m *defaultPortMonitor) checkLocalhostDial(ctx context.Context, port int) (PortState, string) {
	// TCP4 Loopback
	addr4 := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := m.dialer.DialTimeout("tcp4", addr4, DialTimeout)
	if err == nil {
		conn.Close()
		return PortListening, ""
	}

	// Check context cancellation
	if ctx.Err() != nil {
		return PortUnknown, "collection timeout exceeded"
	}

	// TCP6 Loopback
	addr6 := fmt.Sprintf("[::1]:%d", port)
	conn6, err6 := m.dialer.DialTimeout("tcp6", addr6, DialTimeout)
	if err6 == nil {
		conn6.Close()
		return PortListening, ""
	}

	// Check context cancellation
	if ctx.Err() != nil {
		return PortUnknown, "collection timeout exceeded"
	}

	// Both failed, usually indicates connection refused or timeout
	// Check if it was a timeout or connection refused
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return PortUnknown, "tcp dial timeout"
	}

	return PortNotListening, ""
}
