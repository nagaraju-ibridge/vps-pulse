package port

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	gopsnet "github.com/shirou/gopsutil/v4/net"
	"vpsmonitoring-agent/internal/application/config"
)

type fakeConn struct {
	net.Conn
}

func (c *fakeConn) Close() error { return nil }

type fakeDialer struct {
	Err4 error
	Err6 error
}

func (d *fakeDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	if strings.HasPrefix(network, "tcp4") {
		if d.Err4 != nil {
			return nil, d.Err4
		}
		return &fakeConn{}, nil
	}
	if strings.HasPrefix(network, "tcp6") {
		if d.Err6 != nil {
			return nil, d.Err6
		}
		return &fakeConn{}, nil
	}
	return nil, errors.New("unsupported network")
}

type fakeListenerSource struct {
	Conns []gopsnet.ConnectionStat
	Err   error
}

func (s *fakeListenerSource) TCPListeners(ctx context.Context) ([]gopsnet.ConnectionStat, error) {
	return s.Conns, s.Err
}

// Mock net.Error for timeout
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

func ptrInt(i int) *int {
	return &i
}

func TestPortMonitor_NotConfigured(t *testing.T) {
	monitor := NewPortMonitorWithDeps(&fakeDialer{}, &fakeListenerSource{})
	configs := []config.ApplicationConfig{
		{ID: 1, IsEnabled: true}, // No monitor_port
	}

	results := monitor.Collect(context.Background(), configs)
	if len(results) != 1 {
		t.Fatalf("expected 1 result")
	}

	if results[0].Configured != false || results[0].State != PortNotConfigured {
		t.Errorf("expected NOT_CONFIGURED, got %s", results[0].State)
	}
}

func TestPortMonitor_InvalidPortRange(t *testing.T) {
	monitor := NewPortMonitorWithDeps(&fakeDialer{}, &fakeListenerSource{})
	configs := []config.ApplicationConfig{
		{ID: 1, IsEnabled: true, MonitorPort: ptrInt(0)},
		{ID: 2, IsEnabled: true, MonitorPort: ptrInt(70000)},
	}

	results := monitor.Collect(context.Background(), configs)
	if len(results) != 2 {
		t.Fatalf("expected 2 results")
	}

	if results[0].State != PortUnknown {
		t.Errorf("expected 0 to be UNKNOWN, got %s", results[0].State)
	}
	if results[1].State != PortUnknown {
		t.Errorf("expected 70000 to be UNKNOWN, got %s", results[1].State)
	}
}

func TestPortMonitor_ListenerIndexMatch(t *testing.T) {
	ls := &fakeListenerSource{
		Conns: []gopsnet.ConnectionStat{
			{Status: "LISTEN", Laddr: gopsnet.Addr{Port: 8080}},
			{Status: "ESTABLISHED", Laddr: gopsnet.Addr{Port: 9090}}, // Should not match
		},
	}

	// Dialer set to fail, proving it uses the listener index
	d := &fakeDialer{Err4: errors.New("refused"), Err6: errors.New("refused")}

	monitor := NewPortMonitorWithDeps(d, ls)
	configs := []config.ApplicationConfig{
		{ID: 1, IsEnabled: true, MonitorPort: ptrInt(8080)},
		{ID: 2, IsEnabled: true, MonitorPort: ptrInt(9090)},
	}

	results := monitor.Collect(context.Background(), configs)

	if results[0].State != PortListening {
		t.Errorf("expected 8080 to be LISTENING (via index), got %s", results[0].State)
	}
	if results[1].State != PortNotListening {
		t.Errorf("expected 9090 to NOT_LISTENING (not LISTEN state), got %s", results[1].State)
	}
}

func TestPortMonitor_FallbackDialMatch(t *testing.T) {
	// Empty listener index, forcing dial fallback
	ls := &fakeListenerSource{}

	// Dialer succeeds on TCP4
	d := &fakeDialer{Err6: errors.New("refused")}

	monitor := NewPortMonitorWithDeps(d, ls)
	configs := []config.ApplicationConfig{
		{ID: 1, IsEnabled: true, MonitorPort: ptrInt(3000)},
	}

	results := monitor.Collect(context.Background(), configs)

	if results[0].State != PortListening {
		t.Errorf("expected 3000 to be LISTENING via dial fallback, got %s", results[0].State)
	}
}

func TestPortMonitor_FallbackDialTimeout(t *testing.T) {
	ls := &fakeListenerSource{}
	// Dialer times out
	d := &fakeDialer{Err4: &timeoutError{}, Err6: &timeoutError{}}

	monitor := NewPortMonitorWithDeps(d, ls)
	configs := []config.ApplicationConfig{
		{ID: 1, IsEnabled: true, MonitorPort: ptrInt(3000)},
	}

	results := monitor.Collect(context.Background(), configs)

	if results[0].State != PortUnknown {
		t.Errorf("expected 3000 to be UNKNOWN on timeout, got %s", results[0].State)
	}
}

func TestPortMonitor_ListenerIndexPermissionDenied(t *testing.T) {
	// Ensure that if listener index fails (e.g. permission denied), it gracefully falls back to Dialer
	ls := &fakeListenerSource{Err: errors.New("permission denied")}
	d := &fakeDialer{} // Succeeds by default

	monitor := NewPortMonitorWithDeps(d, ls)
	configs := []config.ApplicationConfig{
		{ID: 1, IsEnabled: true, MonitorPort: ptrInt(3000)},
	}

	results := monitor.Collect(context.Background(), configs)

	if results[0].State != PortListening {
		t.Errorf("expected 3000 to be LISTENING via dial fallback after listener error, got %s", results[0].State)
	}
}
