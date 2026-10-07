package collector

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"vpsmonitoring-agent/internal/discovery/models"
)

func TestDiscoveryCollectorEmptyProcessList(t *testing.T) {
	payload := collectWithFakes(t, nil, nil, Limits{})

	if len(payload.Applications) != 0 {
		t.Fatalf("expected no applications, got %d", len(payload.Applications))
	}
	if len(payload.Services) != 0 {
		t.Fatalf("expected no services, got %d", len(payload.Services))
	}
	if len(payload.Listeners) != 0 {
		t.Fatalf("expected no listeners, got %d", len(payload.Listeners))
	}
}

func TestDiscoveryCollectorNormalProcessCollection(t *testing.T) {
	start := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	ppid := int64(1)
	processes := []ProcessHandle{
		&fakeProcess{
			pid:       10,
			ppid:      &ppid,
			name:      "node",
			exe:       "/usr/bin/node",
			username:  "appuser",
			startTime: &start,
			cmdline:   []string{"node", "server.js"},
		},
	}

	payload := collectWithFakes(t, processes, nil, Limits{})

	if len(payload.Applications) != 1 {
		t.Fatalf("expected one application, got %d", len(payload.Applications))
	}
	app := payload.Applications[0]
	if app.Runtime != models.RuntimeNodeJS {
		t.Fatalf("expected node runtime, got %s", app.Runtime)
	}
	if app.Process.ParentPID == nil || *app.Process.ParentPID != ppid {
		t.Fatalf("expected parent pid %d, got %+v", ppid, app.Process.ParentPID)
	}
	if app.Process.ExePath != "/usr/bin/node" || app.Process.User != "appuser" {
		t.Fatalf("unexpected process metadata: %+v", app.Process)
	}
	if app.Process.StartTime == nil || !app.Process.StartTime.Equal(start) {
		t.Fatalf("expected start time copied, got %+v", app.Process.StartTime)
	}
}

func TestDiscoveryCollectorProcessPermissionErrorKeepsSafeFields(t *testing.T) {
	processes := []ProcessHandle{
		&fakeProcess{
			pid:        11,
			name:       "python3",
			ppidErr:    errDenied,
			exeErr:     errDenied,
			userErr:    errDenied,
			startErr:   errDenied,
			cmdlineErr: errDenied,
		},
	}

	payload := collectWithFakes(t, processes, nil, Limits{})

	if len(payload.Applications) != 1 {
		t.Fatalf("expected one application, got %d", len(payload.Applications))
	}
	app := payload.Applications[0]
	if app.Process.Name != "python3" || app.Process.PID != 11 {
		t.Fatalf("expected required process fields, got %+v", app.Process)
	}
	if app.Process.ExePath != "" || app.Process.CmdlineRedacted != "" || app.Process.User != "" {
		t.Fatalf("expected optional fields omitted on permission errors, got %+v", app.Process)
	}
	requireWarning(t, payload.Warnings, "permission denied for process metadata")
}

func TestDiscoveryCollectorProcessDisappearingDuringCollection(t *testing.T) {
	processes := []ProcessHandle{
		&fakeProcess{pid: 12, nameErr: errors.New("process disappeared")},
		&fakeProcess{pid: 13, name: "java", cmdline: []string{"java", "-jar", "app.jar"}},
	}

	payload := collectWithFakes(t, processes, nil, Limits{})

	if len(payload.Applications) != 1 {
		t.Fatalf("expected one application after skipping disappeared process, got %d", len(payload.Applications))
	}
	if payload.Applications[0].Process.PID != 13 {
		t.Fatalf("expected pid 13, got %d", payload.Applications[0].Process.PID)
	}
}

func TestDiscoveryCollectorProcessCountLimit(t *testing.T) {
	processes := []ProcessHandle{
		&fakeProcess{pid: 3, name: "node", cmdline: []string{"node", "three.js"}},
		&fakeProcess{pid: 1, name: "java", cmdline: []string{"java", "-jar", "one.jar"}},
		&fakeProcess{pid: 2, name: "python3", cmdline: []string{"python3", "two.py"}},
	}

	payload := collectWithFakes(t, processes, nil, Limits{MaxProcesses: 2})

	if len(payload.Applications) != 2 {
		t.Fatalf("expected two bounded applications, got %d", len(payload.Applications))
	}
	if payload.Applications[0].Process.PID != 2 || payload.Applications[1].Process.PID != 3 {
		t.Fatalf("expected deterministic pid ordering, got %+v", payload.Applications)
	}
	requireWarning(t, payload.Warnings, "process inspection limit reached")
}

func TestDiscoveryCollectorListenerCollectionAndScopes(t *testing.T) {
	pid := int64(20)
	listeners := []ListenerInfo{
		{Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 8080, PID: &pid},
		{Protocol: "tcp", LocalAddress: "10.0.0.5", LocalPort: 8081},
		{Protocol: "tcp", LocalAddress: "8.8.8.8", LocalPort: 8082},
		{Protocol: "tcp", LocalAddress: "0.0.0.0", LocalPort: 8083},
		{Protocol: "tcp", LocalAddress: "::1", LocalPort: 8084},
		{Protocol: "tcp", LocalAddress: "::", LocalPort: 8085},
	}

	payload := collectWithFakes(t, nil, listeners, Limits{})
	scopes := map[int]models.PortScope{}
	for _, listener := range payload.Listeners {
		scopes[listener.LocalPort] = listener.Scope
	}

	assertScope(t, scopes, 8080, models.PortScopeLoopback)
	assertScope(t, scopes, 8081, models.PortScopePrivate)
	assertScope(t, scopes, 8082, models.PortScopePublic)
	assertScope(t, scopes, 8083, models.PortScopeUnspecified)
	assertScope(t, scopes, 8084, models.PortScopeLoopback)
	assertScope(t, scopes, 8085, models.PortScopeUnspecified)
}

func TestDiscoveryCollectorListenerCountLimit(t *testing.T) {
	listeners := []ListenerInfo{
		{Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 1},
		{Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 2},
		{Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 3},
	}

	payload := collectWithFakes(t, nil, listeners, Limits{MaxListeners: 2})

	if len(payload.Listeners) != 2 {
		t.Fatalf("expected two listeners, got %d", len(payload.Listeners))
	}
	requireWarning(t, payload.Warnings, "listener limit reached")
}

func TestDiscoveryCollectorPIDPortCorrelation(t *testing.T) {
	pid := int64(30)
	processes := []ProcessHandle{
		&fakeProcess{pid: pid, name: "node", cmdline: []string{"node", "server.js"}},
	}
	listeners := []ListenerInfo{
		{Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 3000, PID: &pid},
	}

	payload := collectWithFakes(t, processes, listeners, Limits{})

	if len(payload.Applications) != 1 {
		t.Fatalf("expected one application, got %d", len(payload.Applications))
	}
	if len(payload.Applications[0].Ports) != 1 || payload.Applications[0].Ports[0].LocalPort != 3000 {
		t.Fatalf("expected listener associated with app, got %+v", payload.Applications[0].Ports)
	}
	if payload.Listeners[0].ProcessName != "node" {
		t.Fatalf("expected listener process association, got %q", payload.Listeners[0].ProcessName)
	}
}

func TestDiscoveryCollectorMissingPIDAssociationKeepsListener(t *testing.T) {
	listeners := []ListenerInfo{
		{Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 3000},
	}

	payload := collectWithFakes(t, nil, listeners, Limits{})

	if len(payload.Listeners) != 1 {
		t.Fatalf("expected listener retained, got %d", len(payload.Listeners))
	}
	if payload.Listeners[0].PID != nil || payload.Listeners[0].ProcessName != "" {
		t.Fatalf("expected missing association to remain empty, got %+v", payload.Listeners[0])
	}
}

func TestDiscoveryCollectorDuplicateListeners(t *testing.T) {
	pid := int64(40)
	listeners := []ListenerInfo{
		{Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 3000, PID: &pid},
		{Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 3000, PID: &pid},
	}

	payload := collectWithFakes(t, nil, listeners, Limits{})

	if len(payload.Listeners) != 1 {
		t.Fatalf("expected duplicate listener removed, got %d", len(payload.Listeners))
	}
}

func TestDiscoveryCollectorCommandLineRedactionIntegration(t *testing.T) {
	processes := []ProcessHandle{
		&fakeProcess{
			pid:  50,
			name: "node",
			cmdline: []string{
				"node",
				"server.js",
				"--password=super-secret",
				"--token",
				"abc123",
				"postgres://user:pass@localhost/db",
			},
		},
	}

	payload := collectWithFakes(t, processes, nil, Limits{})

	cmd := payload.Applications[0].Process.CmdlineRedacted
	if strings.Contains(cmd, "super-secret") || strings.Contains(cmd, "abc123") || strings.Contains(cmd, "user:pass") {
		t.Fatalf("expected secrets redacted, got %q", cmd)
	}
	if !strings.Contains(cmd, "--password=REDACTED") || !strings.Contains(cmd, "--token REDACTED") {
		t.Fatalf("expected secret placeholders, got %q", cmd)
	}
}

func TestDiscoveryCollectorTimeoutWarning(t *testing.T) {
	processes := []ProcessHandle{
		&fakeProcess{pid: 60, name: "node", blockNameUntilDone: true},
	}

	payload := collectWithFakes(t, processes, nil, Limits{Timeout: 10 * time.Millisecond})

	requireWarning(t, payload.Warnings, "discovery collection timeout reached")
}

func TestDiscoveryCollectorApplicationCandidatesByRuntime(t *testing.T) {
	processes := []ProcessHandle{
		&fakeProcess{pid: 1, name: "java", cmdline: []string{"java", "-jar", "app.jar"}},
		&fakeProcess{pid: 2, name: "node", cmdline: []string{"node", "server.js"}},
		&fakeProcess{pid: 3, name: "python3", cmdline: []string{"python3", "app.py"}},
		&fakeProcess{pid: 4, name: "php", cmdline: []string{"php", "worker.php"}},
		&fakeProcess{pid: 5, name: "dotnet", cmdline: []string{"dotnet", "Worker.dll"}},
		&fakeProcess{pid: 6, name: "custom", cmdline: []string{"custom"}},
	}

	payload := collectWithFakes(t, processes, nil, Limits{})
	runtimes := map[int64]models.Runtime{}
	for _, app := range payload.Applications {
		runtimes[app.Process.PID] = app.Runtime
	}

	if len(payload.Applications) != 5 {
		t.Fatalf("expected five application candidates, got %d", len(payload.Applications))
	}
	if runtimes[1] != models.RuntimeJava || runtimes[2] != models.RuntimeNodeJS ||
		runtimes[3] != models.RuntimePython || runtimes[4] != models.RuntimePHP ||
		runtimes[5] != models.RuntimeDotNet {
		t.Fatalf("unexpected runtimes: %+v", runtimes)
	}
	if _, ok := runtimes[6]; ok {
		t.Fatal("expected unknown process excluded from applications")
	}
}

func TestDiscoveryCollectorFrameworkEvidencePreserved(t *testing.T) {
	processes := []ProcessHandle{
		&fakeProcess{pid: 1, name: "java", cmdline: []string{"java", "org.springframework.boot.loader.JarLauncher"}},
		&fakeProcess{pid: 2, name: "node", cmdline: []string{"node", "node_modules/.bin/next", "start"}},
		&fakeProcess{pid: 3, name: "gunicorn", cmdline: []string{"gunicorn", "site.wsgi:application"}},
		&fakeProcess{pid: 4, name: "uvicorn", cmdline: []string{"uvicorn", "fastapi_app.main:app"}},
	}

	payload := collectWithFakes(t, processes, nil, Limits{})
	frameworks := map[int64]models.Framework{}
	for _, app := range payload.Applications {
		frameworks[app.Process.PID] = app.Framework
		if len(app.Evidence) == 0 {
			t.Fatalf("expected evidence for pid %d", app.Process.PID)
		}
	}

	if frameworks[1] != models.FrameworkSpringBoot ||
		frameworks[2] != models.FrameworkNextJS ||
		frameworks[3] != models.FrameworkDjango ||
		frameworks[4] != models.FrameworkFastAPI {
		t.Fatalf("unexpected frameworks: %+v", frameworks)
	}
}

func TestDiscoveryCollectorNoFalseFrameworkInferenceFromPorts(t *testing.T) {
	pidJava, pidNode, pidPython := int64(10), int64(11), int64(12)
	processes := []ProcessHandle{
		&fakeProcess{pid: pidJava, name: "java", cmdline: []string{"java", "-jar", "app.jar"}},
		&fakeProcess{pid: pidNode, name: "node", cmdline: []string{"node", "server.js"}},
		&fakeProcess{pid: pidPython, name: "python3", cmdline: []string{"python3", "worker.py"}},
	}
	listeners := []ListenerInfo{
		{Protocol: "tcp", LocalAddress: "0.0.0.0", LocalPort: 8080, PID: &pidJava},
		{Protocol: "tcp", LocalAddress: "0.0.0.0", LocalPort: 3000, PID: &pidNode},
		{Protocol: "tcp", LocalAddress: "0.0.0.0", LocalPort: 8000, PID: &pidPython},
	}

	payload := collectWithFakes(t, processes, listeners, Limits{})
	for _, app := range payload.Applications {
		if app.Framework != models.FrameworkUnknown {
			t.Fatalf("expected no framework inferred from port/runtime, got %+v", app)
		}
	}
}

func TestDiscoveryCollectorInfrastructureServicesSeparated(t *testing.T) {
	processes := []ProcessHandle{
		&fakeProcess{pid: 1, name: "nginx", cmdline: []string{"nginx"}},
		&fakeProcess{pid: 2, name: "apache2", cmdline: []string{"apache2"}},
		&fakeProcess{pid: 3, name: "caddy", cmdline: []string{"caddy"}},
		&fakeProcess{pid: 4, name: "postgres", cmdline: []string{"postgres"}},
		&fakeProcess{pid: 5, name: "mysqld", cmdline: []string{"mysqld"}},
		&fakeProcess{pid: 6, name: "mariadbd", cmdline: []string{"mariadbd"}},
		&fakeProcess{pid: 7, name: "mongod", cmdline: []string{"mongod"}},
		&fakeProcess{pid: 8, name: "redis-server", cmdline: []string{"redis-server"}},
	}

	payload := collectWithFakes(t, processes, nil, Limits{})

	if len(payload.Applications) != 0 {
		t.Fatalf("expected infrastructure services separated from applications, got %+v", payload.Applications)
	}
	if len(payload.Services) != 8 {
		t.Fatalf("expected eight service candidates, got %d", len(payload.Services))
	}
}

func TestDiscoveryCollectorMultiplePortsForOneProcess(t *testing.T) {
	pid := int64(70)
	processes := []ProcessHandle{&fakeProcess{pid: pid, name: "node", cmdline: []string{"node", "server.js"}}}
	listeners := []ListenerInfo{
		{Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 3000, PID: &pid},
		{Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 3001, PID: &pid},
	}

	payload := collectWithFakes(t, processes, listeners, Limits{})

	if len(payload.Applications) != 1 || len(payload.Applications[0].Ports) != 2 {
		t.Fatalf("expected one app with two ports, got %+v", payload.Applications)
	}
}

func TestDiscoveryCollectorProcessWithoutListener(t *testing.T) {
	processes := []ProcessHandle{&fakeProcess{pid: 71, name: "node", cmdline: []string{"node", "worker.js"}}}
	payload := collectWithFakes(t, processes, nil, Limits{})

	if len(payload.Applications) != 1 {
		t.Fatalf("expected app candidate, got %d", len(payload.Applications))
	}
	if len(payload.Applications[0].Ports) != 0 {
		t.Fatalf("expected no associated ports, got %+v", payload.Applications[0].Ports)
	}
}

func TestDiscoveryCollectorDeduplicatesProcessAndServiceCandidates(t *testing.T) {
	processes := []ProcessHandle{
		&fakeProcess{pid: 80, name: "node", cmdline: []string{"node", "server.js"}},
		&fakeProcess{pid: 80, name: "node", cmdline: []string{"node", "server.js"}},
		&fakeProcess{pid: 81, name: "nginx", cmdline: []string{"nginx"}},
		&fakeProcess{pid: 81, name: "nginx", cmdline: []string{"nginx"}},
	}

	payload := collectWithFakes(t, processes, nil, Limits{})

	if len(payload.Applications) != 1 {
		t.Fatalf("expected one deduplicated app, got %d", len(payload.Applications))
	}
	if len(payload.Services) != 1 {
		t.Fatalf("expected one deduplicated service, got %d", len(payload.Services))
	}
}

func TestDiscoveryCollectorEnumerationFailuresReturnPartialPayload(t *testing.T) {
	processes := []ProcessHandle{&fakeProcess{pid: 90, name: "node", cmdline: []string{"node", "server.js"}}}
	payload := collectWithSources(
		&fakeProcessSource{processes: processes},
		&fakeListenerSource{err: errors.New("boom with possible details")},
		Limits{},
	)

	if len(payload.Applications) != 1 {
		t.Fatalf("expected process data despite listener failure, got %d apps", len(payload.Applications))
	}
	requireWarning(t, payload.Warnings, "listener PID correlation unavailable")
	payload = collectWithSources(
		&fakeProcessSource{err: errors.New("boom with possible details")},
		&fakeListenerSource{listeners: []ListenerInfo{{Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 3000}}},
		Limits{},
	)
	if len(payload.Applications) != 0 || len(payload.Listeners) != 1 {
		t.Fatalf("expected listener data despite process failure, got %+v", payload)
	}
	requireWarning(t, payload.Warnings, "process enumeration failed")
}

func TestDiscoveryCollectorSafeWarningsAndNoRawSecrets(t *testing.T) {
	processes := []ProcessHandle{
		&fakeProcess{pid: 91, name: "node", cmdline: []string{"node", "--password=raw-secret"}},
		&fakeProcess{pid: 92, nameErr: errors.New("raw-secret in os error")},
	}
	payload := collectWithFakes(t, processes, nil, Limits{})

	joinedWarnings := strings.Join(payload.Warnings, " ")
	if strings.Contains(joinedWarnings, "raw-secret") {
		t.Fatalf("warnings leaked raw secret: %+v", payload.Warnings)
	}
	for _, app := range payload.Applications {
		if strings.Contains(app.Process.CmdlineRedacted, "raw-secret") {
			t.Fatalf("redacted command leaked raw secret: %q", app.Process.CmdlineRedacted)
		}
		for _, ev := range app.Evidence {
			if strings.Contains(ev.Value, "raw-secret") {
				t.Fatalf("evidence leaked raw secret: %+v", ev)
			}
		}
	}
}

func TestDiscoveryCollectorDeterministicOrdering(t *testing.T) {
	pidNode, pidJava := int64(20), int64(10)
	processes := []ProcessHandle{
		&fakeProcess{pid: pidNode, name: "node", cmdline: []string{"node", "server.js"}},
		&fakeProcess{pid: pidJava, name: "java", cmdline: []string{"java", "-jar", "app.jar"}},
	}
	listeners := []ListenerInfo{
		{Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 9000, PID: &pidNode},
		{Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 8000, PID: &pidJava},
	}

	first := collectWithFakes(t, processes, listeners, Limits{})
	second := collectWithFakes(t, processes, listeners, Limits{})

	if first.Applications[0].Process.PID != 10 || first.Applications[1].Process.PID != 20 {
		t.Fatalf("expected apps sorted by pid, got %+v", first.Applications)
	}
	if first.Listeners[0].LocalPort != 8000 || first.Listeners[1].LocalPort != 9000 {
		t.Fatalf("expected listeners sorted by port, got %+v", first.Listeners)
	}
	if first.Applications[0].Runtime != second.Applications[0].Runtime ||
		first.Listeners[0].LocalPort != second.Listeners[0].LocalPort {
		t.Fatalf("expected deterministic outputs, got %+v and %+v", first, second)
	}
}

func collectWithFakes(t *testing.T, processes []ProcessHandle, listeners []ListenerInfo, limits Limits) models.DiscoveryPayload {
	t.Helper()
	return collectWithSources(&fakeProcessSource{processes: processes}, &fakeListenerSource{listeners: listeners}, limits)
}

func collectWithSources(processes ProcessSource, listeners ListenerSource, limits Limits) models.DiscoveryPayload {
	collector := NewDiscoveryCollectorWithSources(
		processes,
		listeners,
		NewClassifier(),
		limits,
	)
	return collector.Collect(context.Background())
}

func requireWarning(t *testing.T, warnings []string, expected string) {
	t.Helper()
	for _, warning := range warnings {
		if warning == expected {
			return
		}
	}
	t.Fatalf("expected warning %q in %+v", expected, warnings)
}

func assertScope(t *testing.T, scopes map[int]models.PortScope, port int, expected models.PortScope) {
	t.Helper()
	if scopes[port] != expected {
		t.Fatalf("expected port %d scope %s, got %s", port, expected, scopes[port])
	}
}

type fakeProcessSource struct {
	processes []ProcessHandle
	err       error
}

func (s *fakeProcessSource) Processes(ctx context.Context) ([]ProcessHandle, error) {
	return s.processes, s.err
}

type fakeListenerSource struct {
	listeners []ListenerInfo
	err       error
}

func (s *fakeListenerSource) TCPListeners(ctx context.Context, pids []int64) ([]ListenerInfo, error) {
	return s.listeners, s.err
}

type fakeProcess struct {
	pid                int64
	ppid               *int64
	name               string
	exe                string
	username           string
	startTime          *time.Time
	cmdline            []string
	nameErr            error
	ppidErr            error
	exeErr             error
	userErr            error
	startErr           error
	cmdlineErr         error
	blockNameUntilDone bool
}

func (p *fakeProcess) PID() int64 {
	return p.pid
}

func (p *fakeProcess) Name(ctx context.Context) (string, error) {
	if p.blockNameUntilDone {
		<-ctx.Done()
		return "", ctx.Err()
	}
	return p.name, p.nameErr
}

func (p *fakeProcess) ParentPID(ctx context.Context) (int64, error) {
	if p.ppidErr != nil || p.ppid == nil {
		return 0, p.ppidErr
	}
	return *p.ppid, nil
}

func (p *fakeProcess) ExePath(ctx context.Context) (string, error) {
	return p.exe, p.exeErr
}

func (p *fakeProcess) Username(ctx context.Context) (string, error) {
	return p.username, p.userErr
}

func (p *fakeProcess) StartTime(ctx context.Context) (time.Time, error) {
	if p.startErr != nil || p.startTime == nil {
		return time.Time{}, p.startErr
	}
	return *p.startTime, nil
}

func (p *fakeProcess) Cmdline(ctx context.Context) ([]string, error) {
	return p.cmdline, p.cmdlineErr
}

func (p *fakeProcess) SystemdUnit() string {
	return ""
}

var errDenied = errors.New("permission denied")
