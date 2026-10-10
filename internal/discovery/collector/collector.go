package collector

import (
	"context"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	gopsnet "github.com/shirou/gopsutil/v4/net"
	gopsprocess "github.com/shirou/gopsutil/v4/process"

	"log"

	"vpsmonitoring-agent/internal/discovery/models"
	"vpsmonitoring-agent/internal/discovery/users"
	"vpsmonitoring-agent/internal/discovery/web/apache"
	"vpsmonitoring-agent/internal/discovery/web/nginx"
)

var procRoot = "/proc"

const (
	defaultCollectionTimeout = 3 * time.Second
	defaultMaxProcesses      = 300
	defaultMaxApplications   = 100
	defaultMaxListeners      = 300
)

type DiscoveryCollector interface {
	Collect(ctx context.Context) models.DiscoveryPayload
}

type ProcessSource interface {
	Processes(ctx context.Context) ([]ProcessHandle, error)
}

type ProcessHandle interface {
	PID() int64
	Name(ctx context.Context) (string, error)
	ParentPID(ctx context.Context) (int64, error)
	ExePath(ctx context.Context) (string, error)
	Username(ctx context.Context) (string, error)
	StartTime(ctx context.Context) (time.Time, error)
	Cmdline(ctx context.Context) ([]string, error)
	SystemdUnit() string
}

type ListenerSource interface {
	TCPListeners(ctx context.Context, pids []int64) ([]ListenerInfo, error)
}

type ListenerInfo struct {
	Protocol     string
	LocalAddress string
	LocalPort    int
	PID          *int64
}

type Limits struct {
	Timeout         time.Duration
	MaxProcesses    int
	MaxApplications int
	MaxListeners    int
}

type defaultDiscoveryCollector struct {
	processes  ProcessSource
	listeners  ListenerSource
	classifier Classifier
	limits     Limits
}

func NewDiscoveryCollector() DiscoveryCollector {
	return NewDiscoveryCollectorWithSources(
		&gopsutilProcessSource{},
		&gopsutilListenerSource{},
		NewClassifier(),
		Limits{},
	)
}

func NewDiscoveryCollectorWithSources(processes ProcessSource, listeners ListenerSource, classifier Classifier, limits Limits) DiscoveryCollector {
	return &defaultDiscoveryCollector{
		processes:  processes,
		listeners:  listeners,
		classifier: classifier,
		limits:     normalizeLimits(limits),
	}
}

func (c *defaultDiscoveryCollector) Collect(ctx context.Context) models.DiscoveryPayload {
	payload := models.DiscoveryPayload{
		CollectedAt:  time.Now().UTC(),
		Applications: []models.ApplicationCandidate{},
		Services:     []models.ServiceCandidate{},
		Listeners:    []models.Listener{},
	}

	collectCtx, cancel := context.WithTimeout(ctx, c.limits.Timeout)
	defer cancel()

	processes := c.collectProcesses(collectCtx, &payload)

	var pids []int64
	for _, p := range processes {
		pids = append(pids, p.PID)
	}

	listeners := c.collectListeners(collectCtx, &payload, pids)
	processByPID := make(map[int64]models.ProcessMetadata, len(processes))
	listenersByPID := make(map[int64][]models.Listener)

	for _, listener := range listeners {
		payload.Listeners = append(payload.Listeners, listener)
		if listener.PID != nil {
			listenersByPID[*listener.PID] = append(listenersByPID[*listener.PID], listener)
		}
	}

	for i := range processes {
		processes[i].Listeners = listenersByPID[processes[i].PID]
		processByPID[processes[i].PID] = processes[i]
	}

	for i, listener := range payload.Listeners {
		if listener.PID == nil {
			continue
		}
		if process, ok := processByPID[*listener.PID]; ok {
			payload.Listeners[i].ProcessName = process.Name
		}
	}

	seenProcesses := make(map[int64]bool)
	seenApplications := make(map[string]bool)
	seenServices := make(map[string]bool)
	for _, process := range processes {
		if seenProcesses[process.PID] {
			continue
		}
		seenProcesses[process.PID] = true

		if len(payload.Applications) >= c.limits.MaxApplications {
			addWarning(&payload.Warnings, "application candidate limit reached")
			break
		}
		classification := c.classifier.ClassifyProcess(process)
		for _, app := range classification.Applications {
			key := applicationKey(app)
			if seenApplications[key] {
				continue
			}
			seenApplications[key] = true
			payload.Applications = append(payload.Applications, app)
			if len(payload.Applications) >= c.limits.MaxApplications {
				addWarning(&payload.Warnings, "application candidate limit reached")
				break
			}
		}
		for _, service := range classification.Services {
			key := serviceKey(service)
			if seenServices[key] {
				continue
			}
			seenServices[key] = true
			payload.Services = append(payload.Services, service)
		}
	}

	log.Printf("[DEBUG] applications classified: %d, services classified: %d", len(payload.Applications), len(payload.Services))

	sortPayload(&payload)

	// Execute Web Discovery (W1 & W3)
	nginxCol := nginx.NewCollector("/etc/nginx")
	websites, webWarnings := nginxCol.Collect(collectCtx)
	for _, w := range webWarnings {
		addWarning(&payload.Warnings, w)
	}

	apacheCol := apache.NewCollector([]string{"/etc/apache2", "/etc/httpd"})
	apacheSites, apacheWarnings := apacheCol.Collect(collectCtx)
	for _, w := range apacheWarnings {
		addWarning(&payload.Warnings, w)
	}

	// Merge apacheSites into websites without creating duplicate identities
	websiteMap := make(map[string]*models.WebsiteCandidate)
	for i := range websites {
		if len(websites[i].Domains) > 0 {
			primary := websites[i].Domains[0].Name
			websiteMap[primary] = &websites[i]
		}
	}
	for i := range apacheSites {
		if len(apacheSites[i].Domains) > 0 {
			primary := apacheSites[i].Domains[0].Name
			if existing, ok := websiteMap[primary]; ok {
				// Nginx takes precedence, but we can append evidence
				existing.Evidence = append(existing.Evidence, apacheSites[i].Evidence...)
			} else {
				websiteMap[primary] = &apacheSites[i]
				websites = append(websites, apacheSites[i])
			}
		}
	}

	payload.Websites = append(payload.Websites, websites...)

	// Execute OS User / Hosting Discovery
	userCol := users.NewCollector("/etc/passwd", "/home")
	hostingUsers, userWarnings := userCol.Collect(collectCtx, payload.Websites)
	for _, w := range userWarnings {
		addWarning(&payload.Warnings, w)
	}
	payload.HostingUsers = hostingUsers

	return payload
}

func (c *defaultDiscoveryCollector) collectProcesses(ctx context.Context, payload *models.DiscoveryPayload) []models.ProcessMetadata {
	handles, err := c.processes.Processes(ctx)
	if err != nil {
		log.Printf("[DEBUG] processes.Processes() returned error: %v", err)
		addWarning(&payload.Warnings, "process enumeration failed")
		return []models.ProcessMetadata{}
	}
	log.Printf("[DEBUG] processes enumerated: %d", len(handles))

	if len(handles) > c.limits.MaxProcesses {
		sort.Slice(handles, func(i, j int) bool { return handles[i].PID() > handles[j].PID() })
		handles = handles[:c.limits.MaxProcesses]
		addWarning(&payload.Warnings, "process inspection limit reached")
	}

	out := make([]models.ProcessMetadata, 0, len(handles))
	for _, handle := range handles {
		select {
		case <-ctx.Done():
			addWarning(&payload.Warnings, "discovery collection timeout reached")
			return out
		default:
		}

		process, warnings, ok := processMetadata(ctx, handle)
		for _, warning := range warnings {
			addWarning(&payload.Warnings, warning)
		}
		if ok {
			out = append(out, process)
		}
		if ctx.Err() != nil {
			addWarning(&payload.Warnings, "discovery collection timeout reached")
			return out
		}
	}
	log.Printf("[DEBUG] processes retained: %d", len(out))
	
	// Diagnostics
	uidCount := 0
	cgroupCount := 0
	for _, process := range out {
		if process.User != "" {
			uidCount++
		}
		if process.SystemdUnit != "" {
			cgroupCount++
		}
		if process.PID == 59146 {
			log.Printf("[DEBUG] Found PID 59146: UID=%s, Unit=%s", process.User, process.SystemdUnit)
		}
	}
	log.Printf("[DEBUG] processes with UID: %d, processes with cgroup: %d", uidCount, cgroupCount)

	return out
}

func processMetadata(ctx context.Context, handle ProcessHandle) (models.ProcessMetadata, []string, bool) {
	var warnings []string
	name, err := handle.Name(ctx)
	if err != nil || name == "" {
		name = "<unknown>"
	}

	process := models.ProcessMetadata{
		PID:         handle.PID(),
		Name:        name,
		SystemdUnit: handle.SystemdUnit(),
	}

	if ppid, err := handle.ParentPID(ctx); err == nil {
		process.ParentPID = &ppid
	} else {
		warnings = append(warnings, "permission denied for process metadata")
	}
	if exe, err := handle.ExePath(ctx); err == nil {
		process.ExePath = exe
	} else {
		warnings = append(warnings, "permission denied for process metadata")
	}
	if user, err := handle.Username(ctx); err == nil {
		process.User = user
	} else {
		warnings = append(warnings, "permission denied for process metadata")
	}
	if start, err := handle.StartTime(ctx); err == nil {
		process.StartTime = &start
	} else {
		warnings = append(warnings, "permission denied for process metadata")
	}
	if args, err := handle.Cmdline(ctx); err == nil {
		process.CmdlineRedacted = redactCommandLine(args)
	} else {
		warnings = append(warnings, "permission denied for process metadata")
	}

	return process, warnings, true
}

func (c *defaultDiscoveryCollector) collectListeners(ctx context.Context, payload *models.DiscoveryPayload, pids []int64) []models.Listener {
	infos, err := c.listeners.TCPListeners(ctx, pids)
	if err != nil {
		addWarning(&payload.Warnings, "listener PID correlation unavailable")
		// Assume the fallback (or original) provided some partial listeners, handled below.
	}

	sort.Slice(infos, func(i, j int) bool {
		if infos[i].LocalAddress != infos[j].LocalAddress {
			return infos[i].LocalAddress < infos[j].LocalAddress
		}
		if infos[i].LocalPort != infos[j].LocalPort {
			return infos[i].LocalPort < infos[j].LocalPort
		}
		return pidValue(infos[i].PID) < pidValue(infos[j].PID)
	})

	out := make([]models.Listener, 0, min(len(infos), c.limits.MaxListeners))
	seen := make(map[string]bool)
	for _, info := range infos {
		if len(out) >= c.limits.MaxListeners {
			addWarning(&payload.Warnings, "listener limit reached")
			break
		}
		if info.LocalPort <= 0 {
			addWarning(&payload.Warnings, "listener metadata unavailable")
			continue
		}
		key := listenerKey(info)
		if seen[key] {
			continue
		}
		seen[key] = true
		address := normalizeAddress(info.LocalAddress)
		out = append(out, models.Listener{
			Protocol:     normalizeProtocol(info.Protocol),
			LocalAddress: address,
			LocalPort:    info.LocalPort,
			Scope:        classifyAddressScope(address),
			PID:          info.PID,
		})
	}
	return out
}

func sortPayload(payload *models.DiscoveryPayload) {
	sort.Slice(payload.Applications, func(i, j int) bool {
		return payload.Applications[i].Process.PID < payload.Applications[j].Process.PID
	})
	sort.Slice(payload.Services, func(i, j int) bool {
		left, right := payload.Services[i], payload.Services[j]
		if left.Process.PID != right.Process.PID {
			return left.Process.PID < right.Process.PID
		}
		return left.Kind < right.Kind
	})
	sort.Slice(payload.Listeners, func(i, j int) bool {
		left, right := payload.Listeners[i], payload.Listeners[j]
		if left.LocalPort != right.LocalPort {
			return left.LocalPort < right.LocalPort
		}
		if left.LocalAddress != right.LocalAddress {
			return left.LocalAddress < right.LocalAddress
		}
		return pidValue(left.PID) < pidValue(right.PID)
	})
}

func applicationKey(app models.ApplicationCandidate) string {
	return itoa64(app.Process.PID) + "|" + string(app.Runtime)
}

func serviceKey(service models.ServiceCandidate) string {
	return itoa64(service.Process.PID) + "|" + string(service.Kind)
}

func addWarning(warnings *[]string, warning string) {
	for _, existing := range *warnings {
		if existing == warning {
			return
		}
	}
	*warnings = append(*warnings, warning)
}

func normalizeLimits(l Limits) Limits {
	if l.Timeout <= 0 {
		l.Timeout = defaultCollectionTimeout
	}
	if l.MaxProcesses <= 0 {
		l.MaxProcesses = defaultMaxProcesses
	}
	if l.MaxApplications <= 0 {
		l.MaxApplications = defaultMaxApplications
	}
	if l.MaxListeners <= 0 {
		l.MaxListeners = defaultMaxListeners
	}
	return l
}

func normalizeProtocol(protocol string) string {
	if protocol == "" {
		return "tcp"
	}
	return protocol
}

func normalizeAddress(address string) string {
	if address == "" {
		return ""
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return address
	}
	return ip.String()
}

func classifyAddressScope(address string) models.PortScope {
	ip := net.ParseIP(address)
	if ip == nil {
		return models.PortScopeUnknown
	}
	if ip.IsUnspecified() {
		return models.PortScopeUnspecified
	}
	if ip.IsLoopback() {
		return models.PortScopeLoopback
	}
	if ip.IsPrivate() {
		return models.PortScopePrivate
	}
	return models.PortScopePublic
}

func listenerKey(info ListenerInfo) string {
	return normalizeProtocol(info.Protocol) + "|" + normalizeAddress(info.LocalAddress) + "|" + itoa(info.LocalPort) + "|" + itoa64(pidValue(info.PID))
}

func pidValue(pid *int64) int64 {
	if pid == nil {
		return 0
	}
	return *pid
}

func itoa(i int) string {
	return itoa64(int64(i))
}

func itoa64(i int64) string {
	return strconv.FormatInt(i, 10)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type gopsutilProcessSource struct{}

func (s *gopsutilProcessSource) Processes(ctx context.Context) ([]ProcessHandle, error) {
	procs, err := gopsprocess.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}
	handles := make([]ProcessHandle, 0, len(procs))
	for _, proc := range procs {
		handles = append(handles, &gopsutilProcessHandle{process: proc})
	}
	return handles, nil
}

type gopsutilProcessHandle struct {
	process *gopsprocess.Process
}

func (h *gopsutilProcessHandle) PID() int64 {
	return int64(h.process.Pid)
}

func (h *gopsutilProcessHandle) Name(ctx context.Context) (string, error) {
	return h.process.NameWithContext(ctx)
}

func (h *gopsutilProcessHandle) ParentPID(ctx context.Context) (int64, error) {
	ppid, err := h.process.PpidWithContext(ctx)
	return int64(ppid), err
}

func (h *gopsutilProcessHandle) ExePath(ctx context.Context) (string, error) {
	return h.process.ExeWithContext(ctx)
}

func (h *gopsutilProcessHandle) Username(ctx context.Context) (string, error) {
	return h.process.UsernameWithContext(ctx)
}

func (h *gopsutilProcessHandle) StartTime(ctx context.Context) (time.Time, error) {
	ms, err := h.process.CreateTimeWithContext(ctx)
	if err != nil {
		return time.Time{}, err
	}
	return time.UnixMilli(ms).UTC(), nil
}

func (h *gopsutilProcessHandle) Cmdline(ctx context.Context) ([]string, error) {
	return h.process.CmdlineSliceWithContext(ctx)
}

func (h *gopsutilProcessHandle) SystemdUnit() string {
	path := procRoot + "/" + strconv.FormatInt(h.PID(), 10) + "/cgroup"
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

type gopsutilListenerSource struct{}

func (s *gopsutilListenerSource) TCPListeners(ctx context.Context, pids []int64) ([]ListenerInfo, error) {
	conns, err := gopsnet.ConnectionsWithContext(ctx, "tcp")
	if err != nil {
		return fallbackTCPListeners(pids)
	}
	listeners := make([]ListenerInfo, 0, len(conns))
	for _, conn := range conns {
		if conn.Status != "LISTEN" {
			continue
		}
		var pid *int64
		if conn.Pid > 0 {
			v := int64(conn.Pid)
			pid = &v
		}
		listeners = append(listeners, ListenerInfo{
			Protocol:     "tcp",
			LocalAddress: conn.Laddr.IP,
			LocalPort:    int(conn.Laddr.Port),
			PID:          pid,
		})
	}
	return listeners, nil
}

func getUIDForPID(pid int64) (string, error) {
	data, err := os.ReadFile(procRoot + "/" + strconv.FormatInt(pid, 10) + "/status")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				return fields[1], nil
			}
		}
	}
	return "", os.ErrNotExist
}

func fallbackTCPListeners(pids []int64) ([]ListenerInfo, error) {
	inodeToPID := make(map[string]int64)
	uidToPIDs := make(map[string][]int64)

	for _, pid := range pids {
		uid, err := getUIDForPID(pid)
		if err == nil {
			uidToPIDs[uid] = append(uidToPIDs[uid], pid)
		}

		fdDir := procRoot + "/" + strconv.FormatInt(pid, 10) + "/fd"
		entries, err := os.ReadDir(fdDir)
		if err != nil {
			continue // Permission denied or process died
		}

		count := 0
		for _, entry := range entries {
			if count > 500 { // Bound number of fds per process to prevent unbounded scans
				break
			}
			count++

			if entry.Type()&os.ModeSymlink == 0 {
				continue
			}
			link, err := os.Readlink(fdDir + "/" + entry.Name())
			if err != nil {
				continue
			}
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				inode := link[8 : len(link)-1]
				inodeToPID[inode] = pid
			}
		}
	}
	log.Printf("[DEBUG] uidToPIDs entries: %d", len(uidToPIDs))

	var rawListeners []ListenerInfo
	tcp4Count := 0
	tcp6Count := 0
	inodeMatched := 0
	uidMatched := 0
	uncorrelated := 0

	for _, path := range []string{procRoot + "/net/tcp", procRoot + "/net/tcp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if !strings.Contains(line, ":") || strings.Contains(line, "local_address") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			if fields[3] != "0A" { // 0A is LISTEN
				continue
			}
			parts := strings.Split(fields[1], ":")
			if len(parts) != 2 {
				continue
			}
			port, err := strconv.ParseInt(parts[1], 16, 32)
			if err != nil {
				continue
			}
			ipStr := parseIPHex(parts[0])
			uid := fields[7]
			inode := fields[9]

			var pidPtr *int64
			if pid, ok := inodeToPID[inode]; ok {
				pidVal := pid
				pidPtr = &pidVal
				inodeMatched++
			} else if pidsForUID, ok := uidToPIDs[uid]; ok && len(pidsForUID) == 1 {
				pidVal := pidsForUID[0]
				pidPtr = &pidVal
				uidMatched++
			} else {
				uncorrelated++
			}

			if pidPtr != nil && *pidPtr == 59146 {
				log.Printf("[DEBUG] Found PID 59146 listener: port=%d, correlated_by_inode=%v", port, inodeToPID[inode] == 59146)
			}

			if strings.HasSuffix(path, "tcp") {
				tcp4Count++
			} else {
				tcp6Count++
			}

			rawListeners = append(rawListeners, ListenerInfo{
				Protocol:     "tcp",
				LocalAddress: ipStr,
				LocalPort:    int(port),
				PID:          pidPtr,
			})
		}
	}

	// Deduplicate IPv4 and IPv6 wildcards
	var deduplicated []ListenerInfo
	seen := make(map[string]bool)

	// First pass: add IPv6 listeners (e.g. [::]) to seen set, because [::] covers 0.0.0.0
	for _, l := range rawListeners {
		if l.LocalAddress == "::" {
			key := "0.0.0.0|" + strconv.Itoa(l.LocalPort)
			seen[key] = true
			deduplicated = append(deduplicated, l)
		}
	}

	// Second pass: add other listeners if not covered
	for _, l := range rawListeners {
		if l.LocalAddress == "::" {
			continue
		}
		key := l.LocalAddress + "|" + strconv.Itoa(l.LocalPort)
		if !seen[key] {
			seen[key] = true
			deduplicated = append(deduplicated, l)
		}
	}

	log.Printf("[DEBUG] tcp listeners parsed: %d, tcp6 listeners parsed: %d", tcp4Count, tcp6Count)
	log.Printf("[DEBUG] listeners correlated by inode: %d, by UID: %d, uncorrelated: %d", inodeMatched, uidMatched, uncorrelated)

	return deduplicated, nil
}

func parseIPHex(hexStr string) string {
	if len(hexStr) == 8 {
		var ip [4]byte
		for i := 0; i < 4; i++ {
			b, _ := strconv.ParseUint(hexStr[i*2:i*2+2], 16, 8)
			ip[i] = byte(b)
		}
		return net.IPv4(ip[3], ip[2], ip[1], ip[0]).String()
	} else if len(hexStr) == 32 {
		var ip net.IP = make(net.IP, 16)
		for i := 0; i < 4; i++ {
			for j := 0; j < 4; j++ {
				b, _ := strconv.ParseUint(hexStr[(i*8+j*2):(i*8+j*2+2)], 16, 8)
				ip[i*4+3-j] = byte(b)
			}
		}
		return ip.String()
	}
	return ""
}
