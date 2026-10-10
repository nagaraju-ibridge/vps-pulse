package users

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpsmonitoring-agent/internal/discovery/models"
)

type Collector interface {
	Collect(ctx context.Context, discoveredWebsites []models.WebsiteCandidate) ([]models.HostingUserCandidate, []string)
}

type defaultCollector struct {
	passwdPath string
	homePath   string
	mysqlPath  string
}

func NewCollector(passwdPath, homePath string) Collector {
	if passwdPath == "" {
		passwdPath = "/etc/passwd"
	}
	if homePath == "" {
		homePath = "/home"
	}
	return &defaultCollector{
		passwdPath: passwdPath,
		homePath:   homePath,
		mysqlPath:  "/var/lib/mysql",
	}
}

type passwdEntry struct {
	username string
	uid      int
	gid      int
	gecos    string
	homeDir  string
	shell    string
}

func (c *defaultCollector) Collect(ctx context.Context, discoveredWebsites []models.WebsiteCandidate) ([]models.HostingUserCandidate, []string) {
	var warnings []string
	userMap := make(map[string]*passwdEntry)

	// 1. Parse /etc/passwd
	if file, err := os.Open(c.passwdPath); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Split(line, ":")
			if len(parts) >= 7 {
				uid, _ := strconv.Atoi(parts[2])
				gid, _ := strconv.Atoi(parts[3])
				gecos := ""
				if len(parts) > 4 {
					gecos = strings.TrimSpace(strings.Split(parts[4], ",")[0])
				}
				userMap[parts[0]] = &passwdEntry{
					username: parts[0],
					uid:      uid,
					gid:      gid,
					gecos:    gecos,
					homeDir:  parts[5],
					shell:    parts[6],
				}
			}
		}
		_ = file.Close()
	} else {
		warnings = append(warnings, fmt.Sprintf("unable to read passwd: %v", err))
	}

	// 2. Scan /home for user directories
	discoveredUsers := make(map[string]*models.HostingUserCandidate)

	homeEntries, err := os.ReadDir(c.homePath)
	if err == nil {
		for _, entry := range homeEntries {
			if !entry.IsDir() {
				continue
			}
			uName := entry.Name()
			if uName == "lost+found" || strings.HasPrefix(uName, ".") {
				continue
			}

			userHome := filepath.Join(c.homePath, uName)
			cand := &models.HostingUserCandidate{
				Username: uName,
				HomeDir:  userHome,
				Package:  "default",
				Role:     "user",
			}

			if pEntry, ok := userMap[uName]; ok {
				cand.LinuxUID = pEntry.uid
				cand.Shell = pEntry.shell
				if pEntry.uid == 0 || uName == "admin" || uName == "root" {
					cand.Role = "admin"
					cand.Package = "system"
				}
				if isSuspendedShell(pEntry.shell) {
					cand.IsSuspended = true
				}
			} else {
				if uName == "admin" || uName == "root" {
					cand.Role = "admin"
					cand.Package = "system"
				}
			}

			discoveredUsers[uName] = cand
		}
	}

	// Also include admin if not already in discoveredUsers but exists in passwd
	for _, adminName := range []string{"admin", "root"} {
		if pEntry, ok := userMap[adminName]; ok && discoveredUsers[adminName] == nil {
			discoveredUsers[adminName] = &models.HostingUserCandidate{
				Username:    adminName,
				HomeDir:     pEntry.homeDir,
				Shell:       pEntry.shell,
				LinuxUID:    pEntry.uid,
				Role:        "admin",
				Package:     "system",
				IsSuspended: isSuspendedShell(pEntry.shell),
			}
		}
	}

	// Read MySQL database names for correlating DB count per user prefix
	dbNames := c.getMySQLDatabases()

	// 3. For each user, enrich with disk usage, web count, db count, and creation date
	var results []models.HostingUserCandidate
	for uName, user := range discoveredUsers {
		// A. Date Created (from directory stat)
		if stat, err := os.Stat(user.HomeDir); err == nil {
			user.DateCreated = stat.ModTime().Format("2006-01-02")
		} else {
			user.DateCreated = time.Now().Format("2006-01-02")
		}

		// B. Disk Usage (du -sm)
		user.DiskUsageMB = c.measureDiskUsageMB(ctx, user.HomeDir)

		// C. Correlate Discovered Websites from Web Servers
		siteSet := make(map[string]bool)
		for _, w := range discoveredWebsites {
			if strings.Contains(w.DocumentRoot, "/home/"+uName+"/") ||
				strings.HasPrefix(w.DocumentRoot, user.HomeDir) ||
				strings.Contains(w.DocumentRoot, "/web/"+uName+"/") {
				for _, d := range w.Domains {
					if d.Name != "" && !siteSet[d.Name] {
						siteSet[d.Name] = true
						user.Websites = append(user.Websites, d.Name)
					}
				}
			}
		}

		// Also check user's filesystem for web domains (e.g. /home/<user>/web/<domain>)
		webDir := filepath.Join(user.HomeDir, "web")
		if webEntries, err := os.ReadDir(webDir); err == nil {
			for _, wEntry := range webEntries {
				if wEntry.IsDir() {
					dName := wEntry.Name()
					if strings.Contains(dName, ".") && !siteSet[dName] {
						siteSet[dName] = true
						user.Websites = append(user.Websites, dName)
					}
				}
			}
		}

		// Also check public_html fallback
		publicHtml := filepath.Join(user.HomeDir, "public_html")
		if _, err := os.Stat(publicHtml); err == nil && len(user.Websites) == 0 {
			// user has a single main site
			siteSet[uName] = true
			user.Websites = append(user.Websites, uName)
		}

		user.WebCount = len(user.Websites)

		// D. Count Databases matching user prefix (<user>_*)
		userDbPrefix := uName + "_"
		dbCount := 0
		for _, dbName := range dbNames {
			if strings.HasPrefix(strings.ToLower(dbName), strings.ToLower(userDbPrefix)) {
				dbCount++
			}
		}
		user.DBCount = dbCount

		// E. Mail count from /home/<user>/mail
		mailDir := filepath.Join(user.HomeDir, "mail")
		if mailEntries, err := os.ReadDir(mailDir); err == nil {
			for _, mEntry := range mailEntries {
				if mEntry.IsDir() && strings.Contains(mEntry.Name(), ".") {
					user.MailCount++
				}
			}
		}

		// F. Passive enrichment (read static user.conf and web.conf if present, or query CP)
		c.passiveEnrichUser(ctx, user, userMap[uName], discoveredWebsites)

		results = append(results, *user)
	}

	return results, warnings
}

func isSuspendedShell(shell string) bool {
	s := strings.ToLower(shell)
	return strings.Contains(s, "nologin") || strings.Contains(s, "false") || s == "/dev/null"
}

func (c *defaultCollector) measureDiskUsageMB(ctx context.Context, dir string) int64 {
	duCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(duCtx, "du", "-sm", dir)
	out, err := cmd.Output()
	if err == nil {
		fields := strings.Fields(string(out))
		if len(fields) >= 1 {
			if mb, err := strconv.ParseInt(fields[0], 10, 64); err == nil && mb > 0 {
				return mb
			}
		}
	}

	// Fallback to sudo -n du if non-root user
	cmdSudo := exec.CommandContext(duCtx, "sudo", "-n", "du", "-sm", dir)
	if outSudo, errSudo := cmdSudo.Output(); errSudo == nil {
		fields := strings.Fields(string(outSudo))
		if len(fields) >= 1 {
			if mb, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
				return mb
			}
		}
	}

	return 0
}

func (c *defaultCollector) getMySQLDatabases() []string {
	var dbs []string
	entries, err := os.ReadDir(c.mysqlPath)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				name := entry.Name()
				if name != "mysql" && name != "performance_schema" && name != "information_schema" && name != "sys" {
					dbs = append(dbs, name)
				}
			}
		}
		return dbs
	}

	// Fallback to sudo -n ls if non-root user
	cmd := exec.Command("sudo", "-n", "ls", "-1", c.mysqlPath)
	if out, err := cmd.Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, l := range lines {
			name := strings.TrimSpace(l)
			if name != "" && name != "mysql" && name != "performance_schema" && name != "information_schema" && name != "sys" {
				dbs = append(dbs, name)
			}
		}
	}
	return dbs
}

// parseConfRecord extracts KEY='VAL' pairs from a config line or file text
func parseConfRecord(text string) map[string]string {
	res := make(map[string]string)
	r := regexp.MustCompile(`([A-Z0-9_]+)=['"]?([^'"]*)['"]?`)
	matches := r.FindAllStringSubmatch(text, -1)
	for _, m := range matches {
		if len(m) >= 3 {
			res[m[1]] = strings.Trim(m[2], "'\"")
		}
	}
	return res
}

// passiveEnrichUser enriches user with Image 2 (profile & quotas) and Image 3 (web domains)
func (c *defaultCollector) passiveEnrichUser(ctx context.Context, user *models.HostingUserCandidate, pEntry *passwdEntry, discoveredWebsites []models.WebsiteCandidate) {
	if pEntry != nil && pEntry.gecos != "" && user.FullName == "" {
		user.FullName = pEntry.gecos
	}

	// 1. Enrich User Details & Quotas (Image 2 data)
	hestiaUserConf := fmt.Sprintf("/usr/local/hestia/data/users/%s/user.conf", user.Username)
	vestaUserConf := fmt.Sprintf("/usr/local/vesta/data/users/%s/user.conf", user.Username)

	confPath := ""
	if _, err := os.Stat(hestiaUserConf); err == nil {
		confPath = hestiaUserConf
	} else if _, err := os.Stat(vestaUserConf); err == nil {
		confPath = vestaUserConf
	} else {
		// Even if stat failed due to permissions, try the paths
		confPath = hestiaUserConf
	}

	var confMap map[string]string
	var confData []byte
	if confPath != "" {
		if data, err := os.ReadFile(confPath); err == nil {
			confData = data
		} else {
			cmd := exec.CommandContext(ctx, "sudo", "-n", "cat", confPath)
			if out, err := cmd.Output(); err == nil && len(out) > 0 {
				confData = out
			}
		}
	}

	if len(confData) > 0 {
		confMap = parseConfRecord(string(confData))
	}

	// If user.conf was unreadable directly, query CLI (v-list-user <user>)
	if len(confMap) == 0 {
		confMap = c.queryCLIUser(ctx, user.Username)
	}

	if len(confMap) > 0 {
		c.applyUserConfMap(user, confMap)
	}

	// Quota Fallbacks for non-Hestia/Vesta environments
	if user.WebDomainsQuota == "" {
		user.WebDomainsQuota = fmt.Sprintf("%d/unlimited", user.WebCount)
	}
	if user.WebAliasesQuota == "" {
		user.WebAliasesQuota = "0/unlimited"
	}
	if user.DNSDomainsQuota == "" {
		user.DNSDomainsQuota = fmt.Sprintf("%d/unlimited", user.DNSCount)
	}
	if user.DNSRecordsQuota == "" {
		user.DNSRecordsQuota = "0/unlimited"
	}
	if user.MailDomainsQuota == "" {
		user.MailDomainsQuota = fmt.Sprintf("%d/unlimited", user.MailCount)
	}
	if user.MailAccountsQuota == "" {
		user.MailAccountsQuota = "0/unlimited"
	}
	if user.BackupsQuota == "" {
		user.BackupsQuota = "0/1"
	}
	if user.DatabasesQuota == "" {
		user.DatabasesQuota = fmt.Sprintf("%d/unlimited", user.DBCount)
	}
	if user.CronJobsQuota == "" {
		user.CronJobsQuota = "0/unlimited"
	}
	if user.DiskQuota == "" {
		user.DiskQuota = fmt.Sprintf("%d/unlimited", user.DiskUsageMB)
	}
	if user.BandwidthQuota == "" {
		user.BandwidthQuota = fmt.Sprintf("%d/unlimited", user.BandwidthMB)
	}
	if user.IPAddressesQuota == "" {
		user.IPAddressesQuota = "1/0"
	}

	// 2. Enrich User Web Domains (Image 3 data)
	c.collectUserWebDomains(ctx, user, discoveredWebsites)
}

func (c *defaultCollector) applyUserConfMap(user *models.HostingUserCandidate, m map[string]string) {
	if val := getFirst(m, "FULL NAME", "NAME"); val != "" {
		user.FullName = val
	}
	if val := getFirst(m, "EMAIL"); val != "" {
		user.Email = val
	}
	if val := getFirst(m, "PACKAGE"); val != "" {
		user.Package = val
	}
	if val := getFirst(m, "ROLE"); val != "" {
		user.Role = val
	}
	if val := getFirst(m, "LANGUAGE"); val != "" {
		user.Language = val
	}
	if val := getFirst(m, "THEME"); val != "" {
		user.Theme = val
	}
	if val := getFirst(m, "SHELL"); val != "" {
		user.Shell = val
	}
	if val := getFirst(m, "TIME"); val != "" {
		user.TimeCreated = val
	}
	if val := getFirst(m, "DATE"); val != "" {
		user.DateCreated = val
	}
	if val := getFirst(m, "SUSPENDED"); val != "" {
		user.IsSuspended = strings.EqualFold(val, "yes") || strings.EqualFold(val, "true")
	}

	// Quotas: check for direct CLI text "used/limit" or separate conf keys
	if val := getFirst(m, "WEB DOMAINS"); val != "" {
		user.WebDomainsQuota = val
		if parts := strings.Split(val, "/"); len(parts) > 0 {
			if cnt, err := strconv.Atoi(parts[0]); err == nil && cnt > 0 {
				user.WebCount = cnt
			}
		}
	} else {
		user.WebDomainsQuota = formatQuota(m["U_WEB_DOMAINS"], m["WEB_DOMAINS"], user.WebCount, "unlimited")
	}

	if val := getFirst(m, "WEB ALIASES"); val != "" {
		user.WebAliasesQuota = val
	} else {
		user.WebAliasesQuota = formatQuota(m["U_WEB_ALIASES"], m["WEB_ALIASES"], 0, "unlimited")
	}

	if val := getFirst(m, "DNS DOMAINS"); val != "" {
		user.DNSDomainsQuota = val
		if parts := strings.Split(val, "/"); len(parts) > 0 {
			if cnt, err := strconv.Atoi(parts[0]); err == nil && cnt > 0 {
				user.DNSCount = cnt
			}
		}
	} else {
		user.DNSDomainsQuota = formatQuota(m["U_DNS_DOMAINS"], m["DNS_DOMAINS"], user.DNSCount, "unlimited")
	}

	if val := getFirst(m, "DNS RECORDS"); val != "" {
		user.DNSRecordsQuota = val
	} else {
		user.DNSRecordsQuota = formatQuota(m["U_DNS_RECORDS"], m["DNS_RECORDS"], 0, "unlimited")
	}

	if val := getFirst(m, "MAIL DOMAINS"); val != "" {
		user.MailDomainsQuota = val
		if parts := strings.Split(val, "/"); len(parts) > 0 {
			if cnt, err := strconv.Atoi(parts[0]); err == nil && cnt > 0 {
				user.MailCount = cnt
			}
		}
	} else {
		user.MailDomainsQuota = formatQuota(m["U_MAIL_DOMAINS"], m["MAIL_DOMAINS"], user.MailCount, "unlimited")
	}

	if val := getFirst(m, "MAIL ACCOUNTS"); val != "" {
		user.MailAccountsQuota = val
	} else {
		user.MailAccountsQuota = formatQuota(m["U_MAIL_ACCOUNTS"], m["MAIL_ACCOUNTS"], 0, "unlimited")
	}

	if val := getFirst(m, "BACKUPS"); val != "" {
		user.BackupsQuota = val
	} else {
		user.BackupsQuota = formatQuota(m["U_BACKUPS"], m["BACKUPS"], 0, "1")
	}

	if val := getFirst(m, "DATABASES"); val != "" {
		user.DatabasesQuota = val
		if parts := strings.Split(val, "/"); len(parts) > 0 {
			if cnt, err := strconv.Atoi(parts[0]); err == nil && cnt > 0 {
				user.DBCount = cnt
			}
		}
	} else {
		user.DatabasesQuota = formatQuota(m["U_DATABASES"], m["DATABASES"], user.DBCount, "unlimited")
	}

	if val := getFirst(m, "CRON_JOBS", "CRON JOBS"); val != "" {
		user.CronJobsQuota = val
	} else {
		user.CronJobsQuota = formatQuota(m["U_CRON_JOBS"], m["CRON_JOBS"], 0, "unlimited")
	}

	if val := getFirst(m, "DISK"); val != "" {
		user.DiskQuota = val
		if parts := strings.Split(val, "/"); len(parts) > 0 {
			if mb, err := strconv.ParseInt(parts[0], 10, 64); err == nil && mb > 0 {
				user.DiskUsageMB = mb
			}
		}
	} else {
		user.DiskQuota = formatQuota(m["U_DISK"], m["DISK_QUOTA"], user.DiskUsageMB, "unlimited")
	}

	if val := getFirst(m, "BANDWIDTH"); val != "" {
		user.BandwidthQuota = val
		if parts := strings.Split(val, "/"); len(parts) > 0 {
			if mb, err := strconv.ParseInt(parts[0], 10, 64); err == nil && mb > 0 {
				user.BandwidthMB = mb
			}
		}
	} else {
		user.BandwidthQuota = formatQuota(m["U_BANDWIDTH"], m["BANDWIDTH"], user.BandwidthMB, "unlimited")
	}

	if val := getFirst(m, "IP ADDRESSES"); val != "" {
		user.IPAddressesQuota = val
	} else {
		ipAvail := m["IP_AVAIL"]
		if ipAvail == "" {
			ipAvail = "1"
		}
		ipOwned := m["IP_OWNED"]
		if ipOwned == "" {
			ipOwned = "0"
		}
		user.IPAddressesQuota = fmt.Sprintf("%s/%s", ipAvail, ipOwned)
	}
}

func getFirst(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if val, ok := m[k]; ok && strings.TrimSpace(val) != "" {
			return strings.TrimSpace(val)
		}
	}
	return ""
}

func formatQuota(used, max string, defaultUsed interface{}, defaultMax string) string {
	u := strings.TrimSpace(used)
	m := strings.TrimSpace(max)
	if u == "" {
		u = fmt.Sprintf("%v", defaultUsed)
	}
	if m == "" {
		m = defaultMax
	}
	return fmt.Sprintf("%s/%s", u, m)
}

// collectUserWebDomains reads web.conf or queries CLI for Image 3 data
func (c *defaultCollector) collectUserWebDomains(ctx context.Context, user *models.HostingUserCandidate, discoveredWebsites []models.WebsiteCandidate) {
	// First priority: query CLI v-list-web-domains (exact output matching Image 3)
	domains := c.queryCLIWebDomains(ctx, user.Username)

	// Second priority: read web.conf from disk
	if len(domains) == 0 {
		hestiaWebConf := fmt.Sprintf("/usr/local/hestia/data/users/%s/web.conf", user.Username)
		vestaWebConf := fmt.Sprintf("/usr/local/vesta/data/users/%s/web.conf", user.Username)

		webConfPath := ""
		if _, err := os.Stat(hestiaWebConf); err == nil {
			webConfPath = hestiaWebConf
		} else if _, err := os.Stat(vestaWebConf); err == nil {
			webConfPath = vestaWebConf
		} else {
			webConfPath = hestiaWebConf
		}

		var webConfData []byte
		if webConfPath != "" {
			if data, err := os.ReadFile(webConfPath); err == nil {
				webConfData = data
			} else {
				cmd := exec.CommandContext(ctx, "sudo", "-n", "cat", webConfPath)
				if out, err := cmd.Output(); err == nil && len(out) > 0 {
					webConfData = out
				}
			}
		}

		if len(webConfData) > 0 {
			scanner := bufio.NewScanner(bytesNewReader(webConfData))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				rec := parseConfRecord(line)
				dName := rec["DOMAIN"]
				if dName == "" {
					continue
				}

				diskMB, _ := strconv.ParseInt(rec["U_DISK"], 10, 64)
				bwMB, _ := strconv.ParseInt(rec["U_BANDWIDTH"], 10, 64)
				spnd := strings.EqualFold(rec["SUSPENDED"], "yes") || strings.EqualFold(rec["SUSPENDED"], "true")

				ssl := rec["SSL"]
				if ssl == "" {
					ssl = "no"
				}

				tpl := rec["TPL"]
				if tpl == "" {
					tpl = "default"
				}

				ip := rec["IP"]
				if ip == "" {
					ip = "default"
				}

				dateCreated := rec["DATE"]
				if dateCreated == "" {
					dateCreated = user.DateCreated
				}

				domains = append(domains, models.HostingWebDomainCandidate{
					Domain:      dName,
					IP:          ip,
					Template:    tpl,
					SSL:         ssl,
					DiskUsageMB: diskMB,
					BandwidthMB: bwMB,
					IsSuspended: spnd,
					DateCreated: dateCreated,
					Aliases:     rec["ALIAS"],
				})
			}
		}
	}

	// Fallback to synthesizing from user.Websites or discoveredWebsites
	if len(domains) == 0 && len(user.Websites) > 0 {
		for _, wName := range user.Websites {
			matchedKind := "default"
			for _, dw := range discoveredWebsites {
				for _, d := range dw.Domains {
					if strings.EqualFold(d.Name, wName) {
						if dw.WebServerKind != "" {
							matchedKind = string(dw.WebServerKind)
						}
						break
					}
				}
			}

			domains = append(domains, models.HostingWebDomainCandidate{
				Domain:      wName,
				IP:          "default",
				Template:    matchedKind,
				SSL:         "no",
				DiskUsageMB: 0,
				BandwidthMB: 0,
				IsSuspended: user.IsSuspended,
				DateCreated: user.DateCreated,
			})
		}
	}

	// Probe domain health (HTTP status, latency, SSL certificate)
	if len(domains) > 0 {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 5)
		for i := range domains {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				health := probeDomainHealth(ctx, domains[idx].Domain, user.Username)
				domains[idx].HTTPStatus = health.httpStatus
				domains[idx].ResponseTimeMs = health.responseTimeMs
				domains[idx].DNSLookupMs = health.dnsLookupMs
				domains[idx].ConnectTimeMs = health.connectTimeMs
				domains[idx].TLSHandshakeMs = health.tlsHandshakeMs
				domains[idx].TTFBMs = health.ttfbMs
				domains[idx].DownloadedBytes = health.downloadedBytes
				domains[idx].SSLValid = health.sslValid
				domains[idx].SSLDaysLeft = health.sslDaysLeft
				domains[idx].SSLExpiryDate = health.sslExpiryDate
				domains[idx].SSLIssuer = health.sslIssuer

				if health.sslValid || health.sslExpiryDate != "" {
					domains[idx].SSL = "yes"
				}

				// Collect comprehensive traffic and error log telemetry
				domains[idx].Traffic = collectDomainTrafficReport(ctx, domains[idx].Domain, user.Username)
			}(i)
		}
		wg.Wait()
	}

	// 3. User & domain resource usage (CPU %, Memory RSS MB, Workers, Disk fallback, and Load RPM)
	userCPU, userMemMB, workerCount := collectUserProcessesResourceUsage(ctx, user.Username, user.LinuxUID)
	user.CPUPercent = userCPU
	user.MemoryMB = userMemMB
	user.WorkerProcesses = workerCount

	totalUserRequests := int64(0)
	for i := range domains {
		if domains[i].Traffic != nil {
			totalUserRequests += domains[i].Traffic.TotalRequests
		}
	}

	for i := range domains {
		// Fallback disk usage check if not reported by panel
		if domains[i].DiskUsageMB <= 0 {
			dir := fmt.Sprintf("/home/%s/web/%s/public_html", user.Username, domains[i].Domain)
			if mb := checkDirectoryDiskUsageMB(ctx, dir); mb > 0 {
				domains[i].DiskUsageMB = mb
			}
		}

		// Calculate load RPM from access log telemetry
		domains[i].LoadRPM = calculateDomainLoadRPM(domains[i].Traffic)
		domains[i].WorkerProcesses = workerCount

		// Attribute CPU & Memory to domain
		if len(domains) == 1 {
			domains[i].CPUPercent = userCPU
			domains[i].MemoryMB = userMemMB
		} else if totalUserRequests > 0 && domains[i].Traffic != nil && domains[i].Traffic.TotalRequests > 0 {
			share := float64(domains[i].Traffic.TotalRequests) / float64(totalUserRequests)
			domains[i].CPUPercent = math.Round((userCPU*share)*10) / 10
			domains[i].MemoryMB = int64(math.Round(float64(userMemMB) * share))
		} else if len(domains) > 0 {
			share := 1.0 / float64(len(domains))
			domains[i].CPUPercent = math.Round((userCPU*share)*10) / 10
			domains[i].MemoryMB = int64(math.Round(float64(userMemMB) * share))
		}
	}

	user.WebDomainList = domains

	// Ensure user.Websites has all discovered domains
	siteMap := make(map[string]bool)
	for _, w := range user.Websites {
		siteMap[w] = true
	}
	for _, d := range domains {
		if !siteMap[d.Domain] {
			siteMap[d.Domain] = true
			user.Websites = append(user.Websites, d.Domain)
		}
	}
	if len(user.Websites) > user.WebCount {
		user.WebCount = len(user.Websites)
	}
}

func collectUserProcessesResourceUsage(ctx context.Context, username string, uid int) (float64, int64, int) {
	if strings.TrimSpace(username) == "" {
		return 0, 0, 0
	}

	cmdCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	userArgs := []string{"-u", username, "-o", "%cpu,rss,comm", "--no-headers"}
	if uid > 0 {
		userArgs = []string{"-u", fmt.Sprintf("%s,%d", username, uid), "-o", "%cpu,rss,comm", "--no-headers"}
	}

	cmd := exec.CommandContext(cmdCtx, "ps", userArgs...)
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		sudoArgs := append([]string{"-n", "ps"}, userArgs...)
		cmdSudo := exec.CommandContext(cmdCtx, "sudo", sudoArgs...)
		if outSudo, errSudo := cmdSudo.Output(); errSudo == nil && len(outSudo) > 0 {
			out = outSudo
		}
	}

	// Also check if any PHP-FPM pool worker processes are matching "pool <username>"
	poolPattern := fmt.Sprintf("pool %s", username)
	cmdPool := exec.CommandContext(cmdCtx, "pgrep", "-f", poolPattern)
	if pidsOut, pidsErr := cmdPool.Output(); pidsErr == nil && len(pidsOut) > 0 {
		pids := strings.Fields(string(pidsOut))
		if len(pids) > 0 {
			pidList := strings.Join(pids, ",")
			cmdPid := exec.CommandContext(cmdCtx, "ps", "-p", pidList, "-o", "%cpu,rss,comm", "--no-headers")
			if pidPsOut, pidPsErr := cmdPid.Output(); pidPsErr == nil && len(pidPsOut) > 0 {
				out = append(out, pidPsOut...)
			}
		}
	}

	if len(out) == 0 {
		return 0, 0, 0
	}

	var totalCPU float64
	var totalRSSKB int64
	workers := 0

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if c, err := strconv.ParseFloat(fields[0], 64); err == nil {
				totalCPU += c
			}
			if r, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				totalRSSKB += r
			}
			workers++
		}
	}

	memMB := totalRSSKB / 1024
	roundedCPU := math.Round(totalCPU*10) / 10
	return roundedCPU, memMB, workers
}

func calculateDomainLoadRPM(traffic *models.DomainTrafficReport) float64 {
	if traffic == nil {
		return 0
	}
	if len(traffic.RequestsByMinute) > 0 {
		latest := traffic.RequestsByMinute[len(traffic.RequestsByMinute)-1].Count
		return float64(latest)
	}
	if traffic.TotalRequests > 0 {
		return math.Round((float64(traffic.TotalRequests)/60.0)*10) / 10
	}
	return 0
}

func checkDirectoryDiskUsageMB(ctx context.Context, dirPath string) int64 {
	if fi, err := os.Stat(dirPath); err != nil || !fi.IsDir() {
		return 0
	}
	cmdCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "du", "-sm", dirPath)
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		cmdSudo := exec.CommandContext(cmdCtx, "sudo", "-n", "du", "-sm", dirPath)
		if outSudo, errSudo := cmdSudo.Output(); errSudo == nil {
			out = outSudo
		}
	}
	if len(out) > 0 {
		fields := strings.Fields(string(out))
		if len(fields) > 0 {
			if mb, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
				return mb
			}
		}
	}
	return 0
}

func bytesNewReader(b []byte) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(string(b)))
}

func (c *defaultCollector) queryCLIUser(ctx context.Context, username string) map[string]string {
	cmdCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	cmdPaths := []string{
		"v-list-user",
		"/usr/local/hestia/bin/v-list-user",
		"/usr/local/vesta/bin/v-list-user",
	}

	argSets := [][]string{
		{username},
		{username, "json"},
	}

	for _, bin := range cmdPaths {
		for _, args := range argSets {
			cmd := exec.CommandContext(cmdCtx, bin, args...)
			cmd.Env = append(os.Environ(), "HESTIA=/usr/local/hestia", "VESTA=/usr/local/vesta")
			if out, err := cmd.Output(); err == nil && len(out) > 0 {
				if userMap := parseUserOutput(out); len(userMap) > 0 {
					return userMap
				}
			}

			sudoArgs := append([]string{"-n", bin}, args...)
			cmdSudo := exec.CommandContext(cmdCtx, "sudo", sudoArgs...)
			cmdSudo.Env = append(os.Environ(), "HESTIA=/usr/local/hestia", "VESTA=/usr/local/vesta")
			if outSudo, errSudo := cmdSudo.Output(); errSudo == nil && len(outSudo) > 0 {
				if userMap := parseUserOutput(outSudo); len(userMap) > 0 {
					return userMap
				}
			}
		}
	}
	return nil
}

func parseUserOutput(output []byte) map[string]string {
	text := string(output)
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil
	}

	// Try JSON first if it starts with '{'
	if strings.HasPrefix(trimmed, "{") {
		var wrapper map[string]map[string]interface{}
		if err := json.Unmarshal(output, &wrapper); err == nil && len(wrapper) > 0 {
			for _, userData := range wrapper {
				res := make(map[string]string)
				for k, v := range userData {
					res[k] = fmt.Sprintf("%v", v)
				}
				return res
			}
		}
	}

	// Plain text key-value parsing (matches Image 2: KEY: VALUE)
	res := make(map[string]string)
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		res[key] = val
	}
	return res
}

func (c *defaultCollector) queryCLIWebDomains(ctx context.Context, username string) []models.HostingWebDomainCandidate {
	cmdCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	cmdPaths := []string{
		"v-list-web-domains",
		"/usr/local/hestia/bin/v-list-web-domains",
		"/usr/local/vesta/bin/v-list-web-domains",
	}

	argSets := [][]string{
		{username},
		{username, "json"},
	}

	for _, bin := range cmdPaths {
		for _, args := range argSets {
			cmd := exec.CommandContext(cmdCtx, bin, args...)
			cmd.Env = append(os.Environ(), "HESTIA=/usr/local/hestia", "VESTA=/usr/local/vesta")
			if out, err := cmd.Output(); err == nil && len(out) > 0 {
				if domains := parseWebDomainsOutput(out); len(domains) > 0 {
					return domains
				}
			}

			sudoArgs := append([]string{"-n", bin}, args...)
			cmdSudo := exec.CommandContext(cmdCtx, "sudo", sudoArgs...)
			cmdSudo.Env = append(os.Environ(), "HESTIA=/usr/local/hestia", "VESTA=/usr/local/vesta")
			if outSudo, errSudo := cmdSudo.Output(); errSudo == nil && len(outSudo) > 0 {
				if domains := parseWebDomainsOutput(outSudo); len(domains) > 0 {
					return domains
				}
			}
		}
	}
	return nil
}

func parseWebDomainsOutput(output []byte) []models.HostingWebDomainCandidate {
	text := string(output)
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil
	}

	// Try JSON first if it starts with '{'
	if strings.HasPrefix(trimmed, "{") {
		var domainMap map[string]map[string]interface{}
		if err := json.Unmarshal(output, &domainMap); err == nil && len(domainMap) > 0 {
			var res []models.HostingWebDomainCandidate
			for dName, props := range domainMap {
				ip := fmt.Sprintf("%v", props["IP"])
				tpl := fmt.Sprintf("%v", props["TPL"])
				ssl := fmt.Sprintf("%v", props["SSL"])
				spndStr := fmt.Sprintf("%v", props["SUSPENDED"])
				dateStr := fmt.Sprintf("%v", props["DATE"])
				aliases := fmt.Sprintf("%v", props["ALIAS"])

				diskVal, _ := strconv.ParseInt(fmt.Sprintf("%v", props["U_DISK"]), 10, 64)
				bwVal, _ := strconv.ParseInt(fmt.Sprintf("%v", props["U_BANDWIDTH"]), 10, 64)

				res = append(res, models.HostingWebDomainCandidate{
					Domain:      dName,
					IP:          ip,
					Template:    tpl,
					SSL:         ssl,
					DiskUsageMB: diskVal,
					BandwidthMB: bwVal,
					IsSuspended: strings.EqualFold(spndStr, "yes") || strings.EqualFold(spndStr, "true"),
					DateCreated: dateStr,
					Aliases:     aliases,
				})
			}
			return res
		}
	}

	// Plain text tabular parsing (matches Image 3: DOMAIN IP TPL SSL DISK BW SPND DATE)
	var res []models.HostingWebDomainCandidate
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "DOMAIN") || strings.HasPrefix(line, "---") || strings.HasPrefix(line, "===") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 8 {
			dName := fields[0]
			ip := fields[1]
			tpl := fields[2]
			ssl := fields[3]
			diskVal, _ := strconv.ParseInt(fields[4], 10, 64)
			bwVal, _ := strconv.ParseInt(fields[5], 10, 64)
			spnd := strings.EqualFold(fields[6], "yes") || strings.EqualFold(fields[6], "true")
			dateVal := fields[7]

			res = append(res, models.HostingWebDomainCandidate{
				Domain:      dName,
				IP:          ip,
				Template:    tpl,
				SSL:         ssl,
				DiskUsageMB: diskVal,
				BandwidthMB: bwVal,
				IsSuspended: spnd,
				DateCreated: dateVal,
			})
		}
	}
	return res
}

type domainHealthResult struct {
	httpStatus      int
	responseTimeMs  int64
	dnsLookupMs     int64
	connectTimeMs   int64
	tlsHandshakeMs  int64
	ttfbMs          int64
	downloadedBytes int64
	sslValid        bool
	sslDaysLeft     int
	sslExpiryDate   string
	sslIssuer       string
}

func probeDomainHealth(ctx context.Context, domain, user string) domainHealthResult {
	res := domainHealthResult{}
	cleanDomain := strings.TrimSpace(domain)
	if cleanDomain == "" {
		return res
	}

	// 1. SSL Certificate check
	certLoaded := probeLocalCertificate(cleanDomain, user, &res)
	if !certLoaded {
		probeTLSConnection(cleanDomain, &res)
	}

	// 2. HTTP Health & Latency check with detailed cURL-equivalent timing breakdown
	probeHTTPReachability(ctx, cleanDomain, &res)

	return res
}

func probeLocalCertificate(domain, user string, res *domainHealthResult) bool {
	paths := []string{
		fmt.Sprintf("/home/%s/conf/web/%s/ssl/%s.crt", user, domain, domain),
		fmt.Sprintf("/home/%s/conf/web/%s/ssl/%s.pem", user, domain, domain),
		fmt.Sprintf("/home/%s/ssl/%s.crt", user, domain),
		fmt.Sprintf("/etc/letsencrypt/live/%s/cert.pem", domain),
		fmt.Sprintf("/etc/letsencrypt/live/%s/fullchain.pem", domain),
	}

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil || len(data) == 0 {
			continue
		}
		for {
			block, rest := pem.Decode(data)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					now := time.Now()
					res.sslValid = now.After(cert.NotBefore) && now.Before(cert.NotAfter)
					res.sslDaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
					res.sslExpiryDate = cert.NotAfter.Format("2006-01-02")
					issuer := cert.Issuer.CommonName
					if issuer == "" && len(cert.Issuer.Organization) > 0 {
						issuer = cert.Issuer.Organization[0]
					}
					res.sslIssuer = issuer
					return true
				}
			}
			data = rest
		}
	}
	return false
}

func probeTLSConnection(domain string, res *domainHealthResult) {
	dialTargets := []string{"127.0.0.1:443", domain + ":443"}

	for _, target := range dialTargets {
		dialer := &net.Dialer{Timeout: 3 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         domain,
		})
		if err == nil {
			defer conn.Close()
			state := conn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				now := time.Now()
				res.sslValid = now.After(cert.NotBefore) && now.Before(cert.NotAfter)
				res.sslDaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
				res.sslExpiryDate = cert.NotAfter.Format("2006-01-02")
				issuer := cert.Issuer.CommonName
				if issuer == "" && len(cert.Issuer.Organization) > 0 {
					issuer = cert.Issuer.Organization[0]
				}
				res.sslIssuer = issuer
				return
			}
		}
	}
}

func probeHTTPReachability(ctx context.Context, domain string, res *domainHealthResult) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	scheme := "https"
	if res.sslExpiryDate == "" && !res.sslValid {
		scheme = "http"
	}

	runProbe := func(targetScheme string, useLoopback bool) bool {
		urlStr := fmt.Sprintf("%s://%s/", targetScheme, domain)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, urlStr, nil)
		if err != nil {
			return false
		}
		req.Header.Set("User-Agent", "VPSMonitor-Agent/1.0 (HealthProbe)")
		req.Header.Set("Host", domain)

		var (
			dnsStart, dnsDone   time.Time
			connStart, connDone time.Time
			tlsStart, tlsDone   time.Time
			ttfbTime            time.Time
		)

		trace := &httptrace.ClientTrace{
			DNSStart: func(_ httptrace.DNSStartInfo) {
				dnsStart = time.Now()
			},
			DNSDone: func(_ httptrace.DNSDoneInfo) {
				dnsDone = time.Now()
			},
			ConnectStart: func(_, _ string) {
				if connStart.IsZero() {
					connStart = time.Now()
				}
			},
			ConnectDone: func(_, _ string, _ error) {
				if connDone.IsZero() {
					connDone = time.Now()
				}
			},
			TLSHandshakeStart: func() {
				tlsStart = time.Now()
			},
			TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
				tlsDone = time.Now()
			},
			GotFirstResponseByte: func() {
				ttfbTime = time.Now()
			},
		}

		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

		dialer := &net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}

		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         domain,
			},
			DisableKeepAlives: true,
		}

		if useLoopback {
			transport.DialContext = func(dCtx context.Context, network, addr string) (net.Conn, error) {
				_, port, _ := net.SplitHostPort(addr)
				return dialer.DialContext(dCtx, network, "127.0.0.1:"+port)
			}
		} else {
			transport.DialContext = dialer.DialContext
		}

		client := &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		}

		totalStart := time.Now()
		resp, err := client.Do(req)
		if err != nil || resp == nil {
			return false
		}
		defer resp.Body.Close()

		res.httpStatus = resp.StatusCode
		n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 5*1024*1024))
		res.downloadedBytes = n
		res.responseTimeMs = time.Since(totalStart).Milliseconds()

		if !dnsStart.IsZero() && !dnsDone.IsZero() {
			res.dnsLookupMs = dnsDone.Sub(dnsStart).Milliseconds()
		}
		if !connStart.IsZero() && !connDone.IsZero() {
			res.connectTimeMs = connDone.Sub(connStart).Milliseconds()
		}
		if !tlsStart.IsZero() && !tlsDone.IsZero() {
			res.tlsHandshakeMs = tlsDone.Sub(tlsStart).Milliseconds()
		}
		if !ttfbTime.IsZero() {
			res.ttfbMs = ttfbTime.Sub(totalStart).Milliseconds()
		} else {
			res.ttfbMs = res.responseTimeMs
		}

		return true
	}

	// 1. Try public HTTPS
	if scheme == "https" && runProbe("https", false) {
		return
	}
	// 2. Try loopback HTTPS (if public hairpin NAT blocked on host)
	if scheme == "https" && runProbe("https", true) {
		return
	}
	// 3. Fallback to HTTP (public)
	if runProbe("http", false) {
		return
	}
	// 4. Fallback to HTTP (loopback)
	runProbe("http", true)
}

func collectDomainTrafficReport(ctx context.Context, domain string, username string) *models.DomainTrafficReport {
	cleanDomain := strings.TrimSpace(domain)
	if cleanDomain == "" {
		return nil
	}

	logCandidates := []string{
		fmt.Sprintf("/var/log/apache2/domains/%s.log", cleanDomain),
		fmt.Sprintf("/var/log/nginx/domains/%s.log", cleanDomain),
		fmt.Sprintf("/var/log/httpd/domains/%s.log", cleanDomain),
		fmt.Sprintf("/home/%s/web/%s/logs/access.log", username, cleanDomain),
		fmt.Sprintf("/home/%s/logs/%s/access.log", username, cleanDomain),
	}

	errorCandidates := []string{
		fmt.Sprintf("/var/log/apache2/domains/%s.error.log", cleanDomain),
		fmt.Sprintf("/var/log/nginx/domains/%s.error.log", cleanDomain),
		fmt.Sprintf("/var/log/httpd/domains/%s.error.log", cleanDomain),
		fmt.Sprintf("/home/%s/web/%s/logs/error.log", username, cleanDomain),
	}

	var accessLogPath string
	var logSize int64
	for _, p := range logCandidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			accessLogPath = p
			logSize = fi.Size()
			break
		}
	}

	var errorLogPath string
	for _, p := range errorCandidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			errorLogPath = p
			break
		}
	}

	if accessLogPath == "" {
		for _, p := range logCandidates {
			testCmd := exec.CommandContext(ctx, "sudo", "-n", "test", "-f", p)
			if err := testCmd.Run(); err == nil {
				accessLogPath = p
				sizeCmd := exec.CommandContext(ctx, "sudo", "-n", "stat", "-c", "%s", p)
				if out, err := sizeCmd.Output(); err == nil {
					logSize, _ = strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
				}
				break
			}
		}
	}

	if accessLogPath == "" {
		return nil
	}

	report := &models.DomainTrafficReport{
		Domain:       cleanDomain,
		LogPath:      accessLogPath,
		LogSizeBytes: logSize,
		GeneratedAt:  time.Now().Format("Mon Jan 2 15:04:05 MST 2006"),
		StatusCodes:  make(map[string]int64),
		Methods:      make(map[string]int64),
	}

	var scanner *bufio.Scanner
	var fileToClose *os.File
	if f, err := os.Open(accessLogPath); err == nil {
		fileToClose = f
		scanner = bufio.NewScanner(f)
	} else {
		tailCmd := exec.CommandContext(ctx, "sudo", "-n", "tail", "-n", "100000", accessLogPath)
		if stdout, err := tailCmd.StdoutPipe(); err == nil {
			if err := tailCmd.Start(); err == nil {
				scanner = bufio.NewScanner(stdout)
				go func() { _ = tailCmd.Wait() }()
			}
		}
	}

	if scanner != nil {
		if fileToClose != nil {
			defer fileToClose.Close()
		}

		urlMap := make(map[string]int64)
		ipMap := make(map[string]int64)
		minuteMap := make(map[string]int64)
		var recentEntries []models.AccessLogEntry

		buf := make([]byte, 64*1024)
		scanner.Buffer(buf, 256*1024)

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			report.TotalRequests++
			report.TotalEntries++

			entry, ok := parseAccessLogLine(line)
			if !ok {
				continue
			}

			statusStr := strconv.Itoa(entry.Status)
			report.StatusCodes[statusStr]++
			if entry.Status >= 200 && entry.Status < 300 {
				report.Successful2xx++
			} else if entry.Status >= 300 && entry.Status < 400 {
				report.Redirects3xx++
			} else if entry.Status >= 400 && entry.Status < 500 {
				report.ClientErrors4xx++
			} else if entry.Status >= 500 && entry.Status < 600 {
				report.ServerErrors5xx++
			}

			if entry.Method != "" {
				report.Methods[entry.Method]++
			}

			if entry.URL != "" {
				urlMap[entry.URL]++
			}

			if entry.ClientIP != "" {
				ipMap[entry.ClientIP]++
			}

			if entry.Bytes > 0 {
				report.RequestsWithBytes++
				report.TotalResponseBytes += entry.Bytes
			}

			if len(entry.Timestamp) >= 17 {
				minuteKey := entry.Timestamp[:17]
				minuteMap[minuteKey]++
			}

			recentEntries = append(recentEntries, entry)
			if len(recentEntries) > 20 {
				recentEntries = recentEntries[1:]
			}
		}

		report.LatestRequests = recentEntries

		type kv struct {
			k string
			v int64
		}
		var urlList []kv
		for k, v := range urlMap {
			urlList = append(urlList, kv{k, v})
		}
		sort.Slice(urlList, func(i, j int) bool { return urlList[i].v > urlList[j].v })
		limitU := 20
		if len(urlList) < limitU {
			limitU = len(urlList)
		}
		for i := 0; i < limitU; i++ {
			report.TopURLs = append(report.TopURLs, models.TrafficItem{
				Key:   urlList[i].k,
				Count: urlList[i].v,
			})
		}

		var ipList []kv
		for k, v := range ipMap {
			ipList = append(ipList, kv{k, v})
		}
		sort.Slice(ipList, func(i, j int) bool { return ipList[i].v > ipList[j].v })
		limitIP := 20
		if len(ipList) < limitIP {
			limitIP = len(ipList)
		}
		for i := 0; i < limitIP; i++ {
			report.TopClientIPs = append(report.TopClientIPs, models.TrafficItem{
				Key:   ipList[i].k,
				Count: ipList[i].v,
			})
		}

		var minList []kv
		for k, v := range minuteMap {
			minList = append(minList, kv{k, v})
		}
		sort.Slice(minList, func(i, j int) bool { return minList[i].k < minList[j].k })
		startMin := 0
		if len(minList) > 25 {
			startMin = len(minList) - 25
		}
		for i := startMin; i < len(minList); i++ {
			report.RequestsByMinute = append(report.RequestsByMinute, models.TimeTrafficItem{
				Time:  minList[i].k,
				Count: minList[i].v,
			})
		}
	}

	if errorLogPath != "" {
		report.LatestErrors = collectErrorLogEntries(ctx, errorLogPath)
	}

	return report
}

func parseAccessLogLine(line string) (models.AccessLogEntry, bool) {
	var entry models.AccessLogEntry
	firstSpace := strings.IndexByte(line, ' ')
	if firstSpace <= 0 {
		return entry, false
	}
	entry.ClientIP = line[:firstSpace]

	openBracket := strings.IndexByte(line, '[')
	closeBracket := strings.IndexByte(line, ']')
	if openBracket > 0 && closeBracket > openBracket {
		entry.Timestamp = line[openBracket+1 : closeBracket]
	}

	firstQuote := strings.IndexByte(line, '"')
	if firstQuote < 0 {
		return entry, false
	}
	rest := line[firstQuote+1:]
	secondQuote := strings.IndexByte(rest, '"')
	if secondQuote < 0 {
		return entry, false
	}
	reqStr := rest[:secondQuote]
	parts := strings.Split(reqStr, " ")
	if len(parts) >= 1 {
		entry.Method = parts[0]
	}
	if len(parts) >= 2 {
		entry.URL = parts[1]
	}

	afterReq := strings.TrimSpace(rest[secondQuote+1:])
	fields := strings.Fields(afterReq)
	if len(fields) >= 1 {
		entry.Status, _ = strconv.Atoi(fields[0])
	}
	if len(fields) >= 2 {
		entry.Bytes, _ = strconv.ParseInt(fields[1], 10, 64)
	}

	quote3 := strings.IndexByte(afterReq, '"')
	if quote3 >= 0 {
		restQ := afterReq[quote3+1:]
		quote4 := strings.IndexByte(restQ, '"')
		if quote4 >= 0 {
			entry.Referer = restQ[:quote4]
			restUA := restQ[quote4+1:]
			quote5 := strings.IndexByte(restUA, '"')
			if quote5 >= 0 {
				quote6 := strings.IndexByte(restUA[quote5+1:], '"')
				if quote6 >= 0 {
					entry.UserAgent = restUA[quote5+1 : quote5+1+quote6]
				}
			}
		}
	}

	return entry, true
}

func collectErrorLogEntries(ctx context.Context, path string) []models.ErrorLogEntry {
	var results []models.ErrorLogEntry
	var lines []string

	if data, err := os.ReadFile(path); err == nil {
		all := strings.Split(string(data), "\n")
		start := 0
		if len(all) > 30 {
			start = len(all) - 30
		}
		lines = all[start:]
	} else {
		cmd := exec.CommandContext(ctx, "sudo", "-n", "tail", "-n", "30", path)
		if out, err := cmd.Output(); err == nil {
			lines = strings.Split(string(out), "\n")
		}
	}

	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		entry := models.ErrorLogEntry{
			Message: l,
		}
		if strings.HasPrefix(l, "[") {
			if end := strings.IndexByte(l, ']'); end > 0 {
				entry.Timestamp = l[1:end]
			}
		}
		if idx := strings.Index(l, ":error]"); idx > 0 {
			entry.Level = "error"
		} else if idx := strings.Index(l, ":warn]"); idx > 0 {
			entry.Level = "warning"
		}
		if refIdx := strings.Index(l, ", referer: "); refIdx > 0 {
			entry.Referer = strings.TrimSpace(l[refIdx+11:])
		}
		results = append(results, entry)
	}

	return results
}


