// Package models defines the read-only application discovery payloads.
//
// Phase 3.5C discovery is inventory-only. These models intentionally avoid
// environment variables, source files, raw secrets, and arbitrary file content.
package models

import "time"

type Confidence string

const (
	ConfidenceHigh    Confidence = "HIGH"
	ConfidenceMedium  Confidence = "MEDIUM"
	ConfidenceLow     Confidence = "LOW"
	ConfidenceUnknown Confidence = "UNKNOWN"
)

type Runtime string

const (
	RuntimeUnknown Runtime = "unknown"
	RuntimeJava    Runtime = "java"
	RuntimeNodeJS  Runtime = "nodejs"
	RuntimePython  Runtime = "python"
	RuntimePHP     Runtime = "php"
	RuntimeDotNet  Runtime = "dotnet"
	RuntimeGo      Runtime = "go"
)

type Framework string

const (
	FrameworkUnknown    Framework = "unknown"
	FrameworkSpringBoot Framework = "spring_boot"
	FrameworkNextJS     Framework = "nextjs"
	FrameworkExpress    Framework = "express"
	FrameworkNestJS     Framework = "nestjs"
	FrameworkDjango     Framework = "django"
	FrameworkFastAPI    Framework = "fastapi"
	FrameworkFlask      Framework = "flask"
	FrameworkLaravel    Framework = "laravel"
	FrameworkWordPress  Framework = "wordpress"
	FrameworkASPNETCore Framework = "aspnet_core"
)

type ServiceKind string

const (
	ServiceUnknown    ServiceKind = "unknown"
	ServiceNginx      ServiceKind = "nginx"
	ServiceApache     ServiceKind = "apache"
	ServiceCaddy      ServiceKind = "caddy"
	ServicePostgreSQL ServiceKind = "postgresql"
	ServiceMySQL      ServiceKind = "mysql"
	ServiceMariaDB    ServiceKind = "mariadb"
	ServiceMongoDB    ServiceKind = "mongodb"
	ServiceRedis      ServiceKind = "redis"
	ServicePHPFPM     ServiceKind = "php_fpm"
)

type PortScope string

const (
	PortScopeUnknown     PortScope = "unknown"
	PortScopeLoopback    PortScope = "loopback"
	PortScopePrivate     PortScope = "private"
	PortScopePublic      PortScope = "public"
	PortScopeUnspecified PortScope = "unspecified"
)

type Evidence struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type DiscoverySource string

const (
	SourceNginxConfig  DiscoverySource = "nginx_config"
	SourceApacheConfig DiscoverySource = "apache_config"
)

type WebDomainCandidate struct {
	Name      string `json:"name"`
	IsPrimary bool   `json:"is_primary"`
}

type WebsiteCandidate struct {
	ID               string               `json:"id,omitempty"` // Internal use only
	Domains          []WebDomainCandidate `json:"domains"`
	DocumentRoot     string               `json:"document_root,omitempty"`
	WebServerKind    ServiceKind          `json:"web_server_kind"`
	Source           DiscoverySource      `json:"source"`
	ListenPorts      []int                `json:"listen_ports,omitempty"`
	ProxyPassTargets []string             `json:"proxy_pass_targets,omitempty"`
	FpmSocketPaths   []string             `json:"fpm_socket_paths,omitempty"`
	Confidence       Confidence           `json:"confidence"`
	Evidence         []Evidence           `json:"evidence"`
}

type Listener struct {
	Protocol     string    `json:"protocol"`
	LocalAddress string    `json:"local_address"`
	LocalPort    int       `json:"local_port"`
	Scope        PortScope `json:"scope"`
	PID          *int64    `json:"pid,omitempty"`
	ProcessName  string    `json:"process_name,omitempty"`
}

type ProcessMetadata struct {
	PID             int64      `json:"pid"`
	ParentPID       *int64     `json:"parent_pid,omitempty"`
	Name            string     `json:"name"`
	ExePath         string     `json:"exe_path,omitempty"`
	CmdlineRedacted string     `json:"cmdline_redacted,omitempty"`
	User            string     `json:"user,omitempty"`
	StartTime       *time.Time `json:"start_time,omitempty"`
	SystemdUnit     string     `json:"systemd_unit,omitempty"`
	Listeners       []Listener `json:"listeners,omitempty"`
}

type ApplicationCandidate struct {
	ID                  string          `json:"id"`
	Runtime             Runtime         `json:"runtime"`
	RuntimeConfidence   Confidence      `json:"runtime_confidence"`
	Framework           Framework       `json:"framework"`
	FrameworkConfidence Confidence      `json:"framework_confidence"`
	Process             ProcessMetadata `json:"process"`
	Ports               []Listener      `json:"ports,omitempty"`
	SystemdUnit         string          `json:"systemd_unit,omitempty"`
	Evidence            []Evidence      `json:"evidence"`
}

type ServiceCandidate struct {
	ID          string          `json:"id"`
	Kind        ServiceKind     `json:"kind"`
	Confidence  Confidence      `json:"confidence"`
	Process     ProcessMetadata `json:"process"`
	Ports       []Listener      `json:"ports,omitempty"`
	SystemdUnit string          `json:"systemd_unit,omitempty"`
	Evidence    []Evidence      `json:"evidence"`
}

type HostingWebDomainCandidate struct {
	Domain         string `json:"domain"`
	IP             string `json:"ip"`
	Template       string `json:"template"`
	SSL            string `json:"ssl"`
	DiskUsageMB    int64  `json:"disk_usage_mb"`
	BandwidthMB    int64  `json:"bandwidth_mb"`
	IsSuspended    bool   `json:"is_suspended"`
	DateCreated    string `json:"date_created"`
	Aliases        string `json:"aliases,omitempty"`
	HTTPStatus      int    `json:"http_status,omitempty"`
	ResponseTimeMs  int64  `json:"response_time_ms,omitempty"`
	DNSLookupMs     int64  `json:"dns_lookup_ms,omitempty"`
	ConnectTimeMs   int64  `json:"connect_time_ms,omitempty"`
	TLSHandshakeMs  int64  `json:"tls_handshake_ms,omitempty"`
	TTFBMs          int64  `json:"ttfb_ms,omitempty"`
	DownloadedBytes int64  `json:"downloaded_bytes,omitempty"`
	SSLValid        bool                 `json:"ssl_valid,omitempty"`
	SSLDaysLeft     int                  `json:"ssl_days_left,omitempty"`
	SSLExpiryDate   string               `json:"ssl_expiry_date,omitempty"`
	SSLIssuer       string               `json:"ssl_issuer,omitempty"`
	Traffic         *DomainTrafficReport `json:"traffic,omitempty"`
	CPUPercent      float64              `json:"cpu_percent,omitempty"`
	MemoryMB        int64                `json:"memory_mb,omitempty"`
	WorkerProcesses int                  `json:"worker_processes,omitempty"`
	LoadRPM         float64              `json:"load_rpm,omitempty"`
}

type TrafficItem struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

type TimeTrafficItem struct {
	Time  string `json:"time"`
	Count int64  `json:"count"`
}

type AccessLogEntry struct {
	ClientIP  string `json:"client_ip"`
	Timestamp string `json:"timestamp"`
	Method    string `json:"method"`
	URL       string `json:"url"`
	Status    int    `json:"status"`
	Bytes     int64  `json:"bytes"`
	Referer   string `json:"referer,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type ErrorLogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level,omitempty"`
	Message   string `json:"message"`
	Referer   string `json:"referer,omitempty"`
	Client    string `json:"client,omitempty"`
}

type DomainTrafficReport struct {
	Domain             string           `json:"domain"`
	LogPath            string           `json:"log_path,omitempty"`
	LogSizeBytes       int64            `json:"log_size_bytes,omitempty"`
	TotalRequests      int64            `json:"total_requests"`
	GeneratedAt        string           `json:"generated_at,omitempty"`
	TotalEntries       int64            `json:"total_entries"`
	Successful2xx      int64            `json:"successful_2xx"`
	Redirects3xx       int64            `json:"redirects_3xx"`
	ClientErrors4xx    int64            `json:"client_errors_4xx"`
	ServerErrors5xx    int64            `json:"server_errors_5xx"`
	StatusCodes        map[string]int64 `json:"status_codes,omitempty"`
	Methods            map[string]int64 `json:"methods,omitempty"`
	TopURLs            []TrafficItem    `json:"top_urls,omitempty"`
	TopClientIPs       []TrafficItem    `json:"top_client_ips,omitempty"`
	RequestsWithBytes  int64            `json:"requests_with_bytes"`
	TotalResponseBytes int64            `json:"total_response_bytes"`
	RequestsByMinute   []TimeTrafficItem`json:"requests_by_minute,omitempty"`
	LatestRequests     []AccessLogEntry `json:"latest_requests,omitempty"`
	LatestErrors       []ErrorLogEntry  `json:"latest_errors,omitempty"`
}

type HostingUserCandidate struct {
	Username          string                      `json:"username"`
	FullName          string                      `json:"full_name,omitempty"`
	Email             string                      `json:"email,omitempty"`
	Role              string                      `json:"role"`
	Package           string                      `json:"package"`
	Language          string                      `json:"language,omitempty"`
	Theme             string                      `json:"theme,omitempty"`
	WebCount          int                         `json:"web_count"`
	DNSCount          int                         `json:"dns_count"`
	MailCount         int                         `json:"mail_count"`
	DBCount           int                         `json:"db_count"`
	DiskUsageMB       int64                       `json:"disk_usage_mb"`
	BandwidthMB       int64                       `json:"bandwidth_mb"`
	IsSuspended       bool                        `json:"is_suspended"`
	DateCreated       string                      `json:"date_created"`
	TimeCreated       string                      `json:"time_created,omitempty"`
	HomeDir           string                      `json:"home_dir"`
	Shell             string                      `json:"shell"`
	LinuxUID          int                         `json:"linux_uid"`
	Websites          []string                    `json:"websites"`
	WebDomainsQuota   string                      `json:"web_domains_quota,omitempty"`
	WebAliasesQuota   string                      `json:"web_aliases_quota,omitempty"`
	DNSDomainsQuota   string                      `json:"dns_domains_quota,omitempty"`
	DNSRecordsQuota   string                      `json:"dns_records_quota,omitempty"`
	MailDomainsQuota  string                      `json:"mail_domains_quota,omitempty"`
	MailAccountsQuota string                      `json:"mail_accounts_quota,omitempty"`
	BackupsQuota      string                      `json:"backups_quota,omitempty"`
	DatabasesQuota    string                      `json:"databases_quota,omitempty"`
	CronJobsQuota     string                      `json:"cron_jobs_quota,omitempty"`
	DiskQuota         string                      `json:"disk_quota,omitempty"`
	BandwidthQuota    string                      `json:"bandwidth_quota,omitempty"`
	IPAddressesQuota  string                      `json:"ip_addresses_quota,omitempty"`
	CPUPercent        float64                     `json:"cpu_percent,omitempty"`
	MemoryMB          int64                       `json:"memory_mb,omitempty"`
	WorkerProcesses   int                         `json:"worker_processes,omitempty"`
	WebDomainList     []HostingWebDomainCandidate `json:"web_domain_list,omitempty"`
}

type DiscoveryPayload struct {
	CollectedAt  time.Time              `json:"collected_at"`
	Applications []ApplicationCandidate `json:"applications"`
	Services     []ServiceCandidate     `json:"services"`
	Listeners    []Listener             `json:"listeners"`
	Websites     []WebsiteCandidate     `json:"websites,omitempty"`
	HostingUsers []HostingUserCandidate `json:"hosting_users,omitempty"`
	Warnings     []string               `json:"warnings,omitempty"`
}

