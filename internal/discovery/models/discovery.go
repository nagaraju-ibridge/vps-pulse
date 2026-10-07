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

type DiscoveryPayload struct {
	CollectedAt  time.Time              `json:"collected_at"`
	Applications []ApplicationCandidate `json:"applications"`
	Services     []ServiceCandidate     `json:"services"`
	Listeners    []Listener             `json:"listeners"`
	Warnings     []string               `json:"warnings,omitempty"`
}
