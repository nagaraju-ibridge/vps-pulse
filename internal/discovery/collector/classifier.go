// Package collector contains pure classification helpers for application discovery.
package collector

import (
	"fmt"
	"path/filepath"
	"strings"

	"vpsmonitoring-agent/internal/discovery/models"
)

type Classification struct {
	Applications []models.ApplicationCandidate
	Services     []models.ServiceCandidate
}

type Classifier interface {
	ClassifyProcess(process models.ProcessMetadata) Classification
}

type DefaultClassifier struct{}

func NewClassifier() *DefaultClassifier {
	return &DefaultClassifier{}
}

func (c *DefaultClassifier) ClassifyProcess(process models.ProcessMetadata) Classification {
	var out Classification

	serviceKind, serviceConfidence, serviceEvidence := classifyService(process)
	if serviceKind != models.ServiceUnknown {
		out.Services = append(out.Services, models.ServiceCandidate{
			ID:          candidateID(process.PID),
			Kind:        serviceKind,
			Confidence:  serviceConfidence,
			Process:     process,
			Ports:       process.Listeners,
			SystemdUnit: process.SystemdUnit,
			Evidence:    serviceEvidence,
		})
	}

	runtime, runtimeConfidence, runtimeEvidence := classifyRuntime(process)
	framework, frameworkConfidence, frameworkEvidence := classifyFramework(process, runtime)
	if runtime != models.RuntimeUnknown || framework != models.FrameworkUnknown {
		evidence := append(runtimeEvidence, frameworkEvidence...)
		out.Applications = append(out.Applications, models.ApplicationCandidate{
			ID:                  candidateID(process.PID),
			Runtime:             runtime,
			RuntimeConfidence:   runtimeConfidence,
			Framework:           framework,
			FrameworkConfidence: frameworkConfidence,
			Process:             process,
			Ports:               process.Listeners,
			SystemdUnit:         process.SystemdUnit,
			Evidence:            evidence,
		})
	}

	return out
}

func classifyRuntime(p models.ProcessMetadata) (models.Runtime, models.Confidence, []models.Evidence) {
	name := normalizeName(p.Name)
	exe := strings.ToLower(p.ExePath)
	cmd := strings.ToLower(p.CmdlineRedacted)

	switch {
	case name == "java" || strings.HasSuffix(exe, "/java") || strings.HasSuffix(exe, `\java.exe`):
		return models.RuntimeJava, models.ConfidenceHigh, []models.Evidence{evidence("process_name", "java")}
	case name == "node" || name == "nodejs" || strings.HasSuffix(exe, "/node") || strings.HasSuffix(exe, `\node.exe`):
		return models.RuntimeNodeJS, models.ConfidenceHigh, []models.Evidence{evidence("process_name", name)}
	case name == "python" || name == "python3" || strings.HasPrefix(name, "python3."):
		return models.RuntimePython, models.ConfidenceHigh, []models.Evidence{evidence("process_name", name)}
	case name == "gunicorn" || name == "uvicorn":
		return models.RuntimePython, models.ConfidenceMedium, []models.Evidence{evidence("process_name", name)}
	case name == "php" || name == "php-fpm" || strings.HasPrefix(name, "php-fpm"):
		return models.RuntimePHP, models.ConfidenceHigh, []models.Evidence{evidence("process_name", name)}
	case name == "dotnet" || strings.HasSuffix(exe, "/dotnet") || strings.HasSuffix(exe, `\dotnet.exe`):
		return models.RuntimeDotNet, models.ConfidenceHigh, []models.Evidence{evidence("process_name", "dotnet")}
	case strings.Contains(cmd, "go run ") || strings.Contains(cmd, "go-build"):
		return models.RuntimeGo, models.ConfidenceMedium, []models.Evidence{evidence("command_pattern", "go_execution")}
	case strings.Contains(name, "golang") || strings.Contains(exe, "/go/bin/"):
		return models.RuntimeGo, models.ConfidenceLow, []models.Evidence{evidence("process_metadata", "go_hint")}
	default:
		return models.RuntimeUnknown, models.ConfidenceUnknown, nil
	}
}

func classifyService(p models.ProcessMetadata) (models.ServiceKind, models.Confidence, []models.Evidence) {
	name := normalizeName(p.Name)
	unit := strings.ToLower(p.SystemdUnit)
	exe := strings.ToLower(p.ExePath)

	switch {
	case name == "nginx" || strings.Contains(unit, "nginx"):
		return models.ServiceNginx, models.ConfidenceHigh, []models.Evidence{evidence("service_name", "nginx")}
	case name == "apache2" || name == "httpd" || strings.Contains(unit, "apache2") || strings.Contains(unit, "httpd"):
		return models.ServiceApache, models.ConfidenceHigh, []models.Evidence{evidence("service_name", name)}
	case name == "caddy" || strings.Contains(unit, "caddy"):
		return models.ServiceCaddy, models.ConfidenceHigh, []models.Evidence{evidence("service_name", "caddy")}
	case name == "postgres" || name == "postgresql" || strings.Contains(unit, "postgres"):
		return models.ServicePostgreSQL, models.ConfidenceHigh, []models.Evidence{evidence("service_name", "postgresql")}
	case name == "mysqld" || name == "mysql" || strings.Contains(unit, "mysql.service"):
		return models.ServiceMySQL, models.ConfidenceHigh, []models.Evidence{evidence("service_name", "mysql")}
	case name == "mariadbd" || strings.Contains(unit, "mariadb"):
		return models.ServiceMariaDB, models.ConfidenceHigh, []models.Evidence{evidence("service_name", "mariadb")}
	case name == "mongod" || name == "mongodb" || strings.Contains(unit, "mongodb"):
		return models.ServiceMongoDB, models.ConfidenceHigh, []models.Evidence{evidence("service_name", "mongodb")}
	case name == "redis-server" || name == "redis" || strings.Contains(unit, "redis"):
		return models.ServiceRedis, models.ConfidenceHigh, []models.Evidence{evidence("service_name", "redis")}
	case name == "php-fpm" || strings.HasPrefix(name, "php-fpm") || strings.Contains(exe, "php-fpm"):
		return models.ServicePHPFPM, models.ConfidenceHigh, []models.Evidence{evidence("service_name", "php_fpm")}
	default:
		return models.ServiceUnknown, models.ConfidenceUnknown, nil
	}
}

func classifyFramework(p models.ProcessMetadata, runtime models.Runtime) (models.Framework, models.Confidence, []models.Evidence) {
	cmd := strings.ToLower(p.CmdlineRedacted)
	name := normalizeName(p.Name)
	exe := strings.ToLower(p.ExePath)
	unit := strings.ToLower(p.SystemdUnit)
	text := strings.Join([]string{cmd, name, exe, unit}, " ")

	switch runtime {
	case models.RuntimeJava:
		if containsAny(text, "org.springframework.boot.loader", "spring-boot:run", "springboot") {
			return models.FrameworkSpringBoot, models.ConfidenceHigh, []models.Evidence{evidence("framework_pattern", "spring_boot_loader_or_command")}
		}
		if strings.Contains(text, "spring") && strings.Contains(text, ".jar") {
			return models.FrameworkSpringBoot, models.ConfidenceMedium, []models.Evidence{evidence("artifact_name", "spring_jar")}
		}
	case models.RuntimeNodeJS:
		if strings.Contains(cmd, "next start") {
			return models.FrameworkNextJS, models.ConfidenceHigh, []models.Evidence{evidence("framework_command", "next_start")}
		}
		if containsAny(text, ".next", " next ") {
			return models.FrameworkNextJS, models.ConfidenceMedium, []models.Evidence{evidence("framework_pattern", "next")}
		}
		if containsAny(text, "nestjs", " nest ") {
			return models.FrameworkNestJS, models.ConfidenceMedium, []models.Evidence{evidence("framework_pattern", "nestjs")}
		}
		if containsAny(text, "express") {
			return models.FrameworkExpress, models.ConfidenceLow, []models.Evidence{evidence("framework_pattern", "express")}
		}
	case models.RuntimePython:
		if containsAny(text, "manage.py runserver", "django.core", ".wsgi", " wsgi:") {
			return models.FrameworkDjango, models.ConfidenceHigh, []models.Evidence{evidence("framework_pattern", "django_wsgi_or_manage_py")}
		}
		if strings.Contains(text, "django") {
			return models.FrameworkDjango, models.ConfidenceMedium, []models.Evidence{evidence("framework_pattern", "django")}
		}
		if strings.Contains(text, "uvicorn") && strings.Contains(text, "fastapi") {
			return models.FrameworkFastAPI, models.ConfidenceHigh, []models.Evidence{evidence("framework_pattern", "uvicorn_fastapi")}
		}
		if strings.Contains(text, "uvicorn") {
			return models.FrameworkFastAPI, models.ConfidenceMedium, []models.Evidence{evidence("framework_pattern", "uvicorn")}
		}
		if containsAny(text, "flask run", " flask ") {
			return models.FrameworkFlask, models.ConfidenceMedium, []models.Evidence{evidence("framework_command", "flask")}
		}
	case models.RuntimePHP:
		if containsAny(text, "artisan serve", " artisan ") {
			return models.FrameworkLaravel, models.ConfidenceMedium, []models.Evidence{evidence("framework_command", "artisan")}
		}
	case models.RuntimeDotNet:
		if containsAny(text, "aspnetcore", "microsoft.aspnetcore", ".web.dll") {
			return models.FrameworkASPNETCore, models.ConfidenceMedium, []models.Evidence{evidence("framework_pattern", "aspnet_core")}
		}
	}

	return models.FrameworkUnknown, models.ConfidenceUnknown, nil
}

func normalizeName(name string) string {
	base := strings.ToLower(filepath.Base(name))
	return strings.TrimSuffix(base, ".exe")
}

func containsAny(s string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func candidateID(pid int64) string {
	return fmt.Sprintf("pid:%d", pid)
}

func evidence(kind, value string) models.Evidence {
	return models.Evidence{Kind: kind, Value: value}
}
