package collector

import (
	"testing"

	"vpsmonitoring-agent/internal/discovery/models"
)

func TestClassifyRuntimeCandidates(t *testing.T) {
	tests := []struct {
		name       string
		process    models.ProcessMetadata
		runtime    models.Runtime
		confidence models.Confidence
	}{
		{"java", proc("java", "java -jar app.jar"), models.RuntimeJava, models.ConfidenceHigh},
		{"node", proc("node", "node server.js"), models.RuntimeNodeJS, models.ConfidenceHigh},
		{"python", proc("python3", "python3 app.py"), models.RuntimePython, models.ConfidenceHigh},
		{"php fpm", proc("php-fpm8.2", "php-fpm: pool www"), models.RuntimePHP, models.ConfidenceHigh},
		{"dotnet", proc("dotnet", "dotnet MyApp.dll"), models.RuntimeDotNet, models.ConfidenceHigh},
		{"go run", proc("go", "go run ./cmd/server"), models.RuntimeGo, models.ConfidenceMedium},
		{"unknown", proc("custom-app", "custom-app --serve"), models.RuntimeUnknown, models.ConfidenceUnknown},
	}

	classifier := NewClassifier()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifier.ClassifyProcess(tt.process)
			if tt.runtime == models.RuntimeUnknown {
				if len(got.Applications) != 0 {
					t.Fatalf("expected no application candidate, got %+v", got.Applications)
				}
				return
			}
			if len(got.Applications) != 1 {
				t.Fatalf("expected one application candidate, got %d", len(got.Applications))
			}
			app := got.Applications[0]
			if app.Runtime != tt.runtime {
				t.Fatalf("expected runtime %s, got %s", tt.runtime, app.Runtime)
			}
			if app.RuntimeConfidence != tt.confidence {
				t.Fatalf("expected confidence %s, got %s", tt.confidence, app.RuntimeConfidence)
			}
			if len(app.Evidence) == 0 {
				t.Fatal("expected evidence")
			}
		})
	}
}

func TestClassifyInfrastructureServices(t *testing.T) {
	tests := []struct {
		name       string
		process    models.ProcessMetadata
		kind       models.ServiceKind
		confidence models.Confidence
	}{
		{"nginx", proc("nginx", "nginx: master process"), models.ServiceNginx, models.ConfidenceHigh},
		{"apache", proc("apache2", "/usr/sbin/apache2 -k start"), models.ServiceApache, models.ConfidenceHigh},
		{"httpd", proc("httpd", "/usr/sbin/httpd -DFOREGROUND"), models.ServiceApache, models.ConfidenceHigh},
		{"caddy", proc("caddy", "caddy run"), models.ServiceCaddy, models.ConfidenceHigh},
		{"postgres", proc("postgres", "postgres -D /var/lib/postgresql/data"), models.ServicePostgreSQL, models.ConfidenceHigh},
		{"mysql", proc("mysqld", "mysqld"), models.ServiceMySQL, models.ConfidenceHigh},
		{"mariadb", proc("mariadbd", "mariadbd"), models.ServiceMariaDB, models.ConfidenceHigh},
		{"mongodb", proc("mongod", "mongod --config REDACTED"), models.ServiceMongoDB, models.ConfidenceHigh},
		{"redis", proc("redis-server", "redis-server 127.0.0.1:6379"), models.ServiceRedis, models.ConfidenceHigh},
	}

	classifier := NewClassifier()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifier.ClassifyProcess(tt.process)
			if len(got.Services) != 1 {
				t.Fatalf("expected one service candidate, got %d", len(got.Services))
			}
			service := got.Services[0]
			if service.Kind != tt.kind {
				t.Fatalf("expected service %s, got %s", tt.kind, service.Kind)
			}
			if service.Confidence != tt.confidence {
				t.Fatalf("expected confidence %s, got %s", tt.confidence, service.Confidence)
			}
			if len(service.Evidence) == 0 {
				t.Fatal("expected evidence")
			}
		})
	}
}

func TestClassifyFrameworkCandidates(t *testing.T) {
	tests := []struct {
		name       string
		process    models.ProcessMetadata
		framework  models.Framework
		confidence models.Confidence
	}{
		{
			name:       "spring boot strong",
			process:    proc("java", "java org.springframework.boot.loader.JarLauncher"),
			framework:  models.FrameworkSpringBoot,
			confidence: models.ConfidenceHigh,
		},
		{
			name:       "spring boot medium jar",
			process:    proc("java", "java -jar billing-spring-boot.jar"),
			framework:  models.FrameworkSpringBoot,
			confidence: models.ConfidenceMedium,
		},
		{
			name:       "nextjs strong",
			process:    proc("node", "node node_modules/.bin/next start"),
			framework:  models.FrameworkNextJS,
			confidence: models.ConfidenceHigh,
		},
		{
			name:       "django strong",
			process:    proc("gunicorn", "gunicorn mysite.wsgi:application"),
			framework:  models.FrameworkDjango,
			confidence: models.ConfidenceHigh,
		},
		{
			name:       "fastapi strong",
			process:    proc("uvicorn", "uvicorn fastapi_app.main:app"),
			framework:  models.FrameworkFastAPI,
			confidence: models.ConfidenceHigh,
		},
		{
			name:       "flask medium",
			process:    proc("python", "python -m flask run"),
			framework:  models.FrameworkFlask,
			confidence: models.ConfidenceMedium,
		},
		{
			name:       "laravel medium",
			process:    proc("php", "php artisan serve"),
			framework:  models.FrameworkLaravel,
			confidence: models.ConfidenceMedium,
		},
		{
			name:       "aspnet core medium",
			process:    proc("dotnet", "dotnet Orders.Web.dll"),
			framework:  models.FrameworkASPNETCore,
			confidence: models.ConfidenceMedium,
		},
		{
			name:       "express explicit",
			process:    proc("node", "node express-server.js"),
			framework:  models.FrameworkExpress,
			confidence: models.ConfidenceLow,
		},
		{
			name:       "nestjs explicit",
			process:    proc("node", "node dist/nestjs/main.js"),
			framework:  models.FrameworkNestJS,
			confidence: models.ConfidenceMedium,
		},
	}

	classifier := NewClassifier()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifier.ClassifyProcess(tt.process)
			if len(got.Applications) != 1 {
				t.Fatalf("expected one application candidate, got %d", len(got.Applications))
			}
			app := got.Applications[0]
			if app.Framework != tt.framework {
				t.Fatalf("expected framework %s, got %s", tt.framework, app.Framework)
			}
			if app.FrameworkConfidence != tt.confidence {
				t.Fatalf("expected confidence %s, got %s", tt.confidence, app.FrameworkConfidence)
			}
			if len(app.Evidence) == 0 {
				t.Fatal("expected evidence")
			}
		})
	}
}

func TestClassifierDoesNotInferFrameworksFromRuntimeAlone(t *testing.T) {
	tests := []struct {
		name    string
		process models.ProcessMetadata
	}{
		{"java not spring", proc("java", "java -jar app.jar")},
		{"node not next", proc("node", "node server.js")},
		{"python not django fastapi", proc("python3", "python3 worker.py")},
		{"php fpm not laravel wordpress", proc("php-fpm", "php-fpm: pool www")},
		{"dotnet not aspnet", proc("dotnet", "dotnet Worker.dll")},
	}

	classifier := NewClassifier()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifier.ClassifyProcess(tt.process)
			if len(got.Applications) != 1 {
				t.Fatalf("expected one runtime application candidate, got %d", len(got.Applications))
			}
			app := got.Applications[0]
			if app.Framework != models.FrameworkUnknown {
				t.Fatalf("expected unknown framework, got %s", app.Framework)
			}
			if app.FrameworkConfidence != models.ConfidenceUnknown {
				t.Fatalf("expected unknown framework confidence, got %s", app.FrameworkConfidence)
			}
		})
	}
}

func TestArbitraryBinaryDoesNotBecomeGo(t *testing.T) {
	classifier := NewClassifier()
	got := classifier.ClassifyProcess(proc("api-server", "/opt/apps/api-server --listen :8080"))
	if len(got.Applications) != 0 {
		t.Fatalf("expected arbitrary binary not to become an application runtime candidate, got %+v", got.Applications)
	}
}

func TestClassifierCopiesSafeMetadata(t *testing.T) {
	parentPID := int64(1)
	process := models.ProcessMetadata{
		PID:             1234,
		ParentPID:       &parentPID,
		Name:            "node",
		ExePath:         "/usr/bin/node",
		CmdlineRedacted: "node server.js --token REDACTED",
		User:            "appuser",
		SystemdUnit:     "app.service",
		Listeners: []models.Listener{{
			Protocol:     "tcp",
			LocalAddress: "127.0.0.1",
			LocalPort:    3000,
			Scope:        models.PortScopeLoopback,
		}},
	}

	got := NewClassifier().ClassifyProcess(process)
	if len(got.Applications) != 1 {
		t.Fatalf("expected application candidate, got %d", len(got.Applications))
	}
	app := got.Applications[0]
	if app.ID != "pid:1234" {
		t.Fatalf("expected pid candidate id, got %s", app.ID)
	}
	if app.Process.CmdlineRedacted != process.CmdlineRedacted {
		t.Fatal("expected redacted command line to be copied without raw command collection")
	}
	if len(app.Ports) != 1 || app.Ports[0].LocalPort != 3000 {
		t.Fatalf("expected listener metadata to be copied, got %+v", app.Ports)
	}
	if app.SystemdUnit != "app.service" {
		t.Fatalf("expected systemd unit to be copied, got %s", app.SystemdUnit)
	}
}

func proc(name, cmd string) models.ProcessMetadata {
	return models.ProcessMetadata{
		PID:             100,
		Name:            name,
		CmdlineRedacted: cmd,
	}
}
