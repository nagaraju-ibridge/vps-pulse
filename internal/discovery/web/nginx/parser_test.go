package nginx

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNginxDiscovery(t *testing.T) {
	tempDir := t.TempDir()

	// 0. Deduplication test setup (two malformed files)
	os.MkdirAll(filepath.Join(tempDir, "dedup"), 0755)
	os.WriteFile(filepath.Join(tempDir, "dedup", "bad1.conf"), []byte(`server { listen 80 }`), 0644)
	os.WriteFile(filepath.Join(tempDir, "dedup", "bad2.conf"), []byte(`server { listen 81 }`), 0644)

	// 1. Basic server block, comments, ports, alias, location proxy
	mainConf := `
# Main Config
server {
    listen 80;
    listen 443 ssl;
    server_name example.com www.example.com;
    root /var/www/example;
    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}
# Escaping include
include ../../../../../passwd;
include conf.d/*.conf;
include dedup/*.conf;
`
	os.WriteFile(filepath.Join(tempDir, "nginx.conf"), []byte(mainConf), 0644)

	os.MkdirAll(filepath.Join(tempDir, "conf.d"), 0755)

	// 2. Default server block, FastCGI, Credentials strip
	conf1 := `
server {
    listen 80 default_server;
    server_name _;
    root /var/www/html;
}
server {
    listen [::]:8080;
    server_name creds.com;
    location / {
        proxy_pass http://user:pass@10.0.0.1:9090;
    }
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.1-fpm.sock;
    }
}
`
	os.WriteFile(filepath.Join(tempDir, "conf.d", "a.conf"), []byte(conf1), 0644)

	// 3. Duplicate server blocks for same domain
	conf2 := `
server {
    listen 80;
    server_name example.com;
    location /api {
        proxy_pass http://127.0.0.1:4000;
    }
}
`
	os.WriteFile(filepath.Join(tempDir, "conf.d", "b.conf"), []byte(conf2), 0644)

	// 4. Malformed syntax
	conf3 := `
server {
    listen 80
}
`
	os.WriteFile(filepath.Join(tempDir, "conf.d", "c.conf"), []byte(conf3), 0644)

	c := NewCollector(tempDir)
	websites, warnings := c.Collect(context.Background())

	// Verifications
	if len(websites) != 3 {
		t.Fatalf("expected 3 websites, got %d", len(websites))
	}

	var exampleWebsite, credsWebsite, defaultWebsite interface{}
	_ = exampleWebsite
	_ = credsWebsite
	_ = defaultWebsite

	foundExample := false
	foundCreds := false
	foundDefault := false

	for _, w := range websites {
		if w.Domains[0].Name == "example.com" {
			foundExample = true
			if len(w.Domains) != 2 || w.Domains[1].Name != "www.example.com" {
				t.Errorf("unexpected domains for example.com: %v", w.Domains)
			}
			if len(w.ListenPorts) != 2 || w.ListenPorts[0] != 80 || w.ListenPorts[1] != 443 {
				t.Errorf("unexpected ports for example.com: %v", w.ListenPorts)
			}
			if w.DocumentRoot != "/var/www/example" {
				t.Errorf("unexpected root: %s", w.DocumentRoot)
			}
			if len(w.ProxyPassTargets) != 2 {
				t.Errorf("expected 2 proxy targets for merged example.com, got %d", len(w.ProxyPassTargets))
			} else {
				if w.ProxyPassTargets[0] != "http://127.0.0.1:3000" && w.ProxyPassTargets[1] != "http://127.0.0.1:3000" {
					t.Errorf("missing target 3000")
				}
				if w.ProxyPassTargets[0] != "http://127.0.0.1:4000" && w.ProxyPassTargets[1] != "http://127.0.0.1:4000" {
					t.Errorf("missing target 4000")
				}
			}
			if string(w.Confidence) != "HIGH" {
				t.Errorf("expected HIGH confidence for example.com")
			}
		}

		if w.Domains[0].Name == "creds.com" {
			foundCreds = true
			if len(w.ListenPorts) != 1 || w.ListenPorts[0] != 8080 {
				t.Errorf("unexpected port for creds.com: %v", w.ListenPorts)
			}
			if len(w.ProxyPassTargets) != 1 || w.ProxyPassTargets[0] != "http://10.0.0.1:9090" {
				t.Errorf("expected stripped credentials proxy pass, got: %v", w.ProxyPassTargets)
			}
			if len(w.FpmSocketPaths) != 1 || w.FpmSocketPaths[0] != "unix:/run/php/php8.1-fpm.sock" {
				t.Errorf("unexpected fastcgi pass: %v", w.FpmSocketPaths)
			}
		}

		if w.Domains[0].Name == "_" {
			foundDefault = true
			if string(w.Confidence) != "LOW" {
				t.Errorf("expected LOW confidence for default server")
			}
		}
	}

	if !foundExample || !foundCreds || !foundDefault {
		t.Errorf("missing expected websites")
	}

	// Warnings check
	foundMalformedWarnCount := 0
	for _, w := range warnings {
		if strings.Contains(w, "nginx: malformed configuration missing semicolon") {
			foundMalformedWarnCount++
		}
	}
	if foundMalformedWarnCount != 1 {
		t.Errorf("expected exactly 1 categorical warning for multiple malformed configs, got %d", foundMalformedWarnCount)
	}
}
