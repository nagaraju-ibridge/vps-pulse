package apache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApacheParser(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "apache_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	confDir := filepath.Join(tempDir, "conf.d")
	os.Mkdir(confDir, 0755)

	// TEST 1: Basic VirtualHost
	// TEST 2: ServerAlias
	// TEST 3: HTTPS VirtualHost
	// TEST 4: ProxyPass
	// TEST 9: Catch-all
	// TEST 12: Credential-bearing proxy URL
	mainConf := `
<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /var/www/example
</VirtualHost>

<VirtualHost *:443>
    ServerName secure.example.com
    DocumentRoot /var/www/secure
</VirtualHost>

<VirtualHost *:80>
    ServerName app.example.com
    ProxyPass / http://127.0.0.1:3000/
</VirtualHost>

<VirtualHost *:80>
    ServerName _
    DocumentRoot /var/www/html
</VirtualHost>

<VirtualHost *:80>
    ServerName creds.example.com
    ProxyPass / http://user:password@127.0.0.1:3000/
</VirtualHost>

# TEST 5: Include
Include conf.d/inc1.conf
# TEST 6: IncludeOptional missing file
IncludeOptional conf.d/missing.conf
# TEST 7: Path traversal
Include ../outside.conf

# TEST 8: Malformed configuration
<VirtualHost *:80>
    ServerName broken.example.com
`

	os.WriteFile(filepath.Join(tempDir, "httpd.conf"), []byte(mainConf), 0644)
	os.WriteFile(filepath.Join(confDir, "inc1.conf"), []byte(`
<VirtualHost *:80>
    ServerName included.example.com
</VirtualHost>
	`), 0644)

	os.WriteFile(filepath.Join(tempDir, "..", "outside.conf"), []byte(`
<VirtualHost *:80>
    ServerName outside.example.com
</VirtualHost>
	`), 0644)

	var warnings []string
	parser := NewParser(tempDir, &warnings)
	blocks := parser.ParseMain(filepath.Join(tempDir, "httpd.conf"))

	// Find block by ServerName
	findBlock := func(name string) *ServerBlock {
		for _, b := range blocks {
			for _, sn := range b.ServerNames {
				if sn == name {
					return b
				}
			}
		}
		return nil
	}

	b1 := findBlock("example.com")
	if b1 == nil || b1.Root != "/var/www/example" {
		t.Errorf("TEST 1 failed, expected example.com with /var/www/example")
	}
	if b1 != nil && (len(b1.ServerNames) < 2 || b1.ServerNames[1] != "www.example.com") {
		t.Errorf("TEST 2 failed, expected ServerAlias www.example.com")
	}

	b3 := findBlock("secure.example.com")
	if b3 == nil || b3.Root != "/var/www/secure" {
		t.Errorf("TEST 3 failed, expected secure.example.com")
	}

	b4 := findBlock("app.example.com")
	if b4 == nil || len(b4.ProxyPass) == 0 || b4.ProxyPass[0] != "http://127.0.0.1:3000/" {
		t.Errorf("TEST 4 failed, expected app.example.com with ProxyPass")
	}

	b5 := findBlock("included.example.com")
	if b5 == nil {
		t.Errorf("TEST 5 failed, expected included.example.com from Include")
	}

	b9 := findBlock("_")
	if b9 == nil {
		t.Errorf("TEST 9 failed, expected _ block to be parsed")
	}

	b12 := findBlock("creds.example.com")
	if b12 == nil || len(b12.ProxyPass) == 0 || strings.Contains(b12.ProxyPass[0], "password") {
		t.Errorf("TEST 12 failed, expected creds redacted. Got: %v", b12.ProxyPass)
	}

	// Verify warnings
	warningsStr := strings.Join(warnings, " ")
	if !strings.Contains(warningsStr, "rejected include path") && !strings.Contains(warningsStr, "permission denied") && !strings.Contains(warningsStr, "invalid include pattern") {
		t.Errorf("TEST 7 failed, expected warning for path traversal. Got: %s", warningsStr)
	}
}
