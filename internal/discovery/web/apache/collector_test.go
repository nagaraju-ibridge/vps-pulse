package apache

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestApacheCollector(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "apache_col_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	confDir := filepath.Join(tempDir, "conf")
	os.Mkdir(confDir, 0755)

	mainConf := `
<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
</VirtualHost>

<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/example
</VirtualHost>

<VirtualHost *:80>
    ServerName _
</VirtualHost>
`
	os.WriteFile(filepath.Join(confDir, "httpd.conf"), []byte(mainConf), 0644)

	col := NewCollector([]string{tempDir})
	res, _ := col.Collect(context.Background())

	if len(res) == 0 {
		t.Fatal("expected results, got 0")
	}

	// Find example.com
	var found bool
	for _, c := range res {
		if len(c.Domains) > 0 && c.Domains[0].Name == "example.com" {
			found = true
			if c.DocumentRoot != "/var/www/example" {
				t.Errorf("TEST 10/11 failed, expected merged DocumentRoot /var/www/example")
			}
			if len(c.Domains) < 2 || c.Domains[1].Name != "www.example.com" {
				t.Errorf("expected merged alias www.example.com")
			}
		}
	}
	if !found {
		t.Errorf("expected example.com in results")
	}
}
