package collector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFallbackTCPListeners(t *testing.T) {
	tempDir := t.TempDir()

	// Override procRoot for this test
	originalProcRoot := procRoot
	procRoot = tempDir
	defer func() { procRoot = originalProcRoot }()

	netDir := filepath.Join(tempDir, "net")
	if err := os.MkdirAll(netDir, 0755); err != nil {
		t.Fatalf("Failed to create temp net dir: %v", err)
	}

	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:2382 00000000:0000 0A 00000000:00000000 00:00000000 00000000   100        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 67890 1 0000000000000000 100 0 0 10 0
   2: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99999 1 0000000000000000 100 0 0 10 0
   3: 00000000:270F 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 77777 1 0000000000000000 100 0 0 10 0
   4: 00000000:2710 00000000:0000 0A 00000000:00000000 00:00000000 00000000   888        0 88888 1 0000000000000000 100 0 0 10 0
`
	tcp6Content := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:2382 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   100        0 12346 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   100        0 54321 1 0000000000000000 100 0 0 10 0
`

	os.WriteFile(filepath.Join(netDir, "tcp"), []byte(tcpContent), 0644)
	os.WriteFile(filepath.Join(netDir, "tcp6"), []byte(tcp6Content), 0644)

	pids := []int64{1000, 1001, 2000, 3000, 4000, 5000, 6000, 6001}

	// Create UID status files
	createStatus := func(pid, uid string) {
		dir := filepath.Join(tempDir, pid)
		os.MkdirAll(dir, 0755)
		content := "Name:\ttest\nUid:\t" + uid + "\t" + uid + "\t" + uid + "\t" + uid + "\n"
		os.WriteFile(filepath.Join(dir, "status"), []byte(content), 0644)
	}

	createStatus("1000", "100")
	createStatus("1001", "100")
	createStatus("2000", "101")
	createStatus("3000", "500")
	createStatus("4000", "100")
	createStatus("5000", "999") // Unique UID match testing fallback
	createStatus("6000", "888") // Ambiguous UID match testing fallback (two PIDs with same UID)
	createStatus("6001", "888")

	// Create FD dirs for those we have permission to read
	for _, pid := range []string{"1000", "1001", "2000", "4000"} {
		fdDir := filepath.Join(tempDir, pid, "fd")
		os.MkdirAll(fdDir, 0755)
	}

	// 5000, 6000, 6001 will NOT have fd directory created, simulating Permission Denied

	// Create symlinks
	createSymlink := func(target, link string) {
		err := os.Symlink(target, link)
		if err != nil {
			t.Skipf("Symlinks not supported in this test environment: %v", err)
		}
	}

	createSymlink("socket:[12345]", filepath.Join(tempDir, "1000", "fd", "3"))
	createSymlink("socket:[12346]", filepath.Join(tempDir, "1001", "fd", "3"))
	createSymlink("socket:[67890]", filepath.Join(tempDir, "2000", "fd", "3"))
	createSymlink("socket:[54321]", filepath.Join(tempDir, "4000", "fd", "3"))

	// Test the fallback parser
	listeners, err := fallbackTCPListeners(pids)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify deduplication and PID resolution
	if len(listeners) != 6 {
		t.Fatalf("Expected 6 listeners, got %d", len(listeners))
	}

	var found9090, found9999, found10000 bool
	for _, l := range listeners {
		if l.LocalPort == 9090 {
			found9090 = true
			if l.PID == nil {
				t.Errorf("Expected PID for port 9090, got nil")
			} else if *l.PID != 1001 { // tcp6 [::]:9090 is returned because [::] covers 0.0.0.0, so the IPv6 listener is the deduplicated one
				t.Errorf("Expected PID 1001 for port 9090 IPv6, got %d", *l.PID)
			}
		}
		if l.LocalPort == 8080 {
			if l.PID == nil || *l.PID != 2000 {
				t.Errorf("Expected PID 2000 for port 8080, got %v", l.PID)
			}
		}
		if l.LocalPort == 80 {
			if l.PID == nil || *l.PID != 4000 {
				t.Errorf("Expected PID 4000 for port 80, got %v", l.PID)
			}
		}
		if l.LocalPort == 22 {
			if l.PID != nil {
				t.Errorf("Expected nil PID for port 22, got %d", *l.PID)
			}
		}
		if l.LocalPort == 9999 {
			found9999 = true
			if l.PID == nil || *l.PID != 5000 {
				t.Errorf("Expected PID 5000 (via UID fallback) for port 9999, got %v", l.PID)
			}
		}
		if l.LocalPort == 10000 {
			found10000 = true
			if l.PID != nil {
				t.Errorf("Expected nil PID for port 10000 due to ambiguous UID fallback, got %v", *l.PID)
			}
		}
	}

	if !found9090 {
		t.Errorf("Did not find port 9090")
	}
	if !found9999 {
		t.Errorf("Did not find port 9999")
	}
	if !found10000 {
		t.Errorf("Did not find port 10000")
	}
}
