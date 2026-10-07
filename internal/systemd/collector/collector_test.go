package collector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	gops "github.com/shirou/gopsutil/v4/process"
)

func TestSystemdCollector_Success(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPathFmt = filepath.Join(tmpDir, "%d")

	// Fake cgroup for PID 100
	_ = os.WriteFile(filepath.Join(tmpDir, "100"), []byte("1:name=systemd:/system.slice/nginx.service\n"), 0644)
	// Fake cgroup for PID 200
	_ = os.WriteFile(filepath.Join(tmpDir, "200"), []byte("0::/system.slice/ssh.service\n"), 0644)
	// Fake cgroup for PID 300 (not a service)
	_ = os.WriteFile(filepath.Join(tmpDir, "300"), []byte("0::/system.slice/some.target\n"), 0644)

	c := NewSystemdCollectorWithLister(func(ctx context.Context) ([]*gops.Process, error) {
		return []*gops.Process{
			{Pid: 100},
			{Pid: 200},
			{Pid: 300},
		}, nil
	})

	payload := c.Collect(context.Background())
	if len(payload.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(payload.Services))
	}

	foundNginx := false
	for _, s := range payload.Services {
		if s.Name == "nginx.service" {
			foundNginx = true
		}
	}
	if !foundNginx {
		t.Errorf("expected nginx.service in results")
	}
}

func TestSystemdCollector_ListError(t *testing.T) {
	c := NewSystemdCollectorWithLister(func(ctx context.Context) ([]*gops.Process, error) {
		return nil, errors.New("list failed")
	})

	payload := c.Collect(context.Background())
	if len(payload.Services) != 0 {
		t.Fatalf("expected 0 services, got %d", len(payload.Services))
	}
}

func TestSystemdCollector_MaxCount(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPathFmt = filepath.Join(tmpDir, "%d")

	var mockProcs []*gops.Process
	for i := 0; i < MaxServiceCount+10; i++ {
		pid := int32(i + 1)
		mockProcs = append(mockProcs, &gops.Process{Pid: pid})
		_ = os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("%d", pid)), []byte(fmt.Sprintf("0::/system.slice/test-%d.service\n", pid)), 0644)
	}

	c := NewSystemdCollectorWithLister(func(ctx context.Context) ([]*gops.Process, error) {
		return mockProcs, nil
	})

	payload := c.Collect(context.Background())
	if len(payload.Services) != MaxServiceCount {
		t.Fatalf("expected %d services, got %d", MaxServiceCount, len(payload.Services))
	}
}

func TestSystemdCollector_Timeout(t *testing.T) {
	c := NewSystemdCollectorWithLister(func(ctx context.Context) ([]*gops.Process, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
			return nil, nil
		}
	})

	start := time.Now()
	payload := c.Collect(context.Background())
	duration := time.Since(start)

	if len(payload.Services) != 0 {
		t.Fatalf("expected 0 services due to timeout, got %d", len(payload.Services))
	}
	if duration >= 3*time.Second {
		t.Fatalf("timeout did not work properly, took %v", duration)
	}
}
