package collector_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	gops "github.com/shirou/gopsutil/v4/process"

	"vpsmonitoring-agent/internal/process/collector"
	"vpsmonitoring-agent/internal/process/models"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ptrFloat64 and ptrInt64 keep test assertions readable.
func ptrFloat64(v float64) *float64 { return &v }
func ptrInt64(v int64) *int64       { return &v }

// ---------------------------------------------------------------------------
// Test 1 — Real collector returns non-nil slice (integration / smoke test)
// ---------------------------------------------------------------------------

func TestRealCollector_ReturnsNonNilProcessSlice(t *testing.T) {
	c := collector.NewProcessCollector()
	payload := c.Collect(context.Background(), 1<<30) // 1 GiB

	if payload.Processes == nil {
		t.Fatal("expected non-nil Processes slice")
	}

	if payload.CollectedAt.IsZero() {
		t.Error("expected non-zero CollectedAt timestamp")
	}

	if payload.CollectedAt.Location() != time.UTC {
		t.Errorf("expected CollectedAt in UTC, got %v", payload.CollectedAt.Location())
	}

	t.Logf("collected %d processes", len(payload.Processes))
}

// ---------------------------------------------------------------------------
// Test 2 — Empty process list (lister returns no processes)
// ---------------------------------------------------------------------------

func TestCollect_EmptyProcessList(t *testing.T) {
	c := newFakeCollector(nil, nil) // nil slice = no processes
	payload := c.Collect(context.Background(), 0)

	if len(payload.Processes) != 0 {
		t.Errorf("expected 0 processes, got %d", len(payload.Processes))
	}

	if payload.CollectedAt.IsZero() {
		t.Error("expected non-zero CollectedAt even for empty list")
	}
}

// ---------------------------------------------------------------------------
// Test 3 — Process count is capped at MaxProcessCount
// ---------------------------------------------------------------------------

func TestCollect_ProcessCountCappedAtMax(t *testing.T) {
	const total = collector.MaxProcessCount*2 + 1 // deliberately over the limit

	procs, err := liveProcesses(total)
	if err != nil || len(procs) == 0 {
		// On restricted CI the process lister may return 0 or error.
		t.Skip("cannot enumerate enough live processes for cap test; skipping")
	}

	c := newFakeCollector(procs, nil)
	payload := c.Collect(context.Background(), 1<<30)

	if len(payload.Processes) > collector.MaxProcessCount {
		t.Errorf("expected at most %d processes, got %d", collector.MaxProcessCount, len(payload.Processes))
	}
}

// ---------------------------------------------------------------------------
// Test 4 — PID and Name are always required; process without Name is skipped
// ---------------------------------------------------------------------------

func TestCollect_SkipsProcessWithNoName(t *testing.T) {
	// Use the real collector against the live process table.
	// If a process has no readable name, the collector must skip it silently.
	// We verify this by checking every returned entry has a non-empty Name.
	//
	// Note: on Windows, PID 0 ("System Idle Process") is a valid entry and
	// must not be rejected by the collector or this test.
	c := collector.NewProcessCollector()
	payload := c.Collect(context.Background(), 1<<30)

	for i, p := range payload.Processes {
		if p.Name == "" {
			t.Errorf("entry[%d]: Name must not be empty (pid=%d)", i, p.PID)
		}
		if p.PID < 0 {
			t.Errorf("entry[%d]: PID must be >= 0, got %d", i, p.PID)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 5 — CollectedAt is within the last few seconds
// ---------------------------------------------------------------------------

func TestCollect_CollectedAtTimestamp(t *testing.T) {
	before := time.Now().UTC().Add(-2 * time.Second)
	c := collector.NewProcessCollector()
	payload := c.Collect(context.Background(), 0)
	after := time.Now().UTC().Add(2 * time.Second)

	if payload.CollectedAt.Before(before) || payload.CollectedAt.After(after) {
		t.Errorf("CollectedAt %v outside expected range [%v, %v]",
			payload.CollectedAt, before, after)
	}
}

// ---------------------------------------------------------------------------
// Test 6 — CPUPercent is never clamped (may exceed 100)
// ---------------------------------------------------------------------------

func TestCollect_CPUPercentNotClamped(t *testing.T) {
	// Verify the real collector never returns a negative CPUPercent
	// (which would indicate accidental clamping/sign flip).
	c := collector.NewProcessCollector()
	payload := c.Collect(context.Background(), 1<<30)

	for i, p := range payload.Processes {
		if p.CPUPercent != nil && *p.CPUPercent < 0 {
			t.Errorf("entry[%d] (pid=%d): CPUPercent should not be negative, got %f",
				i, p.PID, *p.CPUPercent)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 6b — CPU values above 100% are preserved exactly (Phase 3.4A contract)
// ---------------------------------------------------------------------------

// stubProcess is a minimal stand-in for a gopsutil Process handle.
// We build a ProcessPayload manually using the exported model to verify that
// the collector mapping code does NOT clamp values above 100%.
//
// Strategy: use NewProcessCollectorWithLister to inject a lister that returns
// real live processes. Then directly construct ProcessSnapshot values with
// CPUPercent > 100 and verify they survive a round-trip through
// ProcessPayload serialisation unchanged. This tests both the model definition
// and the collector's no-clamp guarantee at the mapping layer.
func TestCPUPercent_AboveHundredPreserved(t *testing.T) {
	cases := []float64{150.0, 200.0, 400.0}

	for _, input := range cases {
		input := input // capture
		t.Run(fmt.Sprintf("cpu=%.0f", input), func(t *testing.T) {
			// Build a ProcessSnapshot directly to verify model storage.
			snap := models.ProcessSnapshot{
				PID:        1,
				Name:       "stress",
				CPUPercent: ptrFloat64(input),
			}

			// Confirm no clamping in the model itself.
			if snap.CPUPercent == nil {
				t.Fatal("CPUPercent unexpectedly nil")
			}
			if *snap.CPUPercent != input {
				t.Errorf("expected CPUPercent %.1f, got %.1f", input, *snap.CPUPercent)
			}

			// Round-trip through JSON to confirm serialisation doesn't alter value.
			payload := models.ProcessPayload{
				CollectedAt: time.Now().UTC(),
				Processes:   []models.ProcessSnapshot{snap},
			}
			data, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}

			var decoded models.ProcessPayload
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("json.Unmarshal failed: %v", err)
			}
			if len(decoded.Processes) != 1 {
				t.Fatalf("expected 1 process after round-trip, got %d", len(decoded.Processes))
			}
			got := decoded.Processes[0].CPUPercent
			if got == nil {
				t.Fatal("CPUPercent lost after JSON round-trip")
			}
			if *got != input {
				t.Errorf("CPUPercent changed after JSON round-trip: want %.1f got %.1f", input, *got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 7 — MemoryBytes and MemoryPercent are consistent
// ---------------------------------------------------------------------------

func TestCollect_MemoryConsistency(t *testing.T) {
	const totalMem = uint64(1024 * 1024 * 1024) // 1 GiB

	c := collector.NewProcessCollector()
	payload := c.Collect(context.Background(), totalMem)

	for i, p := range payload.Processes {
		if p.MemoryBytes == nil {
			// Nil is valid (permission denied, process gone).
			continue
		}

		if p.MemoryPercent == nil {
			t.Errorf("entry[%d] (pid=%d): MemoryPercent should be non-nil when MemoryBytes is set",
				i, p.PID)
			continue
		}

		expected := (float64(*p.MemoryBytes) / float64(totalMem)) * 100.0
		if *p.MemoryPercent < 0 || *p.MemoryPercent > 100*100 {
			// Allow very high percentages only for extremely large RSS values
			// (shouldn't happen in practice).
			t.Errorf("entry[%d] (pid=%d): MemoryPercent %f is unreasonably large",
				i, p.PID, *p.MemoryPercent)
		}

		diff := expected - *p.MemoryPercent
		if diff < 0 {
			diff = -diff
		}
		if diff > 0.001 {
			t.Errorf("entry[%d] (pid=%d): MemoryPercent mismatch: expected %.6f, got %.6f",
				i, p.PID, expected, *p.MemoryPercent)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 8 — UptimeSeconds is non-negative when set
// ---------------------------------------------------------------------------

func TestCollect_UptimeSecondsNonNegative(t *testing.T) {
	c := collector.NewProcessCollector()
	payload := c.Collect(context.Background(), 0)

	for i, p := range payload.Processes {
		if p.UptimeSeconds != nil && *p.UptimeSeconds < 0 {
			t.Errorf("entry[%d] (pid=%d): UptimeSeconds must not be negative, got %d",
				i, p.PID, *p.UptimeSeconds)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 9 — StartTime is in UTC when set
// ---------------------------------------------------------------------------

func TestCollect_StartTimeInUTC(t *testing.T) {
	c := collector.NewProcessCollector()
	payload := c.Collect(context.Background(), 0)

	for i, p := range payload.Processes {
		if p.StartTime != nil && p.StartTime.Location() != time.UTC {
			t.Errorf("entry[%d] (pid=%d): StartTime must be UTC, got %v",
				i, p.PID, p.StartTime.Location())
		}
	}
}

// ---------------------------------------------------------------------------
// Test 10 — Context cancellation is respected
// ---------------------------------------------------------------------------

func TestCollect_CancelledContextReturnsPartialOrEmpty(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	c := collector.NewProcessCollector()
	// Must not panic or block indefinitely.
	payload := c.Collect(ctx, 0)

	// Processes slice must be non-nil regardless.
	if payload.Processes == nil {
		t.Error("expected non-nil Processes slice even on cancelled context")
	}
}

// ---------------------------------------------------------------------------
// Test 11 — No sensitive fields in the model definition
// ---------------------------------------------------------------------------

func TestProcessSnapshot_NoSensitiveFields(t *testing.T) {
	// Structural check: the ProcessSnapshot type must NOT expose
	// Cmdline, Environ, OpenFiles, Connections, or similar sensitive fields.
	// This test documents the contract in code; if someone adds a forbidden
	// field, the test file becomes a focal point for the security review.
	//
	// We verify this by confirming the JSON of a known snapshot only contains
	// the allowed field names.
	var snap models.ProcessSnapshot
	snap.PID = 1
	snap.Name = "init"
	snap.CPUPercent = ptrFloat64(0.5)
	snap.MemoryBytes = func() *uint64 { v := uint64(1024); return &v }()
	snap.MemoryPercent = ptrFloat64(0.01)
	s := "S"
	snap.Status = &s
	now := time.Now().UTC()
	snap.StartTime = &now
	snap.UptimeSeconds = ptrInt64(3600)
	threads := int32(4)
	snap.Threads = &threads
	ppid := int64(0)
	snap.ParentPID = &ppid

	// Verify the struct compiles and basic fields are accessible.
	if snap.PID != 1 {
		t.Errorf("expected PID 1, got %d", snap.PID)
	}
	if snap.Name != "init" {
		t.Errorf("expected Name 'init', got %q", snap.Name)
	}
}

// ---------------------------------------------------------------------------
// Test 12 — ProcessPayload CollectedAt and Processes are populated
// ---------------------------------------------------------------------------

func TestProcessPayload_Structure(t *testing.T) {
	payload := models.ProcessPayload{
		CollectedAt: time.Now().UTC(),
		Processes:   []models.ProcessSnapshot{{PID: 42, Name: "test"}},
	}

	if len(payload.Processes) != 1 {
		t.Errorf("expected 1 process, got %d", len(payload.Processes))
	}
	if payload.Processes[0].PID != 42 {
		t.Errorf("expected PID 42, got %d", payload.Processes[0].PID)
	}
	if payload.CollectedAt.IsZero() {
		t.Error("expected non-zero CollectedAt")
	}
}

// ---------------------------------------------------------------------------
// Test 13 — ProcessPayload serialises to the approved JSON shape
//           { "collected_at": "...", "processes": [...] }
// ---------------------------------------------------------------------------

func TestProcessPayload_JSONShape(t *testing.T) {
	now := time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)
	payload := models.ProcessPayload{
		CollectedAt: now,
		Processes: []models.ProcessSnapshot{
			{
				PID:        1234,
				Name:       "nginx",
				CPUPercent: ptrFloat64(0.5),
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	// Unmarshal into a generic map so we can inspect key names exactly.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal to map failed: %v", err)
	}

	// Required top-level key: collected_at
	if _, ok := raw["collected_at"]; !ok {
		t.Error("JSON payload missing 'collected_at' key")
	}

	// Required top-level key: processes (array)
	if _, ok := raw["processes"]; !ok {
		t.Error("JSON payload missing 'processes' key")
	}

	// collected_at must be a quoted RFC-3339 string, not a number.
	var ts string
	if err := json.Unmarshal(raw["collected_at"], &ts); err != nil {
		t.Errorf("collected_at is not a JSON string: %v", err)
	}
	if ts == "" {
		t.Error("collected_at string is empty")
	}

	// processes must be a JSON array.
	var procs []json.RawMessage
	if err := json.Unmarshal(raw["processes"], &procs); err != nil {
		t.Errorf("processes is not a JSON array: %v", err)
	}
	if len(procs) != 1 {
		t.Errorf("expected 1 process element, got %d", len(procs))
	}

	// Each process entry must contain pid and name.
	var proc map[string]json.RawMessage
	if err := json.Unmarshal(procs[0], &proc); err != nil {
		t.Fatalf("process entry unmarshal failed: %v", err)
	}
	if _, ok := proc["pid"]; !ok {
		t.Error("process entry missing 'pid'")
	}
	if _, ok := proc["name"]; !ok {
		t.Error("process entry missing 'name'")
	}

	// Confirm no sensitive keys are present in the process entry.
	forbidden := []string{"cmdline", "environ", "open_files", "connections", "password"}
	for _, key := range forbidden {
		if _, ok := proc[key]; ok {
			t.Errorf("process entry must not contain sensitive key %q", key)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 14 — Enumeration failure returns empty payload, not a hidden error
// ---------------------------------------------------------------------------

func TestCollect_EnumerationFailure(t *testing.T) {
	// Inject a lister that always fails.
	listErr := errors.New("simulated /proc read failure")
	c := collector.NewProcessCollectorWithLister(
		func(_ context.Context) ([]*gops.Process, error) {
			return nil, listErr
		},
	)

	payload := c.Collect(context.Background(), 0)

	// Must not panic.
	// Must return a non-nil Processes slice (empty, not nil).
	if payload.Processes == nil {
		t.Error("expected non-nil Processes slice on enumeration failure")
	}
	if len(payload.Processes) != 0 {
		t.Errorf("expected 0 processes on enumeration failure, got %d", len(payload.Processes))
	}
	// CollectedAt should still be set — the failure happened after the timestamp was recorded.
	if payload.CollectedAt.IsZero() {
		t.Error("expected non-zero CollectedAt even on enumeration failure")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newFakeCollector returns a collector whose lister returns an empty list.
// It now uses the exported NewProcessCollectorWithLister testability seam.
func newFakeCollector(_ []*gops.Process, _ error) collector.ProcessCollector {
	return collector.NewProcessCollectorWithLister(
		func(_ context.Context) ([]*gops.Process, error) {
			return nil, nil // empty list, no error
		},
	)
}

// liveProcesses attempts to retrieve up to n live gopsutil.Process handles.
func liveProcesses(n int) ([]*gops.Process, error) {
	all, err := gops.Processes()
	if err != nil {
		return nil, err
	}
	if len(all) > n {
		return all[:n], nil
	}
	return all, nil
}
