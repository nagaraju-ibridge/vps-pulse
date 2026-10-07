package matcher

import (
	"context"
	"testing"
	"time"

	"vpsmonitoring-agent/internal/application/config"
)

func TestMatcher(t *testing.T) {
	now := time.Now()

	fakeIdx := processIndex{
		byExe: map[string][]ProcessMatchEvidence{
			"/usr/bin/nginx": {{PID: 100, ExePath: "/usr/bin/nginx", StartTime: &now}},
			"/usr/bin/node":  {{PID: 200, ExePath: "/usr/bin/node", StartTime: &now}, {PID: 201, ExePath: "/usr/bin/node", StartTime: &now}},
		},
		byUnit: map[string][]ProcessMatchEvidence{
			"nginx.service": {{PID: 100, ExePath: "/usr/bin/nginx", StartTime: &now}},
			"node.service":  {{PID: 200, ExePath: "/usr/bin/node", StartTime: &now}, {PID: 201, ExePath: "/usr/bin/node", StartTime: &now}},
		},
		unknown: false,
	}

	m := NewMatcher()
	m.IndexBuilder = func(ctx context.Context) processIndex {
		return fakeIdx
	}

	configs := []config.ApplicationConfig{
		{ID: 1, Name: "Nginx", MatchType: "systemd_unit", MatchValue: "nginx.service", IsEnabled: true},
		{ID: 2, Name: "MissingUnit", MatchType: "systemd_unit", MatchValue: "missing.service", IsEnabled: true},
		{ID: 3, Name: "NodeApp", MatchType: "exe_path", MatchValue: "/usr/bin/node", IsEnabled: true},
		{ID: 4, Name: "MissingApp", MatchType: "exe_path", MatchValue: "/usr/bin/missing", IsEnabled: true},
		{ID: 5, Name: "DisabledApp", MatchType: "exe_path", MatchValue: "/usr/bin/node", IsEnabled: false},
		{ID: 6, Name: "EmptyValue", MatchType: "exe_path", MatchValue: "", IsEnabled: true},
		{ID: 7, Name: "UnknownType", MatchType: "invalid", MatchValue: "val", IsEnabled: true},
	}

	results := m.Match(context.Background(), configs)

	// Filter active ones
	if len(results) != 6 { // DisabledApp is skipped
		t.Fatalf("expected 6 results, got %d", len(results))
	}

	for _, r := range results {
		switch r.ApplicationID {
		case 1:
			if r.State != StateMatched || len(r.Processes) != 1 {
				t.Errorf("expected Nginx to match 1 process, got state %s and %d procs", r.State, len(r.Processes))
			}
		case 2:
			if r.State != StateNotMatched {
				t.Errorf("expected MissingUnit to not match, got %s", r.State)
			}
		case 3:
			if r.State != StateMatched || len(r.Processes) != 2 {
				t.Errorf("expected NodeApp to match 2 processes, got state %s and %d procs", r.State, len(r.Processes))
			}
		case 4:
			if r.State != StateNotMatched {
				t.Errorf("expected MissingApp to not match, got %s", r.State)
			}
		case 6:
			if r.State != StateUnknown {
				t.Errorf("expected EmptyValue to be UNKNOWN, got %s", r.State)
			}
		case 7:
			if r.State != StateUnknown {
				t.Errorf("expected UnknownType to be UNKNOWN, got %s", r.State)
			}
		}
	}
}

func TestMatcher_PermissionHandling(t *testing.T) {
	// If permissions were insufficient during enumeration, missing units return UNKNOWN instead of NOT_MATCHED.
	fakeIdx := processIndex{
		byExe:   map[string][]ProcessMatchEvidence{},
		byUnit:  map[string][]ProcessMatchEvidence{},
		unknown: true,
	}

	m := NewMatcher()
	m.IndexBuilder = func(ctx context.Context) processIndex {
		return fakeIdx
	}

	configs := []config.ApplicationConfig{
		{ID: 1, Name: "App", MatchType: "exe_path", MatchValue: "/missing", IsEnabled: true},
	}

	results := m.Match(context.Background(), configs)
	if len(results) != 1 {
		t.Fatal("expected 1 result")
	}

	if results[0].State != StateUnknown {
		t.Fatalf("expected UNKNOWN due to index unknown state, got %s", results[0].State)
	}
}
