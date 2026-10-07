package collector

import (
	"strings"
	"testing"
)

func TestRedactCommandLineSensitiveArgumentForms(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    string
		notWant []string
	}{
		{
			name:    "password equals",
			args:    []string{"app", "--password=value"},
			want:    "app --password=REDACTED",
			notWant: []string{"value"},
		},
		{
			name:    "password next arg",
			args:    []string{"app", "--password", "value"},
			want:    "app --password REDACTED",
			notWant: []string{"value"},
		},
		{
			name:    "token equals",
			args:    []string{"app", "--token=value"},
			want:    "app --token=REDACTED",
			notWant: []string{"value"},
		},
		{
			name:    "token next arg",
			args:    []string{"app", "--token", "value"},
			want:    "app --token REDACTED",
			notWant: []string{"value"},
		},
		{
			name:    "secret equals",
			args:    []string{"app", "--secret=value"},
			want:    "app --secret=REDACTED",
			notWant: []string{"value"},
		},
		{
			name:    "api key equals",
			args:    []string{"app", "--api-key=value"},
			want:    "app --api-key=REDACTED",
			notWant: []string{"value"},
		},
		{
			name:    "api key next arg",
			args:    []string{"app", "--api-key", "value"},
			want:    "app --api-key REDACTED",
			notWant: []string{"value"},
		},
		{
			name:    "database url equals",
			args:    []string{"app", "--database-url=postgres://user:pass@host/db"},
			want:    "app --database-url=REDACTED",
			notWant: []string{"user:pass", "postgres://user"},
		},
		{
			name:    "case variations",
			args:    []string{"app", "--Password=one", "--API_KEY", "two"},
			want:    "app --Password=REDACTED --API_KEY REDACTED",
			notWant: []string{"one", "two"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactCommandLine(tt.args)
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
			for _, secret := range tt.notWant {
				if strings.Contains(got, secret) {
					t.Fatalf("redacted command contains secret %q: %q", secret, got)
				}
			}
		})
	}
}

func TestRedactCommandLineURLCredentials(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		blocked []string
	}{
		{
			name:    "postgres userinfo",
			raw:     "postgres://user:password@host/db",
			blocked: []string{"user:password", "password@host"},
		},
		{
			name:    "mysql userinfo",
			raw:     "mysql://root:secret@localhost:3306/db",
			blocked: []string{"root:secret", "secret@localhost"},
		},
		{
			name:    "http userinfo",
			raw:     "https://admin:pass@example.com/path",
			blocked: []string{"admin:pass", "pass@example.com"},
		},
		{
			name:    "query token",
			raw:     "https://example.com/callback?token=abc123&next=/home",
			blocked: []string{"abc123"},
		},
		{
			name:    "query api key",
			raw:     "https://example.com/api?api-key=abc123&name=ok",
			blocked: []string{"abc123"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactCommandLine([]string{"app", tt.raw})
			if !strings.Contains(got, "REDACTED") {
				t.Fatalf("expected redaction in %q", got)
			}
			for _, blocked := range tt.blocked {
				if strings.Contains(got, blocked) {
					t.Fatalf("redacted URL contains secret %q: %q", blocked, got)
				}
			}
		})
	}
}

func TestRedactCommandLineBearerAndJWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"

	tests := []struct {
		name    string
		args    []string
		blocked []string
	}{
		{
			name:    "bearer next value",
			args:    []string{"app", "Bearer", "secret-token"},
			blocked: []string{"secret-token"},
		},
		{
			name:    "auth bearer value",
			args:    []string{"app", "--auth=Bearer secret-token"},
			blocked: []string{"secret-token"},
		},
		{
			name:    "jwt looking standalone",
			args:    []string{"app", jwt},
			blocked: []string{jwt},
		},
		{
			name:    "jwt flag",
			args:    []string{"app", "--jwt", jwt},
			blocked: []string{jwt},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactCommandLine(tt.args)
			for _, blocked := range tt.blocked {
				if strings.Contains(got, blocked) {
					t.Fatalf("redacted command contains secret %q: %q", blocked, got)
				}
			}
			if !strings.Contains(got, "REDACTED") {
				t.Fatalf("expected redaction in %q", got)
			}
		})
	}
}

func TestRedactCommandLinePreservesOrdinaryArguments(t *testing.T) {
	args := []string{
		"node",
		"server.js",
		"--port=3000",
		"--keyboard-layout=us",
		"--monkey=banana",
		"https://example.com/path?name=value",
		"literal=a=b=c",
	}

	got := redactCommandLine(args)
	want := strings.Join(args, " ")
	if got != want {
		t.Fatalf("expected ordinary arguments preserved:\nwant %q\n got %q", want, got)
	}
}

func TestRedactCommandLineMixedSensitiveAndNonSensitiveOrdering(t *testing.T) {
	got := redactCommandLine([]string{
		"app",
		"--port",
		"8080",
		"--token",
		"secret",
		"--name=api",
		"--password=pwd",
	})

	want := "app --port 8080 --token REDACTED --name=api --password=REDACTED"
	if got != want {
		t.Fatalf("expected order-preserving redaction %q, got %q", want, got)
	}
}

func TestRedactCommandLineShortAndEmptyArguments(t *testing.T) {
	got := redactCommandLine([]string{"", "-", "--", "--pwd", ""})
	want := " - -- --pwd REDACTED"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestRedactCommandLineLengthLimitAfterRedaction(t *testing.T) {
	longSafe := strings.Repeat("a", 700)
	got := redactCommandLine([]string{"app", "--password=" + strings.Repeat("s", 700), longSafe})

	if len(got) != maxRedactedCommandLineLen {
		t.Fatalf("expected length %d, got %d", maxRedactedCommandLineLen, len(got))
	}
	if strings.Contains(got, strings.Repeat("s", 20)) {
		t.Fatalf("expected long sensitive value redacted, got %q", got)
	}
}
