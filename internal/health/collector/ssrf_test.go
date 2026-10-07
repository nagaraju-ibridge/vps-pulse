package collector

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestDefaultIPValidator_ValidateIP(t *testing.T) {
	v := &defaultIPValidator{}

	cases := []struct {
		name    string
		ip      string
		allowed bool
	}{
		// Allowed IPv4
		{"public v4", "8.8.8.8", true},
		{"public v4 2", "1.1.1.1", true},

		// Allowed IPv6
		{"public v6", "2606:4700:4700::1111", true},

		// Blocked IPv4
		{"loopback v4", "127.0.0.1", false},
		{"loopback v4 any", "127.123.0.5", false},
		{"private v4 class a", "10.0.0.1", false},
		{"private v4 class b", "172.16.0.1", false},
		{"private v4 class c", "192.168.1.1", false},
		{"link local v4", "169.254.169.254", false},
		{"multicast v4", "224.0.0.1", false},
		{"unspecified v4", "0.0.0.0", false},

		// Blocked IPv6
		{"loopback v6", "::1", false},
		{"private v6", "fc00::1", false},
		{"link local v6", "fe80::1", false},
		{"unspecified v6", "::", false},
		{"multicast v6", "ff02::1", false},

		// Blocked IPv4-mapped IPv6
		{"v4-mapped loopback", "::ffff:127.0.0.1", false},
		{"v4-mapped private", "::ffff:192.168.1.1", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ip := net.ParseIP(c.ip)
			if ip == nil {
				t.Fatalf("invalid test ip: %s", c.ip)
			}
			err := v.ValidateIP(ip)
			if c.allowed && err != nil {
				t.Errorf("expected %s to be allowed, got error: %v", c.ip, err)
			}
			if !c.allowed && err == nil {
				t.Errorf("expected %s to be blocked, got allowed", c.ip)
			}
		})
	}
}

// mockResolver for testing dialer
type mockResolver struct {
	ips map[string][]net.IPAddr
	err error
}

func (m *mockResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if m.err != nil {
		return nil, m.err
	}
	if ips, ok := m.ips[host]; ok {
		return ips, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestSafeDialer_DialContext(t *testing.T) {
	resolver := &mockResolver{
		ips: map[string][]net.IPAddr{
			"safe.com":        {{IP: net.ParseIP("8.8.8.8")}},
			"blocked.com":     {{IP: net.ParseIP("127.0.0.1")}},
			"mixed.com":       {{IP: net.ParseIP("192.168.1.1")}, {IP: net.ParseIP("8.8.8.8")}},
			"all-blocked.com": {{IP: net.ParseIP("10.0.0.1")}, {IP: net.ParseIP("169.254.169.254")}},
		},
	}

	dialer := NewSafeDialer()
	dialer.resolver = resolver

	// Note: We don't actually want to dial 8.8.8.8:80 for real in a unit test if we can avoid it.
	// But DialContext will attempt it. We just care if it fails with ErrSSRFBlocked or not.
	ctx := context.Background()

	t.Run("safe domain allowed", func(t *testing.T) {
		// It will try to dial 8.8.8.8:80, which might timeout or succeed.
		// We just verify it doesn't fail with ErrSSRFBlocked.
		_, err := dialer.DialContext(ctx, "tcp", "safe.com:80")
		if errors.Is(err, ErrSSRFBlocked) {
			t.Errorf("expected safe.com not to be blocked by SSRF")
		}
	})

	t.Run("blocked domain rejected", func(t *testing.T) {
		_, err := dialer.DialContext(ctx, "tcp", "blocked.com:80")
		if !errors.Is(err, ErrSSRFBlocked) {
			t.Errorf("expected ErrSSRFBlocked, got %v", err)
		}
	})

	t.Run("mixed domain dials safe IP", func(t *testing.T) {
		// mixed.com has private and public. Should pick public and not block.
		_, err := dialer.DialContext(ctx, "tcp", "mixed.com:80")
		if errors.Is(err, ErrSSRFBlocked) {
			t.Errorf("expected mixed.com to allow safe IP, got SSRF blocked")
		}
	})

	t.Run("all blocked domain rejected", func(t *testing.T) {
		_, err := dialer.DialContext(ctx, "tcp", "all-blocked.com:80")
		if !errors.Is(err, ErrSSRFBlocked) {
			t.Errorf("expected ErrSSRFBlocked, got %v", err)
		}
	})

	t.Run("dns failure returns dns error", func(t *testing.T) {
		_, err := dialer.DialContext(ctx, "tcp", "notfound.com:80")
		if err == nil || errors.Is(err, ErrSSRFBlocked) {
			t.Errorf("expected DNS error, got %v", err)
		}
	})

	t.Run("fallback: unreachable IP followed by reachable IP", func(t *testing.T) {
		// Create a local listener to act as the "reachable" IP
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer l.Close()
		_, port, _ := net.SplitHostPort(l.Addr().String())

		// We need to bypass the SSRF check for 127.0.0.1 just for this test so we can dial the local listener
		originalValidator := dialer.validator
		dialer.validator = mockAllowAllValidator{}
		defer func() { dialer.validator = originalValidator }()

		// 192.0.2.1 is TEST-NET-1 (unreachable). 127.0.0.1 is our listener.
		resolver.ips["fallback.com"] = []net.IPAddr{
			{IP: net.ParseIP("192.0.2.1")}, // Will fail/timeout
			{IP: net.ParseIP("127.0.0.1")}, // Will succeed
		}

		// Dial with a short timeout so the first IP fails quickly
		dialer.dialer.Timeout = 50 * time.Millisecond

		conn, err := dialer.DialContext(ctx, "tcp", "fallback.com:"+port)
		if err != nil {
			t.Fatalf("expected fallback to succeed, got: %v", err)
		}
		defer conn.Close()

		if conn.RemoteAddr().(*net.TCPAddr).IP.String() != "127.0.0.1" {
			t.Errorf("expected to connect to 127.0.0.1, got %v", conn.RemoteAddr())
		}
	})

	t.Run("all validated IPs fail", func(t *testing.T) {
		originalValidator := dialer.validator
		dialer.validator = mockAllowAllValidator{}
		defer func() { dialer.validator = originalValidator }()

		resolver.ips["all-fail.com"] = []net.IPAddr{
			{IP: net.ParseIP("192.0.2.1")},
			{IP: net.ParseIP("192.0.2.2")},
		}

		dialer.dialer.Timeout = 10 * time.Millisecond
		_, err := dialer.DialContext(ctx, "tcp", "all-fail.com:80")
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if errors.Is(err, ErrSSRFBlocked) {
			t.Errorf("expected dial error, got SSRF blocked")
		}
	})
}

type mockAllowAllValidator struct{}

func (m mockAllowAllValidator) ValidateIP(ip net.IP) error {
	return nil
}
