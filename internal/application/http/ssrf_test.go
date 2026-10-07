package http

import (
	"context"
	"net"
	"testing"
)

type fakeResolver struct {
	ips []net.IPAddr
	err error
}

func (r *fakeResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return r.ips, r.err
}

func TestApplicationIPValidator(t *testing.T) {
	tests := []struct {
		name          string
		allowLoopback bool
		ip            net.IP
		expectErr     bool
	}{
		{"loopback_not_allowed", false, net.ParseIP("127.0.0.1"), true},
		{"loopback_allowed", true, net.ParseIP("127.0.0.1"), false},
		{"private_not_allowed_even_if_loopback_allowed", true, net.ParseIP("10.0.0.1"), true},
		{"private_not_allowed", false, net.ParseIP("192.168.1.1"), true},
		{"public_ip_allowed", false, net.ParseIP("8.8.8.8"), false},
		{"public_ip_allowed_loopback_true", true, net.ParseIP("8.8.8.8"), false},
		{"metadata_blocked", true, net.ParseIP("169.254.169.254"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &appIPValidator{allowLoopback: tt.allowLoopback}
			err := v.ValidateIP(tt.ip)
			if tt.expectErr && err == nil {
				t.Errorf("expected error for IP %s", tt.ip)
			}
			if !tt.expectErr && err != nil {
				t.Errorf("unexpected error for IP %s: %v", tt.ip, err)
			}
		})
	}
}
