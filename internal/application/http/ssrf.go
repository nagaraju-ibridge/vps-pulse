package http

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

var (
	ErrSSRFBlocked = errors.New("ssrf_blocked")
)

type IPValidator interface {
	ValidateIP(ip net.IP) error
}

type appIPValidator struct {
	allowLoopback bool
}

func (v *appIPValidator) ValidateIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("%w: invalid IP address", ErrSSRFBlocked)
	}

	if ip.IsLoopback() {
		if !v.allowLoopback {
			return fmt.Errorf("%w: loopback address blocked (%s)", ErrSSRFBlocked, ip.String())
		}
		// loopback allowed for explicitly configured local applications
	} else if ip.IsPrivate() {
		return fmt.Errorf("%w: private address blocked (%s)", ErrSSRFBlocked, ip.String())
	} else if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("%w: link-local address blocked (%s)", ErrSSRFBlocked, ip.String())
	} else if ip.IsMulticast() {
		return fmt.Errorf("%w: multicast address blocked (%s)", ErrSSRFBlocked, ip.String())
	} else if ip.IsUnspecified() {
		return fmt.Errorf("%w: unspecified address blocked (%s)", ErrSSRFBlocked, ip.String())
	}

	return nil
}

type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// ApplicationSafeDialer acts as a replacement for http.Transport.DialContext.
// It performs DNS resolution, validates all IPs, and dials the first valid one.
type ApplicationSafeDialer struct {
	resolver  Resolver
	validator IPValidator
	dialer    *net.Dialer
}

func NewApplicationSafeDialer(allowLoopback bool) *ApplicationSafeDialer {
	return &ApplicationSafeDialer{
		resolver:  net.DefaultResolver,
		validator: &appIPValidator{allowLoopback: allowLoopback},
		dialer: &net.Dialer{
			Timeout:   5 * time.Second, // TCP timeout
			KeepAlive: 30 * time.Second,
		},
	}
}

// NewApplicationSafeDialerWithDeps allows test injection
func NewApplicationSafeDialerWithDeps(allowLoopback bool, r Resolver, d *net.Dialer) *ApplicationSafeDialer {
	return &ApplicationSafeDialer{
		resolver:  r,
		validator: &appIPValidator{allowLoopback: allowLoopback},
		dialer:    d,
	}
}

func (d *ApplicationSafeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}

	// Resolve IPs
	ips, err := d.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dns resolution failed: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("dns resolution failed: no addresses found for %s", host)
	}

	var lastErr error
	var attempted int

	for _, ipAddr := range ips {
		if err := d.validator.ValidateIP(ipAddr.IP); err != nil {
			continue // Skip SSRF blocked IPs
		}

		attempted++
		safeAddr := net.JoinHostPort(ipAddr.IP.String(), port)
		conn, err := d.dialer.DialContext(ctx, network, safeAddr)
		if err == nil {
			return conn, nil // Success
		}

		lastErr = err
	}

	if attempted == 0 {
		return nil, ErrSSRFBlocked
	}

	return nil, lastErr
}
