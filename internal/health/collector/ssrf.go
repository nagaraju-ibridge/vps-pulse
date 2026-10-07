package collector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

var (
	ErrSSRFBlocked = errors.New(ErrClassSSRFBlocked)
)

// IPValidator checks if a given net.IP is allowed to be dialed.
type IPValidator interface {
	ValidateIP(ip net.IP) error
}

type defaultIPValidator struct{}

func (v *defaultIPValidator) ValidateIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("%w: invalid IP address", ErrSSRFBlocked)
	}

	// Go's built-in checks correctly handle IPv4-mapped IPv6 addresses.
	if ip.IsLoopback() {
		return fmt.Errorf("%w: loopback address blocked (%s)", ErrSSRFBlocked, ip.String())
	}
	if ip.IsPrivate() {
		return fmt.Errorf("%w: private address blocked (%s)", ErrSSRFBlocked, ip.String())
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("%w: link-local address blocked (%s)", ErrSSRFBlocked, ip.String())
	}
	if ip.IsMulticast() {
		return fmt.Errorf("%w: multicast address blocked (%s)", ErrSSRFBlocked, ip.String())
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("%w: unspecified address blocked (%s)", ErrSSRFBlocked, ip.String())
	}

	return nil
}

// Resolver resolves hostnames to IP addresses.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// SafeDialer resolves and dials a hostname while enforcing SSRF protections.
// It ensures that the exact validated IP is the one that is dialed.
type SafeDialer struct {
	resolver  Resolver
	validator IPValidator
	dialer    *net.Dialer
}

func NewSafeDialer() *SafeDialer {
	return &SafeDialer{
		resolver:  net.DefaultResolver,
		validator: &defaultIPValidator{},
		dialer: &net.Dialer{
			Timeout:   5 * time.Second, // TCP timeout
			KeepAlive: 30 * time.Second,
		},
	}
}

// DialContext acts as a replacement for http.Transport.DialContext.
// It performs DNS resolution, validates all IPs, and dials the first valid one.
func (d *SafeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
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
