package fritz

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

var (
	lookupHost = func(ctx context.Context, host string) ([]string, error) {
		return net.DefaultResolver.LookupHost(ctx, host)
	}
	defaultGateway = func() (net.IP, error) { return defaultGatewayFromRoute() }
)

// DefaultGateway returns the system's default gateway IP address.
// It parses the routing table to find the gateway for the default route.
func DefaultGateway() (net.IP, error) {
	gateway, err := defaultGateway()
	if err != nil {
		return nil, fmt.Errorf("default gateway: %w", err)
	}
	if gateway == nil {
		return nil, fmt.Errorf("default gateway: no gateway in default route")
	}
	return gateway, nil
}

// IsPrivateIP reports whether ip is a private (RFC 1918) or link-local address.
func IsPrivateIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// ProbeTR064 checks whether ip:port hosts a TR-064 device description endpoint.
// It performs a GET /tr64desc.xml and reports whether the response contains a
// valid UPnP device description. This is used for FRITZ!Box discovery.
func ProbeTR064(ctx context.Context, httpClient *http.Client, ip string, port int, insecure bool) bool {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec // caller controls TLS verification for discovery
			},
		}
	}
	scheme := "http"
	if port == 49443 {
		scheme = "https"
	}
	u := fmt.Sprintf("%s://%s:%d/tr64desc.xml", scheme, ip, port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	// Read a small prefix to check for the UPnP device description namespace.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return false
	}
	// A valid tr64desc.xml contains a UPnP or DSL Forum device-1-0 namespace.
	// Real FRITZ!Box devices use urn:dslforum-org; the standard UPnP namespace
	// is urn:schemas-upnp-org. Accept either.
	return bytesContains(body, []byte("urn:schemas-upnp-org:device-1-0")) ||
		bytesContains(body, []byte("urn:dslforum-org:device-1-0"))
}

// probeCandidate checks both port 49000 (HTTP) and 49443 (HTTPS) for TR-064.
func probeCandidate(ctx context.Context, httpClient *http.Client, ip string, insecure bool) bool {
	if ProbeTR064(ctx, httpClient, ip, 49000, insecure) {
		return true
	}
	if ProbeTR064(ctx, httpClient, ip, 49443, insecure) {
		return true
	}
	return false
}

func bytesContains(b, subs []byte) bool {
	return len(b) >= len(subs) && bytesContainsSubsequence(b, subs)
}

func bytesContainsSubsequence(b, subs []byte) bool {
	if len(subs) == 0 {
		return true
	}
	for i := 0; i <= len(b)-len(subs); i++ {
		if equalBytes(b[i:i+len(subs)], subs) {
			return true
		}
	}
	return false
}

func equalBytes(a, b []byte) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// publicHostHint returns a suggestion string if the host resolves to a public IP,
// or empty string if it resolves privately or cannot be determined.
func publicHostHint(ctx context.Context, host string) string {
	if host == "" {
		return ""
	}
	ips, err := lookupHost(ctx, host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	allPublic := true
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip != nil && IsPrivateIP(ip) {
			allPublic = false
			break
		}
	}
	if !allPublic {
		return ""
	}
	gw, gwErr := DefaultGateway()
	if gwErr == nil && gw != nil {
		return fmt.Sprintf("Hint: %s resolves to a public IP. Try setting SYMFRITZ_HOST=%s", host, gw)
	}
	return fmt.Sprintf("Hint: %s resolves to a public IP. Run 'symfritz detect' to find your FRITZ!Box.", host)
}

// DiscoverBox attempts to find the local FRITZ!Box by:
// 1. Checking if the configured host resolves to a private IP and probing it
// 2. Trying the system default gateway
// 3. Trying common FRITZ!Box default IPs
//
// It returns the first IP that responds to a TR-064 probe, or an error if none found.
func DiscoverBox(ctx context.Context, httpClient *http.Client, host string, insecure bool) (string, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 3 * time.Second}
	}

	// Step 1: If host is configured, resolve and check if it's private.
	if host != "" {
		ips, err := lookupHost(ctx, host)
		if err == nil {
			for _, ipStr := range ips {
				ip := net.ParseIP(ipStr)
				if ip != nil && IsPrivateIP(ip) && probeCandidate(ctx, httpClient, ipStr, insecure) {
					return ipStr, nil
				}
			}
			// If we got IPs but none are private, the host resolves publicly.
			// Fall through to gateway discovery.
		}
	}

	// Step 2: Try the system default gateway.
	gw, err := DefaultGateway()
	if err == nil && gw != nil {
		gwStr := gw.String()
		if probeCandidate(ctx, httpClient, gwStr, insecure) {
			return gwStr, nil
		}
	}

	// Step 3: Try common FRITZ!Box default IPs.
	commonIPs := []string{
		"192.168.178.1", // Most common FRITZ!Box default
		"192.168.1.1",   // Common alternative
		"192.168.0.1",   // Common alternative
		"192.168.188.1", // Daniel's network
	}
	for _, ip := range commonIPs {
		// Skip if we already tried this IP (e.g., it was the gateway).
		if gw != nil && gw.String() == ip {
			continue
		}
		if probeCandidate(ctx, httpClient, ip, insecure) {
			return ip, nil
		}
	}

	gwHint := ""
	if err == nil && gw != nil {
		gwHint = fmt.Sprintf(" or set SYMFRITZ_HOST=%s (your default gateway)", gw)
	}
	return "", fmt.Errorf("discover: could not find a FRITZ!Box on the local network; run 'symfritz detect' to troubleshoot%s", gwHint)
}

// ResolveHostInfo contains the result of resolving a hostname.
type ResolveHostInfo struct {
	IPs       []string // resolved IP addresses
	IsPublic  bool     // true if all IPs are public (non-private)
	IsGateway bool     // true if any IP matches the default gateway
}

// ResolveHost resolves a hostname and classifies the result.
func ResolveHostInfoFor(ctx context.Context, host string) (*ResolveHostInfo, error) {
	if host == "" {
		return nil, fmt.Errorf("resolve: empty host")
	}

	ips, err := lookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses", host)
	}

	info := &ResolveHostInfo{IPs: ips}

	gw, gwErr := DefaultGateway()
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if IsPrivateIP(ip) {
			info.IsPublic = false
		}
		if gwErr == nil && gw != nil && ip.Equal(gw) {
			info.IsGateway = true
		}
	}

	// If no private IPs were found, consider it public.
	allPublic := true
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip != nil && IsPrivateIP(ip) {
			allPublic = false
			break
		}
	}
	info.IsPublic = allPublic

	return info, nil
}

// checkHostDNS checks if the configured client Host resolves to a public IP.
// If it does, it fast-fails and attempts to detect the local FRITZ!Box to provide
// a helpful hint suggesting the detected IP.
func (c *Client) checkHostDNS(ctx context.Context) error {
	if c.tr064BaseURL != "" || c.httpBaseURL != "" {
		return nil
	}
	host := c.Host
	if host == "" {
		host = "fritz.box"
	}
	// If it is already an IP, check if it's public.
	if ip := net.ParseIP(host); ip != nil {
		if !IsPrivateIP(ip) {
			gw, gwErr := DefaultGateway()
			if gwErr == nil && gw != nil {
				return fmt.Errorf("host %q is a public IP. Local FRITZ!Box detected at %s. Try setting SYMFRITZ_HOST=%s", host, gw, gw)
			}
			return fmt.Errorf("host %q is a public IP. Run 'symfritz detect' to find your FRITZ!Box", host)
		}
		return nil
	}

	ips, err := lookupHost(ctx, host)
	if err != nil {
		// DNS resolution failed, let it fail naturally in HTTP or return here
		return nil
	}
	if len(ips) == 0 {
		return nil
	}

	allPublic := true
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip != nil && IsPrivateIP(ip) {
			allPublic = false
			break
		}
	}

	if allPublic {
		// Public IP! Perform quick local discovery using a short timeout.
		var transport http.RoundTripper
		if c.http != nil {
			transport = c.http.Transport
		}
		if transport == nil {
			transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: c.InsecureTLS}, //nolint:gosec // self-signed box cert; honour user setting
			}
		}
		discHTTPClient := &http.Client{
			Timeout:   1 * time.Second,
			Transport: transport,
		}
		detectedIP, detectErr := DiscoverBox(ctx, discHTTPClient, host, c.InsecureTLS)
		if detectErr == nil && detectedIP != "" {
			return fmt.Errorf("host %q resolves to a public IP (%s). Local FRITZ!Box detected at %s. Try setting SYMFRITZ_HOST=%s", host, strings.Join(ips, ", "), detectedIP, detectedIP)
		}
		return fmt.Errorf("host %q resolves to a public IP (%s). Run 'symfritz detect' to find your FRITZ!Box", host, strings.Join(ips, ", "))
	}

	return nil
}
