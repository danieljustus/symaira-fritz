// Package fritz is the core client library for talking to an AVM FRITZ!Box.
//
// It speaks the three interfaces a FRITZ!Box exposes:
//
//   - TR-064 (SOAP over HTTP, port 49000/49443) — administration: connection
//     state, WAN, WLAN, port forwardings, host list, mesh, reboot. See tr064.go.
//   - AHA-HTTP (/webservices/homeautoswitch.lua) — DECT smart-home actors
//     (switches, thermostats). See aha.go.
//   - Session login (/login_sid.lua) — the challenge-response handshake that
//     yields a session id (SID) used by AHA and by web-UI scraping. See session.go.
//
// The client is safe for sequential use. A single Client caches one SID and
// refreshes it on demand.
package fritz

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Client is a connection to a single FRITZ!Box.
type Client struct {
	// Host is the box address without scheme, e.g. "fritz.box" or "192.168.178.1".
	Host string
	// User is the FRITZ!Box user. May be empty for boxes that authenticate by
	// password only (legacy single-user setups).
	User string
	// Password is the box password. Prefer sourcing this from the environment
	// (SYMFRITZ_PASSWORD) or symvault rather than a plaintext config file.
	Password string

	// UseTLS selects https://host:49443 over http://host:49000 for TR-064.
	UseTLS bool
	// InsecureTLS skips certificate verification. FRITZ!Box ships a self-signed
	// cert, so this is commonly required for TLS. Off by default.
	InsecureTLS bool

	http *http.Client

	pinStore *PinStore

	// Base URL overrides for testing against a local fake box. When empty the
	// real host:port endpoints are used.
	tr064BaseURL string
	httpBaseURL  string

	mu  sync.Mutex
	sid string // cached session id from session.go; "" means not logged in

	// digestCache stores the most recent TR-064 digest challenge so subsequent
	// requests can pre-send the Authorization header instead of waiting for a
	// 401 challenge. The nc counter increments per reuse (RFC 7616 §4.7).
	digestCache *cachedDigest

	// Cached service list from tr64desc.xml, populated by the first Discover
	// and reused by ServiceByName to avoid redundant HTTP fetches.
	// Protected by discoverMu.
	discoverMu sync.Mutex
	discovered []Service

	fallbackWarnOnce sync.Once
	warnWriter       io.Writer
}

// Option configures a Client.
type Option func(*Client)

// WithUser sets the FRITZ!Box username.
func WithUser(u string) Option { return func(c *Client) { c.User = u } }

// WithPassword sets the FRITZ!Box password.
func WithPassword(p string) Option { return func(c *Client) { c.Password = p } }

// WithTLS enables the https TR-064 endpoint. insecure skips cert verification
// (usually needed for the box's self-signed certificate).
func WithTLS(insecure bool) Option {
	return func(c *Client) {
		c.UseTLS = true
		c.InsecureTLS = insecure
	}
}

// WithPinStore sets a custom PinStore for certificate verification.
func WithPinStore(ps *PinStore) Option {
	return func(c *Client) { c.pinStore = ps }
}

// WithTimeout sets the HTTP client timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.http.Timeout = d }
}

// WithWarnWriter sets the output writer for warnings. Defaults to os.Stderr.
func WithWarnWriter(w io.Writer) Option {
	return func(c *Client) { c.warnWriter = w }
}

// New constructs a Client for the given host.
func New(host string, opts ...Option) *Client {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimSuffix(host, "/")
	if host == "" {
		host = "fritz.box"
	}

	c := &Client{
		Host: host,
		http: &http.Client{Timeout: 15 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}

	// Build a transport that honours the InsecureTLS choice once options applied.
	var tlsConfig *tls.Config
	if c.InsecureTLS {
		tlsConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-out specified by user
	} else if c.UseTLS {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // manual verification in VerifyPeerCertificate
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return fmt.Errorf("no server certificate presented")
				}
				pin, err := CalculateSPKIPin(rawCerts[0])
				if err != nil {
					return fmt.Errorf("invalid server certificate: %w", err)
				}
				store := c.pinStore
				if store == nil {
					store = NewPinStore("")
				}
				storedPin := store.GetPin(c.Host)
				if storedPin == "" {
					if err := store.SetPin(c.Host, pin); err != nil {
						return fmt.Errorf("failed to record certificate pin: %w", err)
					}
					return nil
				}
				if storedPin != pin {
					return &FritzError{
						Kind:    ErrUnauthorized,
						Service: c.Host,
						Raw:     fmt.Sprintf("certificate pin mismatch for %s (possible MITM attack or firmware update)", c.Host),
					}
				}
				return nil
			},
		}
	}
	baseTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	c.http.Transport = &fallbackTransport{
		client:        c,
		baseTransport: baseTransport,
	}
	return c
}

// fallbackTransport wraps an http.Transport to provide automatic fallback from
// HTTPS endpoints to HTTP when TLS endpoints (443/49443) do not answer.
type fallbackTransport struct {
	client        *Client
	baseTransport *http.Transport
}

func (t *fallbackTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return t.baseTransport.RoundTrip(req)
	}

	resp, err := t.baseTransport.RoundTrip(req)
	if err == nil {
		return resp, nil
	}

	if !isTLSEndpointNotAnswering(err, req.Context()) {
		return nil, err
	}

	// TLS endpoint did not answer; fallback to plain HTTP.
	t.client.fallbackToHTTP()

	fallbackURL := *req.URL
	fallbackURL.Scheme = "http"
	host := fallbackURL.Hostname()
	port := fallbackURL.Port()
	if port == "49443" {
		fallbackURL.Host = net.JoinHostPort(host, "49000")
	} else if port == "443" || port == "" {
		fallbackURL.Host = host
	}

	reqHTTP := req.Clone(req.Context())
	reqHTTP.URL = &fallbackURL
	if req.Host != "" {
		h, p, err := net.SplitHostPort(req.Host)
		if err == nil && p == "49443" {
			reqHTTP.Host = net.JoinHostPort(h, "49000")
		} else if err == nil && p == "443" {
			reqHTTP.Host = h
		}
	}
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		reqHTTP.Body = body
	}

	plainTransport := t.baseTransport.Clone()
	plainTransport.TLSClientConfig = nil
	return plainTransport.RoundTrip(reqHTTP)
}

func (t *fallbackTransport) CloseIdleConnections() {
	t.baseTransport.CloseIdleConnections()
}

func isTLSEndpointNotAnswering(err error, ctx context.Context) bool {
	if err == nil {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}

	var fe *FritzError
	if errors.As(err, &fe) {
		return false
	}
	var certErr x509.CertificateInvalidError
	var authErr x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	if errors.As(err, &certErr) || errors.As(err, &authErr) || errors.As(err, &hostErr) {
		return false
	}

	msg := err.Error()
	if strings.Contains(msg, "pin mismatch") ||
		strings.Contains(msg, "certificate") ||
		strings.Contains(msg, "tls:") ||
		strings.Contains(msg, "handshake") ||
		strings.Contains(msg, "remote error") {
		return false
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Op == "dial" {
			return true
		}
	}
	if errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) {
		return true
	}
	if strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connect: connection refused") ||
		strings.Contains(msg, "i/o timeout") {
		return true
	}
	return false
}

func (c *Client) fallbackToHTTP() {
	c.UseTLS = false
	c.emitFallbackWarning()
}

func (c *Client) emitFallbackWarning() {
	c.fallbackWarnOnce.Do(func() {
		w := c.warnWriter
		if w == nil {
			w = os.Stderr
		}
		fmt.Fprintf(w, "warning: TLS endpoint on %s did not answer, falling back to HTTP (set use_tls = false to silence)\n", c.Host)
	})
}

// invalidateSID clears the cached session id so the next SID call re-logs in.
// Used to recover from a 403 caused by an expired session.
func (c *Client) invalidateSID() {
	c.mu.Lock()
	c.sid = ""
	c.mu.Unlock()
}

// baseHTTP returns the plain-HTTP base URL used for session login and AHA,
// which always run on the standard web port (80/443), not the TR-064 port.
func (c *Client) baseHTTP() string {
	if c.httpBaseURL != "" {
		return c.httpBaseURL
	}
	if c.UseTLS {
		return "https://" + c.Host
	}
	return "http://" + c.Host
}

// tr064Base returns the TR-064 control base URL (port 49000/49443).
func (c *Client) tr064Base() string {
	if c.tr064BaseURL != "" {
		return c.tr064BaseURL
	}
	if c.UseTLS {
		return "https://" + c.Host + ":49443"
	}
	return "http://" + c.Host + ":49000"
}

// SetMockURLs overrides the base URLs for testing.
func (c *Client) SetMockURLs(url string) {
	c.tr064BaseURL = url
	c.httpBaseURL = url
}
