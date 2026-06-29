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
	"crypto/tls"
	"net/http"
	"strings"
	"sync"
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

	// Base URL overrides for testing against a local fake box. When empty the
	// real host:port endpoints are used.
	tr064BaseURL string
	httpBaseURL  string

	mu  sync.Mutex
	sid string // cached session id from session.go; "" means not logged in
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

// WithTimeout sets the HTTP client timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.http.Timeout = d }
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
	c.http.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: c.InsecureTLS}, //nolint:gosec // self-signed box cert; opt-in via WithTLS(insecure)
	}
	return c
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
