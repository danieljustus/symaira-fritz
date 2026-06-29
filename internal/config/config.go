// Package config loads symfritz configuration from ~/.config/symfritz/config.toml
// and the SYMFRITZ_* environment, via the shared corekit configkit loader.
package config

import (
	"time"

	"github.com/danieljustus/symaira-corekit/configkit"
)

// Config is the full symfritz configuration.
type Config struct {
	Box Box `json:"box" toml:"box"`
}

// Box holds connection details for a single FRITZ!Box.
type Box struct {
	// Host is the box address without scheme, e.g. "fritz.box" or "192.168.178.1".
	Host string `json:"host" toml:"host"`
	// User is the FRITZ!Box username.
	User string `json:"user" toml:"user"`
	// Password is the box password.
	//
	// SECURITY: prefer NOT storing this here. Set SYMFRITZ_PASSWORD in the
	// environment, or source it from symvault (op://). A plaintext password in
	// a dotfile is the weakest option and is only supported for convenience.
	Password string `json:"password" toml:"password"`
	// UseTLS selects the https TR-064 endpoint (port 49443).
	UseTLS bool `json:"use_tls" toml:"use_tls"`
	// InsecureTLS skips certificate verification (needed for the box's
	// self-signed certificate when UseTLS is on).
	InsecureTLS bool `json:"insecure_tls" toml:"insecure_tls"`
	// TimeoutSeconds is the per-request HTTP timeout.
	TimeoutSeconds int `json:"timeout_seconds" toml:"timeout_seconds"`
}

// Defaults returns the built-in configuration.
func Defaults() *Config {
	return &Config{
		Box: Box{
			Host:           "fritz.box",
			User:           "",
			Password:       "",
			UseTLS:         false,
			InsecureTLS:    false,
			TimeoutSeconds: 15,
		},
	}
}

// Timeout returns the configured timeout as a duration.
func (b Box) Timeout() time.Duration {
	if b.TimeoutSeconds <= 0 {
		return 15 * time.Second
	}
	return time.Duration(b.TimeoutSeconds) * time.Second
}

var loader = configkit.NewLoader[Config](configkit.Options{
	AppName:   "symfritz",
	EnvPrefix: "SYMFRITZ",
}, Defaults)

// Load reads config from disk and environment, falling back to defaults.
func Load() (*Config, error) {
	return loader.Load()
}

// DefaultConfigTOML is the template written by `symfritz config init`.
func DefaultConfigTOML() string {
	return `# symfritz configuration

[box]
# FRITZ!Box address (hostname or IP), without scheme.
host = "fritz.box"

# FRITZ!Box username. Leave empty for legacy password-only boxes.
user = ""

# Password. RECOMMENDED: leave empty here and set SYMFRITZ_PASSWORD in your
# environment, or source it from symvault. A plaintext password in this file is
# the least secure option.
password = ""

# Use the TLS TR-064 endpoint (https, port 49443).
use_tls = false

# Skip TLS certificate verification (required for the box's self-signed cert
# when use_tls = true).
insecure_tls = false

# Per-request HTTP timeout in seconds.
timeout_seconds = 15
`
}
