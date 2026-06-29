package fritz

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"
)

// CheckStatus is the outcome of one diagnosis step.
type CheckStatus string

const (
	StatusOK   CheckStatus = "ok"
	StatusFail CheckStatus = "fail"
	StatusWarn CheckStatus = "warn"
	StatusSkip CheckStatus = "skip"
)

// Check is a single end-to-end diagnosis step.
type Check struct {
	Name   string      `json:"name"`
	Status CheckStatus `json:"status"`
	Detail string      `json:"detail,omitempty"`
}

// Diagnosis is the full result of diagnosing one host.
type Diagnosis struct {
	Ref    string  `json:"ref"`              // what the user asked for
	Host   *Host   `json:"host,omitempty"`   // resolved host table entry, if any
	Target string  `json:"target,omitempty"` // IP actually probed
	Checks []Check `json:"checks"`
	OK     bool    `json:"ok"` // true if no check failed
}

// PortProbe names a TCP port to check during diagnosis.
type PortProbe struct {
	Port  int
	Label string
}

// DefaultProbes are the ports commonly relevant for a Mac host (SSH, screen
// sharing/VNC, Paperless). Override via DiagnoseOptions.Ports.
var DefaultProbes = []PortProbe{
	{22, "SSH"},
	{5900, "VNC/Screen Sharing"},
	{8001, "Paperless"},
}

// DiagnoseOptions tunes a diagnosis run.
type DiagnoseOptions struct {
	Ports       []PortProbe
	DialTimeout time.Duration
}

// Diagnose runs an end-to-end check for a host reference (name, MAC, or IP):
// is it in the box's host table, is it active, on LAN or WLAN, does its name
// resolve via DNS, and are the relevant TCP ports reachable from this machine.
func (c *Client) Diagnose(ctx context.Context, ref string, opts DiagnoseOptions) *Diagnosis {
	if len(opts.Ports) == 0 {
		opts.Ports = DefaultProbes
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 2 * time.Second
	}

	d := &Diagnosis{Ref: ref, OK: true}

	// 1–4: what does the FRITZ!Box know about this host?
	host, err := c.ResolveHost(ctx, ref)
	if err != nil {
		d.add("FRITZ!Box knows host", StatusFail, err.Error())
		// Without a box entry we can still probe ref if it's an IP/hostname.
		if looksLikeIP(ref) {
			d.Target = ref
		}
	} else {
		d.Host = host
		d.add("FRITZ!Box knows host", StatusOK, host.Name)
		if host.Active {
			d.add("Host active", StatusOK, "")
		} else {
			d.add("Host active", StatusWarn, "box reports host as inactive")
		}
		if host.IP != "" {
			d.add("IP address", StatusOK, host.IP)
			d.Target = host.IP
		} else {
			d.add("IP address", StatusWarn, "no IP in host table")
		}
		link := host.Link()
		linkStatus := StatusOK
		if link == "—" {
			linkStatus = StatusWarn
		}
		d.add("Link medium", linkStatus, link)
	}

	// 5: DNS resolution of the reference name (when not already an IP).
	if !looksLikeIP(ref) && !looksLikeMAC(ref) {
		if ips, derr := net.DefaultResolver.LookupHost(ctx, ref); derr == nil && len(ips) > 0 {
			d.add("DNS resolves", StatusOK, joinShort(ips))
			if d.Target == "" {
				d.Target = ips[0]
			}
		} else {
			d.add("DNS resolves", StatusWarn, "name does not resolve via system DNS")
		}
	}

	// 6–N: TCP reachability of the relevant ports.
	if d.Target == "" {
		d.add("TCP reachability", StatusSkip, "no target IP to probe")
		d.finalize()
		return d
	}

	for _, p := range opts.Ports {
		name := fmt.Sprintf("TCP %d (%s)", p.Port, p.Label)
		if dialTCP(ctx, d.Target, p.Port, opts.DialTimeout) {
			d.add(name, StatusOK, "open")
		} else {
			d.add(name, StatusFail, "closed or filtered")
		}
	}

	d.finalize()
	return d
}

func (d *Diagnosis) add(name string, status CheckStatus, detail string) {
	d.Checks = append(d.Checks, Check{Name: name, Status: status, Detail: detail})
}

func (d *Diagnosis) finalize() {
	for _, ch := range d.Checks {
		if ch.Status == StatusFail {
			d.OK = false
			return
		}
	}
}

// dialTCP reports whether a TCP connection to ip:port succeeds within timeout.
func dialTCP(ctx context.Context, ip string, port int, timeout time.Duration) bool {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(dctx, "tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func joinShort(ips []string) string {
	sort.Strings(ips)
	if len(ips) > 3 {
		ips = ips[:3]
	}
	out := ""
	for i, ip := range ips {
		if i > 0 {
			out += ", "
		}
		out += ip
	}
	return out
}
