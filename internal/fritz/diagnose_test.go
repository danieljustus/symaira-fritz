package fritz

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDiagnose_ConcurrentPortProbes(t *testing.T) {
	// Two probes against unreachable ports (port 1 always refuses on loopback).
	// Sequential: ~1s. Concurrent: << 1s. We assert wall-clock stays well under
	// the sum of both timeouts.
	c := New("fritz.box")
	c.tr064BaseURL = "http://127.0.0.1:1"

	start := time.Now()
	d := c.Diagnose(context.Background(), "127.0.0.1", DiagnoseOptions{
		Ports: []PortProbe{
			{Port: 1, Label: "closed1", Type: "tcp"},
			{Port: 1, Label: "closed2", Type: "tcp"},
			{Port: 1, Label: "closed3", Type: "tcp"},
		},
		DialTimeout: 500 * time.Millisecond,
	})
	elapsed := time.Since(start)

	// Sequential would be ~1.5s. Concurrent should be under 1s.
	if elapsed > 800*time.Millisecond {
		t.Errorf("concurrent probes took %v (sequential would be ~1.5s)", elapsed)
	}

	// Collect only the TCP probe checks (skip the "FRITZ!Box knows host" check).
	var tcpChecks []Check
	for _, ch := range d.Checks {
		if strings.HasPrefix(ch.Name, "TCP ") {
			tcpChecks = append(tcpChecks, ch)
		}
	}
	if len(tcpChecks) != 3 {
		t.Fatalf("expected 3 TCP checks, got %d", len(tcpChecks))
	}
	// Results must be in original order (closed1, closed2, closed3).
	for i, want := range []string{"closed1", "closed2", "closed3"} {
		if !strings.Contains(tcpChecks[i].Name, want) {
			t.Errorf("tcp check[%d] = %q, want to contain %q", i, tcpChecks[i].Name, want)
		}
	}
}

func TestDiagnose_PortOrder(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	c := New("fritz.box")
	c.tr064BaseURL = "http://127.0.0.1:1"

	d := c.Diagnose(context.Background(), "127.0.0.1", DiagnoseOptions{
		Ports: []PortProbe{
			{Port: 9999, Label: "z-first"},
			{Port: port, Label: "a-second"},
			{Port: 9998, Label: "m-third"},
		},
		DialTimeout: 500 * time.Millisecond,
	})

	// Collect only the TCP probe checks — despite concurrency they must be in input order.
	var tcpChecks []Check
	for _, ch := range d.Checks {
		if strings.HasPrefix(ch.Name, "TCP ") {
			tcpChecks = append(tcpChecks, ch)
		}
	}
	if len(tcpChecks) != 3 {
		t.Fatalf("expected 3 TCP checks, got %d", len(tcpChecks))
	}
	if !strings.Contains(tcpChecks[0].Name, "z-first") {
		t.Errorf("tcp check[0] = %q, want to contain z-first", tcpChecks[0].Name)
	}
	if !strings.Contains(tcpChecks[1].Name, "a-second") {
		t.Errorf("tcp check[1] = %q, want to contain a-second", tcpChecks[1].Name)
	}
	if tcpChecks[1].Status != StatusOK {
		t.Errorf("tcp check[1] = %+v, want StatusOK", tcpChecks[1])
	}
}

func TestDiagnose_PortProbes(t *testing.T) {
	// Open a listener so one probe succeeds.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	openPort := ln.Addr().(*net.TCPAddr).Port

	// Point the client's TR-064 base at an address that refuses instantly so the
	// host-table lookup fails fast (we only care about the port probes here).
	c := New("fritz.box", WithTimeout(500*time.Millisecond))
	c.tr064BaseURL = "http://127.0.0.1:1"

	d := c.Diagnose(context.Background(), "127.0.0.1", DiagnoseOptions{
		Ports: []PortProbe{
			{Port: openPort, Label: "open"},
			{Port: 1, Label: "closed"},
		},
		DialTimeout: 500 * time.Millisecond,
	})

	if d.Target != "127.0.0.1" {
		t.Errorf("target = %q, want 127.0.0.1", d.Target)
	}

	var open, closed *Check
	for i := range d.Checks {
		switch d.Checks[i].Name {
		case "TCP " + itoa(openPort) + " (open)":
			open = &d.Checks[i]
		case "TCP 1 (closed)":
			closed = &d.Checks[i]
		}
	}
	if open == nil || open.Status != StatusOK {
		t.Errorf("open port check = %+v", open)
	}
	if closed == nil || closed.Status != StatusFail {
		t.Errorf("closed port check = %+v", closed)
	}
	// A failing check must flip OK to false.
	if d.OK {
		t.Error("diagnosis OK should be false when a port is closed")
	}
}

func TestDialTCP_OpenAndClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	if !dialTCP(context.Background(), "127.0.0.1", port, time.Second) {
		t.Error("expected open port to dial")
	}
	if dialTCP(context.Background(), "127.0.0.1", 1, 500*time.Millisecond) {
		t.Error("expected closed port to fail")
	}
}

func TestJoinShort(t *testing.T) {
	tests := []struct {
		name string
		ips  []string
		want string
	}{
		{"empty", nil, ""},
		{"one", []string{"10.0.0.1"}, "10.0.0.1"},
		{"two sorted", []string{"10.0.0.2", "10.0.0.1"}, "10.0.0.1, 10.0.0.2"},
		{"three", []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"}, "10.0.0.1, 10.0.0.2, 10.0.0.3"},
		{"more than three truncated", []string{"10.0.0.4", "10.0.0.1", "10.0.0.2", "10.0.0.3"}, "10.0.0.1, 10.0.0.2, 10.0.0.3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := joinShort(tt.ips)
			if got != tt.want {
				t.Errorf("joinShort(%v) = %q, want %q", tt.ips, got, tt.want)
			}
		})
	}
}

func TestDialSSH_ConnRefused(t *testing.T) {
	// Port 1 is not SSH — dialSSH should return false.
	got := dialSSH(context.Background(), "127.0.0.1", 1, 500*time.Millisecond)
	if got {
		t.Error("dialSSH on closed port should return false")
	}
}

func TestDialSSH_Timeout(t *testing.T) {
	// Use a listener that accepts but never responds, forcing timeout.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	got := dialSSH(context.Background(), "127.0.0.1", port, 200*time.Millisecond)
	if got {
		t.Error("dialSSH should return false on a non-SSH listener")
	}
}

func TestDialSSH_BannerDetected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.8\r\n"))
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	got := dialSSH(context.Background(), "127.0.0.1", port, time.Second)
	if !got {
		t.Error("dialSSH should return true when SSH banner is detected")
	}
}

func TestDialSSH_NoBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n"))
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	got := dialSSH(context.Background(), "127.0.0.1", port, time.Second)
	if got {
		t.Error("dialSSH should return false when server sends non-SSH banner")
	}
}

// itoa avoids importing strconv just for the test labels.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func TestDiagnose_ResolvedReferenceForms(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	tests := []struct {
		name string
		ref  string
		host string
	}{
		{name: "ip", ref: "127.0.0.1", host: "ip-host"},
		{name: "mac", ref: "aa:bb:cc:dd:ee:ff", host: "mac-host"},
		{name: "name", ref: "localhost", host: "localhost"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fakeBox(t, func(action, body string) string {
				switch {
				case tt.name == "ip" && action == "X_AVM-DE_GetSpecificHostEntryByIP":
					return soapEnvelope(action, map[string]string{
						"NewHostName": tt.host, "NewIPAddress": "127.0.0.1",
						"NewMACAddress": "11:22:33:44:55:66", "NewActive": "1",
						"NewInterfaceType": "Ethernet",
					})
				case tt.name == "mac" && action == "GetSpecificHostEntry":
					if !strings.Contains(body, "AA:BB:CC:DD:EE:FF") {
						t.Errorf("MAC lookup body = %q, want upper-case MAC", body)
					}
					return soapEnvelope(action, map[string]string{
						"NewHostName": tt.host, "NewIPAddress": "127.0.0.1",
						"NewMACAddress": "AA:BB:CC:DD:EE:FF", "NewActive": "1",
						"NewInterfaceType": "Ethernet",
					})
				case tt.name == "name" && action == "GetHostNumberOfEntries":
					return soapEnvelope(action, map[string]string{"NewHostNumberOfEntries": "1"})
				case tt.name == "name" && action == "GetGenericHostEntry":
					return soapEnvelope(action, map[string]string{
						"NewHostName": tt.host, "NewIPAddress": "127.0.0.1",
						"NewMACAddress": "11:22:33:44:55:66", "NewActive": "1",
						"NewInterfaceType": "Ethernet",
					})
				}
				return soapEnvelope(action, nil)
			})

			d := c.Diagnose(context.Background(), tt.ref, DiagnoseOptions{
				Ports:       []PortProbe{{Port: port, Label: "local"}},
				DialTimeout: time.Second,
			})
			if d.Host == nil || d.Host.Name != tt.host || d.Host.IP != "127.0.0.1" {
				t.Fatalf("resolved host = %+v, want %q at 127.0.0.1", d.Host, tt.host)
			}
			if d.Target != "127.0.0.1" {
				t.Errorf("target = %q, want 127.0.0.1", d.Target)
			}
			if d.OK != true {
				t.Errorf("diagnosis OK = %v, want true; checks = %+v", d.OK, d.Checks)
			}
			for _, name := range []string{"FRITZ!Box knows host", "Host active", "IP address", "Link medium"} {
				var check *Check
				for i := range d.Checks {
					if d.Checks[i].Name == name {
						check = &d.Checks[i]
						break
					}
				}
				if check == nil || check.Status != StatusOK {
					t.Errorf("check %q = %+v, want StatusOK", name, check)
				}
			}
			wantChecks := 5
			if tt.name == "name" {
				wantChecks++ // hostname references also include the DNS check.
			}
			if len(d.Checks) != wantChecks {
				t.Errorf("checks = %+v, want %d checks", d.Checks, wantChecks)
			}
		})
	}
}

func TestDiagnose_HostWarningsAndNoTarget(t *testing.T) {
	c := fakeBox(t, func(action, body string) string {
		if action == "GetSpecificHostEntry" {
			return soapEnvelope(action, map[string]string{
				"NewHostName": "sleeping", "NewActive": "0",
				"NewMACAddress": "AA:BB:CC:DD:EE:FF",
			})
		}
		return soapEnvelope(action, nil)
	})

	d := c.Diagnose(context.Background(), "aa:bb:cc:dd:ee:ff", DiagnoseOptions{
		Ports:       []PortProbe{{Port: 1, Label: "must-skip"}},
		DialTimeout: 100 * time.Millisecond,
	})
	if d.Host == nil || d.Host.Name != "sleeping" {
		t.Fatalf("resolved host = %+v, want sleeping", d.Host)
	}
	if d.Target != "" {
		t.Errorf("target = %q, want empty when host has no IP", d.Target)
	}
	want := map[string]struct {
		status CheckStatus
		detail string
	}{
		"FRITZ!Box knows host": {StatusOK, "sleeping"},
		"Host active":          {StatusWarn, "box reports host as inactive"},
		"IP address":           {StatusWarn, "no IP in host table"},
		"Link medium":          {StatusWarn, "—"},
		"TCP reachability":     {StatusSkip, "no target IP to probe"},
	}
	for name, expected := range want {
		var got *Check
		for i := range d.Checks {
			if d.Checks[i].Name == name {
				got = &d.Checks[i]
				break
			}
		}
		if got == nil {
			t.Errorf("missing check %q in %+v", name, d.Checks)
			continue
		}
		if got.Status != expected.status || got.Detail != expected.detail {
			t.Errorf("check %q = %+v, want status=%q detail=%q", name, got, expected.status, expected.detail)
		}
	}
	if !d.OK {
		t.Errorf("diagnosis OK = false for warnings/skips: %+v", d.Checks)
	}
}

func TestDiagnose_DNSOutcomes(t *testing.T) {
	t.Run("resolution supplies target", func(t *testing.T) {
		c := fakeBox(t, func(action, body string) string {
			return soapEnvelope(action, nil)
		})
		d := c.Diagnose(context.Background(), "localhost", DiagnoseOptions{
			Ports:       []PortProbe{{Port: 1, Label: "local"}},
			DialTimeout: 100 * time.Millisecond,
		})
		if net.ParseIP(d.Target) == nil {
			t.Fatalf("target = %q, want an address supplied by DNS", d.Target)
		}
		var dns *Check
		for i := range d.Checks {
			if d.Checks[i].Name == "DNS resolves" {
				dns = &d.Checks[i]
				break
			}
		}
		if dns == nil || dns.Status != StatusOK || dns.Detail == "" {
			t.Errorf("DNS check = %+v, want successful non-empty result", dns)
		}
	})

	t.Run("resolution failure skips probes", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c := New("fritz.box")
		c.tr064BaseURL = "http://127.0.0.1:1"
		d := c.Diagnose(ctx, "router.invalid", DiagnoseOptions{
			Ports:       []PortProbe{{Port: 22, Label: "ssh", Type: "ssh"}},
			DialTimeout: 100 * time.Millisecond,
		})
		if d.Target != "" {
			t.Errorf("target = %q, want empty after DNS failure", d.Target)
		}
		want := map[string]CheckStatus{
			"FRITZ!Box knows host": StatusFail,
			"DNS resolves":         StatusWarn,
			"TCP reachability":     StatusSkip,
		}
		for name, status := range want {
			var got *Check
			for i := range d.Checks {
				if d.Checks[i].Name == name {
					got = &d.Checks[i]
					break
				}
			}
			if got == nil || got.Status != status {
				t.Errorf("check %q = %+v, want %q", name, got, status)
			}
		}
		if d.OK {
			t.Errorf("diagnosis OK = true despite host-resolution failure: %+v", d.Checks)
		}
	})
}

func TestDiagnose_SSHProbeFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n"))
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	c := New("fritz.box")
	c.tr064BaseURL = "http://127.0.0.1:1"
	d := c.Diagnose(context.Background(), "127.0.0.1", DiagnoseOptions{
		Ports:       []PortProbe{{Port: port, Label: "SSH", Type: "ssh"}},
		DialTimeout: time.Second,
	})

	name := "SSH " + itoa(port) + " (SSH)"
	var ssh *Check
	for i := range d.Checks {
		if d.Checks[i].Name == name {
			ssh = &d.Checks[i]
			break
		}
	}
	if ssh == nil {
		t.Fatalf("missing SSH check %q in %+v", name, d.Checks)
	}
	if ssh.Status != StatusFail || ssh.Detail != "closed or no ssh banner" {
		t.Errorf("SSH check = %+v, want failed banner assertion", ssh)
	}
	if d.OK {
		t.Errorf("diagnosis OK = true despite SSH probe failure: %+v", d.Checks)
	}
}

func TestDiagnose_SSHProbeSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("SSH-2.0-test-server\r\n"))
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	c := fakeBox(t, func(action, body string) string {
		if action == "X_AVM-DE_GetSpecificHostEntryByIP" {
			return soapEnvelope(action, map[string]string{
				"NewHostName": "ssh-host", "NewIPAddress": "127.0.0.1",
				"NewMACAddress": "11:22:33:44:55:66", "NewActive": "1",
				"NewInterfaceType": "Ethernet",
			})
		}
		return soapEnvelope(action, nil)
	})
	d := c.Diagnose(context.Background(), "127.0.0.1", DiagnoseOptions{
		Ports:       []PortProbe{{Port: port, Label: "SSH", Type: "ssh"}},
		DialTimeout: time.Second,
	})

	name := "SSH " + itoa(port) + " (SSH)"
	var ssh *Check
	for i := range d.Checks {
		if d.Checks[i].Name == name {
			ssh = &d.Checks[i]
			break
		}
	}
	if ssh == nil || ssh.Status != StatusOK || ssh.Detail != "ssh handshake ok" {
		t.Errorf("SSH check = %+v, want successful handshake", ssh)
	}
	if !d.OK {
		t.Errorf("diagnosis OK = false despite successful host and SSH checks: %+v", d.Checks)
	}
}
