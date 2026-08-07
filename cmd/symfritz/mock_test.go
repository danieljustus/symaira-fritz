package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/danieljustus/symaira-fritz/internal/config"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

// writeSOAP writes a minimal TR-064 SOAP success envelope for action with the
// given out-argument fields. Field values are written verbatim (no escaping),
// which is fine for the numeric/simple values the mocks produce.
func writeSOAP(w http.ResponseWriter, action, xmlns string, fields map[string]string) {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:`)
	b.WriteString(action)
	b.WriteString(`Response xmlns:u="`)
	b.WriteString(xmlns)
	b.WriteString(`">`)
	for k, v := range fields {
		b.WriteString("<" + k + ">" + v + "</" + k + ">")
	}
	b.WriteString(`</u:`)
	b.WriteString(action)
	b.WriteString(`Response></s:Body></s:Envelope>`)
	_, _ = w.Write(b.Bytes())
}

// soapAction returns the SoapAction header of a TR-064 POST.
func soapAction(r *http.Request) string { return r.Header.Get("SoapAction") }

// loginSIDXML is a successful /login_sid.lua response granting a session.
const loginSIDXML = `<SessionInfo><SID>0123456789abcdef</SID><Challenge></Challenge></SessionInfo>`

// tr64descXML is a minimal TR-064 service description document.
const tr64descXML = `<?xml version="1.0"?><root xmlns="urn:dslforum-org:device-1-0"><device><deviceType>urn:dslforum-org:device:InternetGatewayDevice:1</deviceType><serviceList><service><serviceType>urn:dslforum-org:service:DeviceInfo:1</serviceType><controlURL>/upnp/control/deviceinfo</controlURL></service></serviceList></device></root>`

// mockClient returns a fritz.Client pointed at the given mock server.
func mockClient(srv *httptest.Server) *fritz.Client {
	c := fritz.New("fritz.box", fritz.WithPassword("pw"))
	c.SetMockURLs(srv.URL)
	return c
}

// stubNewClient points the package newClient seam at a mock-backed client.
func stubNewClient(t *testing.T, srv *httptest.Server) {
	t.Helper()
	orig := newClient
	newClient = func() (*fritz.Client, *config.Config, error) {
		return mockClient(srv), config.Defaults(), nil
	}
	t.Cleanup(func() { newClient = orig })
}

// stubNewClientFor points the package newClientFor seam at a mock-backed
// client (used by verifyCredential and the auth commands).
func stubNewClientFor(t *testing.T, srv *httptest.Server) {
	t.Helper()
	orig := newClientFor
	newClientFor = func(box config.Box, password string) *fritz.Client {
		return mockClient(srv)
	}
	t.Cleanup(func() { newClientFor = orig })
}

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// captureStderr runs fn with os.Stderr redirected and returns what it wrote.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	defer func() { os.Stderr = orig }()
	fn()
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// openTCPListener starts a listener on 127.0.0.1 that accepts and immediately
// closes connections, so TCP reachability probes succeed. Returns the port.
func openTCPListener(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// closedPort returns a TCP port on 127.0.0.1 that is currently closed.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// fakeBin puts an executable shell script named name on PATH (replacing PATH)
// so exec-based backends (security, symvault) resolve to it.
func fakeBin(t *testing.T, name, body string) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, name)
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

// nonTerminalStdin replaces os.Stdin with a plain file so promptHidden sees a
// non-terminal and takes its error path.
func nonTerminalStdin(t *testing.T) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	orig := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = orig })
}
