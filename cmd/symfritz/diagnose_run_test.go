package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// diagnoseMockServer serves the TR-064 Hosts service entries the diagnose
// flows resolve: a single host at 127.0.0.1 named TestPC on Ethernet.
func diagnoseMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login_sid.lua" {
			_, _ = io.WriteString(w, loginSIDXML)
			return
		}
		sa := soapAction(r)
		switch {
		case strings.Contains(sa, "Hosts:1#X_AVM-DE_GetSpecificHostEntryByIP"):
			writeSOAP(w, "X_AVM-DE_GetSpecificHostEntryByIP", "urn:dslforum-org:service:Hosts:1", map[string]string{
				"NewHostName":           "TestPC",
				"NewIPAddress":          "127.0.0.1",
				"NewMACAddress":         "AA:BB:CC:DD:EE:FF",
				"NewActive":             "1",
				"NewInterfaceType":      "Ethernet",
				"NewAddressSource":      "DHCP",
				"NewLeaseTimeRemaining": "3600",
			})
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRunDiagnoseRouter_Reachable(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_HOST", "127.0.0.1")
	srv := diagnoseMockServer(t)
	stubNewClient(t, srv)
	port := openTCPListener(t)

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"diagnose", "router", "--port", strconv.Itoa(port)})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("diagnose router: %v", err)
		}
	})

	for _, want := range []string{
		"Diagnose router  →  127.0.0.1",
		"FRITZ!Box knows host",
		"Result: reachable (no failed checks)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRunDiagnoseRouter_ProblemsDetected(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_HOST", "127.0.0.1")
	srv := diagnoseMockServer(t)
	stubNewClient(t, srv)

	cmd := newRootCmd()
	cmd.SetArgs([]string{"diagnose", "router", "--port", strconv.Itoa(closedPort(t))})
	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("expected error for closed port, got nil")
	}
	if !strings.Contains(err.Error(), "router not fully reachable") {
		t.Errorf("error = %q, want router-not-reachable message", err.Error())
	}
}

func TestRunDiagnoseRouter_JSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_HOST", "127.0.0.1")
	srv := diagnoseMockServer(t)
	stubNewClient(t, srv)
	port := openTCPListener(t)

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"diagnose", "router", "--json", "--port", strconv.Itoa(port)})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("diagnose router --json: %v", err)
		}
	})

	if !strings.Contains(out, `"ok": true`) || !strings.Contains(out, `"target": "127.0.0.1"`) {
		t.Errorf("JSON output missing ok/target fields:\n%s", out)
	}
}

func TestRunDiagnoseRouter_DiscoveryFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	// SYMFRITZ_HOST unset: the router command must discover the box first.
	origDiscover := discoverBox
	discoverBox = func(_ context.Context, _ *http.Client, _ string, _ bool) (string, error) {
		return "", errors.New("discover: no box found")
	}
	t.Cleanup(func() { discoverBox = origDiscover })

	cmd := newRootCmd()
	cmd.SetArgs([]string{"diagnose", "router"})
	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "could not find FRITZ!Box on the network") {
		t.Errorf("error = %q, want box-not-found message", err.Error())
	}
}

func TestDiagnoseCmd_Reachable(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := diagnoseMockServer(t)
	stubNewClient(t, srv)
	port := openTCPListener(t)

	var out string
	cmd := newRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"diagnose", "127.0.0.1", "--port", strconv.Itoa(port)})
	stdout := captureStdout(t, func() {
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("diagnose: %v", err)
		}
	})
	out = buf.String() + stdout

	for _, want := range []string{"Diagnose 127.0.0.1", "Result: reachable (no failed checks)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestDiagnoseCmd_ProblemsDetected(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := diagnoseMockServer(t)
	stubNewClient(t, srv)

	cmd := newRootCmd()
	cmd.SetArgs([]string{"diagnose", "127.0.0.1", "--port", strconv.Itoa(closedPort(t))})
	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("expected error for closed port, got nil")
	}
	if !strings.Contains(err.Error(), "host not fully reachable") {
		t.Errorf("error = %q, want host-not-reachable message", err.Error())
	}
}

func TestDiagnoseCmd_JSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := diagnoseMockServer(t)
	stubNewClient(t, srv)
	port := openTCPListener(t)

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"diagnose", "127.0.0.1", "--json", "--port", strconv.Itoa(port)})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("diagnose --json: %v", err)
		}
	})

	if !strings.Contains(out, `"ok": true`) {
		t.Errorf("JSON output missing ok field:\n%s", out)
	}
}
