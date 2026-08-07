package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

// detectMockServer serves the TR-064 endpoints runDetect touches: DSL line
// stats, online monitor, and the tr64desc.xml service description.
func detectMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login_sid.lua" {
			_, _ = io.WriteString(w, loginSIDXML)
			return
		}
		if r.URL.Path == "/tr64desc.xml" {
			_, _ = io.WriteString(w, tr64descXML)
			return
		}
		sa := soapAction(r)
		switch {
		case strings.Contains(sa, "WANDSLInterfaceConfig:1#GetInfo"):
			writeSOAP(w, "GetInfo", "urn:dslforum-org:service:WANDSLInterfaceConfig:1", map[string]string{
				"NewUpstreamNoiseMargin":   "6",
				"NewDownstreamNoiseMargin": "7",
				"NewUpstreamAttenuation":   "8",
				"NewDownstreamAttenuation": "9",
			})
		case strings.Contains(sa, "WANCommonInterfaceConfig:1#GetCommonLinkProperties"):
			writeSOAP(w, "GetCommonLinkProperties", "urn:dslforum-org:service:WANCommonInterfaceConfig:1", map[string]string{
				"NewLayer1DownstreamMaxBitRate": "100000000",
				"NewLayer1UpstreamMaxBitRate":   "40000000",
			})
		case strings.Contains(sa, "WANCommonInterfaceConfig:1#X_AVM-DE_GetOnlineMonitor"):
			writeSOAP(w, "X_AVM-DE_GetOnlineMonitor", "urn:dslforum-org:service:WANCommonInterfaceConfig:1", map[string]string{
				"Newds_current_bps":   "1200000,900000",
				"Newprio_default_bps": "300000,200000",
			})
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// stubDetectDiscovery points the discovery and detect-client seams at the
// given mock server, with discovery returning ip.
func stubDetectDiscovery(t *testing.T, srv *httptest.Server, ip string) {
	t.Helper()
	origDiscover := discoverBox
	discoverBox = func(context.Context, *http.Client, string, bool) (string, error) {
		return ip, nil
	}
	t.Cleanup(func() { discoverBox = origDiscover })

	origClient := newDetectClient
	newDetectClient = func(string) *fritz.Client {
		return mockClient(srv)
	}
	t.Cleanup(func() { newDetectClient = origClient })
}

func TestRunDetect_DiscoveryFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_HOST", "fritz.box")

	origDiscover := discoverBox
	discoverBox = func(context.Context, *http.Client, string, bool) (string, error) {
		return "", errors.New("discover: no box found")
	}
	t.Cleanup(func() { discoverBox = origDiscover })

	err := runDetect(newRootCmd(), false)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "detect failed") {
		t.Errorf("error = %q, want detect-failed message", err.Error())
	}
}

func TestRunDetect_TextOutput(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_HOST", "fritz.box")
	srv := detectMockServer(t)
	stubDetectDiscovery(t, srv, "192.168.178.1")

	out := captureStdout(t, func() {
		if err := runDetect(newRootCmd(), false); err != nil {
			t.Fatalf("runDetect: %v", err)
		}
	})

	for _, want := range []string{
		"Detected FRITZ!Box at: 192.168.178.1",
		"Configured host: fritz.box",
		"Suggested config snippet:",
		"Link Capacity (IGD):     100000000/40000000 bps (down/up)",
		"Current Throughput (IGD): 1200000/300000 bps (down/up)",
		"Verifying connection... ok",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRunDetect_JSONOutput(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_HOST", "fritz.box")
	srv := detectMockServer(t)
	stubDetectDiscovery(t, srv, "192.168.178.1")

	out := captureStdout(t, func() {
		if err := runDetect(newRootCmd(), true); err != nil {
			t.Fatalf("runDetect: %v", err)
		}
	})

	for _, want := range []string{
		`"host": "fritz.box"`,
		`"ip": "192.168.178.1"`,
		`"ready": true`,
		`"downstream_max_bit_rate": 100000000`,
		`"current_downstream_bps": 1200000`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON output missing %q:\n%s", want, out)
		}
	}
}

func TestRunDetect_VerificationFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_HOST", "fritz.box")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tr64desc.xml" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.URL.Path == "/login_sid.lua" {
			_, _ = io.WriteString(w, loginSIDXML)
			return
		}
		sa := soapAction(r)
		switch {
		case strings.Contains(sa, "WANDSLInterfaceConfig:1#GetInfo"):
			writeSOAP(w, "GetInfo", "urn:dslforum-org:service:WANDSLInterfaceConfig:1", nil)
		case strings.Contains(sa, "WANCommonInterfaceConfig:1#GetCommonLinkProperties"):
			writeSOAP(w, "GetCommonLinkProperties", "urn:dslforum-org:service:WANCommonInterfaceConfig:1", nil)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	stubDetectDiscovery(t, srv, "192.168.178.1")

	err := runDetect(newRootCmd(), false)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "connection verification failed") {
		t.Errorf("error = %q, want verification-failed message", err.Error())
	}
}

func TestNewHTTPClient(t *testing.T) {
	c := newHTTPClient()
	if c == nil {
		t.Fatal("newHTTPClient returned nil")
	}
	if c.Timeout != 3*time.Second {
		t.Errorf("Timeout = %v, want 3s", c.Timeout)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", c.Transport)
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify TLS config for discovery")
	}
}

func TestNewDetectCmd(t *testing.T) {
	cmd := newDetectCmd()
	if cmd.Use != "detect" {
		t.Errorf("Use = %q, want %q", cmd.Use, "detect")
	}
	if cmd.Flags().Lookup("json") == nil {
		t.Error("missing --json flag")
	}
}
