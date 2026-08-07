package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// wlanMockServer serves WLANConfiguration GetInfo/SetEnable actions plus the
// associated-device enumeration used by `wlan radios` / `wlan clients`.
func wlanMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login_sid.lua" {
			_, _ = io.WriteString(w, loginSIDXML)
			return
		}
		sa := soapAction(r)
		switch {
		case strings.Contains(sa, "WLANConfiguration:1#GetInfo"):
			writeSOAP(w, "GetInfo", "urn:dslforum-org:service:WLANConfiguration:1", map[string]string{
				"NewSSID": "MyWLAN", "NewEnable": "1", "NewChannel": "6", "NewStandard": "n",
			})
		case strings.Contains(sa, "WLANConfiguration:1#GetTotalAssociations"):
			writeSOAP(w, "GetTotalAssociations", "urn:dslforum-org:service:WLANConfiguration:1", map[string]string{
				"NewTotalAssociations": "1",
			})
		case strings.Contains(sa, "WLANConfiguration:1#GetGenericAssociatedDeviceInfo"):
			writeSOAP(w, "GetGenericAssociatedDeviceInfo", "urn:dslforum-org:service:WLANConfiguration:1", map[string]string{
				"NewAssociatedDeviceMACAddress": "AA:BB:CC:DD:EE:FF",
				"NewAssociatedDeviceIPAddress":  "192.168.178.50",
				"NewX_AVM-DE_SignalStrength":    "80",
				"NewX_AVM-DE_Speed":             "300",
				"NewAssociatedDeviceAuthState":  "1",
			})
		case strings.Contains(sa, "WLANConfiguration:3#GetInfo"):
			writeSOAP(w, "GetInfo", "urn:dslforum-org:service:WLANConfiguration:3", map[string]string{
				"NewSSID": "Gast", "NewEnable": "1", "NewChannel": "11", "NewStandard": "n",
			})
		case strings.Contains(sa, "WLANConfiguration:3#SetEnable"):
			writeSOAP(w, "SetEnable", "urn:dslforum-org:service:WLANConfiguration:3", nil)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSetGuest(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	t.Run("enable", func(t *testing.T) {
		srv := wlanMockServer(t)
		stubNewClient(t, srv)
		out := captureStdout(t, func() {
			if err := setGuest(3, true); err != nil {
				t.Fatalf("setGuest: %v", err)
			}
		})
		if !strings.Contains(out, "Guest WLAN (index 3) enabled.") {
			t.Errorf("output = %q, want enabled message", out)
		}
	})

	t.Run("disable", func(t *testing.T) {
		srv := wlanMockServer(t)
		stubNewClient(t, srv)
		out := captureStdout(t, func() {
			if err := setGuest(3, false); err != nil {
				t.Fatalf("setGuest: %v", err)
			}
		})
		if !strings.Contains(out, "Guest WLAN (index 3) disabled.") {
			t.Errorf("output = %q, want disabled message", out)
		}
	})

	t.Run("client error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(srv.Close)
		stubNewClient(t, srv)
		err := setGuest(3, true)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "guest toggle failed") {
			t.Errorf("error = %q, want guest-toggle message", err.Error())
		}
	})
}

func TestWLANRadiosCmd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := wlanMockServer(t)
	stubNewClient(t, srv)

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"wlan", "radios"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("wlan radios: %v", err)
		}
	})

	if !strings.Contains(out, "MyWLAN") || !strings.Contains(out, "6") {
		t.Errorf("output missing radio info:\n%s", out)
	}
}

func TestWLANClientsCmd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := wlanMockServer(t)
	stubNewClient(t, srv)

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"wlan", "clients"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("wlan clients: %v", err)
		}
	})

	if !strings.Contains(out, "AA:BB:CC:DD:EE:FF") || !strings.Contains(out, "192.168.178.50") {
		t.Errorf("output missing client info:\n%s", out)
	}
}

func TestWLANGuestStatusCmd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := wlanMockServer(t)
	stubNewClient(t, srv)

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"wlan", "guest", "status"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("wlan guest status: %v", err)
		}
	})

	if !strings.Contains(out, `SSID="Gast"`) || !strings.Contains(out, "enabled=true") {
		t.Errorf("output missing guest status:\n%s", out)
	}
}
