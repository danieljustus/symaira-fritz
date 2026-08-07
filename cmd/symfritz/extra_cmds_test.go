package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// extraMockServer serves the TR-064 endpoints used by the dsl, traffic, call,
// hosts, services, reboot, and wol commands.
func extraMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login_sid.lua" {
			_, _ = io.WriteString(w, loginSIDXML)
			return
		}
		if r.URL.Path == "/tr64desc.xml" {
			_, _ = io.WriteString(w, tr64descXML)
			return
		}
		sa := soapAction(r)
		body, _ := io.ReadAll(r.Body)
		switch {
		case strings.Contains(sa, "WANDSLInterfaceConfig:1#GetInfo"):
			writeSOAP(w, "GetInfo", "urn:dslforum-org:service:WANDSLInterfaceConfig:1", map[string]string{
				"NewUpstreamNoiseMargin": "65", "NewDownstreamNoiseMargin": "70",
				"NewUpstreamAttenuation": "30", "NewDownstreamAttenuation": "35",
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
		case strings.Contains(sa, "Hosts:1#GetHostNumberOfEntries"):
			writeSOAP(w, "GetHostNumberOfEntries", "urn:dslforum-org:service:Hosts:1", map[string]string{
				"NewHostNumberOfEntries": "2",
			})
		case strings.Contains(sa, "Hosts:1#GetGenericHostEntry"):
			if strings.Contains(string(body), "<NewIndex>0</NewIndex>") {
				writeSOAP(w, "GetGenericHostEntry", "urn:dslforum-org:service:Hosts:1", map[string]string{
					"NewHostName": "TestPC", "NewIPAddress": "192.168.178.50",
					"NewMACAddress": "AA:BB:CC:DD:EE:FF", "NewActive": "1",
					"NewInterfaceType": "Ethernet", "NewAddressSource": "DHCP",
					"NewLeaseTimeRemaining": "3600",
				})
			} else {
				writeSOAP(w, "GetGenericHostEntry", "urn:dslforum-org:service:Hosts:1", map[string]string{
					"NewHostName": "OldPC", "NewIPAddress": "192.168.178.51",
					"NewMACAddress": "11:22:33:44:55:66", "NewActive": "0",
					"NewInterfaceType": "802.11", "NewAddressSource": "Static",
				})
			}
		case strings.Contains(sa, "Hosts:1#X_AVM-DE_GetSpecificHostEntryByIP") || strings.Contains(sa, "Hosts:1#GetSpecificHostEntry"):
			writeSOAP(w, strings.TrimSuffix(sa[strings.LastIndex(sa, "#")+1:], ""), "urn:dslforum-org:service:Hosts:1", map[string]string{
				"NewHostName": "TestPC", "NewIPAddress": "192.168.178.50",
				"NewMACAddress": "AA:BB:CC:DD:EE:FF", "NewActive": "1",
				"NewInterfaceType": "Ethernet", "NewAddressSource": "DHCP",
				"NewLeaseTimeRemaining": "3600",
			})
		case strings.Contains(sa, "Hosts:1#X_AVM-DE_WakeOnLANByMACAddress"):
			writeSOAP(w, "X_AVM-DE_WakeOnLANByMACAddress", "urn:dslforum-org:service:Hosts:1", nil)
		case strings.Contains(sa, "DeviceInfo:1#GetInfo"):
			writeSOAP(w, "GetInfo", "urn:dslforum-org:service:DeviceInfo:1", map[string]string{
				"NewModelName": "FRITZ!Box 7590", "NewSoftwareVersion": "7.57",
			})
		case strings.Contains(sa, "DeviceConfig:1#Reboot"):
			writeSOAP(w, "Reboot", "urn:dslforum-org:service:DeviceConfig:1", nil)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDSLCmd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := extraMockServer(t)
	stubNewClient(t, srv)

	t.Run("text", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"dsl"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("dsl: %v", err)
			}
		})
		if !strings.Contains(out, "DSL Line Statistics:") || !strings.Contains(out, "Max Bit Rate:   40.00 Mbit/s (Up) / 100.00 Mbit/s (Down)") {
			t.Errorf("unexpected dsl output:\n%s", out)
		}
	})

	t.Run("json", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"dsl", "--json"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("dsl --json: %v", err)
			}
		})
		if !strings.Contains(out, `"downstream_max_bit_rate": 100000000`) {
			t.Errorf("unexpected dsl json output:\n%s", out)
		}
	})
}

func TestTrafficCmd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := extraMockServer(t)
	stubNewClient(t, srv)

	t.Run("text", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"traffic"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("traffic: %v", err)
			}
		})
		if !strings.Contains(out, "WAN Traffic Monitoring") || !strings.Contains(out, "Internet: 1.20 Mbit/s") {
			t.Errorf("unexpected traffic output:\n%s", out)
		}
	})

	t.Run("json", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"traffic", "--json"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("traffic --json: %v", err)
			}
		})
		if !strings.Contains(out, `"downstream_internet"`) {
			t.Errorf("unexpected traffic json output:\n%s", out)
		}
	})
}

func TestCallCmd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := extraMockServer(t)
	stubNewClient(t, srv)

	t.Run("success", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"call", "deviceinfo", "GetInfo"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("call: %v", err)
			}
		})
		if !strings.Contains(out, `"NewModelName": "FRITZ!Box 7590"`) {
			t.Errorf("unexpected call output:\n%s", out)
		}
	})

	t.Run("bad argument", func(t *testing.T) {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"call", "deviceinfo", "GetInfo", "notkv"})
		_, err := cmd.ExecuteC()
		if err == nil || !strings.Contains(err.Error(), "bad argument") {
			t.Errorf("expected bad-argument error, got %v", err)
		}
	})

	t.Run("unknown service falls back to discovery", func(t *testing.T) {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"call", "nosuchservice", "GetInfo"})
		_, err := cmd.ExecuteC()
		if err == nil || !strings.Contains(err.Error(), "unknown service") {
			t.Errorf("expected unknown-service error, got %v", err)
		}
	})

	t.Run("action error", func(t *testing.T) {
		failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(failSrv.Close)
		stubNewClient(t, failSrv)
		cmd := newRootCmd()
		cmd.SetArgs([]string{"call", "deviceinfo", "GetInfo"})
		_, err := cmd.ExecuteC()
		if err == nil || !strings.Contains(err.Error(), "tr064 call failed") {
			t.Errorf("expected tr064-call-failed error, got %v", err)
		}
	})
}

func TestHostsCmd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := extraMockServer(t)
	stubNewClient(t, srv)

	t.Run("list", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"hosts", "list"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("hosts list: %v", err)
			}
		})
		for _, want := range []string{"TestPC", "OldPC", "192.168.178.50", "AA:BB:CC:DD:EE:FF"} {
			if !strings.Contains(out, want) {
				t.Errorf("output missing %q:\n%s", want, out)
			}
		}
	})

	t.Run("active filters inactive", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"hosts", "active"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("hosts active: %v", err)
			}
		})
		if !strings.Contains(out, "TestPC") || strings.Contains(out, "OldPC") {
			t.Errorf("unexpected active output:\n%s", out)
		}
	})

	t.Run("get by ip", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"hosts", "get", "--ip", "192.168.178.50"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("hosts get: %v", err)
			}
		})
		if !strings.Contains(out, "Name:    TestPC") || !strings.Contains(out, "Lease:   3600s") {
			t.Errorf("unexpected get output:\n%s", out)
		}
	})

	t.Run("get by name", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"hosts", "get", "TestPC"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("hosts get TestPC: %v", err)
			}
		})
		if !strings.Contains(out, "Name:    TestPC") {
			t.Errorf("unexpected get-by-name output:\n%s", out)
		}
	})

	t.Run("get without reference", func(t *testing.T) {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"hosts", "get"})
		_, err := cmd.ExecuteC()
		if err == nil || !strings.Contains(err.Error(), "missing host reference") {
			t.Errorf("expected missing-reference error, got %v", err)
		}
	})

	t.Run("list empty", func(t *testing.T) {
		emptySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(soapAction(r), "Hosts:1#GetHostNumberOfEntries") {
				writeSOAP(w, "GetHostNumberOfEntries", "urn:dslforum-org:service:Hosts:1", map[string]string{
					"NewHostNumberOfEntries": "0",
				})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(emptySrv.Close)
		stubNewClient(t, emptySrv)
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"hosts", "list"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("hosts list: %v", err)
			}
		})
		if !strings.Contains(out, "No hosts found.") {
			t.Errorf("unexpected empty output:\n%s", out)
		}
	})
}

func TestServicesCmd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := extraMockServer(t)
	stubNewClientFor(t, srv)

	t.Run("text", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"services"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("services: %v", err)
			}
		})
		if !strings.Contains(out, "urn:dslforum-org:service:DeviceInfo:1") {
			t.Errorf("unexpected services output:\n%s", out)
		}
	})

	t.Run("json", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"services", "--json"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("services --json: %v", err)
			}
		})
		if !strings.Contains(out, `"ControlURL"`) {
			t.Errorf("unexpected services json output:\n%s", out)
		}
	})
}

func TestRebootCmd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	t.Run("refuses without --yes", func(t *testing.T) {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"reboot"})
		_, err := cmd.ExecuteC()
		if err == nil || !strings.Contains(err.Error(), "refusing to reboot without --yes") {
			t.Errorf("expected confirmation error, got %v", err)
		}
	})

	t.Run("with --yes", func(t *testing.T) {
		srv := extraMockServer(t)
		stubNewClient(t, srv)
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"reboot", "--yes"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("reboot --yes: %v", err)
			}
		})
		if !strings.Contains(out, "Reboot triggered.") {
			t.Errorf("unexpected reboot output:\n%s", out)
		}
	})
}

func TestWoLCmd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := extraMockServer(t)
	stubNewClient(t, srv)

	t.Run("by mac", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"wol", "--mac", "AA:BB:CC:DD:EE:FF"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("wol: %v", err)
			}
		})
		if !strings.Contains(out, "Wake-on-LAN packet sent to AA:BB:CC:DD:EE:FF.") {
			t.Errorf("unexpected wol output:\n%s", out)
		}
	})

	t.Run("by name", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"wol", "TestPC"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("wol TestPC: %v", err)
			}
		})
		if !strings.Contains(out, "Wake-on-LAN packet sent to AA:BB:CC:DD:EE:FF.") {
			t.Errorf("unexpected wol-by-name output:\n%s", out)
		}
	})

	t.Run("missing target", func(t *testing.T) {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"wol"})
		_, err := cmd.ExecuteC()
		if err == nil || !strings.Contains(err.Error(), "missing host reference") {
			t.Errorf("expected missing-reference error, got %v", err)
		}
	})
}
