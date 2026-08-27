package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// homeMockServer serves the AHA-HTTP endpoint, TR-064 Homeauto/DeviceInfo/Hosts
// actions, the mesh list JSON, and the data.lua scrape endpoint.
func homeMockServer(t *testing.T) *httptest.Server {
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
		if r.URL.Path == "/webservices/homeautoswitch.lua" {
			switch r.URL.Query().Get("switchcmd") {
			case "getdevicelistinfos":
				_, _ = io.WriteString(w, ahaDeviceListXML)
			case "setswitchon", "setswitchoff", "sethkrtsoll":
				_, _ = io.WriteString(w, "ok")
			default:
				w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}
		if r.URL.Path == "/data.lua" {
			_, _ = io.WriteString(w, `{"status":"ok","page":"netDev"}`)
			return
		}
		if r.URL.Path == "/mesh/mesh.json" {
			_, _ = io.WriteString(w, meshListJSON)
			return
		}
		if r.URL.Path == "/cgi-bin/log.lua" {
			_, _ = io.WriteString(w, `<DeviceLog><Event><id>1</id><group>sys</group><date>07.08.26</date><time>10:00:00</time><msg>test event</msg></Event></DeviceLog>`)
			return
		}
		sa := soapAction(r)
		body, _ := io.ReadAll(r.Body)
		switch {
		case strings.Contains(sa, "DeviceInfo:1#X_AVM-DE_GetDeviceLogPath"):
			writeSOAP(w, "X_AVM-DE_GetDeviceLogPath", "urn:dslforum-org:service:DeviceInfo:1", map[string]string{
				"NewDeviceLogPath": "/cgi-bin/log.lua",
			})
		case strings.Contains(sa, "Hosts:1#X_AVM-DE_GetMeshListPath"):
			writeSOAP(w, "X_AVM-DE_GetMeshListPath", "urn:dslforum-org:service:Hosts:1", map[string]string{
				"NewX_AVM-DE_MeshListPath": srv.URL + "/mesh/mesh.json",
			})
		case strings.Contains(sa, "Homeauto:1#GetGenericDeviceInfos"):
			if strings.Contains(string(body), "<NewIndex>0</NewIndex>") {
				writeSOAP(w, "GetGenericDeviceInfos", "urn:dslforum-org:service:X_AVM-DE_Homeauto:1", map[string]string{
					"NewAIN": "12345 678901", "NewProductName": "FRITZ!DECT 200",
					"NewManufacturer": "AVM", "NewFirmwareVersion": "05.23",
					"NewFunctionBitMask": "0",
				})
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

const ahaDeviceListXML = `<?xml version="1.0"?><devicelist>
<device identifier="12345 678901" id="17" functionbitmask="0" fwversion="05.23" manufacturer="AVM" productname="FRITZ!DECT 200">
<present>1</present><name>Lampe</name>
<switch><state>1</state></switch>
<hkr><tist>210</tist><tsoll>200</tsoll><battery>80</battery><windowopenactiv>1</windowopenactiv><errorcode>1</errorcode></hkr>
<powermeter><power>2500</power><energy>1000</energy></powermeter>
</device>
<device identifier="09876 543210" id="18" functionbitmask="0" fwversion="04.08" manufacturer="AVM" productname="FRITZ!DECT 301">
<present>0</present><name>Alt</name>
<switch><state>0</state></switch>
</device>
<group identifier="GRP-123" id="20"><name>Wohnzimmer</name><groupinfo><masterdeviceid>17</masterdeviceid><members>17,18</members></groupinfo></group>
</devicelist>`

const meshListJSON = `{"schema_version":"1.0","nodes":[{"uid":"1","device_name":"FRITZ!Box","device_model":"7590 AX","mesh_role":"master","node_interfaces":[{"uid":"i1","name":"eth0","type":"LAN","node_links":[{"state":"active","node_1":"1","node_2":"2","cur_data_rate_rx":500,"cur_data_rate_tx":1000}]}]},{"uid":"2","device_name":"Repeater","device_model":"2400","mesh_role":"slave","node_interfaces":[{"uid":"i2","name":"wlan0","type":"WLAN","node_links":[{"state":"","node_1":"2","node_2":"1"}]}]}]}`

func TestHomeListCmd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := homeMockServer(t)
	stubNewClient(t, srv)

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"home", "list"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("home list: %v", err)
		}
	})

	for _, want := range []string{"Lampe", "12345 678901", "on", "online", "temp:", "bat: 80%", "window: open", "Keine Verbindung zum Stellantrieb möglich", "power: 2.50W", "Alt", "off", "offline", "Groups:", "Wohnzimmer"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestHomeListCmd_JSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := homeMockServer(t)
	stubNewClient(t, srv)

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"home", "list", "--json"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("home list --json: %v", err)
		}
	})

	if !strings.Contains(out, `"devices"`) || !strings.Contains(out, `"groups"`) {
		t.Errorf("unexpected home json output:\n%s", out)
	}
}

func TestHomeListCmd_TR064(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := homeMockServer(t)
	stubNewClient(t, srv)

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"home", "list", "--tr064"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("home list --tr064: %v", err)
		}
	})

	if !strings.Contains(out, "FRITZ!DECT 200") || !strings.Contains(out, "12345 678901") {
		t.Errorf("unexpected home tr064 output:\n%s", out)
	}
}

func TestHomeSwitchCmd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := homeMockServer(t)
	stubNewClient(t, srv)

	t.Run("on", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"home", "switch", "12345 678901", "on"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("home switch: %v", err)
			}
		})
		if !strings.Contains(out, "OK: 12345 678901 -> on") {
			t.Errorf("unexpected switch output:\n%s", out)
		}
	})

	t.Run("off", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"home", "switch", "12345 678901", "off"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("home switch off: %v", err)
			}
		})
		if !strings.Contains(out, "OK: 12345 678901 -> off") {
			t.Errorf("unexpected switch output:\n%s", out)
		}
	})

	t.Run("bad state", func(t *testing.T) {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"home", "switch", "12345 678901", "maybe"})
		_, err := cmd.ExecuteC()
		if err == nil || !strings.Contains(err.Error(), "state must be on or off") {
			t.Errorf("expected bad-state error, got %v", err)
		}
	})
}

func TestHomeTempCmd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := homeMockServer(t)
	stubNewClient(t, srv)

	t.Run("celsius", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"home", "temp", "09876 543210", "20.5"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("home temp: %v", err)
			}
		})
		if !strings.Contains(out, "OK: 09876 543210 -> 20.5") {
			t.Errorf("unexpected temp output:\n%s", out)
		}
	})

	t.Run("on", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"home", "temp", "09876 543210", "on"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("home temp on: %v", err)
			}
		})
		if !strings.Contains(out, "OK: 09876 543210 -> on") {
			t.Errorf("unexpected temp output:\n%s", out)
		}
	})

	t.Run("bad temperature", func(t *testing.T) {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"home", "temp", "09876 543210", "abc"})
		_, err := cmd.ExecuteC()
		if err == nil || !strings.Contains(err.Error(), "bad temperature") {
			t.Errorf("expected bad-temperature error, got %v", err)
		}
	})
}

func TestLogCmd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := homeMockServer(t)
	stubNewClient(t, srv)

	t.Run("text", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"log"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("log: %v", err)
			}
		})
		if !strings.Contains(out, "[sys]") || !strings.Contains(out, "test event") {
			t.Errorf("unexpected log output:\n%s", out)
		}
	})

	t.Run("json", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"log", "--json"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("log --json: %v", err)
			}
		})
		if !strings.Contains(out, `"Msg"`) {
			t.Errorf("unexpected log json output:\n%s", out)
		}
	})
}

func TestVersionCmd(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		cmd := newRootCmd()
		buf := new(strings.Builder)
		cmd.SetOut(buf)
		cmd.SetArgs([]string{"version"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("version: %v", err)
		}
		if !strings.Contains(buf.String(), "symfritz") {
			t.Errorf("unexpected version output: %q", buf.String())
		}
	})

	t.Run("json", func(t *testing.T) {
		cmd := newRootCmd()
		buf := new(strings.Builder)
		cmd.SetOut(buf)
		cmd.SetArgs([]string{"version", "--json"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("version --json: %v", err)
		}
		if !strings.Contains(buf.String(), `"version"`) {
			t.Errorf("unexpected version json output: %q", buf.String())
		}
	})
}

func TestMeshCmd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := homeMockServer(t)
	stubNewClient(t, srv)

	t.Run("text", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"mesh"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("mesh: %v", err)
			}
		})
		for _, want := range []string{"FRITZ!Box", "master", "7590 AX", "Repeater", "slave", "(500/1000 Mbit/s)"} {
			if !strings.Contains(out, want) {
				t.Errorf("output missing %q:\n%s", want, out)
			}
		}
	})

	t.Run("json", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"mesh", "--json"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("mesh --json: %v", err)
			}
		})
		if !strings.Contains(out, `"device_name"`) {
			t.Errorf("unexpected mesh json output:\n%s", out)
		}
	})
}

func TestScrapeCmd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := homeMockServer(t)
	stubNewClient(t, srv)

	t.Run("success", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"scrape", "netDev"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("scrape: %v", err)
			}
		})
		if !strings.Contains(out, `"status":"ok"`) {
			t.Errorf("unexpected scrape output:\n%s", out)
		}
	})

	t.Run("bad argument", func(t *testing.T) {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"scrape", "netDev", "notkv"})
		_, err := cmd.ExecuteC()
		if err == nil || !strings.Contains(err.Error(), "bad argument") {
			t.Errorf("expected bad-argument error, got %v", err)
		}
	})
}

func TestAuthTrustCmd_Reset(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	pinPath := filepath.Join(home, ".config", "symfritz", "pins.json")

	t.Run("no pin recorded", func(t *testing.T) {
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"auth", "trust", "--reset", "fritz.box"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("auth trust: %v", err)
			}
		})
		if !strings.Contains(out, "No pin recorded for fritz.box.") {
			t.Errorf("unexpected trust output:\n%s", out)
		}
	})

	t.Run("pin reset", func(t *testing.T) {
		if err := os.MkdirAll(filepath.Dir(pinPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pinPath, []byte(`{"pins":{"fritz.box":"deadbeef"}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"auth", "trust", "--reset", "fritz.box"})
			if _, err := cmd.ExecuteC(); err != nil {
				t.Fatalf("auth trust reset: %v", err)
			}
		})
		if !strings.Contains(out, "Reset certificate pin for fritz.box.") {
			t.Errorf("unexpected trust output:\n%s", out)
		}
	})
}
