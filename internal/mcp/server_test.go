package mcp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

func TestStartServer_RequiresStdin(t *testing.T) {
	c := fritz.New("fritz.box")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so ServeStdio fails

	err := StartServer(ctx, c)
	if err == nil {
		t.Error("expected error when context is cancelled, got nil")
	}
}

func TestMCPServerTools(t *testing.T) {
	// Spin up mock server for FRITZ!Box APIs
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")

		// 1. AHA-HTTP requests
		if strings.Contains(r.URL.Path, "homeautoswitch.lua") {
			cmd := r.URL.Query().Get("switchcmd")
			w.Header().Set("Content-Type", "text/plain")
			switch cmd {
			case "getdevicelistinfos":
				_, _ = io.WriteString(w, `<devicelist>
					<device identifier="123" present="1" name="Switch 1">
						<switch><state>1</state></switch>
						<powermeter><power>1500</power><energy>100</energy></powermeter>
					</device>
				</devicelist>`)
			case "setswitchon":
				_, _ = io.WriteString(w, "1")
			case "setswitchoff":
				_, _ = io.WriteString(w, "0")
			default:
				w.WriteHeader(http.StatusNotFound)
			}
			return
		}

		// 2. SOAP requests
		sa := r.Header.Get("SoapAction")
		bodyBytes, _ := io.ReadAll(r.Body)
		body := string(bodyBytes)

		if strings.Contains(sa, "GetInfo") {
			if strings.Contains(body, "DeviceInfo") || strings.Contains(sa, "DeviceInfo") {
				_, _ = io.WriteString(w, soapEnvelope("GetInfo", map[string]string{
					"NewModelName":       "FRITZ!Box 7590",
					"NewSoftwareVersion": "7.57",
					"NewUpTime":          "3600",
				}))
				return
			}
			if strings.Contains(body, "WANIPConnection") || strings.Contains(sa, "WANIPConnection") {
				_, _ = io.WriteString(w, soapEnvelope("GetInfo", map[string]string{
					"NewConnectionStatus": "Connected",
				}))
				return
			}
			if strings.Contains(body, "WLANConfiguration") || strings.Contains(sa, "WLANConfiguration") {
				_, _ = io.WriteString(w, soapEnvelope("GetInfo", map[string]string{
					"NewEnable": "1",
					"NewStatus": "Up",
				}))
				return
			}
		}
		if strings.Contains(sa, "GetExternalIPAddress") {
			_, _ = io.WriteString(w, soapEnvelope("GetExternalIPAddress", map[string]string{
				"NewExternalIPAddress": "203.0.113.1",
			}))
			return
		}
		if strings.Contains(sa, "GetHostNumberOfEntries") {
			_, _ = io.WriteString(w, soapEnvelope("GetHostNumberOfEntries", map[string]string{
				"NewHostNumberOfEntries": "1",
			}))
			return
		}
		if strings.Contains(sa, "GetGenericHostEntry") {
			_, _ = io.WriteString(w, soapEnvelope("GetGenericHostEntry", map[string]string{
				"NewIPAddress":     "192.168.178.20",
				"NewMACAddress":    "00:11:22:33:44:55",
				"NewHostName":      "my-host",
				"NewActive":        "1",
				"NewInterfaceType": "Ethernet",
				"NewAddressSource": "DHCP",
			}))
			return
		}
		if strings.Contains(sa, "GetSpecificHostEntry") {
			_, _ = io.WriteString(w, soapEnvelope("GetSpecificHostEntry", map[string]string{
				"NewIPAddress":     "192.168.178.20",
				"NewMACAddress":    "00:11:22:33:44:55",
				"NewHostName":      "my-host",
				"NewActive":        "1",
				"NewInterfaceType": "Ethernet",
				"NewAddressSource": "DHCP",
			}))
			return
		}
		if strings.Contains(sa, "WakeOnLAN") {
			_, _ = io.WriteString(w, soapEnvelope("WakeOnLAN", nil))
			return
		}
		if strings.Contains(sa, "GetRadioInfo") {
			_, _ = io.WriteString(w, soapEnvelope("GetRadioInfo", map[string]string{
				"NewEnable": "1",
			}))
			return
		}
		if strings.Contains(sa, "GetStatisticsTotal") {
			_, _ = io.WriteString(w, soapEnvelope("GetStatisticsTotal", nil))
			return
		}
		if strings.Contains(sa, "GetMeshListPath") {
			_, _ = io.WriteString(w, soapEnvelope("GetMeshListPath", map[string]string{
				"NewMeshListPath": "/mesh.xml",
			}))
			return
		}
		if strings.Contains(r.URL.Path, "mesh.xml") {
			_, _ = io.WriteString(w, `<mesh>
				<device>
					<uid>box</uid>
					<name>fritz.box</name>
				</device>
			</mesh>`)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	c := fritz.New("fritz.box")
	c.SetMockURLs(srv.URL) // Set both tr064 and base HTTP URLs to mock server

	s := buildServer(c)

	tests := []struct {
		name    string
		reqJSON string
		wantErr bool
	}{
		{
			name:    "status tool",
			reqJSON: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"status","arguments":{}},"id":1}`,
		},
		{
			name:    "host_list tool",
			reqJSON: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"host_list","arguments":{"active_only":true}},"id":2}`,
		},
		{
			name:    "host_get tool (by mac)",
			reqJSON: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"host_get","arguments":{"mac":"00:11:22:33:44:55"}},"id":3}`,
		},
		{
			name:    "host_get tool (by ip)",
			reqJSON: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"host_get","arguments":{"ip":"192.168.178.20"}},"id":4}`,
		},
		{
			name:    "host_get tool (by name)",
			reqJSON: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"host_get","arguments":{"name":"my-host"}},"id":5}`,
		},
		{
			name:    "diagnose tool",
			reqJSON: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"diagnose","arguments":{"host":"my-host","ports":[22]}},"id":6}`,
		},
		{
			name:    "mesh tool",
			reqJSON: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"mesh","arguments":{}},"id":7}`,
		},
		{
			name:    "wlan_clients tool",
			reqJSON: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"wlan_clients","arguments":{}},"id":8}`,
		},
		{
			name:    "wake_on_lan tool",
			reqJSON: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"wake_on_lan","arguments":{"mac":"00:11:22:33:44:55"}},"id":9}`,
		},
		{
			name:    "wake_on_lan tool by name",
			reqJSON: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"wake_on_lan","arguments":{"host":"my-host"}},"id":10}`,
		},
		{
			name:    "home_list tool",
			reqJSON: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"home_list","arguments":{}},"id":11}`,
		},
		{
			name:    "home_switch tool on",
			reqJSON: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"home_switch","arguments":{"ain":"123","on":true}},"id":12}`,
		},
		{
			name:    "home_switch tool off",
			reqJSON: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"home_switch","arguments":{"ain":"123","on":false}},"id":13}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rBuf bytes.Buffer
			var wBuf bytes.Buffer

			// Frame the request message
			rBuf.WriteString(fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(tt.reqJSON), tt.reqJSON))

			ctx := context.Background()
			err := s.ServeIO(ctx, &rBuf, &wBuf)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ServeIO error = %v, wantErr %v", err, tt.wantErr)
			}

			// Validate response
			res := wBuf.String()
			if !strings.Contains(res, `"jsonrpc"`) {
				t.Errorf("invalid JSON-RPC response: %s", res)
			}
			if strings.Contains(res, `"error"`) {
				t.Errorf("response contains error: %s", res)
			}
		})
	}
}

func soapEnvelope(action string, args map[string]string) string {
	var sb strings.Builder
	sb.WriteString(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">`)
	sb.WriteString(`<soap:Body>`)
	sb.WriteString(fmt.Sprintf(`<u:%sResponse xmlns:u="urn:schemas-any-org:service:any:1">`, action))
	for k, v := range args {
		sb.WriteString(fmt.Sprintf(`<%s>%s</%s>`, k, v, k))
	}
	sb.WriteString(fmt.Sprintf(`</u:%sResponse>`, action))
	sb.WriteString(`</soap:Body>`)
	sb.WriteString(`</soap:Envelope>`)
	return sb.String()
}
