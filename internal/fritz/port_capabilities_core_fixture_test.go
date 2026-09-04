package fritz

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type portCapabilitiesCoreFixture struct {
	SchemaVersion int                      `json:"schema_version"`
	Oracle        string                   `json:"oracle"`
	Hosts         []Host                   `json:"hosts"`
	Radios        []Radio                  `json:"radios"`
	WLANClients   []WLANClient             `json:"wlan_clients"`
	Mesh          MeshTopology             `json:"mesh"`
	Diagnosis     Diagnosis                `json:"diagnosis"`
	Requests      []portCapabilityRequest  `json:"requests"`
	Negative      []portCapabilityNegative `json:"negative"`
}

type portCapabilityRequest struct {
	ID          string            `json:"id"`
	ServiceType string            `json:"service_type"`
	ControlURL  string            `json:"control_url"`
	Action      string            `json:"action"`
	Args        map[string]string `json:"args,omitempty"`
}

type portCapabilityNegative struct {
	ID      string `json:"id"`
	Input   string `json:"input"`
	Message string `json:"message"`
}

func TestPortCapabilitiesCoreFixture(t *testing.T) {
	fixture := portCapabilitiesCoreFixture{
		SchemaVersion: 1,
		Oracle:        "Go internal/fritz typed capability production models and request seams",
		Hosts: []Host{
			hostFromEntry(map[string]string{
				"NewHostName": "macmini", "NewIPAddress": "192.168.188.65",
				"NewMACAddress": "f0:18:98:f3:64:b5", "NewActive": "1",
				"NewInterfaceType": "Ethernet", "NewAddressSource": "DHCP",
				"NewLeaseTimeRemaining": "3600",
			}),
			hostFromEntry(map[string]string{
				"NewHostName": "macbook", "NewIPAddress": "192.168.188.40",
				"NewMACAddress": "aa:bb:cc:dd:ee:ff", "NewActive": "0",
				"NewInterfaceType": "802.11ax", "NewAddressSource": "DHCP",
			}),
		},
		Radios: []Radio{
			{Index: 1, SSID: "MyNet", Enabled: true, Channel: "6", Standard: "802.11ac", BSSID: "AA:BB:CC:DD:EE:01", Status: "Up"},
			{Index: 3, SSID: "GuestNet", Enabled: false, Channel: "11", Standard: "802.11n", Status: "Down"},
		},
		WLANClients: []WLANClient{
			{RadioIndex: 1, MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.188.10", Signal: "80", Speed: "300", Authorized: true},
			{RadioIndex: 3, MAC: "aa:bb:cc:dd:ee:03", IP: "192.168.188.30", Signal: "65", Speed: "150", Authorized: false},
		},
		Mesh: MeshTopology{
			SchemaVersion: "1.0",
			Nodes: []MeshNode{{
				UID: "n1", DeviceName: "FRITZ!Box 7590", DeviceModel: "FB7590",
				IsMeshed: true, MeshRole: "master",
				Interfaces: []MeshInterface{{
					UID: "n1-lan", Name: "LAN Bridge", Type: "LAN",
					Links: []MeshLink{{State: "CONNECTED", Node1: "n1-lan", Node2: "n2-wlan", MaxDataRateRx: 1000, MaxDataRateTx: 1000, CurDataRateRx: 500, CurDataRateTx: 400}},
				}},
			}},
		},
		Diagnosis: Diagnosis{Ref: "fixture-ref", Checks: []Check{}, OK: true},
		Requests: []portCapabilityRequest{
			{ID: "status-device-info", ServiceType: ServiceDeviceInfo.Type, ControlURL: ServiceDeviceInfo.ControlURL, Action: "GetInfo"},
			{ID: "status-wan-info", ServiceType: ServiceWANIPConnection.Type, ControlURL: ServiceWANIPConnection.ControlURL, Action: "GetInfo"},
			{ID: "status-wan-external-ip", ServiceType: ServiceWANIPConnection.Type, ControlURL: ServiceWANIPConnection.ControlURL, Action: "GetExternalIPAddress"},
			{ID: "status-user-interface", ServiceType: ServiceUserInterface.Type, ControlURL: ServiceUserInterface.ControlURL, Action: "GetInfo"},
			{ID: "host-by-mac", ServiceType: ServiceHosts.Type, ControlURL: ServiceHosts.ControlURL, Action: "GetSpecificHostEntry", Args: map[string]string{"NewMACAddress": "AA:BB:CC:DD:EE:FF"}},
			{ID: "host-by-ip", ServiceType: ServiceHosts.Type, ControlURL: ServiceHosts.ControlURL, Action: "X_AVM-DE_GetSpecificHostEntryByIP", Args: map[string]string{"NewIPAddress": "192.168.188.40"}},
			{ID: "wake-on-lan", ServiceType: ServiceHosts.Type, ControlURL: ServiceHosts.ControlURL, Action: "X_AVM-DE_WakeOnLANByMACAddress", Args: map[string]string{"NewMACAddress": "AA:BB:CC:DD:EE:FF"}},
			{ID: "guest-set-enable", ServiceType: wlanService(3).Type, ControlURL: wlanService(3).ControlURL, Action: "SetEnable", Args: map[string]string{"NewEnable": "1"}},
		},
		Negative: []portCapabilityNegative{
			{ID: "empty-host-name", Input: "", Message: "no host named \"\" in the FRITZ!Box host table"},
			{ID: "duplicate-host-name", Input: "duplicate", Message: "2 hosts named \"duplicate\"; use --mac or --ip to disambiguate"},
			{ID: "empty-mesh-path", Input: "", Message: "box returned no mesh list path (unsupported firmware?)"},
		},
	}

	got, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := portCapabilitiesCoreFixturePath(t)
	if os.Getenv(updatePortFixturesEnv) == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read capabilities-core fixture: %v (regenerate with make port-capabilities-core-fixtures)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("capabilities-core fixture drifted; regenerate deliberately with make port-capabilities-core-fixtures")
	}
}

func portCapabilitiesCoreFixturePath(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve capabilities-core fixture source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "port", "capabilities-core", "contracts.json"))
}
