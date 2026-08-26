package fritz

import (
	"context"
	_ "embed"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// tr64descFixture is a redacted capture from the FRITZ!Box used for development.
//
//go:embed testdata/tr64desc.xml
var tr64descFixture []byte

const tr64descSample = `<?xml version="1.0"?>
<root xmlns="urn:dslforum-org:device-1-0">
  <device>
    <deviceType>urn:dslforum-org:device:InternetGatewayDevice:1</deviceType>
    <serviceList>
      <service>
        <serviceType>urn:dslforum-org:service:DeviceInfo:1</serviceType>
        <controlURL>/upnp/control/deviceinfo</controlURL>
      </service>
    </serviceList>
    <deviceList>
      <device>
        <deviceType>urn:dslforum-org:device:LANDevice:1</deviceType>
        <serviceList>
          <service>
            <serviceType>urn:dslforum-org:service:Hosts:1</serviceType>
            <controlURL>/upnp/control/hosts</controlURL>
          </service>
        </serviceList>
      </device>
    </deviceList>
  </device>
</root>`

func discoverClient(t *testing.T) *Client {
	t.Helper()
	return discoverClientWithDescription(t, tr64descFixture)
}

func discoverSampleClient(t *testing.T) *Client {
	t.Helper()
	return discoverClientWithDescription(t, []byte(tr64descSample))
}

func discoverClientWithDescription(t *testing.T, description []byte) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tr64desc.xml" {
			_, _ = w.Write(description)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	c := New("fritz.box")
	c.tr064BaseURL = srv.URL
	return c
}

func TestDiscover_WalksNestedDevices(t *testing.T) {
	c := discoverSampleClient(t)
	services, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(services) != 2 {
		t.Fatalf("want 2 services, got %d: %+v", len(services), services)
	}
	// Sorted by type: DeviceInfo before Hosts.
	if services[0].Type != "urn:dslforum-org:service:DeviceInfo:1" {
		t.Errorf("service[0] = %q", services[0].Type)
	}
	if services[1].ControlURL != "/upnp/control/hosts" {
		t.Errorf("Hosts controlURL = %q", services[1].ControlURL)
	}
}

// TestDiscover_CachesServiceList verifies Issue #127: a second Discover or
// ServiceByName call must not re-fetch /tr64desc.xml.
func TestDiscover_CachesServiceList(t *testing.T) {
	var fetchCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetchCount, 1)
		if r.URL.Path == "/tr64desc.xml" {
			_, _ = w.Write([]byte(tr64descSample))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	c := New("fritz.box")
	c.tr064BaseURL = srv.URL

	// First call fetches.
	_, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if fetchCount != 1 {
		t.Fatalf("after first Discover: fetchCount = %d, want 1", fetchCount)
	}

	// Second call must hit cache.
	_, err = c.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if fetchCount != 1 {
		t.Fatalf("after second Discover: fetchCount = %d, want 1 (cached)", fetchCount)
	}

	// ServiceByName also hits cache.
	_, err = c.ServiceByName(context.Background(), "DeviceInfo")
	if err != nil {
		t.Fatalf("ServiceByName: %v", err)
	}
	if fetchCount != 1 {
		t.Fatalf("after ServiceByName: fetchCount = %d, want 1 (cached)", fetchCount)
	}

	// RefreshDiscovery must re-fetch.
	_, err = c.RefreshDiscovery(context.Background())
	if err != nil {
		t.Fatalf("RefreshDiscovery: %v", err)
	}
	if fetchCount != 2 {
		t.Fatalf("after RefreshDiscovery: fetchCount = %d, want 2", fetchCount)
	}
}

func TestServiceByName(t *testing.T) {
	c := discoverClient(t)
	const servicePrefix = "urn:dslforum-org:service:"

	tests := []struct {
		name       string
		wantType   string
		wantURL    string
		errMessage string
	}{
		{
			name:     "DeviceInfo",
			wantType: servicePrefix + "DeviceInfo:1",
			wantURL:  "/upnp/control/deviceinfo",
		},
		{
			name:     "WLANConfiguration",
			wantType: servicePrefix + "WLANConfiguration:1",
			wantURL:  "/upnp/control/wlanconfig1",
		},
		{
			name:       "X_AVM-DE",
			errMessage: "be more specific",
		},
		{
			name:       "NoSuchService",
			errMessage: "no discovered service matches",
		},
		{
			name:     "WLANConfiguration:2",
			wantType: servicePrefix + "WLANConfiguration:2",
			wantURL:  "/upnp/control/wlanconfig2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, err := c.ServiceByName(context.Background(), tt.name)
			if tt.errMessage != "" {
				if err == nil {
					t.Fatalf("ServiceByName(%q) succeeded: %+v", tt.name, svc)
				}
				if !strings.Contains(err.Error(), tt.errMessage) {
					t.Errorf("ServiceByName(%q) error = %q, want substring %q", tt.name, err, tt.errMessage)
				}
				return
			}
			if err != nil {
				t.Fatalf("ServiceByName(%q): %v", tt.name, err)
			}
			if svc.Type != tt.wantType {
				t.Errorf("ServiceByName(%q) type = %q, want %q", tt.name, svc.Type, tt.wantType)
			}
			if svc.ControlURL != tt.wantURL {
				t.Errorf("ServiceByName(%q) control URL = %q, want %q", tt.name, svc.ControlURL, tt.wantURL)
			}
		})
	}
}
