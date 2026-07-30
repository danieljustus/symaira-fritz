package fritz

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tr64desc.xml" {
			_, _ = io.WriteString(w, tr64descSample)
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
	c := discoverClient(t)
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

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return string(data)
}

func discoverClientWithFixture(t *testing.T, content string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tr64desc.xml" {
			_, _ = io.WriteString(w, content)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	c := New("fritz.box")
	c.tr064BaseURL = srv.URL
	return c
}

func TestDiscover_RealFixture_Count(t *testing.T) {
	fixture := readTestdata(t, "tr64desc.xml")
	c := discoverClientWithFixture(t, fixture)
	services, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	// The fixture defines 15 services across several nesting levels.
	want := 15
	if len(services) != want {
		t.Fatalf("want %d services, got %d", want, len(services))
	}
}

func TestServiceByName_RealFixture_Unique(t *testing.T) {
	fixture := readTestdata(t, "tr64desc.xml")
	c := discoverClientWithFixture(t, fixture)
	svc, err := c.ServiceByName(context.Background(), "Hosts")
	if err != nil {
		t.Fatalf("ServiceByName(Hosts): %v", err)
	}
	if want := "/upnp/control/hosts"; svc.ControlURL != want {
		t.Errorf("Hosts controlURL = %q, want %q", svc.ControlURL, want)
	}
}

func TestServiceByName_RealFixture_Ambiguous(t *testing.T) {
	fixture := readTestdata(t, "tr64desc.xml")
	c := discoverClientWithFixture(t, fixture)
	// WANIPConnection:1 and :2 both match "IPConnection", but ":ipconnection:"
	// is NOT a substring of either (it's embedded in ":wanipconnection:"),
	// so the tiebreak fails → "be more specific".
	_, err := c.ServiceByName(context.Background(), "IPConnection")
	if err == nil {
		t.Fatal("expected error for ambiguous IPConnection, got nil")
	}
	if !strings.Contains(err.Error(), "be more specific") {
		t.Errorf("error %q should contain \"be more specific\"", err)
	}
}

func TestServiceByName_RealFixture_ExactTieBreak(t *testing.T) {
	fixture := readTestdata(t, "tr64desc.xml")
	c := discoverClientWithFixture(t, fixture)
	// Both WANIPConnection:1 and WANIPConnection:2 match "WANIPConnection",
	// but the tiebreak prefers ":wanipconnection:" which matches the first one.
	svc, err := c.ServiceByName(context.Background(), "WANIPConnection")
	if err != nil {
		t.Fatalf("ServiceByName(WANIPConnection): %v", err)
	}
	// Should return the first matching control URL.
	if svc.ControlURL == "" {
		t.Error("expected non-empty control URL from tiebreak match")
	}
}

func TestServiceByName_RealFixture_NoMatch(t *testing.T) {
	fixture := readTestdata(t, "tr64desc.xml")
	c := discoverClientWithFixture(t, fixture)
	_, err := c.ServiceByName(context.Background(), "NonExistentService")
	if err == nil {
		t.Fatal("expected error for unknown service")
	}
}
func TestServiceByName(t *testing.T) {
	c := discoverClient(t)
	svc, err := c.ServiceByName(context.Background(), "Hosts")
	if err != nil {
		t.Fatalf("ServiceByName: %v", err)
	}
	if svc.ControlURL != "/upnp/control/hosts" {
		t.Errorf("got %q", svc.ControlURL)
	}
	if _, err := c.ServiceByName(context.Background(), "NoSuchService"); err == nil {
		t.Error("expected error for unknown service")
	}
}
