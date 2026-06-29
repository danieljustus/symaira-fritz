package fritz

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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
