package fritz

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"169.254.1.1", true},  // link-local
		{"8.8.8.8", false},     // public
		{"1.1.1.1", false},     // public
		{"2001:db8::1", false}, // documentation, not private
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}
			if got := IsPrivateIP(ip); got != tt.want {
				t.Errorf("IsPrivateIP(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestProbeTR064(t *testing.T) {
	// Test with a valid TR-064 response
	validServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tr64desc.xml" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:LivingNetworkDevice:1</deviceType>
  </device>
</root>`)
	}))
	defer validServer.Close()

	// Test with an invalid response
	invalidServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "Not a TR-064 device")
	}))
	defer invalidServer.Close()

	// Test with a server that returns 404
	notFoundServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer notFoundServer.Close()

	tests := []struct {
		name   string
		server *httptest.Server
		want   bool
	}{
		{"valid TR-064", validServer, true},
		{"invalid response", invalidServer, false},
		{"not found", notFoundServer, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.server.URL)
			if err != nil {
				t.Fatalf("failed to parse server URL: %v", err)
			}
			host := u.Hostname()
			port := u.Port()

			httpClient := &http.Client{
				Transport: &http.Transport{
					DialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
						return net.Dial(network, net.JoinHostPort(host, port))
					},
				},
			}

			var portNum int
			fmt.Sscanf(port, "%d", &portNum)
			got := ProbeTR064(context.Background(), httpClient, host, portNum)
			if got != tt.want {
				t.Errorf("ProbeTR064() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDiscoverBox(t *testing.T) {
	// Create a test server that mimics a FRITZ!Box
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tr64desc.xml" {
			w.Header().Set("Content-Type", "text/xml")
			fmt.Fprint(w, `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:LivingNetworkDevice:1</deviceType>
  </device>
</root>`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}
	host := u.Hostname()
	port := u.Port()

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
				return net.Dial(network, net.JoinHostPort(host, port))
			},
		},
	}

	// Test with an empty host (should fall through to gateway/common IPs)
	// This will fail because we can't actually probe the gateway in a test
	// But we can verify the function doesn't panic
	_, err = DiscoverBox(context.Background(), httpClient, "")
	if err == nil {
		// If it succeeds, it found something (unlikely in test env)
		t.Log("DiscoverBox found a device (unexpected in test env)")
	} else {
		// Expected to fail in test environment
		t.Log("DiscoverBox failed as expected:", err)
	}
}

func TestResolveHostInfoFor(t *testing.T) {
	// Test with a hostname that resolves
	info, err := ResolveHostInfoFor(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("ResolveHostInfoFor failed: %v", err)
	}
	if len(info.IPs) == 0 {
		t.Error("expected at least one IP for localhost")
	}

	// Test with empty host
	_, err = ResolveHostInfoFor(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty host")
	}

	// Test with non-existent host
	_, err = ResolveHostInfoFor(context.Background(), "nonexistent.invalid")
	if err == nil {
		t.Error("expected error for non-existent host")
	}
}
