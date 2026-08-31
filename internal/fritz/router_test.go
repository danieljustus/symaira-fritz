package fritz

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	// Test with a valid TR-064 response using standard UPnP namespace
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

	// Test with a FRITZ!Box-style response using DSL Forum namespace
	fritzBoxServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tr64desc.xml" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, `<?xml version="1.0"?>
<root xmlns="urn:dslforum-org:device-1-0">
  <device>
    <deviceType>urn:dslforum-org:device:InternetGatewayDevice:1</deviceType>
  </device>
</root>`)
	}))
	defer fritzBoxServer.Close()

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
		{"valid TR-064 (UPnP namespace)", validServer, true},
		{"valid TR-064 (DSL Forum namespace)", fritzBoxServer, true},
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
			got := ProbeTR064(context.Background(), httpClient, host, portNum, true)
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
	_, err = DiscoverBox(context.Background(), httpClient, "", true)
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

// fritzBoxTR064Body is the XML body a real FRITZ!Box returns from /tr64desc.xml,
// using the DSL Forum namespace (not the standard UPnP one).
const fritzBoxTR064Body = `<?xml version="1.0"?>
<root xmlns="urn:dslforum-org:device-1-0">
  <device>
    <deviceType>urn:dslforum-org:device:InternetGatewayDevice:1</deviceType>
  </device>
</root>`

func TestDiscoverBox_PublicIPGatewayFallback(t *testing.T) {
	origLookupHost := lookupHost
	origDefaultGateway := defaultGateway
	defer func() {
		lookupHost = origLookupHost
		defaultGateway = origDefaultGateway
	}()

	lookupHost = func(_ context.Context, host string) ([]string, error) {
		if host == "fritz.box" {
			return []string{"212.42.244.122"}, nil
		}
		return nil, fmt.Errorf("unknown host: %s", host)
	}

	defaultGateway = func() (net.IP, error) {
		return net.ParseIP("192.168.188.1"), nil
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tr64desc.xml" {
			w.Header().Set("Content-Type", "text/xml")
			fmt.Fprint(w, fritzBoxTR064Body)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}
	serverHost := u.Hostname()
	serverPort := u.Port()

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				host, _, _ := net.SplitHostPort(addr)
				if host == "192.168.188.1" {
					return net.Dial(network, net.JoinHostPort(serverHost, serverPort))
				}
				return nil, fmt.Errorf("connect: no route to host %s", host)
			},
		},
	}

	ip, err := DiscoverBox(context.Background(), httpClient, "fritz.box", true)
	if err != nil {
		t.Fatalf("DiscoverBox failed: %v", err)
	}
	if ip != "192.168.188.1" {
		t.Errorf("DiscoverBox returned %q, want %q", ip, "192.168.188.1")
	}
}

func TestDiscoverBox_PublicIPCommonIPFallback(t *testing.T) {
	origLookupHost := lookupHost
	origDefaultGateway := defaultGateway
	defer func() {
		lookupHost = origLookupHost
		defaultGateway = origDefaultGateway
	}()

	lookupHost = func(_ context.Context, host string) ([]string, error) {
		if host == "fritz.box" {
			return []string{"212.42.244.122"}, nil
		}
		return nil, fmt.Errorf("unknown host: %s", host)
	}

	defaultGateway = func() (net.IP, error) {
		return nil, fmt.Errorf("no gateway")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tr64desc.xml" {
			w.Header().Set("Content-Type", "text/xml")
			fmt.Fprint(w, fritzBoxTR064Body)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}
	serverHost := u.Hostname()
	serverPort := u.Port()

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				host, _, _ := net.SplitHostPort(addr)
				if host == "192.168.188.1" {
					return net.Dial(network, net.JoinHostPort(serverHost, serverPort))
				}
				return nil, fmt.Errorf("connect: no route to host %s", host)
			},
		},
	}

	ip, err := DiscoverBox(context.Background(), httpClient, "fritz.box", true)
	if err != nil {
		t.Fatalf("DiscoverBox failed: %v", err)
	}
	if ip != "192.168.188.1" {
		t.Errorf("DiscoverBox returned %q, want %q", ip, "192.168.188.1")
	}
}

func TestCheckHostDNS_PublicHost(t *testing.T) {
	// Backup mockable variables
	origLookupHost := lookupHost
	origDefaultGateway := defaultGateway
	defer func() {
		lookupHost = origLookupHost
		defaultGateway = origDefaultGateway
	}()

	// 1. Mock DNS resolution of fritz.box to a public IP
	lookupHost = func(ctx context.Context, host string) ([]string, error) {
		if host == "fritz.box" {
			return []string{"212.42.244.122"}, nil
		}
		return nil, fmt.Errorf("unknown host")
	}

	// 2. Mock default gateway
	defaultGateway = func() (net.IP, error) {
		return net.ParseIP("192.168.188.1"), nil
	}

	// 3. Create a mock TR-064 server running at the default gateway (localhost in test)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tr64desc.xml" {
			w.Header().Set("Content-Type", "text/xml")
			fmt.Fprint(w, fritzBoxTR064Body)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}
	serverHost := u.Hostname()
	serverPort := u.Port()

	// 4. Configure fritz client with a transport that routes requests to the test server
	c := New("fritz.box")
	c.http.Transport = &http.Transport{
		DialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
			return net.Dial(network, net.JoinHostPort(serverHost, serverPort))
		},
	}

	// 5. Run checkHostDNS and verify it returns a helpful error pointing to the gateway (which we mocked)
	err = c.checkHostDNS(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	expectedSub := `Local FRITZ!Box detected at 192.168.188.1. Try setting SYMFRITZ_HOST=192.168.188.1`
	if !strings.Contains(err.Error(), expectedSub) {
		t.Errorf("expected error to contain %q, got: %v", expectedSub, err)
	}
}

func TestAllPublic(t *testing.T) {
	tests := []struct {
		name string
		ips  []string
		want bool
	}{
		{"all private", []string{"192.168.1.1", "10.0.0.1"}, false},
		{"all public", []string{"8.8.8.8", "1.1.1.1"}, true},
		{"mixed", []string{"192.168.1.1", "8.8.8.8"}, false},
		{"empty", nil, true},
		{"unparseable", []string{"not-an-ip"}, true},
		{"localhost", []string{"127.0.0.1"}, true},
		{"link-local", []string{"169.254.1.1"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allPublic(tt.ips); got != tt.want {
				t.Errorf("allPublic(%v) = %v, want %v", tt.ips, got, tt.want)
			}
		})
	}
}

func TestPublicHostHint_FailureAndFallbackPaths(t *testing.T) {
	origLookupHost := lookupHost
	origDefaultGateway := defaultGateway
	t.Cleanup(func() {
		lookupHost = origLookupHost
		defaultGateway = origDefaultGateway
	})

	tests := []struct {
		name       string
		lookup     []string
		lookupErr  error
		gateway    net.IP
		gatewayErr error
		want       string
	}{
		{name: "empty host", want: ""},
		{name: "DNS failure", lookupErr: errors.New("DNS unavailable"), want: ""},
		{name: "no addresses", lookup: []string{}, want: ""},
		{name: "private address", lookup: []string{"192.168.1.1"}, want: ""},
		{
			name:    "public address with gateway",
			lookup:  []string{"8.8.8.8"},
			gateway: net.ParseIP("192.168.1.1"),
			want:    "Hint: public.example resolves to a public IP. Try setting SYMFRITZ_HOST=192.168.1.1",
		},
		{
			name:       "public address without gateway",
			lookup:     []string{"8.8.8.8"},
			gatewayErr: errors.New("gateway unavailable"),
			want:       "Hint: public.example resolves to a public IP. Run 'symfritz detect' to find your FRITZ!Box.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookupHost = func(context.Context, string) ([]string, error) {
				return tt.lookup, tt.lookupErr
			}
			defaultGateway = func() (net.IP, error) {
				return tt.gateway, tt.gatewayErr
			}

			got := publicHostHint(context.Background(), func() string {
				if tt.name == "empty host" {
					return ""
				}
				return "public.example"
			}())
			if got != tt.want {
				t.Errorf("publicHostHint() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCheckHostDNS_FailureAndFallbackPaths(t *testing.T) {
	origLookupHost := lookupHost
	origDefaultGateway := defaultGateway
	t.Cleanup(func() {
		lookupHost = origLookupHost
		defaultGateway = origDefaultGateway
	})

	t.Run("configured endpoint skips DNS", func(t *testing.T) {
		called := false
		lookupHost = func(context.Context, string) ([]string, error) {
			called = true
			return nil, errors.New("lookup should be skipped")
		}
		c := New("public.example")
		c.tr064BaseURL = "http://127.0.0.1:1"
		if err := c.checkHostDNS(context.Background()); err != nil {
			t.Fatalf("checkHostDNS() = %v, want nil", err)
		}
		if called {
			t.Fatal("checkHostDNS performed DNS lookup for configured endpoint")
		}
	})

	t.Run("DNS failure allows HTTP handling", func(t *testing.T) {
		lookupHost = func(context.Context, string) ([]string, error) {
			return nil, errors.New("DNS unavailable")
		}
		c := New("router.example")
		if err := c.checkHostDNS(context.Background()); err != nil {
			t.Fatalf("checkHostDNS() = %v, want nil after DNS failure", err)
		}
	})

	t.Run("empty resolution allows HTTP handling", func(t *testing.T) {
		lookupHost = func(context.Context, string) ([]string, error) { return nil, nil }
		c := New("router.example")
		if err := c.checkHostDNS(context.Background()); err != nil {
			t.Fatalf("checkHostDNS() = %v, want nil for empty resolution", err)
		}
	})

	t.Run("private resolution allows HTTP handling", func(t *testing.T) {
		lookupHost = func(context.Context, string) ([]string, error) {
			return []string{"192.168.1.1"}, nil
		}
		c := New("router.example")
		if err := c.checkHostDNS(context.Background()); err != nil {
			t.Fatalf("checkHostDNS() = %v, want nil for private resolution", err)
		}
	})

	t.Run("public literal uses gateway fallback", func(t *testing.T) {
		defaultGateway = func() (net.IP, error) { return net.ParseIP("192.168.1.1"), nil }
		c := New("8.8.8.8")
		err := c.checkHostDNS(context.Background())
		if err == nil || !strings.Contains(err.Error(), "Local FRITZ!Box detected at 192.168.1.1") {
			t.Fatalf("checkHostDNS() = %v, want gateway detection hint", err)
		}
		if !strings.Contains(err.Error(), "SYMFRITZ_HOST=192.168.1.1") {
			t.Fatalf("checkHostDNS() = %v, want gateway host setting", err)
		}
	})

	t.Run("public literal without gateway uses detect fallback", func(t *testing.T) {
		defaultGateway = func() (net.IP, error) { return nil, errors.New("gateway unavailable") }
		c := New("8.8.8.8")
		err := c.checkHostDNS(context.Background())
		want := "host \"8.8.8.8\" is a public IP. Run 'symfritz detect' to find your FRITZ!Box"
		if err == nil || err.Error() != want {
			t.Fatalf("checkHostDNS() = %v, want %q", err, want)
		}
	})

	t.Run("public hostname discovery failure uses detect fallback", func(t *testing.T) {
		lookupHost = func(context.Context, string) ([]string, error) {
			return []string{"8.8.8.8"}, nil
		}
		defaultGateway = func() (net.IP, error) { return net.ParseIP("192.168.1.1"), nil }
		c := New("router.example")
		c.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("test transport refused connection")
		})

		err := c.checkHostDNS(context.Background())
		if err == nil || !strings.Contains(err.Error(), `host "router.example" resolves to a public IP (8.8.8.8)`) {
			t.Fatalf("checkHostDNS() = %v, want public-host error", err)
		}
	})

	t.Run("empty host uses fritz.box", func(t *testing.T) {
		var gotHost string
		lookupHost = func(_ context.Context, host string) ([]string, error) {
			gotHost = host
			return []string{"192.168.1.1"}, nil
		}
		c := New("router.example")
		c.Host = ""
		if err := c.checkHostDNS(context.Background()); err != nil {
			t.Fatalf("checkHostDNS() = %v, want nil for private default host", err)
		}
		if gotHost != "fritz.box" {
			t.Fatalf("lookup host = %q, want fritz.box", gotHost)
		}
	})

	t.Run("public hostname builds default transport", func(t *testing.T) {
		lookupHost = func(context.Context, string) ([]string, error) {
			return []string{"8.8.8.8"}, nil
		}
		defaultGateway = func() (net.IP, error) { return nil, errors.New("gateway unavailable") }
		c := New("router.example")
		c.http.Transport = nil
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := c.checkHostDNS(ctx)
		if err == nil || !strings.Contains(err.Error(), "Run 'symfritz detect'") {
			t.Fatalf("checkHostDNS() = %v, want detect fallback", err)
		}
	})
}
