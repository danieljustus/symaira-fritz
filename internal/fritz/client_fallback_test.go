package fritz

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"
)

func TestClient_HTTPFallback_TR064(t *testing.T) {
	// Start an HTTP server representing the plain TR-064 port (49000).
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tr64desc.xml" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0"?><root xmlns="urn:dslforum-org:device-1-0"><device><deviceType>urn:dslforum-org:device:InternetGatewayDevice:1</deviceType><serviceList><service><serviceType>urn:dslforum-org:service:DeviceInfo:1</serviceType><controlURL>/upnp/control/deviceinfo</controlURL></service></serviceList></device></root>`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer httpSrv.Close()

	u, err := url.Parse(httpSrv.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	httpHost, httpPort, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}

	var warnBuf bytes.Buffer

	// Configure client with UseTLS enabled on a private IP.
	client := New("192.168.178.1", WithTLS(false), WithWarnWriter(&warnBuf))

	// Direct 49443 requests to connection refused and 49000 requests to the HTTP server.
	client.http.Transport = &fallbackTransport{
		client: client,
		baseTransport: &http.Transport{
			DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				_, p, _ := net.SplitHostPort(addr)
				if p == "49443" {
					return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
				}
				return net.Dial(network, net.JoinHostPort(httpHost, httpPort))
			},
		},
	}

	// 1. Initial request (Discover) - TLS 49443 fails to connect, falls back to 49000.
	services, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("expected successful fallback, got err: %v", err)
	}
	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}

	// Verify warning was emitted and names use_tls.
	warnOutput := warnBuf.String()
	if !strings.Contains(warnOutput, "warning:") || !strings.Contains(warnOutput, "use_tls") {
		t.Errorf("expected warning naming use_tls, got %q", warnOutput)
	}

	// Verify client state was updated to UseTLS = false.
	if client.UseTLS {
		t.Errorf("expected client.UseTLS to be false after fallback, got true")
	}

	// 2. Second request - should use HTTP directly without emitting another warning.
	warnBuf.Reset()
	services2, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("second discover failed: %v", err)
	}
	if len(services2) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services2))
	}
	if warnBuf.Len() > 0 {
		t.Errorf("expected no additional warning, got %q", warnBuf.String())
	}
}

func TestClient_HTTPFallback_SessionLogin(t *testing.T) {
	// Start an HTTP server representing the plain HTTP port 80.
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/login_sid.lua") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<SessionInfo><SID>0123456789abcdef</SID><Challenge></Challenge></SessionInfo>`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer httpSrv.Close()

	u, err := url.Parse(httpSrv.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	httpHost, httpPort, _ := net.SplitHostPort(u.Host)

	var warnBuf bytes.Buffer

	client := New("192.168.178.1", WithPassword("pw"), WithTLS(false), WithWarnWriter(&warnBuf))
	client.http.Transport = &fallbackTransport{
		client: client,
		baseTransport: &http.Transport{
			DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				_, p, _ := net.SplitHostPort(addr)
				if p == "443" {
					return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
				}
				return net.Dial(network, net.JoinHostPort(httpHost, httpPort))
			},
		},
	}

	sid, err := client.SID(context.Background())
	if err != nil {
		t.Fatalf("expected successful session login via fallback, got err: %v", err)
	}
	if sid != "0123456789abcdef" {
		t.Errorf("expected sid 0123456789abcdef, got %q", sid)
	}

	warnOutput := warnBuf.String()
	if !strings.Contains(warnOutput, "warning:") || !strings.Contains(warnOutput, "use_tls") {
		t.Errorf("expected warning naming use_tls, got %q", warnOutput)
	}
}

func TestClient_NoFallbackOnPinMismatch(t *testing.T) {
	// TLS server with a certificate
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<?xml version="1.0"?><root xmlns="urn:dslforum-org:device-1-0"><device><deviceType>urn:dslforum-org:device:InternetGatewayDevice:1</deviceType></device></root>`))
	}))
	defer tlsSrv.Close()

	u, err := url.Parse(tlsSrv.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}

	tmpDir := t.TempDir()
	pinStore := NewPinStore(tmpDir + "/pins.json")
	// Store wrong pin
	_ = pinStore.SetPin(u.Host, "mismatched-pin")

	var warnBuf bytes.Buffer
	client := New(u.Host, WithTLS(false), WithPinStore(pinStore), WithWarnWriter(&warnBuf))

	req, err := http.NewRequest(http.MethodGet, tlsSrv.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	_, err = client.http.Do(req)
	if err == nil {
		t.Fatal("expected error on pin mismatch, got nil")
	}

	var fe *FritzError
	if !errors.As(err, &fe) || fe.Kind != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized FritzError, got %v", err)
	}

	// Warning about use_tls fallback should NOT be emitted because TLS is answering
	if strings.Contains(warnBuf.String(), "falling back to HTTP") {
		t.Errorf("did not expect fallback warning on pin mismatch, got %q", warnBuf.String())
	}
}
