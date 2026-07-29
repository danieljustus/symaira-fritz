package fritz

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func generateTestCert(t *testing.T) ([]byte, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "fritz.box",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	pin, err := CalculateSPKIPin(certDER)
	if err != nil {
		t.Fatalf("failed to calculate pin: %v", err)
	}
	return certDER, pin
}

func TestPinStore_SaveLoadReset(t *testing.T) {
	tmpDir := t.TempDir()
	pinPath := filepath.Join(tmpDir, "pins.json")

	store := NewPinStore(pinPath)
	host := "fritz.box:49443"

	if pin := store.GetPin(host); pin != "" {
		t.Fatalf("expected empty pin, got %q", pin)
	}

	_, testPin := generateTestCert(t)
	if err := store.SetPin(host, testPin); err != nil {
		t.Fatalf("failed to set pin: %v", err)
	}

	// Verify file mode 0600
	info, err := os.Stat(pinPath)
	if err != nil {
		t.Fatalf("failed to stat pin file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected permissions 0600, got %o", perm)
	}

	// Reload store
	store2 := NewPinStore(pinPath)
	if pin := store2.GetPin(host); pin != testPin {
		t.Errorf("expected pin %q, got %q", testPin, pin)
	}

	// Reset pin
	reset, err := store2.ResetPin(host)
	if err != nil {
		t.Fatalf("failed to reset pin: %v", err)
	}
	if !reset {
		t.Errorf("expected reset true, got false")
	}
	if pin := store2.GetPin(host); pin != "" {
		t.Errorf("expected empty pin after reset, got %q", pin)
	}
}

func TestClient_CertificatePinning(t *testing.T) {
	tmpDir := t.TempDir()
	pinPath := filepath.Join(tmpDir, "pins.json")
	pinStore := NewPinStore(pinPath)

	ts1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetInfoResponse xmlns:u="urn:dslforum-org:service:DeviceInfo:1"></u:GetInfoResponse></s:Body></s:Envelope>`))
	}))
	defer ts1.Close()

	u, err := url.Parse(ts1.URL)
	if err != nil {
		t.Fatalf("failed to parse test server url: %v", err)
	}
	host := u.Host

	client := New(host, WithTLS(false), WithPinStore(pinStore))

	// 1. First contact -> TOFU pin stored
	req, err := http.NewRequest(http.MethodGet, ts1.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	resp, err := client.http.Do(req)
	if err != nil {
		t.Fatalf("expected successful TOFU connection, got %v", err)
	}
	_ = resp.Body.Close()

	recordedPin := pinStore.GetPin(host)
	if recordedPin == "" {
		t.Fatalf("expected recorded pin for %s, got empty", host)
	}

	// 2. Second contact -> pin matches
	resp2, err := client.http.Do(req)
	if err != nil {
		t.Fatalf("expected successful matching pin connection, got %v", err)
	}
	_ = resp2.Body.Close()

	// 3. Different server -> pin mismatch error
	ts2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts2.Close()

	req2, err := http.NewRequest(http.MethodGet, ts2.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request 2: %v", err)
	}
	// Use client configured with ts2's host but pointing to ts1's pin
	client2 := New(u.Host, WithTLS(false), WithPinStore(pinStore))

	// Tamper pin to simulate mismatched cert
	_ = pinStore.SetPin(host, "invalid-pin-base64")

	_, err = client2.http.Do(req2)
	if err == nil {
		t.Fatalf("expected pin mismatch error, got nil")
	}
	var fe *FritzError
	if !errors.As(err, &fe) || fe.Kind != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized FritzError, got %v", err)
	}
	if hint := fe.Hint(); !strings.Contains(hint, "symfritz auth trust --reset") {
		t.Errorf("expected reset hint in error, got %q", hint)
	}

	// 4. Reset pin -> next connection re-pins
	reset, err := pinStore.ResetPin(host)
	if err != nil || !reset {
		t.Fatalf("failed to reset pin: reset=%v err=%v", reset, err)
	}
	resp3, err := client.http.Do(req)
	if err != nil {
		t.Fatalf("expected successful connection after reset, got %v", err)
	}
	_ = resp3.Body.Close()
	if pinStore.GetPin(host) == "" {
		t.Errorf("expected new pin stored after reset")
	}
}
