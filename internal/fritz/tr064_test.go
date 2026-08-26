package fritz

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSoapFaultString_WithDescription(t *testing.T) {
	raw := []byte(`<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError errorcode="402"><errorDescription>Invalid Args</errorDescription></UPnPError></detail></s:Fault>`)
	got := soapFaultString(raw)
	if got != "Invalid Args" {
		t.Errorf("soapFaultString = %q, want %q", got, "Invalid Args")
	}
}

func TestSoapFaultString_NoDescription(t *testing.T) {
	raw := []byte(`<s:Fault><faultcode>s:Client</faultcode><faultstring>No such entry</faultstring></s:Fault>`)
	got := soapFaultString(raw)
	if got != string(raw) {
		t.Errorf("soapFaultString = %q, want raw body", got)
	}
}

func TestSoapFaultString_Truncated(t *testing.T) {
	// Body longer than 200 chars without errorDescription
	raw := []byte(strings.Repeat("x", 300))
	got := soapFaultString(raw)
	if len(got) != 200 {
		t.Errorf("soapFaultString length = %d, want 200", len(got))
	}
}

func TestSoapFaultString_Empty(t *testing.T) {
	got := soapFaultString(nil)
	if got != "" {
		t.Errorf("soapFaultString(nil) = %q, want empty", got)
	}
}

func TestFetchAuthenticatedURL_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "file-content")
	}))
	t.Cleanup(srv.Close)

	c := New("fritz.box")
	c.httpBaseURL = srv.URL

	got, err := c.fetchAuthenticatedURL(context.Background(), srv.URL+"/test")
	if err != nil {
		t.Fatalf("fetchAuthenticatedURL: %v", err)
	}
	if string(got) != "file-content" {
		t.Errorf("got %q, want %q", string(got), "file-content")
	}
}

func TestFetchAuthenticatedURL_UnauthorizedRetry(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="abc", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "authenticated-content")
	}))
	t.Cleanup(srv.Close)

	c := New("fritz.box", WithUser("user"), WithPassword("pass"))
	c.httpBaseURL = srv.URL

	got, err := c.fetchAuthenticatedURL(context.Background(), srv.URL+"/test")
	if err != nil {
		t.Fatalf("fetchAuthenticatedURL: %v", err)
	}
	if string(got) != "authenticated-content" {
		t.Errorf("got %q, want %q", string(got), "authenticated-content")
	}
	if callCount != 2 {
		t.Errorf("callCount = %d, want 2", callCount)
	}
}

func TestFetchAuthenticatedURL_UnauthorizedNoChallenge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		// No WWW-Authenticate header
	}))
	t.Cleanup(srv.Close)

	c := New("fritz.box")
	c.httpBaseURL = srv.URL

	_, err := c.fetchAuthenticatedURL(context.Background(), srv.URL+"/test")
	if err == nil {
		t.Fatal("expected error for 401 without digest challenge")
	}
	if !strings.Contains(err.Error(), "401 without digest challenge") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFetchAuthenticatedURL_NonOKAfterAuth(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="abc", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c := New("fritz.box", WithUser("user"), WithPassword("pass"))
	c.httpBaseURL = srv.URL

	_, err := c.fetchAuthenticatedURL(context.Background(), srv.URL+"/test")
	if err == nil {
		t.Fatal("expected error for HTTP 500 after auth")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFetchAuthenticatedURL_DirectNonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	c := New("fritz.box")
	c.httpBaseURL = srv.URL

	_, err := c.fetchAuthenticatedURL(context.Background(), srv.URL+"/test")
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCall_SOAPFault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError errorcode="402"><errorDescription>Invalid Args</errorDescription></UPnPError></detail></s:Fault>`)
	}))
	t.Cleanup(srv.Close)

	c := New("fritz.box")
	c.tr064BaseURL = srv.URL

	_, err := c.Call(context.Background(), ServiceDeviceInfo, "GetInfo", nil)
	if err == nil {
		t.Fatal("expected error for SOAP fault")
	}
	if !strings.Contains(err.Error(), "Invalid Args") {
		t.Errorf("error should contain fault description, got: %v", err)
	}
}

func TestCall_InvalidActionOnClientError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError errorcode="401"><errorDescription>Invalid Action</errorDescription></UPnPError></detail></s:Fault>`)
	}))
	t.Cleanup(srv.Close)

	c := New("fritz.box")
	c.tr064BaseURL = srv.URL

	_, err := c.Call(context.Background(), ServiceHosts, "X_AVM-DE_GetMeshListPath", nil)
	if err == nil {
		t.Fatal("expected error for Invalid Action")
	}
	if !IsUnsupportedAction(err) {
		t.Errorf("expected unsupported action, got %v", err)
	}
}

func TestCall_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	c := New("fritz.box")
	c.tr064BaseURL = srv.URL

	_, err := c.Call(context.Background(), ServiceHosts, "X_AVM-DE_GetMeshListPath", nil)
	if err == nil {
		t.Fatal("expected error for 401")
	}
	if !IsUnauthorized(err) {
		t.Errorf("expected unauthorized, got %v", err)
	}
}

func TestCall_UnauthorizedNoDigest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		// No WWW-Authenticate header
	}))
	t.Cleanup(srv.Close)

	c := New("fritz.box")
	c.tr064BaseURL = srv.URL

	_, err := c.Call(context.Background(), ServiceDeviceInfo, "GetInfo", nil)
	if err == nil {
		t.Fatal("expected error for 401 without digest challenge")
	}
	if !strings.Contains(err.Error(), "401 without a parseable digest challenge") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCall_NumericErrorCodeClassification(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:dslforum-org:control-1-0"><errorCode>606</errorCode><errorDescription>Aktion nicht autorisiert</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`)
	}))
	t.Cleanup(srv.Close)

	c := New("fritz.box")
	c.tr064BaseURL = srv.URL

	_, err := c.Call(context.Background(), ServiceDeviceInfo, "GetInfo", nil)
	if err == nil {
		t.Fatal("expected error for SOAP fault 606")
	}
	var fe *FritzError
	if !errors.As(err, &fe) {
		t.Fatalf("expected FritzError, got %T", err)
	}
	if fe.ErrorCode != 606 {
		t.Errorf("ErrorCode = %d, want 606", fe.ErrorCode)
	}
	if !IsUnauthorized(err) {
		t.Errorf("expected Kind == ErrUnauthorized for code 606, got %v", fe.Kind)
	}
}

// TestCall_CachedChallengeReducesRoundTrips verifies Issue #122: when a cached
// digest challenge exists, the second Call should reuse the Authorization header
// and issue only ONE HTTP request (not two).
func TestCall_CachedChallengeReducesRoundTrips(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		auth := r.Header.Get("Authorization")
		if auth == "" {
			// First call for this challenge — challenge it.
			w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="abc123", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Authenticated request succeeds.
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetInfoResponse xmlns:u="urn:deviceinfo:1"><SerialNumber>ABC123</SerialNumber></u:GetInfoResponse></s:Body></s:Envelope>`)
	}))
	t.Cleanup(srv.Close)

	c := New("fritz.box", WithUser("user"), WithPassword("pass"))
	c.tr064BaseURL = srv.URL

	// First call: triggers 401 handshake, caches challenge.
	_, err := c.Call(context.Background(), ServiceDeviceInfo, "GetInfo", nil)
	if err != nil {
		t.Fatalf("first Call: %v", err)
	}

	// Second call: should use cached challenge — only 1 request, not 2.
	before := callCount
	_, err = c.Call(context.Background(), ServiceDeviceInfo, "GetInfo", nil)
	if err != nil {
		t.Fatalf("second Call: %v", err)
	}
	after := callCount
	if after != before+1 {
		t.Errorf("second call issued %d requests, want 1 (cached challenge should be reused)", after-before)
	}
}

// TestCachedDigestChallenge_NcIncrements verifies Issue #122: the nc counter
// increments each time the cached challenge is reused.
func TestCachedDigestChallenge_NcIncrements(t *testing.T) {
	c := New("fritz.box", WithUser("user"), WithPassword("pass"))
	dc := digestChallenge{realm: "test", nonce: "n1", qop: "auth"}
	c.setCachedDigestChallenge(dc)

	h1 := c.getCachedDigestAuth("POST", "/ctrl")
	h2 := c.getCachedDigestAuth("POST", "/ctrl")

	// nc should increment: first use is nc=1, second is nc=2
	if !strings.Contains(h1, "nc=00000001") {
		t.Errorf("first cached auth should have nc=1, got: %s", h1)
	}
	if !strings.Contains(h2, "nc=00000002") {
		t.Errorf("second cached auth should have nc=2, got: %s", h2)
	}

	// cnonce should differ between the two (random per request)
	cnonce1 := extractCnonce(h1)
	cnonce2 := extractCnonce(h2)
	if cnonce1 == cnonce2 {
		t.Errorf("cnonce should be random per request, both were %q", cnonce1)
	}
}

func extractCnonce(header string) string {
	for _, part := range strings.Split(header, ", ") {
		if strings.HasPrefix(part, `cnonce="`) {
			return strings.Trim(strings.TrimPrefix(part, `cnonce="`), `"`)
		}
	}
	return ""
}
