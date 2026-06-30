package fritz

import (
	"context"
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
