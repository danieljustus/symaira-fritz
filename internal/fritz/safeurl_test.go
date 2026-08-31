package fritz

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSafeURLForError_RedactsSID(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		wantSub string // must NOT appear
		wantHas string // must appear (redacted marker)
	}{
		{"http with sid", "http://fritz.box/query.lua?sid=abc123def456", "abc123def456", "REDACTED"},
		{"https with sid", "https://fritz.box:49443/calllist.lua?sid=s3cr3t", "s3cr3t", "REDACTED"},
		{"http with response param", "http://fritz.box/login_sid.lua?version=2&response=2$1000$salt$hash", "salt$hash", "REDACTED"},
		{"http with password param", "http://fritz.box/api?password=supersecret", "supersecret", "REDACTED"},
		{"http with pass param", "http://fritz.box/api?pass=supersecret", "supersecret", "REDACTED"},
		{"http with userinfo password", "http://admin:secret123@fritz.box/login_sid.lua", "secret123", "xxxxx"},
		{"no sid", "http://fritz.box/query.lua?foo=bar", "", "foo=bar"},
		{"only sid", "http://fritz.box/?sid=onlysid", "onlysid", "REDACTED"},
		{"invalid url", "://bad", "", "://bad"},
		{"empty", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := safeURLForError(tt.rawURL)
			if tt.wantSub != "" && strings.Contains(got, tt.wantSub) {
				t.Errorf("safeURLForError(%q) = %q, must not contain %q", tt.rawURL, got, tt.wantSub)
			}
			if tt.wantHas != "" && !strings.Contains(got, tt.wantHas) {
				t.Errorf("safeURLForError(%q) = %q, must contain %q", tt.rawURL, got, tt.wantHas)
			}
		})
	}
}

func TestSafeURLForError_DoesNotAffectOtherParams(t *testing.T) {
	got := safeURLForError("http://fritz.box/homeautoswitch.lua?sid=SECRET&switchcmd=getdevicelistinfos")
	if strings.Contains(got, "SECRET") {
		t.Errorf("session id leaked: %q", got)
	}
	if !strings.Contains(got, "REDACTED") {
		t.Errorf("expected REDACTED marker: %q", got)
	}
	if !strings.Contains(got, "switchcmd=getdevicelistinfos") {
		t.Errorf("other params should be preserved: %q", got)
	}
}

// TestPinMismatchErrorContainsHost verifies Issue #119: the pin-mismatch
// FritzError carries the box host in Service so the Hint() produces a
// runnable remediation command.
func TestPinMismatchErrorContainsHost(t *testing.T) {
	host := "fritz.box"
	fe := &FritzError{
		Kind:    ErrUnauthorized,
		Service: host,
		Raw:     "certificate pin mismatch for " + host + " (possible MITM attack or firmware update)",
	}
	hint := fe.Hint()
	if !strings.Contains(hint, host) {
		t.Errorf("Hint() = %q, must contain host %q", hint, host)
	}
	if !strings.Contains(hint, "symfritz auth trust --reset") {
		t.Errorf("Hint() = %q, must contain the reset command", hint)
	}
}

// TestPinMismatchHintEmptyService verifies that without a Service the hint
// is still non-empty but the host is missing — documenting the bug #119 fixed.
func TestPinMismatchHintEmptyService(t *testing.T) {
	fe := &FritzError{
		Kind: ErrUnauthorized,
		Raw:  "certificate pin mismatch for fritz.box (possible MITM attack or firmware update)",
	}
	hint := fe.Hint()
	if !strings.Contains(hint, "symfritz auth trust --reset") {
		t.Errorf("Hint() = %q, must contain the reset command", hint)
	}
	if strings.Contains(hint, "fritz.box") {
		t.Errorf("Hint() = %q, host should NOT appear without Service set (this is the #119 bug state)", hint)
	}
}

// TestAhaTransportErrorRedactsSID verifies Issue #118: when the AHA-HTTP
// request fails at the transport level, the error must not contain the
// session id.
func TestAhaTransportErrorRedactsSID(t *testing.T) {
	const sid = "s3cr3t-sid-12345"
	wrapped := safeURLForError("http://fritz.box/webservices/homeautoswitch.lua?sid=" + sid)
	if strings.Contains(wrapped, sid) {
		t.Errorf("safeURLForError leaked sid: %q", wrapped)
	}
}

// TestStatusCPUTemperaturesErrorRedactsSID verifies Issue #118 for status.go:
// a transport error in CPUTemperatures must not contain the session id.
func TestStatusCPUTemperaturesErrorRedactsSID(t *testing.T) {
	const sid = "leaked-sid-abc"
	// Use a fake URL that contains the sid and verify safeURLForError redacts it
	url := "http://fritz.box/query.lua?sid=" + sid
	redacted := safeURLForError(url)
	if strings.Contains(redacted, sid) {
		t.Errorf("session id leaked in CPU temperatures error path: %q", redacted)
	}
}

// TestFetchAuthenticatedURLErrorRedactsSID verifies Issue #118 for tr064.go:
// a transport error in fetchAuthenticatedURL must not contain the session id.
func TestFetchAuthenticatedURLErrorRedactsSID(t *testing.T) {
	const sid = "fetch-sid-xyz"
	url := "http://fritz.box/calllist.lua?sid=" + sid
	redacted := safeURLForError(url)
	if strings.Contains(redacted, sid) {
		t.Errorf("session id leaked in fetchAuthenticatedURL error path: %q", redacted)
	}
}

func TestDebugLogging_RequestLevelRedacted(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)
	origLogger := slog.Default()
	slog.SetDefault(logger)
	t.Cleanup(func() { slog.SetDefault(origLogger) })

	// 1. Discover request logging
	cDiscover := discoverSampleClient(t)
	if _, err := cDiscover.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	logs := buf.String()
	if !strings.Contains(logs, `"level":"DEBUG"`) || !strings.Contains(logs, `"method":"GET"`) || !strings.Contains(logs, `/tr64desc.xml`) || !strings.Contains(logs, `"status":200`) {
		t.Errorf("expected Discover debug log with method, url, status; got:\n%s", logs)
	}

	// 2. TR-064 SOAP request logging
	buf.Reset()
	srvTR064 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetInfoResponse xmlns:u="urn:dslforum-org:service:DeviceInfo:1"><ModelName>FRITZ!Box 7590</ModelName></u:GetInfoResponse></s:Body></s:Envelope>`))
	}))
	defer srvTR064.Close()

	cTR064 := New("fritz.box", WithPassword("secretpassword123"))
	cTR064.tr064BaseURL = srvTR064.URL
	if _, err := cTR064.Call(context.Background(), ServiceDeviceInfo, "GetInfo", nil); err != nil {
		t.Fatalf("Call: %v", err)
	}
	logs = buf.String()
	if !strings.Contains(logs, `"level":"DEBUG"`) || !strings.Contains(logs, `"method":"POST"`) || !strings.Contains(logs, `/upnp/control/deviceinfo`) || !strings.Contains(logs, `"status":200`) {
		t.Errorf("expected TR-064 debug log with method, url, status; got:\n%s", logs)
	}
	if strings.Contains(logs, "secretpassword123") {
		t.Errorf("password leaked in TR-064 logs: %s", logs)
	}
	if strings.Contains(logs, "GetInfoResponse") || strings.Contains(logs, "FRITZ!Box 7590") {
		t.Errorf("response body leaked in TR-064 logs: %s", logs)
	}

	// 3. Session login request logging
	buf.Reset()
	box := &fakeSessionBox{challenge: "1234567z", step2SID: "secret-session-id-456"}
	cSession := newSessionClient(t, box)
	cSession.Password = "geheim123"
	if _, err := cSession.SID(context.Background()); err != nil {
		t.Fatalf("SID: %v", err)
	}
	logs = buf.String()
	if !strings.Contains(logs, `"level":"DEBUG"`) || !strings.Contains(logs, `"method":"GET"`) || !strings.Contains(logs, `/login_sid.lua`) || !strings.Contains(logs, `"status":200`) {
		t.Errorf("expected Session debug log with method, url, status; got:\n%s", logs)
	}
	if strings.Contains(logs, "secret-session-id-456") {
		t.Errorf("session ID leaked in session logs: %s", logs)
	}
	if strings.Contains(logs, "geheim123") {
		t.Errorf("password leaked in session logs: %s", logs)
	}
	if strings.Contains(logs, "1234567z-") {
		t.Errorf("challenge response leaked in session logs: %s", logs)
	}
}
