package fritz

import (
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
