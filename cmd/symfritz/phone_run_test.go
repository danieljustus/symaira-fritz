package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

// phoneMockServer serves the OnTel GetCallList action and the call list
// document it points to, plus the VoIP dial/hangup actions.
func phoneMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login_sid.lua" {
			_, _ = io.WriteString(w, loginSIDXML)
			return
		}
		if r.URL.Path == "/calls/calllist.lua" {
			_, _ = io.WriteString(w, callListXML)
			return
		}
		sa := soapAction(r)
		switch {
		case strings.Contains(sa, "X_AVM-DE_OnTel:1#GetCallList"):
			writeSOAP(w, "GetCallList", "urn:dslforum-org:service:X_AVM-DE_OnTel:1", map[string]string{
				"NewCallListURL": srv.URL + "/calls/calllist.lua",
			})
		case strings.Contains(sa, "X_VoIP:1#X_AVM-DE_DialNumber"):
			writeSOAP(w, "X_AVM-DE_DialNumber", "urn:dslforum-org:service:X_VoIP:1", nil)
		case strings.Contains(sa, "X_VoIP:1#X_AVM-DE_DialHangup"):
			writeSOAP(w, "X_AVM-DE_DialHangup", "urn:dslforum-org:service:X_VoIP:1", nil)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// callListXML is a call list with one incoming (type 1) and one missed (type 2) call.
const callListXML = `<?xml version="1.0"?><CallList><Call><Type>1</Type><Caller>0301234567</Caller><Called></Called><Name>Alice</Name><Date>01.01.26 10:00</Date><Duration>00:05</Duration></Call><Call><Type>2</Type><Caller>0307654321</Caller><Called></Called><Name></Name><Date>01.01.26 11:00</Date><Duration>5</Duration></Call></CallList>`

func TestParseCallType(t *testing.T) {
	tests := []struct {
		in    string
		want  fritz.CallType
		valid bool
	}{
		{"incoming", fritz.CallIncoming, true},
		{"missed", fritz.CallMissed, true},
		{"outgoing", fritz.CallOutgoing, true},
		{"rejected", fritz.CallRejected, true},
		{"all", fritz.CallAll, true},
		{"INCOMING", fritz.CallIncoming, true},
		{"Mixed", 0, false},
		{"bogus", 0, false},
		{"", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseCallType(tt.in)
			if tt.valid && err != nil {
				t.Fatalf("parseCallType(%q) error: %v", tt.in, err)
			}
			if !tt.valid && err == nil {
				t.Fatalf("parseCallType(%q) = %v, want error", tt.in, got)
			}
			if got != tt.want {
				t.Errorf("parseCallType(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestCallTypeStr(t *testing.T) {
	tests := []struct {
		in   fritz.CallType
		want string
	}{
		{fritz.CallIncoming, "incoming"},
		{fritz.CallMissed, "missed"},
		{fritz.CallOutgoing, "outgoing"},
		{fritz.CallRejected, "rejected"},
		{fritz.CallType(99), "unknown"},
		{fritz.CallAll, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := callTypeStr(tt.in); got != tt.want {
				t.Errorf("callTypeStr(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCallsCmd_TextOutput(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := phoneMockServer(t)
	stubNewClient(t, srv)

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"calls"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("calls: %v", err)
		}
	})

	for _, want := range []string{"Alice", "incoming", "missed", "0301234567", "0307654321"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestCallsCmd_TypeFilter(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := phoneMockServer(t)
	stubNewClient(t, srv)

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"calls", "--type", "incoming"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("calls --type: %v", err)
		}
	})

	if !strings.Contains(out, "incoming") {
		t.Errorf("output missing incoming:\n%s", out)
	}
	if strings.Contains(out, "missed") {
		t.Errorf("output should not contain missed calls:\n%s", out)
	}
}

func TestCallsCmd_JSONOutput(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := phoneMockServer(t)
	stubNewClient(t, srv)

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"calls", "--json"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("calls --json: %v", err)
		}
	})

	if !strings.Contains(out, `"CallerNumber": "0301234567"`) {
		t.Errorf("JSON output missing call entry:\n%s", out)
	}
}

func TestCallsCmd_EmptyList(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login_sid.lua" {
			_, _ = io.WriteString(w, loginSIDXML)
			return
		}
		if r.URL.Path == "/calls/calllist.lua" {
			_, _ = io.WriteString(w, `<?xml version="1.0"?><CallList></CallList>`)
			return
		}
		if strings.Contains(soapAction(r), "X_AVM-DE_OnTel:1#GetCallList") {
			writeSOAP(w, "GetCallList", "urn:dslforum-org:service:X_AVM-DE_OnTel:1", map[string]string{
				"NewCallListURL": srv.URL + "/calls/calllist.lua",
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	stubNewClient(t, srv)

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"calls"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("calls: %v", err)
		}
	})

	if !strings.Contains(out, "No calls found.") {
		t.Errorf("output = %q, want empty-list message", out)
	}
}

func TestCallsCmd_InvalidType(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := phoneMockServer(t)
	stubNewClient(t, srv)

	cmd := newRootCmd()
	cmd.SetArgs([]string{"calls", "--type", "bogus"})
	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid call type") {
		t.Errorf("error = %q, want invalid-call-type message", err.Error())
	}
}

func TestCallsCmd_ListError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	stubNewClient(t, srv)

	cmd := newRootCmd()
	cmd.SetArgs([]string{"calls"})
	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "calls failed") {
		t.Errorf("error = %q, want calls-failed message", err.Error())
	}
}

func TestDialCmd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := phoneMockServer(t)
	stubNewClient(t, srv)

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"dial", "0301234567"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("dial: %v", err)
		}
	})

	if !strings.Contains(out, "Dialing 0301234567...") {
		t.Errorf("output = %q, want dialing message", out)
	}
}

func TestDialCmd_Error(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	stubNewClient(t, srv)

	cmd := newRootCmd()
	cmd.SetArgs([]string{"dial", "0301234567"})
	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "dial failed") {
		t.Errorf("error = %q, want dial-failed message", err.Error())
	}
}

func TestHangupCmd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := phoneMockServer(t)
	stubNewClient(t, srv)

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"hangup"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("hangup: %v", err)
		}
	})

	if !strings.Contains(out, "Hanging up...") {
		t.Errorf("output = %q, want hangup message", out)
	}
}

func TestHangupCmd_Error(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	stubNewClient(t, srv)

	cmd := newRootCmd()
	cmd.SetArgs([]string{"hangup"})
	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "hangup failed") {
		t.Errorf("error = %q, want hangup-failed message", err.Error())
	}
}
