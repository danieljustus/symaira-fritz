package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-corekit/exitcodes"
)

func TestScrapeCmdRejectsHTMLLoginPageAsStructuredError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login_sid.lua":
			_, _ = io.WriteString(w, `<?xml version="1.0"?><SessionInfo><SID>0123456789abcdef</SID><Challenge>x</Challenge><BlockTime>0</BlockTime></SessionInfo>`)
		case "/data.lua":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, `<!DOCTYPE html><html><head><title>FRITZ!Box</title></head><body>Login</body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	stubNewClient(t, srv)

	cmd := newRootCmd()
	cmd.SetArgs([]string{"scrape", "overview", "--json"})
	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("scrape returned success for an HTML login page")
	}
	if code := exitcodes.ExitCodeFromError(err); code == 0 {
		t.Fatalf("exit code = %d, want non-zero", code)
	}

	raw, marshalErr := json.Marshal(errorPayload(err))
	if marshalErr != nil {
		t.Fatalf("marshal error payload: %v", marshalErr)
	}
	var payload struct {
		Error struct {
			Kind    string `json:"kind"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if unmarshalErr := json.Unmarshal(raw, &payload); unmarshalErr != nil {
		t.Fatalf("unmarshal error payload: %v", unmarshalErr)
	}
	if payload.Error.Kind != "unavailable" {
		t.Errorf("error kind = %q, want unavailable", payload.Error.Kind)
	}
	for _, want := range []string{"HTML login page", "symfritz auth test"} {
		if !strings.Contains(payload.Error.Message, want) {
			t.Errorf("structured error message = %q, want %q", payload.Error.Message, want)
		}
	}
}
