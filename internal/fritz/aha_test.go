package fritz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestHome_RefreshesSIDOn403 verifies the AHA layer re-logs in once on a 403
// and retries, instead of surfacing a spurious "session expired" error.
func TestHome_RefreshesSIDOn403(t *testing.T) {
	var sidServes, ahaCalls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/login_sid.lua"):
			// Any login attempt returns a valid SID immediately.
			n := atomic.AddInt32(&sidServes, 1)
			_, _ = w.Write([]byte(`<?xml version="1.0"?><SessionInfo><SID>sid` +
				string(rune('0'+n)) + `000000000000</SID><Challenge>x</Challenge><BlockTime>0</BlockTime></SessionInfo>`))
		case strings.HasPrefix(r.URL.Path, "/webservices/homeautoswitch.lua"):
			// First AHA call 403s; the retry (with a refreshed SID) succeeds.
			if atomic.AddInt32(&ahaCalls, 1) == 1 {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte("OK\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := New("fritz.box")
	c.httpBaseURL = srv.URL
	// Seed a cached SID so the first request uses it (and then gets a 403).
	c.sid = "staleSID00000000"

	out, err := c.Home(context.Background(), "getswitchlist", nil)
	if err != nil {
		t.Fatalf("Home returned error despite retry path: %v", err)
	}
	if out != "OK" {
		t.Errorf("output = %q, want OK", out)
	}
	if atomic.LoadInt32(&ahaCalls) != 2 {
		t.Errorf("expected 2 AHA calls (403 then retry), got %d", ahaCalls)
	}
	if atomic.LoadInt32(&sidServes) == 0 {
		t.Error("expected a re-login after the 403")
	}
}
