package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-fritz/internal/config"
)

// authMockServer serves login_sid.lua and the DeviceInfo GetInfo action. sid
// controls the session login result; tr064OK controls the TR-064 probe.
func authMockServer(t *testing.T, sid string, tr064OK bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login_sid.lua" {
			_, _ = io.WriteString(w, `<SessionInfo><SID>`+sid+`</SID><Challenge></Challenge></SessionInfo>`)
			return
		}
		if strings.Contains(soapAction(r), "DeviceInfo:1#GetInfo") {
			if !tr064OK {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			writeSOAP(w, "GetInfo", "urn:dslforum-org:service:DeviceInfo:1", map[string]string{
				"NewModelName": "FRITZ!Box 7590",
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestVerifyCredential(t *testing.T) {
	ctx := context.Background()
	box := config.Box{Host: "fritz.box"}

	t.Run("session and tr064 ok", func(t *testing.T) {
		srv := authMockServer(t, "0123456789abcdef", true)
		stubNewClientFor(t, srv)
		sOK, tOK := verifyCredential(ctx, box, "pw")
		if !sOK || !tOK {
			t.Errorf("verifyCredential = (%v, %v), want (true, true)", sOK, tOK)
		}
	})

	t.Run("session rejected", func(t *testing.T) {
		srv := authMockServer(t, "0000000000000000", true)
		stubNewClientFor(t, srv)
		sOK, tOK := verifyCredential(ctx, box, "pw")
		if sOK || !tOK {
			t.Errorf("verifyCredential = (%v, %v), want (false, true)", sOK, tOK)
		}
	})

	t.Run("tr064 unavailable", func(t *testing.T) {
		srv := authMockServer(t, "0123456789abcdef", false)
		stubNewClientFor(t, srv)
		sOK, tOK := verifyCredential(ctx, box, "pw")
		if !sOK || tOK {
			t.Errorf("verifyCredential = (%v, %v), want (true, false)", sOK, tOK)
		}
	})
}

func TestStoreCredential(t *testing.T) {
	ctx := context.Background()
	box := config.Box{Host: "fritz.box"}

	t.Run("symvault success", func(t *testing.T) {
		fakeBin(t, "symvault", "exit 0")
		backend, hint, err := storeCredential(ctx, box, "pw", false, "fritz.password")
		if err != nil {
			t.Fatalf("storeCredential: %v", err)
		}
		if backend != "symvault (fritz.password)" {
			t.Errorf("backend = %q, want symvault label", backend)
		}
		if !strings.Contains(hint, "password_ref") {
			t.Errorf("hint = %q, want password_ref hint", hint)
		}
	})

	t.Run("symvault failure", func(t *testing.T) {
		fakeBin(t, "symvault", "exit 1")
		_, _, err := storeCredential(ctx, box, "pw", false, "fritz.password")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "symvault set") {
			t.Errorf("error = %q, want symvault-set message", err.Error())
		}
	})

	t.Run("keychain success", func(t *testing.T) {
		if runtime.GOOS != "darwin" {
			t.Skip("Keychain requires macOS")
		}
		fakeBin(t, "security", "exit 0")
		backend, hint, err := storeCredential(ctx, box, "pw", true, "")
		if err != nil {
			t.Fatalf("storeCredential: %v", err)
		}
		if !strings.Contains(backend, "macOS Keychain") {
			t.Errorf("backend = %q, want keychain label", backend)
		}
		if !strings.Contains(hint, "keychain = true") {
			t.Errorf("hint = %q, want keychain hint", hint)
		}
	})

	t.Run("keychain failure", func(t *testing.T) {
		if runtime.GOOS != "darwin" {
			t.Skip("Keychain requires macOS")
		}
		fakeBin(t, "security", "exit 1")
		_, _, err := storeCredential(ctx, box, "pw", true, "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "keychain store failed") {
			t.Errorf("error = %q, want keychain-store message", err.Error())
		}
	})

	t.Run("no backend available", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		_, _, err := storeCredential(ctx, box, "pw", false, "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "no storage backend available") {
			t.Errorf("error = %q, want no-backend message", err.Error())
		}
	})
}

func TestPromptHidden_NonTerminalStdin(t *testing.T) {
	nonTerminalStdin(t)
	_, err := promptHidden("Password: ")
	if err == nil {
		t.Fatal("expected error for non-terminal stdin, got nil")
	}
	if !strings.Contains(err.Error(), "not a terminal") {
		t.Errorf("error = %q, want not-a-terminal message", err.Error())
	}
}

func TestAuthTestCmd_ValidCredential(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_PASSWORD", "pw")
	srv := authMockServer(t, "0123456789abcdef", true)
	stubNewClientFor(t, srv)

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"auth", "test"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("auth test: %v", err)
		}
	})

	for _, want := range []string{"Credential source: env", "OK: credential is valid."} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestAuthTestCmd_RejectedCredential(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_PASSWORD", "wrong")
	srv := authMockServer(t, "0000000000000000", false)
	stubNewClientFor(t, srv)

	cmd := newRootCmd()
	cmd.SetArgs([]string{"auth", "test"})
	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "credential rejected by box") {
		t.Errorf("error = %q, want rejected message", err.Error())
	}
}

func TestAuthTestCmd_NoCredential(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_PASSWORD", "")

	cmd := newRootCmd()
	cmd.SetArgs([]string{"auth", "test"})
	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no password configured") {
		t.Errorf("error = %q, want no-password message", err.Error())
	}
}

func TestAuthLoginCmd_NonTerminal(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_PASSWORD", "")
	nonTerminalStdin(t)

	cmd := newRootCmd()
	cmd.SetArgs([]string{"auth", "login"})
	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not a terminal") {
		t.Errorf("error = %q, want not-a-terminal message", err.Error())
	}
}

func TestAuthStoreCmd_Symvault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_PASSWORD", "pw")
	fakeBin(t, "symvault", "exit 0")

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"auth", "store", "--symvault", "fritz.password"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("auth store: %v", err)
		}
	})

	if !strings.Contains(out, "Stored in symvault (fritz.password).") {
		t.Errorf("output missing store confirmation:\n%s", out)
	}
}

func TestAuthStoreCmd_EmptyPasswordPrompts(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_PASSWORD", "")
	nonTerminalStdin(t)

	cmd := newRootCmd()
	cmd.SetArgs([]string{"auth", "store"})
	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not a terminal") {
		t.Errorf("error = %q, want not-a-terminal message", err.Error())
	}
}
