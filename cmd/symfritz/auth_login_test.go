package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubPromptHidden points the terminal seams (termIsTerminal, readPassword) at
// canned values so the interactive login flow can be tested without a real PTY.
func stubPromptHidden(t *testing.T, isTerm bool, pwd []byte, err error) {
	t.Helper()
	origTerm := termIsTerminal
	termIsTerminal = func(int) bool { return isTerm }
	origRead := readPassword
	readPassword = func(int) ([]byte, error) { return pwd, err }
	t.Cleanup(func() {
		termIsTerminal = origTerm
		readPassword = origRead
	})
}

func TestAuthLoginCmd_Success(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_PASSWORD", "")
	stubPromptHidden(t, true, []byte("secret"), nil)
	srv := authMockServer(t, "0123456789abcdef", true)
	stubNewClientFor(t, srv)
	fakeBin(t, "symvault", "exit 0")

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"auth", "login", "--symvault", "fritz.password"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("auth login: %v", err)
		}
	})

	for _, want := range []string{"Verified: web login", "Stored in symvault"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestAuthLoginCmd_WrongPassword(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_PASSWORD", "")
	stubPromptHidden(t, true, []byte("wrong"), nil)
	srv := authMockServer(t, "0000000000000000", false)
	stubNewClientFor(t, srv)

	marker := filepath.Join(t.TempDir(), "symvault-called")
	fakeBin(t, "symvault", "echo called > "+marker)

	cmd := newRootCmd()
	cmd.SetArgs([]string{"auth", "login", "--symvault", "fritz.password"})
	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "box rejected the password") {
		t.Errorf("error = %q, want box-rejected message", err.Error())
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Error("symvault store was invoked despite rejected password")
	}
}

func TestAuthLoginCmd_StoreFailure(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_PASSWORD", "")
	stubPromptHidden(t, true, []byte("secret"), nil)
	srv := authMockServer(t, "0123456789abcdef", true)
	stubNewClientFor(t, srv)
	fakeBin(t, "symvault", "exit 1")

	cmd := newRootCmd()
	cmd.SetArgs([]string{"auth", "login", "--symvault", "fritz.password"})
	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "store failed") {
		t.Errorf("error = %q, want store-failed message", err.Error())
	}
}

func TestAuthLoginCmd_PromptCancel(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_PASSWORD", "")
	stubPromptHidden(t, true, nil, io.EOF)

	cmd := newRootCmd()
	cmd.SetArgs([]string{"auth", "login"})
	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "reading password") {
		t.Errorf("error = %q, want reading-password message", err.Error())
	}
}

func TestAuthLoginCmd_EmptyInput(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_PASSWORD", "")
	stubPromptHidden(t, true, []byte(""), nil)

	cmd := newRootCmd()
	cmd.SetArgs([]string{"auth", "login"})
	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "empty password") {
		t.Errorf("error = %q, want empty-password message", err.Error())
	}
}

func TestPromptHidden_HiddenInput(t *testing.T) {
	stubPromptHidden(t, true, []byte("  secret  "), nil)

	var (
		got string
		err error
	)
	stderr := captureStderr(t, func() {
		got, err = promptHidden("FRITZ!Box password: ")
	})
	if err != nil {
		t.Fatalf("promptHidden: %v", err)
	}
	if got != "secret" {
		t.Errorf("promptHidden = %q, want trimmed %q", got, "secret")
	}
	if !strings.Contains(stderr, "FRITZ!Box password: ") {
		t.Errorf("stderr missing prompt text: %q", stderr)
	}
}
