package secret

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// withStubs swaps the backend hooks for the duration of a test.
func withStubs(t *testing.T, symvault func(context.Context, string) (string, error), keychain func(context.Context, string, string) (string, error)) {
	t.Helper()
	origS, origK := symvaultGetFn, keychainGetFn
	symvaultGetFn, keychainGetFn = symvault, keychain
	t.Cleanup(func() { symvaultGetFn, keychainGetFn = origS, origK })
}

// fakeScript creates a temporary executable shell script with the given name
// and body, then prepends its directory to PATH so exec.LookPath and
// exec.CommandContext can find it.
func fakeScript(t *testing.T, name, body string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// stubLookPath replaces lookPathFn for the duration of t and restores it.
func stubLookPath(t *testing.T, fn func(string) (string, error)) {
	t.Helper()
	orig := lookPathFn
	lookPathFn = fn
	t.Cleanup(func() { lookPathFn = orig })
}

func TestResolve_Priority(t *testing.T) {
	ctx := context.Background()

	t.Run("env wins over everything", func(t *testing.T) {
		t.Setenv("SYMFRITZ_PASSWORD", "from-env")
		withStubs(t,
			func(context.Context, string) (string, error) { return "from-vault", nil },
			func(context.Context, string, string) (string, error) { return "from-kc", nil },
		)
		res, err := Resolve(ctx, Options{EnvVar: "SYMFRITZ_PASSWORD", Ref: "x", Keychain: true, Plaintext: "p"})
		if err != nil {
			t.Fatal(err)
		}
		if res.Password != "from-env" || res.Source != SourceEnv {
			t.Errorf("got %+v", res)
		}
	})

	t.Run("symvault before keychain and plaintext", func(t *testing.T) {
		t.Setenv("SYMFRITZ_PASSWORD", "")
		withStubs(t,
			func(_ context.Context, ref string) (string, error) {
				if ref != "fritz.password" {
					t.Errorf("ref = %q", ref)
				}
				return "from-vault", nil
			},
			func(context.Context, string, string) (string, error) { return "from-kc", nil },
		)
		res, err := Resolve(ctx, Options{EnvVar: "SYMFRITZ_PASSWORD", Ref: "fritz.password", Keychain: true, Plaintext: "p"})
		if err != nil {
			t.Fatal(err)
		}
		if res.Password != "from-vault" || res.Source != SourceSymvault {
			t.Errorf("got %+v", res)
		}
	})

	t.Run("keychain before plaintext", func(t *testing.T) {
		t.Setenv("SYMFRITZ_PASSWORD", "")
		withStubs(t, nil,
			func(_ context.Context, svc, acct string) (string, error) {
				if svc != KeychainService {
					t.Errorf("service = %q", svc)
				}
				return "from-kc", nil
			},
		)
		res, err := Resolve(ctx, Options{EnvVar: "SYMFRITZ_PASSWORD", Keychain: true, KeychainAccount: "fritz.box", Plaintext: "p"})
		if err != nil {
			t.Fatal(err)
		}
		if res.Password != "from-kc" || res.Source != SourceKeychain {
			t.Errorf("got %+v", res)
		}
	})

	t.Run("plaintext fallback", func(t *testing.T) {
		t.Setenv("SYMFRITZ_PASSWORD", "")
		res, err := Resolve(ctx, Options{EnvVar: "SYMFRITZ_PASSWORD", Plaintext: "plain"})
		if err != nil {
			t.Fatal(err)
		}
		if res.Password != "plain" || res.Source != SourceConfig {
			t.Errorf("got %+v", res)
		}
	})

	t.Run("nothing configured", func(t *testing.T) {
		t.Setenv("SYMFRITZ_PASSWORD", "")
		res, err := Resolve(ctx, Options{EnvVar: "SYMFRITZ_PASSWORD"})
		if err != nil {
			t.Fatal(err)
		}
		if res.Source != SourceNone {
			t.Errorf("source = %q, want none", res.Source)
		}
	})
}

func TestResolve_BackendErrorSurfaces(t *testing.T) {
	t.Setenv("SYMFRITZ_PASSWORD", "")
	withStubs(t,
		func(context.Context, string) (string, error) { return "", errors.New("vault is locked") },
		nil,
	)
	// A configured-but-failing symvault must error, not silently fall through to
	// the plaintext value.
	_, err := Resolve(context.Background(), Options{EnvVar: "SYMFRITZ_PASSWORD", Ref: "fritz.password", Plaintext: "should-not-be-used"})
	if err == nil {
		t.Fatal("expected error from locked vault")
	}
}

func TestAvailability_RespectsLookPath(t *testing.T) {
	orig := lookPathFn
	t.Cleanup(func() { lookPathFn = orig })

	lookPathFn = func(string) (string, error) { return "", errors.New("not found") }
	if SymvaultAvailable() {
		t.Error("SymvaultAvailable should be false when not on PATH")
	}

	lookPathFn = func(string) (string, error) { return "/usr/bin/symvault", nil }
	if !SymvaultAvailable() {
		t.Error("SymvaultAvailable should be true when on PATH")
	}
}

func TestKeychainAvailable(t *testing.T) {
	t.Run("not darwin returns false", func(t *testing.T) {
		if runtime.GOOS == "darwin" {
			t.Skip("non-darwin only")
		}
		if KeychainAvailable() {
			t.Error("expected false on non-darwin")
		}
	})

	t.Run("lookPathFn fails returns false", func(t *testing.T) {
		if runtime.GOOS != "darwin" {
			t.Skip("darwin only — non-darwin always returns false")
		}
		stubLookPath(t, func(string) (string, error) { return "", errors.New("not found") })
		if KeychainAvailable() {
			t.Error("expected false when security not on PATH")
		}
	})

	t.Run("lookPathFn succeeds returns true", func(t *testing.T) {
		if runtime.GOOS != "darwin" {
			t.Skip("darwin only")
		}
		stubLookPath(t, func(string) (string, error) { return "/usr/bin/security", nil })
		if !KeychainAvailable() {
			t.Error("expected true when security is on PATH")
		}
	})
}

func TestSymvaultGet_NotInstalled(t *testing.T) {
	stubLookPath(t, func(string) (string, error) { return "", errors.New("not found") })
	_, err := symvaultGet(context.Background(), "fritz.password")
	if !errors.Is(err, ErrNotInstalled) {
		t.Errorf("expected ErrNotInstalled, got %v", err)
	}
}

func TestSymvaultGet_Success(t *testing.T) {
	fakeScript(t, "symvault", `echo "secret-value"`)
	v, err := symvaultGet(context.Background(), "fritz.password")
	if err != nil {
		t.Fatal(err)
	}
	if v != "secret-value" {
		t.Errorf("got %q, want %q", v, "secret-value")
	}
}

func TestSymvaultGet_TrimCarriageReturn(t *testing.T) {
	fakeScript(t, "symvault", `printf "value\r\n"`)
	v, err := symvaultGet(context.Background(), "fritz.password")
	if err != nil {
		t.Fatal(err)
	}
	if v != "value" {
		t.Errorf("got %q, want %q", v, "value")
	}
}

func TestSymvaultGet_EmptyValue(t *testing.T) {
	fakeScript(t, "symvault", `printf ""`)
	_, err := symvaultGet(context.Background(), "fritz.password")
	if err == nil {
		t.Error("expected error for empty value")
	}
}

func TestSymvaultGet_CommandFails(t *testing.T) {
	fakeScript(t, "symvault", `echo "permission denied" >&2; exit 1`)
	_, err := symvaultGet(context.Background(), "fritz.password")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("expected error to contain %q, got %v", "permission denied", err)
	}
}

func TestSymvaultSet_NotInstalled(t *testing.T) {
	stubLookPath(t, func(string) (string, error) { return "", errors.New("not found") })
	err := SymvaultSet(context.Background(), "fritz.password", "secret")
	if !errors.Is(err, ErrNotInstalled) {
		t.Errorf("expected ErrNotInstalled, got %v", err)
	}
}

func TestSymvaultSet_Success(t *testing.T) {
	fakeScript(t, "symvault", `cat > /dev/null`)
	err := SymvaultSet(context.Background(), "fritz.password", "secret")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSymvaultSet_Failure(t *testing.T) {
	fakeScript(t, "symvault", `echo "write error" >&2; exit 1`)
	err := SymvaultSet(context.Background(), "fritz.password", "secret")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "write error") {
		t.Errorf("expected error to contain %q, got %v", "write error", err)
	}
}

func TestKeychainGet_NotDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("non-darwin only")
	}
	_, err := keychainGet(context.Background(), "symfritz", "host")
	if !errors.Is(err, ErrNotInstalled) {
		t.Errorf("expected ErrNotInstalled, got %v", err)
	}
}

func TestKeychainGet_SecurityNotOnPath(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin only — non-darwin always returns ErrNotInstalled")
	}
	stubLookPath(t, func(string) (string, error) { return "", errors.New("not found") })
	_, err := keychainGet(context.Background(), "symfritz", "host")
	if !errors.Is(err, ErrNotInstalled) {
		t.Errorf("expected ErrNotInstalled, got %v", err)
	}
}

func TestKeychainGet_Success(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin only")
	}
	fakeScript(t, "security", `echo "password"`)
	v, err := keychainGet(context.Background(), "symfritz", "host")
	if err != nil {
		t.Fatal(err)
	}
	if v != "password" {
		t.Errorf("got %q, want %q", v, "password")
	}
}

func TestKeychainSet_NotDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("non-darwin only")
	}
	err := KeychainSet(context.Background(), "symfritz", "host", "password")
	if !errors.Is(err, ErrNotInstalled) {
		t.Errorf("expected ErrNotInstalled, got %v", err)
	}
}

func TestKeychainSet_SecurityNotOnPath(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin only — non-darwin always returns ErrNotInstalled")
	}
	stubLookPath(t, func(string) (string, error) { return "", errors.New("not found") })
	err := KeychainSet(context.Background(), "symfritz", "host", "password")
	if !errors.Is(err, ErrNotInstalled) {
		t.Errorf("expected ErrNotInstalled, got %v", err)
	}
}

func TestKeychainSet_Success(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin only")
	}
	fakeScript(t, "security", `cat > /dev/null`)
	err := KeychainSet(context.Background(), "symfritz", "host", "password")
	if err != nil {
		t.Fatal(err)
	}
}
