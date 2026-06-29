package secret

import (
	"context"
	"errors"
	"testing"
)

// withStubs swaps the backend hooks for the duration of a test.
func withStubs(t *testing.T, symvault func(context.Context, string) (string, error), keychain func(context.Context, string, string) (string, error)) {
	t.Helper()
	origS, origK := symvaultGetFn, keychainGetFn
	symvaultGetFn, keychainGetFn = symvault, keychain
	t.Cleanup(func() { symvaultGetFn, keychainGetFn = origS, origK })
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
