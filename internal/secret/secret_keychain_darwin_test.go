//go:build darwin

package secret

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestKeychainSetInteractiveStdinStoresPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "symfritz-test.keychain-db")
	const keychainPassword = "test-keychain-password"
	const storedPassword = "dummy-password-value"

	create := exec.Command("security", "create-keychain", "-p", keychainPassword, path)
	if output, err := create.CombinedOutput(); err != nil {
		t.Fatalf("create temporary keychain: %v: %s", err, output)
	}
	t.Cleanup(func() {
		_ = exec.Command("security", "delete-keychain", path).Run()
	})
	unlock := exec.Command("security", "unlock-keychain", "-p", keychainPassword, path)
	if output, err := unlock.CombinedOutput(); err != nil {
		t.Fatalf("unlock temporary keychain: %v: %s", err, output)
	}

	store := exec.CommandContext(context.Background(), "security", keychainSetArgs()...)
	store.Stdin = bytes.NewBufferString(keychainSetPayloadForKeychain(
		"symfritz-test",
		"test-account",
		storedPassword,
		path,
	))
	if output, err := store.CombinedOutput(); err != nil {
		t.Fatalf("store password through interactive stdin: %v: %s", err, output)
	}

	read := exec.Command("security", "find-generic-password", "-a", "test-account", "-s", "symfritz-test", "-w", path)
	output, err := read.Output()
	if err != nil {
		t.Fatalf("read temporary keychain password: %v", err)
	}
	if got := string(bytes.TrimSpace(output)); got != storedPassword {
		t.Fatalf("stored password = %q, want dummy test value", got)
	}
}
