// Package secret resolves the FRITZ!Box password from several backends without
// hard-coupling symfritz to any of them. The resolution order, highest first:
//
//  1. an explicit environment variable (SYMFRITZ_PASSWORD)
//  2. a symvault reference (shell-out to `symvault get`, optional)
//  3. the macOS Keychain (shell-out to `security`, optional)
//  4. a plaintext value from config (discouraged)
//
// symvault and the Keychain are reached via their CLIs, so symfritz has no
// build dependency on either and degrades gracefully when they are absent.
package secret

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Source labels where a resolved password came from.
type Source string

const (
	SourceEnv       Source = "env"
	SourceSymvault  Source = "symvault"
	SourceKeychain  Source = "keychain"
	SourceConfig    Source = "config"
	SourceNone      Source = "none"
	KeychainService        = "symfritz"
)

// ErrNotInstalled is returned when a backend's CLI is not available.
var ErrNotInstalled = errors.New("backend CLI not installed")

// Options describes where to look for the password.
type Options struct {
	EnvVar          string // env var name to check first (e.g. "SYMFRITZ_PASSWORD")
	Ref             string // symvault dotted path, e.g. "fritz.password"
	Keychain        bool   // consult the macOS Keychain
	KeychainAccount string // Keychain account (service is KeychainService)
	Plaintext       string // plaintext fallback from config
}

// Result is a resolved password and where it came from.
type Result struct {
	Password string
	Source   Source
}

// Indirection points so tests can stub the backends.
var (
	symvaultGetFn = symvaultGet
	keychainGetFn = keychainGet
	lookPathFn    = exec.LookPath
)

// Resolve walks the backends in priority order and returns the first hit.
// A configured-but-failing backend (e.g. symvault locked) returns an error
// rather than silently falling through, so the user learns why.
func Resolve(ctx context.Context, opts Options) (Result, error) {
	if opts.EnvVar != "" {
		if v := os.Getenv(opts.EnvVar); v != "" {
			return Result{v, SourceEnv}, nil
		}
	}
	if opts.Ref != "" {
		v, err := symvaultGetFn(ctx, opts.Ref)
		if err != nil {
			return Result{}, fmt.Errorf("symvault get %q: %w", opts.Ref, err)
		}
		return Result{v, SourceSymvault}, nil
	}
	if opts.Keychain {
		v, err := keychainGetFn(ctx, KeychainService, opts.KeychainAccount)
		if err != nil {
			return Result{}, fmt.Errorf("keychain lookup: %w", err)
		}
		return Result{v, SourceKeychain}, nil
	}
	if opts.Plaintext != "" {
		return Result{opts.Plaintext, SourceConfig}, nil
	}
	return Result{"", SourceNone}, nil
}

// SymvaultAvailable reports whether the symvault CLI is on PATH.
func SymvaultAvailable() bool {
	_, err := lookPathFn("symvault")
	return err == nil
}

// KeychainAvailable reports whether the macOS `security` CLI is usable.
func KeychainAvailable() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	_, err := lookPathFn("security")
	return err == nil
}

// symvaultGet shells out to `symvault get <ref> --print` and returns the value.
func symvaultGet(ctx context.Context, ref string) (string, error) {
	if _, err := lookPathFn("symvault"); err != nil {
		return "", fmt.Errorf("%w: symvault", ErrNotInstalled)
	}
	cmd := exec.CommandContext(ctx, "symvault", symvaultGetArgs(ref)...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("%s", msg)
	}
	v := strings.TrimRight(out.String(), "\r\n")
	if v == "" {
		return "", fmt.Errorf("symvault returned an empty value for %q", ref)
	}
	return v, nil
}

// SymvaultSet stores value at ref by piping it to `symvault set <ref>` over
// stdin, so the secret never appears in the process argument list.
func SymvaultSet(ctx context.Context, ref, value string) error {
	if _, err := lookPathFn("symvault"); err != nil {
		return fmt.Errorf("%w: symvault", ErrNotInstalled)
	}
	cmd := exec.CommandContext(ctx, "symvault", symvaultSetArgs(ref)...)
	cmd.Stdin = strings.NewReader(symvaultSetPayload(value))
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := redactSecretOutput(strings.TrimSpace(errb.String()), value)
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("symvault set %q: %s", ref, msg)
	}
	return nil
}

// keychainGet reads a password from the macOS Keychain.
func keychainGet(ctx context.Context, service, account string) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("%w: keychain is macOS-only", ErrNotInstalled)
	}
	if _, err := lookPathFn("security"); err != nil {
		return "", fmt.Errorf("%w: security", ErrNotInstalled)
	}
	args := keychainGetArgs(service, account)
	cmd := exec.CommandContext(ctx, "security", args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("keychain entry not found (service %q account %q)", service, account)
	}
	return strings.TrimRight(out.String(), "\r\n"), nil
}

// KeychainSet stores a password in the macOS Keychain, updating any existing
// entry for the same service/account.
func KeychainSet(ctx context.Context, service, account, value string) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("%w: keychain is macOS-only", ErrNotInstalled)
	}
	if _, err := lookPathFn("security"); err != nil {
		return fmt.Errorf("%w: security", ErrNotInstalled)
	}
	// Run security in interactive mode and send a hex-encoded value through
	// stdin. The secret never appears in the process argument list.
	args := keychainSetArgs()
	cmd := exec.CommandContext(ctx, "security", args...)
	cmd.Stdin = strings.NewReader(keychainSetPayload(service, account, value))
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := redactSecretOutput(strings.TrimSpace(errb.String()), value)
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("keychain store failed: %s", msg)
	}
	return nil
}

func symvaultGetArgs(ref string) []string {
	return []string{"get", ref, "--print"}
}

func symvaultSetArgs(ref string) []string {
	return []string{"set", ref, "--stdin-value"}
}

func symvaultSetPayload(value string) string {
	return value + "\n"
}

func keychainGetArgs(service, account string) []string {
	args := []string{"find-generic-password", "-s", service, "-w"}
	if account != "" {
		args = append(args, "-a", account)
	}
	return args
}

func keychainSetArgs() []string {
	return []string{"-i", "-q"}
}

func keychainSetPayload(service, account, value string) string {
	return keychainSetPayloadForKeychain(service, account, value, "")
}

func keychainSetPayloadForKeychain(service, account, value, keychain string) string {
	command := "add-generic-password -U -s " + securityInteractiveQuote(service)
	if account != "" {
		command += " -a " + securityInteractiveQuote(account)
	}
	command += " -X " + hex.EncodeToString([]byte(value))
	if keychain != "" {
		command += " " + securityInteractiveQuote(keychain)
	}
	return command + "\n"
}

func securityInteractiveQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}

func redactSecretOutput(message, secret string) string {
	if secret == "" {
		return message
	}
	message = strings.ReplaceAll(message, secret, "REDACTED")
	hexSecret := hex.EncodeToString([]byte(secret))
	message = strings.ReplaceAll(message, hexSecret, "REDACTED")
	return strings.ReplaceAll(message, strings.ToUpper(hexSecret), "REDACTED")
}
