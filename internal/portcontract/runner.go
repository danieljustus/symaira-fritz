// Package portcontract runs migration binaries in isolated environments.
package portcontract

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Result is the raw observable process contract.
type Result struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
	TimedOut bool
}

// Run executes one binary with a fresh HOME/XDG/TMP environment and a timeout.
func Run(binary string, args []string, home string, timeout time.Duration) (Result, error) {
	env, err := IsolatedEnvironment(home)
	if err != nil {
		return Result{}, err
	}

	cmd := exec.Command(binary, args...)
	cmd.Env = env
	configureProcessGroup(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("start %s: %w", binary, err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case waitErr := <-done:
		if waitErr != nil {
			if _, ok := waitErr.(*exec.ExitError); !ok {
				return Result{}, fmt.Errorf("wait for %s: %w", binary, waitErr)
			}
		}
		return Result{
			ExitCode: cmd.ProcessState.ExitCode(),
			Stdout:   stdout.Bytes(),
			Stderr:   stderr.Bytes(),
		}, nil
	case <-timer.C:
		if err := killProcessGroup(cmd); err != nil {
			return Result{}, fmt.Errorf("kill timed-out %s: %w", binary, err)
		}
		<-done
		return Result{
			ExitCode: -1,
			Stdout:   stdout.Bytes(),
			Stderr:   stderr.Bytes(),
			TimedOut: true,
		}, nil
	}
}

// IsolatedEnvironment removes all symfritz inputs and redirects user-writable
// directories so parity runs cannot reach the developer's real configuration.
func IsolatedEnvironment(home string) ([]string, error) {
	dirs := map[string]string{
		"HOME":            home,
		"XDG_CONFIG_HOME": filepath.Join(home, "config"),
		"XDG_CACHE_HOME":  filepath.Join(home, "cache"),
		"XDG_DATA_HOME":   filepath.Join(home, "data"),
		"TMPDIR":          filepath.Join(home, "tmp"),
		"TMP":             filepath.Join(home, "tmp"),
		"TEMP":            filepath.Join(home, "tmp"),
	}
	for _, path := range dirs {
		if err := os.MkdirAll(path, 0700); err != nil {
			return nil, fmt.Errorf("create isolated directory %s: %w", path, err)
		}
	}

	blocked := map[string]bool{
		"HOME": true, "XDG_CONFIG_HOME": true, "XDG_CACHE_HOME": true,
		"XDG_DATA_HOME": true, "TMPDIR": true, "TMP": true, "TEMP": true,
		"LC_ALL": true, "LANG": true, "TZ": true,
	}
	env := make([]string, 0, len(os.Environ())+len(dirs)+3)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "SYMFRITZ_") || blocked[upper] {
			continue
		}
		env = append(env, entry)
	}
	for key, value := range dirs {
		env = append(env, key+"="+value)
	}
	return append(env, "LC_ALL=C", "LANG=C", "TZ=UTC"), nil
}
