package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigInitCmd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	run := func(args ...string) (string, string) {
		t.Helper()
		cmd := newRootCmd()
		var out, errOut string
		out = captureStdout(t, func() {
			errOut = captureStderr(t, func() {
				cmd.SetArgs(args)
				if _, err := cmd.ExecuteC(); err != nil {
					t.Fatalf("%v: %v", args, err)
				}
			})
		})
		return out, errOut
	}

	path := filepath.Join(home, ".config", "symfritz", "config.toml")

	t.Run("writes default config", func(t *testing.T) {
		out, _ := run("config", "init")
		if !strings.Contains(out, "Config written to") {
			t.Errorf("output = %q, want written message", out)
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("config file not written: %v", err)
		}
	})

	t.Run("existing config not overwritten", func(t *testing.T) {
		_, errOut := run("config", "init")
		if !strings.Contains(errOut, "already exists") {
			t.Errorf("stderr = %q, want already-exists message", errOut)
		}
	})

	t.Run("force overwrites", func(t *testing.T) {
		out, _ := run("config", "init", "--force")
		if !strings.Contains(out, "Config written to") {
			t.Errorf("output = %q, want written message", out)
		}
	})
}
