package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-fritz/internal/config"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

func writeDoctorConfig(t *testing.T, home string) {
	t.Helper()
	path := filepath.Join(home, ".config", "symfritz", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(config.DefaultConfigTOML()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func stubDoctorClient(t *testing.T, srvURL string) {
	t.Helper()
	orig := newClientFor
	newClientFor = func(_ config.Box, _ string) *fritz.Client {
		return mockClientURL(srvURL)
	}
	t.Cleanup(func() { newClientFor = orig })
}

func mockClientURL(srvURL string) *fritz.Client {
	c := fritz.New("fritz.box", fritz.WithPassword("pw"))
	c.SetMockURLs(srvURL)
	return c
}

func TestDoctorCmdHealthy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SYMFRITZ_PASSWORD", "pw")
	writeDoctorConfig(t, home)
	srv := homeMockServer(t)
	stubDoctorClient(t, srv.URL)

	cmd := newRootCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"doctor", "--output", "json"})
	if _, err := cmd.ExecuteC(); err != nil {
		t.Fatalf("doctor: %v\n%s", err, out.String())
	}

	var report doctorReport
	if err := json.Unmarshal([]byte(out.String()), &report); err != nil {
		t.Fatalf("doctor output is not JSON: %v\n%s", err, out.String())
	}
	if !report.Healthy {
		t.Errorf("doctor report is unhealthy: %+v", report)
	}
	if report.Host != "fritz.box" {
		t.Errorf("host = %q, want fritz.box", report.Host)
	}
	for _, check := range report.Checks {
		if check.Status == "fail" {
			t.Errorf("unexpected failed check: %+v", check)
		}
	}
}

func TestDoctorCmdMissingConfigFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_PASSWORD", "")

	cmd := newRootCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"doctor"})
	if _, err := cmd.ExecuteC(); err == nil {
		t.Fatal("doctor without config should fail")
	}
	if !strings.Contains(out.String(), "config file") || !strings.Contains(out.String(), "problems detected") {
		t.Errorf("unexpected doctor output:\n%s", out.String())
	}
}

func TestDoctorCmdMalformedConfigFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".config", "symfritz", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[box\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"doctor", "--output", "yaml"})
	if _, err := cmd.ExecuteC(); err == nil {
		t.Fatal("doctor with malformed config should fail")
	}
	if !strings.Contains(out.String(), "name: config parse") || !strings.Contains(out.String(), "healthy: false") {
		t.Errorf("unexpected doctor YAML output:\n%s", out.String())
	}
}
