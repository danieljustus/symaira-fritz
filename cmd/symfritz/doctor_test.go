package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestDoctorCmdDiscoveryFailureAppendsReason(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SYMFRITZ_PASSWORD", "pw")
	writeDoctorConfig(t, home)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tr64desc.xml" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	stubDoctorClient(t, srv.URL)

	cmd := newRootCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"doctor", "--output", "json"})
	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("doctor should fail when discovery fails")
	}

	var report doctorReport
	if err := json.Unmarshal([]byte(out.String()), &report); err != nil {
		t.Fatalf("doctor output is not JSON: %v\n%s", err, out.String())
	}
	if report.Healthy {
		t.Error("expected report.Healthy = false")
	}

	var foundReachable, foundTR064 bool
	for _, check := range report.Checks {
		if check.Name == "box reachable" {
			foundReachable = true
			if check.Status != "fail" {
				t.Errorf("box reachable status = %q, want fail", check.Status)
			}
			if !strings.Contains(check.Detail, "HTTP 500") {
				t.Errorf("box reachable detail %q should contain HTTP 500", check.Detail)
			}
		}
		if check.Name == "TR-064 enabled" {
			foundTR064 = true
			if check.Status != "fail" {
				t.Errorf("TR-064 enabled status = %q, want fail", check.Status)
			}
			if !strings.Contains(check.Detail, "HTTP 500") {
				t.Errorf("TR-064 enabled detail %q should contain HTTP 500", check.Detail)
			}
		}
	}
	if !foundReachable || !foundTR064 {
		t.Errorf("missing checks: reachable=%v, tr064=%v", foundReachable, foundTR064)
	}
}

func TestDoctorCmdSessionLoginFailureAppendsReason(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SYMFRITZ_PASSWORD", "pw")
	writeDoctorConfig(t, home)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tr64desc.xml":
			_, _ = w.Write([]byte(tr64descXML))
		case "/login_sid.lua":
			_, _ = w.Write([]byte(`<SessionInfo><SID>0000000000000000</SID><Challenge>1234567z</Challenge><BlockTime>60</BlockTime></SessionInfo>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	stubDoctorClient(t, srv.URL)

	cmd := newRootCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"doctor", "--output", "json"})
	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("doctor should fail when session login fails")
	}

	var report doctorReport
	if err := json.Unmarshal([]byte(out.String()), &report); err != nil {
		t.Fatalf("doctor output is not JSON: %v\n%s", err, out.String())
	}
	if report.Healthy {
		t.Error("expected report.Healthy = false")
	}

	var foundSession, foundReachable bool
	for _, check := range report.Checks {
		if check.Name == "box reachable" {
			foundReachable = true
			if check.Status != "ok" {
				t.Errorf("box reachable status = %q, want ok", check.Status)
			}
		}
		if check.Name == "session login" {
			foundSession = true
			if check.Status != "fail" {
				t.Errorf("session login status = %q, want fail", check.Status)
			}
			if !strings.Contains(check.Detail, "rate-limiting for 60s") {
				t.Errorf("session login detail %q should contain failure reason (rate-limiting for 60s)", check.Detail)
			}
		}
	}
	if !foundReachable || !foundSession {
		t.Errorf("missing checks: reachable=%v, session=%v", foundReachable, foundSession)
	}
}

func TestDoctorCmdCredentialFailureAppendsReason(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SYMFRITZ_PASSWORD", "")
	fakeBin(t, "symvault", "echo 'symvault locked' >&2; exit 1")

	path := filepath.Join(home, ".config", "symfritz", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	toml := "[box]\nhost = \"fritz.box\"\npassword_ref = \"fritz.password\"\n"
	if err := os.WriteFile(path, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"doctor", "--output", "json"})
	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("doctor should fail when credential resolution fails")
	}

	var report doctorReport
	if err := json.Unmarshal([]byte(out.String()), &report); err != nil {
		t.Fatalf("doctor output is not JSON: %v\n%s", err, out.String())
	}
	if report.Healthy {
		t.Error("expected report.Healthy = false")
	}

	var foundCred bool
	for _, check := range report.Checks {
		if check.Name == "credentials" {
			foundCred = true
			if check.Status != "fail" {
				t.Errorf("credentials status = %q, want fail", check.Status)
			}
			if !strings.Contains(check.Detail, "symvault locked") {
				t.Errorf("credentials detail %q should contain 'symvault locked'", check.Detail)
			}
		}
	}
	if !foundCred {
		t.Error("missing credentials check")
	}
}

func TestDoctorCmdNoSecretLeakage(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	const secretPW = "super-secret-password-xyz"
	t.Setenv("SYMFRITZ_PASSWORD", secretPW)
	writeDoctorConfig(t, home)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	stubDoctorClient(t, srv.URL)

	cmd := newRootCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"doctor"})
	_, _ = cmd.ExecuteC()

	if strings.Contains(out.String(), secretPW) {
		t.Errorf("secret password leaked in doctor text output:\n%s", out.String())
	}
}
