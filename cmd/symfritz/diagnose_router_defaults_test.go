package main

import (
	"strings"
	"testing"
)

func TestRunDiagnoseRouter_DefaultProbesAreRouterSpecific(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SYMFRITZ_HOST", "127.0.0.1")
	srv := diagnoseMockServer(t)
	stubNewClient(t, srv)

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"diagnose", "router"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("diagnose router: %v", err)
		}
	})

	for _, want := range []string{
		"TCP 49000 (TR-064 HTTP)",
		"TCP 49443 (TR-064 HTTPS)",
		"TCP 80 (web UI HTTP)",
		"TCP 443 (web UI HTTPS)",
		"Result: reachable (no failed checks)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	for _, unexpected := range []string{"SSH 22", "VNC/Screen Sharing", "Paperless"} {
		if strings.Contains(out, unexpected) {
			t.Errorf("router diagnosis used generic host probe %q:\n%s", unexpected, out)
		}
	}
}
