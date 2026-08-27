package main

import (
	"strings"
	"testing"
)

func TestGlobalOutputFormats(t *testing.T) {
	t.Run("root json shorthand reaches mesh", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		srv := homeMockServer(t)
		stubNewClient(t, srv)

		var err error
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"--json", "mesh"})
			_, err = cmd.ExecuteC()
		})
		if err != nil {
			t.Fatalf("mesh --json: %v", err)
		}
		if !strings.Contains(out, `"device_name"`) {
			t.Errorf("expected JSON mesh output, got:\n%s", out)
		}
	})

	t.Run("yaml reaches mesh", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		srv := homeMockServer(t)
		stubNewClient(t, srv)

		var err error
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"mesh", "--output", "yaml"})
			_, err = cmd.ExecuteC()
		})
		if err != nil {
			t.Fatalf("mesh --output yaml: %v", err)
		}
		if !strings.Contains(out, "device_name:") || strings.Contains(out, "{") {
			t.Errorf("expected YAML mesh output, got:\n%s", out)
		}
	})

	t.Run("yaml reaches calls", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		srv := phoneMockServer(t)
		stubNewClient(t, srv)

		var err error
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"calls", "--output", "yaml"})
			_, err = cmd.ExecuteC()
		})
		if err != nil {
			t.Fatalf("calls --output yaml: %v", err)
		}
		if !strings.Contains(out, "CallerNumber:") || strings.Contains(out, "DATE") {
			t.Errorf("expected YAML calls output, got:\n%s", out)
		}
	})

	t.Run("yaml reaches log", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		srv := homeMockServer(t)
		stubNewClient(t, srv)

		var err error
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"log", "--output", "yaml"})
			_, err = cmd.ExecuteC()
		})
		if err != nil {
			t.Fatalf("log --output yaml: %v", err)
		}
		if !strings.Contains(out, "Msg:") || strings.Contains(out, "[sys]") {
			t.Errorf("expected YAML log output, got:\n%s", out)
		}
	})

	t.Run("yaml reaches services", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		srv := homeMockServer(t)
		stubNewClientFor(t, srv)

		var err error
		out := captureStdout(t, func() {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"services", "--output", "yaml"})
			_, err = cmd.ExecuteC()
		})
		if err != nil {
			t.Fatalf("services --output yaml: %v", err)
		}
		if !strings.Contains(out, "ControlURL:") {
			t.Errorf("expected YAML services output, got:\n%s", out)
		}
	})

	t.Run("invalid and conflicting formats fail before network access", func(t *testing.T) {
		for name, args := range map[string][]string{
			"invalid":     {"--output", "csv", "mesh"},
			"conflicting": {"--output", "yaml", "--json", "mesh"},
		} {
			t.Run(name, func(t *testing.T) {
				cmd := newRootCmd()
				cmd.SetArgs(args)
				_, err := cmd.ExecuteC()
				if err == nil {
					t.Fatal("expected output-format error")
				}
			})
		}
	})
}

func TestRootHelpDocumentsGlobalOutput(t *testing.T) {
	cmd := newRootCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--help"})
	if _, err := cmd.ExecuteC(); err != nil {
		t.Fatalf("help: %v", err)
	}
	for _, want := range []string{"doctor", "--output", "text|json|yaml", "--json"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("help missing %q:\n%s", want, out.String())
		}
	}
}
