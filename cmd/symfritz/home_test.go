package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-corekit/exitcodes"
	"github.com/danieljustus/symaira-fritz/internal/config"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

func TestHomeList_NoCredentialFailsBeforeLogin(t *testing.T) {
	origNewClient := newClient
	t.Cleanup(func() { newClient = origNewClient })
	newClient = func() (*fritz.Client, *config.Config, error) {
		return fritz.New("fritz.box"), config.Defaults(), nil
	}

	cmd := newRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"home", "list", "--json"})

	_, err := cmd.ExecuteC()
	if err == nil {
		t.Fatal("expected no-credential error, got nil")
	}
	if got := exitcodes.ExitCodeFromError(err); got != exitcodes.ExitNoAuth {
		t.Fatalf("exit code = %d, want %d (err: %v)", got, exitcodes.ExitNoAuth, err)
	}
	if !strings.Contains(err.Error(), "no password configured") {
		t.Fatalf("error = %q, want no-password message", err.Error())
	}
}

func TestParseHkrTemp(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty string error", "", "—"},
		{"non-numeric error", "abc", "—"},
		{"on (254)", "254", "ON"},
		{"off (253)", "253", "OFF"},
		{"normal value 20", "20", "10.0"},
		{"normal value 21", "21", "10.5"},
		{"normal value 1", "1", "0.5"},
		{"normal value 30", "30", "15.0"},
		{"zero value", "0", "0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseHkrTemp(tt.in)
			if got != tt.want {
				t.Errorf("parseHkrTemp(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseInt(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{"empty string", "", 0},
		{"zero", "0", 0},
		{"positive", "42", 42},
		{"non-numeric", "abc", 0},
		{"negative", "-5", -5},
		{"large value", "999999", 999999},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseInt(tt.in)
			if got != tt.want {
				t.Errorf("parseInt(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}
