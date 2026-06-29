package config

import (
	"strings"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()

	if cfg == nil {
		t.Fatal("Defaults() returned nil")
	}

	if cfg.Box.Host != "fritz.box" {
		t.Errorf("Host = %q, want %q", cfg.Box.Host, "fritz.box")
	}
	if cfg.Box.User != "" {
		t.Errorf("User = %q, want empty", cfg.Box.User)
	}
	if cfg.Box.Password != "" {
		t.Errorf("Password = %q, want empty", cfg.Box.Password)
	}
	if cfg.Box.UseTLS {
		t.Error("UseTLS = true, want false")
	}
	if cfg.Box.InsecureTLS {
		t.Error("InsecureTLS = true, want false")
	}
	if cfg.Box.TimeoutSeconds != 15 {
		t.Errorf("TimeoutSeconds = %d, want 15", cfg.Box.TimeoutSeconds)
	}
}

func TestTimeout(t *testing.T) {
	tests := []struct {
		name           string
		timeoutSeconds int
		want           time.Duration
	}{
		{
			name:           "zero returns default",
			timeoutSeconds: 0,
			want:           15 * time.Second,
		},
		{
			name:           "explicit positive value",
			timeoutSeconds: 30,
			want:           30 * time.Second,
		},
		{
			name:           "negative returns default",
			timeoutSeconds: -1,
			want:           15 * time.Second,
		},
		{
			name:           "one second",
			timeoutSeconds: 1,
			want:           1 * time.Second,
		},
		{
			name:           "large value",
			timeoutSeconds: 300,
			want:           300 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			box := Box{TimeoutSeconds: tt.timeoutSeconds}
			got := box.Timeout()
			if got != tt.want {
				t.Errorf("TimeoutSeconds=%d: Timeout() = %v, want %v",
					tt.timeoutSeconds, got, tt.want)
			}
		})
	}
}

func TestDefaultConfigTOML(t *testing.T) {
	got := DefaultConfigTOML()

	if got == "" {
		t.Fatal("DefaultConfigTOML() returned empty string")
	}

	// Verify expected TOML keys are present.
	wantKeys := []string{
		"host",
		"user",
		"password",
		"use_tls",
		"timeout_seconds",
	}
	for _, key := range wantKeys {
		if !strings.Contains(got, key) {
			t.Errorf("DefaultConfigTOML() missing key %q", key)
		}
	}

	// Verify it contains the default host value.
	if !strings.Contains(got, "fritz.box") {
		t.Error("DefaultConfigTOML() missing default host 'fritz.box'")
	}
}

func TestLoad(t *testing.T) {
	t.Setenv("SYMFRITZ_BOX_HOST", "my-custom-box")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Box.Host != "my-custom-box" {
		t.Errorf("Host = %q, want %q", cfg.Box.Host, "my-custom-box")
	}
}
