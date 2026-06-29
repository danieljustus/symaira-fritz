package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-fritz/internal/config"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

func TestSecretOptions(t *testing.T) {
	t.Run("keychain_account set", func(t *testing.T) {
		box := config.Box{
			Host:            "fritz.box",
			PasswordRef:     "fritz.password",
			Keychain:        true,
			KeychainAccount: "myaccount",
			Password:        "secret123",
		}
		got := secretOptions(box)
		if got.EnvVar != "SYMFRITZ_PASSWORD" {
			t.Errorf("EnvVar = %q, want %q", got.EnvVar, "SYMFRITZ_PASSWORD")
		}
		if got.Ref != "fritz.password" {
			t.Errorf("Ref = %q, want %q", got.Ref, "fritz.password")
		}
		if !got.Keychain {
			t.Error("Keychain should be true")
		}
		if got.KeychainAccount != "myaccount" {
			t.Errorf("KeychainAccount = %q, want %q", got.KeychainAccount, "myaccount")
		}
		if got.Plaintext != "secret123" {
			t.Errorf("Plaintext = %q, want %q", got.Plaintext, "secret123")
		}
	})

	t.Run("keychain_account empty falls back to host", func(t *testing.T) {
		box := config.Box{
			Host: "192.168.178.1",
		}
		got := secretOptions(box)
		if got.KeychainAccount != "192.168.178.1" {
			t.Errorf("KeychainAccount = %q, want host %q", got.KeychainAccount, "192.168.178.1")
		}
	})

	t.Run("zero value box", func(t *testing.T) {
		box := config.Box{}
		got := secretOptions(box)
		if got.EnvVar != "SYMFRITZ_PASSWORD" {
			t.Errorf("EnvVar = %q, want %q", got.EnvVar, "SYMFRITZ_PASSWORD")
		}
		if got.KeychainAccount != "" {
			t.Errorf("KeychainAccount = %q, want empty (host also empty)", got.KeychainAccount)
		}
	})
}

func TestPrintJSON(t *testing.T) {
	// Capture stdout.
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	t.Run("string value", func(t *testing.T) {
		err := printJSON("hello")
		w.Close()
		var buf bytes.Buffer
		io.Copy(&buf, r)
		os.Stdout = orig
		os.Stdout = orig // restore for next test
		// Re-pipe for next sub-test
		r, w, _ = os.Pipe()
		os.Stdout = w

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got := strings.TrimSpace(buf.String())
		if got != `"hello"` {
			t.Errorf("output = %q, want %q", got, `"hello"`)
		}
	})

	t.Run("struct value", func(t *testing.T) {
		type point struct {
			X int `json:"x"`
			Y int `json:"y"`
		}
		err := printJSON(point{X: 1, Y: 2})
		w.Close()
		var buf bytes.Buffer
		io.Copy(&buf, r)
		os.Stdout = orig
		r, w, _ = os.Pipe()
		os.Stdout = w

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got := buf.String()
		if !strings.Contains(got, `"x": 1`) || !strings.Contains(got, `"y": 2`) {
			t.Errorf("output missing expected fields: %s", got)
		}
	})

	t.Run("nil value", func(t *testing.T) {
		err := printJSON(nil)
		w.Close()
		var buf bytes.Buffer
		io.Copy(&buf, r)
		os.Stdout = orig

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got := strings.TrimSpace(buf.String())
		if got != "null" {
			t.Errorf("output = %q, want %q", got, "null")
		}
	})
}

func TestOrDash(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty string", "", "—"},
		{"whitespace only", "   ", "—"},
		{"tab only", "\t", "—"},
		{"newline only", "\n", "—"},
		{"non-empty", "hello", "hello"},
		{"leading/trailing spaces", "  foo  ", "  foo  "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := orDash(tt.in)
			if got != tt.want {
				t.Errorf("orDash(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDashIf(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty string", "", "—"},
		{"whitespace", "  ", "—"},
		{"non-empty", "value", "value"},
		{"single space surrounded", " x ", " x "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dashIf(tt.in)
			if got != tt.want {
				t.Errorf("dashIf(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"shorter than n", "hello", 10, "hello"},
		{"equal to n", "hello", 5, "hello"},
		{"longer than n", "hello", 3, "he…"},
		{"n=1 longer", "hello", 1, "h"},
		{"n=0", "hello", 0, ""},
		{"n=1 equal", "a", 1, "a"},
		{"n=2 longer", "hello", 2, "h…"},
		{"empty string", "", 5, ""},
		{"empty string n=0", "", 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncate(tt.s, tt.n)
			if got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.s, tt.n, got, tt.want)
			}
		})
	}
}

func TestBoolGlyph(t *testing.T) {
	if got := boolGlyph(true); got != "✓" {
		t.Errorf("boolGlyph(true) = %q, want %q", got, "✓")
	}
	if got := boolGlyph(false); got != "✗" {
		t.Errorf("boolGlyph(false) = %q, want %q", got, "✗")
	}
}

func TestOkWord(t *testing.T) {
	if got := okWord(true); got != "✓" {
		t.Errorf("okWord(true) = %q, want %q", got, "✓")
	}
	if got := okWord(false); got != "✗ (disabled or unavailable)" {
		t.Errorf("okWord(false) = %q, want %q", got, "✗ (disabled or unavailable)")
	}
}

func TestStatusGlyph(t *testing.T) {
	tests := []struct {
		name   string
		status fritz.CheckStatus
		want   string
	}{
		{"StatusOK", fritz.StatusOK, "✓"},
		{"StatusFail", fritz.StatusFail, "✗"},
		{"StatusWarn", fritz.StatusWarn, "!"},
		{"unknown status", fritz.CheckStatus("bogus"), "·"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := statusGlyph(tt.status)
			if got != tt.want {
				t.Errorf("statusGlyph(%q) = %q, want %q", tt.status, got, tt.want)
			}
		})
	}
}

func TestModelSuffix(t *testing.T) {
	tests := []struct {
		name  string
		model string
		want  string
	}{
		{"empty", "", ""},
		{"whitespace", "  ", ""},
		{"non-empty", "FRITZ!Box 7590 AX", " FRITZ!Box 7590 AX"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := modelSuffix(tt.model)
			if got != tt.want {
				t.Errorf("modelSuffix(%q) = %q, want %q", tt.model, got, tt.want)
			}
		})
	}
}

func TestDataRate(t *testing.T) {
	tests := []struct {
		name string
		link fritz.MeshLink
		want string
	}{
		{"zero rates", fritz.MeshLink{}, ""},
		{"zero rx non-zero tx", fritz.MeshLink{CurDataRateTx: 300}, "(0/300 Mbit/s)"},
		{"non-zero rates", fritz.MeshLink{CurDataRateRx: 500, CurDataRateTx: 1000}, "(500/1000 Mbit/s)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dataRate(tt.link)
			if got != tt.want {
				t.Errorf("dataRate(%+v) = %q, want %q", tt.link, got, tt.want)
			}
		})
	}
}
