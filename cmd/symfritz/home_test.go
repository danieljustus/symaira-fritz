package main

import "testing"

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
