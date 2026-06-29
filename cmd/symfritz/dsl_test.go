package main

import "testing"

func TestFormatBitRate(t *testing.T) {
	tests := []struct {
		name string
		bps  int
		want string
	}{
		{"zero returns dash", 0, "—"},
		{"megabit", 1500000, "1.50 Mbit/s"},
		{"kilobit", 500000, "500.00 kbit/s"},
		{"bit", 500, "500 bit/s"},
		{"exactly 1M", 1000000, "1.00 Mbit/s"},
		{"exactly 1k", 1000, "1.00 kbit/s"},
		{"large value", 100000000, "100.00 Mbit/s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatBitRate(tt.bps)
			if got != tt.want {
				t.Errorf("formatBitRate(%d) = %q, want %q", tt.bps, got, tt.want)
			}
		})
	}
}
