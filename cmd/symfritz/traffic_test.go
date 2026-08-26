package main

import (
	"testing"
)

func TestFormatSpeedList(t *testing.T) {
	tests := []struct {
		name  string
		rates []float64
		want  string
	}{
		{"empty slice", nil, "—"},
		{"empty slice literal", []float64{}, "—"},
		{"single value megabit", []float64{1500000}, "1.50 Mbit/s"},
		{"single value kilobit", []float64{500000}, "500.00 kbit/s"},
		{"single value bit", []float64{500}, "500 bit/s"},
		{"takes first value", []float64{2000000, 1000000}, "2.00 Mbit/s"},
		{"exactly 1M", []float64{1000000}, "1.00 Mbit/s"},
		{"exactly 1k", []float64{1000}, "1.00 kbit/s"},
		{"zero", []float64{0}, "—"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatSpeedList(tt.rates)
			if got != tt.want {
				t.Errorf("formatSpeedList(%v) = %q, want %q", tt.rates, got, tt.want)
			}
		})
	}
}

// formatSpeedList formats the first value of a float64 slice as a human-readable
// speed string.
func formatSpeedList(rates []float64) string {
	if len(rates) == 0 || rates[0] == 0 {
		return "—"
	}
	return formatSpeed(rates[0])
}
