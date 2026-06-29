package main

import "testing"

func TestFormatRateList(t *testing.T) {
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
		{"zero", []float64{0}, "0 bit/s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatRateList(tt.rates)
			if got != tt.want {
				t.Errorf("formatRateList(%v) = %q, want %q", tt.rates, got, tt.want)
			}
		})
	}
}
