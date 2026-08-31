package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func trafficMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login_sid.lua" {
			_, _ = io.WriteString(w, loginSIDXML)
			return
		}
		if r.URL.Path == "/tr64desc.xml" {
			_, _ = io.WriteString(w, tr64descXML)
			return
		}
		sa := soapAction(r)
		if strings.Contains(sa, "WANCommonInterfaceConfig:1#X_AVM-DE_GetOnlineMonitor") {
			writeSOAP(w, "X_AVM-DE_GetOnlineMonitor", "urn:dslforum-org:service:WANCommonInterfaceConfig:1", map[string]string{
				"Newds_current_bps":    "1500000,1200000",
				"Newmc_current_bps":    "500000",
				"Newds_guest_bps":      "0",
				"Newprio_realtime_bps": "100000",
				"Newprio_high_bps":     "200000",
				"Newprio_default_bps":  "800000",
				"Newprio_low_bps":      "50000",
				"Newus_guest_bps":      "0",
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTrafficCmd_OneShotText(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := trafficMockServer(t)
	stubNewClient(t, srv)

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"traffic"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("traffic: %v", err)
		}
	})

	expectedStrings := []string{
		"WAN Traffic Statistics:",
		"Downstream",
		"Internet",
		"1.50 Mbit/s",
		"Media",
		"500.00 kbit/s",
		"Upstream",
		"Realtime",
		"100.00 kbit/s",
		"Default",
		"800.00 kbit/s",
	}
	for _, s := range expectedStrings {
		if !strings.Contains(out, s) {
			t.Errorf("traffic output missing %q:\n%s", s, out)
		}
	}
}

func TestTrafficCmd_OneShotJSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := trafficMockServer(t)
	stubNewClient(t, srv)

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"traffic", "--json"})
		if _, err := cmd.ExecuteC(); err != nil {
			t.Fatalf("traffic --json: %v", err)
		}
	})

	var data map[string]any
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		t.Fatalf("failed to parse one-shot JSON output: %v\nOutput:\n%s", err, out)
	}

	if _, ok := data["downstream_internet"]; !ok {
		t.Errorf("expected 'downstream_internet' field in JSON output: %s", out)
	}
}

func TestTrafficCmd_WatchNDJSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := trafficMockServer(t)
	stubNewClient(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetContext(ctx)
		cmd.SetArgs([]string{"traffic", "--watch", "--json", "--interval", "10ms"})
		_ = cmd.Execute()
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 NDJSON lines in watch mode, got %d:\n%s", len(lines), out)
	}

	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Errorf("line %d is not valid compact JSON (%v): %q", i, err, line)
		}
		if _, ok := record["downstream_internet"]; !ok {
			t.Errorf("line %d missing downstream_internet key: %q", i, line)
		}
	}
}

func TestTrafficCmd_WatchTextAppendedNoEscapes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv := trafficMockServer(t)
	stubNewClient(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	out := captureStdout(t, func() {
		cmd := newRootCmd()
		cmd.SetContext(ctx)
		cmd.SetArgs([]string{"traffic", "--watch", "--interval", "10ms"})
		_ = cmd.Execute()
	})

	if strings.Contains(out, "\x1b") {
		t.Errorf("output contains ANSI escape sequences:\n%q", out)
	}

	occurrences := strings.Count(out, "WAN Traffic Statistics:")
	if occurrences < 2 {
		t.Errorf("expected multiple appended snapshots (at least 2), got %d:\n%s", occurrences, out)
	}
}
