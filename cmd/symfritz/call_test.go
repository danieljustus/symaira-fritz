package main

import (
	"testing"

	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

func TestServiceByShortcut(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   fritz.Service
		wantOK bool
	}{
		{"deviceinfo", "deviceinfo", fritz.ServiceDeviceInfo, true},
		{"wanip", "wanip", fritz.ServiceWANIPConnection, true},
		{"wanppp", "wanppp", fritz.ServiceWANPPPConnection, true},
		{"wancommon", "wancommon", fritz.ServiceWANCommonIFC, true},
		{"hosts", "hosts", fritz.ServiceHosts, true},
		{"wlan1", "wlan1", fritz.ServiceWLANConfig1, true},
		{"case insensitive", "DeviceInfo", fritz.ServiceDeviceInfo, true},
		{"mixed case WANIP", "WANIP", fritz.ServiceWANIPConnection, true},
		{"unknown shortcut", "unknown", fritz.Service{}, false},
		{"empty string", "", fritz.Service{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := serviceByShortcut(tt.input)
			if ok != tt.wantOK {
				t.Errorf("serviceByShortcut(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("serviceByShortcut(%q) = %+v, want %+v", tt.input, got, tt.want)
			}
		})
	}
}

func TestNewCallCmd(t *testing.T) {
	cmd := newCallCmd()

	if cmd.Use == "" {
		t.Error("Use should not be empty")
	}
	if cmd.Short == "" {
		t.Error("Short should not be empty")
	}

	// Verify MinimumNArgs(2) — 0 args should fail
	if cmd.Args == nil {
		t.Fatal("Args should not be nil")
	}
	err := cmd.Args(cmd, []string{})
	if err == nil {
		t.Error("expected error for 0 args (MinimumNArgs(2))")
	}
	err = cmd.Args(cmd, []string{"svc"})
	if err == nil {
		t.Error("expected error for 1 arg (MinimumNArgs(2))")
	}
	err = cmd.Args(cmd, []string{"svc", "action"})
	if err != nil {
		t.Errorf("expected no error for 2 args, got: %v", err)
	}
}
