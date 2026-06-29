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
