package fritz

import (
	"net"
	"testing"
)

func TestParseLinuxDefaultGateway(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string // empty means "no gateway"
	}{
		{
			name:   "ipv4 default route",
			output: "default via 192.168.178.1 dev enp0s3",
			want:   "192.168.178.1",
		},
		{
			name:   "ipv6 default route",
			output: "default via fe80::1 dev eth0 metric 1024",
			want:   "fe80::1",
		},
		{
			name:   "no via clause",
			output: "default dev eth0",
			want:   "",
		},
		{
			name:   "via with invalid address",
			output: "default via not-an-ip dev eth0",
			want:   "",
		},
		{
			name:   "empty output",
			output: "",
			want:   "",
		},
		{
			name:   "garbage output",
			output: "foo bar baz\nqux\n",
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLinuxDefaultGateway(tt.output)
			if err != nil {
				t.Fatalf("parseLinuxDefaultGateway returned error: %v", err)
			}
			if tt.want == "" {
				if got != nil {
					t.Fatalf("want nil gateway, got %v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("want gateway %s, got nil", tt.want)
			}
			if !got.Equal(net.ParseIP(tt.want)) {
				t.Fatalf("want gateway %s, got %v", tt.want, got)
			}
		})
	}
}

func TestParseWindowsDefaultGateway(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string // empty means "no gateway"
	}{
		{
			name:   "ipv4 route line",
			output: "  0.0.0.0          0.0.0.0      192.168.178.1    192.168.178.2     25",
			want:   "192.168.178.1",
		},
		{
			name:   "no match on non-default network",
			output: "  10.0.0.0          255.0.0.0      10.0.0.1    10.0.0.2     1",
			want:   "",
		},
		{
			name:   "malformed default line",
			output: "  0.0.0.0          0.0.0.0      not-an-ip    192.168.178.2     25",
			want:   "",
		},
		{
			name:   "empty output",
			output: "",
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseWindowsDefaultGateway(tt.output)
			if err != nil {
				t.Fatalf("parseWindowsDefaultGateway returned error: %v", err)
			}
			if tt.want == "" {
				if got != nil {
					t.Fatalf("want nil gateway, got %v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("want gateway %s, got nil", tt.want)
			}
			if !got.Equal(net.ParseIP(tt.want)) {
				t.Fatalf("want gateway %s, got %v", tt.want, got)
			}
		})
	}
}
