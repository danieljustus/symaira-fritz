package fritz

import (
	"errors"
	"fmt"
	"testing"
)

func TestFritzError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *FritzError
		want string
	}{
		{
			name: "unauthorized",
			err:  &FritzError{Kind: ErrUnauthorized, Service: "WANIPConnection", Action: "GetInfo", Raw: "401 without digest challenge", HTTPStatus: 401},
			want: "authentication required for WANIPConnection.GetInfo: 401 without digest challenge",
		},
		{
			name: "unsupported action",
			err:  &FritzError{Kind: ErrUnsupportedAction, Service: "WANDSLInterfaceConfig", Action: "GetInfo", Raw: "Invalid Action"},
			want: "WANDSLInterfaceConfig.GetInfo unsupported on this FRITZ!Box: Invalid Action",
		},
		{
			name: "timeout",
			err:  &FritzError{Kind: ErrTimeout, Service: "WLANConfiguration", Action: "GetInfo", Raw: "context deadline exceeded"},
			want: "timeout contacting WLANConfiguration.GetInfo: context deadline exceeded",
		},
		{
			name: "transport",
			err:  &FritzError{Kind: ErrTransport, Service: "DeviceInfo", Action: "GetInfo", Raw: "connection refused"},
			want: "transport error for DeviceInfo.GetInfo: connection refused",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFritzError_Hint(t *testing.T) {
	tests := []struct {
		name string
		err  *FritzError
		want string
	}{
		{
			name: "unauthorized",
			err:  &FritzError{Kind: ErrUnauthorized, Service: "WANIPConnection", Action: "GetInfo", Raw: "401"},
			want: "Run: symfritz auth login",
		},
		{
			name: "unsupported",
			err:  &FritzError{Kind: ErrUnsupportedAction, Service: "WANDSLInterfaceConfig", Action: "GetInfo", Raw: "Invalid Action"},
			want: "This FRITZ!Box model may not support WANDSLInterfaceConfig.GetInfo",
		},
		{
			name: "timeout",
			err:  &FritzError{Kind: ErrTimeout, Service: "WLANConfiguration", Action: "GetInfo", Raw: "timeout"},
			want: "Check network connectivity and try again",
		},
		{
			name: "transport",
			err:  &FritzError{Kind: ErrTransport, Service: "DeviceInfo", Action: "GetInfo", Raw: "connection refused"},
			want: "Check that the FRITZ!Box is reachable and SYMFRITZ_HOST is correct",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Hint(); got != tt.want {
				t.Errorf("Hint() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClassifyError(t *testing.T) {
	svc := Service{Type: "urn:dslforum-org:service:WANIPConnection:1", ControlURL: "/upnp/control/wanipconnection1"}

	tests := []struct {
		name    string
		err     error
		wantNil bool
		want    ErrorKind
	}{
		{"nil error", nil, true, ""},
		{"timeout", fmt.Errorf("context deadline exceeded"), false, ErrTimeout},
		{"transport refused", fmt.Errorf("dial tcp: connection refused"), false, ErrTransport},
		{"transport eof", fmt.Errorf("read tcp: EOF"), false, ErrTransport},
		{"401", fmt.Errorf("tr064: HTTP 401"), false, ErrUnauthorized},
		{"invalid action", fmt.Errorf("tr064: HTTP 500: Invalid Action"), false, ErrUnsupportedAction},
		{"no such entry", fmt.Errorf("tr064: HTTP 500: No such entry"), false, ErrServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyError(tt.err, svc, "GetInfo")
			if tt.wantNil {
				if got != nil {
					t.Errorf("classifyError() = %v, want nil", got)
				}
				return
			}
			var fe *FritzError
			if !errors.As(got, &fe) {
				t.Fatalf("classifyError() returned %T, want *FritzError", got)
			}
			if fe.Kind != tt.want {
				t.Errorf("Kind = %q, want %q", fe.Kind, tt.want)
			}
			if fe.Service != "WANIPConnection" {
				t.Errorf("Service = %q, want WANIPConnection", fe.Service)
			}
			if fe.Action != "GetInfo" {
				t.Errorf("Action = %q, want GetInfo", fe.Action)
			}
		})
	}
}

func TestShortService(t *testing.T) {
	tests := []struct {
		urn  string
		want string
	}{
		{"urn:dslforum-org:service:WANIPConnection:1", "WANIPConnection"},
		{"urn:dslforum-org:service:DeviceInfo:1", "DeviceInfo"},
		{"urn:dslforum-org:service:X_AVM-DE_Homeauto:1", "X_AVM-DE_Homeauto"},
		{"short", "short"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := shortService(tt.urn); got != tt.want {
				t.Errorf("shortService(%q) = %q, want %q", tt.urn, got, tt.want)
			}
		})
	}
}

func TestIsUnauthorized(t *testing.T) {
	err := &FritzError{Kind: ErrUnauthorized, Service: "Test", Action: "GetInfo", Raw: "401"}
	if !IsUnauthorized(err) {
		t.Error("IsUnauthorized() = false, want true")
	}
	if IsUnauthorized(fmt.Errorf("not a FritzError")) {
		t.Error("IsUnauthorized() = true for non-FritzError")
	}
}

func TestIsUnsupportedAction(t *testing.T) {
	err := &FritzError{Kind: ErrUnsupportedAction, Service: "Test", Action: "GetInfo", Raw: "Invalid Action"}
	if !IsUnsupportedAction(err) {
		t.Error("IsUnsupportedAction() = false, want true")
	}
}
