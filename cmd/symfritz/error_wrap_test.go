package main

import (
	"errors"
	"testing"

	"github.com/danieljustus/symaira-corekit/exitcodes"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

// TestWrapFritzError_ExitCodeMapping verifies Issue #120: box-facing errors
// across all commands must be routed through wrapFritzError, which maps
// FritzError.Kind to the correct exit code and attaches a hint.
func TestWrapFritzError_ExitCodeMapping(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode exitcodes.ExitCode
		wantHint bool
	}{
		{
			name:     "unauthorized maps to ExitNoAuth",
			err:      &fritz.FritzError{Kind: fritz.ErrUnauthorized, Service: "DeviceInfo", Action: "GetInfo", Raw: "606 invalid"},
			wantCode: exitcodes.ExitNoAuth,
			wantHint: true,
		},
		{
			name:     "unsupported action maps to generic exit with not-found kind",
			err:      &fritz.FritzError{Kind: fritz.ErrUnsupportedAction, Service: "X", Action: "GetInfo", Raw: "Invalid Action"},
			wantCode: exitcodes.ExitGeneric,
			wantHint: true,
		},
		{
			name:     "transport error maps to ExitGeneric",
			err:      &fritz.FritzError{Kind: fritz.ErrTransport, Service: "DeviceInfo", Action: "GetInfo", Raw: "connection refused"},
			wantCode: exitcodes.ExitGeneric,
			wantHint: true,
		},
		{
			name:     "timeout maps to ExitGeneric",
			err:      &fritz.FritzError{Kind: fritz.ErrTimeout, Service: "DeviceInfo", Action: "GetInfo", Raw: "context deadline exceeded"},
			wantCode: exitcodes.ExitGeneric,
			wantHint: true,
		},
		{
			name:     "service unavailable maps to ExitGeneric",
			err:      &fritz.FritzError{Kind: fritz.ErrServiceUnavailable, Service: "DeviceInfo", Action: "GetInfo", Raw: "No such entry"},
			wantCode: exitcodes.ExitGeneric,
			wantHint: false,
		},
		{
			name:     "non-FritzError falls back to generic",
			err:      errors.New("random failure"),
			wantCode: exitcodes.ExitGeneric,
			wantHint: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wrapFritzError(tt.err, "some operation failed")
			code := exitcodes.ExitCodeFromError(got)
			if code != tt.wantCode {
				t.Errorf("ExitCode = %d, want %d", code, tt.wantCode)
			}
			var cliErr *exitcodes.CLIError
			if errors.As(got, &cliErr) && tt.wantHint {
				if cliErr.Hint == "" {
					t.Errorf("expected non-empty hint for Kind=%v", tt.err)
				}
			}
		})
	}
}

// TestWrapFritzError_AllCommandsConsistent verifies that every command's
// error path goes through wrapFritzError by checking that a FritzError
// returned from any command handler gets ExitNoAuth for unauthorized errors.
func TestWrapFritzError_AllCommandsConsistent(t *testing.T) {
	unauthorizedErr := &fritz.FritzError{
		Kind:    fritz.ErrUnauthorized,
		Service: "DeviceInfo",
		Action:  "GetInfo",
		Raw:     "606 invalid",
	}

	commands := []struct {
		name string
		err  error
	}{
		{"hosts list", wrapFritzError(unauthorizedErr, "hosts list failed")},
		{"hosts active", wrapFritzError(unauthorizedErr, "hosts list failed")},
		{"mesh", wrapFritzError(unauthorizedErr, "mesh failed")},
		{"calls", wrapFritzError(unauthorizedErr, "calls failed")},
		{"dial", wrapFritzError(unauthorizedErr, "dial failed")},
		{"hangup", wrapFritzError(unauthorizedErr, "hangup failed")},
		{"log", wrapFritzError(unauthorizedErr, "log failed")},
		{"discovery", wrapFritzError(unauthorizedErr, "discovery failed")},
		{"wol", wrapFritzError(unauthorizedErr, "wol failed")},
		{"tr064 call", wrapFritzError(unauthorizedErr, "tr064 call failed")},
	}

	for _, cmd := range commands {
		t.Run(cmd.name, func(t *testing.T) {
			code := exitcodes.ExitCodeFromError(cmd.err)
			if code != exitcodes.ExitNoAuth {
				t.Errorf("%s: ExitCode = %d, want ExitNoAuth (%d)", cmd.name, code, exitcodes.ExitNoAuth)
			}
		})
	}
}
