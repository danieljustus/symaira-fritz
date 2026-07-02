package fritz

import (
	"errors"
	"fmt"
	"strings"
)

// ErrorKind classifies FRITZ!Box errors into actionable categories.
type ErrorKind string

const (
	ErrUnauthorized       ErrorKind = "unauthorized"
	ErrServiceUnavailable ErrorKind = "service_unavailable"
	ErrUnsupportedAction  ErrorKind = "unsupported_action"
	ErrTimeout            ErrorKind = "timeout"
	ErrTransport          ErrorKind = "transport_error"
)

// ErrNoCredential is returned before session-login-only interfaces attempt to
// authenticate without a configured password. This avoids burning FRITZ!Box
// login attempts and triggering rate limits when the user has not run auth login.
var ErrNoCredential = errors.New("no password configured (run 'symfritz auth login')")

// FritzError is a structured error from the FRITZ!Box TR-064 or AHA-HTTP layer.
type FritzError struct {
	Kind       ErrorKind
	Service    string
	Action     string
	ErrorCode  int    // UPnP error code, 0 if not applicable
	Raw        string // original error description
	HTTPStatus int    // HTTP status code, 0 if not applicable
}

func (e *FritzError) Error() string {
	switch e.Kind {
	case ErrUnauthorized:
		return fmt.Sprintf("authentication required for %s.%s: %s", e.Service, e.Action, e.Raw)
	case ErrServiceUnavailable:
		return fmt.Sprintf("%s.%s unavailable: %s", e.Service, e.Action, e.Raw)
	case ErrUnsupportedAction:
		return fmt.Sprintf("%s.%s unsupported on this FRITZ!Box: %s", e.Service, e.Action, e.Raw)
	case ErrTimeout:
		return fmt.Sprintf("timeout contacting %s.%s: %s", e.Service, e.Action, e.Raw)
	case ErrTransport:
		return fmt.Sprintf("transport error for %s.%s: %s", e.Service, e.Action, e.Raw)
	default:
		return fmt.Sprintf("%s.%s: %s", e.Service, e.Action, e.Raw)
	}
}

// Hint returns an actionable suggestion for the user, or empty string.
func (e *FritzError) Hint() string {
	switch e.Kind {
	case ErrUnauthorized:
		return "Run: symfritz auth login"
	case ErrUnsupportedAction:
		return fmt.Sprintf("This FRITZ!Box model may not support %s.%s", e.Service, e.Action)
	case ErrTimeout:
		return "Check network connectivity and try again"
	case ErrTransport:
		return "Check that the FRITZ!Box is reachable and SYMFRITZ_HOST is correct"
	default:
		return ""
	}
}

// ClassifyError wraps a raw error into a FritzError with the appropriate kind.
// It inspects the HTTP status, SOAP fault content, and error messages to
// determine the category.
func classifyError(err error, svc Service, action string) error {
	if err == nil {
		return nil
	}

	msg := err.Error()

	// Timeout detection
	if strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded") {
		return &FritzError{Kind: ErrTimeout, Service: shortService(svc.Type), Action: action, Raw: msg}
	}

	// Transport errors
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "dial tcp") || strings.Contains(msg, "EOF") {
		return &FritzError{Kind: ErrTransport, Service: shortService(svc.Type), Action: action, Raw: msg}
	}

	// HTTP 401 — unauthorized
	if strings.Contains(msg, "HTTP 401") {
		return &FritzError{Kind: ErrUnauthorized, Service: shortService(svc.Type), Action: action, Raw: msg, HTTPStatus: 401}
	}

	// SOAP fault with "Invalid Action" — unsupported
	if strings.Contains(msg, "Invalid Action") || strings.Contains(msg, "invalid action") {
		return &FritzError{Kind: ErrUnsupportedAction, Service: shortService(svc.Type), Action: action, Raw: msg}
	}

	// SOAP fault with "No such entry" — service unavailable
	if strings.Contains(msg, "No such entry") || strings.Contains(msg, "no such entry") {
		return &FritzError{Kind: ErrServiceUnavailable, Service: shortService(svc.Type), Action: action, Raw: msg}
	}

	return err
}

// shortService extracts the service name from a full URN.
// "urn:dslforum-org:service:WANIPConnection:1" → "WANIPConnection"
func shortService(urn string) string {
	parts := strings.Split(urn, ":")
	if len(parts) >= 5 {
		return parts[3]
	}
	return urn
}

// IsUnauthorized reports whether err is (or wraps) an unauthorized FritzError.
func IsUnauthorized(err error) bool {
	var fe *FritzError
	if errors.As(err, &fe) {
		return fe.Kind == ErrUnauthorized
	}
	return false
}

// IsUnsupportedAction reports whether err is (or wraps) an unsupported action error.
func IsUnsupportedAction(err error) bool {
	var fe *FritzError
	if errors.As(err, &fe) {
		return fe.Kind == ErrUnsupportedAction
	}
	return false
}

// IsServiceUnavailable reports whether err is (or wraps) a service unavailable error.
func IsServiceUnavailable(err error) bool {
	var fe *FritzError
	if errors.As(err, &fe) {
		return fe.Kind == ErrServiceUnavailable
	}
	return false
}

// IsTimeout reports whether err is (or wraps) a timeout error.
func IsTimeout(err error) bool {
	var fe *FritzError
	if errors.As(err, &fe) {
		return fe.Kind == ErrTimeout
	}
	return false
}

// IsTransport reports whether err is (or wraps) a transport error.
func IsTransport(err error) bool {
	var fe *FritzError
	if errors.As(err, &fe) {
		return fe.Kind == ErrTransport
	}
	return false
}
