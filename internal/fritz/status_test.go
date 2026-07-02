package fritz

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStatus_ReturnsAllFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		sa := r.Header.Get("SoapAction")
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)

		if strings.Contains(sa, "GetInfo") {
			if strings.Contains(string(body), "DeviceInfo") || strings.Contains(sa, "DeviceInfo") {
				_, _ = io.WriteString(w, soapEnvelope("GetInfo", map[string]string{
					"NewModelName":       "FRITZ!Box 7590",
					"NewSoftwareVersion": "7.57",
					"NewUpTime":          "3600",
				}))
				return
			}
			if strings.Contains(string(body), "WANIPConnection") || strings.Contains(sa, "WANIPConnection") {
				_, _ = io.WriteString(w, soapEnvelope("GetInfo", map[string]string{
					"NewConnectionStatus": "Connected",
				}))
				return
			}
			if strings.Contains(string(body), "UserInterface") || strings.Contains(sa, "UserInterface") {
				_, _ = io.WriteString(w, soapEnvelope("GetInfo", map[string]string{
					"NewUpgradeAvailable": "0",
				}))
				return
			}
		}
		if strings.Contains(sa, "GetExternalIPAddress") {
			_, _ = io.WriteString(w, soapEnvelope("GetExternalIPAddress", map[string]string{
				"NewExternalIPAddress": "203.0.113.1",
			}))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New("fritz.box")
	c.tr064BaseURL = srv.URL

	s, err := c.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if s.ModelName != "FRITZ!Box 7590" {
		t.Errorf("ModelName = %q", s.ModelName)
	}
	if s.FirmwareVersion != "7.57" {
		t.Errorf("FirmwareVersion = %q", s.FirmwareVersion)
	}
	if s.ExternalIP != "203.0.113.1" {
		t.Errorf("ExternalIP = %q", s.ExternalIP)
	}
	if s.ConnectionState != "Connected" {
		t.Errorf("ConnectionState = %q", s.ConnectionState)
	}
	if s.Uptime != "3600" {
		t.Errorf("Uptime = %q", s.Uptime)
	}
	if s.Partial {
		t.Error("Partial = true, want false")
	}
	if len(s.Errors) != 0 {
		t.Errorf("Errors has %d entries, want 0", len(s.Errors))
	}
}

func TestStatus_PartialFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		sa := r.Header.Get("SoapAction")
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)

		if strings.Contains(sa, "GetInfo") {
			if strings.Contains(string(body), "DeviceInfo") || strings.Contains(sa, "DeviceInfo") {
				_, _ = io.WriteString(w, soapEnvelope("GetInfo", map[string]string{
					"NewModelName":       "FRITZ!Box 7530",
					"NewSoftwareVersion": "7.39",
					"NewUpTime":          "100",
				}))
				return
			}
			if strings.Contains(string(body), "UserInterface") || strings.Contains(sa, "UserInterface") {
				_, _ = io.WriteString(w, soapEnvelope("GetInfo", map[string]string{
					"NewUpgradeAvailable": "0",
				}))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if strings.Contains(sa, "GetExternalIPAddress") {
			_, _ = io.WriteString(w, soapEnvelope("GetExternalIPAddress", map[string]string{
				"NewExternalIPAddress": "10.0.0.1",
			}))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New("fritz.box")
	c.tr064BaseURL = srv.URL

	s, err := c.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if s.ModelName != "FRITZ!Box 7530" {
		t.Errorf("ModelName = %q", s.ModelName)
	}
	if s.ExternalIP != "10.0.0.1" {
		t.Errorf("ExternalIP = %q", s.ExternalIP)
	}
	if s.ConnectionState != "" {
		t.Errorf("ConnectionState = %q, want empty", s.ConnectionState)
	}
	if !s.Partial {
		t.Error("Partial = false, want true")
	}
	if len(s.Errors) == 0 {
		t.Error("Errors is empty, want at least one entry")
	}

	failedActions := map[string]bool{}
	for _, e := range s.Errors {
		failedActions[e.Action] = true
	}
	if !failedActions["GetInfo"] {
		t.Errorf("expected GetInfo in errors, got %v", s.Errors)
	}
}

func TestStatus_AllFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New("fritz.box")
	c.tr064BaseURL = srv.URL

	s, err := c.Status(context.Background())
	if err == nil {
		t.Fatal("expected error when all sub-queries fail")
	}
	if !s.Partial {
		t.Error("Partial = false, want true")
	}
	if len(s.Errors) != 4 {
		t.Errorf("Errors has %d entries, want 4", len(s.Errors))
	}
}

func TestStatus_AllPrimaryFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		sa := r.Header.Get("SoapAction")
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)

		if strings.Contains(sa, "GetInfo") {
			if strings.Contains(string(body), "UserInterface") || strings.Contains(sa, "UserInterface") {
				_, _ = io.WriteString(w, soapEnvelope("GetInfo", map[string]string{
					"NewUpgradeAvailable": "0",
				}))
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := New("fritz.box")
	c.tr064BaseURL = srv.URL

	s, err := c.Status(context.Background())
	if err == nil {
		t.Fatal("expected error when all primary sub-queries fail")
	}
	if !s.Partial {
		t.Error("Partial = false, want true")
	}
	if len(s.Errors) != 3 {
		t.Errorf("Errors has %d entries, want 3", len(s.Errors))
	}
	if !IsUnauthorized(err) {
		t.Errorf("expected unauthorized error, got %v", err)
	}
}

func TestStatus_PrioritizeAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sa := r.Header.Get("SoapAction")
		if strings.Contains(sa, "GetExternalIPAddress") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := New("fritz.box")
	c.tr064BaseURL = srv.URL

	s, err := c.Status(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !IsUnauthorized(err) {
		t.Errorf("expected unauthorized error as priority, got %v", err)
	}
	if len(s.Errors) != 4 {
		t.Errorf("Errors has %d entries, want 4", len(s.Errors))
	}

	foundAuth := false
	for _, e := range s.Errors {
		if e.Kind == ErrUnauthorized {
			foundAuth = true
		}
	}
	if !foundAuth {
		t.Error("expected to find ErrUnauthorized in StatusError Kind fields")
	}
}
