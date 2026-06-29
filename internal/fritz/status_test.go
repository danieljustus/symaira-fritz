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
}
