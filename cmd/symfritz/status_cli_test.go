package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-fritz/internal/config"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

func TestStatusCmd_Integration(t *testing.T) {
	captureStdout := func(fn func()) string {
		orig := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		fn()
		w.Close()
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		os.Stdout = orig
		return buf.String()
	}

	t.Run("all subqueries succeed", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/xml; charset=utf-8")
			sa := r.Header.Get("SoapAction")
			if strings.Contains(sa, "GetInfo") {
				if strings.Contains(sa, "DeviceInfo") {
					_, _ = io.WriteString(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetInfoResponse xmlns:u="urn:dslforum-org:service:DeviceInfo:1"><NewModelName>FRITZ!Box 7590</NewModelName><NewSoftwareVersion>7.57</NewSoftwareVersion><NewUpTime>3600</NewUpTime></u:GetInfoResponse></s:Body></s:Envelope>`)
					return
				}
				if strings.Contains(sa, "WANIPConnection") {
					_, _ = io.WriteString(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetInfoResponse xmlns:u="urn:dslforum-org:service:WANIPConnection:1"><NewConnectionStatus>Connected</NewConnectionStatus></u:GetInfoResponse></s:Body></s:Envelope>`)
					return
				}
			}
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(srv.Close)

		origNewClient := newClient
		t.Cleanup(func() { newClient = origNewClient })
		newClient = func() (*fritz.Client, *config.Config, error) {
			c := fritz.New("fritz.box")
			c.SetMockURLs(srv.URL)
			return c, &config.Config{}, nil
		}

		cmd := newRootCmd()
		var out string
		stdoutStr := captureStdout(func() {
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs([]string{"status"})
			_, err := cmd.ExecuteC()
			if err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
			out = buf.String()
		})

		combined := out + stdoutStr
		if !strings.Contains(combined, "Model:       FRITZ!Box 7590") {
			t.Errorf("unexpected output: %s", combined)
		}
	})

	t.Run("all subqueries fail", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		t.Cleanup(srv.Close)

		origNewClient := newClient
		t.Cleanup(func() { newClient = origNewClient })
		newClient = func() (*fritz.Client, *config.Config, error) {
			c := fritz.New("fritz.box")
			c.SetMockURLs(srv.URL)
			return c, &config.Config{}, nil
		}

		cmd := newRootCmd()
		buf := new(bytes.Buffer)
		cmd.SetOut(buf)
		cmd.SetErr(buf)
		cmd.SetArgs([]string{"status"})
		_, err := cmd.ExecuteC()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("all subqueries fail with --json", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		t.Cleanup(srv.Close)

		origNewClient := newClient
		t.Cleanup(func() { newClient = origNewClient })
		newClient = func() (*fritz.Client, *config.Config, error) {
			c := fritz.New("fritz.box")
			c.SetMockURLs(srv.URL)
			return c, &config.Config{}, nil
		}

		cmd := newRootCmd()
		var out string
		stdoutStr := captureStdout(func() {
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs([]string{"status", "--json"})
			_, _ = cmd.ExecuteC()
			out = buf.String()
		})

		combined := out + stdoutStr
		if !strings.Contains(combined, `"partial": true`) || !strings.Contains(combined, `"kind": "unauthorized"`) {
			t.Errorf("expected stdout to contain JSON diagnostics, got: %q", combined)
		}
	})
}

func TestPrintJSONError(t *testing.T) {
	captureStdout := func(fn func()) string {
		orig := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		fn()
		w.Close()
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		os.Stdout = orig
		return buf.String()
	}

	t.Run("FritzError unauthorized", func(t *testing.T) {
		fe := &fritz.FritzError{
			Kind:    fritz.ErrUnauthorized,
			Service: "WLANConfiguration",
			Action:  "GetInfo",
			Raw:     "Authentication Required",
		}
		out := captureStdout(func() {
			printJSONError(fe)
		})
		if !strings.Contains(out, `"kind": "unauthorized"`) || !strings.Contains(out, `"service": "WLANConfiguration"`) {
			t.Errorf("unexpected printJSONError output: %s", out)
		}
	})

	t.Run("generic error", func(t *testing.T) {
		err := os.ErrNotExist
		out := captureStdout(func() {
			printJSONError(err)
		})
		if !strings.Contains(out, `"kind": "unavailable"`) {
			t.Errorf("unexpected printJSONError output: %s", out)
		}
	})
}
