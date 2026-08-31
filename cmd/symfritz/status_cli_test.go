package main

import (
	"bytes"
	"context"
	"encoding/json"
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
		newClient = func(_ context.Context) (*fritz.Client, *config.Config, error) {
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
		newClient = func(_ context.Context) (*fritz.Client, *config.Config, error) {
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
		newClient = func(_ context.Context) (*fritz.Client, *config.Config, error) {
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

	t.Run("partial failure with --json shows distinct kind and error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/xml; charset=utf-8")
			sa := r.Header.Get("SoapAction")
			if strings.Contains(sa, "DeviceInfo") {
				_, _ = io.WriteString(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetInfoResponse xmlns:u="urn:dslforum-org:service:DeviceInfo:1"><NewModelName>FRITZ!Box 7590</NewModelName><NewSoftwareVersion>7.57</NewSoftwareVersion><NewUpTime>3600</NewUpTime></u:GetInfoResponse></s:Body></s:Envelope>`)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		}))
		t.Cleanup(srv.Close)

		origNewClient := newClient
		t.Cleanup(func() { newClient = origNewClient })
		newClient = func(_ context.Context) (*fritz.Client, *config.Config, error) {
			c := fritz.New("fritz.box")
			c.SetMockURLs(srv.URL)
			return c, &config.Config{}, nil
		}

		cmd := newRootCmd()
		stdoutStr := captureStdout(func() {
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs([]string{"status", "--json"})
			_, _ = cmd.ExecuteC()
		})

		var parsed struct {
			Partial bool `json:"partial"`
			Errors  []struct {
				Kind    string `json:"kind"`
				Error   string `json:"error"`
				Message string `json:"message"`
			} `json:"errors"`
		}
		if err := json.Unmarshal([]byte(stdoutStr), &parsed); err != nil {
			t.Fatalf("failed to unmarshal JSON status: %v\nOutput: %s", err, stdoutStr)
		}
		if !parsed.Partial {
			t.Errorf("expected partial: true")
		}
		if len(parsed.Errors) == 0 {
			t.Fatalf("expected errors in JSON status, got none")
		}
		for _, e := range parsed.Errors {
			if e.Kind == e.Error {
				t.Errorf("expected kind (%q) and error (%q) to differ", e.Kind, e.Error)
			}
			if e.Error != e.Message {
				t.Errorf("expected error (%q) to match failure message (%q)", e.Error, e.Message)
			}
		}
	})
}

func TestStatusPayload_KindAndErrorDiffer(t *testing.T) {
	st := &fritz.Status{
		ModelName: "FRITZ!Box 7590",
		Partial:   true,
		Errors: []fritz.StatusError{
			{
				Service: "WANConnection",
				Action:  "GetInfo",
				Message: "HTTP 401 Unauthorized",
				Kind:    fritz.ErrUnauthorized,
			},
		},
	}
	dto := statusPayload(st, []int{45, 48})
	if !dto.Partial {
		t.Error("expected partial to be true")
	}
	if len(dto.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(dto.Errors))
	}
	errDTO := dto.Errors[0]
	if errDTO.Kind != "unauthorized" {
		t.Errorf("Kind = %q, want %q", errDTO.Kind, "unauthorized")
	}
	if errDTO.Error != "HTTP 401 Unauthorized" {
		t.Errorf("Error = %q, want %q", errDTO.Error, "HTTP 401 Unauthorized")
	}
	if errDTO.Kind == errDTO.Error {
		t.Errorf("Kind and Error should differ, both are %q", errDTO.Kind)
	}
	if errDTO.Message != "HTTP 401 Unauthorized" {
		t.Errorf("Message = %q, want %q", errDTO.Message, "HTTP 401 Unauthorized")
	}
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
