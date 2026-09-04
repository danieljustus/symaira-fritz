package fritz

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

type portTransportFixture struct {
	SchemaVersion int                  `json:"schema_version"`
	Oracle        string               `json:"oracle"`
	Certificate   portCertificate      `json:"certificate"`
	PinStore      portPinStore         `json:"pin_store"`
	SafeURLs      []portSafeURL        `json:"safe_urls"`
	Fallback      []portFallbackVector `json:"fallback"`
}

type portCertificate struct {
	InputFile string `json:"input_file"`
	SPKIPin   string `json:"spki_pin"`
}

type portPinStore struct {
	Host             string `json:"host"`
	Pin              string `json:"pin"`
	WrittenJSON      string `json:"written_json"`
	FileMode         string `json:"file_mode,omitempty"`
	DirectoryMode    string `json:"directory_mode,omitempty"`
	CorruptSetFails  bool   `json:"corrupt_set_fails"`
	ResetRepairs     bool   `json:"reset_repairs"`
	RepairedJSON     string `json:"repaired_json"`
	MissingResetNoop bool   `json:"missing_reset_noop"`
}

type portSafeURL struct {
	ID       string `json:"id"`
	Raw      string `json:"raw"`
	Redacted string `json:"redacted"`
}

type portFallbackVector struct {
	ID       string `json:"id"`
	Message  string `json:"message"`
	Canceled bool   `json:"canceled,omitempty"`
	Expected bool   `json:"expected"`
}

func TestPortTransportFixture(t *testing.T) {
	fixture := buildPortTransportFixture(t)
	got, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := portTransportFixturePath(t)
	if os.Getenv(updatePortFixturesEnv) == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read transport fixture: %v (regenerate with make port-fixtures)", err)
	}
	if string(want) != string(got) {
		t.Fatal("transport fixture drifted; regenerate deliberately with make port-fixtures")
	}
}

func buildPortTransportFixture(t *testing.T) portTransportFixture {
	t.Helper()
	certificateFile := "testdata/port/transport/test-certificate.der.b64"
	encoded, err := os.ReadFile(filepath.Join(portRepositoryRoot(t), certificateFile))
	if err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		t.Fatal(err)
	}
	pin, err := CalculateSPKIPin(der)
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	path := filepath.Join(root, "nested", "pins.json")
	store := NewPinStore(path)
	const host = "fritz.box"
	const storedPin = "AQID"
	if err := store.SetPin(host, storedPin); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fileMode, directoryMode := "", ""
	if runtime.GOOS != "windows" {
		fileInfo, _ := os.Stat(path)
		dirInfo, _ := os.Stat(filepath.Dir(path))
		fileMode = fileInfo.Mode().Perm().String()
		directoryMode = dirInfo.Mode().Perm().String()
	}
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	corrupt := NewPinStore(path)
	corruptSetFails := corrupt.SetPin("other", "pin") != nil
	resetRepairs, err := corrupt.ResetPin("other")
	if err != nil {
		t.Fatal(err)
	}
	repaired, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	missingResetNoop, err := NewPinStore(filepath.Join(root, "missing.json")).ResetPin("none")
	if err != nil {
		t.Fatal(err)
	}

	safeInputs := []struct{ id, raw string }{
		{"sid", "http://fritz.box/query.lua?sid=abc123&foo=bar"},
		{"response", "https://fritz.box/login_sid.lua?response=2$1000$salt$hash&version=2"},
		{"password", "http://fritz.box/api?password=plain-value"},
		{"userinfo", "http://admin:plain-value@fritz.box/path"},
		{"unchanged", "http://fritz.box/path?foo=bar"},
		{"invalid", "://bad"},
	}
	safeURLs := make([]portSafeURL, 0, len(safeInputs))
	for _, input := range safeInputs {
		safeURLs = append(safeURLs, portSafeURL{ID: input.id, Raw: input.raw, Redacted: safeURLForError(input.raw)})
	}

	fallbackInputs := []portFallbackVector{
		{ID: "connection-refused", Message: "dial tcp: connection refused", Expected: true},
		{ID: "io-timeout", Message: "dial tcp: i/o timeout", Expected: true},
		{ID: "host-unreachable", Message: "dial tcp: no route to host", Expected: true},
		{ID: "tls-handshake", Message: "tls: handshake failure", Expected: false},
		{ID: "pin-mismatch", Message: "certificate pin mismatch", Expected: false},
		{ID: "http-auth", Message: "HTTP 401", Expected: false},
		{ID: "canceled-timeout", Message: "dial tcp: i/o timeout", Canceled: true, Expected: false},
	}
	for i := range fallbackInputs {
		ctx := context.Background()
		var err error = errors.New(fallbackInputs[i].Message)
		if fallbackInputs[i].ID == "host-unreachable" {
			err = syscall.ENETUNREACH
			fallbackInputs[i].Message = err.Error()
		}
		if fallbackInputs[i].Canceled {
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
		}
		fallbackInputs[i].Expected = isTLSEndpointNotAnswering(err, ctx)
	}
	if !isTLSEndpointNotAnswering(syscall.ECONNREFUSED, context.Background()) {
		t.Fatal("ECONNREFUSED classification drift")
	}

	return portTransportFixture{
		SchemaVersion: 1,
		Oracle:        "Go internal/fritz pin, URL redaction and fallback production functions",
		Certificate:   portCertificate{InputFile: certificateFile, SPKIPin: pin},
		PinStore: portPinStore{
			Host:             host,
			Pin:              storedPin,
			WrittenJSON:      string(written),
			FileMode:         fileMode,
			DirectoryMode:    directoryMode,
			CorruptSetFails:  corruptSetFails,
			ResetRepairs:     resetRepairs,
			RepairedJSON:     string(repaired),
			MissingResetNoop: !missingResetNoop,
		},
		SafeURLs: safeURLs,
		Fallback: fallbackInputs,
	}
}

func portRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func portTransportFixturePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(portRepositoryRoot(t), "testdata", "port", "transport", "contracts.json")
}
