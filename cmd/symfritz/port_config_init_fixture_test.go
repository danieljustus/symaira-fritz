package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type portConfigInitFixture struct {
	SchemaVersion int                  `json:"schema_version"`
	Oracle        string               `json:"oracle"`
	Cases         []portConfigInitCase `json:"cases"`
}

type portConfigInitCase struct {
	ID             string `json:"id"`
	FileExists     bool   `json:"file_exists"`
	InitialContent string `json:"initial_content,omitempty"`
	InitialMode    string `json:"initial_mode,omitempty"`
	Force          bool   `json:"force"`
	Stdout         string `json:"stdout"`
	Stderr         string `json:"stderr"`
	Body           string `json:"body"`
	Mode           string `json:"mode,omitempty"`
}

func TestPortConfigInitFixture(t *testing.T) {
	fixture := buildPortConfigInitFixture(t)
	got, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	path := portConfigInitFixturePath(t)
	if os.Getenv("SYMFRITZ_UPDATE_PORT_FIXTURES") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config-init fixture: %v (regenerate with make port-fixtures)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("config-init fixture drifted; regenerate deliberately with make port-fixtures")
	}
}

func buildPortConfigInitFixture(t *testing.T) portConfigInitFixture {
	t.Helper()
	inputs := []portConfigInitCase{
		{ID: "fresh", Force: false},
		{
			ID:             "existing-without-force",
			FileExists:     true,
			InitialContent: "# existing\n[box]\nhost = \"old.box\"\n",
			InitialMode:    "0644",
			Force:          false,
		},
		{
			ID:             "existing-with-force",
			FileExists:     true,
			InitialContent: "# existing\n[box]\nhost = \"old.box\"\n",
			InitialMode:    "0644",
			Force:          true,
		},
	}

	cases := make([]portConfigInitCase, 0, len(inputs))
	for _, input := range inputs {
		dir := t.TempDir()
		path := filepath.Join(dir, ".config", "symfritz", "config.toml")
		if input.FileExists {
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(input.InitialContent), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
		}

		var stdout, stderr bytes.Buffer
		if err := initConfigFile(path, input.Force, &stdout, &stderr); err != nil {
			t.Fatalf("%s: %v", input.ID, err)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		mode := ""
		if runtime.GOOS != "windows" {
			mode = fmt.Sprintf("%04o", info.Mode().Perm())
		}
		input.Stdout = strings.ReplaceAll(stdout.String(), path, "{path}")
		input.Stderr = strings.ReplaceAll(stderr.String(), path, "{path}")
		input.Body = string(body)
		input.Mode = mode
		cases = append(cases, input)
	}
	return portConfigInitFixture{
		SchemaVersion: 1,
		Oracle:        "Go cmd/symfritz initConfigFile production helper",
		Cases:         cases,
	}
}

func portConfigInitFixturePath(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve fixture source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "port", "config", "config-init-vectors.json"))
}
