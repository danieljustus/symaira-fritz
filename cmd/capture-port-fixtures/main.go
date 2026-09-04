// Command capture-port-fixtures records deterministic CLI contracts from Go.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/danieljustus/symaira-fritz/internal/portcontract"
)

type cliCase struct {
	ID         string   `json:"id"`
	Args       []string `json:"args"`
	ExitCode   int      `json:"exit_code"`
	Stdout     string   `json:"stdout"`
	Stderr     string   `json:"stderr"`
	Comparison string   `json:"comparison"`
}

type fixture struct {
	SchemaVersion int               `json:"schema_version"`
	Oracle        string            `json:"oracle"`
	Environment   map[string]string `json:"environment"`
	Cases         []cliCase         `json:"cases"`
}

var cases = []cliCase{
	{ID: "version-text", Args: []string{"version"}},
	{ID: "version-flag", Args: []string{"--version"}},
	{ID: "version-json-output", Args: []string{"version", "--output", "json"}},
	{ID: "version-json-flag", Args: []string{"version", "--json"}},
	{ID: "version-json-case-insensitive", Args: []string{"version", "--output", "JSON"}},
	{ID: "version-yaml", Args: []string{"version", "--output", "yaml"}},
	{ID: "version-extra-argument", Args: []string{"version", "extra"}},
	{ID: "version-invalid-output", Args: []string{"--output", "wat", "version"}},
	{ID: "version-conflicting-output", Args: []string{"version", "--json", "--output", "yaml"}},
}

func main() {
	oracleFlag := flag.String("oracle", "./symfritz", "path to the Go oracle")
	outputFlag := flag.String("output", "testdata/port/cli/version-cases.json", "fixture output path")
	timeoutFlag := flag.Duration("timeout", 10*time.Second, "per-case timeout")
	flag.Parse()

	oracle, err := filepath.Abs(*oracleFlag)
	if err != nil {
		fatal(err)
	}
	root, err := os.MkdirTemp("", "symfritz-port-oracle-")
	if err != nil {
		fatal(err)
	}
	defer os.RemoveAll(root)

	captured := make([]cliCase, 0, len(cases))
	for _, testCase := range cases {
		home := filepath.Join(root, testCase.ID)
		result, err := portcontract.Run(oracle, testCase.Args, home, *timeoutFlag)
		if err != nil {
			fatal(fmt.Errorf("%s: %w", testCase.ID, err))
		}
		if result.TimedOut {
			fatal(fmt.Errorf("%s: oracle timed out after %s", testCase.ID, *timeoutFlag))
		}
		testCase.ExitCode = result.ExitCode
		testCase.Stdout = string(result.Stdout)
		testCase.Stderr = string(result.Stderr)
		testCase.Comparison = "bytes"
		captured = append(captured, testCase)
	}

	data, err := json.MarshalIndent(fixture{
		SchemaVersion: 1,
		Oracle:        "Go symfritz built with version=dev",
		Environment: map[string]string{
			"HOME/XDG/TMP": "isolated temporary directories",
			"LC_ALL/LANG":  "C",
			"TZ":           "UTC",
			"SYMFRITZ_*":   "unset",
		},
		Cases: captured,
	}, "", "  ")
	if err != nil {
		fatal(err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(*outputFlag), 0755); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*outputFlag, data, 0644); err != nil {
		fatal(err)
	}
	fmt.Printf("captured %d cases in %s\n", len(captured), *outputFlag)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(1)
}
