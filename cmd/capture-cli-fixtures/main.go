// Command capture-cli-fixtures records the documented CLI tree and parser
// contracts from the Go/Cobra oracle. The output is intentionally language
// neutral so the Rust parser can consume it without importing Go code.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/danieljustus/symaira-fritz/internal/portcontract"
)

type commandCase struct {
	Path       string   `json:"path"`
	HelpArgs   []string `json:"help_args"`
	ExitCode   int      `json:"exit_code"`
	Stdout     string   `json:"stdout"`
	Stderr     string   `json:"stderr"`
	Comparison string   `json:"comparison"`
}

type validationCase struct {
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
	Commands      []commandCase     `json:"commands"`
	Validation    []validationCase  `json:"validation"`
}

var commandPaths = []string{
	"symfritz",
	"symfritz auth", "symfritz auth login", "symfritz auth store", "symfritz auth test", "symfritz auth trust",
	"symfritz call", "symfritz calls",
	"symfritz completion", "symfritz completion bash", "symfritz completion fish", "symfritz completion powershell", "symfritz completion zsh",
	"symfritz config", "symfritz config detect", "symfritz config init",
	"symfritz detect", "symfritz diagnose", "symfritz diagnose router", "symfritz dial", "symfritz doctor", "symfritz dsl", "symfritz hangup", "symfritz help",
	"symfritz home", "symfritz home list", "symfritz home switch", "symfritz home temp",
	"symfritz hosts", "symfritz hosts active", "symfritz hosts get", "symfritz hosts list",
	"symfritz log", "symfritz mcp", "symfritz mesh", "symfritz reboot", "symfritz scrape", "symfritz services", "symfritz status", "symfritz traffic", "symfritz version",
	"symfritz wlan", "symfritz wlan clients", "symfritz wlan guest", "symfritz wlan guest off", "symfritz wlan guest on", "symfritz wlan guest status", "symfritz wlan radios",
	"symfritz wol",
}

var validationArgs = []struct {
	id   string
	args []string
}{
	{"call-missing-service-and-action", []string{"call"}},
	{"call-missing-action", []string{"call", "service"}},
	{"scrape-missing-page", []string{"scrape"}},
	{"diagnose-missing-host", []string{"diagnose"}},
	{"diagnose-excess-host", []string{"diagnose", "host", "extra"}},
	{"diagnose-router-invalid-port", []string{"diagnose", "router", "--port", "wat"}},
	{"dial-missing-number", []string{"dial"}},
	{"dial-excess-number", []string{"dial", "123", "456"}},
	{"home-switch-missing-args", []string{"home", "switch"}},
	{"home-switch-missing-state", []string{"home", "switch", "ain"}},
	{"home-temp-missing-args", []string{"home", "temp"}},
	{"hosts-get-excess-name", []string{"hosts", "get", "one", "two"}},
	{"wol-excess-host", []string{"wol", "one", "two"}},
	{"completion-bash-excess-arg", []string{"completion", "bash", "extra"}},
	{"unknown-command", []string{"not-a-command"}},
	{"invalid-port", []string{"diagnose", "host", "--port", "wat"}},
	{"invalid-duration", []string{"traffic", "--interval", "wat"}},
}

func main() {
	oracleFlag := flag.String("oracle", "./symfritz", "path to the Go oracle")
	outputFlag := flag.String("output", "testdata/port/cli/command-contracts.json", "fixture output path")
	timeoutFlag := flag.Duration("timeout", 10*time.Second, "per-case timeout")
	flag.Parse()

	oracle, err := filepath.Abs(*oracleFlag)
	if err != nil {
		fatal(err)
	}
	root, err := os.MkdirTemp("", "symfritz-cli-oracle-")
	if err != nil {
		fatal(err)
	}
	defer os.RemoveAll(root)

	commands := make([]commandCase, 0, len(commandPaths))
	for _, path := range commandPaths {
		args := []string{"--help"}
		if path != "symfritz" {
			args = append([]string{"help"}, splitPath(path)...)
		}
		result, runErr := portcontract.Run(oracle, args, filepath.Join(root, "help", path), *timeoutFlag)
		if runErr != nil {
			fatal(fmt.Errorf("help %s: %w", path, runErr))
		}
		if result.TimedOut {
			fatal(fmt.Errorf("help %s: oracle timed out", path))
		}
		commands = append(commands, commandCase{Path: path, HelpArgs: args, ExitCode: result.ExitCode, Stdout: string(result.Stdout), Stderr: string(result.Stderr), Comparison: "semantic-help"})
	}

	validation := make([]validationCase, 0, len(validationArgs))
	for _, testCase := range validationArgs {
		result, runErr := portcontract.Run(oracle, testCase.args, filepath.Join(root, "validation", testCase.id), *timeoutFlag)
		if runErr != nil {
			fatal(fmt.Errorf("validation %s: %w", testCase.id, runErr))
		}
		if result.TimedOut {
			fatal(fmt.Errorf("validation %s: oracle timed out", testCase.id))
		}
		validation = append(validation, validationCase{ID: testCase.id, Args: testCase.args, ExitCode: result.ExitCode, Stdout: string(result.Stdout), Stderr: string(result.Stderr), Comparison: "bytes"})
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
		Commands:   commands,
		Validation: validation,
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
	fmt.Printf("captured %d command help and %d validation cases in %s\n", len(commands), len(validation), *outputFlag)
}

func splitPath(path string) []string {
	parts := strings.Fields(path)
	if len(parts) == 0 || parts[0] != "symfritz" {
		return nil
	}
	return parts[1:]
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(1)
}
