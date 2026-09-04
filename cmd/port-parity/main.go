// Command port-parity compares Go and Rust binaries against golden fixtures.
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
	ID       string   `json:"id"`
	Args     []string `json:"args"`
	ExitCode int      `json:"exit_code"`
	Stdout   string   `json:"stdout"`
	Stderr   string   `json:"stderr"`
}

type fixture struct {
	Cases []cliCase `json:"cases"`
}

func main() {
	referenceFlag := flag.String("reference", "./symfritz", "path to the Go binary")
	candidateFlag := flag.String("candidate", "./target/debug/symfritz-rust", "path to the Rust binary")
	fixtureFlag := flag.String("fixture", "testdata/port/cli/version-cases.json", "golden fixture path")
	timeoutFlag := flag.Duration("timeout", 10*time.Second, "per-process timeout")
	flag.Parse()

	reference, err := filepath.Abs(*referenceFlag)
	if err != nil {
		fatal(err)
	}
	candidate, err := filepath.Abs(*candidateFlag)
	if err != nil {
		fatal(err)
	}
	data, err := os.ReadFile(*fixtureFlag)
	if err != nil {
		fatal(err)
	}
	var golden fixture
	if err := json.Unmarshal(data, &golden); err != nil {
		fatal(err)
	}

	root, err := os.MkdirTemp("", "symfritz-port-parity-")
	if err != nil {
		fatal(err)
	}
	defer os.RemoveAll(root)

	failed := 0
	for _, testCase := range golden.Cases {
		var failures []string
		for _, implementation := range []struct {
			label  string
			binary string
		}{
			{label: "reference", binary: reference},
			{label: "candidate", binary: candidate},
		} {
			home := filepath.Join(root, testCase.ID+"-"+implementation.label)
			actual, err := portcontract.Run(implementation.binary, testCase.Args, home, *timeoutFlag)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s infrastructure: %v", implementation.label, err))
				continue
			}
			failures = append(failures, compare(implementation.label, testCase, actual)...)
		}
		if len(failures) == 0 {
			fmt.Println("PASS", testCase.ID)
			continue
		}
		failed++
		fmt.Println("FAIL", testCase.ID)
		for _, failure := range failures {
			fmt.Println(" ", failure)
		}
	}

	fmt.Printf("\n%d/%d parity cases passed\n", len(golden.Cases)-failed, len(golden.Cases))
	if failed != 0 {
		os.Exit(1)
	}
}

func compare(label string, expected cliCase, actual portcontract.Result) []string {
	var failures []string
	if actual.TimedOut {
		failures = append(failures, label+" timed out")
		return failures
	}
	if actual.ExitCode != expected.ExitCode {
		failures = append(failures, fmt.Sprintf("%s exit_code: expected %d, got %d", label, expected.ExitCode, actual.ExitCode))
	}
	if string(actual.Stdout) != expected.Stdout {
		failures = append(failures, fmt.Sprintf("%s stdout: expected %q, got %q", label, expected.Stdout, actual.Stdout))
	}
	if string(actual.Stderr) != expected.Stderr {
		failures = append(failures, fmt.Sprintf("%s stderr: expected %q, got %q", label, expected.Stderr, actual.Stderr))
	}
	return failures
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(1)
}
