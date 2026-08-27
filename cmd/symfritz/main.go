// Command symfritz is a CLI to administer, analyse, and control an AVM FRITZ!Box.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
	"github.com/danieljustus/symaira-corekit/logkit"
	"github.com/danieljustus/symaira-fritz/internal/config"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
	"github.com/danieljustus/symaira-fritz/internal/secret"
)

var version = "0.4.4"

func main() {
	slog.SetDefault(logkit.NewFromEnv("symfritz"))

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := newRootCmd()
	root.SetContext(rootCtx)
	cmd, err := root.ExecuteC()
	if err != nil {
		// Map context.Canceled to a distinct exit code (Issue #123).
		if errors.Is(err, context.Canceled) {
			os.Exit(int(ExitCanceled))
		}
		localJSON, _ := cmd.Flags().GetBool("json")
		format := outputText
		if resolved, formatErr := resolveOutputFormat(cmd, localJSON); formatErr == nil {
			format = resolved
		}
		if format != outputText && cmd.Name() != "status" && cmd.Name() != "doctor" {
			printOutputError(err, format)
		} else {
			fmt.Fprintln(os.Stderr, "Error:", exitcodes.FormatCLIError(err))
		}
		os.Exit(int(exitcodes.ExitCodeFromError(err)))
	}

	// Propagate root context cancellation to cobra's RunE via ExecuteContext.
	_ = rootCtx
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "symfritz",
		Short:         "Administer, analyse, and control an AVM FRITZ!Box",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Long: `symfritz talks to a FRITZ!Box over its documented interfaces:

  TR-064  (SOAP)  administration: status, WAN/IP, WLAN, hosts, mesh, reboot
  AHA-HTTP        DECT smart-home actors (switches, thermostats)
  Session login   for AHA and (later) web-UI data scraping

Configure the box once with 'symfritz config init', then set the password via
the SYMFRITZ_PASSWORD environment variable.`,
	}
	root.PersistentFlags().String("output", "text", "Output format: text|json|yaml (--json is shorthand for --output json)")
	root.PersistentFlags().Bool("json", false, "Output as JSON (shorthand for --output json)")

	root.AddCommand(
		newStatusCmd(),
		newHostsCmd(),
		newDiagnoseCmd(),
		newDoctorCmd(),
		newMeshCmd(),
		newWLANCmd(),
		newWoLCmd(),
		newHomeCmd(),
		newCallCmd(),
		newScrapeCmd(),
		newServicesCmd(),
		newRebootCmd(),
		newAuthCmd(),
		newMCPCmd(),
		newConfigCmd(),
		newVersionCmd(),
		newTrafficCmd(),
		newDSLCmd(),
		newCallsCmd(),
		newDialCmd(),
		newHangupCmd(),
		newLogCmd(),
		newDetectCmd(),
	)
	root.AddCommand(newGenDocsCmd(root))
	return root
}

// boxFromEnv loads the box config and applies host/user environment overrides.
func boxFromEnv() (config.Box, *config.Config) {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: config error: %v\n", err)
		cfg = config.Defaults()
	}
	box := cfg.Box
	if env := os.Getenv("SYMFRITZ_HOST"); env != "" {
		box.Host = env
	}
	if env := os.Getenv("SYMFRITZ_USER"); env != "" {
		box.User = env
	}
	return box, cfg
}

// secretOptions maps box config to the credential-resolution options.
func secretOptions(box config.Box) secret.Options {
	account := box.KeychainAccount
	if account == "" {
		account = box.Host
	}
	return secret.Options{
		EnvVar:          "SYMFRITZ_PASSWORD",
		Ref:             box.PasswordRef,
		Keychain:        box.Keychain,
		KeychainAccount: account,
		Plaintext:       box.Password,
	}
}

// newClient builds a fritz.Client, resolving the password via the backend chain
// (env → symvault → keychain → plaintext).
var newClient = func() (*fritz.Client, *config.Config, error) {
	box, cfg := boxFromEnv()
	res, err := secret.Resolve(context.Background(), secretOptions(box))
	if err != nil {
		return nil, cfg, fmt.Errorf("could not resolve password: %w", err)
	}
	if res.Source == secret.SourceConfig {
		fmt.Fprintln(os.Stderr, "warning: password loaded from plaintext config. Consider 'symfritz auth login' for Keychain/symvault storage.")
	}
	return newClientFor(box, res.Password), cfg, nil
}

// newClientFor builds a client for a box with an explicit password. It is a
// var so tests can substitute a mock-URL client.
var newClientFor = func(box config.Box, password string) *fritz.Client {
	opts := []fritz.Option{
		fritz.WithUser(box.User),
		fritz.WithPassword(password),
		fritz.WithTimeout(box.Timeout()),
	}
	if box.UseTLS {
		opts = append(opts, fritz.WithTLS(box.InsecureTLS))
	}
	return fritz.New(box.Host, opts...)
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func dashIf(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func boolGlyph(ok bool) string {
	if ok {
		return "✓"
	}
	return "✗"
}

func okWord(ok bool) string {
	if ok {
		return "✓"
	}
	return "✗ (disabled or unavailable)"
}

func statusGlyph(st fritz.CheckStatus) string {
	switch st {
	case fritz.StatusOK:
		return "✓"
	case fritz.StatusFail:
		return "✗"
	case fritz.StatusWarn:
		return "!"
	default:
		return "·"
	}
}

func modelSuffix(model string) string {
	if strings.TrimSpace(model) == "" {
		return ""
	}
	return " " + model
}

func dataRate(link fritz.MeshLink) string {
	if link.CurDataRateRx == 0 && link.CurDataRateTx == 0 {
		return ""
	}
	return fmt.Sprintf("(%d/%d Mbit/s)", link.CurDataRateRx, link.CurDataRateTx)
}

// wrapFritzError converts a fritz.FritzError into an exitcodes.CLIError
// with the appropriate exit code, kind, and actionable hint.
func wrapFritzError(err error, msg string) error {
	if errors.Is(err, fritz.ErrNoCredential) {
		return exitcodes.Wrap(err, exitcodes.ExitNoAuth, exitcodes.KindAuth, "no credential")
	}

	var fe *fritz.FritzError
	if errors.As(err, &fe) {
		code := exitcodes.ExitGeneric
		kind := exitcodes.KindUnavailable
		switch fe.Kind {
		case fritz.ErrUnauthorized:
			code = exitcodes.ExitNoAuth
			kind = exitcodes.KindAuth
		case fritz.ErrUnsupportedAction:
			kind = exitcodes.KindNotFound
		case fritz.ErrTimeout:
			kind = exitcodes.KindUnavailable
		case fritz.ErrTransport:
			kind = exitcodes.KindUnavailable
		}
		cliErr := exitcodes.Wrap(err, code, kind, msg)
		cliErr.Hint = fe.Hint()
		return cliErr
	}
	return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, msg)
}

func printJSONError(err error) {
	printOutputError(err, outputJSON)
}

func printOutputError(err error, format outputFormat) {
	_ = writeOutput(os.Stdout, errorPayload(err), format)
}

func errorPayload(err error) any {
	type errDetails struct {
		Kind    string `json:"kind"`
		Service string `json:"service,omitempty"`
		Action  string `json:"action,omitempty"`
		Raw     string `json:"raw,omitempty"`
		Message string `json:"message,omitempty"`
	}
	type jsonErr struct {
		Error errDetails `json:"error"`
	}

	var fe *fritz.FritzError
	if errors.As(err, &fe) {
		return jsonErr{
			Error: errDetails{
				Kind:    string(fe.Kind),
				Service: fe.Service,
				Action:  fe.Action,
				Raw:     fe.Raw,
				Message: err.Error(),
			},
		}
	}

	var cliErr *exitcodes.CLIError
	if errors.As(err, &cliErr) {
		return jsonErr{
			Error: errDetails{
				Kind:    string(cliErr.Kind),
				Message: err.Error(),
			},
		}
	}

	// Fallback for non-FritzError/non-CLIError
	return jsonErr{
		Error: errDetails{
			Kind:    "unavailable",
			Message: err.Error(),
		},
	}
}
