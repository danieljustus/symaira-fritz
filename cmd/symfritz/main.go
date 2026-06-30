// Command symfritz is a CLI to administer, analyse, and control an AVM FRITZ!Box.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
	"github.com/danieljustus/symaira-corekit/logkit"
	"github.com/danieljustus/symaira-fritz/internal/config"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
	"github.com/danieljustus/symaira-fritz/internal/secret"
)

var version = "0.1.0-dev"

func main() {
	slog.SetDefault(logkit.NewFromEnv("symfritz"))
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", exitcodes.FormatCLIError(err))
		os.Exit(int(exitcodes.ExitCodeFromError(err)))
	}
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

	root.AddCommand(
		newStatusCmd(),
		newHostsCmd(),
		newDiagnoseCmd(),
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
func newClient() (*fritz.Client, *config.Config, error) {
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

// newClientFor builds a client for a box with an explicit password.
func newClientFor(box config.Box, password string) *fritz.Client {
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

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
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
