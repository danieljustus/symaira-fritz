package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/danieljustus/symaira-corekit/exitcodes"
	"github.com/danieljustus/symaira-fritz/internal/config"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
	"github.com/danieljustus/symaira-fritz/internal/secret"
)

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage FRITZ!Box credentials (test, login, store)",
		Long: `Resolve, verify, and store the FRITZ!Box password.

Resolution order: SYMFRITZ_PASSWORD env → symvault (password_ref) → macOS
Keychain → plaintext config. 'auth login' captures the password once, verifies
it against the box, and stores it in the Keychain or symvault so nothing sits in
a dotfile.`,
	}
	cmd.AddCommand(newAuthTestCmd(), newAuthLoginCmd(), newAuthStoreCmd())
	return cmd
}

func newAuthTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Resolve the password and verify it against the box",
		RunE: func(cmd *cobra.Command, _ []string) error {
			box, _ := boxFromEnv()
			ctx := context.Background()
			res, err := secret.Resolve(ctx, secretOptions(box))
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitConfig, exitcodes.KindConfig, "credential resolution failed")
			}
			if res.Source == secret.SourceNone {
				return exitcodes.Wrap(fmt.Errorf("no password configured (run 'symfritz auth login')"),
					exitcodes.ExitNoAuth, exitcodes.KindAuth, "no credential")
			}
			fmt.Printf("Credential source: %s\n", res.Source)
			fmt.Printf("Box:               %s (user %q)\n", box.Host, box.User)

			sOK, tOK := verifyCredential(ctx, box, res.Password)
			fmt.Printf("  %s Web session login (login_sid.lua)\n", boolGlyph(sOK))
			fmt.Printf("  %s TR-064 access (DeviceInfo)\n", boolGlyph(tOK))
			if !tOK {
				fmt.Println("\nNote: TR-064 must be enabled on the box: Home Network → Network →\n" +
					"Network Settings → \"Allow access for applications\".")
			}
			if !sOK {
				return exitcodes.Wrap(fmt.Errorf("credential rejected by box"),
					exitcodes.ExitNoAuth, exitcodes.KindAuth, "invalid credential")
			}
			fmt.Println("\nOK: credential is valid.")
			return nil
		},
	}
}

func newAuthLoginCmd() *cobra.Command {
	var (
		toKeychain bool
		toSymvault string
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Prompt for the password, verify it, and store it securely",
		RunE: func(cmd *cobra.Command, _ []string) error {
			box, _ := boxFromEnv()
			ctx := context.Background()

			password, err := promptHidden(fmt.Sprintf("FRITZ!Box password for %s@%s: ", orDash(box.User), box.Host))
			if err != nil {
				return err
			}
			if password == "" {
				return exitcodes.Wrap(fmt.Errorf("empty password"),
					exitcodes.ExitConfig, exitcodes.KindValidation, "empty password")
			}

			// Verify before storing so we never persist a bad credential.
			sOK, tOK := verifyCredential(ctx, box, password)
			if !sOK {
				return exitcodes.Wrap(fmt.Errorf("box rejected the password"),
					exitcodes.ExitNoAuth, exitcodes.KindAuth, "invalid credential")
			}
			fmt.Printf("Verified: web login ✓  TR-064 %s\n", okWord(tOK))

			backend, hint, err := storeCredential(ctx, box, password, toKeychain, toSymvault)
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindInternal, "store failed")
			}
			fmt.Printf("Stored in %s.\n", backend)
			if hint != "" {
				fmt.Println(hint)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&toKeychain, "keychain", false, "Store in the macOS Keychain (default on macOS)")
	cmd.Flags().StringVar(&toSymvault, "symvault", "", "Store in symvault at this entry path (e.g. fritz.password)")
	return cmd
}

func newAuthStoreCmd() *cobra.Command {
	var (
		toKeychain bool
		toSymvault string
	)
	cmd := &cobra.Command{
		Use:   "store",
		Short: "Store a password (from prompt or SYMFRITZ_PASSWORD) without verifying",
		RunE: func(cmd *cobra.Command, _ []string) error {
			box, _ := boxFromEnv()
			ctx := context.Background()
			password := os.Getenv("SYMFRITZ_PASSWORD")
			if password == "" {
				var err error
				password, err = promptHidden(fmt.Sprintf("Password to store for %s: ", box.Host))
				if err != nil {
					return err
				}
			}
			if password == "" {
				return exitcodes.Wrap(fmt.Errorf("empty password"),
					exitcodes.ExitConfig, exitcodes.KindValidation, "empty password")
			}
			backend, hint, err := storeCredential(ctx, box, password, toKeychain, toSymvault)
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindInternal, "store failed")
			}
			fmt.Printf("Stored in %s.\n", backend)
			if hint != "" {
				fmt.Println(hint)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&toKeychain, "keychain", false, "Store in the macOS Keychain (default on macOS)")
	cmd.Flags().StringVar(&toSymvault, "symvault", "", "Store in symvault at this entry path")
	return cmd
}

// storeCredential persists password to the chosen backend and returns a label
// and an optional config hint. If neither flag is set it defaults to the
// Keychain on macOS, otherwise it requires an explicit --symvault path.
func storeCredential(ctx context.Context, box config.Box, password string, toKeychain bool, toSymvault string) (string, string, error) {
	switch {
	case toSymvault != "":
		if err := secret.SymvaultSet(ctx, toSymvault, password); err != nil {
			return "", "", err
		}
		hint := fmt.Sprintf("Set 'password_ref = \"%s\"' in ~/.config/symfritz/config.toml to use it.", toSymvault)
		return fmt.Sprintf("symvault (%s)", toSymvault), hint, nil

	case toKeychain || (!toKeychain && toSymvault == "" && secret.KeychainAvailable()):
		account := box.KeychainAccount
		if account == "" {
			account = box.Host
		}
		if err := secret.KeychainSet(ctx, secret.KeychainService, account, password); err != nil {
			return "", "", err
		}
		hint := "Set 'keychain = true' in ~/.config/symfritz/config.toml to use it."
		return fmt.Sprintf("macOS Keychain (service %q, account %q)", secret.KeychainService, account), hint, nil

	default:
		return "", "", fmt.Errorf("no storage backend available; use --symvault <path> (symvault not required to be running for storage on macOS Keychain)")
	}
}

// verifyCredential checks a password against the box via the web session login
// (always available) and a TR-064 call (only if TR-064 is enabled).
func verifyCredential(ctx context.Context, box config.Box, password string) (sessionOK, tr064OK bool) {
	c := newClientFor(box, password)
	if _, err := c.SID(ctx); err == nil {
		sessionOK = true
	}
	if _, err := c.Call(ctx, fritz.ServiceDeviceInfo, "GetInfo", nil); err == nil {
		tr064OK = true
	}
	return sessionOK, tr064OK
}

// promptHidden reads a line from the terminal without echoing it.
func promptHidden(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("cannot prompt for password: stdin is not a terminal (set SYMFRITZ_PASSWORD instead)")
	}
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}
