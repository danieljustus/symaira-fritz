// Command symfritz is a CLI to administer, analyse, and control an AVM FRITZ!Box.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
	"github.com/danieljustus/symaira-corekit/logkit"
	"github.com/danieljustus/symaira-corekit/updatecheck"
	"github.com/danieljustus/symaira-fritz/internal/config"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
	"github.com/danieljustus/symaira-fritz/internal/mcp"
)

var version = "0.1.0-dev"

func main() {
	slog.SetDefault(logkit.NewFromEnv("symfritz"))
	if err := newRootCmd().Execute(); err != nil {
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
		newCallCmd(),
		newHomeCmd(),
		newRebootCmd(),
		newMCPCmd(),
		newConfigCmd(),
		newVersionCmd(),
	)
	return root
}

// newClient builds a fritz.Client from config + environment.
func newClient() (*fritz.Client, *config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: config error: %v\n", err)
		cfg = config.Defaults()
	}
	box := cfg.Box

	// Environment override for the password is the recommended path.
	if env := os.Getenv("SYMFRITZ_PASSWORD"); env != "" {
		box.Password = env
	}
	if env := os.Getenv("SYMFRITZ_HOST"); env != "" {
		box.Host = env
	}
	if env := os.Getenv("SYMFRITZ_USER"); env != "" {
		box.User = env
	}

	opts := []fritz.Option{
		fritz.WithUser(box.User),
		fritz.WithPassword(box.Password),
		fritz.WithTimeout(box.Timeout()),
	}
	if box.UseTLS {
		opts = append(opts, fritz.WithTLS(box.InsecureTLS))
	}
	return fritz.New(box.Host, opts...), cfg, nil
}

func newStatusCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show a box overview (model, firmware, connection, external IP)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			st, err := c.Status(context.Background())
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "status failed")
			}
			if asJSON {
				return printJSON(st)
			}
			fmt.Printf("Model:       %s\n", orDash(st.ModelName))
			fmt.Printf("Firmware:    %s\n", orDash(st.FirmwareVersion))
			fmt.Printf("Connection:  %s\n", orDash(st.ConnectionState))
			fmt.Printf("External IP: %s\n", orDash(st.ExternalIP))
			fmt.Printf("Uptime (s):  %s\n", orDash(st.Uptime))
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

// newCallCmd is the power-user escape hatch: raw TR-064 action invocation.
func newCallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "call <service> <action> [Key=Value ...]",
		Short: "Invoke a raw TR-064 action (power user)",
		Long: `Invoke any TR-064 action by service shortcut and action name.

Known service shortcuts: deviceinfo, wanip, wancommon, hosts, wlan1.
Arguments are passed as Key=Value pairs (TR-064 input arguments).

Examples:
  symfritz call deviceinfo GetInfo
  symfritz call wanip GetExternalIPAddress
  symfritz call hosts GetGenericHostEntry NewIndex=0`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, ok := serviceByShortcut(args[0])
			if !ok {
				return exitcodes.Wrap(
					fmt.Errorf("unknown service %q (known: deviceinfo, wanip, wancommon, hosts, wlan1)", args[0]),
					exitcodes.ExitConfig, exitcodes.KindValidation, "bad service")
			}
			action := args[1]
			in := map[string]string{}
			for _, kv := range args[2:] {
				k, v, found := strings.Cut(kv, "=")
				if !found {
					return exitcodes.Wrap(fmt.Errorf("argument %q is not Key=Value", kv),
						exitcodes.ExitConfig, exitcodes.KindValidation, "bad argument")
				}
				in[k] = v
			}
			c, _, err := newClient()
			if err != nil {
				return err
			}
			out, err := c.Call(context.Background(), svc, action, in)
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "tr064 call failed")
			}
			return printJSON(out)
		},
	}
	return cmd
}

func serviceByShortcut(name string) (fritz.Service, bool) {
	switch strings.ToLower(name) {
	case "deviceinfo":
		return fritz.ServiceDeviceInfo, true
	case "wanip":
		return fritz.ServiceWANIPConnection, true
	case "wancommon":
		return fritz.ServiceWANCommonIFC, true
	case "hosts":
		return fritz.ServiceHosts, true
	case "wlan1":
		return fritz.ServiceWLANConfig1, true
	default:
		return fritz.Service{}, false
	}
}

func newHomeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "home",
		Short: "DECT smart-home actors (switches, thermostats)",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List DECT actors with AIN, name, and state",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			devs, err := c.Devices(context.Background())
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "device list failed")
			}
			if len(devs) == 0 {
				fmt.Println("No DECT smart-home actors found.")
				return nil
			}
			for _, d := range devs {
				state := "n/a"
				if d.Switch.State == "1" {
					state = "on"
				} else if d.Switch.State == "0" {
					state = "off"
				}
				present := "offline"
				if d.Present == 1 {
					present = "online"
				}
				fmt.Printf("%-16s  %-20s  %-8s  %s\n", d.Identifier, d.Name, state, present)
			}
			return nil
		},
	}

	switchCmd := &cobra.Command{
		Use:   "switch <ain> <on|off>",
		Short: "Turn a switch actor on or off",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			ctx := context.Background()
			switch strings.ToLower(args[1]) {
			case "on":
				err = c.SwitchOn(ctx, args[0])
			case "off":
				err = c.SwitchOff(ctx, args[0])
			default:
				return exitcodes.Wrap(fmt.Errorf("state must be on or off"),
					exitcodes.ExitConfig, exitcodes.KindValidation, "bad state")
			}
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "switch failed")
			}
			fmt.Printf("OK: %s -> %s\n", args[0], strings.ToLower(args[1]))
			return nil
		},
	}

	cmd.AddCommand(listCmd, switchCmd)
	return cmd
}

func newRebootCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "reboot",
		Short: "Reboot the FRITZ!Box",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !yes {
				return exitcodes.Wrap(fmt.Errorf("refusing to reboot without --yes"),
					exitcodes.ExitConfig, exitcodes.KindValidation, "confirmation required")
			}
			c, _, err := newClient()
			if err != nil {
				return err
			}
			svc := fritz.Service{
				Type:       "urn:dslforum-org:service:DeviceConfig:1",
				ControlURL: "/upnp/control/deviceconfig",
			}
			if _, err := c.Call(context.Background(), svc, "Reboot", nil); err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "reboot failed")
			}
			fmt.Println("Reboot triggered.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "Confirm the reboot")
	return cmd
}

func newMCPCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "mcp",
		Aliases:      []string{"serve"},
		Short:        "Start the MCP stdio server",
		Long:         "Start a JSON-RPC 2.0 MCP server over stdin/stdout for use with AI agents.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mcp.ServerVersion = version
			c, _, err := newClient()
			if err != nil {
				return err
			}
			return mcp.StartServer(context.Background(), c)
		},
	}
}

func newConfigCmd() *cobra.Command {
	cfg := &cobra.Command{Use: "config", Short: "Manage symfritz configuration"}

	initCmd := &cobra.Command{
		Use:          "init",
		Short:        "Write default config to ~/.config/symfritz/config.toml",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitConfig, exitcodes.KindConfig, "cannot determine home directory")
			}
			dir := home + "/.config/symfritz"
			if err := os.MkdirAll(dir, 0755); err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitConfig, exitcodes.KindConfig, "cannot create config directory")
			}
			path := dir + "/config.toml"
			force, _ := cmd.Flags().GetBool("force")
			if _, err := os.Stat(path); err == nil && !force {
				fmt.Fprintf(os.Stderr, "config already exists at %s (use --force to overwrite)\n", path)
				return nil
			}
			if err := os.WriteFile(path, []byte(config.DefaultConfigTOML()), 0600); err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitConfig, exitcodes.KindConfig, "cannot write config file")
			}
			fmt.Printf("Config written to %s\n", path)
			return nil
		},
	}
	initCmd.Flags().Bool("force", false, "overwrite existing config file")
	cfg.AddCommand(initCmd)
	return cfg
}

func newVersionCmd() *cobra.Command {
	var check bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Println("symfritz", version)
			if check {
				checker := updatecheck.NewChecker("danieljustus", "symaira-fritz")
				release, err := checker.Check(context.Background(), version)
				if err != nil {
					fmt.Fprintf(os.Stderr, "update check failed: %v\n", err)
					return nil
				}
				if release != nil {
					fmt.Printf("Update available: %s\nDownload: %s\n", release.TagName, release.HTMLURL)
				} else {
					fmt.Println("Already up to date.")
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "Check for updates on GitHub")
	return cmd
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

// sortedKeys is a small helper kept for future tabular output of Call results.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var _ = sortedKeys // referenced once commands format Call output as tables
