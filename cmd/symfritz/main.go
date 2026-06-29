// Command symfritz is a CLI to administer, analyse, and control an AVM FRITZ!Box.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/danieljustus/symaira-corekit/exitcodes"
	"github.com/danieljustus/symaira-corekit/logkit"
	"github.com/danieljustus/symaira-corekit/updatecheck"
	"github.com/danieljustus/symaira-fritz/internal/config"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
	"github.com/danieljustus/symaira-fritz/internal/mcp"
	"github.com/danieljustus/symaira-fritz/internal/secret"
)

var version = "0.1.0-dev"

func main() {
	slog.SetDefault(logkit.NewFromEnv("symfritz"))
	if err := newRootCmd().Execute(); err != nil {
		// Root sets SilenceErrors so cobra doesn't print; do it here once, with
		// the resolved exit code from corekit.
		fmt.Fprintln(os.Stderr, "Error:", err)
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

Known shortcuts: deviceinfo, wanip, wancommon, hosts, wlan1. Any other service
name is resolved via tr64desc.xml discovery (e.g. "WLANConfiguration:2").
Arguments are passed as Key=Value pairs (TR-064 input arguments).

Examples:
  symfritz call deviceinfo GetInfo
  symfritz call wanip GetExternalIPAddress
  symfritz call hosts GetGenericHostEntry NewIndex=0`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			ctx := context.Background()
			svc, ok := serviceByShortcut(args[0])
			if !ok {
				// Fall back to tr64desc.xml discovery for any advertised service.
				svc, err = c.ServiceByName(ctx, args[0])
				if err != nil {
					return exitcodes.Wrap(
						fmt.Errorf("unknown service %q: %w (known shortcuts: deviceinfo, wanip, wancommon, hosts, wlan1)", args[0], err),
						exitcodes.ExitConfig, exitcodes.KindValidation, "bad service")
				}
			}
			out, err := c.Call(ctx, svc, action, in)
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "tr064 call failed")
			}
			return printJSON(out)
		},
	}
	return cmd
}

func newScrapeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scrape <page> [Key=Value ...]",
		Short: "Fetch a data.lua page (best-effort, fragile)",
		Long: `Fetch raw JSON from the FRITZ!Box internal data.lua endpoint.

WARNING: This is a best-effort, version-fragile API.
AVM frequently changes the data.lua structure, endpoints, and variables
across FRITZ!OS updates. Use TR-064 or AHA whenever possible instead.

Arguments are passed as Key=Value POST parameters.

Examples:
  symfritz scrape netDev
  symfritz scrape dslStats`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			page := args[0]
			params := url.Values{}
			for _, kv := range args[1:] {
				k, v, found := strings.Cut(kv, "=")
				if !found {
					return exitcodes.Wrap(fmt.Errorf("argument %q is not Key=Value", kv),
						exitcodes.ExitConfig, exitcodes.KindValidation, "bad argument")
				}
				params.Add(k, v)
			}
			c, _, err := newClient()
			if err != nil {
				return err
			}
			out, err := c.ScrapeDataLUA(context.Background(), page, params)
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "scrape failed")
			}
			fmt.Println(out)
			return nil
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

	var listJSON bool
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
			if listJSON {
				return printJSON(devs)
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

	tempCmd := &cobra.Command{
		Use:   "temp <ain> <celsius|on|off>",
		Short: "Set the target temperature for a thermostat",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			ctx := context.Background()
			var temp float64
			switch strings.ToLower(args[1]) {
			case "on":
				temp = 254
			case "off":
				temp = 253
			default:
				var parseErr error
				temp, parseErr = strconv.ParseFloat(args[1], 64)
				if parseErr != nil {
					return exitcodes.Wrap(fmt.Errorf("temperature must be 'on', 'off', or a number (e.g. 20.5)"),
						exitcodes.ExitConfig, exitcodes.KindValidation, "bad temperature")
				}
			}
			if err := c.SetHkrTemp(ctx, args[0], temp); err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "set temp failed")
			}
			fmt.Printf("OK: %s -> %s\n", args[0], args[1])
			return nil
		},
	}

	listCmd.Flags().BoolVar(&listJSON, "json", false, "Output as JSON")
	cmd.AddCommand(listCmd, switchCmd, tempCmd)
	return cmd
}

func newHostsCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "hosts",
		Short: "FRITZ!Box host table (LAN/WLAN devices)",
	}

	printHosts := func(hosts []fritz.Host) error {
		if asJSON {
			return printJSON(hosts)
		}
		if len(hosts) == 0 {
			fmt.Println("No hosts found.")
			return nil
		}
		fmt.Printf("%-24s %-15s %-17s %-6s %-5s %s\n", "NAME", "IP", "MAC", "STATE", "LINK", "SOURCE")
		for _, h := range hosts {
			state := "down"
			if h.Active {
				state = "up"
			}
			fmt.Printf("%-24s %-15s %-17s %-6s %-5s %s\n",
				truncate(h.Name, 24), h.IP, h.MAC, state, h.Link(), h.AddressSource)
		}
		return nil
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all known hosts",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			hosts, err := c.Hosts(context.Background())
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "hosts failed")
			}
			return printHosts(hosts)
		},
	}

	activeCmd := &cobra.Command{
		Use:   "active",
		Short: "List only currently active hosts",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			hosts, err := c.ActiveHosts(context.Background())
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "hosts failed")
			}
			return printHosts(hosts)
		},
	}

	var byMAC, byIP string
	getCmd := &cobra.Command{
		Use:   "get [name]",
		Short: "Show one host by name, --mac, or --ip",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			ctx := context.Background()
			var host *fritz.Host
			switch {
			case byMAC != "":
				host, err = c.HostByMAC(ctx, byMAC)
			case byIP != "":
				host, err = c.HostByIP(ctx, byIP)
			case len(args) == 1:
				host, err = c.ResolveHost(ctx, args[0])
			default:
				return exitcodes.Wrap(fmt.Errorf("provide a name argument or --mac/--ip"),
					exitcodes.ExitConfig, exitcodes.KindValidation, "missing host reference")
			}
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitNotFound, exitcodes.KindNotFound, "host lookup failed")
			}
			if asJSON {
				return printJSON(host)
			}
			fmt.Printf("Name:    %s\n", orDash(host.Name))
			fmt.Printf("IP:      %s\n", orDash(host.IP))
			fmt.Printf("MAC:     %s\n", orDash(host.MAC))
			fmt.Printf("Active:  %v\n", host.Active)
			fmt.Printf("Link:    %s\n", host.Link())
			fmt.Printf("Source:  %s\n", orDash(host.AddressSource))
			fmt.Printf("Lease:   %ds\n", host.LeaseTimeRemaining)
			return nil
		},
	}
	getCmd.Flags().StringVar(&byMAC, "mac", "", "Look up by MAC address")
	getCmd.Flags().StringVar(&byIP, "ip", "", "Look up by IP address")

	cmd.PersistentFlags().BoolVar(&asJSON, "json", false, "Output as JSON")
	cmd.AddCommand(listCmd, activeCmd, getCmd)
	return cmd
}

func newDiagnoseCmd() *cobra.Command {
	var (
		asJSON bool
		ports  []int
	)
	cmd := &cobra.Command{
		Use:     "diagnose <host>",
		Aliases: []string{"doctor"},
		Short:   "End-to-end reachability check for a host (name, MAC, or IP)",
		Long: `Diagnose resolves a host via the FRITZ!Box host table, then checks it
end-to-end from this machine: is it known, active, on LAN or WLAN, does its name
resolve via DNS, and are the relevant TCP ports reachable.

Default ports probed: 22 (SSH), 5900 (VNC/Screen Sharing), 8001 (Paperless).
Override with --port (repeatable).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			opts := fritz.DiagnoseOptions{}
			for _, p := range ports {
				opts.Ports = append(opts.Ports, fritz.PortProbe{Port: p, Label: "custom"})
			}
			d := c.Diagnose(context.Background(), args[0], opts)
			if asJSON {
				if err := printJSON(d); err != nil {
					return err
				}
			} else {
				fmt.Printf("Diagnose %s", d.Ref)
				if d.Target != "" {
					fmt.Printf("  →  %s", d.Target)
				}
				fmt.Println()
				for _, ch := range d.Checks {
					fmt.Printf("  %s %-26s %s\n", statusGlyph(ch.Status), ch.Name, ch.Detail)
				}
				if d.OK {
					fmt.Println("\nResult: reachable (no failed checks)")
				} else {
					fmt.Println("\nResult: problems detected")
				}
			}
			if !d.OK {
				return exitcodes.Wrap(fmt.Errorf("diagnosis found failing checks"),
					exitcodes.ExitGeneric, exitcodes.KindUnavailable, "host not fully reachable")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	cmd.Flags().IntSliceVar(&ports, "port", nil, "TCP port to probe (repeatable; replaces default ports 22, 5900, 8001)")
	return cmd
}

func newMeshCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "mesh",
		Short: "Show the mesh topology (nodes, repeaters, links)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			topo, err := c.MeshTopology(context.Background())
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "mesh failed")
			}
			if asJSON {
				return printJSON(topo)
			}
			for _, n := range topo.Nodes {
				role := n.MeshRole
				if role == "" {
					role = "client"
				}
				fmt.Printf("● %s  [%s%s]\n", orDash(n.DeviceName), role, modelSuffix(n.DeviceModel))
				for _, iface := range n.Interfaces {
					for _, link := range iface.Links {
						if link.State == "" {
							continue
						}
						peer := topo.NodeName(link.Node2)
						if peer == n.DeviceName || peer == link.Node2 {
							peer = topo.NodeName(link.Node1)
						}
						fmt.Printf("    %-5s %-9s → %-20s %s\n",
							iface.Type, link.State, peer, dataRate(link))
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

func newWLANCmd() *cobra.Command {
	var (
		asJSON   bool
		guestIdx int
	)
	cmd := &cobra.Command{Use: "wlan", Short: "WLAN radios, clients, and guest network"}

	radiosCmd := &cobra.Command{
		Use:   "radios",
		Short: "List WLAN radios (SSID, band, channel, state)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			radios, err := c.Radios(context.Background(), 3)
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "wlan failed")
			}
			if asJSON {
				return printJSON(radios)
			}
			fmt.Printf("%-3s %-24s %-8s %-8s %s\n", "IDX", "SSID", "ENABLED", "CHANNEL", "STANDARD")
			for _, r := range radios {
				fmt.Printf("%-3d %-24s %-8v %-8s %s\n", r.Index, truncate(r.SSID, 24), r.Enabled, r.Channel, r.Standard)
			}
			return nil
		},
	}

	clientsCmd := &cobra.Command{
		Use:   "clients",
		Short: "List devices associated with the WLAN radios",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			clients, err := c.AllWLANClients(context.Background(), 3)
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "wlan clients failed")
			}
			if asJSON {
				return printJSON(clients)
			}
			fmt.Printf("%-3s %-17s %-15s %-7s %s\n", "RAD", "MAC", "IP", "SIGNAL", "SPEED")
			for _, cl := range clients {
				fmt.Printf("%-3d %-17s %-15s %-7s %s\n", cl.RadioIndex, cl.MAC, cl.IP, dashIf(cl.Signal), dashIf(cl.Speed))
			}
			return nil
		},
	}

	guestCmd := &cobra.Command{Use: "guest", Short: "Guest WLAN status/enable/disable"}
	guestStatus := &cobra.Command{
		Use:   "status",
		Short: "Show guest WLAN state",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			r, err := c.GuestWLANStatus(context.Background(), guestIdx)
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "guest status failed")
			}
			if asJSON {
				return printJSON(r)
			}
			fmt.Printf("Guest WLAN (index %d): SSID=%q enabled=%v\n", r.Index, r.SSID, r.Enabled)
			return nil
		},
	}
	guestOn := &cobra.Command{
		Use: "on", Short: "Enable guest WLAN",
		RunE: func(cmd *cobra.Command, _ []string) error { return setGuest(guestIdx, true) },
	}
	guestOff := &cobra.Command{
		Use: "off", Short: "Disable guest WLAN",
		RunE: func(cmd *cobra.Command, _ []string) error { return setGuest(guestIdx, false) },
	}
	guestCmd.AddCommand(guestStatus, guestOn, guestOff)

	cmd.PersistentFlags().BoolVar(&asJSON, "json", false, "Output as JSON")
	cmd.PersistentFlags().IntVar(&guestIdx, "guest-index", 3, "WLANConfiguration index of the guest radio")
	cmd.AddCommand(radiosCmd, clientsCmd, guestCmd)
	return cmd
}

func setGuest(idx int, enable bool) error {
	c, _, err := newClient()
	if err != nil {
		return err
	}
	if err := c.SetGuestWLAN(context.Background(), idx, enable); err != nil {
		return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "guest toggle failed")
	}
	state := "disabled"
	if enable {
		state = "enabled"
	}
	fmt.Printf("Guest WLAN (index %d) %s.\n", idx, state)
	return nil
}

func newWoLCmd() *cobra.Command {
	var byMAC string
	cmd := &cobra.Command{
		Use:   "wol [host]",
		Short: "Send a Wake-on-LAN packet via the FRITZ!Box",
		Long:  "Wake a host by name/IP (resolved via the host table) or by explicit --mac.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			ctx := context.Background()
			mac := byMAC
			if mac == "" {
				if len(args) != 1 {
					return exitcodes.Wrap(fmt.Errorf("provide a host argument or --mac"),
						exitcodes.ExitConfig, exitcodes.KindValidation, "missing host reference")
				}
				host, err := c.ResolveHost(ctx, args[0])
				if err != nil {
					return exitcodes.Wrap(err, exitcodes.ExitNotFound, exitcodes.KindNotFound, "host lookup failed")
				}
				mac = host.MAC
			}
			if mac == "" {
				return exitcodes.Wrap(fmt.Errorf("no MAC address resolved for target"),
					exitcodes.ExitGeneric, exitcodes.KindValidation, "no mac")
			}
			if err := c.WakeOnLAN(ctx, mac); err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "wol failed")
			}
			fmt.Printf("Wake-on-LAN packet sent to %s.\n", mac)
			return nil
		},
	}
	cmd.Flags().StringVar(&byMAC, "mac", "", "Target MAC address")
	return cmd
}

func newServicesCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "services",
		Short: "Discover TR-064 services advertised by the box (tr64desc.xml)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			box, _ := boxFromEnv()
			c := newClientFor(box, "")
			services, err := c.Discover(context.Background())
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "discovery failed")
			}
			if asJSON {
				return printJSON(services)
			}
			for _, s := range services {
				fmt.Printf("%-60s %s\n", s.Type, s.ControlURL)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
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

