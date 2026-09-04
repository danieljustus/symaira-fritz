package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

func newDiagnoseCmd() *cobra.Command {
	var (
		asJSON bool
		ports  []int
	)
	cmd := &cobra.Command{
		Use:   "diagnose <host>",
		Short: "End-to-end reachability check for a host (name, MAC, or IP)",
		Long: `Diagnose resolves a host via the FRITZ!Box host table, then checks it
end-to-end from this machine: is it known, active, on LAN or WLAN, does its name
resolve via DNS, and are the relevant TCP ports reachable.

Default ports probed: 22 (SSH), 5900 (VNC/Screen Sharing), 8001 (Paperless).
Override with --port (repeatable).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := resolveOutputFormat(cmd, asJSON)
			if err != nil {
				return err
			}
			return runWithClient(cmd, "diagnosis failed", func(ctx context.Context, c *fritz.Client) error {
				opts := fritz.DiagnoseOptions{}
				for _, p := range ports {
					opts.Ports = append(opts.Ports, fritz.PortProbe{Port: p, Label: "custom"})
				}
				d := c.Diagnose(ctx, args[0], opts)
				if format != outputText {
					if err := printOutput(d, format); err != nil {
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
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	cmd.Flags().IntSliceVar(&ports, "port", nil, "TCP port to probe (repeatable; replaces default ports 22, 5900, 8001)")

	routerCmd := &cobra.Command{
		Use:   "router",
		Short: "Detect and diagnose the local FRITZ!Box router",
		Long: `Detect the local FRITZ!Box and run end-to-end diagnosis on it.

When SYMFRITZ_HOST is set, skips discovery and diagnoses that explicit host
directly.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDiagnoseRouter(cmd, asJSON, ports)
		},
	}
	routerCmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	routerCmd.Flags().IntSliceVar(&ports, "port", nil, "TCP port to probe (repeatable; replaces router defaults 49000, 49443, 80, 443)")
	cmd.AddCommand(routerCmd)

	return cmd
}

func runDiagnoseRouter(cmd *cobra.Command, asJSON bool, ports []int) error {
	format, err := resolveOutputFormat(cmd, asJSON)
	if err != nil {
		return err
	}
	box, _ := boxFromEnv()

	return runWithClient(cmd, "diagnosis failed", func(ctx context.Context, c *fritz.Client) error {
		httpClient := newHTTPClient()

		var routerHost string
		envHost := os.Getenv("SYMFRITZ_HOST")
		if envHost != "" {
			routerHost = envHost
		} else {
			ip, err := discoverBox(ctx, httpClient, box.Host, true)
			if err != nil {
				return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "could not find FRITZ!Box on the network")
			}
			routerHost = ip
		}
		c.Host = routerHost

		opts := fritz.DiagnoseOptions{Ports: fritz.RouterProbes}
		if len(ports) > 0 {
			opts.Ports = nil
			for _, p := range ports {
				opts.Ports = append(opts.Ports, fritz.PortProbe{Port: p, Label: "custom"})
			}
		}
		d := c.Diagnose(ctx, routerHost, opts)
		if format != outputText {
			if err := printOutput(d, format); err != nil {
				return err
			}
		} else {
			fmt.Printf("Diagnose router  →  %s\n", d.Target)
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
				exitcodes.ExitGeneric, exitcodes.KindUnavailable, "router not fully reachable")
		}
		return nil
	})
}
