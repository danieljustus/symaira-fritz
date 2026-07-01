package main

import (
	"context"
	"fmt"

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

	routerCmd := &cobra.Command{
		Use:   "router",
		Short: "Detect and diagnose the local FRITZ!Box router",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDetect(cmd, asJSON)
		},
	}
	routerCmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	cmd.AddCommand(routerCmd)

	return cmd
}
