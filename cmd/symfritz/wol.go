package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
)

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
