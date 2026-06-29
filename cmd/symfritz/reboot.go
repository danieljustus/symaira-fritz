package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

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
