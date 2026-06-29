package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
)

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
