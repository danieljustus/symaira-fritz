package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

func newLogCmd() *cobra.Command {
	var (
		asJSON bool
		filter string
	)
	cmd := &cobra.Command{
		Use:   "log",
		Short: "Show FRITZ!Box system event log",
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, err := resolveOutputFormat(cmd, asJSON)
			if err != nil {
				return err
			}
			c, _, err := newClient()
			if err != nil {
				return err
			}
			events, err := c.DeviceLog(context.Background(), filter)
			if err != nil {
				return wrapFritzError(err, "log failed")
			}
			if format != outputText {
				return printOutput(events, format)
			}
			if len(events) == 0 {
				fmt.Println("No log events found.")
				return nil
			}

			for _, ev := range events {
				fmt.Printf("%s [%s] %s\n",
					ev.Time.Format("02.01.06 15:04:05"),
					ev.Group,
					ev.Msg,
				)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	cmd.Flags().StringVar(&filter, "filter", "all", "Filter by category (all, sys, net, fon, wlan, usb)")
	return cmd
}
