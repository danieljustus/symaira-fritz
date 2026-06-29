package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
)

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
