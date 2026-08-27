package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newServicesCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "services",
		Short: "Discover TR-064 services advertised by the box (tr64desc.xml)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, err := resolveOutputFormat(cmd, asJSON)
			if err != nil {
				return err
			}
			box, _ := boxFromEnv()
			c := newClientFor(box, "")
			services, err := c.Discover(cmd.Context())
			if err != nil {
				return wrapFritzError(err, "discovery failed")
			}
			if format != outputText {
				return printOutput(services, format)
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
