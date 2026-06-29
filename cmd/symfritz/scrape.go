package main

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
)

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
