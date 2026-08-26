package main

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
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
			return runWithClient(cmd, "scrape failed", func(ctx context.Context, c *fritz.Client) error {
				out, err := c.ScrapeDataLUA(ctx, page, params)
				if err != nil {
					return wrapFritzError(err, "scrape failed")
				}
				fmt.Println(out)
				return nil
			})
		},
	}
	return cmd
}
