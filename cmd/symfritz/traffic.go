package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

func newTrafficCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "traffic",
		Aliases: []string{"monitor"},
		Short:   "Show real-time WAN traffic monitoring data",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := newClient()
			if err != nil {
				return err
			}
			data, err := c.OnlineMonitor(context.Background())
			if err != nil {
				return wrapFritzError(err, "traffic failed")
			}
			if asJSON {
				return printJSON(data)
			}

			// Format lists nicely. Show the first value (most recent) of each list
			fmt.Println("WAN Traffic Monitoring (current rates):")
			fmt.Println("Downstream:")
			fmt.Printf("  Internet: %s\n", formatRateList(data.DownstreamInternet))
			fmt.Printf("  Media:    %s\n", formatRateList(data.DownstreamMedia))
			fmt.Printf("  Guest:    %s\n", formatRateList(data.DownstreamGuest))
			fmt.Println("Upstream:")
			fmt.Printf("  Realtime: %s\n", formatRateList(data.UpstreamRealtime))
			fmt.Printf("  High:     %s\n", formatRateList(data.UpstreamHighPriority))
			fmt.Printf("  Default:  %s\n", formatRateList(data.UpstreamDefaultPriority))
			fmt.Printf("  Low:      %s\n", formatRateList(data.UpstreamLowPriority))
			fmt.Printf("  Guest:    %s\n", formatRateList(data.UpstreamGuest))
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

func formatRateList(rates []float64) string {
	if len(rates) == 0 {
		return "—"
	}
	// The first value in the returned list is the most recent
	val := rates[0]
	// Convert bits per second to human-readable speed
	if val >= 1000000 {
		return fmt.Sprintf("%.2f Mbit/s", val/1000000.0)
	} else if val >= 1000 {
		return fmt.Sprintf("%.2f kbit/s", val/1000.0)
	}
	return fmt.Sprintf("%.0f bit/s", val)
}
