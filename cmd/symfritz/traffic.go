package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

func newTrafficCmd() *cobra.Command {
	var (
		asJSON   bool
		watch    bool
		interval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "traffic",
		Short: "Show WAN traffic statistics",
		Long: `Show downstream/upstream traffic by category. When --watch is set,
re-poll and append snapshots at the configured --interval until Ctrl-C.
In JSON mode (--json or --output json), --watch streams one compact JSON object
per line (NDJSON).

Examples:
  symfritz traffic                     # one-shot snapshot
  symfritz traffic --watch             # append snapshots periodically (exits on Ctrl-C)
  symfritz traffic --watch --json      # stream NDJSON objects (one per line)
  symfritz traffic --watch --interval 5s`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, err := resolveOutputFormat(cmd, asJSON)
			if err != nil {
				return err
			}
			return runWithClient(cmd, "traffic failed", func(ctx context.Context, c *fritz.Client) error {
				if watch {
					return runTrafficWatch(ctx, c, format, interval)
				}
				return runTrafficOnce(ctx, c, format)
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	cmd.Flags().BoolVar(&watch, "watch", false, "Continuously re-poll and append snapshots until Ctrl-C")
	cmd.Flags().DurationVar(&interval, "interval", 2*time.Second, "Polling interval for --watch mode")
	return cmd
}

func runTrafficOnce(ctx context.Context, c *fritz.Client, format outputFormat) error {
	stats, err := c.OnlineMonitor(ctx)
	if err != nil {
		return wrapFritzError(err, "traffic failed")
	}
	if format != outputText {
		return printOutput(stats, format)
	}
	printTrafficStats(stats)
	return nil
}

func runTrafficWatch(ctx context.Context, c *fritz.Client, format outputFormat, interval time.Duration) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		stats, err := c.OnlineMonitor(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return wrapFritzError(err, "traffic watch failed")
		}

		switch format {
		case outputJSON:
			b, err := json.Marshal(stats)
			if err != nil {
				return err
			}
			fmt.Println(string(b))
		case outputYAML:
			_ = printOutput(stats, format)
		default:
			printTrafficStats(stats)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

// printTrafficStats renders WAN traffic monitoring data as a box-drawing table.
func printTrafficStats(stats *fritz.TrafficData) {
	if stats == nil {
		fmt.Println("No traffic data available.")
		return
	}
	fmt.Println("WAN Traffic Statistics:")
	fmt.Println("┌─ Downstream ────────────────────────────────────────┐")
	printTrafficCategory("Internet", stats.DownstreamInternet)
	printTrafficCategory("Media", stats.DownstreamMedia)
	printTrafficCategory("Guest", stats.DownstreamGuest)
	fmt.Println("├─ Upstream ───────────────────────────────────────────┤")
	printTrafficCategory("Realtime", stats.UpstreamRealtime)
	printTrafficCategory("High Priority", stats.UpstreamHighPriority)
	printTrafficCategory("Default", stats.UpstreamDefaultPriority)
	printTrafficCategory("Low Priority", stats.UpstreamLowPriority)
	printTrafficCategory("Guest", stats.UpstreamGuest)
	fmt.Println("└──────────────────────────────────────────────────────┘")
}

func printTrafficCategory(name string, bps []float64) {
	val := 0.0
	if len(bps) > 0 {
		val = bps[0]
	}
	fmt.Printf("│  %-50s %12s │\n", name, formatSpeed(val))
}

func formatSpeed(bps float64) string {
	if bps == 0 {
		return "—"
	}
	if bps >= 1000000 {
		return fmt.Sprintf("%.2f Mbit/s", bps/1000000.0)
	}
	if bps >= 1000 {
		return fmt.Sprintf("%.2f kbit/s", bps/1000.0)
	}
	return fmt.Sprintf("%.0f bit/s", bps)
}
