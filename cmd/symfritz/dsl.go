package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

func newDSLCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "dsl",
		Short: "Show DSL line statistics (noise margin, attenuation, max bit rate)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, err := resolveOutputFormat(cmd, asJSON)
			if err != nil {
				return err
			}
			return runWithClient(cmd, "dsl stats failed", func(ctx context.Context, c *fritz.Client) error {
				stats, err := c.DSLLineStats(ctx)
				if err != nil {
					return wrapFritzError(err, "dsl stats failed")
				}
				if format != outputText {
					return printOutput(stats, format)
				}

				fmt.Println("DSL Line Statistics:")
				fmt.Printf("Noise Margin:   %d dB (Up) / %d dB (Down)\n", stats.UpstreamNoiseMargin/10, stats.DownstreamNoiseMargin/10)
				fmt.Printf("Attenuation:    %d dB (Up) / %d dB (Down)\n", stats.UpstreamAttenuation/10, stats.DownstreamAttenuation/10)
				fmt.Printf("Max Bit Rate:   %s (Up) / %s (Down)\n", formatBitRate(stats.UpstreamMaxBitRate), formatBitRate(stats.DownstreamMaxBitRate))
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

func formatBitRate(bps int) string {
	if bps == 0 {
		return "—"
	}
	val := float64(bps)
	if val >= 1000000 {
		return fmt.Sprintf("%.2f Mbit/s", val/1000000.0)
	} else if val >= 1000 {
		return fmt.Sprintf("%.2f kbit/s", val/1000.0)
	}
	return fmt.Sprintf("%d bit/s", bps)
}
