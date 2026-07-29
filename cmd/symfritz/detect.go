package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-corekit/exitcodes"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

func newDetectCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "detect",
		Short: "Detect the local FRITZ!Box on the network",
		Long: `Detect attempts to find a FRITZ!Box on the local network by:
  1. Checking if the configured host resolves to a private IP
  2. Probing the system default gateway
  3. Trying common FRITZ!Box default IPs

This is useful when 'fritz.box' resolves to a public IP instead of your local
FRITZ!Box, causing connection timeouts.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDetect(cmd, asJSON)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

func runDetect(cmd *cobra.Command, asJSON bool) error {
	box, _ := boxFromEnv()
	ctx := context.Background()

	// Create an HTTP client for probing
	httpClient := newHTTPClient()

	// Run discovery
	ip, err := fritz.DiscoverBox(ctx, httpClient, box.Host, true)
	if err != nil {
		return exitcodes.Wrap(err, exitcodes.ExitGeneric, exitcodes.KindUnavailable, "detect failed")
	}

	// Probe unauthenticated WAN capacity/traffic via IGD
	client := fritz.New(ip)
	linkStats, _ := client.DSLLineStats(ctx)
	trafficStats, _ := client.OnlineMonitor(ctx)

	var (
		downMax, upMax int
		downBps, upBps float64
		hasIGD         bool
	)
	if linkStats != nil && (linkStats.DownstreamMaxBitRate > 0 || linkStats.UpstreamMaxBitRate > 0) {
		downMax = linkStats.DownstreamMaxBitRate
		upMax = linkStats.UpstreamMaxBitRate
		hasIGD = true
	}
	if trafficStats != nil && len(trafficStats.DownstreamInternet) > 0 {
		downBps = trafficStats.DownstreamInternet[0]
		if len(trafficStats.UpstreamDefaultPriority) > 0 {
			upBps = trafficStats.UpstreamDefaultPriority[0]
		}
		hasIGD = true
	}

	if asJSON {
		type DetectResult struct {
			Host                 string  `json:"host"`
			IP                   string  `json:"ip"`
			Ready                bool    `json:"ready"`
			DownstreamMaxBitRate int     `json:"downstream_max_bit_rate,omitempty"`
			UpstreamMaxBitRate   int     `json:"upstream_max_bit_rate,omitempty"`
			CurrentDownstreamBps float64 `json:"current_downstream_bps,omitempty"`
			CurrentUpstreamBps   float64 `json:"current_upstream_bps,omitempty"`
			IsReducedDataset     bool    `json:"is_reduced_dataset,omitempty"`
		}
		return printJSON(DetectResult{
			Host:                 box.Host,
			IP:                   ip,
			Ready:                true,
			DownstreamMaxBitRate: downMax,
			UpstreamMaxBitRate:   upMax,
			CurrentDownstreamBps: downBps,
			CurrentUpstreamBps:   upBps,
			IsReducedDataset:     hasIGD,
		})
	}

	// Human-readable output
	fmt.Printf("Detected FRITZ!Box at: %s\n", ip)
	if ip != box.Host {
		fmt.Printf("Configured host: %s\n", box.Host)
		fmt.Printf("\nSuggested config snippet:\n")
		fmt.Printf("  [box]\n")
		fmt.Printf("  host = \"%s\"\n", ip)
	}

	if hasIGD {
		if downMax > 0 || upMax > 0 {
			fmt.Printf("Link Capacity (IGD):     %d/%d bps (down/up)\n", downMax, upMax)
		}
		if downBps > 0 || upBps > 0 {
			fmt.Printf("Current Throughput (IGD): %.0f/%.0f bps (down/up)\n", downBps, upBps)
		}
	}

	// Verify the detected IP works
	fmt.Printf("\nVerifying connection... ")
	_, err = client.Discover(ctx)
	if err != nil {
		fmt.Printf("failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ok\n")

	return nil
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed box cert; discovery-only
		},
	}
}
