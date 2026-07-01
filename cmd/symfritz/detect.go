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

	if asJSON {
		type DetectResult struct {
			Host  string `json:"host"`
			IP    string `json:"ip"`
			Ready bool   `json:"ready"`
		}
		return printJSON(DetectResult{
			Host:  box.Host,
			IP:    ip,
			Ready: true,
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

	// Verify the detected IP works
	fmt.Printf("\nVerifying connection... ")
	client := fritz.New(ip)
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
