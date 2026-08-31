package main

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-fritz/internal/config"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
	"github.com/danieljustus/symaira-fritz/internal/mcp"
)

func newMCPCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "mcp",
		Aliases:      []string{"serve"},
		Short:        "Start the MCP stdio server",
		Long:         "Start a JSON-RPC 2.0 MCP server over stdin/stdout for use with AI agents.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mcp.ServerVersion = version
			return runWithClientAndConfig(cmd, "mcp server failed", func(ctx context.Context, c *fritz.Client, _ *config.Config) error {
				return mcp.StartServer(ctx, c)
			})
		},
	}
}
