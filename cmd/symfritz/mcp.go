package main

import (
	"context"

	"github.com/spf13/cobra"

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
			c, _, err := newClient()
			if err != nil {
				return err
			}
			return mcp.StartServer(context.Background(), c)
		},
	}
}
