// Package mcp exposes symfritz over the Model Context Protocol so AI agents can
// query and control the FRITZ!Box. It is a thin wrapper around the fritz client
// using the shared corekit MCP server.
//
// This is a starter surface: `status` and `home_list` are wired as examples.
// Add tools as the command set grows (wifi_guest, reboot, host_list, …).
package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/danieljustus/symaira-corekit/mcpserver"
	"github.com/danieljustus/symaira-fritz/internal/fritz"
)

// ServerVersion is injected by main so the MCP handshake reports the binary version.
var ServerVersion = "dev"

// StartServer runs the MCP stdio server backed by the given client.
func StartServer(ctx context.Context, c *fritz.Client) error {
	s := mcpserver.New("symfritz", ServerVersion)
	s.SetInstructions("Query and control an AVM FRITZ!Box: connection status, " +
		"WAN/IP, and DECT smart-home actors. Use status for an overview before " +
		"acting; use home_list to enumerate switchable devices and their AINs.")

	s.RegisterTool(&mcpserver.Tool{
		Name:        "status",
		Description: "Get a FRITZ!Box overview: model, firmware, connection state, external IP.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		Handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			return c.Status(ctx)
		},
	})

	s.RegisterTool(&mcpserver.Tool{
		Name:        "home_list",
		Description: "List DECT smart-home actors (switches, thermostats) with their AIN, name, and state.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		Handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			devs, err := c.Devices(ctx)
			if err != nil {
				return nil, err
			}
			return devs, nil
		},
	})

	// TODO: home_switch (ain, on/off), wifi_guest, reboot, host_list, call_raw.

	if err := s.ServeStdio(ctx); err != nil {
		return fmt.Errorf("mcp server: %w", err)
	}
	return nil
}
