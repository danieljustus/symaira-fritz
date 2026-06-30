// Package mcp exposes symfritz over the Model Context Protocol so AI agents can
// query and control the FRITZ!Box. It is a thin wrapper around the fritz client
// using the shared corekit MCP server.
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

const emptyObjectSchema = `{"type":"object","properties":{}}`

// toJSON marshals v to an indented JSON string suitable for MCP content.text.
// The MCP spec requires content[].text to be a string; this ensures structured
// results are serialized as JSON strings rather than raw objects.
func toJSON(v any) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// StartServer runs the MCP stdio server backed by the given client.
func StartServer(ctx context.Context, c *fritz.Client) error {
	s := buildServer(c)
	if err := s.ServeStdio(ctx); err != nil {
		return fmt.Errorf("mcp server: %w", err)
	}
	return nil
}

func buildServer(c *fritz.Client) *mcpserver.Server {
	s := mcpserver.New("symfritz", ServerVersion)
	s.SetInstructions("Query and control an AVM FRITZ!Box: connection status, " +
		"the LAN/WLAN host table, mesh topology, WLAN clients, and DECT smart-home " +
		"actors. For 'is host X reachable' questions use diagnose. Use host_list to " +
		"find a device's MAC/IP before wake_on_lan or home_switch.")

	s.RegisterTool(&mcpserver.Tool{
		Name:        "status",
		Description: "FRITZ!Box overview: model, firmware, connection state, external IP.",
		InputSchema: json.RawMessage(emptyObjectSchema),
		Handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			st, err := c.Status(ctx)
			if err != nil {
				return nil, err
			}
			return toJSON(st)
		},
	})

	s.RegisterTool(&mcpserver.Tool{
		Name:        "host_list",
		Description: "List devices in the FRITZ!Box host table (name, IP, MAC, active, LAN/WLAN).",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"active_only":{"type":"boolean","description":"Only return currently active hosts"}}}`),
		Handler: func(ctx context.Context, in json.RawMessage) (any, error) {
			var args struct {
				ActiveOnly bool `json:"active_only"`
			}
			_ = json.Unmarshal(in, &args)
			if args.ActiveOnly {
				hosts, err := c.ActiveHosts(ctx)
				if err != nil {
					return nil, err
				}
				return toJSON(hosts)
			}
			hosts, err := c.Hosts(ctx)
			if err != nil {
				return nil, err
			}
			return toJSON(hosts)
		},
	})

	s.RegisterTool(&mcpserver.Tool{
		Name:        "host_get",
		Description: "Look up one host by name, MAC, or IP. Provide exactly one of name/mac/ip.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"},"mac":{"type":"string"},"ip":{"type":"string"}}}`),
		Handler: func(ctx context.Context, in json.RawMessage) (any, error) {
			var args struct{ Name, MAC, IP string }
			if err := json.Unmarshal(in, &args); err != nil {
				return nil, err
			}
			var (
				host *fritz.Host
				err  error
			)
			switch {
			case args.MAC != "":
				host, err = c.HostByMAC(ctx, args.MAC)
			case args.IP != "":
				host, err = c.HostByIP(ctx, args.IP)
			case args.Name != "":
				host, err = c.ResolveHost(ctx, args.Name)
			default:
				return nil, fmt.Errorf("provide one of name, mac, or ip")
			}
			if err != nil {
				return nil, err
			}
			return toJSON(host)
		},
	})

	s.RegisterTool(&mcpserver.Tool{
		Name:        "diagnose",
		Description: "End-to-end reachability check for a host (name/MAC/IP): known to box, active, LAN/WLAN, DNS, and TCP ports (default 22/5900/8001).",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"host":{"type":"string"},"ports":{"type":"array","items":{"type":"integer"}}},"required":["host"]}`),
		Handler: func(ctx context.Context, in json.RawMessage) (any, error) {
			var args struct {
				Host  string `json:"host"`
				Ports []int  `json:"ports"`
			}
			if err := json.Unmarshal(in, &args); err != nil {
				return nil, err
			}
			if args.Host == "" {
				return nil, fmt.Errorf("host is required")
			}
			var opts fritz.DiagnoseOptions
			for _, p := range args.Ports {
				opts.Ports = append(opts.Ports, fritz.PortProbe{Port: p, Label: "custom"})
			}
			return toJSON(c.Diagnose(ctx, args.Host, opts))
		},
	})

	s.RegisterTool(&mcpserver.Tool{
		Name:        "mesh",
		Description: "Mesh topology: nodes (box, repeaters, clients) and the links between them.",
		InputSchema: json.RawMessage(emptyObjectSchema),
		Handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			topo, err := c.MeshTopology(ctx)
			if err != nil {
				return nil, err
			}
			return toJSON(topo)
		},
	})

	s.RegisterTool(&mcpserver.Tool{
		Name:        "wlan_clients",
		Description: "List devices associated with the WLAN radios (MAC, IP, signal, speed).",
		InputSchema: json.RawMessage(emptyObjectSchema),
		Handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			clients, err := c.AllWLANClients(ctx, 3)
			if err != nil {
				return nil, err
			}
			return toJSON(clients)
		},
	})

	s.RegisterTool(&mcpserver.Tool{
		Name:        "wake_on_lan",
		Description: "Send a Wake-on-LAN packet via the box. Provide host (name/IP, resolved via host table) or mac.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"host":{"type":"string"},"mac":{"type":"string"}}}`),
		Handler: func(ctx context.Context, in json.RawMessage) (any, error) {
			var args struct{ Host, MAC string }
			if err := json.Unmarshal(in, &args); err != nil {
				return nil, err
			}
			mac := args.MAC
			if mac == "" {
				if args.Host == "" {
					return nil, fmt.Errorf("provide host or mac")
				}
				h, err := c.ResolveHost(ctx, args.Host)
				if err != nil {
					return nil, err
				}
				mac = h.MAC
			}
			if err := c.WakeOnLAN(ctx, mac); err != nil {
				return nil, err
			}
			return toJSON(map[string]string{"woke": mac})
		},
	})

	s.RegisterTool(&mcpserver.Tool{
		Name:        "home_list",
		Description: "List DECT smart-home actors (switches, thermostats) with AIN, name, and state.",
		InputSchema: json.RawMessage(emptyObjectSchema),
		Handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			devices, err := c.Devices(ctx)
			if err != nil {
				return nil, err
			}
			return toJSON(devices)
		},
	})

	s.RegisterTool(&mcpserver.Tool{
		Name:        "home_switch",
		Description: "Turn a DECT switch actor on or off by its AIN.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"ain":{"type":"string"},"on":{"type":"boolean"}},"required":["ain","on"]}`),
		Handler: func(ctx context.Context, in json.RawMessage) (any, error) {
			var args struct {
				AIN string `json:"ain"`
				On  bool   `json:"on"`
			}
			if err := json.Unmarshal(in, &args); err != nil {
				return nil, err
			}
			if args.AIN == "" {
				return nil, fmt.Errorf("ain is required")
			}
			var err error
			if args.On {
				err = c.SwitchOn(ctx, args.AIN)
			} else {
				err = c.SwitchOff(ctx, args.AIN)
			}
			if err != nil {
				return nil, err
			}
			return toJSON(map[string]any{"ain": args.AIN, "on": args.On})
		},
	})

	return s
}
