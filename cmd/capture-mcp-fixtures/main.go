// Command capture-mcp-fixtures generates language-neutral MCP wire fixtures
// from the pinned Go corekit server. Rust parity tests consume the result.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/danieljustus/symaira-corekit/mcpserver"
)

const instructions = "Query and control an AVM FRITZ!Box: connection status, the LAN/WLAN host table, mesh topology, WLAN clients, and DECT smart-home actors. For 'is host X reachable' questions use diagnose. Use host_list to find a device's MAC/IP before wake_on_lan or home_switch."

var emptySchema = json.RawMessage(`{"type":"object","properties":{}}`)

func main() {
	output := flag.String("output", "testdata/mcp/protocol-fixtures.json", "fixture output path")
	serve := flag.Bool("serve", false, "serve the deterministic oracle on stdio instead of writing fixtures")
	flag.Parse()
	server := fixtureServer()
	if *serve {
		if err := server.ServeStdio(context.Background()); err != nil {
			panic(err)
		}
		return
	}
	cases := []fixtureCase{
		{Name: "initialize", Request: frame(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)},
		{Name: "tools-list", Request: frame(`{"jsonrpc":"2.0","id":"list","method":"tools/list"}`)},
		{Name: "ping-null-id", Request: frame(`{"jsonrpc":"2.0","id":null,"method":"ping"}`)},
		{Name: "initialized-notification", Request: frame(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)},
		{Name: "status-success", Request: frame(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"status","arguments":{}}}`)},
		{Name: "home-switch-success", Request: frame(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"home_switch","arguments":{"ain":"123","on":true}}}`)},
		{Name: "handler-failure", Request: frame(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"host_get","arguments":{}}}`)},
		{Name: "unknown-tool", Request: frame(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"missing","arguments":{}}}`)},
		{Name: "invalid-params", Request: frame(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":"wrong"}`)},
		{Name: "parse-error", Request: frame(`{bad}`)},
	}
	for i := range cases {
		var response bytes.Buffer
		if err := server.ServeIO(context.Background(), bytes.NewReader([]byte(cases[i].Request)), &response); err != nil {
			// A malformed JSON body still produces a JSON-RPC parse response.
			// Transport/header errors are intentionally not fixtures.
			panic(fmt.Sprintf("fixture %s: %v", cases[i].Name, err))
		}
		cases[i].Response = responseBody(response.Bytes())
	}
	data, err := json.MarshalIndent(map[string]any{
		"format": "symfritz-mcp-fixture-v1",
		"cases":  cases,
	}, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.MkdirAll(filepathDir(*output), 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(*output, append(data, '\n'), 0o644); err != nil {
		panic(err)
	}
}

type fixtureCase struct {
	Name     string          `json:"name"`
	Request  string          `json:"request"`
	Response json.RawMessage `json:"response"`
}

func fixtureJSON(value any) string {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(data)
}

func frame(body string) string {
	return fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)
}

func responseBody(raw []byte) json.RawMessage {
	const separator = "\r\n\r\n"
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	body := raw
	if i := bytes.Index(raw, []byte(separator)); i >= 0 {
		body = raw[i+len(separator):]
	}
	return json.RawMessage(append([]byte(nil), bytes.TrimSpace(body)...))
}

func filepathDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			if i == 0 {
				return "."
			}
			return path[:i]
		}
	}
	return "."
}

func fixtureServer() *mcpserver.Server {
	s := mcpserver.New("symfritz", "dev")
	s.SetInstructions(instructions)
	add := func(name, description string, schema json.RawMessage, handler func(context.Context, json.RawMessage) (any, error), annotations mcpserver.ToolAnnotations) {
		s.RegisterTool(&mcpserver.Tool{Name: name, Description: description, InputSchema: schema, Annotations: &annotations, Handler: handler})
	}
	read := mcpserver.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true}
	write := mcpserver.ToolAnnotations{OpenWorldHint: true}
	add("status", "FRITZ!Box overview: model, firmware, connection state, external IP.", emptySchema, func(context.Context, json.RawMessage) (any, error) {
		return fixtureJSON(map[string]any{"ok": true}), nil
	}, read)
	add("host_list", "List devices in the FRITZ!Box host table (name, IP, MAC, active, LAN/WLAN).", json.RawMessage(`{"type":"object","properties":{"active_only":{"type":"boolean","description":"Only return currently active hosts"}}}`), func(context.Context, json.RawMessage) (any, error) { return map[string]any{"hosts": []any{}}, nil }, read)
	add("host_get", "Look up one host by name, MAC, or IP. Provide exactly one of name/mac/ip.", json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"},"mac":{"type":"string"},"ip":{"type":"string"}}}`), func(_ context.Context, input json.RawMessage) (any, error) {
		var args map[string]string
		if err := json.Unmarshal(input, &args); err != nil {
			return nil, err
		}
		if args["name"] == "" && args["mac"] == "" && args["ip"] == "" {
			return nil, fmt.Errorf("provide one of name, mac, or ip")
		}
		return args, nil
	}, read)
	add("diagnose", "End-to-end reachability check for a host (name/MAC/IP): known to box, active, LAN/WLAN, DNS, and TCP ports (default 22/5900/8001).", json.RawMessage(`{"type":"object","properties":{"host":{"type":"string"},"ports":{"type":"array","items":{"type":"integer"}}},"required":["host"]}`), func(context.Context, json.RawMessage) (any, error) { return map[string]any{"ok": true}, nil }, read)
	add("mesh", "Mesh topology: nodes (box, repeaters, clients) and the links between them.", emptySchema, func(context.Context, json.RawMessage) (any, error) { return map[string]any{"nodes": []any{}}, nil }, read)
	add("wlan_clients", "List devices associated with the WLAN radios (MAC, IP, signal, speed).", emptySchema, func(context.Context, json.RawMessage) (any, error) { return []any{}, nil }, read)
	add("wake_on_lan", "Send a Wake-on-LAN packet via the box. Provide host (name/IP, resolved via host table) or mac.", json.RawMessage(`{"type":"object","properties":{"host":{"type":"string"},"mac":{"type":"string"}}}`), func(_ context.Context, input json.RawMessage) (any, error) {
		var args map[string]string
		if err := json.Unmarshal(input, &args); err != nil {
			return nil, err
		}
		if args["host"] == "" && args["mac"] == "" {
			return nil, fmt.Errorf("provide host or mac")
		}
		return map[string]string{"woke": args["mac"]}, nil
	}, write)
	add("home_list", "List DECT smart-home actors (switches, thermostats) with AIN, name, and state.", emptySchema, func(context.Context, json.RawMessage) (any, error) { return []any{}, nil }, read)
	add("home_switch", "Turn a DECT switch actor on or off by its AIN.", json.RawMessage(`{"type":"object","properties":{"ain":{"type":"string"},"on":{"type":"boolean"}},"required":["ain","on"]}`), func(_ context.Context, input json.RawMessage) (any, error) {
		var args struct {
			AIN string `json:"ain"`
			On  bool   `json:"on"`
		}
		if err := json.Unmarshal(input, &args); err != nil {
			return nil, err
		}
		if args.AIN == "" {
			return nil, fmt.Errorf("ain is required")
		}
		return fixtureJSON(map[string]any{"ain": args.AIN, "on": args.On}), nil
	}, write)
	return s
}
