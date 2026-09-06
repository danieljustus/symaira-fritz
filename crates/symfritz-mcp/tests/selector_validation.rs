#![deny(unsafe_code)]

use std::io::Cursor;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use serde_json::{Value, json};
use symfritz_mcp::{Capabilities, Server, tool_definitions};

#[derive(Clone, Default)]
struct CountingCapabilities {
    calls: Arc<AtomicUsize>,
}

impl Capabilities for CountingCapabilities {
    fn status(&mut self) -> Result<Value, String> {
        Ok(json!({}))
    }
    fn host_list(&mut self, _: bool) -> Result<Value, String> {
        Ok(json!([]))
    }
    fn host_get(
        &mut self,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<Value, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"ok": true}))
    }
    fn diagnose(&mut self, _: &str, _: &[i64]) -> Result<Value, String> {
        Ok(json!({}))
    }
    fn mesh(&mut self) -> Result<Value, String> {
        Ok(json!({}))
    }
    fn wlan_clients(&mut self) -> Result<Value, String> {
        Ok(json!([]))
    }
    fn wake_on_lan(&mut self, _: Option<&str>, _: Option<&str>) -> Result<Value, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"ok": true}))
    }
    fn home_list(&mut self) -> Result<Value, String> {
        Ok(json!([]))
    }
    fn home_switch(&mut self, _: &str, _: bool) -> Result<Value, String> {
        Ok(json!({}))
    }
}

fn call(tool: &str, arguments: Value, capabilities: CountingCapabilities) -> Value {
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    });
    let mut output = Vec::new();
    Server::new("symfritz", "test", capabilities)
        .serve_io(Cursor::new(format!("{request}\n")), &mut output)
        .expect("server should process request");
    serde_json::from_slice(output.trim_ascii()).expect("response should be JSON")
}

#[test]
fn selector_tool_schemas_are_exclusive_and_closed() {
    let definitions = tool_definitions();
    let host_get = definitions
        .iter()
        .find(|tool| tool.name == "host_get")
        .unwrap();
    let wake_on_lan = definitions
        .iter()
        .find(|tool| tool.name == "wake_on_lan")
        .unwrap();

    for schema in [&host_get.input_schema, &wake_on_lan.input_schema] {
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert!(
            schema["oneOf"]
                .as_array()
                .is_some_and(|variants| !variants.is_empty())
        );
    }
    assert_eq!(host_get.input_schema["oneOf"].as_array().unwrap().len(), 3);
    assert_eq!(
        wake_on_lan.input_schema["oneOf"].as_array().unwrap().len(),
        2
    );
}

#[test]
fn runtime_rejects_zero_or_multiple_selectors_without_calling_capability() {
    let cases = [
        ("host_get", json!({})),
        (
            "host_get",
            json!({"name": "laptop", "mac": "AA:BB:CC:DD:EE:FF"}),
        ),
        ("host_get", json!({"name": "laptop", "ip": "192.0.2.1"})),
        (
            "host_get",
            json!({"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.0.2.1"}),
        ),
        ("wake_on_lan", json!({})),
        (
            "wake_on_lan",
            json!({"host": "laptop", "mac": "AA:BB:CC:DD:EE:FF"}),
        ),
    ];
    for (tool, arguments) in cases {
        let capabilities = CountingCapabilities::default();
        let calls = capabilities.calls.clone();
        let response = call(tool, arguments, capabilities);
        assert_eq!(
            response["result"]["isError"], true,
            "invalid selectors accepted: {tool}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "capability called for invalid selectors: {tool}"
        );
    }
}

#[test]
fn valid_single_selector_behavior_is_preserved() {
    for (tool, arguments) in [
        ("host_get", json!({"name": "laptop"})),
        ("host_get", json!({"mac": "AA:BB:CC:DD:EE:FF"})),
        ("host_get", json!({"ip": "192.0.2.1"})),
        ("wake_on_lan", json!({"host": "laptop"})),
        ("wake_on_lan", json!({"mac": "AA:BB:CC:DD:EE:FF"})),
    ] {
        let capabilities = CountingCapabilities::default();
        let calls = capabilities.calls.clone();
        let response = call(tool, arguments, capabilities);
        assert_eq!(
            response["result"]["isError"], false,
            "valid selector rejected: {tool}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "valid selector did not reach capability: {tool}"
        );
    }
}
