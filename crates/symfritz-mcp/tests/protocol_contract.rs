#![deny(unsafe_code)]

use std::{
    io::{Cursor, Read, Write},
    sync::{Arc, Mutex},
};

use serde_json::{Value, json};
use symfritz_mcp::{
    CODE_INTERNAL_ERROR, CODE_INVALID_PARAMS, CODE_METHOD_NOT_FOUND, CODE_PARSE_ERROR,
    CancellationToken, Capabilities, Server, UnsupportedCapabilities, to_json,
};

type CallLog = Arc<Mutex<Vec<String>>>;

struct RecordingCapabilities {
    calls: CallLog,
    fail_on: Option<&'static str>,
}

impl RecordingCapabilities {
    fn new(calls: CallLog) -> Self {
        Self {
            calls,
            fail_on: None,
        }
    }

    fn failing(calls: CallLog, method: &'static str) -> Self {
        Self {
            calls,
            fail_on: Some(method),
        }
    }

    fn record(
        &mut self,
        method: &'static str,
        call: String,
        payload: Value,
    ) -> Result<Value, String> {
        self.calls.lock().unwrap().push(call);
        if self.fail_on == Some(method) {
            Err(format!("{method} backend failure"))
        } else {
            Ok(json!({"backend": method, "payload": payload}))
        }
    }
}

impl Capabilities for RecordingCapabilities {
    fn status(&mut self) -> Result<Value, String> {
        self.record("status", "status".to_owned(), json!({"ready": true}))
    }

    fn host_list(&mut self, active_only: bool) -> Result<Value, String> {
        self.record(
            "host_list",
            format!("host_list:{active_only}"),
            json!({"active_only": active_only}),
        )
    }

    fn host_get(
        &mut self,
        name: Option<&str>,
        mac: Option<&str>,
        ip: Option<&str>,
    ) -> Result<Value, String> {
        let selector = name
            .map(|value| format!("name={value}"))
            .or_else(|| mac.map(|value| format!("mac={value}")))
            .or_else(|| ip.map(|value| format!("ip={value}")))
            .unwrap_or_else(|| "no-selector".to_owned());
        self.record(
            "host_get",
            format!("host_get:{selector}"),
            json!({"name": name, "mac": mac, "ip": ip}),
        )
    }

    fn diagnose(&mut self, host: &str, ports: &[i64]) -> Result<Value, String> {
        self.record(
            "diagnose",
            format!("diagnose:{host}:{ports:?}"),
            json!({"host": host, "ports": ports}),
        )
    }

    fn mesh(&mut self) -> Result<Value, String> {
        self.record("mesh", "mesh".to_owned(), json!({"mesh": true}))
    }

    fn wlan_clients(&mut self) -> Result<Value, String> {
        self.record(
            "wlan_clients",
            "wlan_clients".to_owned(),
            json!([{"mac": "AA:BB:CC:DD:EE:FF"}]),
        )
    }

    fn wake_on_lan(&mut self, host: Option<&str>, mac: Option<&str>) -> Result<Value, String> {
        let selector = host
            .map(|value| format!("host={value}"))
            .or_else(|| mac.map(|value| format!("mac={value}")))
            .unwrap_or_else(|| "no-selector".to_owned());
        self.record(
            "wake_on_lan",
            format!("wake_on_lan:{selector}"),
            json!({"host": host, "mac": mac}),
        )
    }

    fn home_list(&mut self) -> Result<Value, String> {
        self.record("home_list", "home_list".to_owned(), json!([{"ain": "1"}]))
    }

    fn home_switch(&mut self, ain: &str, on: bool) -> Result<Value, String> {
        self.record(
            "home_switch",
            format!("home_switch:{ain}:{on}"),
            json!({"ain": ain, "on": on}),
        )
    }
}

fn tool_call(id: u64, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })
}

fn append_line(input: &mut Vec<u8>, value: &Value) {
    input.extend_from_slice(value.to_string().as_bytes());
    input.push(b'\n');
}

fn append_frame(input: &mut Vec<u8>, body: &str) {
    input.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    input.extend_from_slice(body.as_bytes());
}

fn line_responses(output: &[u8]) -> Vec<Value> {
    output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("line response should be JSON"))
        .collect()
}

fn mixed_responses(output: &[u8]) -> Vec<(bool, Value)> {
    let mut responses = Vec::new();
    let mut offset = 0;
    while offset < output.len() {
        if output[offset..].starts_with(b"Content-Length: ") {
            let header_end = output[offset..]
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| offset + index)
                .expect("framed response should have a header separator");
            let header = std::str::from_utf8(&output[offset..header_end]).unwrap();
            let length = header
                .strip_prefix("Content-Length: ")
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let body_start = header_end + 4;
            let body_end = body_start + length;
            assert!(body_end <= output.len(), "frame body must be complete");
            let body = &output[body_start..body_end];
            assert_eq!(body.len(), length, "Content-Length counts body bytes");
            responses.push((
                true,
                serde_json::from_slice(body).expect("framed response should be JSON"),
            ));
            offset = body_end;
        } else {
            let line_end = output[offset..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|index| offset + index)
                .expect("line response should end with newline");
            responses.push((
                false,
                serde_json::from_slice(&output[offset..line_end])
                    .expect("line response should be JSON"),
            ));
            offset = line_end + 1;
        }
    }
    responses
}

fn framed_responses(output: &[u8]) -> Vec<Value> {
    let responses = mixed_responses(output);
    assert!(responses.iter().all(|(framed, _)| *framed));
    responses
        .into_iter()
        .map(|(_, response)| response)
        .collect()
}

fn rpc_error_code(response: &Value) -> i64 {
    assert_eq!(response["jsonrpc"], "2.0");
    assert!(response.get("result").is_none());
    response["error"]["code"].as_i64().unwrap()
}

fn tool_result(response: &Value) -> Value {
    assert_eq!(response["jsonrpc"], "2.0");
    assert!(response.get("error").is_none());
    serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
        .expect("backend result should be encoded as JSON text")
}

#[test]
fn malformed_requests_and_unknown_methods_have_protocol_error_codes() {
    let mut input = b"{bad}\n[]\n".to_vec();
    input.extend_from_slice(
        concat!(
            "{\"jsonrpc\":false,\"id\":10,\"method\":\"ping\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":false}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"missing-method\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":13,\"method\":\"missing\"}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"unknown-notification\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"ping\"}\n"
        )
        .as_bytes(),
    );

    let mut output = Vec::new();
    Server::new(
        "symfritz",
        "test",
        RecordingCapabilities::new(Arc::default()),
    )
    .serve_io(Cursor::new(input), &mut output)
    .unwrap();
    let responses = line_responses(&output);
    assert_eq!(responses.len(), 7, "notifications produce no response");
    assert_eq!(
        responses[..4]
            .iter()
            .map(rpc_error_code)
            .collect::<Vec<_>>(),
        [CODE_PARSE_ERROR as i64; 4]
    );
    assert_eq!(responses[4]["id"], "missing-method");
    assert_eq!(rpc_error_code(&responses[4]), CODE_METHOD_NOT_FOUND as i64);
    assert_eq!(responses[5]["id"], 13);
    assert_eq!(rpc_error_code(&responses[5]), CODE_METHOD_NOT_FOUND as i64);
    assert_eq!(responses[6]["id"], Value::Null);
    assert_eq!(responses[6]["result"], json!({}));
}

#[test]
fn line_and_content_length_transports_preserve_framing_and_suppress_notifications() {
    let mut input = Vec::new();
    append_frame(
        &mut input,
        r#"{"jsonrpc":"2.0","id":"München","method":"ping"}"#,
    );
    input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n");
    input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":\"line\",\"method\":\"ping\"}\n");
    append_frame(&mut input, "{broken");
    input.extend_from_slice(b"{broken}\n");

    let mut output = Vec::new();
    Server::new(
        "symfritz",
        "test",
        RecordingCapabilities::new(Arc::default()),
    )
    .serve_io(Cursor::new(input), &mut output)
    .unwrap();
    let responses = mixed_responses(&output);
    assert_eq!(responses.len(), 4);
    assert!(responses[0].0);
    assert_eq!(responses[0].1["id"], "München");
    assert_eq!(responses[0].1["result"], json!({}));
    assert!(!responses[1].0);
    assert_eq!(responses[1].1["id"], "line");
    assert!(responses[2].0);
    assert_eq!(rpc_error_code(&responses[2].1), CODE_PARSE_ERROR as i64);
    assert!(!responses[3].0);
    assert_eq!(rpc_error_code(&responses[3].1), CODE_PARSE_ERROR as i64);
    assert!(output.ends_with(b"\n"));
}

#[test]
fn every_tool_dispatches_to_the_backend_with_validated_arguments_and_result_data() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut input = Vec::new();
    let requests = [
        tool_call(1, "status", json!({})),
        tool_call(2, "host_list", json!({"active_only": true})),
        tool_call(3, "host_list", json!({})),
        tool_call(4, "host_get", json!({"name": "laptop"})),
        tool_call(5, "host_get", json!({"mac": "AA:BB:CC:DD:EE:FF"})),
        tool_call(6, "host_get", json!({"ip": "192.0.2.4"})),
        tool_call(
            7,
            "diagnose",
            json!({"host": "laptop", "ports": [22, 5900]}),
        ),
        tool_call(8, "diagnose", json!({"host": "laptop", "ports": null})),
        tool_call(9, "mesh", json!({})),
        tool_call(10, "wlan_clients", json!({})),
        tool_call(11, "wake_on_lan", json!({"host": "laptop"})),
        tool_call(12, "wake_on_lan", json!({"mac": "AA:BB:CC:DD:EE:FF"})),
        tool_call(13, "home_list", json!({})),
        tool_call(14, "home_switch", json!({"ain": "12345", "on": true})),
        tool_call(15, "home_switch", json!({"ain": "12345", "on": false})),
    ];
    for request in requests {
        append_line(&mut input, &request);
    }

    let mut output = Vec::new();
    Server::new(
        "symfritz",
        "test",
        RecordingCapabilities::new(calls.clone()),
    )
    .serve_io(Cursor::new(input), &mut output)
    .unwrap();
    let responses = line_responses(&output);
    assert_eq!(responses.len(), 15);
    for (index, response) in responses.iter().enumerate() {
        assert_eq!(response["id"], index as u64 + 1);
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(
            tool_result(response)["backend"],
            match index {
                0 => "status",
                1 | 2 => "host_list",
                3..=5 => "host_get",
                6 | 7 => "diagnose",
                8 => "mesh",
                9 => "wlan_clients",
                10 | 11 => "wake_on_lan",
                12 => "home_list",
                _ => "home_switch",
            }
        );
    }
    assert_eq!(tool_result(&responses[1])["payload"]["active_only"], true);
    assert_eq!(tool_result(&responses[2])["payload"]["active_only"], false);
    assert_eq!(
        tool_result(&responses[6])["payload"]["ports"],
        json!([22, 5900])
    );
    assert_eq!(tool_result(&responses[7])["payload"]["ports"], json!([]));
    assert_eq!(tool_result(&responses[14])["payload"]["on"], false);
    assert_eq!(
        *calls.lock().unwrap(),
        [
            "status",
            "host_list:true",
            "host_list:false",
            "host_get:name=laptop",
            "host_get:mac=AA:BB:CC:DD:EE:FF",
            "host_get:ip=192.0.2.4",
            "diagnose:laptop:[22, 5900]",
            "diagnose:laptop:[]",
            "mesh",
            "wlan_clients",
            "wake_on_lan:host=laptop",
            "wake_on_lan:mac=AA:BB:CC:DD:EE:FF",
            "home_list",
            "home_switch:12345:true",
            "home_switch:12345:false",
        ]
    );
}

#[test]
fn malformed_tool_params_and_arguments_are_rejected_before_backend_calls() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut input = Vec::new();
    input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}\n");
    append_line(
        &mut input,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":["status"]}),
    );
    append_line(
        &mut input,
        &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":null}),
    );
    append_line(
        &mut input,
        &json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"not_a_tool"}}),
    );
    let invalid_arguments = [
        ("host_get", Value::Null),
        ("host_get", json!({"name": 42})),
        ("host_get", json!({})),
        (
            "host_get",
            json!({"name":"laptop","mac":"AA:BB:CC:DD:EE:FF"}),
        ),
        ("diagnose", json!({})),
        ("diagnose", json!({"host":"laptop","ports":"22"})),
        ("diagnose", json!({"host":"laptop","ports":["22"]})),
        ("wake_on_lan", json!({})),
        ("wake_on_lan", json!({"host": 7})),
        ("home_switch", json!({})),
        ("home_switch", json!({"ain":"12345"})),
        ("home_switch", json!({"ain":"12345","on":1})),
    ];
    for (offset, (name, arguments)) in invalid_arguments.into_iter().enumerate() {
        append_line(&mut input, &tool_call(offset as u64 + 5, name, arguments));
    }
    append_line(
        &mut input,
        &tool_call(17, "host_list", json!({"active_only":"yes"})),
    );

    let mut output = Vec::new();
    Server::new(
        "symfritz",
        "test",
        RecordingCapabilities::new(calls.clone()),
    )
    .serve_io(Cursor::new(input), &mut output)
    .unwrap();
    let responses = line_responses(&output);
    assert_eq!(responses.len(), 17);
    assert_eq!(rpc_error_code(&responses[0]), CODE_INVALID_PARAMS as i64);
    assert_eq!(rpc_error_code(&responses[1]), CODE_INVALID_PARAMS as i64);
    assert_eq!(rpc_error_code(&responses[2]), CODE_METHOD_NOT_FOUND as i64);
    assert_eq!(rpc_error_code(&responses[3]), CODE_METHOD_NOT_FOUND as i64);
    for response in &responses[4..16] {
        assert!(response.get("error").is_none());
        assert_eq!(response["result"]["isError"], true);
        assert!(response["result"]["content"][0]["text"].is_string());
    }
    assert_eq!(responses[16]["result"]["isError"], false);
    assert_eq!(*calls.lock().unwrap(), ["host_list:false"]);
}

struct PanickingCapabilities;

impl Capabilities for PanickingCapabilities {
    fn status(&mut self) -> Result<Value, String> {
        panic!("injected backend panic");
    }
    fn host_list(&mut self, _: bool) -> Result<Value, String> {
        Err("unused".to_owned())
    }
    fn host_get(
        &mut self,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<Value, String> {
        Err("unused".to_owned())
    }
    fn diagnose(&mut self, _: &str, _: &[i64]) -> Result<Value, String> {
        Err("unused".to_owned())
    }
    fn mesh(&mut self) -> Result<Value, String> {
        Err("unused".to_owned())
    }
    fn wlan_clients(&mut self) -> Result<Value, String> {
        Err("unused".to_owned())
    }
    fn wake_on_lan(&mut self, _: Option<&str>, _: Option<&str>) -> Result<Value, String> {
        Err("unused".to_owned())
    }
    fn home_list(&mut self) -> Result<Value, String> {
        Err("unused".to_owned())
    }
    fn home_switch(&mut self, _: &str, _: bool) -> Result<Value, String> {
        Err("unused".to_owned())
    }
}

#[test]
fn backend_errors_are_tool_errors_and_panics_become_internal_rpc_errors() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let request = tool_call(40, "status", json!({}));
    let mut input = Vec::new();
    append_line(&mut input, &request);
    let mut output = Vec::new();
    Server::new(
        "symfritz",
        "test",
        RecordingCapabilities::failing(calls.clone(), "status"),
    )
    .serve_io(Cursor::new(input), &mut output)
    .unwrap();
    let response = line_responses(&output).remove(0);
    assert_eq!(response["id"], 40);
    assert!(response.get("error").is_none());
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(
        response["result"]["content"][0]["text"],
        "status backend failure"
    );
    assert_eq!(*calls.lock().unwrap(), ["status"]);

    let mut input = Vec::new();
    append_line(&mut input, &tool_call(41, "status", json!({})));
    let mut output = Vec::new();
    Server::new("symfritz", "test", PanickingCapabilities)
        .serve_io(Cursor::new(input), &mut output)
        .unwrap();
    let response = line_responses(&output).remove(0);
    assert_eq!(response["id"], 41);
    assert_eq!(rpc_error_code(&response), CODE_INTERNAL_ERROR as i64);
    assert_eq!(
        response["error"]["message"],
        "Internal error: handler panicked"
    );
}

#[test]
fn initialize_and_tool_list_expose_frozen_protocol_metadata_and_annotations() {
    let mut input = Vec::new();
    append_line(
        &mut input,
        &json!({"jsonrpc":"2.0","id":"init","method":"initialize","params":{}}),
    );
    append_line(
        &mut input,
        &json!({"jsonrpc":"2.0","id":"list","method":"tools/list"}),
    );
    let mut output = Vec::new();
    Server::new(
        "symfritz",
        "2.8.1",
        RecordingCapabilities::new(Arc::default()),
    )
    .serve_io(Cursor::new(input), &mut output)
    .unwrap();
    let responses = line_responses(&output);
    assert_eq!(responses.len(), 2);
    let initialize = &responses[0]["result"];
    assert_eq!(initialize["protocolVersion"], "2024-11-05");
    assert_eq!(initialize["capabilities"], json!({"tools": {}}));
    assert_eq!(
        initialize["serverInfo"],
        json!({"name":"symfritz","version":"2.8.1"})
    );
    assert!(!initialize["instructions"].as_str().unwrap().is_empty());

    let tools = responses[1]["result"]["tools"].as_array().unwrap();
    let names: Vec<_> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "status",
            "host_list",
            "host_get",
            "diagnose",
            "mesh",
            "wlan_clients",
            "wake_on_lan",
            "home_list",
            "home_switch",
        ]
    );
    assert_eq!(tools[2]["inputSchema"]["additionalProperties"], false);
    assert_eq!(
        tools[2]["inputSchema"]["oneOf"].as_array().unwrap().len(),
        3
    );
    assert_eq!(tools[0]["annotations"]["readOnlyHint"], true);
    assert_eq!(tools[0]["annotations"]["idempotentHint"], true);
    assert!(tools[0]["annotations"].get("openWorldHint").is_none());
    assert!(tools[0]["annotations"].get("title").is_none());
    assert_eq!(tools[6]["annotations"]["openWorldHint"], true);
    assert_eq!(tools[8]["annotations"]["destructiveHint"], true);
    assert_eq!(tools[8]["annotations"]["idempotentHint"], true);
}

#[derive(Clone)]
struct SharedOutput(Arc<Mutex<Vec<u8>>>);

impl Write for SharedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn cancelable_stream_drains_calls_before_emitting_a_framed_parse_error() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut input = Vec::new();
    for id in 0..8 {
        append_frame(&mut input, &tool_call(id, "status", json!({})).to_string());
    }
    append_frame(&mut input, "{not-json");
    let output = Arc::new(Mutex::new(Vec::new()));
    let cancellation = CancellationToken::new();
    Server::new(
        "symfritz",
        "test",
        RecordingCapabilities::new(calls.clone()),
    )
    .serve_io_with_context(
        &cancellation,
        Cursor::new(input),
        SharedOutput(output.clone()),
    )
    .unwrap();

    let bytes = output.lock().unwrap().clone();
    let responses = framed_responses(&bytes);
    assert_eq!(responses.len(), 9);
    assert_eq!(
        rpc_error_code(responses.last().unwrap()),
        CODE_PARSE_ERROR as i64
    );
    let mut ids: Vec<_> = responses[..8]
        .iter()
        .map(|response| response["id"].as_u64().unwrap())
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, (0..8).collect::<Vec<_>>());
    assert!(
        responses[..8]
            .iter()
            .all(|response| response["result"]["isError"] == false)
    );
    assert_eq!(calls.lock().unwrap().len(), 8);
}

#[test]
fn unsupported_backend_error_contract_covers_each_public_tool_handler() {
    let cases = [
        ("status", json!({}), "status unavailable"),
        ("host_list", json!({}), "host_list unavailable"),
        (
            "host_get",
            json!({"name": "laptop"}),
            "host_get unavailable",
        ),
        (
            "diagnose",
            json!({"host": "laptop"}),
            "diagnose unavailable",
        ),
        ("mesh", json!({}), "mesh unavailable"),
        ("wlan_clients", json!({}), "wlan_clients unavailable"),
        (
            "wake_on_lan",
            json!({"host": "laptop"}),
            "wake_on_lan unavailable",
        ),
        ("home_list", json!({}), "home_list unavailable"),
        (
            "home_switch",
            json!({"ain": "12345", "on": true}),
            "home_switch unavailable",
        ),
    ];
    let mut input = Vec::new();
    for (id, (name, arguments, _)) in cases.iter().enumerate() {
        append_line(&mut input, &tool_call(id as u64, name, arguments.clone()));
    }
    let mut output = Vec::new();
    let server = Server::new("symfritz", "test", UnsupportedCapabilities);
    assert_eq!(format!("{server:?}"), "Server { .. }");
    server.serve_io(Cursor::new(input), &mut output).unwrap();
    let responses = line_responses(&output);
    assert_eq!(responses.len(), cases.len());
    for (response, (_, _, expected)) in responses.iter().zip(cases) {
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(response["result"]["content"][0]["text"], expected);
    }
}

struct FailingReader;

impl Read for FailingReader {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("injected read failure"))
    }
}

#[test]
fn reader_io_failures_propagate_through_sync_and_cancelable_streams() {
    let server = Server::new(
        "symfritz",
        "test",
        RecordingCapabilities::new(Arc::default()),
    );
    let mut output = Vec::new();
    let error = server.serve_io(FailingReader, &mut output).unwrap_err();
    assert_eq!(error.to_string(), "injected read failure");
    assert!(output.is_empty());

    let output = Arc::new(Mutex::new(Vec::new()));
    let cancellation = CancellationToken::new();
    let error = server
        .serve_io_with_context(&cancellation, FailingReader, SharedOutput(output.clone()))
        .unwrap_err();
    assert_eq!(error.to_string(), "injected read failure");
    assert!(output.lock().unwrap().is_empty());
}

#[test]
fn cancellation_token_reset_json_strings_and_cancelable_alias_keep_their_contracts() {
    let cancellation = CancellationToken::new();
    assert!(!cancellation.is_cancelled());
    cancellation.cancel();
    assert!(cancellation.is_cancelled());
    cancellation.reset();
    assert!(!cancellation.is_cancelled());
    assert_eq!(
        to_json(&Value::String("already serialized".to_owned())).unwrap(),
        "already serialized"
    );

    let output = Arc::new(Mutex::new(Vec::new()));
    Server::new(
        "symfritz",
        "test",
        RecordingCapabilities::new(Arc::default()),
    )
    .serve_io_cancelable(
        &cancellation,
        Cursor::new(Vec::<u8>::new()),
        SharedOutput(output),
    )
    .unwrap();
}

#[test]
fn length_framing_rejects_zero_and_missing_content_length_without_output() {
    for input in ["Content-Length: 0\r\n\r\n", "X-Trace: test\r\n\r\n{}"] {
        let mut output = Vec::new();
        let error = Server::new(
            "symfritz",
            "test",
            RecordingCapabilities::new(Arc::default()),
        )
        .serve_io(Cursor::new(input.as_bytes()), &mut output)
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(output.is_empty());
    }
}
