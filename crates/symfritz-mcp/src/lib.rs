#![deny(unsafe_code)]

//! The Rust MCP stdio server.
//!
//! This is intentionally a small protocol implementation rather than an MCP
//! SDK adapter. The Go `corekit/mcpserver` package is the wire contract for
//! symfritz, including its legacy newline transport and response semantics.

use std::{
    fmt,
    io::{self, BufRead, BufReader, Read, Write},
    sync::{Arc, Mutex},
    thread,
};

use serde::Serialize;
use serde_json::{Map, Value, json};

/// Protocol version returned by the Go corekit server.
pub const PROTOCOL_VERSION: &str = "2024-11-05";
/// Maximum header or line-mode message size accepted by the Go server.
pub const MAX_LINE_BYTES: usize = 1 << 20;
/// Maximum Content-Length accepted by the Go server.
pub const MAX_BODY_BYTES: usize = 1 << 20;

pub const CODE_PARSE_ERROR: i32 = -32700;
pub const CODE_INVALID_REQUEST: i32 = -32600;
pub const CODE_METHOD_NOT_FOUND: i32 = -32601;
pub const CODE_INVALID_PARAMS: i32 = -32602;
pub const CODE_INTERNAL_ERROR: i32 = -32603;

/// The capability boundary used by the protocol layer.
///
/// Implementations own configuration, credentials, transports, and router
/// clients. The protocol crate never contacts a router itself, which keeps
/// unit tests deterministic and prevents accidental real-box access.
pub trait Capabilities: Send {
    fn status(&mut self) -> Result<Value, String>;
    fn host_list(&mut self, active_only: bool) -> Result<Value, String>;
    fn host_get(
        &mut self,
        name: Option<&str>,
        mac: Option<&str>,
        ip: Option<&str>,
    ) -> Result<Value, String>;
    fn diagnose(&mut self, host: &str, ports: &[i64]) -> Result<Value, String>;
    fn mesh(&mut self) -> Result<Value, String>;
    fn wlan_clients(&mut self) -> Result<Value, String>;
    fn wake_on_lan(&mut self, host: Option<&str>, mac: Option<&str>) -> Result<Value, String>;
    fn home_list(&mut self) -> Result<Value, String>;
    fn home_switch(&mut self, ain: &str, on: bool) -> Result<Value, String>;
}

/// A tool definition as exposed by `tools/list`.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    pub annotations: ToolAnnotations,
}

/// MCP tool-behaviour hints. False-valued hints are omitted just like Go's
/// `omitempty` fields.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct ToolAnnotations {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(rename = "readOnlyHint", skip_serializing_if = "is_false")]
    pub read_only_hint: bool,
    #[serde(rename = "idempotentHint", skip_serializing_if = "is_false")]
    pub idempotent_hint: bool,
    #[serde(rename = "openWorldHint", skip_serializing_if = "is_false")]
    pub open_world_hint: bool,
    #[serde(rename = "destructiveHint", skip_serializing_if = "is_false")]
    pub destructive_hint: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn empty_schema() -> Value {
    json!({"type": "object", "properties": {}})
}

fn schema(properties: Value, required: &[&str]) -> Value {
    let mut object = Map::new();
    object.insert("type".to_owned(), Value::String("object".to_owned()));
    object.insert("properties".to_owned(), properties);
    if !required.is_empty() {
        object.insert("required".to_owned(), json!(required));
    }
    Value::Object(object)
}

/// The frozen nine-tool surface, in registration order.
pub fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "status".to_owned(),
            description: "FRITZ!Box overview: model, firmware, connection state, external IP.".to_owned(),
            input_schema: empty_schema(),
            annotations: ToolAnnotations { read_only_hint: true, idempotent_hint: true, ..Default::default() },
        },
        ToolDefinition {
            name: "host_list".to_owned(),
            description: "List devices in the FRITZ!Box host table (name, IP, MAC, active, LAN/WLAN).".to_owned(),
            input_schema: schema(json!({"active_only": {"type": "boolean", "description": "Only return currently active hosts"}}), &[]),
            annotations: ToolAnnotations { read_only_hint: true, idempotent_hint: true, ..Default::default() },
        },
        ToolDefinition {
            name: "host_get".to_owned(),
            description: "Look up one host by name, MAC, or IP. Provide exactly one of name/mac/ip.".to_owned(),
            input_schema: schema(json!({"name": {"type": "string"}, "mac": {"type": "string"}, "ip": {"type": "string"}}), &[]),
            annotations: ToolAnnotations { read_only_hint: true, idempotent_hint: true, ..Default::default() },
        },
        ToolDefinition {
            name: "diagnose".to_owned(),
            description: "End-to-end reachability check for a host (name/MAC/IP): known to box, active, LAN/WLAN, DNS, and TCP ports (default 22/5900/8001).".to_owned(),
            input_schema: schema(json!({"host": {"type": "string"}, "ports": {"type": "array", "items": {"type": "integer"}}}), &["host"]),
            annotations: ToolAnnotations { read_only_hint: true, idempotent_hint: true, ..Default::default() },
        },
        ToolDefinition {
            name: "mesh".to_owned(),
            description: "Mesh topology: nodes (box, repeaters, clients) and the links between them.".to_owned(),
            input_schema: empty_schema(),
            annotations: ToolAnnotations { read_only_hint: true, idempotent_hint: true, ..Default::default() },
        },
        ToolDefinition {
            name: "wlan_clients".to_owned(),
            description: "List devices associated with the WLAN radios (MAC, IP, signal, speed).".to_owned(),
            input_schema: empty_schema(),
            annotations: ToolAnnotations { read_only_hint: true, idempotent_hint: true, ..Default::default() },
        },
        ToolDefinition {
            name: "wake_on_lan".to_owned(),
            description: "Send a Wake-on-LAN packet via the box. Provide host (name/IP, resolved via host table) or mac.".to_owned(),
            input_schema: schema(json!({"host": {"type": "string"}, "mac": {"type": "string"}}), &[]),
            annotations: ToolAnnotations { open_world_hint: true, ..Default::default() },
        },
        ToolDefinition {
            name: "home_list".to_owned(),
            description: "List DECT smart-home actors (switches, thermostats) with AIN, name, and state.".to_owned(),
            input_schema: empty_schema(),
            annotations: ToolAnnotations { read_only_hint: true, idempotent_hint: true, ..Default::default() },
        },
        ToolDefinition {
            name: "home_switch".to_owned(),
            description: "Turn a DECT switch actor on or off by its AIN.".to_owned(),
            input_schema: schema(json!({"ain": {"type": "string"}, "on": {"type": "boolean"}}), &["ain", "on"]),
            annotations: ToolAnnotations { open_world_hint: true, ..Default::default() },
        },
    ]
}

/// Server-level instructions frozen from the Go implementation.
pub const INSTRUCTIONS: &str = "Query and control an AVM FRITZ!Box: connection status, the LAN/WLAN host table, mesh topology, WLAN clients, and DECT smart-home actors. For 'is host X reachable' questions use diagnose. Use host_list to find a device's MAC/IP before wake_on_lan or home_switch.";

/// A JSON-RPC server backed by an injectable capability implementation.
pub struct Server<C> {
    name: String,
    version: String,
    capabilities: Arc<Mutex<C>>,
    instructions: String,
}

impl<C: Capabilities + 'static> Server<C> {
    pub fn new(name: impl Into<String>, version: impl Into<String>, capabilities: C) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            capabilities: Arc::new(Mutex::new(capabilities)),
            instructions: INSTRUCTIONS.to_owned(),
        }
    }

    /// Run on process stdin/stdout. Diagnostics from clients belong on stderr;
    /// this method intentionally emits no output other than protocol frames.
    pub fn serve_stdio(&self) -> io::Result<()> {
        let stdin = io::stdin();
        let stdout = io::stdout();
        self.serve_io(stdin.lock(), stdout)
    }

    /// Run the Content-Length or newline-delimited protocol on arbitrary IO.
    pub fn serve_io<R: Read, W: Write + Send>(&self, reader: R, writer: W) -> io::Result<()> {
        let mut reader = BufReader::new(reader);
        let writer = Arc::new(Mutex::new(writer));
        thread::scope(|scope| {
            let mut workers: Vec<std::thread::ScopedJoinHandle<'_, ()>> = Vec::new();
            loop {
                let (request, mode) = match read_request(&mut reader) {
                    Ok(value) => value,
                    Err(ReadError::Eof) => break,
                    Err(ReadError::Parse { message, mode }) => {
                        for worker in workers.drain(..) {
                            let _ = worker.join();
                        }
                        send_error(
                            &writer,
                            mode,
                            None,
                            CODE_PARSE_ERROR,
                            &format!("Parse error: {message}"),
                        );
                        continue;
                    }
                    Err(ReadError::Io(error)) => return Err(error),
                };

                if request.method == "tools/call" {
                    let server = self.capabilities.clone();
                    let writer = writer.clone();
                    let name = self.name.clone();
                    let version = self.version.clone();
                    let instructions = self.instructions.clone();
                    workers.push(scope.spawn(move || {
                        handle_request(
                            &server,
                            &writer,
                            mode,
                            request,
                            &name,
                            &version,
                            &instructions,
                        )
                    }));
                } else {
                    handle_request(
                        &self.capabilities,
                        &writer,
                        mode,
                        request,
                        &self.name,
                        &self.version,
                        &self.instructions,
                    );
                }
            }
            for worker in workers {
                let _ = worker.join();
            }
            Ok(())
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Framed,
    Line,
}

#[derive(Debug)]
enum ReadError {
    Eof,
    Parse { message: String, mode: Mode },
    Io(io::Error),
}

#[derive(Debug)]
struct Request {
    id: Option<Value>,
    has_id: bool,
    method: String,
    params: Params,
}

#[derive(Debug)]
enum Params {
    Missing,
    Present(Value),
}

fn read_request<R: BufRead>(reader: &mut R) -> Result<(Request, Mode), ReadError> {
    let first = read_non_empty_line(reader)?;
    let mode = if first.starts_with('{') || !first.contains(':') {
        Mode::Line
    } else {
        Mode::Framed
    };
    if mode == Mode::Line {
        return parse_request(first.as_bytes(), Mode::Line).map(|request| (request, Mode::Line));
    }

    let mut content_length = None;
    parse_header(&first, &mut content_length)?;
    loop {
        let line = read_line_limited(reader)?;
        let line = trim_crlf(&line);
        if line.is_empty() {
            break;
        }
        parse_header(line, &mut content_length)?;
    }
    let length = content_length.ok_or_else(|| {
        ReadError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing Content-Length header",
        ))
    })?;
    if length == 0 || length > MAX_BODY_BYTES {
        return Err(ReadError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid Content-Length: {length}"),
        )));
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).map_err(|error| {
        ReadError::Io(io::Error::new(error.kind(), format!("read body: {error}")))
    })?;
    parse_request(&body, Mode::Framed).map(|request| (request, Mode::Framed))
}

fn parse_header(line: &str, content_length: &mut Option<usize>) -> Result<(), ReadError> {
    if let Some(value) = line.strip_prefix("Content-Length:") {
        let parsed = value.trim().parse::<usize>().map_err(|_| {
            ReadError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid Content-Length: {:?}", value.trim()),
            ))
        })?;
        *content_length = Some(parsed);
    }
    Ok(())
}

fn parse_request(body: &[u8], mode: Mode) -> Result<Request, ReadError> {
    let value: Value = serde_json::from_slice(body).map_err(|error| ReadError::Parse {
        message: error.to_string(),
        mode,
    })?;
    let object = value.as_object().ok_or_else(|| ReadError::Parse {
        message: "invalid JSON-RPC request".to_owned(),
        mode,
    })?;
    let jsonrpc = object.get("jsonrpc");
    if jsonrpc.is_some_and(|value| !value.is_string()) {
        return Err(ReadError::Parse {
            message: "invalid JSON-RPC request: jsonrpc must be a string".to_owned(),
            mode,
        });
    }
    let method = match object.get("method") {
        None => String::new(),
        Some(Value::String(method)) => method.clone(),
        Some(_) => {
            return Err(ReadError::Parse {
                message: "invalid JSON-RPC request: method must be a string".to_owned(),
                mode,
            });
        }
    };
    let id = object.get("id").cloned();
    Ok(Request {
        has_id: object.contains_key("id"),
        id,
        method,
        params: object
            .get("params")
            .cloned()
            .map_or(Params::Missing, Params::Present),
    })
}

fn read_non_empty_line<R: BufRead>(reader: &mut R) -> Result<String, ReadError> {
    loop {
        let line = read_line_limited(reader)?;
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_owned());
        }
    }
}

fn read_line_limited<R: BufRead>(reader: &mut R) -> Result<String, ReadError> {
    let mut bytes = Vec::new();
    let count = reader
        .read_until(b'\n', &mut bytes)
        .map_err(ReadError::Io)?;
    if count == 0 {
        return Err(ReadError::Eof);
    }
    if bytes.len() > MAX_LINE_BYTES {
        return Err(ReadError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("line exceeds {MAX_LINE_BYTES} bytes"),
        )));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn trim_crlf(line: &str) -> &str {
    line.trim_end_matches(['\r', '\n'])
}

fn handle_request<C: Capabilities + 'static>(
    capabilities: &Arc<Mutex<C>>,
    writer: &Arc<Mutex<impl Write>>,
    mode: Mode,
    request: Request,
    name: &str,
    version: &str,
    instructions: &str,
) {
    let panic_id = request.id.clone().unwrap_or(Value::Null);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        handle_request_inner(
            capabilities,
            writer,
            mode,
            request,
            name,
            version,
            instructions,
        );
    }));
    if result.is_err() {
        send_error(
            writer,
            mode,
            Some(panic_id),
            CODE_INTERNAL_ERROR,
            "Internal error: handler panicked",
        );
    }
}

fn handle_request_inner<C: Capabilities + 'static>(
    capabilities: &Arc<Mutex<C>>,
    writer: &Arc<Mutex<impl Write>>,
    mode: Mode,
    request: Request,
    name: &str,
    version: &str,
    instructions: &str,
) {
    // The Go implementation suppresses every notification before dispatch,
    // including unknown notifications.
    if !request.has_id && request.id.is_none() {
        return;
    }
    let id = request.id.clone().unwrap_or(Value::Null);
    match request.method.as_str() {
        "initialize" => {
            let mut result = Map::new();
            result.insert(
                "protocolVersion".to_owned(),
                Value::String(PROTOCOL_VERSION.to_owned()),
            );
            result.insert("capabilities".to_owned(), json!({"tools": {}}));
            result.insert(
                "serverInfo".to_owned(),
                json!({"name": name, "version": version}),
            );
            if !instructions.is_empty() {
                result.insert(
                    "instructions".to_owned(),
                    Value::String(instructions.to_owned()),
                );
            }
            send_result(writer, mode, id, Value::Object(result));
        }
        "ping" => send_result(writer, mode, id, json!({})),
        "tools/list" => send_result(writer, mode, id, json!({"tools": tool_definitions()})),
        "tools/call" => handle_tool_call(capabilities, writer, mode, id, request.params),
        method => send_error(
            writer,
            mode,
            Some(id),
            CODE_METHOD_NOT_FOUND,
            &format!("Method not found: {method}"),
        ),
    }
}

fn handle_tool_call<C: Capabilities + 'static>(
    capabilities: &Arc<Mutex<C>>,
    writer: &Arc<Mutex<impl Write>>,
    mode: Mode,
    id: Value,
    params: Params,
) {
    let params = match params {
        Params::Missing => {
            send_error(
                writer,
                mode,
                Some(id),
                CODE_INVALID_PARAMS,
                "Invalid params: EOF",
            );
            return;
        }
        Params::Present(value) if value.is_null() => Map::new(),
        Params::Present(Value::Object(object)) => object,
        Params::Present(_) => {
            send_error(
                writer,
                mode,
                Some(id),
                CODE_INVALID_PARAMS,
                "Invalid params: invalid type: expected object",
            );
            return;
        }
    };
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !tool_definitions().iter().any(|tool| tool.name == name) {
        send_error(
            writer,
            mode,
            Some(id),
            CODE_METHOD_NOT_FOUND,
            &format!("Unknown tool: {name}"),
        );
        return;
    }
    let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
    let result = dispatch_tool(capabilities, name, arguments);
    match result {
        Ok(value) => match to_json(&value) {
            Ok(text) => send_result(
                writer,
                mode,
                id,
                json!({"content": [{"type": "text", "text": text}], "isError": false}),
            ),
            Err(error) => send_tool_error(
                writer,
                mode,
                id,
                &format!("Failed to marshal tool result: {error}"),
            ),
        },
        Err(error) => send_tool_error(writer, mode, id, &error),
    }
}

fn dispatch_tool<C: Capabilities + 'static>(
    capabilities: &Arc<Mutex<C>>,
    name: &str,
    arguments: Value,
) -> Result<Value, String> {
    let mut capabilities = capabilities
        .lock()
        .map_err(|_| "internal error: capability lock poisoned".to_owned())?;
    match name {
        "status" => capabilities.status(),
        "host_list" => {
            // Go deliberately ignores the unmarshal error for host_list.
            let active_only = arguments
                .get("active_only")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            capabilities.host_list(active_only)
        }
        "host_get" => {
            let args = parse_object(&arguments)?;
            let name = optional_string(args.get("name"))?;
            let mac = optional_string(args.get("mac"))?;
            let ip = optional_string(args.get("ip"))?;
            if mac.is_none() && ip.is_none() && name.is_none() {
                return Err("provide one of name, mac, or ip".to_owned());
            }
            capabilities.host_get(name.as_deref(), mac.as_deref(), ip.as_deref())
        }
        "diagnose" => {
            let args = parse_object(&arguments)?;
            let host = args.get("host").and_then(Value::as_str).unwrap_or_default();
            if host.is_empty() {
                return Err("host is required".to_owned());
            }
            let ports = match args.get("ports") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(values)) => values
                    .iter()
                    .map(|value| value.as_i64().ok_or_else(|| "invalid port".to_owned()))
                    .collect::<Result<Vec<_>, _>>()?,
                Some(_) => return Err("invalid ports".to_owned()),
            };
            capabilities.diagnose(host, &ports)
        }
        "mesh" => capabilities.mesh(),
        "wlan_clients" => capabilities.wlan_clients(),
        "wake_on_lan" => {
            let args = parse_object(&arguments)?;
            let host = optional_string(args.get("host"))?;
            let mac = optional_string(args.get("mac"))?;
            if host.is_none() && mac.is_none() {
                return Err("provide host or mac".to_owned());
            }
            capabilities.wake_on_lan(host.as_deref(), mac.as_deref())
        }
        "home_list" => capabilities.home_list(),
        "home_switch" => {
            let args = parse_object(&arguments)?;
            let ain = args.get("ain").and_then(Value::as_str).unwrap_or_default();
            if ain.is_empty() {
                return Err("ain is required".to_owned());
            }
            let on = args.get("on").and_then(Value::as_bool).unwrap_or(false);
            capabilities.home_switch(ain, on)
        }
        _ => Err(format!("Unknown tool: {name}")),
    }
}

fn parse_object(value: &Value) -> Result<&Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| "invalid arguments: expected object".to_owned())
}

fn optional_string(value: Option<&Value>) -> Result<Option<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err("invalid argument: expected string".to_owned()),
    }
}

fn send_result<W: Write>(writer: &Arc<Mutex<W>>, mode: Mode, id: Value, result: Value) {
    send_json(
        writer,
        mode,
        json!({"jsonrpc": "2.0", "id": id, "result": result}),
    );
}

fn send_tool_error<W: Write>(writer: &Arc<Mutex<W>>, mode: Mode, id: Value, text: &str) {
    send_result(
        writer,
        mode,
        id,
        json!({"content": [{"type": "text", "text": text}], "isError": true}),
    );
}

fn send_error<W: Write>(
    writer: &Arc<Mutex<W>>,
    mode: Mode,
    id: Option<Value>,
    code: i32,
    message: &str,
) {
    send_json(
        writer,
        mode,
        json!({"jsonrpc": "2.0", "id": id.unwrap_or(Value::Null), "error": {"code": code, "message": message}}),
    );
}

fn send_json<W: Write>(writer: &Arc<Mutex<W>>, mode: Mode, value: Value) {
    let Ok(bytes) = serde_json::to_vec(&value) else {
        return;
    };
    let Ok(mut writer) = writer.lock() else {
        return;
    };
    match mode {
        Mode::Line => {
            let _ = writer.write_all(&bytes);
            let _ = writer.write_all(b"\n");
        }
        Mode::Framed => {
            let header = format!("Content-Length: {}\r\n\r\n", bytes.len());
            let _ = writer.write_all(header.as_bytes());
            let _ = writer.write_all(&bytes);
        }
    }
    let _ = writer.flush();
}

/// Pretty JSON serialization used by the nine symfritz handlers.
pub fn to_json(value: &Value) -> Result<String, serde_json::Error> {
    if let Value::String(text) = value {
        return Ok(text.clone());
    }
    serde_json::to_string_pretty(value)
}

/// A compact, reusable fake capability implementation helper for downstream
/// tests and fixture harnesses.
#[derive(Default)]
pub struct UnsupportedCapabilities;

impl Capabilities for UnsupportedCapabilities {
    fn status(&mut self) -> Result<Value, String> {
        Err("status unavailable".to_owned())
    }
    fn host_list(&mut self, _: bool) -> Result<Value, String> {
        Err("host_list unavailable".to_owned())
    }
    fn host_get(
        &mut self,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<Value, String> {
        Err("host_get unavailable".to_owned())
    }
    fn diagnose(&mut self, _: &str, _: &[i64]) -> Result<Value, String> {
        Err("diagnose unavailable".to_owned())
    }
    fn mesh(&mut self) -> Result<Value, String> {
        Err("mesh unavailable".to_owned())
    }
    fn wlan_clients(&mut self) -> Result<Value, String> {
        Err("wlan_clients unavailable".to_owned())
    }
    fn wake_on_lan(&mut self, _: Option<&str>, _: Option<&str>) -> Result<Value, String> {
        Err("wake_on_lan unavailable".to_owned())
    }
    fn home_list(&mut self) -> Result<Value, String> {
        Err("home_list unavailable".to_owned())
    }
    fn home_switch(&mut self, _: &str, _: bool) -> Result<Value, String> {
        Err("home_switch unavailable".to_owned())
    }
}

impl fmt::Debug for Server<UnsupportedCapabilities> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Server").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[derive(Default)]
    struct Fake;
    impl Capabilities for Fake {
        fn status(&mut self) -> Result<Value, String> {
            Ok(json!({"ok": true}))
        }
        fn host_list(&mut self, active: bool) -> Result<Value, String> {
            Ok(json!({"active": active}))
        }
        fn host_get(
            &mut self,
            name: Option<&str>,
            mac: Option<&str>,
            ip: Option<&str>,
        ) -> Result<Value, String> {
            Ok(json!({"name": name, "mac": mac, "ip": ip}))
        }
        fn diagnose(&mut self, host: &str, ports: &[i64]) -> Result<Value, String> {
            Ok(json!({"host": host, "ports": ports}))
        }
        fn mesh(&mut self) -> Result<Value, String> {
            Ok(json!({"mesh": true}))
        }
        fn wlan_clients(&mut self) -> Result<Value, String> {
            Ok(json!([]))
        }
        fn wake_on_lan(&mut self, host: Option<&str>, mac: Option<&str>) -> Result<Value, String> {
            Ok(json!({"host": host, "mac": mac}))
        }
        fn home_list(&mut self) -> Result<Value, String> {
            Ok(json!([]))
        }
        fn home_switch(&mut self, ain: &str, on: bool) -> Result<Value, String> {
            Ok(json!({"ain": ain, "on": on}))
        }
    }

    fn framed(value: &str) -> String {
        format!("Content-Length: {}\r\n\r\n{}", value.len(), value)
    }
    fn body(raw: &[u8]) -> Value {
        let text = String::from_utf8_lossy(raw);
        serde_json::from_str(
            text.split("\r\n\r\n")
                .nth(1)
                .unwrap_or(text.as_ref())
                .trim(),
        )
        .unwrap()
    }

    #[test]
    fn tool_surface_is_frozen() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 9);
        assert_eq!(
            tools.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
            [
                "status",
                "host_list",
                "host_get",
                "diagnose",
                "mesh",
                "wlan_clients",
                "wake_on_lan",
                "home_list",
                "home_switch"
            ]
        );
        assert!(tools[0].annotations.read_only_hint);
        assert!(tools[6].annotations.open_world_hint);
    }

    #[test]
    fn initialize_and_list_are_content_length_framed() {
        let input = framed(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#)
            + &framed(r#"{"jsonrpc":"2.0","id":"x","method":"tools/list"}"#);
        let mut output = Vec::new();
        Server::new("symfritz", "dev", Fake)
            .serve_io(Cursor::new(input), &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output.matches("Content-Length:").count(), 2);
        assert!(output.contains("2024-11-05"));
        assert!(output.contains("\"status\""));
    }

    #[test]
    fn ids_preserve_null_string_and_number_and_notifications_are_silent() {
        let input = framed(r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#)
            + &framed(r#"{"jsonrpc":"2.0","id":"abc","method":"ping"}"#)
            + &framed(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
            + &framed(r#"{"jsonrpc":"2.0","id":4,"method":"ping"}"#);
        let mut output = Vec::new();
        Server::new("symfritz", "dev", Fake)
            .serve_io(Cursor::new(input), &mut output)
            .unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("\"id\":null"));
        assert!(text.contains("\"id\":\"abc\""));
        assert!(text.contains("\"id\":4"));
        assert_eq!(text.matches("Content-Length:").count(), 3);
    }

    #[test]
    fn tool_success_is_indented_text_and_failure_is_tool_error() {
        let input = framed(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"status","arguments":{}}}"#,
        );
        let mut output = Vec::new();
        Server::new("symfritz", "dev", Fake)
            .serve_io(Cursor::new(input), &mut output)
            .unwrap();
        let response = body(&output);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\n  \"ok\": true"));
        assert_eq!(response["result"]["isError"], false);

        let input = framed(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"host_get","arguments":{}}}"#,
        );
        let mut output = Vec::new();
        Server::new("symfritz", "dev", Fake)
            .serve_io(Cursor::new(input), &mut output)
            .unwrap();
        let response = body(&output);
        assert_eq!(response["result"]["isError"], true);
        assert!(response["error"].is_null());
    }

    #[test]
    fn line_mode_and_parse_errors_match_corekit_shape() {
        let input = concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
            "\n",
            "{bad}\n"
        );
        let mut output = Vec::new();
        Server::new("symfritz", "dev", Fake)
            .serve_io(Cursor::new(input), &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output.lines().count(), 2);
        assert!(output.contains("\"code\":-32700"));
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn truncated_and_oversized_framed_messages_are_rejected() {
        let input = "a".repeat(MAX_LINE_BYTES + 1);
        let mut output = Vec::new();
        let error = Server::new("symfritz", "dev", Fake)
            .serve_io(Cursor::new(input), &mut output)
            .unwrap_err();
        assert!(error.to_string().contains("line exceeds"));
        assert!(output.is_empty());

        let truncated = "Content-Length: 10\r\n\r\n{}".to_owned();
        let mut output = Vec::new();
        let error = Server::new("symfritz", "dev", Fake)
            .serve_io(Cursor::new(truncated), &mut output)
            .unwrap_err();
        assert!(error.to_string().contains("read body"));
        assert!(output.is_empty());

        let oversized = format!("Content-Length: {}\r\n\r\n", MAX_BODY_BYTES + 1);
        let mut output = Vec::new();
        let error = Server::new("symfritz", "dev", Fake)
            .serve_io(Cursor::new(oversized), &mut output)
            .unwrap_err();
        assert!(error.to_string().contains("invalid Content-Length"));
        assert!(output.is_empty());
    }

    #[test]
    fn malformed_header_is_rejected_without_stdout() {
        let mut output = Vec::new();
        let error = Server::new("symfritz", "dev", Fake)
            .serve_io(Cursor::new("Content-Length: nope\r\n\r\n"), &mut output)
            .unwrap_err();
        assert!(error.to_string().contains("invalid Content-Length"));
        assert!(output.is_empty());
    }
}
