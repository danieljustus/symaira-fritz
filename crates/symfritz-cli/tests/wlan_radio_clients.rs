#![deny(unsafe_code)]

//! Black-box coverage for advertised-radio WLAN client aggregation.
//!
//! Both production adapters — `symfritz wlan clients` and the MCP
//! `wlan_clients` tool — must report the clients of every WLANConfiguration
//! service the box advertises, including the fourth radio on tri-band models.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

use serde_json::Value;

/// One associated client: radio index, MAC and IP address.
#[derive(Clone)]
struct Client {
    radio: usize,
    mac: &'static str,
    ip: &'static str,
}

/// The box under test: advertised WLANConfiguration services and clients.
#[derive(Clone)]
struct Fixture {
    radios: Vec<usize>,
    clients: Vec<Client>,
}

impl Fixture {
    /// Tri-band box: four radios, its only client associated with radio 4.
    fn four_radio() -> Self {
        Self {
            radios: vec![1, 2, 3, 4],
            clients: vec![Client {
                radio: 4,
                mac: "AA:BB:CC:DD:EE:04",
                ip: "192.168.1.40",
            }],
        }
    }

    /// Dual-band box: three radios, clients on radios 1 and 3, none on 2.
    fn three_radio() -> Self {
        Self {
            radios: vec![1, 2, 3],
            clients: vec![
                Client {
                    radio: 1,
                    mac: "AA:BB:CC:DD:EE:01",
                    ip: "192.168.1.41",
                },
                Client {
                    radio: 3,
                    mac: "AA:BB:CC:DD:EE:03",
                    ip: "192.168.1.43",
                },
            ],
        }
    }

    fn radio_clients(&self, radio: usize) -> Vec<&Client> {
        self.clients
            .iter()
            .filter(|client| client.radio == radio)
            .collect()
    }
}

/// A loopback FRITZ!Box double that records the requests it served.
struct MockBox {
    port: u16,
    home: PathBuf,
    requests: Arc<Mutex<Vec<(String, String)>>>,
}

impl MockBox {
    fn start(fixture: Fixture) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock box");
        let port = listener.local_addr().expect("mock box address").port();
        let requests: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
        let sink = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else {
                    return;
                };
                let _ = serve(stream, &fixture, &sink);
            }
        });

        let home = std::env::temp_dir().join(format!(
            "symfritz-wlan-clients-{}-{port}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join("tmp")).expect("mock home");
        Self {
            port,
            home,
            requests,
        }
    }

    /// Requests served with authentication, as (path, SOAP action) pairs.
    fn served(&self) -> Vec<(String, String)> {
        self.requests.lock().expect("mock request log").clone()
    }

    fn served_contains(&self, path: &str, action: &str) -> bool {
        self.served()
            .iter()
            .any(|(seen_path, seen_action)| seen_path == path && seen_action == action)
    }

    /// Point a child process at this box, isolated from the host config.
    fn command(&self, binary: &str) -> Command {
        let mut command = Command::new(binary);
        command
            .current_dir(&self.home)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join("config"))
            .env("TMPDIR", self.home.join("tmp"))
            .env("SYMFRITZ_BOX_HOST", format!("127.0.0.1:{}", self.port))
            .env("SYMFRITZ_BOX_USER", "admin")
            .env("SYMFRITZ_BOX_USE_TLS", "false")
            .env("SYMFRITZ_PASSWORD", "test-password")
            .env("SYMFRITZ_BOX_TIMEOUT_SECONDS", "5")
            .env_remove("SYMFRITZ_HOST")
            .env_remove("SYMFRITZ_USER")
            .env_remove("SYMFRITZ_BOX_PASSWORD_REF")
            .env_remove("SYMFRITZ_BOX_KEYCHAIN")
            .env_remove("SYMFRITZ_BOX_INSECURE_TLS")
            .env_remove("SYMFRITZ_BOX_ALLOW_HTTP_FALLBACK");
        command
    }
}

impl Drop for MockBox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn serve(
    mut stream: TcpStream,
    fixture: &Fixture,
    requests: &Mutex<Vec<(String, String)>>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut head_lines = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" || line.is_empty() {
            break;
        }
        head_lines.push(line);
    }

    let request_line = head_lines.first().cloned().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();

    let mut content_length = 0_usize;
    let mut soap_action = None;
    let mut authorized = false;
    for line in head_lines.iter().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => content_length = value.parse().unwrap_or(0),
            "soapaction" => soap_action = Some(value.trim_matches('"').to_owned()),
            "authorization" => authorized = !value.is_empty(),
            _ => {}
        }
    }

    let mut body = vec![0_u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }
    let body = String::from_utf8_lossy(&body).into_owned();

    if method == "GET" && path == "/tr64desc.xml" {
        requests
            .lock()
            .expect("mock request log")
            .push((path.clone(), String::new()));
        return respond(
            &mut stream,
            "200 OK",
            "text/xml",
            &description(fixture),
            &[],
        );
    }

    if let Some(radio) = wlan_radio(&path) {
        // Unauthenticated SOAP is challenged, like a real box does.
        if !authorized {
            return respond(
                &mut stream,
                "401 Unauthorized",
                "text/xml",
                "",
                &[(
                    "WWW-Authenticate",
                    "Digest realm=\"symfritz-test\", nonce=\"fixed-test-nonce\", qop=\"auth\", algorithm=MD5",
                )],
            );
        }
        let action = soap_action
            .as_deref()
            .and_then(|value| value.split_once('#'))
            .map(|(_, action)| action.to_owned())
            .unwrap_or_default();
        requests
            .lock()
            .expect("mock request log")
            .push((path.clone(), action.clone()));
        let response = match action.as_str() {
            "GetInfo" => soap(
                "GetInfo",
                &[
                    ("NewSSID", format!("Test-{radio}")),
                    ("NewEnable", "1".to_owned()),
                    ("NewChannel", radio.to_string()),
                    ("NewStandard", "802.11ax".to_owned()),
                    ("NewStatus", "Up".to_owned()),
                ],
            ),
            "GetTotalAssociations" => soap(
                "GetTotalAssociations",
                &[(
                    "NewTotalAssociations",
                    fixture.radio_clients(radio).len().to_string(),
                )],
            ),
            "GetGenericAssociatedDeviceInfo" => {
                let index = associated_index(&body);
                let Some(client) = fixture.radio_clients(radio).get(index).copied() else {
                    return respond(
                        &mut stream,
                        "500 Internal Server Error",
                        "text/xml",
                        &fault("ArrayIndexError"),
                        &[],
                    );
                };
                soap(
                    "GetGenericAssociatedDeviceInfo",
                    &[
                        ("NewAssociatedDeviceMACAddress", client.mac.to_owned()),
                        ("NewAssociatedDeviceIPAddress", client.ip.to_owned()),
                        ("NewX_AVM-DE_SignalStrength", "-40".to_owned()),
                        ("NewX_AVM-DE_Speed", "866".to_owned()),
                        ("NewAssociatedDeviceAuthState", "1".to_owned()),
                    ],
                )
            }
            other => {
                return respond(
                    &mut stream,
                    "500 Internal Server Error",
                    "text/xml",
                    &fault(other),
                    &[],
                );
            }
        };
        return respond(&mut stream, "200 OK", "text/xml", &response, &[]);
    }

    respond(&mut stream, "404 Not Found", "text/plain", "not found", &[])
}

fn respond(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> std::io::Result<()> {
    let mut response =
        format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nConnection: close\r\n");
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    response.push_str(body);
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn description(fixture: &Fixture) -> String {
    let services = fixture
        .radios
        .iter()
        .map(|index| {
            format!(
                "<service><serviceType>urn:dslforum-org:service:WLANConfiguration:{index}</serviceType><controlURL>/upnp/control/wlanconfig{index}</controlURL></service>"
            )
        })
        .collect::<String>();
    format!(
        "<root xmlns=\"urn:dslforum-org:device-1-0\"><device><serviceList><service><serviceType>urn:dslforum-org:service:DeviceInfo:1</serviceType><controlURL>/upnp/control/deviceinfo</controlURL></service>{services}</serviceList></device></root>"
    )
}

fn soap(action: &str, values: &[(&str, String)]) -> String {
    let values = values
        .iter()
        .map(|(key, value)| format!("<{key}>{value}</{key}>"))
        .collect::<String>();
    format!(
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:{action}Response xmlns:u=\"urn:dslforum-org:service:test:1\">{values}</u:{action}Response></s:Body></s:Envelope>"
    )
}

fn fault(description: &str) -> String {
    format!(
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>{description}</faultstring></s:Fault></s:Body></s:Envelope>"
    )
}

fn wlan_radio(path: &str) -> Option<usize> {
    path.strip_prefix("/upnp/control/wlanconfig")?.parse().ok()
}

fn associated_index(body: &str) -> usize {
    let Some(start) = body.find("<NewAssociatedDeviceIndex>") else {
        return 0;
    };
    let start = start + "<NewAssociatedDeviceIndex>".len();
    let Some(length) = body[start..].find("</NewAssociatedDeviceIndex>") else {
        return 0;
    };
    body[start..start + length].parse().unwrap_or(0)
}

/// Run `symfritz <args>` against the mock box and decode its JSON payload.
fn run_json(mock: &MockBox, binary: &str, args: &[&str]) -> Value {
    let output = mock
        .command(binary)
        .args(args)
        .output()
        .expect("run symfritz");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "symfritz {args:?} failed: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("symfritz {args:?} emitted invalid JSON {error}: {stdout}"))
}

/// Drive the MCP stdio server and decode the `tools/call` payload.
fn run_mcp_tool(mock: &MockBox, binary: &str, tool: &str) -> Value {
    let mut child = mock
        .command(binary)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start MCP server");

    let mut stdin = child.stdin.take().expect("MCP stdin");
    stdin
        .write_all(br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#)
        .expect("write initialize");
    stdin.write_all(b"\n").expect("write initialize newline");
    let call = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"{tool}","arguments":{{}}}}}}"#
    );
    stdin.write_all(call.as_bytes()).expect("write tools/call");
    stdin.write_all(b"\n").expect("write tools/call newline");
    stdin.flush().expect("flush MCP requests");
    drop(stdin);

    let stdout = child.stdout.take().expect("MCP stdout");
    let (sender, receiver) = mpsc::channel::<Vec<String>>();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut lines = Vec::new();
        for _ in 0..8 {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => lines.push(line),
            }
        }
        let _ = sender.send(lines);
    });
    let lines = receiver
        .recv_timeout(Duration::from_secs(30))
        .expect("MCP responses");

    let mut stderr = String::new();
    if let Some(mut handle) = child.stderr.take() {
        let _ = handle.read_to_string(&mut stderr);
    }
    let status = child.wait().expect("wait for MCP server");
    assert!(status.success(), "MCP server failed: {stderr}");

    let response = lines
        .iter()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| value["id"] == 2)
        .unwrap_or_else(|| panic!("no MCP tool response in {lines:?}"));
    assert!(
        response.get("error").is_none(),
        "MCP tool call failed: {response}"
    );
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("MCP tool result has no text: {response}"));
    serde_json::from_str(text).unwrap_or_else(|error| panic!("MCP payload invalid {error}: {text}"))
}

fn radio_indices(clients: &[Value]) -> Vec<u64> {
    clients
        .iter()
        .map(|client| client["radio_index"].as_u64().expect("radio_index"))
        .collect()
}

fn macs(clients: &[Value]) -> Vec<&str> {
    clients
        .iter()
        .map(|client| client["mac"].as_str().expect("mac"))
        .collect()
}

fn as_clients(payload: Value, surface: &str) -> Vec<Value> {
    match payload {
        Value::Array(clients) => clients,
        other => panic!("{surface} returned no client list: {other}"),
    }
}

#[test]
fn cli_reports_the_client_associated_with_radio_four() {
    let mock = MockBox::start(Fixture::four_radio());
    let binary = env!("CARGO_BIN_EXE_symfritz");

    let clients = as_clients(
        run_json(&mock, binary, &["wlan", "clients", "--json"]),
        "wlan clients",
    );
    assert_eq!(clients.len(), 1, "radio 4 client must be reported");
    assert_eq!(radio_indices(&clients), [4]);
    assert_eq!(macs(&clients), ["AA:BB:CC:DD:EE:04"]);

    let served = mock.served();
    assert_eq!(
        served.first(),
        Some(&(("/tr64desc.xml".to_owned()), String::new())),
        "advertisement discovery must run first: {served:?}"
    );
    assert!(
        mock.served_contains("/upnp/control/wlanconfig4", "GetTotalAssociations"),
        "radio 4 must be probed: {served:?}"
    );
}

#[test]
fn mcp_reports_the_client_associated_with_radio_four() {
    let mock = MockBox::start(Fixture::four_radio());
    let binary = env!("CARGO_BIN_EXE_symfritz");

    let clients = as_clients(
        run_mcp_tool(&mock, binary, "wlan_clients"),
        "MCP wlan_clients",
    );
    assert_eq!(clients.len(), 1, "radio 4 client must be reported");
    assert_eq!(radio_indices(&clients), [4]);
    assert_eq!(macs(&clients), ["AA:BB:CC:DD:EE:04"]);
    assert!(
        mock.served_contains("/upnp/control/wlanconfig4", "GetTotalAssociations"),
        "radio 4 must be probed: {:?}",
        mock.served()
    );
}

#[test]
fn cli_keeps_three_radio_results_deterministic() {
    let mock = MockBox::start(Fixture::three_radio());
    let binary = env!("CARGO_BIN_EXE_symfritz");

    let clients = as_clients(
        run_json(&mock, binary, &["wlan", "clients", "--json"]),
        "wlan clients",
    );
    assert_eq!(clients.len(), 2, "the previous client set must survive");
    assert_eq!(radio_indices(&clients), [1, 3]);
    assert_eq!(macs(&clients), ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:03"]);
    assert!(
        mock.served_contains("/tr64desc.xml", ""),
        "three-radio boxes are discovered too: {:?}",
        mock.served()
    );
    assert!(
        !mock
            .served()
            .iter()
            .any(|(path, _)| path.contains("wlanconfig4")),
        "a three-radio box must not be probed on a fourth radio: {:?}",
        mock.served()
    );
}

#[test]
fn mcp_keeps_three_radio_results_deterministic() {
    let mock = MockBox::start(Fixture::three_radio());
    let binary = env!("CARGO_BIN_EXE_symfritz");

    let clients = as_clients(
        run_mcp_tool(&mock, binary, "wlan_clients"),
        "MCP wlan_clients",
    );
    assert_eq!(clients.len(), 2, "the previous client set must survive");
    assert_eq!(radio_indices(&clients), [1, 3]);
    assert_eq!(macs(&clients), ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:03"]);
}
