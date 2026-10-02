#![deny(unsafe_code)]

//! Black-box command tests against a bounded loopback TR-064 fixture.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use serde_json::Value;

#[derive(Clone, Debug)]
struct Request {
    method: String,
    path: String,
    action: String,
    body: String,
}

struct MockBox {
    address: String,
    port: u16,
    home: PathBuf,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl MockBox {
    fn start() -> Self {
        Self::start_on("127.0.0.1:0")
    }

    fn start_on(address: &str) -> Self {
        let listener = TcpListener::bind(address).expect("bind loopback fixture");
        let address = listener.local_addr().expect("fixture address");
        let port = address.port();
        let address = address.to_string();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&requests);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        listener
            .set_nonblocking(true)
            .expect("nonblocking fixture listener");
        let worker = thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if let Ok(true) = serve(stream, &sink) {
                            break;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                }
            }
        });

        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).expect("test directory nonce");
        let home = std::env::temp_dir().join(format!(
            "symfritz-cli-command-execution-{}",
            hex::encode(nonce)
        ));
        std::fs::create_dir(&home).expect("new isolated home");
        std::fs::create_dir_all(home.join("tmp")).expect("create isolated home");
        std::fs::create_dir_all(home.join(".config")).expect("create isolated config directory");
        Self {
            address,
            port,
            home,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_symfritz"));
        command
            .current_dir(&self.home)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("APPDATA", self.home.join(".config"))
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("TMPDIR", self.home.join("tmp"))
            .env("SYMFRITZ_BOX_HOST", &self.address)
            .env("SYMFRITZ_BOX_USER", "test-user")
            .env("SYMFRITZ_BOX_USE_TLS", "false")
            .env("SYMFRITZ_BOX_TIMEOUT_SECONDS", "3")
            .env("SYMFRITZ_PASSWORD", "fixture-password")
            .env_remove("SYMFRITZ_HOST")
            .env_remove("SYMFRITZ_USER")
            .env_remove("SYMFRITZ_BOX_PASSWORD")
            .env_remove("SYMFRITZ_BOX_PASSWORD_REF")
            .env_remove("SYMFRITZ_BOX_KEYCHAIN_ACCOUNT")
            .env_remove("SYMFRITZ_BOX_KEYCHAIN")
            .env_remove("SYMFRITZ_BOX_INSECURE_TLS")
            .env_remove("SYMFRITZ_BOX_ALLOW_HTTP_FALLBACK");
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.output(self.command().args(args))
    }

    fn output(&self, command: &mut Command) -> Output {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let stdout = self.home.join(format!("stdout-{}", hex::encode(nonce)));
        let stderr = self.home.join(format!("stderr-{}", hex::encode(nonce)));
        let mut child = command
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&stdout).unwrap())
            .stderr(std::fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if started.elapsed() >= Duration::from_secs(30) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("CLI exceeded its 30-second deadline: {command:?}");
            }
            thread::sleep(Duration::from_millis(10));
        };
        Output {
            status,
            stdout: std::fs::read(stdout).unwrap(),
            stderr: std::fs::read(stderr).unwrap(),
        }
    }

    fn requests(&self) -> Vec<Request> {
        self.requests.lock().expect("request log").clone()
    }

    fn has_action(&self, action: &str) -> bool {
        self.requests()
            .iter()
            .any(|request| request.action == action)
    }

    fn action(&self, action: &str) -> Request {
        self.requests()
            .into_iter()
            .find(|request| request.action == action)
            .unwrap_or_else(|| panic!("no {action} request: {:?}", self.requests()))
    }
}

impl Drop for MockBox {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn serve(mut stream: TcpStream, requests: &Mutex<Vec<Request>>) -> std::io::Result<bool> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(false);
    }
    let mut pieces = request_line.split_whitespace();
    let method = pieces.next().unwrap_or_default().to_owned();
    let path = pieces.next().unwrap_or_default().to_owned();
    let mut content_length = 0_usize;
    let mut soap_action = String::new();
    let mut authorized = false;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            match name.trim().to_ascii_lowercase().as_str() {
                "content-length" => content_length = value.trim().parse().unwrap_or(0),
                "soapaction" => soap_action = value.trim().trim_matches('"').to_owned(),
                "authorization" => authorized = !value.trim().is_empty(),
                _ => {}
            }
        }
    }
    let mut body = vec![0_u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }
    let body = String::from_utf8_lossy(&body).into_owned();

    if path == "/__symfritz_shutdown" {
        respond(&mut stream, "200 OK", "text/plain", "stopped", &[])?;
        return Ok(true);
    }
    if path == "/tr64desc.xml" {
        requests.lock().expect("request log").push(Request {
            method,
            path,
            action: String::new(),
            body,
        });
        respond(&mut stream, "200 OK", "text/xml", &description(), &[])?;
        return Ok(false);
    }
    if path.starts_with("/login_sid.lua") {
        requests.lock().expect("request log").push(Request {
            method,
            path: path.clone(),
            action: String::new(),
            body,
        });
        let session = if path.contains("username=") && path.contains("response=") {
            "<SessionInfo><SID>0123456789abcdef</SID><Challenge>fixed-challenge</Challenge><BlockTime>0</BlockTime></SessionInfo>"
        } else {
            "<SessionInfo><SID>0000000000000000</SID><Challenge>fixed-challenge</Challenge><BlockTime>0</BlockTime></SessionInfo>"
        };
        respond(&mut stream, "200 OK", "text/xml", session, &[])?;
        return Ok(false);
    }
    if method == "POST" && (path.starts_with("/query.lua") || path == "/data.lua") {
        requests.lock().expect("request log").push(Request {
            method,
            path: path.clone(),
            action: String::new(),
            body: body.clone(),
        });
        let (content_type, response) = if path.starts_with("/query.lua") {
            ("application/json", r#"{"CPUTEMP":"56,61"}"#)
        } else {
            ("application/json", r#"{"page":"overview","items":[1]}"#)
        };
        respond(&mut stream, "200 OK", content_type, response, &[])?;
        return Ok(false);
    }
    if method == "POST" {
        if !authorized {
            respond(
                &mut stream,
                "401 Unauthorized",
                "text/xml",
                "",
                &[(
                    "WWW-Authenticate",
                    "Digest realm=\"symfritz-cli-test\", nonce=\"fixed-loopback-nonce\", qop=\"auth\", algorithm=MD5",
                )],
            )?;
            return Ok(false);
        }
        let action = soap_action
            .rsplit_once('#')
            .map_or(soap_action.as_str(), |(_, action)| action)
            .to_owned();
        requests.lock().expect("request log").push(Request {
            method,
            path: path.clone(),
            action: action.clone(),
            body: body.clone(),
        });
        if path == "/upnp/control/x_homeauto"
            && action == "GetGenericDeviceInfos"
            && body.contains("<NewIndex>1</NewIndex>")
        {
            respond(
                &mut stream,
                "500 Internal Server Error",
                "text/xml",
                &fault("NoSuchEntry"),
                &[],
            )?;
        } else {
            respond(
                &mut stream,
                "200 OK",
                "text/xml",
                &soap(&action, &response_fields(&path, &action, &body)),
                &[],
            )?;
        }
        return Ok(false);
    }

    requests.lock().expect("request log").push(Request {
        method,
        path: path.clone(),
        action: String::new(),
        body,
    });
    let (content_type, response) = if path.starts_with("/webservices/homeautoswitch.lua") {
        let response = if path.contains("switchcmd=getdevicelistinfos") {
            aha_device_list()
        } else {
            String::from("OK")
        };
        ("text/plain", response)
    } else if path.starts_with("/mesh.json") {
        ("application/json", mesh_topology())
    } else if path.starts_with("/hosts.xml") {
        ("text/xml", host_list())
    } else if path.starts_with("/calls.lua") {
        ("text/xml", call_list())
    } else if path.starts_with("/log.lua") {
        ("text/xml", event_log())
    } else {
        ("text/plain", "fixture route not found".to_owned())
    };
    let status = if response == "fixture route not found" {
        "404 Not Found"
    } else {
        "200 OK"
    };
    respond(&mut stream, status, content_type, &response, &[])?;
    Ok(false)
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
    response.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn description() -> String {
    let services = [
        ("DeviceInfo:1", "deviceinfo"),
        ("UserInterface:1", "userif"),
        ("WANIPConnection:1", "wanipconnection1"),
        ("Hosts:1", "hosts"),
        ("WANDSLInterfaceConfig:1", "wandslifconfig1"),
        ("WANCommonInterfaceConfig:1", "wancommonifconfig1"),
        ("X_VoIP:1", "x_voip"),
        ("X_AVM-DE_OnTel:1", "x_contact"),
        ("DeviceConfig:1", "deviceconfig"),
        ("X_AVM-DE_Homeauto:1", "x_homeauto"),
    ]
    .into_iter()
    .map(|(name, path)| {
        format!(
            "<service><serviceType>urn:dslforum-org:service:{name}</serviceType><controlURL>/upnp/control/{path}</controlURL></service>"
        )
    })
    .chain((1..=4).map(|index| {
        format!(
            "<service><serviceType>urn:dslforum-org:service:WLANConfiguration:{index}</serviceType><controlURL>/upnp/control/wlanconfig{index}</controlURL></service>"
        )
    }))
    .collect::<String>();
    format!(
        "<root xmlns=\"urn:dslforum-org:device-1-0\"><device><serviceList>{services}</serviceList></device></root>"
    )
}

fn response_fields(path: &str, action: &str, request_body: &str) -> Vec<(&'static str, String)> {
    match (path, action) {
        ("/upnp/control/deviceinfo", "GetInfo") => vec![
            ("NewModelName", "FRITZ!Box Loopback".to_owned()),
            ("NewSoftwareVersion", "8.01".to_owned()),
            ("NewUpTime", "86400".to_owned()),
        ],
        ("/upnp/control/deviceinfo", "X_AVM-DE_GetDeviceLogPath") => {
            vec![("NewDeviceLogPath", "/log.lua?sid=fixture".to_owned())]
        }
        ("/upnp/control/wanipconnection1", "GetInfo") => {
            vec![("NewConnectionStatus", "Connected".to_owned())]
        }
        ("/upnp/control/wanipconnection1", "GetExternalIPAddress") => {
            vec![("NewExternalIPAddress", "198.51.100.7".to_owned())]
        }
        ("/upnp/control/userif", "GetInfo") => vec![
            ("NewUpgradeAvailable", "1".to_owned()),
            ("NewX_AVM-DE_Version", "8.02".to_owned()),
        ],
        ("/upnp/control/hosts", "X_AVM-DE_GetHostListPath") => {
            vec![("NewX_AVM-DE_HostListPath", "/hosts.xml".to_owned())]
        }
        ("/upnp/control/hosts", "GetSpecificHostEntry") => vec![
            ("NewHostName", "Desk".to_owned()),
            ("NewIPAddress", "192.0.2.25".to_owned()),
            ("NewMACAddress", "AA:BB:CC:DD:EE:25".to_owned()),
            ("NewActive", "1".to_owned()),
            ("NewInterfaceType", "Ethernet".to_owned()),
            ("NewAddressSource", "DHCP".to_owned()),
            ("NewLeaseTimeRemaining", "3600".to_owned()),
        ],
        ("/upnp/control/hosts", "X_AVM-DE_GetSpecificHostEntryByIP") => {
            let ip = xml_value(request_body, "NewIPAddress").unwrap_or("192.0.2.25");
            vec![
                ("NewHostName", "Loopback target".to_owned()),
                ("NewIPAddress", ip.to_owned()),
                ("NewMACAddress", "AA:BB:CC:DD:EE:25".to_owned()),
                ("NewActive", "1".to_owned()),
                ("NewInterfaceType", "Ethernet".to_owned()),
                ("NewAddressSource", "DHCP".to_owned()),
                ("NewLeaseTimeRemaining", "3600".to_owned()),
            ]
        }
        ("/upnp/control/hosts", "X_AVM-DE_GetMeshListPath") => {
            vec![("NewX_AVM-DE_MeshListPath", "/mesh.json".to_owned())]
        }
        ("/upnp/control/hosts", "X_AVM-DE_WakeOnLANByMACAddress") => Vec::new(),
        ("/upnp/control/wandslifconfig1", "GetInfo") => vec![
            ("NewUpstreamNoiseMargin", "80".to_owned()),
            ("NewDownstreamNoiseMargin", "120".to_owned()),
            ("NewUpstreamAttenuation", "30".to_owned()),
            ("NewDownstreamAttenuation", "40".to_owned()),
        ],
        ("/upnp/control/wancommonifconfig1", "GetCommonLinkProperties") => vec![
            ("NewLayer1UpstreamMaxBitRate", "1000000".to_owned()),
            ("NewLayer1DownstreamMaxBitRate", "100000000".to_owned()),
        ],
        ("/upnp/control/wancommonifconfig1", "X_AVM-DE_GetOnlineMonitor") => vec![
            ("Newds_current_bps", "1000,2000".to_owned()),
            ("Newmc_current_bps", "3000".to_owned()),
            ("Newds_guest_bps", "4000".to_owned()),
            ("Newprio_realtime_bps", "5000".to_owned()),
            ("Newprio_high_bps", "6000".to_owned()),
            ("Newprio_default_bps", "7000".to_owned()),
            ("Newprio_low_bps", "8000".to_owned()),
            ("Newus_guest_bps", "9000".to_owned()),
        ],
        ("/upnp/control/x_contact", "GetCallList") => {
            vec![(
                "NewCallListURL",
                "/calls.lua?sid=fixture&amp;keep=1".to_owned(),
            )]
        }
        ("/upnp/control/x_voip", "X_AVM-DE_DialNumber")
        | ("/upnp/control/x_voip", "X_AVM-DE_DialHangup")
        | ("/upnp/control/deviceconfig", "Reboot")
        | ("/upnp/control/x_homeauto", "SetSwitch")
        | ("/upnp/control/wlanconfig4", "SetEnable") => Vec::new(),
        ("/upnp/control/x_homeauto", "GetGenericDeviceInfos") => vec![
            ("NewAIN", "1234567".to_owned()),
            ("NewFunctionBitMask", "32768".to_owned()),
            ("NewManufacturer", "AVM".to_owned()),
            ("NewProductName", "Smart Plug".to_owned()),
            ("NewFirmwareVersion", "1.2".to_owned()),
        ],
        (path, "GetInfo") if path.starts_with("/upnp/control/wlanconfig") => {
            let index = path.strip_prefix("/upnp/control/wlanconfig").unwrap_or("1");
            vec![
                ("NewSSID", format!("Fixture-{index}")),
                ("NewEnable", "1".to_owned()),
                ("NewChannel", index.to_owned()),
                ("NewStandard", "802.11ax".to_owned()),
                ("NewStatus", "Up".to_owned()),
            ]
        }
        _ => Vec::new(),
    }
}

fn xml_value<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let start = body.find(&format!("<{key}>"))? + key.len() + 2;
    let end = body[start..].find(&format!("</{key}>"))? + start;
    Some(&body[start..end])
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

fn host_list() -> String {
    String::from(
        "<List><Item><HostName>Desk</HostName><IPAddress>192.0.2.25</IPAddress><MACAddress>aa:bb:cc:dd:ee:25</MACAddress><Active>1</Active><InterfaceType>Ethernet</InterfaceType><AddressSource>DHCP</AddressSource><LeaseTimeRemaining>3600</LeaseTimeRemaining></Item><Item><HostName>Backup NAS</HostName><IPAddress>192.0.2.30</IPAddress><MACAddress>aa:bb:cc:dd:ee:30</MACAddress><Active>0</Active><InterfaceType>802.11ac</InterfaceType><AddressSource>Static</AddressSource><LeaseTimeRemaining>0</LeaseTimeRemaining></Item></List>",
    )
}

fn call_list() -> String {
    String::from(
        "<root><CallList><Call><Type>1</Type><Date>01.02.24 03:04</Date><Caller>+491234</Caller><Called>+495678</Called><Name>Alice</Name><Duration>01:30</Duration></Call><Call><Type>3</Type><Date>2024-02-02 10:11:12</Date><Caller>+494444</Caller><Called>+495555</Called><Name></Name><Duration>00:05</Duration></Call></CallList></root>",
    )
}

fn event_log() -> String {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../testdata/port/cli/log-output.json"))
            .expect("log output fixture");
    fixture["xml"].as_str().unwrap().to_owned()
}

fn aha_device_list() -> String {
    String::from(
        "<devicelist version=\"1\"><device identifier=\"ain-switch\" id=\"0\"><name>Kitchen Plug</name><present>1</present><switch><state>1</state></switch><temperature><celsius>235</celsius></temperature><hkr><tist>43</tist><tsoll>44</tsoll><batterylow>0</batterylow><battery>90</battery><windowopenactiv>1</windowopenactiv><errorcode>6</errorcode><nextchange><end>1</end><start>2</start><tchange>60</tchange></nextchange></hkr><powermeter><power>10000</power><energy>3000</energy></powermeter></device><device identifier=\"ain-off\" id=\"1\"><name>Spare Plug</name><present>0</present><switch><state>0</state></switch></device><device identifier=\"ain-unknown\" id=\"2\"><name>Unknown Sensor</name><present>0</present><switch><state>n/a</state></switch></device><group identifier=\"group-1\" id=\"g\"><name>Living Room</name><groupinfo><masterdeviceid>ain-switch</masterdeviceid><members>ain-switch,ain-off,</members></groupinfo></group></devicelist>",
    )
}

fn mesh_topology() -> String {
    String::from(
        r#"{"nodes":[{"uid":"router","device_name":"Router","device_model":"FRITZ!Box","mesh_role":"master","node_interfaces":[{"uid":"router-wifi","interface_type":"Wi-Fi","node_links":[{"state":"active","node_1":"router","node_2":"repeater-if","cur_data_rate_rx":600,"cur_data_rate_tx":300}]}]},{"uid":"repeater","device_name":"Repeater","device_model":"FRITZ!Repeater","node_interfaces":[{"uid":"repeater-if","interface_type":"LAN","node_links":[]}] }]}"#,
    )
}

fn json(output: &Output, command: &str) -> Value {
    assert!(
        output.status.success(),
        "{command} failed with {}: stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{command} wrote stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{command} did not emit JSON ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn text(output: &Output, command: &str) -> String {
    assert!(
        output.status.success(),
        "{command} failed with {}: stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{command} wrote stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).expect("UTF-8 CLI text")
}

#[test]
fn read_commands_render_router_data_and_preserve_request_arguments() {
    let mock = MockBox::start();

    let status = json(&mock.run(&["status", "--json"]), "status --json");
    assert_eq!(status["model_name"], "FRITZ!Box Loopback");
    assert_eq!(status["firmware_version"], "8.01");
    assert_eq!(status["connection_state"], "Connected");
    assert_eq!(status["external_ip"], "198.51.100.7");
    assert_eq!(status["update_available"], "8.02");
    let status_text = text(&mock.run(&["status"]), "status");
    assert!(status_text.contains("Model:       FRITZ!Box Loopback"));
    assert!(status_text.contains("Firmware:    8.01 (Update available: 8.02)"));
    assert!(status_text.contains("External IP: 198.51.100.7"));

    let hosts = text(&mock.run(&["hosts", "list"]), "hosts list");
    assert!(hosts.contains("NAME"));
    assert!(hosts.contains("Desk"));
    assert!(hosts.contains("Backup NAS"));
    let active = json(&mock.run(&["hosts", "active", "--json"]), "hosts active");
    assert_eq!(active.as_array().expect("host array").len(), 1);
    assert_eq!(active[0]["name"], "Desk");
    let by_mac = text(
        &mock.run(&["hosts", "get", "--mac", "aa:bb:cc:dd:ee:25"]),
        "hosts get --mac",
    );
    assert!(by_mac.contains("Name:    Desk"));
    assert!(by_mac.contains("MAC:     AA:BB:CC:DD:EE:25"));
    assert!(by_mac.contains("Link:    LAN"));
    let by_ip = json(
        &mock.run(&["hosts", "get", "--ip", "192.0.2.25", "--json"]),
        "hosts get --ip",
    );
    assert_eq!(by_ip["ip"], "192.0.2.25");
    assert_eq!(by_ip["address_source"], "DHCP");
    assert!(
        mock.action("GetSpecificHostEntry")
            .body
            .contains("<NewMACAddress>AA:BB:CC:DD:EE:25</NewMACAddress>"),
        "MAC lookup should normalize the request value"
    );
    assert!(
        mock.action("X_AVM-DE_GetSpecificHostEntryByIP")
            .body
            .contains("<NewIPAddress>192.0.2.25</NewIPAddress>")
    );

    let radios = text(&mock.run(&["wlan", "radios"]), "wlan radios");
    assert!(radios.contains("Fixture-1"));
    assert!(radios.contains("802.11ax"));
    let guest = json(
        &mock.run(&["wlan", "guest", "status", "--json"]),
        "wlan guest status",
    );
    assert_eq!(guest["index"], 4);
    assert_eq!(guest["ssid"], "Fixture-4");
    let guest_text = text(&mock.run(&["wlan", "guest", "status"]), "wlan guest status");
    assert!(guest_text.contains("Guest WLAN (index 4)"));
    assert!(guest_text.contains("SSID=\"Fixture-4\" enabled=true"));
    let guest_on = json(
        &mock.run(&["wlan", "guest", "on", "--json"]),
        "wlan guest on",
    );
    assert_eq!(guest_on["enabled"], true);
    assert_eq!(guest_on["index"], 4);
    let enable = mock.action("SetEnable");
    assert_eq!(enable.path, "/upnp/control/wlanconfig4");
    assert!(enable.body.contains("<NewEnable>1</NewEnable>"));

    let dsl = json(&mock.run(&["dsl", "--json"]), "dsl --json");
    assert_eq!(dsl["upstream_noise_margin"], 80);
    assert_eq!(dsl["downstream_attenuation"], 40);
    assert_eq!(dsl["upstream_max_bit_rate"], 1_000_000);
    assert_eq!(dsl["downstream_max_bit_rate"], 100_000_000);
    let dsl_text = text(&mock.run(&["dsl"]), "dsl");
    assert!(dsl_text.contains("Noise Margin:   8 dB (Up) / 12 dB (Down)"));
    assert!(dsl_text.contains("Max Bit Rate:   1.00 Mbit/s (Up) / 100.00 Mbit/s (Down)"));

    let traffic = json(&mock.run(&["traffic", "--json"]), "traffic --json");
    assert_eq!(
        traffic["downstream_internet"],
        serde_json::json!([1000.0, 2000.0])
    );
    assert_eq!(traffic["upstream_guest"], serde_json::json!([9000.0]));
    let traffic_text = text(&mock.run(&["traffic"]), "traffic");
    assert!(traffic_text.contains("WAN Traffic Statistics:"));
    assert!(traffic_text.contains("1.00 kbit/s"));

    let calls = text(
        &mock.run(&["calls", "--type", "incoming", "--days", "3", "--limit", "1"]),
        "calls filtered",
    );
    assert!(calls.contains("Alice"));
    assert!(calls.contains("01.02.24 03:04"));
    assert!(calls.contains("1m30s"));
    assert!(!calls.contains("+494444"));
    let call_list_request = mock
        .requests()
        .into_iter()
        .find(|request| request.path.starts_with("/calls.lua?"))
        .expect("authenticated call-list GET");
    assert!(
        call_list_request.path.contains("days=3"),
        "{call_list_request:?}"
    );
    assert!(
        !call_list_request.path.contains("max=1"),
        "router-side max must not be applied before call-type filtering: {call_list_request:?}"
    );
    let all_calls = json(
        &mock.run(&["calls", "--limit", "1", "--json"]),
        "calls --json",
    );
    assert_eq!(all_calls.as_array().expect("calls array").len(), 1);
    let all_calls_text = text(&mock.run(&["calls", "--type", "all"]), "calls all");
    assert!(all_calls_text.contains("outgoing"), "{all_calls_text:?}");
    assert!(all_calls_text.contains("+494444"), "{all_calls_text:?}");
    assert!(all_calls_text.contains("5s"), "{all_calls_text:?}");
    let limited_request = mock
        .requests()
        .into_iter()
        .find(|request| request.path.starts_with("/calls.lua?") && request.path.contains("max=1"))
        .expect("second call-list GET");
    assert!(
        limited_request.path.contains("max=1"),
        "{limited_request:?}"
    );

    let log = text(&mock.run(&["log", "--filter", "wlan"]), "log --filter wlan");
    assert!(
        log.contains("[WLAN] Client connected"),
        "unexpected log output: {log:?}"
    );
    let log_request = mock
        .requests()
        .into_iter()
        .find(|request| request.path.starts_with("/log.lua?"))
        .expect("authenticated device-log GET");
    assert!(log_request.path.contains("filter=wlan"), "{log_request:?}");
    let log_json = json(
        &mock.run(&["log", "--filter", "WLAN", "--json"]),
        "log --json",
    );
    assert_eq!(log_json[0]["ID"], "42");
    assert_eq!(log_json[0]["Group"], "WLAN");
    assert_eq!(log_json[0]["Msg"], "Client connected");

    let services = json(&mock.run(&["services", "--json"]), "services --json");
    assert!(services.as_array().expect("services array").len() >= 10);
    assert!(
        services
            .as_array()
            .expect("services array")
            .iter()
            .any(|service| service["Type"] == "urn:dslforum-org:service:WLANConfiguration:4")
    );

    let raw = json(
        &mock.run(&["call", "deviceinfo", "GetInfo"]),
        "call deviceinfo GetInfo",
    );
    assert_eq!(raw["NewModelName"], "FRITZ!Box Loopback");
    let dynamic = json(
        &mock.run(&["call", "WLANConfiguration:2", "GetInfo", "--json"]),
        "call discovered WLANConfiguration:2",
    );
    assert_eq!(dynamic["NewSSID"], "Fixture-2");
    assert!(mock.requests().iter().any(|request| {
        request.path == "/upnp/control/wlanconfig2" && request.action == "GetInfo"
    }));
    let bad_raw = mock.run(&["call", "deviceinfo", "GetInfo", "not-a-pair"]);
    assert_eq!(bad_raw.status.code(), Some(9));
    assert_eq!(bad_raw.stdout, b"");
    assert_eq!(
        String::from_utf8_lossy(&bad_raw.stderr),
        "Error: bad argument: argument \"not-a-pair\" is not Key=Value\n"
    );

    assert!(mock.has_action("GetInfo"));
    assert!(
        mock.requests()
            .iter()
            .any(|request| { request.method == "GET" && request.path == "/tr64desc.xml" })
    );
}

#[test]
fn mutating_cli_commands_are_confirmed_and_send_exact_soap_values() {
    let mock = MockBox::start();

    let dial = json(&mock.run(&["dial", "+1-555-0100", "--json"]), "dial");
    assert_eq!(dial["number"], "+1-555-0100");
    assert_eq!(dial["action"], "dial");
    assert!(
        mock.action("X_AVM-DE_DialNumber")
            .body
            .contains("<NewX_AVM-DE_PhoneNumber>+1-555-0100</NewX_AVM-DE_PhoneNumber>")
    );

    let hangup = json(&mock.run(&["hangup", "--json"]), "hangup");
    assert_eq!(hangup["action"], "hangup");
    assert!(mock.has_action("X_AVM-DE_DialHangup"));

    let wol = json(
        &mock.run(&["wol", "--mac", "aa:bb:cc:dd:ee:25", "--json"]),
        "wol",
    );
    assert_eq!(wol["mac"], "aa:bb:cc:dd:ee:25");
    assert!(
        mock.action("X_AVM-DE_WakeOnLANByMACAddress")
            .body
            .contains("<NewMACAddress>AA:BB:CC:DD:EE:25</NewMACAddress>")
    );

    let refused = mock.run(&["reboot", "--json"]);
    assert_eq!(refused.status.code(), Some(9));
    assert_eq!(refused.stdout, b"");
    assert_eq!(
        String::from_utf8_lossy(&refused.stderr),
        "Error: confirmation required: refusing to reboot without --yes\n"
    );
    assert!(
        !mock.has_action("Reboot"),
        "unconfirmed reboot reached the box"
    );
    let reboot = json(&mock.run(&["reboot", "--yes", "--json"]), "reboot --yes");
    assert_eq!(reboot["triggered"], true);
    assert!(
        mock.requests()
            .iter()
            .any(|request| request.path == "/upnp/control/deviceconfig"
                && request.action == "Reboot")
    );

    let switch = json(
        &mock.run(&["home", "switch", "1234567", "off", "--tr064", "--json"]),
        "home switch --tr064",
    );
    assert_eq!(switch["ain"], "1234567");
    assert_eq!(switch["state"], "off");
    let switch_request = mock.action("SetSwitch");
    assert_eq!(switch_request.path, "/upnp/control/x_homeauto");
    assert!(switch_request.body.contains("<NewAIN>1234567</NewAIN>"));
    assert!(
        switch_request
            .body
            .contains("<NewSwitchState>OFF</NewSwitchState>")
    );

    let devices = json(
        &mock.run(&["home", "list", "--tr064", "--json"]),
        "home list --tr064",
    );
    assert_eq!(devices.as_array().expect("home device list").len(), 1);
    assert_eq!(devices[0]["AIN"], "1234567");
    assert_eq!(devices[0]["ProductName"], "Smart Plug");
    assert!(mock.requests().iter().any(|request| {
        request.action == "GetGenericDeviceInfos" && request.body.contains("<NewIndex>0</NewIndex>")
    }));
    assert!(mock.requests().iter().any(|request| {
        request.action == "GetGenericDeviceInfos" && request.body.contains("<NewIndex>1</NewIndex>")
    }));

    let cpu = text(&mock.run(&["status", "--cpu"]), "status --cpu");
    assert!(cpu.contains("CPU Temp:    56, 61 °C"), "{cpu:?}");
    let query = mock
        .requests()
        .into_iter()
        .find(|request| request.path.starts_with("/query.lua?sid="))
        .expect("CPU query endpoint");
    assert_eq!(query.body, r#"{"CPUTEMP":"cpu:status/StatTemperature"}"#);

    let home = json(&mock.run(&["home", "list", "--json"]), "home list --json");
    assert_eq!(
        home["devices"].as_array().expect("AHA device list").len(),
        3
    );
    assert_eq!(home["devices"][0]["Name"], "Kitchen Plug");
    assert_eq!(home["devices"][0]["Hkr"]["NextChange"]["TChange"], 60);
    assert_eq!(home["groups"][0]["Members"][0], "ain-switch");
    let home_text = text(&mock.run(&["home", "list"]), "home list");
    assert!(home_text.contains("Kitchen Plug"));
    assert!(home_text.contains("offline"));
    assert!(home_text.contains("n/a"));
    assert!(home_text.contains("temp: 21.5°C (target 22.0°C)"));
    assert!(home_text.contains("bat: 90%"));
    assert!(home_text.contains("window: open"));
    assert!(home_text.contains("battery charge extremely low"));
    assert!(home_text.contains("power: 10.00W (total 3000.0Wh)"));
    assert!(home_text.contains("Living Room"));

    let switch_on = text(
        &mock.run(&["home", "switch", "ain-switch", "on"]),
        "home switch on",
    );
    assert_eq!(switch_on, "OK: ain-switch -> on\n");
    let switch_off = json(
        &mock.run(&["home", "switch", "ain-switch", "off", "--json"]),
        "home switch off",
    );
    assert_eq!(switch_off["state"], "off");
    assert!(mock.requests().iter().any(|request| {
        request.path.starts_with("/webservices/homeautoswitch.lua?")
            && request.path.contains("switchcmd=setswitchon")
            && request.path.contains("ain=ain-switch")
            && request.path.contains("sid=0123456789abcdef")
    }));
    assert!(mock.requests().iter().any(|request| {
        request.path.starts_with("/webservices/homeautoswitch.lua?")
            && request.path.contains("switchcmd=setswitchoff")
    }));

    let temperature = json(
        &mock.run(&["home", "temp", "ain-thermostat", "20.5", "--json"]),
        "home temp",
    );
    assert_eq!(temperature["temperature"], "20.5");
    let target = mock
        .requests()
        .into_iter()
        .find(|request| request.path.contains("switchcmd=sethkrtsoll"))
        .expect("thermostat set command");
    assert!(target.path.contains("ain=ain-thermostat"));
    assert!(target.path.contains("param=41"), "{target:?}");
    let off = text(
        &mock.run(&["home", "temp", "ain-thermostat", "off"]),
        "home temp off",
    );
    assert_eq!(off, "OK: ain-thermostat -> off\n");
    assert!(mock.requests().iter().any(|request| {
        request.path.contains("switchcmd=sethkrtsoll") && request.path.contains("param=253")
    }));

    let scrape = mock.run(&["scrape", "overview", "filter=one", "filter=two"]);
    assert_eq!(scrape.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&scrape.stdout),
        "{\"page\":\"overview\",\"items\":[1]}\n"
    );
    assert!(scrape.stderr.is_empty());
    let data_request = mock
        .requests()
        .into_iter()
        .find(|request| request.path == "/data.lua")
        .expect("data.lua form request");
    assert!(data_request.body.contains("page=overview"));
    assert!(data_request.body.contains("filter=one&filter=two"));
    assert!(data_request.body.contains("sid=0123456789abcdef"));

    let mesh = json(&mock.run(&["mesh", "--json"]), "mesh --json");
    assert_eq!(mesh["nodes"].as_array().expect("mesh nodes").len(), 2);
    assert_eq!(mesh["nodes"][0]["device_name"], "Router");
    let mesh_text = text(&mock.run(&["mesh"]), "mesh");
    assert!(mesh_text.contains("Router  [master FRITZ!Box]"));
    assert!(mesh_text.contains("Repeater"));
    assert!(mesh_text.contains("(600/300) Mbit/s"));
    assert!(mock.requests().iter().any(|request| {
        request.action == "X_AVM-DE_GetMeshListPath" && request.path == "/upnp/control/hosts"
    }));
    assert!(
        mock.requests()
            .iter()
            .any(|request| { request.path.starts_with("/mesh.json?sid=0123456789abcdef") })
    );

    let initialized = text(&mock.run(&["config", "init"]), "config init for doctor");
    assert!(initialized.contains("Config written to "));
    let doctor = json(
        &mock.run(&["doctor", "--json"]),
        "doctor with loopback credentials",
    );
    assert_eq!(doctor["healthy"], true);
    for name in [
        "config file",
        "config parse",
        "credentials",
        "box reachable",
        "TR-064 enabled",
        "session login",
        "AHA endpoint",
    ] {
        assert!(
            doctor["checks"]
                .as_array()
                .expect("doctor checks")
                .iter()
                .any(|check| check["name"] == name && check["status"] == "ok"),
            "doctor omitted successful check {name}: {}",
            doctor["checks"]
        );
    }
    let auth = json(
        &mock.run(&["auth", "test", "--json"]),
        "auth test with loopback credentials",
    );
    assert_eq!(auth["action"], "auth_test");
    assert_eq!(auth["session_ok"], true);
    assert_eq!(auth["tr064_ok"], true);
    assert_eq!(auth["valid"], true);
    assert!(mock.requests().iter().any(|request| {
        request.path.starts_with("/login_sid.lua?")
            && request.path.contains("version=2")
            && request.path.contains("username=test-user")
            && request.path.contains("response=")
    }));
    let auth_text = text(&mock.run(&["auth", "test"]), "auth test");
    assert!(auth_text.contains("Web session login (login_sid.lua)"));
    assert!(auth_text.contains("TR-064 access (DeviceInfo)"));
    assert!(auth_text.contains("OK: credential is valid."));
}

#[test]
fn diagnose_uses_local_probe_and_reports_host_and_port_results() {
    let mock = MockBox::start();
    let port = mock.port.to_string();
    let diagnosis = json(
        &mock.run(&["diagnose", "127.0.0.1", "--port", &port, "--json"]),
        "diagnose loopback",
    );
    assert_eq!(diagnosis["ref"], "127.0.0.1");
    assert_eq!(diagnosis["target"], "127.0.0.1");
    assert_eq!(diagnosis["ok"], true);
    assert_eq!(diagnosis["host"]["name"], "Loopback target");
    assert!(
        diagnosis["checks"]
            .as_array()
            .expect("diagnostic checks")
            .iter()
            .any(|check| check["name"] == format!("TCP {port} (custom)")
                && check["detail"] == "open")
    );
    let text_report = text(
        &mock.run(&["diagnose", "127.0.0.1", "--port", &port]),
        "diagnose loopback text",
    );
    assert!(text_report.contains("Diagnose 127.0.0.1"));
    assert!(text_report.contains("Result: reachable (no failed checks)"));
    let lookup = mock.action("X_AVM-DE_GetSpecificHostEntryByIP");
    assert!(
        lookup
            .body
            .contains("<NewIPAddress>127.0.0.1</NewIPAddress>")
    );
}

#[test]
fn log_text_preserves_local_wallclock_and_invalid_placeholder() {
    let mock = MockBox::start();
    let fixture: Value =
        serde_json::from_str(include_str!("../../../testdata/port/cli/log-output.json"))
            .expect("log output fixture");
    assert_eq!(fixture["schema_version"], 1);
    let structured = json(&mock.run(&["log", "--json"]), "log --json");
    let times: Vec<_> = structured
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["Time"].clone())
        .collect();
    assert_eq!(serde_json::json!(times), fixture["times"]);
    assert_eq!(
        text(&mock.run(&["log"]), "log"),
        fixture["text"].as_str().unwrap()
    );
}

#[test]
fn configured_ipv6_port_is_used_by_tr064_and_web() {
    let mock = MockBox::start_on("[::1]:0");
    let fixture: Value =
        serde_json::from_str(include_str!("../../../testdata/port/cli/ipv6-origins.json"))
            .expect("IPv6 origin fixture");
    assert_eq!(fixture["schema_version"], 1);
    for template in fixture["hosts"].as_array().expect("host templates") {
        let host = template
            .as_str()
            .unwrap()
            .replace("{port}", &mock.port.to_string());
        let services = json(
            &mock.output(
                mock.command()
                    .args(["services", "--json"])
                    .env("SYMFRITZ_BOX_HOST", &host),
            ),
            "IPv6 services",
        );
        assert!(
            services
                .as_array()
                .unwrap()
                .iter()
                .any(|service| service["Type"] == "urn:dslforum-org:service:DeviceInfo:1")
        );
        let home = json(
            &mock.output(
                mock.command()
                    .args(["home", "list", "--json"])
                    .env("SYMFRITZ_BOX_HOST", &host),
            ),
            "IPv6 home list",
        );
        assert_eq!(home["devices"][0]["Name"], "Kitchen Plug");
    }
    assert!(
        mock.requests()
            .iter()
            .any(|request| request.path == "/tr64desc.xml")
    );
    assert!(
        mock.requests()
            .iter()
            .any(|request| request.path.starts_with("/webservices/homeautoswitch.lua?"))
    );
}

#[test]
fn local_config_auth_and_doctor_paths_never_contact_the_fixture_router() {
    let mock = MockBox::start();

    let initialized = text(&mock.run(&["config", "init"]), "config init");
    assert!(initialized.contains("Config written to "));
    let config_path = mock.home.join(".config/symfritz/config.toml");
    let config = std::fs::read_to_string(&config_path).expect("initialized config");
    assert!(config.contains("[box]"));
    assert!(config.contains("host = \"fritz.box\""));
    let exists = mock.run(&["config", "init"]);
    assert_eq!(exists.status.code(), Some(0));
    assert_eq!(exists.stdout, b"");
    assert!(String::from_utf8_lossy(&exists.stderr).contains("use --force to overwrite"));
    let forced = text(
        &mock.run(&["config", "init", "--force"]),
        "config init --force",
    );
    assert!(forced.contains("Config written to "));

    let trust = json(
        &mock.run(&["auth", "trust", "--reset", "router.invalid", "--json"]),
        "auth trust --reset",
    );
    assert_eq!(trust["action"], "auth_trust");
    assert_eq!(trust["host"], "router.invalid");
    assert_eq!(trust["reset"], false);

    let auth_test = mock.output(
        mock.command()
            .args(["auth", "test", "--json"])
            .env_remove("SYMFRITZ_PASSWORD"),
    );
    assert_eq!(auth_test.status.code(), Some(3));
    assert!(auth_test.stderr.is_empty());
    let error: Value = serde_json::from_slice(&auth_test.stdout).expect("structured auth error");
    assert_eq!(error["error"]["kind"], "auth");
    assert_eq!(
        error["error"]["message"],
        "no credential: no password configured (run 'symfritz auth login')"
    );

    let doctor = mock.output(
        mock.command()
            .args(["doctor", "--json"])
            .env_remove("SYMFRITZ_PASSWORD"),
    );
    assert_eq!(doctor.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&doctor.stdout).expect("doctor JSON report");
    assert_eq!(report["healthy"], false);
    assert!(
        report["checks"]
            .as_array()
            .expect("doctor checks")
            .iter()
            .any(|check| check["name"] == "credentials" && check["status"] == "fail")
    );
    assert!(String::from_utf8_lossy(&doctor.stderr).contains("doctor found failing checks"));
    for (args, expected_error) in [
        (
            &["calls", "--type", "sideways"][..],
            "Error: invalid call type: unknown call type: sideways\n",
        ),
        (
            &["home", "switch", "ain-switch", "sideways"][..],
            "Error: state must be on or off\n",
        ),
        (
            &["home", "temp", "ain-thermostat", "nope"][..],
            "Error: temperature must be 'on', 'off', or a number (e.g. 20.5)\n",
        ),
    ] {
        let output = mock.run(args);
        assert_eq!(output.status.code(), Some(9), "{args:?}");
        assert_eq!(output.stdout, b"", "{args:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            expected_error,
            "{args:?}"
        );
    }
    std::fs::write(&config_path, "[box\nhost = \"broken\"\n").expect("write invalid config");
    let malformed_config = mock.output(
        mock.command()
            .args(["doctor", "--json"])
            .env_remove("SYMFRITZ_PASSWORD"),
    );
    assert_eq!(malformed_config.status.code(), Some(1));
    let malformed_report: Value =
        serde_json::from_slice(&malformed_config.stdout).expect("malformed-config doctor JSON");
    assert!(
        malformed_report["checks"]
            .as_array()
            .expect("doctor checks")
            .iter()
            .any(|check| check["name"] == "config parse" && check["status"] == "fail")
    );
    assert!(
        String::from_utf8_lossy(&malformed_config.stderr).contains("doctor found failing checks")
    );
    assert!(
        mock.requests().is_empty(),
        "local-only commands unexpectedly contacted the router: {:?}",
        mock.requests()
    );
}

#[test]
fn help_version_and_completion_commands_render_locally() {
    let mock = MockBox::start();

    let root_help = text(&mock.run(&["--help"]), "--help");
    assert!(root_help.contains("Usage: symfritz"));
    assert!(root_help.contains("symfritz talks to a FRITZ!Box"));

    let auth_help = text(&mock.run(&["help", "auth"]), "help auth");
    assert!(auth_help.contains("Usage: symfritz auth"));
    assert!(auth_help.contains("Resolution order:"));
    let trust_help = text(&mock.run(&["help", "auth", "trust"]), "help auth trust");
    assert!(trust_help.contains("Usage: symfritz auth trust"));

    for (args, prefix) in [
        (&["--version"][..], "symfritz version "),
        (&["version"][..], "symfritz "),
    ] {
        let output = text(&mock.run(args), "version");
        assert!(output.starts_with(prefix), "{output:?}");
    }

    for shell in ["bash", "fish", "powershell", "zsh"] {
        let script = text(
            &mock.run(&["completion", shell, "--no-descriptions"]),
            &format!("completion {shell}"),
        );
        assert!(!script.is_empty(), "completion script missing for {shell}");
        assert!(
            script.contains("symfritz"),
            "unexpected {shell} script: {script}"
        );
    }
    assert!(
        mock.requests().is_empty(),
        "help, version, and completion commands contacted the router: {:?}",
        mock.requests()
    );
}
