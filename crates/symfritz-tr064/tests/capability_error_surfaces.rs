#![deny(unsafe_code)]

use std::{collections::VecDeque, io::Write, net::TcpListener, thread};

use symfritz_tr064::{
    CheckStatus, Client, ClientError, CnonceSource, DiagnoseOptions, DiscoveryError, ErrorKind,
    PortProbe, Request, Response, Service, SoapParseError, StatusError, Transport, TransportError,
    all_public, classify_resolved_host, error_kind, is_private_ip, parse_linux_default_gateway,
    parse_windows_default_gateway, probe_tr064,
};

#[path = "support/accept.rs"]
mod test_accept;

#[derive(Default)]
struct FakeTransport {
    responses: VecDeque<Response>,
    requests: Vec<Request>,
}

impl FakeTransport {
    fn new(responses: impl IntoIterator<Item = Response>) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }
}

impl Transport for FakeTransport {
    fn send(&mut self, request: Request) -> Result<Response, TransportError> {
        self.requests.push(request);
        self.responses
            .pop_front()
            .ok_or_else(|| TransportError("no response queued".to_owned()))
    }
}

#[derive(Default)]
struct NoCnonce;

impl CnonceSource for NoCnonce {
    fn next_cnonce(&mut self) -> Result<String, String> {
        Err("unexpected digest challenge".to_owned())
    }
}

fn client(responses: impl IntoIterator<Item = Response>) -> Client<FakeTransport, NoCnonce> {
    Client::new(
        FakeTransport::new(responses),
        NoCnonce,
        "http://fritz.box:49000",
        "",
        "",
    )
}

fn soap(action: &str, fields: &[(&str, &str)]) -> Response {
    let values = fields
        .iter()
        .map(|(key, value)| format!("<{key}>{value}</{key}>"))
        .collect::<String>();
    Response {
        status: 200,
        body: format!("<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:{action}Response>{values}</u:{action}Response></s:Body></s:Envelope>").into_bytes(),
        ..Response::default()
    }
}

fn fault(code: i32, description: &str) -> ClientError {
    ClientError::SoapFault {
        service: "WANIPConnection".to_owned(),
        action: "GetInfo".to_owned(),
        status: 500,
        code,
        description: description.to_owned(),
    }
}

#[test]
fn every_public_error_family_keeps_its_classification_and_caller_context() {
    let cases = [
        (ClientError::UnauthorizedChallenge, ErrorKind::Unauthorized),
        (
            ClientError::SoapFault {
                service: "WANIPConnection".to_owned(),
                action: "GetInfo".to_owned(),
                status: 401,
                code: 0,
                description: "authentication required".to_owned(),
            },
            ErrorKind::Unauthorized,
        ),
        (fault(401, "anything"), ErrorKind::UnsupportedAction),
        (fault(402, "anything"), ErrorKind::UnsupportedAction),
        (fault(606, "anything"), ErrorKind::Unauthorized),
        (fault(713, "anything"), ErrorKind::ServiceUnavailable),
        (fault(714, "anything"), ErrorKind::ServiceUnavailable),
        (fault(501, "anything"), ErrorKind::Internal),
        (fault(603, "anything"), ErrorKind::Internal),
        (fault(820, "anything"), ErrorKind::Internal),
        (fault(0, "Invalid Action"), ErrorKind::UnsupportedAction),
        (fault(0, "NO SUCH ENTRY"), ErrorKind::ServiceUnavailable),
        (fault(0, "other"), ErrorKind::Unknown),
        (
            ClientError::Transport("HTTP 401 response".to_owned()),
            ErrorKind::Unauthorized,
        ),
        (
            ClientError::Transport("request timed out".to_owned()),
            ErrorKind::Timeout,
        ),
        (
            ClientError::Transport("timeout".to_owned()),
            ErrorKind::Timeout,
        ),
        (
            ClientError::Transport("connection reset".to_owned()),
            ErrorKind::Transport,
        ),
        (
            ClientError::TableEnumeration("bad table".to_owned()),
            ErrorKind::Transport,
        ),
        (
            ClientError::Cnonce("entropy unavailable".to_owned()),
            ErrorKind::Internal,
        ),
        (
            ClientError::DiscoveryHttpStatus(503),
            ErrorKind::ServiceUnavailable,
        ),
        (
            ClientError::Discovery(DiscoveryError("bad XML".to_owned())),
            ErrorKind::ServiceUnavailable,
        ),
        (
            ClientError::SoapParse(SoapParseError("bad SOAP".to_owned())),
            ErrorKind::Internal,
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error_kind(&error), expected, "{error}");
    }

    let wrapped = ClientError::Call {
        service: "WANIPConnection".to_owned(),
        action: "GetInfo".to_owned(),
        source: Box::new(fault(606, "login required")),
    };
    assert_eq!(error_kind(&wrapped), ErrorKind::Unauthorized);
    assert_eq!(
        wrapped.to_string(),
        "SOAP fault HTTP 500, code 606: login required"
    );
    assert!(std::error::Error::source(&wrapped).is_some());
    assert_eq!(
        wrapped.structured_fields(),
        (
            "WANIPConnection".to_owned(),
            "GetInfo".to_owned(),
            "login required".to_owned()
        )
    );
    assert_eq!(
        StatusError {
            service: "DeviceInfo".to_owned(),
            action: "GetInfo".to_owned(),
            message: "offline".to_owned(),
            kind: ErrorKind::Transport
        }
        .to_string(),
        "DeviceInfo/GetInfo: offline"
    );
    assert!(std::error::Error::source(&ClientError::Transport("offline".to_owned())).is_none());
}

#[test]
fn host_ip_mac_and_wake_on_lan_calls_preserve_typed_results_and_wire_arguments() {
    let mut client = client([
        soap(
            "X_AVM-DE_GetSpecificHostEntryByIP",
            &[
                ("NewHostName", "phone"),
                ("NewIPAddress", "192.168.1.5"),
                ("NewActive", "1"),
                ("NewInterfaceType", "802.11ax"),
            ],
        ),
        soap(
            "GetSpecificHostEntry",
            &[
                ("NewHostName", "laptop"),
                ("NewMACAddress", "aa:bb:cc:dd:ee:02"),
                ("NewInterfaceType", "Other"),
            ],
        ),
        soap("X_AVM-DE_WakeOnLANByMACAddress", &[]),
    ]);

    let ip_host = client.resolve_host("192.168.1.5").unwrap();
    assert_eq!(ip_host.name, "phone");
    assert_eq!(ip_host.ip, "192.168.1.5");
    assert_eq!(ip_host.link(), "WLAN");
    let mac_host = client.resolve_host("aa:bb:cc:dd:ee:02").unwrap();
    assert_eq!(mac_host.mac, "AA:BB:CC:DD:EE:02");
    assert_eq!(mac_host.link(), "Other");
    client.wake_on_lan("aa:bb:cc:dd:ee:ff").unwrap();

    let transport = client.into_transport();
    assert_eq!(transport.requests.len(), 3);
    let ip_body = String::from_utf8_lossy(&transport.requests[0].body);
    assert!(ip_body.contains("<NewIPAddress>192.168.1.5</NewIPAddress>"));
    let mac_body = String::from_utf8_lossy(&transport.requests[1].body);
    assert!(mac_body.contains("<NewMACAddress>AA:BB:CC:DD:EE:02</NewMACAddress>"));
    let wol_body = String::from_utf8_lossy(&transport.requests[2].body);
    assert!(wol_body.contains("<NewMACAddress>AA:BB:CC:DD:EE:FF</NewMACAddress>"));
    assert_eq!(
        transport.requests[2].headers["SoapAction"],
        "urn:dslforum-org:service:Hosts:1#X_AVM-DE_WakeOnLANByMACAddress"
    );
}

#[test]
fn name_lookup_rejects_no_match_and_ambiguous_rows() {
    let list = |xml: &'static str| {
        [
            soap(
                "X_AVM-DE_GetHostListPath",
                &[("NewX_AVM-DE_HostListPath", "/hosts.xml")],
            ),
            Response {
                status: 200,
                body: xml.as_bytes().to_vec(),
                ..Response::default()
            },
        ]
    };
    let mut absent = client(list("<root><Item><HostName>alpha</HostName></Item></root>"));
    let error = absent.host_by_name("missing").unwrap_err().to_string();
    assert!(error.contains("no host named \"missing\""));

    let mut duplicate = client(list(
        "<root><Item><HostName>alpha</HostName></Item><Item><HostName>ALPHA</HostName></Item></root>",
    ));
    let error = duplicate.host_by_name("alpha").unwrap_err().to_string();
    assert!(error.contains("2 hosts named \"alpha\""));
    assert!(error.contains("--mac or --ip"));
    assert_eq!(duplicate.into_transport().requests.len(), 2);
}

#[test]
fn diagnosis_reports_local_tcp_open_and_valid_ssh_banner() {
    let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_port = tcp_listener.local_addr().unwrap().port();
    let tcp_server = thread::spawn(move || test_accept::accept(&tcp_listener).unwrap());
    let ssh_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let ssh_port = ssh_listener.local_addr().unwrap().port();
    let ssh_server = thread::spawn(move || {
        let mut stream = test_accept::accept(&ssh_listener).unwrap();
        stream.write_all(b"SSH-2.0-test\r\n").unwrap();
    });
    let mut client = client([soap(
        "X_AVM-DE_GetSpecificHostEntryByIP",
        &[
            ("NewHostName", "local-target"),
            ("NewIPAddress", "127.0.0.1"),
            ("NewActive", "1"),
            ("NewInterfaceType", "Ethernet"),
        ],
    )]);
    let diagnosis = client.diagnose(
        "127.0.0.1",
        DiagnoseOptions {
            ports: vec![
                PortProbe {
                    port: tcp_port,
                    label: "local tcp".to_owned(),
                    probe_type: "tcp".to_owned(),
                    optional: false,
                },
                PortProbe {
                    port: ssh_port,
                    label: "local ssh".to_owned(),
                    probe_type: "ssh".to_owned(),
                    optional: false,
                },
            ],
            dial_timeout_ms: 1000,
        },
    );
    tcp_server.join().unwrap();
    ssh_server.join().unwrap();
    assert!(diagnosis.ok);
    assert_eq!(diagnosis.target, "127.0.0.1");
    assert!(diagnosis.host.is_some());
    assert!(
        diagnosis
            .checks
            .iter()
            .any(|check| check.status == CheckStatus::Ok && check.name.contains("local tcp"))
    );
    assert!(
        diagnosis
            .checks
            .iter()
            .any(|check| check.status == CheckStatus::Ok && check.name.contains("local ssh"))
    );
}

#[test]
fn advertised_service_probe_uses_protocol_scheme_and_response_signature() {
    let mut transport = FakeTransport::new([Response {
        status: 200,
        body: b"<root xmlns=\"urn:schemas-upnp-org:device-1-0\"/>".to_vec(),
        ..Response::default()
    }]);
    assert!(probe_tr064(
        &mut transport,
        "192.168.188.1".parse().unwrap(),
        49443,
        true
    ));
    assert_eq!(
        transport.requests[0].url,
        "https://192.168.188.1:49443/tr64desc.xml"
    );
    assert_eq!(transport.requests[0].response_limit, 4096);

    let mut transport = FakeTransport::new([Response {
        status: 200,
        body: b"urn:dslforum-org:device-1-0".to_vec(),
        ..Response::default()
    }]);
    assert!(probe_tr064(
        &mut transport,
        "192.168.188.2".parse().unwrap(),
        49000,
        false
    ));
    assert_eq!(
        transport.requests[0].url,
        "http://192.168.188.2:49000/tr64desc.xml"
    );

    let mut transport = FakeTransport::new([Response {
        status: 503,
        body: b"urn:dslforum-org:device-1-0".to_vec(),
        ..Response::default()
    }]);
    assert!(!probe_tr064(
        &mut transport,
        "192.168.188.3".parse().unwrap(),
        49000,
        false
    ));
}

#[test]
fn ip_gateway_and_empty_mesh_resolution_helpers_cover_invalid_and_ipv6_inputs() {
    assert!(is_private_ip("fc00::1".parse().unwrap()));
    assert!(is_private_ip("fe80::1".parse().unwrap()));
    assert!(all_public(&["8.8.8.8".to_owned(), "not-an-ip".to_owned()]));
    assert!(!all_public(&[
        "8.8.8.8".to_owned(),
        "192.168.1.1".to_owned()
    ]));
    assert!(all_public(&["not-an-ip".to_owned()]));
    assert!(!classify_resolved_host(&["8.8.8.8".to_owned()], None).is_gateway);
    assert_eq!(parse_linux_default_gateway("default dev en0"), None);
    assert_eq!(
        parse_windows_default_gateway("IPv4 Route Table\n0.0.0.0 invalid"),
        None
    );
    assert_eq!(
        Service::device_info().control_url,
        "/upnp/control/deviceinfo"
    );
}
