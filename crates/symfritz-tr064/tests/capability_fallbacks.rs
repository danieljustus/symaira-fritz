#![deny(unsafe_code)]

use std::{collections::VecDeque, io::Write, net::TcpListener, thread};

use symfritz_tr064::{
    Client, CnonceSource, ErrorKind, Method, Request, Response, Transport, TransportError,
    dial_ssh, dial_tcp,
};

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

fn fault(code: &str, description: &str) -> Response {
    Response {
        status: 500,
        body: format!("<s:Fault><detail><UPnPError><errorCode>{code}</errorCode><errorDescription>{description}</errorDescription></UPnPError></detail></s:Fault>").into_bytes(),
        ..Response::default()
    }
}

#[test]
fn status_without_primary_data_keeps_first_error_even_when_update_query_succeeds() {
    let mut client = client([
        fault("501", "device info unavailable"),
        fault("501", "WAN info unavailable"),
        fault("501", "external address unavailable"),
        soap(
            "GetInfo",
            &[
                ("NewUpgradeAvailable", "1"),
                ("NewX_AVM-DE_Version", "7.59"),
            ],
        ),
    ]);
    let failure = client.status().unwrap_err();
    assert!(failure.status.partial);
    assert_eq!(failure.status.errors.len(), 3);
    assert_eq!(failure.status.update_available, "7.59");
    assert_eq!(failure.status.model_name, "");
    assert_eq!(failure.status.external_ip, "");
    assert!(matches!(
        failure.source,
        symfritz_tr064::ClientError::Call { ref service, ref action, .. }
            if service == "DeviceInfo" && action == "GetInfo"
    ));
    assert_eq!(
        symfritz_tr064::error_kind(&failure.source),
        ErrorKind::Internal
    );
}

#[test]
fn discovery_failure_uses_bounded_legacy_radio_range_and_guest_disable_is_exact() {
    let mut client = client([
        Response {
            status: 502,
            ..Response::default()
        },
        soap("GetInfo", &[("NewSSID", "2.4"), ("NewEnable", "1")]),
        soap("GetInfo", &[("NewSSID", "5")]),
        soap("GetInfo", &[("NewSSID", "guest")]),
        soap("SetEnable", &[]),
    ]);
    let radios = client.radios(0).unwrap();
    assert_eq!(
        radios.iter().map(|radio| radio.index).collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert_eq!(radios[2].ssid, "guest");
    client.set_guest_wlan(3, false).unwrap();

    let transport = client.into_transport();
    assert_eq!(transport.requests[0].method, Method::Get);
    assert_eq!(
        transport.requests[0].url,
        "http://fritz.box:49000/tr64desc.xml"
    );
    assert_eq!(transport.requests.len(), 5);
    assert_eq!(
        transport.requests[1].headers["SoapAction"],
        "urn:dslforum-org:service:WLANConfiguration:1#GetInfo"
    );
    assert_eq!(
        transport.requests[3].headers["SoapAction"],
        "urn:dslforum-org:service:WLANConfiguration:3#GetInfo"
    );
    assert!(
        String::from_utf8_lossy(&transport.requests[4].body).contains("<NewEnable>0</NewEnable>")
    );
}

#[test]
fn dsl_and_online_monitor_do_not_downgrade_on_non_authentication_failures() {
    let mut dsl = client([fault("401", "Invalid Action")]);
    let error = dsl.dsl_line_stats().unwrap_err();
    assert_eq!(
        symfritz_tr064::error_kind(&error),
        ErrorKind::UnsupportedAction
    );
    let transport = dsl.into_transport();
    assert_eq!(transport.requests.len(), 1);
    assert_eq!(
        transport.requests[0].headers["SoapAction"],
        "urn:dslforum-org:service:WANDSLInterfaceConfig:1#GetInfo"
    );

    let mut traffic = client([fault("501", "monitor failed")]);
    let error = traffic.online_monitor().unwrap_err();
    assert_eq!(symfritz_tr064::error_kind(&error), ErrorKind::Internal);
    let transport = traffic.into_transport();
    assert_eq!(transport.requests.len(), 1);
    assert_eq!(
        transport.requests[0].headers["SoapAction"],
        "urn:dslforum-org:service:WANCommonInterfaceConfig:1#X_AVM-DE_GetOnlineMonitor"
    );
}

#[test]
fn tcp_and_ssh_probes_reject_non_ip_and_non_ssh_targets() {
    let timeout = std::time::Duration::from_millis(1);
    assert!(!dial_tcp("not-an-ip", 1, timeout));
    assert!(!dial_ssh("not-an-ip", 22, timeout));

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"HTTP/1.1 200 OK\\r\\n").unwrap();
    });
    assert!(!dial_ssh(
        "127.0.0.1",
        port,
        std::time::Duration::from_secs(1)
    ));
    server.join().unwrap();
}
