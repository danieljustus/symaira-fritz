#![deny(unsafe_code)]

use std::collections::VecDeque;

use symfritz_tr064::{
    CALL_ALL, Client, CnonceSource, ErrorKind, Method, Request, Response, Transport, TransportError,
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
            .ok_or_else(|| TransportError("no fake response queued".to_owned()))
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
        "http://fritz.box:49000/",
        "",
        "",
    )
}

fn soap(action: &str, fields: &[(&str, &str)]) -> Response {
    let mut body = format!(
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:{action}Response>"
    );
    for (name, value) in fields {
        body.push_str(&format!("<{name}>{value}</{name}>"));
    }
    body.push_str(&format!("</u:{action}Response></s:Body></s:Envelope>"));
    Response {
        status: 200,
        body: body.into_bytes(),
        ..Response::default()
    }
}

fn fault(code: &str, description: &str) -> Response {
    Response {
        status: 500,
        body: format!(
            "<s:Fault><detail><UPnPError><errorCode>{code}</errorCode><errorDescription>{description}</errorDescription></UPnPError></detail></s:Fault>"
        )
        .into_bytes(),
        ..Response::default()
    }
}

fn get(body: &str) -> Response {
    Response {
        status: 200,
        body: body.as_bytes().to_vec(),
        ..Response::default()
    }
}

fn soap_action(request: &Request) -> &str {
    request.headers.get("SoapAction").unwrap()
}

#[test]
fn wan_ppp_fallback_is_only_used_for_unsupported_actions() {
    let mut client = client([
        soap("GetInfo", &[("NewModelName", "FRITZ!Box test")]),
        fault("401", "Invalid Action"),
        soap("GetInfo", &[("NewConnectionStatus", "Connected")]),
        fault("401", "Invalid Action"),
        fault("606", "unauthorized"),
        soap("GetInfo", &[("NewUpgradeAvailable", "0")]),
    ]);

    let status = client.status().unwrap();
    assert_eq!(status.model_name, "FRITZ!Box test");
    assert_eq!(status.connection_state, "Connected");
    assert!(status.partial);
    assert_eq!(status.errors.len(), 1);
    assert_eq!(status.errors[0].kind, ErrorKind::Transport);
    assert!(
        status.errors[0]
            .message
            .contains("WANPPPConnection.GetExternalIPAddress fallback failed")
    );
    assert!(status.errors[0].message.contains("code 606: unauthorized"));

    let transport = client.into_transport();
    assert_eq!(
        transport
            .requests
            .iter()
            .map(soap_action)
            .collect::<Vec<_>>(),
        [
            "urn:dslforum-org:service:DeviceInfo:1#GetInfo",
            "urn:dslforum-org:service:WANIPConnection:1#GetInfo",
            "urn:dslforum-org:service:WANPPPConnection:1#GetInfo",
            "urn:dslforum-org:service:WANIPConnection:1#GetExternalIPAddress",
            "urn:dslforum-org:service:WANPPPConnection:1#GetExternalIPAddress",
            "urn:dslforum-org:service:UserInterface:1#GetInfo",
        ]
    );
}

#[test]
fn wan_authentication_errors_do_not_probe_the_ppp_service() {
    let unauthorized = || fault("606", "unauthorized");
    let mut client = client([
        soap("GetInfo", &[("NewModelName", "box")]),
        unauthorized(),
        unauthorized(),
        soap("GetInfo", &[("NewUpgradeAvailable", "0")]),
    ]);

    let status = client.status().unwrap();
    assert!(status.partial);
    assert_eq!(status.errors.len(), 2);
    assert!(
        status
            .errors
            .iter()
            .all(|error| error.kind == ErrorKind::Unauthorized)
    );
    let transport = client.into_transport();
    assert_eq!(transport.requests.len(), 4);
    assert_eq!(
        soap_action(&transport.requests[1]),
        "urn:dslforum-org:service:WANIPConnection:1#GetInfo"
    );
    assert_eq!(
        soap_action(&transport.requests[2]),
        "urn:dslforum-org:service:WANIPConnection:1#GetExternalIPAddress"
    );
    assert!(
        transport
            .requests
            .iter()
            .all(|request| { !soap_action(request).contains("WANPPPConnection") })
    );
}

#[test]
fn bulk_host_list_maps_typed_fields_and_active_name_queries() {
    let path = || {
        soap(
            "X_AVM-DE_GetHostListPath",
            &[("NewHostListPath", "hosts.xml?sid=list-token")],
        )
    };
    let body = "<root><Item><HostName>alpha</HostName><IPAddress>192.168.1.2</IPAddress><MACAddress>aa:bb:cc:dd:ee:01</MACAddress><Active>1</Active><InterfaceType>802.11ac</InterfaceType><AddressSource>DHCP</AddressSource><LeaseTimeRemaining>3600</LeaseTimeRemaining></Item><Item><HostName>beta</HostName><IPAddress>192.168.1.3</IPAddress><MACAddress>aa:bb:cc:dd:ee:02</MACAddress><Active>0</Active><InterfaceType>Ethernet</InterfaceType><AddressSource>Static</AddressSource><LeaseTimeRemaining>bad</LeaseTimeRemaining></Item></root>";
    let mut client = client([path(), get(body), path(), get(body), path(), get(body)]);

    let hosts = client.hosts().unwrap();
    assert_eq!(hosts.len(), 2);
    assert_eq!(hosts[0].name, "alpha");
    assert_eq!(hosts[0].mac, "AA:BB:CC:DD:EE:01");
    assert!(hosts[0].active);
    assert_eq!(hosts[0].link(), "WLAN");
    assert_eq!(hosts[0].lease_time_remaining, 3600);
    assert_eq!(hosts[1].lease_time_remaining, 0);

    let active = client.active_hosts().unwrap();
    assert_eq!(
        active
            .iter()
            .map(|host| host.name.as_str())
            .collect::<Vec<_>>(),
        ["alpha"]
    );
    assert_eq!(client.host_by_name("ALPHA").unwrap(), hosts[0]);

    let transport = client.into_transport();
    assert_eq!(transport.requests.len(), 6);
    for request in transport
        .requests
        .iter()
        .filter(|request| request.method == Method::Get)
    {
        assert_eq!(
            request.url,
            "http://fritz.box:49000/hosts.xml?sid=list-token"
        );
        assert!(request.headers.is_empty());
    }
    assert_eq!(
        soap_action(&transport.requests[0]),
        "urn:dslforum-org:service:Hosts:1#X_AVM-DE_GetHostListPath"
    );
}

#[test]
fn indexed_host_enumeration_skips_failed_rows_without_reordering_indices() {
    let mut client = client([
        Response {
            status: 500,
            body: b"bulk unavailable".to_vec(),
            ..Response::default()
        },
        soap("GetHostNumberOfEntries", &[("NewHostNumberOfEntries", "3")]),
        soap("GetGenericHostEntry", &[("NewHostName", "first")]),
        fault("501", "unsupported"),
        soap("GetGenericHostEntry", &[("NewHostName", "third")]),
    ]);

    let hosts = client.hosts().unwrap();
    assert_eq!(
        hosts
            .iter()
            .map(|host| host.name.as_str())
            .collect::<Vec<_>>(),
        ["first", "third"]
    );
    let transport = client.into_transport();
    assert_eq!(transport.requests.len(), 5);
    for (request, expected_index) in transport.requests[2..].iter().zip(["0", "1", "2"]) {
        assert!(
            String::from_utf8_lossy(&request.body)
                .contains(&format!("<NewIndex>{expected_index}</NewIndex>"))
        );
    }
}

#[test]
fn radio_scan_stops_after_optional_unsupported_radio_but_propagates_first_failure() {
    let mut radio_client = client([
        soap("GetInfo", &[("NewSSID", "main"), ("NewEnable", "1")]),
        fault("401", "Invalid Action"),
        soap("GetInfo", &[("NewSSID", "must not be requested")]),
    ]);
    let radios = radio_client.radios(3).unwrap();
    assert_eq!(radios.len(), 1);
    assert_eq!(radios[0].ssid, "main");
    assert_eq!(radio_client.into_transport().requests.len(), 2);

    let mut client = client([fault("606", "unauthorized")]);
    let error = client.radios(3).unwrap_err();
    assert_eq!(ErrorKind::Unauthorized, symfritz_tr064::error_kind(&error));
    assert_eq!(client.into_transport().requests.len(), 1);
}

#[test]
fn wlan_association_errors_skip_only_the_failed_index_and_keep_typed_rows() {
    let mut client = client([
        soap("GetTotalAssociations", &[("NewTotalAssociations", "3")]),
        soap(
            "GetGenericAssociatedDeviceInfo",
            &[
                ("NewAssociatedDeviceMACAddress", "AA:BB:CC:DD:EE:01"),
                ("NewAssociatedDeviceAuthState", "1"),
            ],
        ),
        fault("714", "No such entry"),
        soap(
            "GetGenericAssociatedDeviceInfo",
            &[
                ("NewAssociatedDeviceMACAddress", "AA:BB:CC:DD:EE:03"),
                ("NewX_AVM-DE_SignalStrength", "72"),
            ],
        ),
    ]);

    let clients = client.wlan_clients(4).unwrap();
    assert_eq!(clients.len(), 2);
    assert_eq!(clients[0].radio_index, 4);
    assert_eq!(clients[0].mac, "AA:BB:CC:DD:EE:01");
    assert!(clients[0].authorized);
    assert_eq!(clients[1].signal, "72");
    let transport = client.into_transport();
    for (request, index) in transport.requests[1..].iter().zip(["0", "1", "2"]) {
        assert!(String::from_utf8_lossy(&request.body).contains(&format!(
            "<NewAssociatedDeviceIndex>{index}</NewAssociatedDeviceIndex>"
        )));
    }
}

#[test]
fn mesh_candidate_refuses_cross_origin_and_bad_urls_before_transport_fallback() {
    let mut mesh_client = client([soap(
        "X_AVM-DE_GetMeshListPath",
        &[(
            "NewX_AVM-DE_MeshListPath",
            "https://attacker.invalid/mesh.json?sid=secret",
        )],
    )]);
    let path = mesh_client.mesh_list_path().unwrap();
    let candidate = mesh_client.mesh_candidate_url(&path).unwrap();
    assert!(!mesh_client.mesh_candidate_matches_origin(&candidate));
    let error = mesh_client.fetch_mesh_candidate(&candidate).unwrap_err();
    assert!(error.to_string().contains("outside configured origin"));
    assert_eq!(mesh_client.into_transport().requests.len(), 1);

    let mut client = client([]);
    let error = client
        .fetch_mesh_candidate("not a URL?sid=must-not-leak")
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("invalid mesh GET URL <invalid URL>")
    );
    assert!(!error.to_string().contains("must-not-leak"));
    assert!(client.into_transport().requests.is_empty());
}

#[test]
fn calls_and_device_log_parse_valid_invalid_and_nested_router_data() {
    let calls_xml = "<root><CallList><Call><Type>3</Type><Caller>111</Caller><Called>222</Called><Name></Name><Date>2024-02-29 23:59:59</Date><Duration>1:02:03</Duration></Call><Call><Type>2</Type><Caller>333</Caller><Called>444</Called><Name>Known</Name><Date>29.06.69 01:02</Date><Duration>90</Duration></Call><Call><Type>x</Type><Caller>555</Caller><Date>31.02.24 12:00:00</Date><Duration>bad</Duration></Call></CallList></root>";
    let log_xml = "<DeviceLog><Event><id>1</id><group>sys</group><date>29.06.26</date><time>14:15:00</time><msg>started</msg></Event><Event><id>2</id><date>31.02.26</date><time>25:00:00</time><msg>bad clock</msg></Event><Event><id>3</id><msg>missing clock</msg></Event></DeviceLog>";
    let mut client = client([
        soap(
            "GetCallList",
            &[("NewCallListURL", "/calls.xml?sid=existing")],
        ),
        get(calls_xml),
        soap(
            "X_AVM-DE_GetDeviceLogPath",
            &[("NewDeviceLogPath", "/log.lua?sid=existing&amp;filter=old")],
        ),
        get(log_xml),
    ]);

    let calls = client.calls(CALL_ALL, 0, 0).unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].caller, "111");
    assert_eq!(calls[0].date, "2024-02-29T23:59:59");
    assert_eq!(calls[0].duration, 3_723_000_000_000);
    assert_eq!(calls[1].caller, "Known");
    assert_eq!(calls[1].date, "1969-06-29T01:02:00");
    assert_eq!(calls[1].duration, 90_000_000_000);
    assert_eq!(calls[2].date, "");
    assert_eq!(calls[2].duration, 0);

    let events = client.device_log("sys").unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].time, "2026-06-29T14:15:00");
    assert_eq!(events[1].time, "");
    assert_eq!(events[2].time, "");
    let transport = client.into_transport();
    assert_eq!(
        transport.requests[1].url,
        "http://fritz.box:49000/calls.xml?sid=existing"
    );
    assert_eq!(
        transport.requests[3].url,
        "http://fritz.box:49000/log.lua?filter=sys&sid=existing"
    );
}

#[test]
fn malformed_call_and_log_bodies_return_transport_errors() {
    let mut calls = client([
        soap("GetCallList", &[("NewCallListURL", "/calls.xml")]),
        get("<CallList>"),
    ]);
    let error = calls.calls(CALL_ALL, 0, 0).unwrap_err();
    assert_eq!(ErrorKind::Transport, symfritz_tr064::error_kind(&error));
    assert_eq!(calls.into_transport().requests.len(), 2);

    let mut log = client([
        soap(
            "X_AVM-DE_GetDeviceLogPath",
            &[("NewDeviceLogPath", "/log.lua")],
        ),
        Response {
            status: 200,
            body: vec![0xff],
            ..Response::default()
        },
    ]);
    let error = log.device_log("all").unwrap_err();
    assert_eq!(ErrorKind::Transport, symfritz_tr064::error_kind(&error));
}
