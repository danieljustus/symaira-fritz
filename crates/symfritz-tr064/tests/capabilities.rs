#![deny(unsafe_code)]

use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    path::PathBuf,
};

use serde::Deserialize;
use symfritz_tr064::{
    Client, CnonceSource, DiagnoseOptions, MAX_TABLE_ENTRIES, Method, PortProbe, Request, Response,
    Service, Transport, TransportError, WlanClient,
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
        Err("cnonce not expected".to_owned())
    }
}

fn soap(action: &str, values: &[(&str, &str)]) -> Response {
    let mut body = format!(
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:{action}Response>"
    );
    for (key, value) in values {
        body.push_str(&format!("<{key}>{value}</{key}>"));
    }
    body.push_str(&format!("</u:{action}Response></s:Body></s:Envelope>"));
    Response {
        status: 200,
        body: body.into_bytes(),
        ..Response::default()
    }
}

fn unauthorized() -> Response {
    Response {
        status: 500,
        body: b"<s:Fault><detail><UPnPError><errorCode>606</errorCode><errorDescription>unauthorized</errorDescription></UPnPError></detail></s:Fault>".to_vec(),
        ..Response::default()
    }
}

/// A non-200 that fails `bulk_hosts`, so `hosts()` falls back to the indexed
/// path under test.
fn bulk_hosts_failure() -> Response {
    Response {
        status: 500,
        body: b"not a SOAP fault".to_vec(),
        ..Response::default()
    }
}

fn make_client(responses: impl IntoIterator<Item = Response>) -> Client<FakeTransport, NoCnonce> {
    Client::new(
        FakeTransport::new(responses),
        NoCnonce,
        "http://fritz.box:49000",
        "",
        "",
    )
}

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: String,
    hosts: Vec<serde_json::Value>,
    radios: Vec<serde_json::Value>,
    wlan_clients: Vec<serde_json::Value>,
    mesh: serde_json::Value,
    diagnosis: serde_json::Value,
    requests: Vec<RequestVector>,
    negative: Vec<NegativeVector>,
}

#[derive(Debug, Deserialize)]
struct RequestVector {
    id: String,
    service_type: String,
    control_url: String,
    action: String,
    #[serde(default)]
    args: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct NegativeVector {
    id: String,
    input: String,
    message: String,
}

fn fixture() -> Fixture {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    serde_json::from_slice(
        &fs::read(root.join("testdata/port/capabilities-core/contracts.json")).unwrap(),
    )
    .unwrap()
}

#[test]
fn go_fixture_covers_core_models_requests_and_negative_branches() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.oracle,
        "Go internal/fritz typed capability production models and request seams"
    );
    assert_eq!(fixture.hosts[0]["mac"], "F0:18:98:F3:64:B5");
    assert_eq!(fixture.radios[1]["index"], 3);
    assert_eq!(fixture.wlan_clients[0]["signal_strength"], "80");
    assert_eq!(fixture.mesh["nodes"][0]["mesh_role"], "master");
    assert_eq!(fixture.diagnosis["ref"], "fixture-ref");
    assert_eq!(fixture.requests[0].id, "status-device-info");
    assert_eq!(
        fixture.requests[0].service_type,
        "urn:dslforum-org:service:DeviceInfo:1"
    );
    assert_eq!(fixture.requests[0].action, "GetInfo");
    assert_eq!(
        fixture.requests[4].args["NewMACAddress"],
        "AA:BB:CC:DD:EE:FF"
    );
    assert_eq!(fixture.requests[7].control_url, "/upnp/control/wlanconfig3");
    assert_eq!(
        fixture.negative[1].message,
        "2 hosts named \"duplicate\"; use --mac or --ip to disambiguate"
    );
    assert_eq!(fixture.negative[0].id, "empty-host-name");
    assert_eq!(fixture.negative[0].input, "");
}

#[test]
fn status_uses_exact_order_and_models_partial_success() {
    let mut client = make_client([
        soap(
            "GetInfo",
            &[
                ("NewModelName", "FRITZ!Box 7590"),
                ("NewSoftwareVersion", "7.57"),
                ("NewUpTime", "3600"),
            ],
        ),
        soap("GetInfo", &[("NewConnectionStatus", "Connected")]),
        soap(
            "GetExternalIPAddress",
            &[("NewExternalIPAddress", "203.0.113.1")],
        ),
        soap("GetInfo", &[("NewUpgradeAvailable", "0")]),
    ]);
    let status = client.status().unwrap();
    assert_eq!(status.model_name, "FRITZ!Box 7590");
    assert_eq!(status.external_ip, "203.0.113.1");
    assert!(!status.partial);
    let transport = client.into_transport();
    assert_eq!(transport.requests.len(), 4);
    assert_eq!(
        transport.requests[0].headers["SoapAction"],
        "urn:dslforum-org:service:DeviceInfo:1#GetInfo"
    );
    assert_eq!(
        transport.requests[1].headers["SoapAction"],
        "urn:dslforum-org:service:WANIPConnection:1#GetInfo"
    );
    assert_eq!(
        transport.requests[2].headers["SoapAction"],
        "urn:dslforum-org:service:WANIPConnection:1#GetExternalIPAddress"
    );
    assert_eq!(
        transport.requests[3].headers["SoapAction"],
        "urn:dslforum-org:service:UserInterface:1#GetInfo"
    );
}

#[test]
fn host_mac_wol_wlan_and_mesh_use_typed_calls() {
    let mut client = make_client([soap(
        "GetSpecificHostEntry",
        &[
            ("NewHostName", "macmini"),
            ("NewIPAddress", "192.168.188.65"),
            ("NewMACAddress", "f0:18:98:f3:64:b5"),
            ("NewActive", "1"),
            ("NewInterfaceType", "Ethernet"),
            ("NewLeaseTimeRemaining", "3600"),
        ],
    )]);
    let host = client.host_by_mac("f0:18:98:f3:64:b5").unwrap();
    assert_eq!(host.mac, "F0:18:98:F3:64:B5");
    assert_eq!(host.link(), "LAN");
    let request = &client.into_transport().requests[0];
    assert_eq!(
        request.headers["SoapAction"],
        "urn:dslforum-org:service:Hosts:1#GetSpecificHostEntry"
    );
    assert!(
        String::from_utf8_lossy(&request.body)
            .contains("<NewMACAddress>F0:18:98:F3:64:B5</NewMACAddress>")
    );

    let mut client = make_client([
        soap("GetTotalAssociations", &[("NewTotalAssociations", "1")]),
        soap(
            "GetGenericAssociatedDeviceInfo",
            &[
                ("NewAssociatedDeviceMACAddress", "aa:bb:cc:dd:ee:01"),
                ("NewAssociatedDeviceIPAddress", "192.168.188.10"),
                ("NewX_AVM-DE_SignalStrength", "80"),
                ("NewX_AVM-DE_Speed", "300"),
                ("NewAssociatedDeviceAuthState", "1"),
            ],
        ),
    ]);
    let clients = client.wlan_clients(1).unwrap();
    assert_eq!(
        clients,
        vec![WlanClient {
            radio_index: 1,
            mac: "aa:bb:cc:dd:ee:01".to_owned(),
            ip: "192.168.188.10".to_owned(),
            signal: "80".to_owned(),
            speed: "300".to_owned(),
            authorized: true
        }]
    );

    let mut client = make_client([soap("SetEnable", &[])]);
    client.set_guest_wlan(3, true).unwrap();
    let request = &client.into_transport().requests[0];
    assert_eq!(
        request.headers["SoapAction"],
        "urn:dslforum-org:service:WLANConfiguration:3#SetEnable"
    );
    assert!(String::from_utf8_lossy(&request.body).contains("<NewEnable>1</NewEnable>"));

    let mesh = br#"{"schema_version":"1.0","nodes":[{"uid":"n1","device_name":"FRITZ!Box 7590","device_model":"FB7590","is_meshed":true,"mesh_role":"master","node_interfaces":[{"uid":"n1-lan","name":"LAN Bridge","type":"LAN","node_links":[{"state":"CONNECTED","node_1":"n1-lan","node_2":"n2-wlan","max_data_rate_rx":1000,"max_data_rate_tx":1000,"cur_data_rate_rx":500,"cur_data_rate_tx":400}]}]}]}"#;
    let mut client = make_client([
        soap(
            "X_AVM-DE_GetMeshListPath",
            &[("NewX_AVM-DE_MeshListPath", "/mesh.json")],
        ),
        Response {
            status: 200,
            body: mesh.to_vec(),
            ..Response::default()
        },
    ]);
    let path = client.mesh_list_path().unwrap();
    let url = client.mesh_candidate_url(&path).unwrap();
    let response = client.fetch_mesh_candidate(&url).unwrap();
    let topology = symfritz_tr064::parse_mesh_topology(&response.body).unwrap();
    assert_eq!(topology.node_name("n1-lan"), "FRITZ!Box 7590");
    assert_eq!(
        topology.nodes[0].node_interfaces[0].node_links[0].cur_data_rate_rx,
        500
    );
    let transport = client.into_transport();
    assert_eq!(transport.requests[1].method, Method::Get);
    assert_eq!(transport.requests[1].headers, BTreeMap::new());
    assert_eq!(
        transport.requests[1].url,
        "http://fritz.box:49000/mesh.json"
    );
}

#[test]
fn diagnosis_keeps_port_order_and_optional_failures_are_warnings() {
    let mut client = make_client([soap(
        "X_AVM-DE_GetSpecificHostEntryByIP",
        &[
            ("NewHostName", "host"),
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
                    port: 1,
                    label: "first".to_owned(),
                    probe_type: "tcp".to_owned(),
                    optional: true,
                },
                PortProbe {
                    port: 1,
                    label: "second".to_owned(),
                    probe_type: "tcp".to_owned(),
                    optional: false,
                },
            ],
            dial_timeout_ms: 50,
        },
    );
    let probes: Vec<_> = diagnosis
        .checks
        .iter()
        .filter(|check| check.name.starts_with("TCP "))
        .collect();
    assert_eq!(probes.len(), 2);
    assert!(probes[0].name.contains("first"));
    assert_eq!(probes[0].status, symfritz_tr064::CheckStatus::Warn);
    assert!(probes[1].name.contains("second"));
    assert_eq!(probes[1].status, symfritz_tr064::CheckStatus::Fail);
    assert!(!diagnosis.ok);
    let json = serde_json::to_value(&diagnosis).unwrap();
    assert_eq!(json["ref"], "127.0.0.1");
    assert!(json.get("reference").is_none());
}

#[allow(dead_code)]
fn _service_type_is_stable(service: &Service) -> (&str, &str) {
    (&service.service_type, &service.control_url)
}

#[test]
fn status_returns_original_prioritized_unauthorized_error() {
    let mut client = make_client([
        Response {
            status: 500,
            body: b"not a SOAP fault".to_vec(),
            ..Response::default()
        },
        unauthorized(),
        Response {
            status: 500,
            body: b"not a SOAP fault".to_vec(),
            ..Response::default()
        },
        Response {
            status: 500,
            body: b"not a SOAP fault".to_vec(),
            ..Response::default()
        },
    ]);
    let failure = client.status().unwrap_err();
    assert_eq!(
        failure.source,
        symfritz_tr064::ClientError::Call {
            service: "WANIPConnection".to_owned(),
            action: "GetInfo".to_owned(),
            source: Box::new(symfritz_tr064::ClientError::SoapFault {
                service: "WANIPConnection".to_owned(),
                action: "GetInfo".to_owned(),
                status: 500,
                code: 606,
                description: "unauthorized".to_owned(),
            }),
        }
    );
    assert_eq!(
        symfritz_tr064::error_kind(&failure.source),
        symfritz_tr064::ErrorKind::Unauthorized
    );
    assert_eq!(failure.to_string(), failure.source.to_string());
    assert!(std::error::Error::source(&failure).is_some());
}

#[test]
fn status_keeps_partial_report_when_returning_original_error() {
    let mut client = make_client([
        unauthorized(),
        unauthorized(),
        unauthorized(),
        unauthorized(),
    ]);
    let failure = client.status().unwrap_err();
    assert!(failure.status.model_name.is_empty());
    assert!(failure.status.firmware_version.is_empty());
    assert!(failure.status.external_ip.is_empty());
    assert!(failure.status.connection_state.is_empty());
    assert!(failure.status.uptime.is_empty());
    assert!(failure.status.update_available.is_empty());
    assert!(failure.status.partial);
    assert_eq!(failure.status.errors.len(), 4);
    assert!(
        failure
            .status
            .errors
            .iter()
            .all(|error| error.kind == symfritz_tr064::ErrorKind::Unauthorized)
    );
    assert_eq!(
        failure.source,
        symfritz_tr064::ClientError::Call {
            service: "DeviceInfo".to_owned(),
            action: "GetInfo".to_owned(),
            source: Box::new(symfritz_tr064::ClientError::SoapFault {
                service: "DeviceInfo".to_owned(),
                action: "GetInfo".to_owned(),
                status: 500,
                code: 606,
                description: "unauthorized".to_owned(),
            }),
        }
    );
    assert_eq!(
        symfritz_tr064::error_kind(&failure.source),
        symfritz_tr064::ErrorKind::Unauthorized
    );
}

#[test]
fn mesh_plain_get_preserves_requested_response_limit_and_auth_mode() {
    let mut body = br#"{"schema_version":"1.0","nodes":[]}"#.to_vec();
    body.resize((1 << 20) + 1, b' ');
    let mut client = make_client([
        soap(
            "X_AVM-DE_GetMeshListPath",
            &[("NewX_AVM-DE_MeshListPath", "/mesh.json?sid=existing")],
        ),
        Response {
            status: 200,
            body,
            ..Response::default()
        },
    ]);
    let path = client.mesh_list_path().unwrap();
    let url = client.mesh_candidate_url(&path).unwrap();
    let response = client.fetch_mesh_candidate(&url).unwrap();
    assert_eq!(response.body.len(), (1 << 20) + 1);
    let transport = client.into_transport();
    assert_eq!(transport.requests[1].response_limit, 8 << 20);
    assert!(transport.requests[1].headers.is_empty());
}

#[test]
fn authenticated_get_status_errors_redact_query_values() {
    let mut client = make_client([
        soap(
            "X_AVM-DE_GetMeshListPath",
            &[("NewX_AVM-DE_MeshListPath", "/mesh.json?sid=secret-sid")],
        ),
        Response {
            status: 500,
            ..Response::default()
        },
    ]);
    let path = client.mesh_list_path().unwrap();
    let url = client.mesh_candidate_url(&path).unwrap();
    let error = client.fetch_mesh_candidate(&url).unwrap_err().to_string();
    assert!(!error.contains("secret-sid"));
    assert!(error.contains("sid=REDACTED"));
}

#[test]
fn host_index_count_within_bound_returns_complete_ordered_hosts() {
    let mut client = make_client([
        bulk_hosts_failure(),
        soap("GetHostNumberOfEntries", &[("NewHostNumberOfEntries", "2")]),
        soap("GetGenericHostEntry", &[("NewHostName", "first")]),
        soap("GetGenericHostEntry", &[("NewHostName", "second")]),
    ]);
    let hosts = client.hosts().unwrap();
    let names: Vec<_> = hosts.iter().map(|host| host.name.as_str()).collect();
    assert_eq!(names, ["first", "second"]);
    assert_eq!(client.into_transport().requests.len(), 4);
}

#[test]
fn host_index_count_at_bound_returns_complete_ordered_hosts() {
    let count = MAX_TABLE_ENTRIES.to_string();
    let mut responses = vec![
        bulk_hosts_failure(),
        soap(
            "GetHostNumberOfEntries",
            &[("NewHostNumberOfEntries", &count)],
        ),
    ];
    responses.extend((0..MAX_TABLE_ENTRIES).map(|index| {
        soap(
            "GetGenericHostEntry",
            &[("NewHostName", &format!("host-{index:04}"))],
        )
    }));
    let mut client = make_client(responses);
    let hosts = client.hosts().unwrap();
    assert_eq!(hosts.len(), MAX_TABLE_ENTRIES);
    for (index, host) in hosts.iter().enumerate() {
        assert_eq!(host.name, format!("host-{index:04}"));
    }
    assert_eq!(
        client.into_transport().requests.len(),
        2 + MAX_TABLE_ENTRIES
    );
}

#[test]
fn host_index_count_rejections_precede_allocation_and_index_requests() {
    let limit = MAX_TABLE_ENTRIES.to_string();
    for value in [usize::MAX.to_string(), (MAX_TABLE_ENTRIES + 1).to_string()] {
        let mut client = make_client([
            bulk_hosts_failure(),
            soap(
                "GetHostNumberOfEntries",
                &[("NewHostNumberOfEntries", &value)],
            ),
        ]);
        let error = client.hosts().unwrap_err();
        let message = error.to_string();
        assert!(message.contains("NewHostNumberOfEntries"), "{message}");
        assert!(message.contains(&limit), "{message}");
        assert_eq!(
            symfritz_tr064::error_kind(&error),
            symfritz_tr064::ErrorKind::Transport
        );
        // Bulk probe plus count query only: no GetGenericHostEntry storm.
        assert_eq!(client.into_transport().requests.len(), 2);
    }

    for value in ["not-a-count", "-1"] {
        let mut client = make_client([
            bulk_hosts_failure(),
            soap(
                "GetHostNumberOfEntries",
                &[("NewHostNumberOfEntries", value)],
            ),
        ]);
        let error = client.hosts().unwrap_err();
        assert!(
            error.to_string().contains("invalid NewHostNumberOfEntries"),
            "{error}"
        );
        assert_eq!(client.into_transport().requests.len(), 2);
    }

    let mut client = make_client([bulk_hosts_failure(), soap("GetHostNumberOfEntries", &[])]);
    let error = client.hosts().unwrap_err();
    assert!(
        error.to_string().contains("NewHostNumberOfEntries missing"),
        "{error}"
    );
    assert_eq!(client.into_transport().requests.len(), 2);
}

#[test]
fn wlan_association_count_at_bound_returns_complete_ordered_clients() {
    let count = MAX_TABLE_ENTRIES.to_string();
    let mut responses = vec![soap(
        "GetTotalAssociations",
        &[("NewTotalAssociations", &count)],
    )];
    responses.extend((0..MAX_TABLE_ENTRIES).map(|index| {
        soap(
            "GetGenericAssociatedDeviceInfo",
            &[
                (
                    "NewAssociatedDeviceMACAddress",
                    &format!("aa:bb:cc:dd:{:02}:{:02}", index >> 8, index & 0xff),
                ),
                ("NewX_AVM-DE_SignalStrength", &index.to_string()),
            ],
        )
    }));
    let mut client = make_client(responses);
    let clients = client.wlan_clients(1).unwrap();
    assert_eq!(clients.len(), MAX_TABLE_ENTRIES);
    for (index, entry) in clients.iter().enumerate() {
        assert_eq!(entry.radio_index, 1);
        assert_eq!(entry.signal, index.to_string());
    }
    assert_eq!(
        client.into_transport().requests.len(),
        1 + MAX_TABLE_ENTRIES
    );
}

#[test]
fn wlan_association_count_rejections_precede_allocation_and_index_requests() {
    let limit = MAX_TABLE_ENTRIES.to_string();
    for value in [usize::MAX.to_string(), (MAX_TABLE_ENTRIES + 1).to_string()] {
        let mut client = make_client([soap(
            "GetTotalAssociations",
            &[("NewTotalAssociations", &value)],
        )]);
        let error = client.wlan_clients(1).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("NewTotalAssociations"), "{message}");
        assert!(message.contains(&limit), "{message}");
        assert_eq!(
            symfritz_tr064::error_kind(&error),
            symfritz_tr064::ErrorKind::Transport
        );
        // Count query only: no GetGenericAssociatedDeviceInfo index storm.
        assert_eq!(client.into_transport().requests.len(), 1);
    }

    for value in ["not-a-count", "-1"] {
        let mut client = make_client([soap(
            "GetTotalAssociations",
            &[("NewTotalAssociations", value)],
        )]);
        let error = client.wlan_clients(1).unwrap_err();
        assert!(
            error.to_string().contains("invalid NewTotalAssociations"),
            "{error}"
        );
        assert_eq!(client.into_transport().requests.len(), 1);
    }

    let mut client = make_client([soap("GetTotalAssociations", &[])]);
    let error = client.wlan_clients(1).unwrap_err();
    assert!(
        error.to_string().contains("NewTotalAssociations missing"),
        "{error}"
    );
    assert_eq!(client.into_transport().requests.len(), 1);
}

#[test]
fn wlan_aggregate_controls_a_rejected_radio_count() {
    let mut client = make_client([
        soap("GetInfo", &[("NewSSID", "net-2g"), ("NewEnable", "1")]),
        soap("GetInfo", &[("NewSSID", "net-5g"), ("NewEnable", "1")]),
        soap("GetTotalAssociations", &[("NewTotalAssociations", "1")]),
        soap(
            "GetGenericAssociatedDeviceInfo",
            &[
                ("NewAssociatedDeviceMACAddress", "aa:bb:cc:dd:ee:01"),
                ("NewAssociatedDeviceIPAddress", "192.168.188.10"),
            ],
        ),
        soap(
            "GetTotalAssociations",
            &[("NewTotalAssociations", &usize::MAX.to_string())],
        ),
    ]);
    let error = client.all_wlan_clients(2).unwrap_err();
    assert!(matches!(
        error,
        symfritz_tr064::ClientError::TableEnumeration(_)
    ));
    assert!(error.to_string().contains("NewTotalAssociations"));
    assert_eq!(
        symfritz_tr064::error_kind(&error),
        symfritz_tr064::ErrorKind::Transport
    );
    // The previously collected radio 1 client must not be reported as a
    // complete successful aggregate after radio 2 rejects its count.
    assert_eq!(client.into_transport().requests.len(), 5);
}
