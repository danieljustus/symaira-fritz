#![deny(unsafe_code)]

use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    path::PathBuf,
};

use serde_json::Value;
use symfritz_tr064::{
    CALL_ALL, CALL_MISSED, Client, CnonceSource, Method, Request, Response, Service, Transport,
    TransportError,
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
        "http://fritz.box:49000",
        "",
        "",
    )
}

fn soap(action: &str, values: &[(&str, &str)]) -> Response {
    let values = values
        .iter()
        .map(|(key, value)| format!("<{key}>{value}</{key}>"))
        .collect::<String>();
    Response {
        status: 200,
        body: format!("<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:{action}Response>{values}</u:{action}Response></s:Body></s:Envelope>").into_bytes(),
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

fn get(body: &str) -> Response {
    Response {
        status: 200,
        body: body.as_bytes().to_vec(),
        ..Response::default()
    }
}

fn fixture() -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    serde_json::from_slice(
        &fs::read(root.join("testdata/port/capabilities-remaining/contracts.json")).unwrap(),
    )
    .unwrap()
}

#[test]
fn go_fixture_freezes_remaining_models_requests_fallbacks_and_negatives() {
    let fixture = fixture();
    assert_eq!(fixture["schema_version"], 1);
    assert!(fixture["models"]["dsl"]["upstream_noise_margin"].is_number());
    assert_eq!(fixture["models"]["calls"][0]["type"], 1);
    assert_eq!(fixture["models"]["traffic"]["downstream_internet"][0], 1000);
    assert_eq!(fixture["models"]["log"][0]["group"], "sys");
    assert_eq!(fixture["requests"].as_array().unwrap().len(), 11);
    assert_eq!(
        fixture["requests"][6]["args"]["NewX_AVM-DE_PhoneNumber"],
        "123"
    );
    assert_eq!(fixture["requests"][9]["action"], "Reboot");
    assert_eq!(fixture["fallbacks"].as_array().unwrap().len(), 5);
    assert_eq!(
        fixture["fallbacks"][0]["expected_request"][0]["action"],
        "GetCommonLinkProperties"
    );
    assert_eq!(
        fixture["negative"][2]["message"],
        "query.lua response missing CPUTEMP key"
    );
}

#[test]
fn dsl_and_traffic_match_authenticated_models_and_arguments() {
    let mut dsl = client([
        soap(
            "GetInfo",
            &[
                ("NewUpstreamNoiseMargin", "60"),
                ("NewDownstreamNoiseMargin", "80"),
                ("NewUpstreamAttenuation", "150"),
                ("NewDownstreamAttenuation", "180"),
            ],
        ),
        soap(
            "GetCommonLinkProperties",
            &[
                ("NewLayer1UpstreamMaxBitRate", "40000000"),
                ("NewLayer1DownstreamMaxBitRate", "100000000"),
            ],
        ),
    ]);
    let stats = dsl.dsl_line_stats().unwrap();
    assert_eq!(stats.upstream_noise_margin, 60);
    assert_eq!(stats.downstream_max_bit_rate, 100000000);
    let transport = dsl.into_transport();
    assert_eq!(transport.requests.len(), 2);
    assert_eq!(
        transport.requests[0].headers["SoapAction"],
        "urn:dslforum-org:service:WANDSLInterfaceConfig:1#GetInfo"
    );
    assert_eq!(
        transport.requests[1].headers["SoapAction"],
        "urn:dslforum-org:service:WANCommonInterfaceConfig:1#GetCommonLinkProperties"
    );

    let mut traffic = client([soap(
        "X_AVM-DE_GetOnlineMonitor",
        &[
            ("Newds_current_bps", "1000,2000"),
            ("Newmc_current_bps", "100,200"),
            ("Newds_guest_bps", "10,20"),
            ("Newprio_realtime_bps", "5,5"),
            ("Newprio_high_bps", "2,2"),
            ("Newprio_default_bps", "1,1"),
            ("Newprio_low_bps", "0,0"),
            ("Newus_guest_bps", "0,0"),
        ],
    )]);
    let stats = traffic.online_monitor().unwrap();
    assert_eq!(stats.downstream_internet, [1000.0, 2000.0]);
    assert_eq!(stats.upstream_guest, [0.0, 0.0]);
    let request = &traffic.into_transport().requests[0];
    assert!(
        String::from_utf8_lossy(&request.body).contains("<NewSyncGroupIndex>0</NewSyncGroupIndex>")
    );
}

#[test]
fn dsl_and_traffic_use_only_the_unauthorized_igd_fallback() {
    let mut dsl = client([
        unauthorized(),
        soap(
            "GetCommonLinkProperties",
            &[
                ("NewLayer1UpstreamMaxBitRate", "40000000"),
                ("NewLayer1DownstreamMaxBitRate", "100000000"),
            ],
        ),
    ]);
    let stats = dsl.dsl_line_stats().unwrap();
    assert!(stats.is_reduced_dataset);
    assert_eq!(
        dsl.into_transport().requests[1].headers["SoapAction"],
        "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1#GetCommonLinkProperties"
    );

    let mut traffic = client([
        unauthorized(),
        soap(
            "GetAddonInfos",
            &[
                ("NewByteReceiveRate", "125000"),
                ("NewByteSendRate", "25000"),
            ],
        ),
    ]);
    let stats = traffic.online_monitor().unwrap();
    assert!(stats.is_reduced_dataset);
    assert_eq!(stats.downstream_internet, [1000000.0]);
    assert_eq!(stats.upstream_default_priority, [200000.0]);
}

#[test]
fn calls_filters_by_type_and_preserves_query_and_order() {
    let xml = "<root><Call><Type>1</Type><Caller>01712345</Caller><Called>089123</Called><Name>Alice</Name><Date>29.06.26 14:15</Date><Duration>0:15</Duration></Call><Call><Type>2</Type><Caller>111</Caller><Called>222</Called><Name></Name><Date>29.06.26 14:16</Date><Duration>90</Duration></Call></root>";
    let mut client = client([
        soap(
            "GetCallList",
            &[(
                "NewCallListURL",
                "http://fritz.box:49000/calls.xml?sid=mock&amp;existing=1",
            )],
        ),
        get(xml),
    ]);
    let calls = client.calls(CALL_MISSED, 2, 7).unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].caller, "111");
    assert_eq!(calls[0].duration, 90_000_000_000);
    let transport = client.into_transport();
    assert_eq!(transport.requests[1].method, Method::Get);
    assert_eq!(
        transport.requests[1].url,
        "http://fritz.box:49000/calls.xml?days=7&existing=1&max=2&sid=mock"
    );
}

#[test]
fn dial_hangup_reboot_and_log_filter_have_exact_raw_calls() {
    let log = "<DeviceLog><Event><id>1</id><group>sys</group><date>29.06.26</date><time>14:15:00</time><msg>started</msg></Event></DeviceLog>";
    let mut client = client([
        soap("X_AVM-DE_DialNumber", &[]),
        soap("X_AVM-DE_DialHangup", &[]),
        soap("Reboot", &[]),
        soap(
            "X_AVM-DE_GetDeviceLogPath",
            &[("NewDeviceLogPath", "/log.lua?sid=one")],
        ),
        get(log),
    ]);
    client.dial("123").unwrap();
    client.hangup().unwrap();
    client.reboot().unwrap();
    let events = client.device_log("all").unwrap();
    assert_eq!(events[0].msg, "started");
    let transport = client.into_transport();
    assert_eq!(
        transport.requests[0].headers["SoapAction"],
        "urn:dslforum-org:service:X_VoIP:1#X_AVM-DE_DialNumber"
    );
    assert!(
        String::from_utf8_lossy(&transport.requests[0].body)
            .contains("<NewX_AVM-DE_PhoneNumber>123</NewX_AVM-DE_PhoneNumber>")
    );
    assert_eq!(
        transport.requests[1].headers["SoapAction"],
        "urn:dslforum-org:service:X_VoIP:1#X_AVM-DE_DialHangup"
    );
    assert_eq!(
        transport.requests[2].headers["SoapAction"],
        "urn:dslforum-org:service:DeviceConfig:1#Reboot"
    );
    assert_eq!(
        transport.requests[4].url,
        "http://fritz.box:49000/log.lua?sid=one"
    );
}

#[test]
fn negative_empty_paths_and_malformed_xml_are_errors() {
    let mut calls = client([soap("GetCallList", &[("NewCallListURL", "")])]);
    assert_eq!(
        calls.calls(CALL_ALL, 0, 0).unwrap_err().to_string(),
        "tr064: GetCallList returned empty NewCallListURL"
    );
    let mut log = client([soap(
        "X_AVM-DE_GetDeviceLogPath",
        &[("NewDeviceLogPath", "")],
    )]);
    assert_eq!(
        log.device_log("sys").unwrap_err().to_string(),
        "tr064: GetDeviceLogPath returned empty path"
    );
    let mut malformed = client([
        soap("GetCallList", &[("NewCallListURL", "/calls")]),
        get("<CallList>"),
    ]);
    assert!(malformed.calls(CALL_ALL, 0, 0).is_err());
}

#[test]
fn public_service_constructors_cover_all_remaining_raw_capabilities() {
    let services = [
        (
            Service::dsl_interface_config(),
            "WANDSLInterfaceConfig",
            "/upnp/control/wandslifconfig1",
        ),
        (
            Service::wan_common_interface(),
            "WANCommonInterfaceConfig",
            "/upnp/control/wancommonifconfig1",
        ),
        (
            Service::igd_wan_common_interface(),
            "WANCommonInterfaceConfig",
            "/igdupnp/control/WANCommonIFC1",
        ),
        (
            Service::ontel(),
            "X_AVM-DE_OnTel",
            "/upnp/control/x_contact",
        ),
        (Service::voip(), "X_VoIP", "/upnp/control/x_voip"),
        (
            Service::device_config(),
            "DeviceConfig",
            "/upnp/control/deviceconfig",
        ),
    ];
    for (service, name, control_url) in services {
        assert!(service.service_type.contains(name));
        assert_eq!(service.control_url, control_url);
    }
}

#[allow(dead_code)]
fn _empty_args() -> BTreeMap<String, String> {
    BTreeMap::new()
}
