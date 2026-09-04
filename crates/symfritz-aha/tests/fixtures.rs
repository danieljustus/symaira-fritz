use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    path::PathBuf,
    time::Instant,
};

use serde::Deserialize;
use symfritz_aha::{
    Client, Clock, Request, Response, Transport, TransportError, parse_device_list,
};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: String,
    hkr_error_descriptions: BTreeMap<String, String>,
    device_xml: Vec<DeviceVector>,
    home_queries: Vec<QueryVector>,
    hkr_params: Vec<HkrVector>,
}

#[derive(Debug, Deserialize)]
struct DeviceVector {
    xml: String,
    devices: Vec<DeviceExpected>,
    groups: Vec<GroupExpected>,
    names_and_ains: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct DeviceExpected {
    identifier: String,
    id: String,
    name: String,
    present: i32,
    #[serde(rename = "switch")]
    switch_state: String,
    celsius: String,
    tist: String,
    tsoll: String,
    batterylow: String,
    battery: String,
    windowopenactiv: String,
    errorcode: String,
    nextchange: symfritz_aha::NextChange,
    power: String,
    energy: String,
}

#[derive(Debug, Deserialize)]
struct GroupExpected {
    identifier: String,
    id: String,
    name: String,
    members: Vec<String>,
    master_device_id: String,
}

#[derive(Debug, Deserialize)]
struct QueryVector {
    sid: String,
    switchcmd: String,
    params: BTreeMap<String, Vec<String>>,
    url: String,
}

#[derive(Debug, Deserialize)]
struct HkrVector {
    temp_celsius: f64,
    param: String,
}

#[derive(Clone, Copy, Debug, Default)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

struct FixtureTransport {
    responses: VecDeque<Response>,
    requests: Vec<Request>,
}

impl Transport for FixtureTransport {
    fn send(&mut self, request: Request) -> Result<Response, TransportError> {
        self.requests.push(request);
        self.responses
            .pop_front()
            .ok_or_else(|| TransportError("fixture exhausted".to_owned()))
    }
}

fn fixture() -> Fixture {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/port/aha/contracts.json");
    let bytes = fs::read(path).expect("read Go AHA fixture");
    serde_json::from_slice(&bytes).expect("parse Go AHA fixture")
}

fn login(sid: &str) -> Response {
    Response {
        status: 200,
        body: format!(
            "<SessionInfo><SID>{sid}</SID><Challenge>x</Challenge><BlockTime>0</BlockTime></SessionInfo>"
        )
        .into_bytes(),
        ..Response::default()
    }
}

#[test]
fn fixture_metadata_is_current() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.oracle,
        "Go internal/fritz AHA Home and Homeauto contracts"
    );
    let expected = BTreeMap::from([
        ("0".to_owned(), "no error".to_owned()),
        ("1".to_owned(), "no connection to actuator".to_owned()),
        ("2".to_owned(), "valve stroke too large".to_owned()),
        ("3".to_owned(), "valve stroke too small".to_owned()),
        (
            "4".to_owned(),
            "installation not ready / check mounting".to_owned(),
        ),
        (
            "5".to_owned(),
            "valve travel too short (sluggish?) / descale".to_owned(),
        ),
        ("6".to_owned(), "battery charge extremely low".to_owned()),
    ]);
    assert_eq!(fixture.hkr_error_descriptions, expected);
    assert_eq!(
        symfritz_aha::HKR_ERROR_DESCRIPTIONS
            .iter()
            .copied()
            .collect::<BTreeMap<_, _>>(),
        expected
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect()
    );
    for (code, description) in &expected {
        assert_eq!(
            symfritz_aha::hkr_error_description(code),
            Some(description.as_str())
        );
    }
}

#[test]
fn device_parsing_matches_go_production_fixture() {
    let vector = &fixture().device_xml[0];
    let list = parse_device_list(vector.xml.as_bytes()).unwrap();
    let device = &list.devices[0];
    let expected = &vector.devices[0];
    assert_eq!(device.identifier, expected.identifier);
    assert_eq!(device.id, expected.id);
    assert_eq!(device.name, expected.name);
    assert_eq!(device.present, expected.present);
    assert_eq!(device.switch.state, expected.switch_state);
    assert_eq!(device.temperature.celsius, expected.celsius);
    assert_eq!(device.hkr.tist, expected.tist);
    assert_eq!(device.hkr.tsoll, expected.tsoll);
    assert_eq!(device.hkr.batterylow, expected.batterylow);
    assert_eq!(device.hkr.battery, expected.battery);
    assert_eq!(device.hkr.windowopenactiv, expected.windowopenactiv);
    assert_eq!(device.hkr.errorcode, expected.errorcode);
    assert_eq!(device.hkr.nextchange, expected.nextchange);
    assert_eq!(device.powermeter.power, expected.power);
    assert_eq!(device.powermeter.energy, expected.energy);
    let group = &list.groups[0];
    let expected_group = &vector.groups[0];
    assert_eq!(group.identifier, expected_group.identifier);
    assert_eq!(group.id, expected_group.id);
    assert_eq!(group.name, expected_group.name);
    assert_eq!(group.members, expected_group.members);
    assert_eq!(group.master_device_id, expected_group.master_device_id);
    assert_eq!(list.names_and_ains(), vector.names_and_ains);
}

#[test]
fn home_queries_match_go_url_values_byte_for_byte() {
    for vector in fixture().home_queries {
        let transport = FixtureTransport {
            responses: VecDeque::from([
                login(&vector.sid),
                Response {
                    status: 200,
                    body: b"OK".to_vec(),
                    ..Response::default()
                },
            ]),
            requests: Vec::new(),
        };
        let mut client = Client::new(transport, FixedClock, "http://fritz.box", "admin", "secret");
        client.home(&vector.switchcmd, &vector.params).unwrap();
        assert_eq!(client.transport_mut().requests[1].url, vector.url);
    }
}

#[test]
fn hkr_temperature_mapping_matches_go_helpers() {
    for vector in fixture().hkr_params {
        let transport = FixtureTransport {
            responses: VecDeque::from([
                login("sid"),
                Response {
                    status: 200,
                    body: b"OK".to_vec(),
                    ..Response::default()
                },
            ]),
            requests: Vec::new(),
        };
        let mut client = Client::new(transport, FixedClock, "http://fritz.box", "admin", "secret");
        client.set_hkr_temp("ain", vector.temp_celsius).unwrap();
        assert!(
            client.transport_mut().requests[1]
                .url
                .contains(&format!("param={}", vector.param))
        );
    }
}
