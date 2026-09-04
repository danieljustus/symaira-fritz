#![deny(unsafe_code)]

use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    path::PathBuf,
    time::Instant,
};

use serde::Deserialize;
use symfritz_aha::{
    Client, Clock, Method, Request, Response, Transport, TransportError, parse_session_info,
};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: String,
    session_xml: Vec<SessionXmlVector>,
    data_forms: Vec<DataFormVector>,
}

#[derive(Debug, Deserialize)]
struct SessionXmlVector {
    id: String,
    xml: String,
    #[serde(default)]
    sid: String,
    #[serde(default)]
    challenge: String,
    #[serde(default)]
    block_time: i64,
    #[serde(default)]
    error: String,
}

#[derive(Debug, Deserialize)]
struct DataFormVector {
    id: String,
    page: String,
    sid: String,
    params: BTreeMap<String, Vec<String>>,
    body: String,
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
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/port/session-data/contracts.json");
    let bytes = fs::read(path).expect("read Go session/data fixture");
    serde_json::from_slice(&bytes).expect("parse Go session/data fixture")
}

#[test]
fn fixture_metadata_is_current() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.oracle,
        "Go internal/fritz session and scrape contracts"
    );
}

#[test]
fn session_xml_matches_go_fixture_contracts() {
    for vector in fixture().session_xml {
        let actual = parse_session_info(vector.xml.as_bytes());
        if vector.error.is_empty() {
            let actual = actual.unwrap_or_else(|error| panic!("{}: {error}", vector.id));
            assert_eq!(actual.sid, vector.sid, "{} sid", vector.id);
            assert_eq!(
                actual.challenge, vector.challenge,
                "{} challenge",
                vector.id
            );
            assert_eq!(
                actual.block_time, vector.block_time,
                "{} block time",
                vector.id
            );
        } else {
            assert!(actual.is_err(), "{}: expected parse error", vector.id);
        }
    }
}

#[test]
fn data_forms_match_go_url_values_byte_for_byte() {
    for vector in fixture().data_forms {
        let transport = FixtureTransport {
            responses: VecDeque::from([
                Response {
                    status: 200,
                    headers: BTreeMap::new(),
                    body: format!(
                        "<SessionInfo><SID>{}</SID><Challenge>x</Challenge></SessionInfo>",
                        vector.sid
                    )
                    .into_bytes(),
                },
                Response {
                    status: 200,
                    headers: BTreeMap::new(),
                    body: b"{}".to_vec(),
                },
            ]),
            requests: Vec::new(),
        };
        let mut client = Client::new(transport, FixedClock, "http://fritz.box", "admin", "secret");
        client
            .data_lua(&vector.page, &vector.params)
            .unwrap_or_else(|error| panic!("{}: {error}", vector.id));
        let request = &client.transport_mut().requests[1];
        assert_eq!(request.method, Method::Post, "{}", vector.id);
        assert_eq!(request.body, vector.body.as_bytes(), "{}", vector.id);
    }
}
