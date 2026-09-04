#![deny(unsafe_code)]

use std::collections::VecDeque;

use symfritz_aha::{Client, Clock, Method, Request, Response, Transport, TransportError};
use symfritz_tr064::{
    Client as Tr064Client, CnonceSource, Response as Tr064Response, Transport as Tr064Transport,
    TransportError as Tr064TransportError,
};

#[derive(Clone, Copy, Debug, Default)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
}

#[derive(Default)]
struct FakeAhaTransport {
    responses: VecDeque<Result<Response, TransportError>>,
    requests: Vec<Request>,
}

impl FakeAhaTransport {
    fn new(responses: impl IntoIterator<Item = Result<Response, TransportError>>) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }
}

impl Transport for FakeAhaTransport {
    fn send(&mut self, request: Request) -> Result<Response, TransportError> {
        self.requests.push(request);
        self.responses
            .pop_front()
            .expect("test supplied enough AHA responses")
    }
}

#[derive(Default)]
struct FakeTr064Transport {
    responses: VecDeque<Result<Tr064Response, Tr064TransportError>>,
    requests: Vec<symfritz_tr064::Request>,
}

impl FakeTr064Transport {
    fn new(
        responses: impl IntoIterator<Item = Result<Tr064Response, Tr064TransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }
}

impl Tr064Transport for FakeTr064Transport {
    fn send(
        &mut self,
        request: symfritz_tr064::Request,
    ) -> Result<Tr064Response, Tr064TransportError> {
        self.requests.push(request);
        self.responses
            .pop_front()
            .expect("test supplied enough TR-064 responses")
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct NoCnonce;

impl CnonceSource for NoCnonce {
    fn next_cnonce(&mut self) -> Result<String, String> {
        Err("cnonce not expected".to_owned())
    }
}

fn soap_path(path: &str) -> Tr064Response {
    let body = format!(
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:X_AVM-DE_GetMeshListPathResponse><NewX_AVM-DE_MeshListPath>{path}</NewX_AVM-DE_MeshListPath></u:X_AVM-DE_GetMeshListPathResponse></s:Body></s:Envelope>"
    );
    Tr064Response {
        status: 200,
        body: body.into_bytes(),
        ..Tr064Response::default()
    }
}

fn tr_response(status: u16, body: &[u8]) -> Tr064Response {
    Tr064Response {
        status,
        body: body.to_vec(),
        ..Tr064Response::default()
    }
}

fn aha_response(status: u16, body: &[u8]) -> Response {
    Response {
        status,
        body: body.to_vec(),
        ..Response::default()
    }
}

fn topology_json() -> &'static [u8] {
    br#"{"schema_version":"1.0","nodes":[]}"#
}

fn clients(
    tr_responses: impl IntoIterator<Item = Result<Tr064Response, Tr064TransportError>>,
    aha_responses: impl IntoIterator<Item = Result<Response, TransportError>>,
) -> (
    Tr064Client<FakeTr064Transport, NoCnonce>,
    Client<FakeAhaTransport, FixedClock>,
) {
    (
        Tr064Client::new(
            FakeTr064Transport::new(tr_responses),
            NoCnonce,
            "http://tr064.box:49000",
            "",
            "",
        ),
        Client::new(
            FakeAhaTransport::new(aha_responses),
            FixedClock,
            "http://web.box",
            "",
            "",
        ),
    )
}

#[test]
fn mesh_appends_sid_and_falls_back_from_tr064_to_web() {
    let (mut tr064, mut aha) = clients(
        [Ok(soap_path("/mesh.json")), Ok(tr_response(500, b"no"))],
        [Ok(aha_response(200, topology_json()))],
    );
    aha.set_cached_sid("mesh-sid");

    let topology = aha.mesh_topology(&mut tr064).unwrap();
    assert!(topology.nodes.is_empty());
    let tr_request = &tr064.into_transport().requests[1];
    assert_eq!(tr_request.method, symfritz_tr064::Method::Get);
    assert_eq!(
        tr_request.url,
        "http://tr064.box:49000/mesh.json?sid=mesh-sid"
    );
    assert!(tr_request.headers.is_empty());
    let aha_request = &aha.into_transport().requests[0];
    assert_eq!(aha_request.method, Method::Get);
    assert_eq!(aha_request.url, "http://web.box/mesh.json?sid=mesh-sid");
    assert!(aha_request.headers.is_empty());
}

#[test]
fn mesh_preserves_preexisting_sid_without_login() {
    let (mut tr064, mut aha) = clients(
        [
            Ok(soap_path("/mesh.json?sid=already-there")),
            Ok(tr_response(200, topology_json())),
        ],
        [],
    );

    aha.mesh_topology(&mut tr064).unwrap();
    let transport = tr064.into_transport();
    assert_eq!(transport.requests.len(), 2);
    assert_eq!(
        transport.requests[1].url,
        "http://tr064.box:49000/mesh.json?sid=already-there"
    );
}

#[test]
fn mesh_absolute_url_is_the_sole_candidate() {
    let (mut tr064, mut aha) = clients(
        [Ok(soap_path("http://web.box/mesh.json?sid=absolute"))],
        [Ok(aha_response(200, topology_json()))],
    );

    aha.mesh_topology(&mut tr064).unwrap();
    assert_eq!(tr064.into_transport().requests.len(), 1);
    let request = &aha.into_transport().requests[0];
    assert_eq!(request.url, "http://web.box/mesh.json?sid=absolute");
}

#[test]
fn mesh_without_candidate_returns_before_any_json_fetch() {
    let (mut tr064, mut aha) = clients([Ok(soap_path(""))], []);

    let error = aha.mesh_topology(&mut tr064).unwrap_err().to_string();
    assert!(error.contains("no mesh list path"));
    assert!(tr064.into_transport().requests.len() == 1);
}

#[test]
fn mesh_is_bounded_to_8_mib_and_errors_redact_sid() {
    let mut body = topology_json().to_vec();
    body.resize(symfritz_tr064::MESH_RESPONSE_LIMIT + 100, b' ');
    let (mut tr064, mut aha) = clients(
        [
            Ok(soap_path("/mesh.json")),
            Err(Tr064TransportError("tr sid=tr-secret".to_owned())),
        ],
        [Err(TransportError("web sid=web-secret".to_owned()))],
    );
    aha.set_cached_sid("secret-sid");

    let error = aha.mesh_topology(&mut tr064).unwrap_err().to_string();
    assert!(!error.contains("secret-sid"));
    assert!(!error.contains("tr-secret"));
    assert!(!error.contains("web-secret"));
    assert!(error.contains("sid=REDACTED"));

    let (mut tr064, mut aha) = clients(
        [Ok(soap_path("/mesh.json")), Ok(tr_response(500, b"no"))],
        [Ok(aha_response(200, &body))],
    );
    aha.set_cached_sid("mesh-sid");
    aha.mesh_topology(&mut tr064).unwrap();
    assert_eq!(
        aha.into_transport().requests[0].response_limit,
        symfritz_tr064::MESH_RESPONSE_LIMIT
    );
}
