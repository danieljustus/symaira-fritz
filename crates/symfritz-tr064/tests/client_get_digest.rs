#![deny(unsafe_code)]

use std::collections::{BTreeMap, VecDeque};

use symfritz_tr064::{
    CALL_ALL, Client, CnonceSource, Method, Request, Response, Transport, TransportError,
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

struct SequenceCnonce(VecDeque<String>);

impl CnonceSource for SequenceCnonce {
    fn next_cnonce(&mut self) -> Result<String, String> {
        self.0
            .pop_front()
            .ok_or_else(|| "no cnonce queued".to_owned())
    }
}

fn soap_path() -> Response {
    Response {
        status: 200,
        body: br#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetCallListResponse><NewCallListURL>/calls.xml?sid=session</NewCallListURL></u:GetCallListResponse></s:Body></s:Envelope>"#.to_vec(),
        ..Response::default()
    }
}

#[test]
fn authenticated_get_retries_with_get_uri_digest_and_preserves_query_arguments() {
    let challenge = Response {
        status: 401,
        headers: BTreeMap::from([(
            "www-authenticate".to_owned(),
            "Digest realm=\"F!Box\", nonce=\"get-nonce\", qop=\"auth\"".to_owned(),
        )]),
        body: Vec::new(),
    };
    let list = Response {
        status: 200,
        body: b"<root><Call><Type>1</Type><Caller>100</Caller><Called>200</Called><Name></Name><Date>29.06.26 14:15</Date><Duration>0:15</Duration></Call></root>".to_vec(),
        ..Response::default()
    };
    let transport = FakeTransport::new([soap_path(), challenge, list]);
    let cnonces = SequenceCnonce(VecDeque::from(["0123456789abcdef".to_owned()]));
    let mut client = Client::new(
        transport,
        cnonces,
        "http://fritz.box:49000",
        "admin",
        "secret",
    );

    let calls = client.calls(CALL_ALL, 0, 7).unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].caller_number, "100");
    assert_eq!(calls[0].date, "2026-06-29T14:15:00");

    let transport = client.into_transport();
    assert_eq!(transport.requests.len(), 3);
    assert_eq!(transport.requests[1].method, Method::Get);
    assert_eq!(
        transport.requests[1].url,
        "http://fritz.box:49000/calls.xml?days=7&sid=session"
    );
    assert!(!transport.requests[1].headers.contains_key("Authorization"));
    let authenticated = &transport.requests[2];
    assert_eq!(authenticated.method, Method::Get);
    assert_eq!(authenticated.url, transport.requests[1].url);
    let authorization = &authenticated.headers["Authorization"];
    assert!(authorization.contains("uri=\"/calls.xml?days=7&sid=session\""));
    assert!(authorization.contains("nc=00000001"));
    assert!(authorization.contains("cnonce=\"0123456789abcdef\""));
    assert!(authenticated.body.is_empty());
    assert_eq!(authenticated.response_limit, 1 << 20);
}
