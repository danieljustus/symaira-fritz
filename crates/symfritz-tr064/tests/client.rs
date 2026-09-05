#![deny(unsafe_code)]

use std::collections::{BTreeMap, VecDeque};

use symfritz_tr064::{
    Client, ClientError, CnonceSource, Method, Request, Response, Service, Transport,
    TransportError,
};

#[derive(Default)]
struct FakeTransport {
    responses: VecDeque<Response>,
    requests: Vec<Request>,
}

impl FakeTransport {
    fn with_responses(responses: impl IntoIterator<Item = Response>) -> Self {
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

fn success_body() -> Vec<u8> {
    br#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetInfoResponse xmlns:u="urn:dslforum-org:service:DeviceInfo:1"><NewModelName>FRITZ!Box 7590 AX</NewModelName></u:GetInfoResponse></s:Body></s:Envelope>"#.to_vec()
}

#[test]
fn digest_handshake_and_cached_reuse_match_request_contract() {
    let challenge = Response {
        status: 401,
        headers: BTreeMap::from([(
            "WWW-Authenticate".to_owned(),
            "Digest realm=\"F!Box\", nonce=\"abc123\", qop=\"auth\"".to_owned(),
        )]),
        body: Vec::new(),
    };
    let success = Response {
        status: 200,
        body: success_body(),
        ..Response::default()
    };
    let transport = FakeTransport::with_responses([challenge, success.clone(), success]);
    let cnonces = SequenceCnonce(VecDeque::from([
        "0011223344556677".to_owned(),
        "8899aabbccddeeff".to_owned(),
    ]));
    let mut client = Client::new(transport, cnonces, "http://fritz.box:49000", "user", "pass");
    let service = Service {
        service_type: "urn:dslforum-org:service:DeviceInfo:1".to_owned(),
        control_url: "/upnp/control/deviceinfo".to_owned(),
    };

    let first = client.call(&service, "GetInfo", &BTreeMap::new()).unwrap();
    assert_eq!(first["NewModelName"], "FRITZ!Box 7590 AX");
    client.call(&service, "GetInfo", &BTreeMap::new()).unwrap();

    let transport = client.into_transport();
    assert_eq!(transport.requests.len(), 3);
    assert_eq!(transport.requests[0].method, Method::Post);
    assert_eq!(
        transport.requests[0].url,
        "http://fritz.box:49000/upnp/control/deviceinfo"
    );
    assert_eq!(
        transport.requests[0].headers["Content-Type"],
        "text/xml; charset=\"utf-8\""
    );
    assert_eq!(
        transport.requests[0].headers["SoapAction"],
        "urn:dslforum-org:service:DeviceInfo:1#GetInfo"
    );
    assert!(!transport.requests[0].headers.contains_key("Authorization"));
    let first_auth = &transport.requests[1].headers["Authorization"];
    assert!(first_auth.contains("nc=00000001"));
    assert!(first_auth.contains("cnonce=\"0011223344556677\""));
    let cached_auth = &transport.requests[2].headers["Authorization"];
    assert!(cached_auth.contains("nc=00000002"));
    assert!(cached_auth.contains("cnonce=\"8899aabbccddeeff\""));
    assert_eq!(transport.requests[0].body, transport.requests[1].body);
    assert_eq!(transport.requests[1].body, transport.requests[2].body);
    assert_eq!(transport.requests[0].response_limit, 1 << 20);
}

#[test]
fn cnonce_failure_stops_before_authenticated_retry() {
    let transport = FakeTransport::with_responses([Response {
        status: 401,
        headers: BTreeMap::from([(
            "WWW-Authenticate".to_owned(),
            "Digest realm=\"F!Box\", nonce=\"abc123\", qop=\"auth\"".to_owned(),
        )]),
        body: Vec::new(),
    }]);
    let mut client = Client::new(
        transport,
        SequenceCnonce(VecDeque::new()),
        "http://fritz.box:49000",
        "user",
        "pass",
    );
    let service = Service {
        service_type: "urn:test:service:Thing:1".to_owned(),
        control_url: "/thing".to_owned(),
    };
    assert_eq!(
        client.call(&service, "Run", &BTreeMap::new()),
        Err(ClientError::Call {
            service: "Thing".to_owned(),
            action: "Run".to_owned(),
            source: Box::new(ClientError::Cnonce("no cnonce queued".to_owned())),
        })
    );
    assert_eq!(client.into_transport().requests.len(), 1);
}

#[test]
fn invalid_digest_challenge_fails_without_retry() {
    let transport = FakeTransport::with_responses([Response {
        status: 401,
        headers: BTreeMap::new(),
        body: Vec::new(),
    }]);
    let mut client = Client::new(
        transport,
        SequenceCnonce(VecDeque::new()),
        "http://fritz.box:49000",
        "user",
        "pass",
    );
    let service = Service {
        service_type: "urn:test:service:Thing:1".to_owned(),
        control_url: "/thing".to_owned(),
    };
    assert_eq!(
        client.call(&service, "Run", &BTreeMap::new()),
        Err(ClientError::Call {
            service: "Thing".to_owned(),
            action: "Run".to_owned(),
            source: Box::new(ClientError::UnauthorizedChallenge),
        })
    );
    assert_eq!(client.into_transport().requests.len(), 1);
}

#[test]
fn soap_fault_preserves_status_code_and_description() {
    let transport = FakeTransport::with_responses([Response {
        status: 500,
        body: br#"<s:Fault><detail><UPnPError><errorCode>606</errorCode><errorDescription>Not authorized</errorDescription></UPnPError></detail></s:Fault>"#.to_vec(),
        ..Response::default()
    }]);
    let mut client = Client::new(
        transport,
        SequenceCnonce(VecDeque::new()),
        "http://fritz.box:49000",
        "",
        "",
    );
    let service = Service {
        service_type: "urn:test:service:Thing:1".to_owned(),
        control_url: "/thing".to_owned(),
    };
    assert_eq!(
        client.call(&service, "Run", &BTreeMap::new()),
        Err(ClientError::Call {
            service: "Thing".to_owned(),
            action: "Run".to_owned(),
            source: Box::new(ClientError::SoapFault {
                service: "Thing".to_owned(),
                action: "Run".to_owned(),
                status: 500,
                code: 606,
                description: "Not authorized".to_owned(),
            }),
        })
    );
}

#[test]
fn discovery_is_cached_and_refresh_refetches() {
    let first = br#"<root><device><serviceList><service><serviceType>urn:test:service:Zulu:1</serviceType><controlURL>/zulu</controlURL></service></serviceList></device></root>"#.to_vec();
    let second = br#"<root><device><serviceList><service><serviceType>urn:test:service:Alpha:1</serviceType><controlURL>/alpha</controlURL></service></serviceList></device></root>"#.to_vec();
    let transport = FakeTransport::with_responses([
        Response {
            status: 200,
            body: first,
            ..Response::default()
        },
        Response {
            status: 200,
            body: second,
            ..Response::default()
        },
    ]);
    let mut client = Client::new(
        transport,
        SequenceCnonce(VecDeque::new()),
        "http://fritz.box:49000/",
        "",
        "",
    );

    assert_eq!(client.discover().unwrap()[0].control_url, "/zulu");
    assert_eq!(client.service_by_name("Zulu").unwrap().control_url, "/zulu");
    assert_eq!(client.discover().unwrap()[0].control_url, "/zulu");
    assert_eq!(client.refresh_discovery().unwrap()[0].control_url, "/alpha");

    let transport = client.into_transport();
    assert_eq!(transport.requests.len(), 2);
    for request in transport.requests {
        assert_eq!(request.method, Method::Get);
        assert_eq!(request.url, "http://fritz.box:49000/tr64desc.xml");
        assert_eq!(request.response_limit, 4 << 20);
    }
}

#[test]
fn discovery_http_status_matches_go_error_context() {
    let transport = FakeTransport::with_responses([Response {
        status: 502,
        ..Response::default()
    }]);
    let mut client = Client::new(
        transport,
        SequenceCnonce(VecDeque::new()),
        "http://fritz.box:49000",
        "",
        "",
    );
    let error = client.discover().unwrap_err();
    assert_eq!(error, ClientError::DiscoveryHttpStatus(502));
    assert_eq!(
        error.to_string(),
        "discover: tr64desc.xml returned HTTP 502"
    );
}

#[test]
fn oversized_response_is_truncated_like_go_limit_reader() {
    let mut body = success_body();
    body.resize(1 << 20, b' ');
    body.extend_from_slice(b"ignored suffix");
    let transport = FakeTransport::with_responses([Response {
        status: 200,
        body,
        ..Response::default()
    }]);
    let mut client = Client::new(
        transport,
        SequenceCnonce(VecDeque::new()),
        "http://fritz.box:49000",
        "",
        "",
    );
    let result = client
        .call(
            &Service {
                service_type: "urn:test:service:Thing:1".to_owned(),
                control_url: "/thing".to_owned(),
            },
            "GetInfo",
            &BTreeMap::new(),
        )
        .unwrap();
    assert_eq!(result["NewModelName"], "FRITZ!Box 7590 AX");
}

#[test]
fn oversized_discovery_is_truncated_like_go_limit_reader() {
    let mut body = br#"<root><device><serviceList><service><serviceType>urn:test:service:Info:1</serviceType><controlURL>/info</controlURL></service></serviceList></device></root>"#.to_vec();
    body.resize(4 << 20, b' ');
    body.extend_from_slice(b"ignored suffix");
    let transport = FakeTransport::with_responses([Response {
        status: 200,
        body,
        ..Response::default()
    }]);
    let mut client = Client::new(
        transport,
        SequenceCnonce(VecDeque::new()),
        "http://fritz.box:49000",
        "",
        "",
    );
    let services = client.discover().unwrap();
    assert_eq!(services[0].control_url, "/info");
}
