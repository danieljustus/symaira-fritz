#![deny(unsafe_code)]

use std::collections::VecDeque;

use symfritz_tr064::{
    CALL_ALL, Client, CnonceSource, Method, Request, Response, Transport, TransportError,
};

#[derive(Default)]
struct ScriptedTransport {
    steps: VecDeque<Result<Response, TransportError>>,
    requests: Vec<Request>,
}

impl ScriptedTransport {
    fn new(steps: impl IntoIterator<Item = Result<Response, TransportError>>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            requests: Vec::new(),
        }
    }
}

impl Transport for ScriptedTransport {
    fn send(&mut self, request: Request) -> Result<Response, TransportError> {
        self.requests.push(request);
        self.steps
            .pop_front()
            .unwrap_or_else(|| Err(TransportError("no scripted response".to_owned())))
    }
}

#[derive(Default)]
struct NoCnonce;
impl CnonceSource for NoCnonce {
    fn next_cnonce(&mut self) -> Result<String, String> {
        Err("no cnonce configured".to_owned())
    }
}

fn call_list_path() -> Response {
    Response {
        status: 200,
        body: br#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetCallListResponse><NewCallListURL>/calls.xml?sid=private-session</NewCallListURL></u:GetCallListResponse></s:Body></s:Envelope>"#.to_vec(),
        ..Response::default()
    }
}

fn success_calls() -> Response {
    Response {
        status: 200,
        body: b"<root></root>".to_vec(),
        ..Response::default()
    }
}

fn call_client(
    base: &str,
    steps: impl IntoIterator<Item = Result<Response, TransportError>>,
) -> Client<ScriptedTransport, NoCnonce> {
    Client::new(ScriptedTransport::new(steps), NoCnonce, base, "", "")
}

#[test]
fn malformed_get_url_fails_before_dispatch_and_discovery_errors_are_typed() {
    let mut client = call_client("not a valid base", [Ok(call_list_path())]);
    let error = client.calls(CALL_ALL, 0, 0).unwrap_err();
    assert!(error.to_string().contains("relative URL without a base"));
    assert_eq!(client.into_transport().requests.len(), 1);

    let mut host_fallback = call_client(
        "not a valid base",
        [
            Ok(Response {
                status: 200,
                body: br#"<s:Envelope><s:Body><u:X_AVM-DE_GetHostListPathResponse><NewX_AVM-DE_HostListPath>/hosts.xml</NewX_AVM-DE_HostListPath></u:X_AVM-DE_GetHostListPathResponse></s:Body></s:Envelope>"#.to_vec(),
                ..Response::default()
            }),
            Ok(Response {
                status: 200,
                body: br#"<s:Envelope><s:Body><u:GetHostNumberOfEntriesResponse><NewHostNumberOfEntries>0</NewHostNumberOfEntries></u:GetHostNumberOfEntriesResponse></s:Body></s:Envelope>"#.to_vec(),
                ..Response::default()
            }),
        ],
    );
    assert!(host_fallback.hosts().unwrap().is_empty());
    let requests = host_fallback.into_transport().requests;
    assert_eq!(
        requests.len(),
        2,
        "an invalid bulk URL must fail before GET dispatch"
    );
    assert!(
        requests
            .iter()
            .all(|request| request.method == Method::Post)
    );

    let mut discovery_client = Client::new(
        ScriptedTransport::new([Err(TransportError("socket failed".to_owned()))]),
        NoCnonce,
        "http://fritz.box:49000",
        "",
        "",
    );
    let error = discovery_client.discover().unwrap_err();
    assert!(
        matches!(error, symfritz_tr064::ClientError::Transport(ref message) if message == "socket failed")
    );
    assert_eq!(discovery_client.into_transport().requests.len(), 1);

    let mut client = call_client(
        "http://fritz.box:49000",
        [Ok(Response {
            status: 200,
            body: b"<root>".to_vec(),
            ..Response::default()
        })],
    );
    let error = client.discover().unwrap_err();
    assert!(matches!(error, symfritz_tr064::ClientError::Discovery(_)));
    assert_eq!(
        client.into_transport().requests[0].url,
        "http://fritz.box:49000/tr64desc.xml"
    );
}

#[test]
fn authenticated_get_reports_http_failures_and_redacts_session_values() {
    let mut client = call_client(
        "http://fritz.box:49000",
        [
            Ok(call_list_path()),
            Ok(Response {
                status: 403,
                ..Response::default()
            }),
        ],
    );
    let error = client.calls(CALL_ALL, 0, 0).unwrap_err().to_string();
    assert!(error.contains("returned HTTP 403"));
    assert!(error.contains("sid=REDACTED"));
    assert!(!error.contains("private-session"));
    assert_eq!(client.into_transport().requests.len(), 2);

    let mut client = call_client(
        "http://fritz.box:49000",
        [
            Ok(call_list_path()),
            Err(TransportError(
                "failed http://fritz.box:49000/calls.xml?sid=private-session".to_owned(),
            )),
        ],
    );
    let error = client.calls(CALL_ALL, 0, 0).unwrap_err().to_string();
    assert!(error.contains("sid=REDACTED"));
    assert!(!error.contains("private-session"));
    assert_eq!(client.into_transport().requests[1].method, Method::Get);
}

#[test]
fn get_digest_challenge_without_auth_header_does_not_retry() {
    let mut client = call_client(
        "http://fritz.box:49000",
        [
            Ok(call_list_path()),
            Ok(Response {
                status: 401,
                ..Response::default()
            }),
        ],
    );
    let error = client.calls(CALL_ALL, 0, 0).unwrap_err();
    assert!(matches!(
        error,
        symfritz_tr064::ClientError::UnauthorizedChallenge
    ));
    assert_eq!(client.into_transport().requests.len(), 2);
}

#[test]
fn invalid_configured_origin_refuses_plain_mesh_get_without_dispatch() {
    let mut client = call_client("not a URL", []);
    let error = client
        .fetch_mesh_candidate("http://router.invalid/mesh.json?sid=private")
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("invalid configured TR-064 origin")
    );
    assert_eq!(client.into_transport().requests.len(), 0);
}

#[test]
fn successful_get_fixture_retains_expected_method_and_typed_empty_result() {
    let mut client = call_client(
        "http://fritz.box:49000",
        [Ok(call_list_path()), Ok(success_calls())],
    );
    assert!(client.calls(CALL_ALL, 0, 0).unwrap().is_empty());
    let requests = client.into_transport().requests;
    assert_eq!(requests[1].method, Method::Get);
    assert_eq!(requests[1].response_limit, 1 << 20);
}
