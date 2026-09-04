#![deny(unsafe_code)]

use std::{
    cell::Cell,
    collections::{BTreeMap, VecDeque},
    rc::Rc,
    time::{Duration, Instant},
};

use symfritz_aha::{
    Client, ClientError, Clock, DATA_LUA_RESPONSE_LIMIT, INVALID_SID, LOGIN_RESPONSE_LIMIT, Method,
    Request, Response, Transport, TransportError, parse_session_info,
};

#[derive(Clone)]
struct TestClock(Rc<Cell<Instant>>);

impl TestClock {
    fn new() -> Self {
        Self(Rc::new(Cell::new(Instant::now())))
    }

    fn advance(&self, duration: Duration) {
        self.0.set(self.0.get() + duration);
    }
}

impl Clock for TestClock {
    fn now(&self) -> Instant {
        self.0.get()
    }
}

struct MockTransport {
    requests: Vec<Request>,
    responses: VecDeque<Result<Response, TransportError>>,
}

impl MockTransport {
    fn new(responses: impl IntoIterator<Item = Result<Response, TransportError>>) -> Self {
        Self {
            requests: Vec::new(),
            responses: responses.into_iter().collect(),
        }
    }
}

impl Transport for MockTransport {
    fn send(&mut self, request: Request) -> Result<Response, TransportError> {
        self.requests.push(request);
        self.responses
            .pop_front()
            .expect("test supplied enough responses")
    }
}

fn response(status: u16, body: &str) -> Response {
    Response {
        status,
        headers: BTreeMap::new(),
        body: body.as_bytes().to_vec(),
    }
}

fn response_with_type(status: u16, content_type: &str, body: &str) -> Response {
    Response {
        status,
        headers: BTreeMap::from([("Content-Type".to_owned(), content_type.to_owned())]),
        body: body.as_bytes().to_vec(),
    }
}

fn login(sid: &str) -> Response {
    response(
        200,
        &format!(
            "<SessionInfo><SID>{sid}</SID><Challenge>ignored</Challenge><BlockTime>0</BlockTime></SessionInfo>"
        ),
    )
}

fn challenged(challenge: &str) -> Response {
    response(
        200,
        &format!(
            "<SessionInfo><SID>{INVALID_SID}</SID><Challenge>{challenge}</Challenge><BlockTime>0</BlockTime></SessionInfo>"
        ),
    )
}

fn make_client(
    clock: &TestClock,
    responses: impl IntoIterator<Item = Result<Response, TransportError>>,
) -> Client<MockTransport, TestClock> {
    Client::new(
        MockTransport::new(responses),
        clock.clone(),
        "http://fritz.box",
        "admin",
        "secret",
    )
}

#[test]
fn no_credential_short_circuits_without_transport() {
    let clock = TestClock::new();
    let mut client = Client::new(
        MockTransport::new([]),
        clock,
        "http://fritz.box",
        "admin",
        "  ",
    );
    assert_eq!(client.sid(), Err(ClientError::NoCredential));
    assert!(client.transport_mut().requests.is_empty());
}

#[test]
fn ready_sid_is_cached_until_expiry_then_relogged_in() {
    let clock = TestClock::new();
    let mut client = make_client(&clock, [Ok(login("sid-one")), Ok(login("sid-two"))])
        .with_sid_ttl(Duration::from_secs(30));
    assert_eq!(client.sid().unwrap(), "sid-one");
    assert_eq!(client.sid().unwrap(), "sid-one");
    clock.advance(Duration::from_secs(30));
    assert_eq!(client.sid().unwrap(), "sid-two");
    assert_eq!(client.transport_mut().requests.len(), 2);
}

#[test]
fn legacy_and_pbkdf2_challenges_are_sent_with_sorted_query_fields() {
    let clock = TestClock::new();
    let mut legacy = make_client(
        &clock,
        [Ok(challenged("1234567z")), Ok(login("legacy-sid"))],
    );
    assert_eq!(legacy.sid().unwrap(), "legacy-sid");
    let requests = &legacy.transport_mut().requests;
    assert!(requests[0].url.ends_with("/login_sid.lua?version=2"));
    assert!(requests[1].url.contains("response=1234567z-"));
    assert!(requests[1].url.contains("username=admin"));
    assert!(
        requests[1].url.find("response=").unwrap() < requests[1].url.find("username=").unwrap()
    );

    let mut modern = make_client(
        &clock,
        [Ok(challenged("2$2$0a0b$3$0c0d")), Ok(login("modern-sid"))],
    );
    assert_eq!(modern.sid().unwrap(), "modern-sid");
    assert!(
        modern.transport_mut().requests[1]
            .url
            .contains("response=0c0d%24")
    );
}

#[test]
fn invalid_sid_and_block_time_are_distinct_errors() {
    let clock = TestClock::new();
    let invalid = response(
        200,
        &format!(
            "<SessionInfo><SID>{INVALID_SID}</SID><Challenge>x</Challenge><BlockTime>0</BlockTime></SessionInfo>"
        ),
    );
    let mut client = make_client(&clock, [Ok(invalid), Ok(login(INVALID_SID))]);
    assert_eq!(client.sid(), Err(ClientError::InvalidCredentials));

    let blocked = response(
        200,
        &format!(
            "<SessionInfo><SID>{INVALID_SID}</SID><Challenge>x</Challenge><BlockTime>42</BlockTime></SessionInfo>"
        ),
    );
    let mut client = make_client(&clock, [Ok(challenged("x")), Ok(blocked)]);
    assert_eq!(client.sid(), Err(ClientError::RateLimited(42)));
}

#[test]
fn login_xml_is_bounded_and_malformed_input_is_rejected() {
    assert_eq!(
        parse_session_info(b"<SessionInfo><SID>sid</SID><Challenge>x</Challenge></SessionInfo>")
            .unwrap()
            .block_time,
        0
    );
    assert!(matches!(
        parse_session_info(b"<SessionInfo><SID>oops"),
        Err(ClientError::MalformedLoginXml(_))
    ));
    assert!(matches!(
        parse_session_info(b"<Other><SID>sid</SID></Other>"),
        Err(ClientError::MalformedLoginXml(_))
    ));
    assert!(matches!(
        parse_session_info(&vec![b'x'; LOGIN_RESPONSE_LIMIT + 1]),
        Err(ClientError::ResponseTooLarge { .. })
    ));
}

#[test]
fn login_non_success_and_transport_errors_are_preserved() {
    let clock = TestClock::new();
    let mut status = make_client(&clock, [Ok(response(500, "error"))]);
    assert_eq!(status.sid(), Err(ClientError::LoginHttpStatus(500)));

    let mut transport = make_client(
        &clock,
        [Err(TransportError("connection refused".to_owned()))],
    );
    assert!(
        matches!(transport.sid(), Err(ClientError::Transport(message)) if message.contains("connection refused"))
    );
}

#[test]
fn data_lua_posts_exact_form_and_preserves_valid_json() {
    let clock = TestClock::new();
    let mut params = BTreeMap::new();
    params.insert("z".to_owned(), vec!["one".to_owned(), "two".to_owned()]);
    params.insert("a".to_owned(), vec!["x&y".to_owned()]);
    let mut client = make_client(
        &clock,
        [
            Ok(login("sid+value")),
            Ok(response_with_type(
                200,
                "application/json",
                " {\"data\":[]}\n",
            )),
        ],
    );
    assert_eq!(
        client.data_lua("a page", &params).unwrap(),
        " {\"data\":[]}\n"
    );
    let request = &client.transport_mut().requests[1];
    assert_eq!(request.method, Method::Post);
    assert_eq!(request.url, "http://fritz.box/data.lua");
    assert_eq!(
        request.headers.get("Content-Type").unwrap(),
        "application/x-www-form-urlencoded"
    );
    assert_eq!(
        String::from_utf8_lossy(&request.body),
        "a=x%26y&page=a+page&sid=sid%2Bvalue&z=one&z=two"
    );
    assert_eq!(request.response_limit, DATA_LUA_RESPONSE_LIMIT);
}

#[test]
fn data_lua_validates_status_json_and_html_login_responses() {
    let clock = TestClock::new();
    let mut status = make_client(&clock, [Ok(login("sid")), Ok(response(500, "error"))]);
    assert_eq!(
        status.data_lua("overview", &BTreeMap::new()),
        Err(ClientError::DataLuaHttpStatus(500))
    );

    let mut html = make_client(
        &clock,
        [
            Ok(login("sid")),
            Ok(response_with_type(
                200,
                "text/html; charset=utf-8",
                "<html>login</html>",
            )),
        ],
    );
    assert_eq!(
        html.data_lua("overview", &BTreeMap::new()),
        Err(ClientError::HtmlLoginPage)
    );

    let mut plain = make_client(
        &clock,
        [
            Ok(login("sid")),
            Ok(response_with_type(200, "text/plain", "offline")),
        ],
    );
    assert_eq!(
        plain.data_lua("overview", &BTreeMap::new()),
        Err(ClientError::NonJsonResponse {
            content_type: "text/plain".to_owned()
        })
    );
}

#[test]
fn data_lua_rejects_unbounded_body() {
    let clock = TestClock::new();
    let oversized = Response {
        status: 200,
        headers: BTreeMap::new(),
        body: vec![b'0'; DATA_LUA_RESPONSE_LIMIT + 1],
    };
    let mut client = make_client(&clock, [Ok(login("sid")), Ok(oversized)]);
    assert!(matches!(
        client.data_lua("overview", &BTreeMap::new()),
        Err(ClientError::ResponseTooLarge {
            endpoint: "data.lua",
            ..
        })
    ));
}

#[test]
fn data_lua_does_not_retry_or_invalidate_on_403() {
    let clock = TestClock::new();
    let mut client = make_client(&clock, [Ok(login("old-sid")), Ok(response(403, ""))]);
    assert_eq!(
        client.data_lua("overview", &BTreeMap::new()),
        Err(ClientError::DataLuaHttpStatus(403))
    );
    // The Go scraper has no 403 relogin behavior; the cached SID remains valid.
    assert_eq!(client.transport_mut().requests.len(), 2);
    assert_eq!(client.cached_sid(), Some("old-sid"));
}
