use std::{
    collections::{BTreeMap, VecDeque},
    time::Instant,
};

use symfritz_aha::{
    Client, ClientError, Clock, Method, Request, Response, Transport, TransportError,
    parse_device_list,
};

#[derive(Clone, Copy, Debug, Default)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

struct FakeTransport {
    responses: VecDeque<Result<Response, TransportError>>,
    requests: Vec<Request>,
}

impl FakeTransport {
    fn new(responses: impl IntoIterator<Item = Result<Response, TransportError>>) -> Self {
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
            .expect("test supplied enough responses")
    }
}

fn response(status: u16, body: &str) -> Response {
    Response {
        status,
        body: body.as_bytes().to_vec(),
        ..Response::default()
    }
}

fn login(sid: &str) -> Response {
    response(
        200,
        &format!(
            "<SessionInfo><SID>{sid}</SID><Challenge>x</Challenge><BlockTime>0</BlockTime></SessionInfo>"
        ),
    )
}

fn client(
    responses: impl IntoIterator<Item = Result<Response, TransportError>>,
) -> Client<FakeTransport, FixedClock> {
    Client::new(
        FakeTransport::new(responses),
        FixedClock,
        "http://fritz.box",
        "admin",
        "secret",
    )
}

#[test]
fn home_composes_get_query_and_trims_success() {
    let mut client = client([Ok(login("sid+1")), Ok(response(200, "  OK\n"))]);
    let params = BTreeMap::from([
        ("param".to_owned(), vec!["20".to_owned()]),
        ("ain".to_owned(), vec!["A&B".to_owned()]),
    ]);
    assert_eq!(client.home("sethkrtsoll", &params).unwrap(), "OK");
    let request = &client.transport_mut().requests[1];
    assert_eq!(request.method, Method::Get);
    assert_eq!(request.body, Vec::<u8>::new());
    assert_eq!(request.response_limit, 1 << 20);
    assert_eq!(
        request.url,
        "http://fritz.box/webservices/homeautoswitch.lua?ain=A%26B&param=20&sid=sid%2B1&switchcmd=sethkrtsoll"
    );
}

#[test]
fn home_relogs_in_once_on_403_and_stops_after_second_403() {
    let mut retry = client([
        Ok(login("old")),
        Ok(response(403, "")),
        Ok(login("new")),
        Ok(response(200, "OK")),
    ]);
    assert_eq!(retry.home("getswitchlist", &BTreeMap::new()).unwrap(), "OK");
    assert_eq!(retry.transport_mut().requests.len(), 4);

    let mut forbidden = client([
        Ok(login("old")),
        Ok(response(403, "")),
        Ok(login("new")),
        Ok(response(403, "")),
    ]);
    assert_eq!(
        forbidden.home("getswitchlist", &BTreeMap::new()),
        Err(ClientError::AhaForbiddenAfterRelogin)
    );
    assert_eq!(forbidden.transport_mut().requests.len(), 4);
}

#[test]
fn aha_commands_map_to_exact_switch_and_temperature_parameters() {
    let mut client = client([
        Ok(login("sid")),
        Ok(response(200, "OK")),
        Ok(response(200, "OK")),
        Ok(response(200, "OK")),
        Ok(response(200, "OK")),
    ]);
    client.switch_on("ain-one").unwrap();
    client.switch_off("ain-two").unwrap();
    client.set_hkr_temp("ain-three", 20.5).unwrap();
    client.set_hkr_temp("ain-four", 254.0).unwrap();
    let requests = &client.transport_mut().requests;
    assert!(requests[1].url.contains("switchcmd=setswitchon"));
    assert!(requests[1].url.contains("ain=ain-one"));
    assert!(requests[2].url.contains("switchcmd=setswitchoff"));
    assert!(requests[2].url.contains("ain=ain-two"));
    assert!(requests[3].url.contains("switchcmd=sethkrtsoll"));
    assert!(requests[3].url.contains("param=41"));
    assert!(requests[4].url.contains("ain=ain-four"));
    assert!(requests[4].url.contains("param=254"));
}

#[test]
fn device_xml_maps_fields_and_splits_group_members() {
    let xml = br#"<?xml version="1.0"?>
<devicelist version="1">
  <device identifier="ain-1" id="0"><name>Plug</name><present>1</present>
    <switch><state>1</state></switch><temperature><celsius>235</celsius></temperature>
    <hkr><tist>44</tist><tsoll>42</tsoll><nextchange><end>1</end><start>2</start><tchange>60</tchange></nextchange></hkr>
    <powermeter><power>12</power><energy>34</energy></powermeter>
  </device>
  <group identifier="group-1" id="g"><name>All</name><groupinfo><masterdeviceid>ain-1</masterdeviceid><members>ain-1,ain-2,</members></groupinfo></group>
</devicelist>"#;
    let list = parse_device_list(xml).unwrap();
    assert_eq!(list.devices[0].identifier, "ain-1");
    assert_eq!(list.devices[0].hkr.nextchange.tchange, 60);
    assert_eq!(list.groups[0].members, ["ain-1", "ain-2", ""]);
    assert_eq!(list.names_and_ains()["All"], "group-1");
}

#[test]
fn aha_response_body_is_bounded_like_go_limit_reader() {
    let prefix = b"OK\n";
    let mut body = prefix.to_vec();
    body.resize((1 << 20) + 10, b'x');
    let mut client = client([
        Ok(login("sid")),
        Ok(Response {
            status: 200,
            body,
            ..Response::default()
        }),
    ]);
    let result = client.home("getswitchlist", &BTreeMap::new()).unwrap();
    assert_eq!(result.len(), 1 << 20);
    assert!(result.starts_with("OK\n"));
}
