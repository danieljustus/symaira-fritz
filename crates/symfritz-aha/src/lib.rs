#![deny(unsafe_code)]

//! Session-id and best-effort `data.lua` clients for FRITZ!OS.
//!
//! `data.lua` is an internal web-UI endpoint. AVM changes its request and
//! response shape between FRITZ!OS releases, so this crate deliberately exposes
//! only the bounded raw JSON response and does not model its contents.

use std::{
    collections::BTreeMap,
    error::Error as StdError,
    fmt,
    time::{Duration, Instant},
};

use quick_xml::{Reader, events::Event};
use serde::Deserialize;
use symfritz_core::auth::{ChallengeError, challenge_response};

/// The sentinel returned by `login_sid.lua` when no authenticated SID exists.
pub const INVALID_SID: &str = "0000000000000000";
/// Maximum response body prefix retained and parsed from `login_sid.lua`.
pub const LOGIN_RESPONSE_LIMIT: usize = 1 << 16;
/// Maximum response body prefix retained and parsed from `data.lua` (5 MiB).
pub const DATA_LUA_RESPONSE_LIMIT: usize = 5 << 20;
/// Default local cache lifetime for a SID.
pub const DEFAULT_SID_TTL: Duration = Duration::from_secs(15 * 60);

/// Exact HKR thermostat error descriptions exposed by the Go client.
///
/// The table is intentionally an immutable slice rather than a runtime map so
/// callers can use it without allocation while preserving the Go string keys.
pub const HKR_ERROR_DESCRIPTIONS: &[(&str, &str)] = &[
    ("0", "no error"),
    ("1", "no connection to actuator"),
    ("2", "valve stroke too large"),
    ("3", "valve stroke too small"),
    ("4", "installation not ready / check mounting"),
    ("5", "valve travel too short (sluggish?) / descale"),
    ("6", "battery charge extremely low"),
];

/// Look up an HKR thermostat error description by its wire-format code.
#[must_use]
pub fn hkr_error_description(error_code: &str) -> Option<&'static str> {
    HKR_ERROR_DESCRIPTIONS
        .iter()
        .find_map(|(code, description)| (*code == error_code).then_some(*description))
}

/// HTTP method required by the injected transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Get,
    Post,
}

/// A complete request passed to an injected transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub method: Method,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    /// The maximum body size the transport should retain for this response.
    pub response_limit: usize,
}

/// A response returned by an injected transport.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Response {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Side-effect boundary for session and `data.lua` requests.
///
/// Production integration can adapt the repository's concrete HTTP transport;
/// tests use a recording implementation and never contact a router.
pub trait Transport {
    fn send(&mut self, request: Request) -> Result<Response, TransportError>;
}

/// Transport failure without coupling this crate to one HTTP library.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportError(pub String);

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl StdError for TransportError {}

/// Clock boundary used for deterministic SID expiry tests.
pub trait Clock {
    fn now(&self) -> Instant;
}

/// Wall-clock-backed clock for production use.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Parsed fields returned by `login_sid.lua`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionInfo {
    pub sid: String,
    pub challenge: String,
    pub block_time: i64,
}

/// Errors from SID acquisition and `data.lua` response validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientError {
    NoCredential,
    Transport(String),
    LoginHttpStatus(u16),
    MalformedLoginXml(String),
    Challenge(ChallengeError),
    InvalidCredentials,
    RateLimited(i64),
    AhaForbiddenAfterRelogin,
    AhaHttpStatus { switchcmd: String, status: u16 },
    DataLuaHttpStatus(u16),
    HtmlLoginPage,
    NonJsonResponse { content_type: String },
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCredential => formatter.write_str("no FRITZ!Box password configured"),
            Self::Transport(message) => formatter.write_str(message),
            Self::LoginHttpStatus(status) => {
                write!(formatter, "login_sid.lua returned HTTP {status}")
            }
            Self::MalformedLoginXml(message) => {
                write!(formatter, "parsing login_sid.lua response: {message}")
            }
            Self::Challenge(error) => error.fmt(formatter),
            Self::InvalidCredentials => formatter.write_str("login failed: invalid credentials"),
            Self::RateLimited(seconds) => write!(
                formatter,
                "login failed; box is rate-limiting for {seconds}s (wrong password?)"
            ),
            Self::AhaForbiddenAfterRelogin => {
                formatter.write_str("aha: forbidden after re-login")
            }
            Self::AhaHttpStatus { switchcmd, status } => {
                write!(formatter, "aha: {switchcmd} returned HTTP {status}")
            }
            Self::DataLuaHttpStatus(status) => {
                write!(formatter, "scrape: data.lua returned HTTP {status}")
            }
            Self::HtmlLoginPage => formatter.write_str(
                "scrape: data.lua returned an HTML login page instead of JSON; run 'symfritz auth test' to verify credentials and retry",
            ),
            Self::NonJsonResponse { content_type } => write!(
                formatter,
                "scrape: data.lua returned a non-JSON response (content type {content_type:?})"
            ),
        }
    }
}

impl StdError for ClientError {}

impl From<ChallengeError> for ClientError {
    fn from(value: ChallengeError) -> Self {
        Self::Challenge(value)
    }
}

/// Session and raw `data.lua` client over an injected transport and clock.
pub struct Client<T, C = SystemClock> {
    transport: T,
    clock: C,
    base_url: String,
    user: String,
    password: String,
    sid: Option<String>,
    sid_acquired_at: Option<Instant>,
    sid_ttl: Duration,
}

impl<T: Transport, C: Clock> Client<T, C> {
    /// Construct a client. `base_url` is normally the router's web origin.
    pub fn new(
        transport: T,
        clock: C,
        base_url: impl Into<String>,
        user: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            transport,
            clock,
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            user: user.into(),
            password: password.into(),
            sid: None,
            sid_acquired_at: None,
            sid_ttl: DEFAULT_SID_TTL,
        }
    }

    /// Change the local SID cache lifetime. A zero duration disables caching.
    #[must_use]
    pub fn with_sid_ttl(mut self, ttl: Duration) -> Self {
        self.sid_ttl = ttl;
        self
    }

    /// Set the local SID cache lifetime after construction.
    pub fn set_sid_ttl(&mut self, ttl: Duration) {
        self.sid_ttl = ttl;
    }

    /// Return a valid cached SID or perform the challenge-response login.
    pub fn sid(&mut self) -> Result<String, ClientError> {
        if self.cached_sid_is_fresh() {
            return Ok(self.sid.clone().expect("fresh SID is present"));
        }
        self.clear_sid();
        if self.password.trim().is_empty() {
            return Err(ClientError::NoCredential);
        }

        let info = self.fetch_session(None)?;
        if is_valid_sid(&info.sid) {
            return self.cache_sid(info.sid);
        }
        let response = challenge_response(&info.challenge, &self.password)?;
        let user = self.user.clone();
        let info = self.fetch_session(Some((&user, &response)))?;
        if is_valid_sid(&info.sid) {
            return self.cache_sid(info.sid);
        }
        if info.block_time > 0 {
            return Err(ClientError::RateLimited(info.block_time));
        }
        Err(ClientError::InvalidCredentials)
    }

    /// Clear the cached SID. The next request performs a fresh login.
    pub fn invalidate_sid(&mut self) {
        self.clear_sid();
    }

    /// Return the cached SID without contacting the router.
    #[must_use]
    pub fn cached_sid(&self) -> Option<&str> {
        self.sid.as_deref().filter(|_| self.cached_sid_is_fresh())
    }

    /// Seed the cache with a SID, primarily for replay adapters and tests.
    pub fn set_cached_sid(&mut self, sid: impl Into<String>) {
        self.sid = Some(sid.into());
        self.sid_acquired_at = Some(self.clock.now());
    }

    /// POST a best-effort, version-fragile request to `/data.lua`.
    ///
    /// The response is returned as raw JSON text to preserve whitespace and
    /// unknown fields. `params` may contain repeated values, matching Go's
    /// `url.Values` behavior.
    pub fn data_lua(
        &mut self,
        page: &str,
        params: &BTreeMap<String, Vec<String>>,
    ) -> Result<String, ClientError> {
        let response = self.data_lua_once(page, params)?;
        self.validate_data_response(response)
    }

    /// Alias with the Go client's terminology.
    pub fn scrape_data_lua(
        &mut self,
        page: &str,
        params: &BTreeMap<String, Vec<String>>,
    ) -> Result<String, ClientError> {
        self.data_lua(page, params)
    }

    /// Access the injected transport for replay/test inspection.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Consume the client and return its transport.
    pub fn into_transport(self) -> T {
        self.transport
    }

    fn cached_sid_is_fresh(&self) -> bool {
        let (Some(sid), Some(acquired_at)) = (&self.sid, self.sid_acquired_at) else {
            return false;
        };
        if !is_valid_sid(sid) || self.sid_ttl.is_zero() {
            return false;
        }
        self.clock
            .now()
            .checked_duration_since(acquired_at)
            .is_some_and(|age| age < self.sid_ttl)
    }

    fn cache_sid(&mut self, sid: String) -> Result<String, ClientError> {
        self.sid = Some(sid.clone());
        self.sid_acquired_at = Some(self.clock.now());
        Ok(sid)
    }

    fn clear_sid(&mut self) {
        self.sid = None;
        self.sid_acquired_at = None;
    }

    fn fetch_session(
        &mut self,
        credentials: Option<(&str, &str)>,
    ) -> Result<SessionInfo, ClientError> {
        let mut pairs = vec![("version", "2".to_owned())];
        if let Some((user, response)) = credentials {
            pairs.push(("username", user.to_owned()));
            pairs.push(("response", response.to_owned()));
        }
        let url = format!("{}/login_sid.lua?{}", self.base_url, encode_pairs(pairs));
        let request = Request {
            method: Method::Get,
            url,
            headers: BTreeMap::new(),
            body: Vec::new(),
            response_limit: LOGIN_RESPONSE_LIMIT,
        };
        let mut response = self
            .transport
            .send(request)
            .map_err(|error| ClientError::Transport(format!("contacting FRITZ!Box: {error}")))?;
        response.body.truncate(LOGIN_RESPONSE_LIMIT);
        if response.status != 200 {
            return Err(ClientError::LoginHttpStatus(response.status));
        }
        parse_session_info(&response.body)
    }

    fn data_lua_once(
        &mut self,
        page: &str,
        params: &BTreeMap<String, Vec<String>>,
    ) -> Result<Response, ClientError> {
        let sid = self.sid()?;
        let mut values = BTreeMap::<String, Vec<String>>::new();
        values.insert("page".to_owned(), vec![page.to_owned()]);
        values.insert("sid".to_owned(), vec![sid]);
        for (key, entries) in params {
            values
                .entry(key.clone())
                .or_default()
                .extend(entries.iter().cloned());
        }
        let pairs = values
            .into_iter()
            .flat_map(|(key, values)| values.into_iter().map(move |value| (key.clone(), value)));
        let request = Request {
            method: Method::Post,
            url: format!("{}/data.lua", self.base_url),
            headers: BTreeMap::from([(
                "Content-Type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            )]),
            body: encode_pairs(pairs).into_bytes(),
            response_limit: DATA_LUA_RESPONSE_LIMIT,
        };
        self.transport.send(request).map_err(|error| {
            ClientError::Transport(format!("scrape: contacting FRITZ!Box: {error}"))
        })
    }

    fn validate_data_response(&self, mut response: Response) -> Result<String, ClientError> {
        response.body.truncate(DATA_LUA_RESPONSE_LIMIT);
        if response.status != 200 {
            return Err(ClientError::DataLuaHttpStatus(response.status));
        }
        if serde_json::from_slice::<serde_json::Value>(&response.body).is_ok() {
            let content_type = response
                .header("Content-Type")
                .unwrap_or("unknown")
                .to_owned();
            return String::from_utf8(response.body)
                .map_err(|_| ClientError::NonJsonResponse { content_type });
        }
        let content_type = response
            .header("Content-Type")
            .unwrap_or("unknown")
            .to_owned();
        if looks_like_html(&response.body, &content_type) {
            return Err(ClientError::HtmlLoginPage);
        }
        Err(ClientError::NonJsonResponse { content_type })
    }

    /// Perform one AHA-HTTP `switchcmd`, retrying exactly once after HTTP 403.
    pub fn home(
        &mut self,
        switchcmd: &str,
        params: &BTreeMap<String, Vec<String>>,
    ) -> Result<String, ClientError> {
        let response = self.home_once(switchcmd, params)?;
        if response.status == 403 {
            self.invalidate_sid();
            let response = self.home_once(switchcmd, params)?;
            if response.status == 403 {
                return Err(ClientError::AhaForbiddenAfterRelogin);
            }
            return self.validate_home_response(switchcmd, response);
        }
        self.validate_home_response(switchcmd, response)
    }

    /// Fetch and parse the AHA `getdevicelistinfos` device list.
    pub fn devices(&mut self) -> Result<Vec<Device>, ClientError> {
        let list = self.device_list()?;
        Ok(list.devices)
    }

    /// Fetch and parse the AHA `getdevicelistinfos` group list.
    pub fn groups(&mut self) -> Result<Vec<Group>, ClientError> {
        let list = self.device_list()?;
        Ok(list.groups)
    }

    /// Fetch and parse the complete AHA device/group list.
    pub fn device_list(&mut self) -> Result<DeviceList, ClientError> {
        let raw = self.home("getdevicelistinfos", &BTreeMap::new())?;
        parse_device_list(raw.as_bytes())
    }

    /// Turn an AHA switch actor on.
    pub fn switch_on(&mut self, ain: &str) -> Result<(), ClientError> {
        let params = BTreeMap::from([("ain".to_owned(), vec![ain.to_owned()])]);
        self.home("setswitchon", &params).map(|_| ())
    }

    /// Turn an AHA switch actor off.
    pub fn switch_off(&mut self, ain: &str) -> Result<(), ClientError> {
        let params = BTreeMap::from([("ain".to_owned(), vec![ain.to_owned()])]);
        self.home("setswitchoff", &params).map(|_| ())
    }

    /// Set an HKR target in Celsius, or use 254 (`ON`) / 253 (`OFF`).
    pub fn set_hkr_temp(&mut self, ain: &str, temp_celsius: f64) -> Result<(), ClientError> {
        let param = if temp_celsius == 254.0 || temp_celsius == 253.0 {
            format!("{temp_celsius:.0}")
        } else {
            format!("{:.0}", temp_celsius * 2.0)
        };
        let params = BTreeMap::from([
            ("ain".to_owned(), vec![ain.to_owned()]),
            ("param".to_owned(), vec![param]),
        ]);
        self.home("sethkrtsoll", &params).map(|_| ())
    }

    fn home_once(
        &mut self,
        switchcmd: &str,
        params: &BTreeMap<String, Vec<String>>,
    ) -> Result<Response, ClientError> {
        let sid = self.sid()?;
        let mut values = BTreeMap::<String, Vec<String>>::new();
        values.insert("sid".to_owned(), vec![sid]);
        values.insert("switchcmd".to_owned(), vec![switchcmd.to_owned()]);
        for (key, entries) in params {
            values
                .entry(key.clone())
                .or_default()
                .extend(entries.iter().cloned());
        }
        let pairs = values
            .into_iter()
            .flat_map(|(key, values)| values.into_iter().map(move |value| (key.clone(), value)));
        let request = Request {
            method: Method::Get,
            url: format!(
                "{}/webservices/homeautoswitch.lua?{}",
                self.base_url,
                encode_pairs(pairs)
            ),
            headers: BTreeMap::new(),
            body: Vec::new(),
            response_limit: 1 << 20,
        };
        self.transport
            .send(request)
            .map_err(|error| ClientError::Transport(format!("aha: contacting FRITZ!Box: {error}")))
    }

    fn validate_home_response(
        &self,
        switchcmd: &str,
        mut response: Response,
    ) -> Result<String, ClientError> {
        // Go uses io.LimitReader without a +1 probe: over-limit bodies are
        // truncated to exactly 1 MiB before status checking and trimming.
        response.body.truncate(1 << 20);
        if response.status != 200 {
            return Err(ClientError::AhaHttpStatus {
                switchcmd: switchcmd.to_owned(),
                status: response.status,
            });
        }
        let text = String::from_utf8(response.body).map_err(|error| {
            ClientError::Transport(format!("aha: invalid response body: {error}"))
        })?;
        Ok(text.trim().to_owned())
    }
}

/// AHA's parsed `getdevicelistinfos` response.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeviceList {
    pub devices: Vec<Device>,
    pub groups: Vec<Group>,
}

/// One AHA actor. Numeric values intentionally remain strings as in Go.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Device {
    pub identifier: String,
    pub id: String,
    pub name: String,
    pub present: i32,
    pub switch: Switch,
    pub temperature: Temperature,
    pub hkr: Hkr,
    pub powermeter: PowerMeter,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Switch {
    pub state: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Temperature {
    pub celsius: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Hkr {
    pub tist: String,
    pub tsoll: String,
    pub batterylow: String,
    pub battery: String,
    pub windowopenactiv: String,
    pub errorcode: String,
    pub nextchange: NextChange,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PowerMeter {
    pub power: String,
    pub energy: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct NextChange {
    #[serde(rename = "End", alias = "end")]
    pub end: String,
    #[serde(rename = "Start", alias = "start")]
    pub start: String,
    #[serde(rename = "TChange", alias = "tchange")]
    pub tchange: i32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Group {
    pub identifier: String,
    pub id: String,
    pub name: String,
    pub members: Vec<String>,
    pub master_device_id: String,
}

/// Links one parsed group with its physical devices.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeviceGroup {
    pub group: Group,
    pub devices: Vec<Device>,
}

#[derive(Debug, Default, Deserialize)]
struct DeviceListWire {
    #[serde(rename = "device", default)]
    devices: Vec<DeviceWire>,
    #[serde(rename = "group", default)]
    groups: Vec<GroupWire>,
}

#[derive(Debug, Default, Deserialize)]
struct DeviceWire {
    #[serde(rename = "@identifier", default)]
    identifier: String,
    #[serde(rename = "@id", default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    present: i32,
    #[serde(default)]
    switch: SwitchWire,
    #[serde(default)]
    temperature: TemperatureWire,
    #[serde(default)]
    hkr: HkrWire,
    #[serde(default)]
    powermeter: PowerMeterWire,
}

#[derive(Debug, Default, Deserialize)]
struct SwitchWire {
    #[serde(default)]
    state: String,
}
#[derive(Debug, Default, Deserialize)]
struct TemperatureWire {
    #[serde(default)]
    celsius: String,
}
#[derive(Debug, Default, Deserialize)]
struct HkrWire {
    #[serde(default)]
    tist: String,
    #[serde(default)]
    tsoll: String,
    #[serde(default)]
    batterylow: String,
    #[serde(default)]
    battery: String,
    #[serde(default)]
    windowopenactiv: String,
    #[serde(default)]
    errorcode: String,
    #[serde(default)]
    nextchange: NextChangeWire,
}
#[derive(Debug, Default, Deserialize)]
struct NextChangeWire {
    #[serde(default)]
    end: String,
    #[serde(default)]
    start: String,
    #[serde(default)]
    tchange: i32,
}
#[derive(Debug, Default, Deserialize)]
struct PowerMeterWire {
    #[serde(default)]
    power: String,
    #[serde(default)]
    energy: String,
}
#[derive(Debug, Default, Deserialize)]
struct GroupWire {
    #[serde(rename = "@identifier", default)]
    identifier: String,
    #[serde(rename = "@id", default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    groupinfo: GroupInfoWire,
}
#[derive(Debug, Default, Deserialize)]
struct GroupInfoWire {
    #[serde(default)]
    masterdeviceid: String,
    #[serde(default)]
    members: String,
}

/// Parse an AHA `devicelist` XML response using the Go field mapping.
pub fn parse_device_list(body: &[u8]) -> Result<DeviceList, ClientError> {
    let mut reader = Reader::from_reader(body);
    let root_name = loop {
        match reader.read_event() {
            Ok(Event::Start(element)) | Ok(Event::Empty(element)) => {
                break element.name().local_name().as_ref().to_owned();
            }
            Ok(Event::Eof) => {
                return Err(ClientError::Transport(
                    "aha: parsing device list: missing root element".to_owned(),
                ));
            }
            Ok(_) => {}
            Err(error) => {
                return Err(ClientError::Transport(format!(
                    "aha: parsing device list: {error}"
                )));
            }
        }
    };
    if root_name != "devicelist" {
        return Err(ClientError::Transport(
            "aha: parsing device list: expected root element devicelist".to_owned(),
        ));
    }
    let wire: DeviceListWire = quick_xml::de::from_reader(body)
        .map_err(|error| ClientError::Transport(format!("aha: parsing device list: {error}")))?;
    let devices = wire
        .devices
        .into_iter()
        .map(|device| Device {
            identifier: device.identifier,
            id: device.id,
            name: device.name,
            present: device.present,
            switch: Switch {
                state: device.switch.state,
            },
            temperature: Temperature {
                celsius: device.temperature.celsius,
            },
            hkr: Hkr {
                tist: device.hkr.tist,
                tsoll: device.hkr.tsoll,
                batterylow: device.hkr.batterylow,
                battery: device.hkr.battery,
                windowopenactiv: device.hkr.windowopenactiv,
                errorcode: device.hkr.errorcode,
                nextchange: NextChange {
                    end: device.hkr.nextchange.end,
                    start: device.hkr.nextchange.start,
                    tchange: device.hkr.nextchange.tchange,
                },
            },
            powermeter: PowerMeter {
                power: device.powermeter.power,
                energy: device.powermeter.energy,
            },
        })
        .collect();
    let groups = wire
        .groups
        .into_iter()
        .map(|group| Group {
            identifier: group.identifier,
            id: group.id,
            name: group.name,
            members: if group.groupinfo.members.is_empty() {
                Vec::new()
            } else {
                group
                    .groupinfo
                    .members
                    .split(',')
                    .map(str::to_owned)
                    .collect()
            },
            master_device_id: group.groupinfo.masterdeviceid,
        })
        .collect();
    Ok(DeviceList { devices, groups })
}

impl DeviceList {
    /// Return the Go-compatible name-to-AIN map; later duplicate names win.
    pub fn names_and_ains(&self) -> BTreeMap<String, String> {
        self.devices
            .iter()
            .map(|device| (&device.name, &device.identifier))
            .chain(
                self.groups
                    .iter()
                    .map(|group| (&group.name, &group.identifier)),
            )
            .map(|(name, ain)| (name.clone(), ain.clone()))
            .collect()
    }
}

/// Adapt the AHA request/response boundary to the production TR-064 HTTP adapter.
impl Transport for symfritz_tr064::BlockingHttpTransport {
    fn send(&mut self, request: Request) -> Result<Response, TransportError> {
        let method = match request.method {
            Method::Get => symfritz_tr064::Method::Get,
            Method::Post => symfritz_tr064::Method::Post,
        };
        let response = <symfritz_tr064::BlockingHttpTransport as symfritz_tr064::Transport>::send(
            self,
            symfritz_tr064::Request {
                method,
                url: request.url,
                headers: request.headers,
                body: request.body,
                response_limit: request.response_limit,
            },
        )
        .map_err(|error| TransportError(error.0))?;
        Ok(Response {
            status: response.status,
            headers: response.headers,
            body: response.body,
        })
    }
}

/// Parse a bounded `login_sid.lua` XML body.
pub fn parse_session_info(body: &[u8]) -> Result<SessionInfo, ClientError> {
    let body = &body[..body.len().min(LOGIN_RESPONSE_LIMIT)];
    let text = std::str::from_utf8(body)
        .map_err(|error| ClientError::MalformedLoginXml(error.to_string()))?;
    let document = roxmltree::Document::parse(text)
        .map_err(|error| ClientError::MalformedLoginXml(error.to_string()))?;
    if document.root_element().tag_name().name() != "SessionInfo" {
        return Err(ClientError::MalformedLoginXml(
            "expected root element SessionInfo".to_owned(),
        ));
    }
    let root = document.root_element();
    let mut sid = String::new();
    let mut challenge = String::new();
    let mut block_time = 0;
    for child in root.children().filter(|node| node.is_element()) {
        let value = child
            .children()
            .filter(|node| node.is_text())
            .filter_map(|node| node.text())
            .collect::<String>();
        match child.tag_name().name() {
            "SID" => sid = value,
            "Challenge" => challenge = value,
            "BlockTime" => {
                block_time = if value.trim().is_empty() {
                    0
                } else {
                    value
                        .trim()
                        .parse::<i64>()
                        .map_err(|error| ClientError::MalformedLoginXml(error.to_string()))?
                };
            }
            _ => {}
        }
    }
    Ok(SessionInfo {
        sid,
        challenge,
        block_time,
    })
}

fn is_valid_sid(sid: &str) -> bool {
    !sid.is_empty() && sid != INVALID_SID
}

fn encode_pairs<I, K, V>(pairs: I) -> String
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    // Go's url.Values.Encode sorts keys and preserves insertion order for
    // repeated values. Sorting before handing pairs to the serializer keeps
    // login URLs and data.lua bodies byte-compatible with that contract.
    let mut pairs: Vec<(String, String)> = pairs
        .into_iter()
        .map(|(key, value)| (key.as_ref().to_owned(), value.as_ref().to_owned()))
        .collect();
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(&key, &value);
    }
    serializer.finish()
}

fn looks_like_html(body: &[u8], content_type: &str) -> bool {
    if content_type.to_ascii_lowercase().contains("text/html") {
        return true;
    }
    // Match Go's bytes.TrimSpace + 512-byte prefix rule. Trimming before the
    // bound is important for login pages preceded by a long whitespace run.
    let body = trim_go_space(body);
    let prefix = &body[..body.len().min(512)];
    let prefix = prefix
        .iter()
        .map(|byte| byte.to_ascii_lowercase())
        .collect::<Vec<_>>();
    prefix.starts_with(b"<!doctype html") || prefix.starts_with(b"<html")
}

fn trim_go_space(body: &[u8]) -> &[u8] {
    let mut first_non_space = None;
    let mut last_non_space_end = 0;
    let mut offset = 0;
    while offset < body.len() {
        let (length, is_space) = go_utf8_rune(body, offset);
        if !is_space {
            first_non_space.get_or_insert(offset);
            last_non_space_end = offset + length;
        }
        offset += length;
    }
    match first_non_space {
        Some(start) => &body[start..last_non_space_end],
        None => &body[0..0],
    }
}

fn go_utf8_rune(body: &[u8], offset: usize) -> (usize, bool) {
    let byte = body[offset];
    if byte.is_ascii() {
        return (1, matches!(byte, b'\t'..=b'\r' | b' '));
    }
    let length = if byte & 0xe0 == 0xc0 {
        2
    } else if byte & 0xf0 == 0xe0 {
        3
    } else if byte & 0xf8 == 0xf0 {
        4
    } else {
        return (1, false);
    };
    if offset + length > body.len() {
        return (1, false);
    }
    let Ok(text) = std::str::from_utf8(&body[offset..offset + length]) else {
        return (1, false);
    };
    let Some(character) = text.chars().next() else {
        return (1, false);
    };
    (length, is_go_space(character))
}

fn is_go_space(character: char) -> bool {
    matches!(
        character,
        '\u{0085}' | '\u{00a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_encoding_matches_url_values_order_and_escaping() {
        let pairs = [("sid", "a+b"), ("page", "overview"), ("foo", "a b")];
        assert_eq!(encode_pairs(pairs), "foo=a+b&page=overview&sid=a%2Bb");
    }

    #[test]
    fn html_detection_matches_go_whitespace_rule() {
        let body = format!("{}<!DOCTYPE html>", " ".repeat(600));
        assert!(looks_like_html(body.as_bytes(), "application/octet-stream"));

        let body = "\u{2003}<!DOCTYPE HTML>";
        assert!(looks_like_html(body.as_bytes(), "application/octet-stream"));
    }

    #[test]
    fn html_detection_uses_a_byte_prefix_and_preserves_invalid_utf8() {
        let mut body = [0xc3, 0xa9].repeat(300);
        body.extend_from_slice(b"<!DOCTYPE html>");
        let trimmed = trim_go_space(&body);
        assert_eq!(trimmed.len(), body.len());
        assert_eq!(&trimmed[..512], &body[..512]);
        assert!(!looks_like_html(&body, "application/octet-stream"));

        let body = [b' ', 0xff, b' ', b'<', b'h', b't', b'm', b'l', b'>'];
        assert_eq!(trim_go_space(&body), &body[1..]);
        assert!(!looks_like_html(&body, "application/octet-stream"));
    }
}
