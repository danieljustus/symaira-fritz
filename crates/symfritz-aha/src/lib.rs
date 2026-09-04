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

use symfritz_core::auth::{ChallengeError, challenge_response};

/// The sentinel returned by `login_sid.lua` when no authenticated SID exists.
pub const INVALID_SID: &str = "0000000000000000";
/// Maximum response body accepted from `login_sid.lua`.
pub const LOGIN_RESPONSE_LIMIT: usize = 1 << 16;
/// Maximum response body accepted from `data.lua` (5 MiB).
pub const DATA_LUA_RESPONSE_LIMIT: usize = 5 << 20;
/// Default local cache lifetime for a SID.
pub const DEFAULT_SID_TTL: Duration = Duration::from_secs(15 * 60);

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
    ResponseTooLarge {
        endpoint: &'static str,
        limit: usize,
        actual: usize,
    },
    MalformedLoginXml(String),
    Challenge(ChallengeError),
    InvalidCredentials,
    RateLimited(i64),
    ForbiddenAfterRelogin,
    DataLuaHttpStatus(u16),
    HtmlLoginPage,
    NonJsonResponse {
        content_type: String,
    },
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCredential => formatter.write_str("no FRITZ!Box password configured"),
            Self::Transport(message) => formatter.write_str(message),
            Self::LoginHttpStatus(status) => {
                write!(formatter, "login_sid.lua returned HTTP {status}")
            }
            Self::ResponseTooLarge {
                endpoint,
                limit,
                actual,
            } => write!(
                formatter,
                "{endpoint} response exceeds {limit}-byte limit: {actual} bytes"
            ),
            Self::MalformedLoginXml(message) => {
                write!(formatter, "parsing login_sid.lua response: {message}")
            }
            Self::Challenge(error) => error.fmt(formatter),
            Self::InvalidCredentials => formatter.write_str("login failed: invalid credentials"),
            Self::RateLimited(seconds) => write!(
                formatter,
                "login failed; box is rate-limiting for {seconds}s (wrong password?)"
            ),
            Self::ForbiddenAfterRelogin => {
                formatter.write_str("data.lua returned HTTP 403 after re-login")
            }
            Self::DataLuaHttpStatus(status) => {
                write!(formatter, "data.lua returned HTTP {status}")
            }
            Self::HtmlLoginPage => formatter.write_str(
                "data.lua returned an HTML login page instead of JSON; run 'symfritz auth test' to verify credentials and retry",
            ),
            Self::NonJsonResponse { content_type } => write!(
                formatter,
                "data.lua returned a non-JSON response (content type {content_type:?})"
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
        if response.status == 403 {
            self.invalidate_sid();
            let response = self.data_lua_once(page, params)?;
            if response.status == 403 {
                return Err(ClientError::ForbiddenAfterRelogin);
            }
            return self.validate_data_response(response);
        }
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
        let response = self
            .transport
            .send(request)
            .map_err(|error| ClientError::Transport(format!("contacting FRITZ!Box: {error}")))?;
        if response.body.len() > LOGIN_RESPONSE_LIMIT {
            return Err(ClientError::ResponseTooLarge {
                endpoint: "login_sid.lua",
                limit: LOGIN_RESPONSE_LIMIT,
                actual: response.body.len(),
            });
        }
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

    fn validate_data_response(&self, response: Response) -> Result<String, ClientError> {
        if response.body.len() > DATA_LUA_RESPONSE_LIMIT {
            return Err(ClientError::ResponseTooLarge {
                endpoint: "data.lua",
                limit: DATA_LUA_RESPONSE_LIMIT,
                actual: response.body.len(),
            });
        }
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
}

/// Parse a bounded `login_sid.lua` XML body.
pub fn parse_session_info(body: &[u8]) -> Result<SessionInfo, ClientError> {
    if body.len() > LOGIN_RESPONSE_LIMIT {
        return Err(ClientError::ResponseTooLarge {
            endpoint: "login_sid.lua",
            limit: LOGIN_RESPONSE_LIMIT,
            actual: body.len(),
        });
    }
    let text = std::str::from_utf8(body)
        .map_err(|error| ClientError::MalformedLoginXml(error.to_string()))?;
    let document = roxmltree::Document::parse(text)
        .map_err(|error| ClientError::MalformedLoginXml(error.to_string()))?;
    if document.root_element().tag_name().name() != "SessionInfo" {
        return Err(ClientError::MalformedLoginXml(
            "expected root element SessionInfo".to_owned(),
        ));
    }
    let value = |name: &str| {
        document
            .descendants()
            .rfind(|node| node.is_element() && node.tag_name().name() == name)
            .and_then(|node| node.text())
            .unwrap_or_default()
            .to_owned()
    };
    let block_time = value("BlockTime");
    let block_time = if block_time.trim().is_empty() {
        0
    } else {
        block_time
            .trim()
            .parse::<i64>()
            .map_err(|error| ClientError::MalformedLoginXml(error.to_string()))?
    };
    Ok(SessionInfo {
        sid: value("SID"),
        challenge: value("Challenge"),
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
    let prefix = String::from_utf8_lossy(body);
    let prefix = prefix.trim_start();
    let prefix = prefix.chars().take(512).collect::<String>();
    let prefix = prefix.to_ascii_lowercase();
    prefix.starts_with("<!doctype html") || prefix.starts_with("<html")
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
    }
}
