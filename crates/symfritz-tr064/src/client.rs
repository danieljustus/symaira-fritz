use std::collections::BTreeMap;

use symfritz_core::auth::{DigestChallenge, digest_authorization_header, parse_digest_challenge};

use crate::{
    DiscoveryError, Service, SoapParseError, build_request, find_service_by_name,
    parse_description, parse_fault, parse_response,
};

const SOAP_RESPONSE_LIMIT: usize = 1 << 20;
const DISCOVERY_RESPONSE_LIMIT: usize = 4 << 20;

/// HTTP method required by the transport adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Get,
    Post,
}

/// Complete bounded request passed to an injected transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub method: Method,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub response_limit: usize,
}

/// Bounded response returned by an injected transport.
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

/// Adapter error without coupling the protocol crate to one HTTP implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportError(pub String);

impl std::fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for TransportError {}

/// Sends one already-bounded HTTP request.
pub trait Transport {
    fn send(&mut self, request: Request) -> Result<Response, TransportError>;
}

/// Supplies unpredictable client nonces for HTTP Digest authentication.
pub trait CnonceSource {
    fn next_cnonce(&mut self) -> Result<String, String>;
}

/// Protocol-engine failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientError {
    Transport(String),
    Cnonce(String),
    UnauthorizedChallenge,
    DiscoveryHttpStatus(u16),
    SoapFault {
        status: u16,
        code: i32,
        description: String,
    },
    SoapParse(SoapParseError),
    Discovery(DiscoveryError),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(message) | Self::Cnonce(message) => formatter.write_str(message),
            Self::UnauthorizedChallenge => {
                formatter.write_str("401 without a parseable digest challenge")
            }
            Self::DiscoveryHttpStatus(status) => {
                write!(formatter, "discover: tr64desc.xml returned HTTP {status}")
            }
            Self::SoapFault {
                status,
                code,
                description,
            } => write!(
                formatter,
                "SOAP fault HTTP {status}, code {code}: {description}"
            ),
            Self::SoapParse(error) => error.fmt(formatter),
            Self::Discovery(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<SoapParseError> for ClientError {
    fn from(value: SoapParseError) -> Self {
        Self::SoapParse(value)
    }
}

impl From<DiscoveryError> for ClientError {
    fn from(value: DiscoveryError) -> Self {
        Self::Discovery(value)
    }
}

#[derive(Clone, Debug)]
struct CachedDigest {
    challenge: DigestChallenge,
    nonce_count: u32,
}

/// TR-064 protocol engine over an injected transport and cnonce source.
pub struct Client<T, C> {
    transport: T,
    cnonce_source: C,
    base_url: String,
    user: String,
    password: String,
    digest: Option<CachedDigest>,
    discovered: Option<Vec<Service>>,
}

impl<T: Transport, C: CnonceSource> Client<T, C> {
    pub fn new(
        transport: T,
        cnonce_source: C,
        base_url: impl Into<String>,
        user: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            transport,
            cnonce_source,
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            user: user.into(),
            password: password.into(),
            digest: None,
            discovered: None,
        }
    }

    /// Invoke one SOAP action, performing and caching an HTTP Digest challenge.
    pub fn call(
        &mut self,
        service: &Service,
        action: &str,
        arguments: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, String>, ClientError> {
        let body = build_request(&service.service_type, action, arguments);
        let soap_action = format!("{}#{action}", service.service_type);
        let url = format!("{}{}", self.base_url, service.control_url);
        let authorization = self.cached_authorization(Method::Post, &service.control_url)?;
        let mut response = self.send_soap(&url, &soap_action, &body, authorization)?;

        if response.status == 401 {
            let (challenge, valid) = response
                .header("WWW-Authenticate")
                .map(parse_digest_challenge)
                .unwrap_or_default();
            if !valid {
                return Err(ClientError::UnauthorizedChallenge);
            }
            self.digest = Some(CachedDigest {
                challenge,
                nonce_count: 0,
            });
            let authorization = self
                .cached_authorization(Method::Post, &service.control_url)?
                .ok_or(ClientError::UnauthorizedChallenge)?;
            response = self.send_soap(&url, &soap_action, &body, Some(authorization))?;
        }

        if response.status != 200 {
            let (code, description) = parse_fault(&response.body);
            return Err(ClientError::SoapFault {
                status: response.status,
                code,
                description,
            });
        }
        parse_response(&response.body, action).map_err(Into::into)
    }

    /// Discover and cache all services advertised by `tr64desc.xml`.
    pub fn discover(&mut self) -> Result<Vec<Service>, ClientError> {
        if let Some(services) = &self.discovered {
            return Ok(services.clone());
        }
        let request = Request {
            method: Method::Get,
            url: format!("{}/tr64desc.xml", self.base_url),
            headers: BTreeMap::new(),
            body: Vec::new(),
            response_limit: DISCOVERY_RESPONSE_LIMIT,
        };
        let mut response = self
            .transport
            .send(request)
            .map_err(|error| ClientError::Transport(error.0))?;
        response.body.truncate(DISCOVERY_RESPONSE_LIMIT);
        if response.status != 200 {
            return Err(ClientError::DiscoveryHttpStatus(response.status));
        }
        let services = parse_description(&response.body)?;
        self.discovered = Some(services.clone());
        Ok(services)
    }

    /// Discard the discovery cache and fetch the description again.
    pub fn refresh_discovery(&mut self) -> Result<Vec<Service>, ClientError> {
        self.discovered = None;
        self.discover()
    }

    /// Resolve one discovered service by case-insensitive name.
    pub fn service_by_name(&mut self, name: &str) -> Result<Service, ClientError> {
        let services = self.discover()?;
        find_service_by_name(&services, name).map_err(Into::into)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    pub(crate) fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub(crate) fn authenticated_get(&mut self, url: &str) -> Result<Response, ClientError> {
        self.authenticated_get_with_limit(url, 1 << 20)
    }

    pub(crate) fn authenticated_get_with_limit(
        &mut self,
        url: &str,
        response_limit: usize,
    ) -> Result<Response, ClientError> {
        let parsed = url::Url::parse(url)
            .map_err(|error| ClientError::Transport(format!("invalid GET URL {url}: {error}")))?;
        let mut uri = parsed.path().to_owned();
        if let Some(query) = parsed.query() {
            uri.push('?');
            uri.push_str(query);
        }
        let mut headers = BTreeMap::new();
        if let Some(authorization) = self.cached_authorization(Method::Get, &uri)? {
            headers.insert("Authorization".to_owned(), authorization);
        }
        let request = Request {
            method: Method::Get,
            url: url.to_owned(),
            headers,
            body: Vec::new(),
            response_limit,
        };
        let mut response = self
            .transport
            .send(request)
            .map_err(|error| ClientError::Transport(error.0))?;
        response.body.truncate(response_limit);
        if response.status == 401 {
            let (challenge, valid) = response
                .header("WWW-Authenticate")
                .map(parse_digest_challenge)
                .unwrap_or_default();
            if !valid {
                return Err(ClientError::UnauthorizedChallenge);
            }
            self.digest = Some(CachedDigest {
                challenge,
                nonce_count: 0,
            });
            let authorization = self
                .cached_authorization(Method::Get, &uri)?
                .ok_or(ClientError::UnauthorizedChallenge)?;
            let request = Request {
                method: Method::Get,
                url: url.to_owned(),
                headers: BTreeMap::from([(String::from("Authorization"), authorization)]),
                body: Vec::new(),
                response_limit: SOAP_RESPONSE_LIMIT,
            };
            response = self
                .transport
                .send(request)
                .map_err(|error| ClientError::Transport(error.0))?;
            response.body.truncate(response_limit);
        }
        if response.status != 200 {
            return Err(ClientError::Transport(format!(
                "GET {url} returned HTTP {}",
                response.status
            )));
        }
        Ok(response)
    }

    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    fn send_soap(
        &mut self,
        url: &str,
        soap_action: &str,
        body: &[u8],
        authorization: Option<String>,
    ) -> Result<Response, ClientError> {
        let mut headers = BTreeMap::from([
            (
                "Content-Type".to_owned(),
                "text/xml; charset=\"utf-8\"".to_owned(),
            ),
            ("SoapAction".to_owned(), soap_action.to_owned()),
        ]);
        if let Some(authorization) = authorization {
            headers.insert("Authorization".to_owned(), authorization);
        }
        let request = Request {
            method: Method::Post,
            url: url.to_owned(),
            headers,
            body: body.to_owned(),
            response_limit: SOAP_RESPONSE_LIMIT,
        };
        let mut response = self
            .transport
            .send(request)
            .map_err(|error| ClientError::Transport(error.0))?;
        response.body.truncate(SOAP_RESPONSE_LIMIT);
        Ok(response)
    }

    fn cached_authorization(
        &mut self,
        method: Method,
        uri: &str,
    ) -> Result<Option<String>, ClientError> {
        let Some(cache) = &mut self.digest else {
            return Ok(None);
        };
        cache.nonce_count = cache.nonce_count.saturating_add(1);
        let challenge = cache.challenge.clone();
        let nonce_count = cache.nonce_count;
        let cnonce = self
            .cnonce_source
            .next_cnonce()
            .map_err(ClientError::Cnonce)?;
        let method = match method {
            Method::Get => "GET",
            Method::Post => "POST",
        };
        Ok(Some(digest_authorization_header(
            &challenge,
            &self.user,
            &self.password,
            method,
            uri,
            nonce_count,
            &cnonce,
        )))
    }
}
