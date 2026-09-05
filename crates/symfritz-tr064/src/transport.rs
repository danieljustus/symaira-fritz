//! Concrete bounded blocking HTTP/TLS transport for the TR-064 engine.

use std::{
    collections::BTreeMap,
    fmt,
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    sync::{
        Arc, Once,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use rustls::{
    ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{self, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use symfritz_core::pins::{PinStore, calculate_spki_pin};
use url::Url;

use crate::safeurl::{SafeUrlError, redact_raw_url, redact_url, validate_request_url};
use crate::{Method, Request, Response, Transport, TransportError};

/// Default maximum response size for a concrete transport.
pub const DEFAULT_RESPONSE_LIMIT: usize = 8 << 20;

/// Optional diagnostic sink used for the single fallback warning.
pub type WarningSink = Arc<dyn Fn(&str) + Send + Sync>;

/// Configuration for [`BlockingHttpTransport`].
#[derive(Clone)]
pub struct HttpTransportConfig {
    pub origin: Url,
    pub pin_store: PinStore,
    pub insecure_tls: bool,
    pub allow_http_fallback: bool,
    pub timeout: Duration,
    pub warning_sink: Option<WarningSink>,
}

impl HttpTransportConfig {
    #[must_use]
    pub fn new(origin: Url, pin_store: PinStore) -> Self {
        Self {
            origin,
            pin_store,
            insecure_tls: false,
            allow_http_fallback: false,
            timeout: Duration::from_secs(15),
            warning_sink: None,
        }
    }

    #[must_use]
    pub fn with_warning_sink(mut self, sink: Arc<dyn Fn(&str) + Send + Sync>) -> Self {
        self.warning_sink = Some(sink);
        self
    }
}

impl fmt::Debug for HttpTransportConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpTransportConfig")
            .field("origin", &redact_url(&self.origin))
            .field("pin_store", &self.pin_store.path())
            .field("insecure_tls", &self.insecure_tls)
            .field("allow_http_fallback", &self.allow_http_fallback)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// Errors produced before the protocol engine sees a response.
#[derive(Debug)]
pub enum HttpTransportError {
    InvalidOrigin(SafeUrlError),
    InvalidRequestUrl { url: String, source: SafeUrlError },
    EndpointUnavailable { url: String, message: String },
    Request { url: String, message: String },
}

impl fmt::Display for HttpTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOrigin(error) => write!(formatter, "invalid configured origin: {error}"),
            Self::InvalidRequestUrl { url, source } => {
                write!(formatter, "unsafe request URL {url}: {source}")
            }
            Self::EndpointUnavailable { url, message } | Self::Request { url, message } => {
                write!(formatter, "request to {url} failed: {message}")
            }
        }
    }
}

impl std::error::Error for HttpTransportError {}

/// A synchronous HTTP/1 transport with strict origin checks, TOFU and fallback.
pub struct BlockingHttpTransport {
    origin: Url,
    resolved_ips: Vec<IpAddr>,
    timeout: Duration,
    tls_config: Arc<rustls::ClientConfig>,
    pin_store: PinStore,
    pin_key: String,
    insecure_tls: bool,
    allow_http_fallback: bool,
    tls_enabled: AtomicBool,
    fallback_warned: Once,
    warning_sink: Option<WarningSink>,
}

impl fmt::Debug for BlockingHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockingHttpTransport")
            .field("origin", &redact_url(&self.origin))
            .field("insecure_tls", &self.insecure_tls)
            .field("allow_http_fallback", &self.allow_http_fallback)
            .field("tls_enabled", &self.tls_enabled.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl BlockingHttpTransport {
    /// Builds a transport. HTTPS always uses either TOFU or explicit insecure mode.
    pub fn new(config: HttpTransportConfig) -> Result<Self, HttpTransportError> {
        validate_origin(&config.origin)?;
        let (_resolved_host, resolved_addresses) = resolve_local_origin(&config.origin)?;
        let resolved_ips = resolved_addresses
            .iter()
            .map(SocketAddr::ip)
            .collect::<Vec<_>>();
        let pin_key = pin_key(&config.origin);
        let provider = Arc::new(crypto::ring::default_provider());
        let verifier: Arc<dyn ServerCertVerifier> = if config.insecure_tls {
            Arc::new(InsecureVerifier {
                provider: provider.clone(),
            })
        } else {
            Arc::new(TofuVerifier {
                provider: provider.clone(),
                pin_store: config.pin_store.clone(),
                pin_key: pin_key.clone(),
            })
        };
        let tls_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|error| HttpTransportError::Request {
                url: redact_url(&config.origin),
                message: format!("TLS configuration failed: {error}"),
            })?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Ok(Self {
            origin: config.origin.clone(),
            resolved_ips,
            timeout: config.timeout,
            tls_config: Arc::new(tls_config),
            pin_store: config.pin_store,
            pin_key,
            insecure_tls: config.insecure_tls,
            allow_http_fallback: config.allow_http_fallback,
            tls_enabled: AtomicBool::new(config.origin.scheme() == "https"),
            fallback_warned: Once::new(),
            warning_sink: config.warning_sink,
        })
    }

    #[must_use]
    pub fn tls_enabled(&self) -> bool {
        self.tls_enabled.load(Ordering::Acquire)
    }

    fn warn_once(&self) {
        self.fallback_warned.call_once(|| {
            let warning = format!(
                "warning: TLS endpoint on {} did not answer, falling back to HTTP because [box].allow_http_fallback is enabled",
                self.origin.host_str().unwrap_or("router")
            );
            if let Some(sink) = &self.warning_sink {
                sink(&warning);
            } else {
                eprintln!("{warning}");
            }
        });
    }

    fn execute(&self, request: &Request, url: &Url) -> Result<Response, HttpTransportError> {
        let deadline = Instant::now() + self.timeout;
        let mut stream = self.connect(url, deadline)?;
        if url.scheme() == "https" {
            let server_name = server_name(url).map_err(|message| HttpTransportError::Request {
                url: redact_url(url),
                message,
            })?;
            let connection =
                ClientConnection::new(self.tls_config.clone(), server_name).map_err(|error| {
                    HttpTransportError::Request {
                        url: redact_url(url),
                        message: format!("TLS handshake failed: {error}"),
                    }
                })?;
            let mut tls = StreamOwned::new(connection, stream);
            tls.conn
                .complete_io(&mut tls.sock)
                .map_err(|error| classify_io_error(error, url, "completing TLS handshake"))?;
            if !self.insecure_tls {
                let certificate = tls
                    .conn
                    .peer_certificates()
                    .and_then(|certificates| certificates.first())
                    .ok_or_else(|| HttpTransportError::Request {
                        url: redact_url(url),
                        message: "TLS peer certificate is unavailable".to_owned(),
                    })?;
                self.record_peer_pin(url, certificate)?;
            }
            write_request(&mut tls, request, url, deadline)
                .map_err(|error| classify_io_error(error, url, "writing request"))?;
            let (status, headers) = read_response_headers(&mut tls, url, deadline)?;
            let body = read_response_body(
                &mut tls,
                status,
                &headers,
                request.response_limit.min(DEFAULT_RESPONSE_LIMIT),
                url,
                deadline,
            )?;
            Ok(Response {
                status,
                headers,
                body,
            })
        } else {
            write_request(&mut stream, request, url, deadline)
                .map_err(|error| classify_io_error(error, url, "writing request"))?;
            let (status, headers) = read_response_headers(&mut stream, url, deadline)?;
            let body = read_response_body(
                &mut stream,
                status,
                &headers,
                request.response_limit.min(DEFAULT_RESPONSE_LIMIT),
                url,
                deadline,
            )?;
            Ok(Response {
                status,
                headers,
                body,
            })
        }
    }

    fn connect(&self, url: &Url, deadline: Instant) -> Result<TcpStream, HttpTransportError> {
        let port = url
            .port_or_known_default()
            .ok_or_else(|| HttpTransportError::Request {
                url: redact_url(url),
                message: "request URL has no port".to_owned(),
            })?;
        let mut last_error = None;
        for ip in &self.resolved_ips {
            let address = SocketAddr::new(*ip, port);
            match TcpStream::connect_timeout(&address, remaining(deadline)) {
                Ok(stream) => {
                    stream
                        .set_read_timeout(Some(remaining(deadline)))
                        .map_err(|error| classify_io_error(error, url, "setting read timeout"))?;
                    stream
                        .set_write_timeout(Some(remaining(deadline)))
                        .map_err(|error| classify_io_error(error, url, "setting write timeout"))?;
                    return Ok(stream);
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(classify_io_error(
            last_error.unwrap_or_else(|| io::Error::other("no resolved addresses")),
            url,
            "connecting",
        ))
    }

    fn record_peer_pin(
        &self,
        url: &Url,
        certificate: &CertificateDer<'_>,
    ) -> Result<(), HttpTransportError> {
        let pin = calculate_spki_pin(certificate.as_ref()).map_err(|error| {
            HttpTransportError::Request {
                url: redact_url(url),
                message: format!("invalid server certificate: {error}"),
            }
        })?;
        match self.pin_store.get(&self.pin_key) {
            Some(expected) if expected != pin => Err(HttpTransportError::Request {
                url: redact_url(url),
                message: format!("certificate pin mismatch for {}", self.pin_key),
            }),
            Some(_) => Ok(()),
            None => self
                .pin_store
                .set(self.pin_key.clone(), pin)
                .map_err(|error| HttpTransportError::Request {
                    url: redact_url(url),
                    message: format!("failed to record certificate pin: {error}"),
                }),
        }
    }
}

impl Transport for BlockingHttpTransport {
    fn send(&mut self, request: Request) -> Result<Response, TransportError> {
        let requested = Url::parse(&request.url).map_err(|error| {
            TransportError(
                HttpTransportError::Request {
                    url: redact_raw_url(&request.url),
                    message: error.to_string(),
                }
                .to_string(),
            )
        })?;
        validate_request_url(&self.origin, &requested).map_err(|source| {
            TransportError(
                HttpTransportError::InvalidRequestUrl {
                    url: redact_url(&requested),
                    source,
                }
                .to_string(),
            )
        })?;
        let tls_attempt = self.tls_enabled() && requested.scheme() == "https";
        let target = if tls_attempt || !self.allow_http_fallback {
            requested.clone()
        } else if requested.scheme() == "https" {
            fallback_url(&requested).map_err(|error| TransportError(error.to_string()))?
        } else {
            requested.clone()
        };
        match self.execute(&request, &target) {
            Ok(response) => Ok(response),
            Err(error)
                if tls_attempt && is_endpoint_unreachable(&error) && self.allow_http_fallback =>
            {
                let fallback =
                    fallback_url(&requested).map_err(|error| TransportError(error.to_string()))?;
                self.warn_once();
                self.tls_enabled.store(false, Ordering::Release);
                self.execute(&request, &fallback)
                    .map_err(|error| TransportError(error.to_string()))
            }
            Err(error) if tls_attempt && is_endpoint_unreachable(&error) => {
                Err(TransportError(format!(
                    "{error}; refusing unencrypted HTTP fallback; set [box].allow_http_fallback = true to opt in, or set [box].use_tls = false to use HTTP directly"
                )))
            }
            Err(error) => Err(TransportError(error.to_string())),
        }
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn server_name(url: &Url) -> Result<ServerName<'static>, String> {
    let host = url
        .host_str()
        .ok_or_else(|| "request URL has no host".to_owned())?;
    if let Ok(address) = host.parse::<std::net::IpAddr>() {
        Ok(ServerName::IpAddress(address.into()))
    } else {
        ServerName::try_from(host.to_owned())
            .map_err(|error| format!("invalid TLS server name: {error}"))
    }
}

fn classify_io_error(error: io::Error, url: &Url, phase: &str) -> HttpTransportError {
    let message = format!("{phase}: {}", error);
    let url = redact_url(url);
    if phase == "connecting" && endpoint_unreachable_message(&message) {
        HttpTransportError::EndpointUnavailable { url, message }
    } else {
        HttpTransportError::Request { url, message }
    }
}

fn write_request<S: Write>(
    stream: &mut S,
    request: &Request,
    url: &Url,
    deadline: Instant,
) -> io::Result<()> {
    let method = match request.method {
        Method::Get => "GET",
        Method::Post => "POST",
    };
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "request URL has no host"))?;
    let host_header = match url.port_or_known_default() {
        Some(80 | 443) => host.to_owned(),
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    let mut wire = format!(
        "{method} {} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\nAccept-Encoding: identity\r\n",
        request_target(url)
    );
    for (name, value) in &request.headers {
        if !valid_header_name(name) || !valid_header_value(value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "request header name or value is invalid",
            ));
        }
        if is_reserved_request_header(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "request attempts to override transport-owned framing headers",
            ));
        }
        wire.push_str(name);
        wire.push_str(": ");
        wire.push_str(value);
        wire.push_str("\r\n");
    }
    if !request.body.is_empty() {
        wire.push_str(&format!("Content-Length: {}\r\n", request.body.len()));
    }
    wire.push_str("\r\n");
    stream.write_all(wire.as_bytes())?;
    if !request.body.is_empty() {
        stream.write_all(&request.body)?;
    }
    stream.flush()?;
    let _ = deadline;
    Ok(())
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn valid_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || (byte >= 0x20 && byte != 0x7f))
}

fn is_reserved_request_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "accept-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "proxy-connection"
    )
}

fn request_target(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    }
}

fn read_response_headers<S: Read>(
    stream: &mut S,
    url: &Url,
    deadline: Instant,
) -> Result<(u16, BTreeMap<String, String>), HttpTransportError> {
    let mut bytes = Vec::with_capacity(4096);
    let mut one = [0_u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() >= 64 * 1024 {
            return Err(HttpTransportError::Request {
                url: redact_url(url),
                message: "response headers exceed 64 KiB".to_owned(),
            });
        }
        let count = stream
            .read(&mut one)
            .map_err(|error| classify_io_error(error, url, "reading response headers"))?;
        if count == 0 {
            return Err(HttpTransportError::Request {
                url: redact_url(url),
                message: "unexpected EOF while reading response headers".to_owned(),
            });
        }
        bytes.push(one[0]);
        if Instant::now() >= deadline {
            return Err(HttpTransportError::Request {
                url: redact_url(url),
                message: "response header timeout".to_owned(),
            });
        }
    }
    let text = std::str::from_utf8(&bytes[..bytes.len() - 4]).map_err(|error| {
        HttpTransportError::Request {
            url: redact_url(url),
            message: format!("response headers are not UTF-8: {error}"),
        }
    })?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| HttpTransportError::Request {
        url: redact_url(url),
        message: "response is missing a status line".to_owned(),
    })?;
    let mut status_parts = status_line.split_whitespace();
    let version = status_parts.next().unwrap_or_default();
    let status = status_parts
        .next()
        .ok_or_else(|| HttpTransportError::Request {
            url: redact_url(url),
            message: "response status line is malformed".to_owned(),
        })?
        .parse::<u16>()
        .map_err(|error| HttpTransportError::Request {
            url: redact_url(url),
            message: format!("response status is malformed: {error}"),
        })?;
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return Err(HttpTransportError::Request {
            url: redact_url(url),
            message: format!("unsupported HTTP response version {version:?}"),
        });
    }
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| HttpTransportError::Request {
                url: redact_url(url),
                message: "response header is malformed".to_owned(),
            })?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if !valid_header_name(&name) || !valid_header_value(value) {
            return Err(HttpTransportError::Request {
                url: redact_url(url),
                message: "response header name or value is invalid".to_owned(),
            });
        }
        if let Some(existing) = headers.get_mut(&name) {
            if matches!(name.as_str(), "content-length" | "transfer-encoding") {
                return Err(HttpTransportError::Request {
                    url: redact_url(url),
                    message: format!("response contains duplicate {name} header"),
                });
            }
            existing.push_str(", ");
            existing.push_str(value);
        } else {
            headers.insert(name, value.to_owned());
        }
    }
    Ok((status, headers))
}

fn read_response_body<S: Read>(
    stream: &mut S,
    status: u16,
    headers: &BTreeMap<String, String>,
    limit: usize,
    url: &Url,
    deadline: Instant,
) -> Result<Vec<u8>, HttpTransportError> {
    if status == 204 || status == 304 {
        return Ok(Vec::new());
    }
    let content_length = header_value(headers, "content-length");
    let transfer_encoding = header_value(headers, "transfer-encoding");
    if content_length.is_some() && transfer_encoding.is_some() {
        return Err(HttpTransportError::Request {
            url: redact_url(url),
            message: "response has both Content-Length and Transfer-Encoding".to_owned(),
        });
    }
    if transfer_encoding.is_some_and(|value| !value.eq_ignore_ascii_case("chunked")) {
        return Err(HttpTransportError::Request {
            url: redact_url(url),
            message: "unsupported response transfer encoding".to_owned(),
        });
    }
    if let Some(length) = content_length {
        let length = length
            .parse::<usize>()
            .map_err(|error| HttpTransportError::Request {
                url: redact_url(url),
                message: format!("response Content-Length is malformed: {error}"),
            })?;
        let mut body = vec![0_u8; length.min(limit)];
        read_exact_deadline(stream, &mut body, url, deadline)?;
        return Ok(body);
    }
    if transfer_encoding.is_some() {
        return read_chunked_body(stream, limit, url, deadline);
    }
    let connection_close = header_value(headers, "connection").is_some_and(|value| {
        value
            .split(',')
            .any(|item| item.trim().eq_ignore_ascii_case("close"))
    });
    if !connection_close {
        return Err(HttpTransportError::Request {
            url: redact_url(url),
            message: "response body has no framing or connection close".to_owned(),
        });
    }
    let mut body = Vec::with_capacity(limit);
    let mut buffer = [0_u8; 8192];
    while body.len() < limit {
        let wanted = (limit - body.len()).min(buffer.len());
        match stream.read(&mut buffer[..wanted]) {
            Ok(0) => break,
            Ok(count) => body.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(classify_io_error(error, url, "reading response body")),
        }
        if Instant::now() >= deadline {
            return Err(HttpTransportError::Request {
                url: redact_url(url),
                message: "response body timeout".to_owned(),
            });
        }
    }
    Ok(body)
}

fn read_chunked_body<S: Read>(
    stream: &mut S,
    limit: usize,
    url: &Url,
    deadline: Instant,
) -> Result<Vec<u8>, HttpTransportError> {
    let mut body = Vec::with_capacity(limit);
    loop {
        let line = read_line(stream, url, deadline)?;
        let size = line
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .strip_prefix("0x")
            .unwrap_or_else(|| line.split(';').next().unwrap_or_default().trim());
        let size =
            usize::from_str_radix(size, 16).map_err(|error| HttpTransportError::Request {
                url: redact_url(url),
                message: format!("chunk size is malformed: {error}"),
            })?;
        if size == 0 {
            loop {
                if read_line(stream, url, deadline)?.is_empty() {
                    return Ok(body);
                }
            }
        }
        let keep = size.min(limit.saturating_sub(body.len()));
        let mut chunk = vec![0_u8; keep];
        read_exact_deadline(stream, &mut chunk, url, deadline)?;
        body.extend_from_slice(&chunk);
        if keep < size || body.len() == limit {
            return Ok(body);
        }
        let terminator = read_line(stream, url, deadline)?;
        if !terminator.is_empty() {
            return Err(HttpTransportError::Request {
                url: redact_url(url),
                message: "chunk terminator is malformed".to_owned(),
            });
        }
    }
}

fn read_line<S: Read>(
    stream: &mut S,
    url: &Url,
    deadline: Instant,
) -> Result<String, HttpTransportError> {
    let mut bytes = Vec::new();
    let mut one = [0_u8; 1];
    loop {
        read_exact_deadline(stream, &mut one, url, deadline)?;
        if one[0] == b'\n' {
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
            return String::from_utf8(bytes).map_err(|error| HttpTransportError::Request {
                url: redact_url(url),
                message: format!("response line is not UTF-8: {error}"),
            });
        }
        bytes.push(one[0]);
        if bytes.len() > 64 * 1024 {
            return Err(HttpTransportError::Request {
                url: redact_url(url),
                message: "response line exceeds 64 KiB".to_owned(),
            });
        }
    }
}

fn read_exact_deadline<S: Read>(
    stream: &mut S,
    buffer: &mut [u8],
    url: &Url,
    deadline: Instant,
) -> Result<(), HttpTransportError> {
    let mut offset = 0;
    while offset < buffer.len() {
        match stream.read(&mut buffer[offset..]) {
            Ok(0) => {
                return Err(HttpTransportError::Request {
                    url: redact_url(url),
                    message: "unexpected EOF while reading response body".to_owned(),
                });
            }
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(HttpTransportError::Request {
                    url: redact_url(url),
                    message: "unexpected EOF while reading response body".to_owned(),
                });
            }
            Err(error) => return Err(classify_io_error(error, url, "reading response body")),
        }
        if Instant::now() >= deadline {
            return Err(HttpTransportError::Request {
                url: redact_url(url),
                message: "response body timeout".to_owned(),
            });
        }
    }
    Ok(())
}

fn header_value<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn validate_origin(origin: &Url) -> Result<(), HttpTransportError> {
    if origin.host_str().is_none() {
        return Err(HttpTransportError::InvalidOrigin(SafeUrlError::Invalid(
            "origin has no host".to_owned(),
        )));
    }
    if origin.username() != "" || origin.password().is_some() {
        return Err(HttpTransportError::InvalidOrigin(
            SafeUrlError::CredentialsNotAllowed,
        ));
    }
    if origin.path() != "/" || origin.query().is_some() || origin.fragment().is_some() {
        return Err(HttpTransportError::InvalidOrigin(SafeUrlError::Invalid(
            "origin must not contain a path, query, or fragment".to_owned(),
        )));
    }
    if !matches!(origin.scheme(), "http" | "https") {
        return Err(HttpTransportError::InvalidOrigin(
            SafeUrlError::UnsupportedScheme(origin.scheme().to_owned()),
        ));
    }
    Ok(())
}

fn resolve_local_origin(origin: &Url) -> Result<(String, Vec<SocketAddr>), HttpTransportError> {
    let host = origin.host_str().ok_or_else(|| {
        HttpTransportError::InvalidOrigin(SafeUrlError::Invalid("origin has no host".to_owned()))
    })?;
    let port = origin.port_or_known_default().ok_or_else(|| {
        HttpTransportError::InvalidOrigin(SafeUrlError::Invalid("origin has no port".to_owned()))
    })?;
    let addresses: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|error| {
            HttpTransportError::InvalidOrigin(SafeUrlError::Invalid(format!(
                "could not resolve configured origin: {error}"
            )))
        })?
        .collect();
    if addresses.is_empty() {
        return Err(HttpTransportError::InvalidOrigin(SafeUrlError::Invalid(
            "configured origin resolved to no addresses".to_owned(),
        )));
    }
    if addresses
        .iter()
        .any(|address| !is_local_address(address.ip()))
    {
        return Err(HttpTransportError::InvalidOrigin(SafeUrlError::Invalid(
            "configured origin resolves outside private/local address space".to_owned(),
        )));
    }
    Ok((host.to_owned(), addresses))
}

fn is_local_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private() || address.is_loopback() || address.is_link_local()
        }
        IpAddr::V6(address) => address.to_ipv4_mapped().map_or_else(
            || {
                address.is_unique_local()
                    || address.is_loopback()
                    || address.is_unicast_link_local()
            },
            |address| address.is_private() || address.is_loopback() || address.is_link_local(),
        ),
    }
}

fn pin_key(origin: &Url) -> String {
    origin.host_str().unwrap_or_default().to_owned()
}

fn fallback_url(url: &Url) -> Result<Url, HttpTransportError> {
    let port = url.port_or_known_default();
    let fallback_port = match port {
        Some(49443) => 49000,
        Some(443) => 80,
        _ => {
            return Err(HttpTransportError::InvalidRequestUrl {
                url: redact_url(url),
                source: SafeUrlError::Invalid("no supported HTTPS fallback port".to_owned()),
            });
        }
    };
    let mut fallback = url.clone();
    fallback
        .set_scheme("http")
        .map_err(|()| HttpTransportError::InvalidRequestUrl {
            url: redact_url(url),
            source: SafeUrlError::Invalid("could not set HTTP fallback scheme".to_owned()),
        })?;
    fallback
        .set_port(Some(fallback_port))
        .map_err(|()| HttpTransportError::InvalidRequestUrl {
            url: redact_url(url),
            source: SafeUrlError::Invalid("could not set HTTP fallback port".to_owned()),
        })?;
    Ok(fallback)
}

fn is_endpoint_unreachable(error: &HttpTransportError) -> bool {
    matches!(error, HttpTransportError::EndpointUnavailable { .. })
}

/// Classifies transport text when a concrete error chain is unavailable.
/// Certificate and TLS failures always win over connectivity wording.
#[must_use]
pub fn endpoint_unreachable_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    if lower.contains("certificate")
        || lower.contains("tls")
        || lower.contains("handshake")
        || lower.contains("invalid peer")
        || lower.contains("unknown issuer")
    {
        return false;
    }
    lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("connection refused")
        || lower.contains("host is unreachable")
        || lower.contains("network is unreachable")
        || lower.contains("no route to host")
}

#[derive(Debug)]
struct TofuVerifier {
    provider: Arc<CryptoProvider>,
    pin_store: PinStore,
    pin_key: String,
}

#[derive(Debug)]
struct InsecureVerifier {
    provider: Arc<CryptoProvider>,
}

fn verify_pin(
    end_entity: &CertificateDer<'_>,
    store: &PinStore,
    key: &str,
) -> Result<ServerCertVerified, rustls::Error> {
    if let Some(error) = store.load_error() {
        return Err(rustls::Error::General(format!(
            "failed to load certificate pins: {error}"
        )));
    }
    let pin = calculate_spki_pin(end_entity.as_ref())
        .map_err(|error| rustls::Error::General(format!("invalid server certificate: {error}")))?;
    match store.get(key) {
        Some(expected) if expected != pin => Err(rustls::Error::General(format!(
            "certificate pin mismatch for {key}"
        ))),
        Some(_) => Ok(ServerCertVerified::assertion()),
        None => Ok(ServerCertVerified::assertion()),
    }
}

fn verify_tls12(
    provider: &CryptoProvider,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    crypto::verify_tls12_signature(
        message,
        cert,
        dss,
        &provider.signature_verification_algorithms,
    )
}

fn verify_tls13(
    provider: &CryptoProvider,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    crypto::verify_tls13_signature(
        message,
        cert,
        dss,
        &provider.signature_verification_algorithms,
    )
}

macro_rules! signature_verifier_impl {
    ($type:ty, $verify:expr) => {
        impl ServerCertVerifier for $type {
            fn verify_server_cert(
                &self,
                end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp_response: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                $verify(self, end_entity)
            }

            fn verify_tls12_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                verify_tls12(&self.provider, message, cert, dss)
            }

            fn verify_tls13_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                verify_tls13(&self.provider, message, cert, dss)
            }

            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                self.provider
                    .signature_verification_algorithms
                    .supported_schemes()
            }
        }
    };
}

signature_verifier_impl!(
    TofuVerifier,
    |verifier: &TofuVerifier, certificate: &CertificateDer<'_>| {
        verify_pin(certificate, &verifier.pin_store, &verifier.pin_key)
    }
);
signature_verifier_impl!(
    InsecureVerifier,
    |_verifier: &InsecureVerifier, _certificate: &CertificateDer<'_>| {
        Ok(ServerCertVerified::assertion())
    }
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, sync::Mutex};

    #[test]
    fn fallback_classifier_rejects_tls_and_accepts_refused() {
        assert!(is_endpoint_unreachable(
            &HttpTransportError::EndpointUnavailable {
                url: "https://fritz.box:49443".to_owned(),
                message: "error sending request: connection refused".to_owned(),
            }
        ));
        assert!(is_endpoint_unreachable(
            &HttpTransportError::EndpointUnavailable {
                url: "https://fritz.box:49443".to_owned(),
                message: "tcp connect error: network is unreachable".to_owned(),
            }
        ));
        assert!(!is_endpoint_unreachable(&HttpTransportError::Request {
            url: "https://fritz.box:49443".to_owned(),
            message: "error: certificate pin mismatch".to_owned(),
        }));
        assert!(!is_endpoint_unreachable(&HttpTransportError::Request {
            url: "https://fritz.box:49443".to_owned(),
            message: "response body read timed out".to_owned(),
        }));
        let url = Url::parse("https://fritz.box:49443").unwrap();
        assert!(is_endpoint_unreachable(&classify_io_error(
            io::Error::new(io::ErrorKind::TimedOut, "timed out"),
            &url,
            "connecting",
        )));
        assert!(!is_endpoint_unreachable(&classify_io_error(
            io::Error::new(io::ErrorKind::TimedOut, "timed out"),
            &url,
            "reading response headers",
        )));
    }

    #[test]
    fn request_headers_cannot_inject_lines_or_override_framing() {
        let url = Url::parse("https://fritz.box:49443/health").unwrap();
        for (name, value) in [
            ("X-Test\r\nInjected", "value"),
            ("X-Test", "value\r\nInjected: true"),
            ("Content-Length", "0"),
            ("Transfer-Encoding", "chunked"),
            ("Host", "attacker.invalid"),
        ] {
            let request = Request {
                method: Method::Get,
                url: url.to_string(),
                headers: BTreeMap::from([(name.to_owned(), value.to_owned())]),
                body: Vec::new(),
                response_limit: 1024,
            };
            let mut wire = Vec::new();
            assert!(write_request(&mut wire, &request, &url, Instant::now()).is_err());
            assert!(wire.is_empty());
        }
    }

    #[test]
    fn response_rejects_duplicate_or_conflicting_framing_headers() {
        let url = Url::parse("https://fritz.box:49443/health").unwrap();
        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\ncontent-length: 1\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"
                .as_slice(),
        ] {
            let mut input = io::Cursor::new(response);
            let result =
                read_response_headers(&mut input, &url, Instant::now() + Duration::from_secs(1));
            if response
                .windows(14)
                .any(|part| part.eq_ignore_ascii_case(b"content-length"))
                && response
                    .windows(17)
                    .any(|part| part.eq_ignore_ascii_case(b"transfer-encoding"))
            {
                let (status, headers) = result.unwrap();
                assert_eq!(status, 200);
                assert!(
                    read_response_body(
                        &mut input,
                        status,
                        &headers,
                        1024,
                        &url,
                        Instant::now() + Duration::from_secs(1),
                    )
                    .is_err()
                );
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn oversized_chunk_stops_at_response_limit_without_discard_allocation() {
        let url = Url::parse("https://fritz.box:49443/health").unwrap();
        let mut input = io::Cursor::new(b"ffffffffffffffff\r\n0123456789abcdef".as_slice());
        let body = read_chunked_body(
            &mut input,
            16,
            &url,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(body, b"0123456789abcdef");
    }

    #[test]
    fn pin_key_matches_go_host_only_storage() {
        assert_eq!(
            pin_key(&Url::parse("https://fritz.box:49443").unwrap()),
            "fritz.box"
        );
    }

    #[test]
    fn public_origin_is_rejected_before_client_creation() {
        let path = std::env::temp_dir().join("symfritz-public-origin-pins.json");
        let _ = fs::remove_file(&path);
        let result = BlockingHttpTransport::new(HttpTransportConfig::new(
            Url::parse("https://8.8.8.8:49443").unwrap(),
            PinStore::new(&path),
        ));
        assert!(matches!(result, Err(HttpTransportError::InvalidOrigin(_))));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn one_warning_sink_is_called_only_once() {
        let calls = Arc::new(Mutex::new(0));
        let sink_calls = calls.clone();
        let path = std::env::temp_dir().join("symfritz-transport-test-pins.json");
        let _ = fs::remove_file(&path);
        let config = HttpTransportConfig::new(
            Url::parse("https://127.0.0.1:49443").unwrap(),
            PinStore::new(&path),
        )
        .with_warning_sink(Arc::new(move |_| *sink_calls.lock().unwrap() += 1));
        let transport = BlockingHttpTransport::new(config).unwrap();
        transport.warn_once();
        transport.warn_once();
        assert_eq!(*calls.lock().unwrap(), 1);
        let _ = fs::remove_file(path);
    }
}
