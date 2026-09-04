//! Concrete bounded blocking HTTP/TLS transport for the TR-064 engine.

use std::{
    fmt,
    io::Read,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::{
        Arc, Once,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use reqwest::blocking::{Client, ClientBuilder};
use reqwest::redirect::Policy;
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{self, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use symfritz_core::pins::{PinStore, calculate_spki_pin};
use url::Url;

use crate::safeurl::{SafeUrlError, redact_raw_url, redact_url, validate_request_url};
use crate::{Method, Request, Response, Transport, TransportError};

/// Default maximum response size for a concrete transport.
pub const DEFAULT_RESPONSE_LIMIT: usize = 5 << 20;

/// Optional diagnostic sink used for the single fallback warning.
pub type WarningSink = Arc<dyn Fn(&str) + Send + Sync>;

/// Configuration for [`BlockingHttpTransport`].
#[derive(Clone)]
pub struct HttpTransportConfig {
    pub origin: Url,
    pub pin_store: PinStore,
    pub insecure_tls: bool,
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

/// A synchronous reqwest adapter with strict origin checks, TOFU and fallback.
pub struct BlockingHttpTransport {
    client: Client,
    origin: Url,
    pin_store: PinStore,
    pin_key: String,
    insecure_tls: bool,
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
            .field("tls_enabled", &self.tls_enabled.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl BlockingHttpTransport {
    /// Builds a transport. HTTPS always uses either TOFU or explicit insecure mode.
    pub fn new(config: HttpTransportConfig) -> Result<Self, HttpTransportError> {
        validate_origin(&config.origin)?;
        let (resolved_host, resolved_addresses) = resolve_local_origin(&config.origin)?;
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
        let client = ClientBuilder::new()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(config.timeout)
            .tls_info(true)
            .resolve_to_addrs(&resolved_host, &resolved_addresses)
            .use_preconfigured_tls(tls_config)
            .build()
            .map_err(|error| HttpTransportError::Request {
                url: redact_url(&config.origin),
                message: error_chain(&error),
            })?;
        Ok(Self {
            client,
            origin: config.origin.clone(),
            pin_store: config.pin_store,
            pin_key,
            insecure_tls: config.insecure_tls,
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
                "warning: TLS endpoint on {} did not answer, falling back to HTTP (set use_tls = false to silence)",
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
        let method = match request.method {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
        };
        let mut builder = self.client.request(method, url.clone());
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        if !request.body.is_empty() {
            builder = builder.body(request.body.clone());
        }
        let mut response = builder
            .send()
            .map_err(|error| classify_send_error(&error, url))?;
        if url.scheme() == "https" && !self.insecure_tls {
            self.record_peer_pin(url, &response)?;
        }
        let limit = request.response_limit.min(DEFAULT_RESPONSE_LIMIT);
        let mut body = Vec::with_capacity(limit);
        response
            .by_ref()
            .take(limit as u64)
            .read_to_end(&mut body)
            .map_err(|error| HttpTransportError::Request {
                url: redact_url(url),
                message: error.to_string(),
            })?;
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect();
        Ok(Response {
            status: response.status().as_u16(),
            headers,
            body,
        })
    }

    fn record_peer_pin(
        &self,
        url: &Url,
        response: &reqwest::blocking::Response,
    ) -> Result<(), HttpTransportError> {
        let certificate = response
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .and_then(reqwest::tls::TlsInfo::peer_certificate)
            .ok_or_else(|| HttpTransportError::Request {
                url: redact_url(url),
                message: "TLS peer certificate is unavailable".to_owned(),
            })?;
        let pin = calculate_spki_pin(certificate).map_err(|error| HttpTransportError::Request {
            url: redact_url(url),
            message: format!("invalid server certificate: {error}"),
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
        let target = if tls_attempt {
            requested.clone()
        } else if requested.scheme() == "https" {
            fallback_url(&requested).map_err(|error| TransportError(error.to_string()))?
        } else {
            requested.clone()
        };
        match self.execute(&request, &target) {
            Ok(response) => Ok(response),
            Err(error) if tls_attempt && is_endpoint_unreachable(&error) => {
                let fallback =
                    fallback_url(&requested).map_err(|error| TransportError(error.to_string()))?;
                self.warn_once();
                self.tls_enabled.store(false, Ordering::Release);
                self.execute(&request, &fallback)
                    .map_err(|error| TransportError(error.to_string()))
            }
            Err(error) => Err(TransportError(error.to_string())),
        }
    }
}

fn error_chain(error: &dyn std::error::Error) -> String {
    let mut messages = vec![error.to_string()];
    let mut source = error.source();
    while let Some(error) = source {
        messages.push(error.to_string());
        source = error.source();
    }
    messages.join(": ")
}

fn redact_error_chain(error: &dyn std::error::Error, url: &Url) -> String {
    error_chain(error).replace(url.as_str(), &redact_url(url))
}

fn classify_send_error(error: &reqwest::Error, url: &Url) -> HttpTransportError {
    let message = redact_error_chain(error, url);
    let url = redact_url(url);
    if endpoint_unreachable_message(&message) {
        HttpTransportError::EndpointUnavailable { url, message }
    } else {
        HttpTransportError::Request { url, message }
    }
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
