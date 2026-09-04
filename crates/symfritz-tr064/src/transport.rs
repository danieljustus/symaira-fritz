//! Concrete bounded blocking HTTP/TLS transport for the TR-064 engine.

use std::{
    fmt,
    io::Read,
    sync::{
        Arc, Once,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use reqwest::blocking::{Client, ClientBuilder};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{self, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use symfritz_core::pins::{PinStore, calculate_spki_pin};
use url::Url;

use crate::safeurl::{SafeUrlError, redact_url, validate_request_url};
use crate::{Method, Request, Response, Transport, TransportError};

/// Default maximum response size for a concrete transport.
pub const DEFAULT_RESPONSE_LIMIT: usize = 4 << 20;

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
    Request { url: String, message: String },
    ResponseTooLarge { limit: usize },
}

impl fmt::Display for HttpTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOrigin(error) => write!(formatter, "invalid configured origin: {error}"),
            Self::InvalidRequestUrl { url, source } => {
                write!(formatter, "unsafe request URL {url}: {source}")
            }
            Self::Request { url, message } => {
                write!(formatter, "request to {url} failed: {message}")
            }
            Self::ResponseTooLarge { limit } => {
                write!(formatter, "response exceeds {limit}-byte limit")
            }
        }
    }
}

impl std::error::Error for HttpTransportError {}

/// A synchronous reqwest adapter with strict origin checks, TOFU and fallback.
pub struct BlockingHttpTransport {
    client: Client,
    origin: Url,
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
        let provider = Arc::new(crypto::ring::default_provider());
        let verifier: Arc<dyn ServerCertVerifier> = if config.insecure_tls {
            Arc::new(InsecureVerifier {
                provider: provider.clone(),
            })
        } else {
            Arc::new(TofuVerifier {
                provider: provider.clone(),
                pin_store: config.pin_store.clone(),
                pin_key: pin_key(&config.origin),
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
            .timeout(config.timeout)
            .use_preconfigured_tls(tls_config)
            .build()
            .map_err(|error| HttpTransportError::Request {
                url: redact_url(&config.origin),
                message: error.to_string(),
            })?;
        Ok(Self {
            client,
            origin: config.origin.clone(),
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
            .map_err(|error| HttpTransportError::Request {
                url: redact_url(url),
                message: error.to_string(),
            })?;
        let limit = request.response_limit.min(DEFAULT_RESPONSE_LIMIT);
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            return Err(HttpTransportError::ResponseTooLarge { limit });
        }
        let mut body = Vec::new();
        response
            .by_ref()
            .take((limit as u64).saturating_add(1))
            .read_to_end(&mut body)
            .map_err(|error| HttpTransportError::Request {
                url: redact_url(url),
                message: error.to_string(),
            })?;
        if body.len() > limit {
            return Err(HttpTransportError::ResponseTooLarge { limit });
        }
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
}

impl Transport for BlockingHttpTransport {
    fn send(&mut self, request: Request) -> Result<Response, TransportError> {
        let requested = Url::parse(&request.url).map_err(|error| {
            TransportError(
                HttpTransportError::Request {
                    url: safe_raw_url(&request.url),
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

fn safe_raw_url(raw: &str) -> String {
    Url::parse(raw)
        .map(|url| redact_url(&url))
        .unwrap_or_else(|_| "<invalid URL>".to_owned())
}

fn validate_origin(origin: &Url) -> Result<(), HttpTransportError> {
    if origin.host_str().is_none() || origin.username() != "" || origin.password().is_some() {
        return Err(HttpTransportError::InvalidOrigin(
            SafeUrlError::CredentialsNotAllowed,
        ));
    }
    if !matches!(origin.scheme(), "http" | "https") {
        return Err(HttpTransportError::InvalidOrigin(
            SafeUrlError::UnsupportedScheme(origin.scheme().to_owned()),
        ));
    }
    if origin.path() != "" && origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(HttpTransportError::InvalidOrigin(SafeUrlError::Invalid(
            "origin must not contain a path, query, or fragment".to_owned(),
        )));
    }
    Ok(())
}

fn pin_key(origin: &Url) -> String {
    origin
        .host_str()
        .map(|host| match origin.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        })
        .unwrap_or_default()
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
    let HttpTransportError::Request { message, .. } = error else {
        return false;
    };
    let lower = message.to_ascii_lowercase();
    if lower.contains("certificate")
        || lower.contains("tls")
        || lower.contains("handshake")
        || lower.contains("invalid peer")
        || lower.contains("unknown issuer")
    {
        return false;
    }
    lower.contains("timed out") || lower.contains("timeout") || lower.contains("connection refused")
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
    let pin = calculate_spki_pin(end_entity.as_ref())
        .map_err(|error| rustls::Error::General(format!("invalid server certificate: {error}")))?;
    match store.get(key) {
        Some(expected) if expected != pin => Err(rustls::Error::General(format!(
            "certificate pin mismatch for {key}"
        ))),
        Some(_) => Ok(ServerCertVerified::assertion()),
        None => {
            store.set(key.to_owned(), pin).map_err(|error| {
                rustls::Error::General(format!("failed to record certificate pin: {error}"))
            })?;
            Ok(ServerCertVerified::assertion())
        }
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
        assert!(is_endpoint_unreachable(&HttpTransportError::Request {
            url: "https://fritz.box:49443".to_owned(),
            message: "error sending request: connection refused".to_owned(),
        }));
        assert!(!is_endpoint_unreachable(&HttpTransportError::Request {
            url: "https://fritz.box:49443".to_owned(),
            message: "error: certificate pin mismatch".to_owned(),
        }));
        assert!(!is_endpoint_unreachable(
            &HttpTransportError::ResponseTooLarge { limit: 1 }
        ));
    }

    #[test]
    fn one_warning_sink_is_called_only_once() {
        let calls = Arc::new(Mutex::new(0));
        let sink_calls = calls.clone();
        let path = std::env::temp_dir().join("symfritz-transport-test-pins.json");
        let _ = fs::remove_file(&path);
        let config = HttpTransportConfig::new(
            Url::parse("https://fritz.box:49443").unwrap(),
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
