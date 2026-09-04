//! URL-origin validation and diagnostic redaction for router requests.

use std::{error::Error, fmt};
use url::Url;

/// URL policy failures are deliberately descriptive but never include secrets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SafeUrlError {
    Invalid(String),
    CredentialsNotAllowed,
    OriginMismatch { expected: String, actual: String },
    UnsupportedScheme(String),
}

impl fmt::Display for SafeUrlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid URL: {message}"),
            Self::CredentialsNotAllowed => formatter.write_str("URL userinfo is not allowed"),
            Self::OriginMismatch { expected, actual } => {
                write!(
                    formatter,
                    "URL origin {actual} is outside configured origin {expected}"
                )
            }
            Self::UnsupportedScheme(scheme) => {
                write!(formatter, "unsupported URL scheme {scheme:?}")
            }
        }
    }
}

impl Error for SafeUrlError {}

/// Checks that a request targets the configured router origin.
///
/// Hostnames are compared case-insensitively and schemes/ports explicitly.
/// Plaintext fallback URLs are generated only inside the transport after a
/// classified endpoint failure; callers cannot request a downgrade directly.
pub fn validate_request_url(
    configured_origin: &Url,
    request_url: &Url,
) -> Result<(), SafeUrlError> {
    if configured_origin.username() != "" || configured_origin.password().is_some() {
        return Err(SafeUrlError::CredentialsNotAllowed);
    }
    if request_url.username() != "" || request_url.password().is_some() {
        return Err(SafeUrlError::CredentialsNotAllowed);
    }
    if !matches!(request_url.scheme(), "http" | "https") {
        return Err(SafeUrlError::UnsupportedScheme(
            request_url.scheme().to_owned(),
        ));
    }
    let same_host = configured_origin
        .host_str()
        .zip(request_url.host_str())
        .is_some_and(|(expected, actual)| expected.eq_ignore_ascii_case(actual));
    if !same_host {
        return Err(SafeUrlError::OriginMismatch {
            expected: redact_url(configured_origin),
            actual: redact_url(request_url),
        });
    }

    let expected_port = configured_origin.port_or_known_default();
    let actual_port = request_url.port_or_known_default();
    let same_origin =
        configured_origin.scheme() == request_url.scheme() && expected_port == actual_port;
    if !same_origin {
        return Err(SafeUrlError::OriginMismatch {
            expected: redact_url(configured_origin),
            actual: redact_url(request_url),
        });
    }
    Ok(())
}

/// Removes userinfo and redacts values of credential/session query keys.
#[must_use]
pub fn redact_url(url: &Url) -> String {
    let mut safe = url.clone();
    let _ = safe.set_username("");
    let _ = safe.set_password(None);
    let sensitive = [
        "sid",
        "response",
        "password",
        "pass",
        "secret",
        "token",
        "authorization",
    ];
    let pairs: Vec<(String, String)> = safe
        .query_pairs()
        .map(|(key, value)| {
            if sensitive.iter().any(|name| key.eq_ignore_ascii_case(name)) {
                (key.into_owned(), "REDACTED".to_owned())
            } else {
                (key.into_owned(), value.into_owned())
            }
        })
        .collect();
    if safe.query().is_some() {
        safe.query_pairs_mut().clear().extend_pairs(pairs);
    }
    safe.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_userinfo_and_sensitive_queries() {
        let url = Url::parse("https://admin:secret@fritz.box:49443/call?sid=abc&foo=bar").unwrap();
        let redacted = redact_url(&url);
        assert!(!redacted.contains("admin"));
        assert!(!redacted.contains("secret"));
        assert!(!redacted.contains("abc"));
        assert!(redacted.contains("sid=REDACTED"));
        assert!(redacted.contains("foo=bar"));
    }

    #[test]
    fn rejects_caller_requested_tls_downgrade() {
        let origin = Url::parse("https://fritz.box:49443").unwrap();
        assert!(
            validate_request_url(&origin, &Url::parse("https://FRITZ.BOX:49443/x").unwrap())
                .is_ok()
        );
        assert!(
            validate_request_url(&origin, &Url::parse("http://fritz.box:49000/x").unwrap())
                .is_err()
        );
        assert!(
            validate_request_url(&origin, &Url::parse("http://other:49000/x").unwrap()).is_err()
        );
        assert!(
            validate_request_url(&origin, &Url::parse("http://fritz.box:80/x").unwrap()).is_err()
        );
    }
}
