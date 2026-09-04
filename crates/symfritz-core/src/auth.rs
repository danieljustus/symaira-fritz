use std::{error::Error, fmt};

use md5::{Digest, Md5};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

/// A parsed HTTP Digest challenge.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
    pub qop: String,
    pub algorithm: String,
    pub opaque: String,
}

/// Errors preserved from the Go session challenge implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeError {
    EmptyChallenge,
    MalformedPbkdf2Challenge,
    MalformedPbkdf2IterationCount,
    MalformedPbkdf2Salt,
}

impl fmt::Display for ChallengeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyChallenge => "empty challenge from box",
            Self::MalformedPbkdf2Challenge => "malformed PBKDF2 challenge",
            Self::MalformedPbkdf2IterationCount => "malformed PBKDF2 iteration count",
            Self::MalformedPbkdf2Salt => "malformed PBKDF2 salt",
        };
        formatter.write_str(message)
    }
}

impl Error for ChallengeError {}

/// Compute the FRITZ!Box response for a legacy or modern login challenge.
///
/// The legacy algorithm is required by older FRITZ!OS releases and hashes the
/// UTF-16LE encoding of `challenge-password` with MD5.
///
/// ```
/// use symfritz_core::auth::challenge_response;
///
/// assert_eq!(
///     challenge_response("1234567z", "äbc").unwrap(),
///     "1234567z-9e224a41eeefa284df7bb0f26c2913e2"
/// );
/// ```
pub fn challenge_response(challenge: &str, password: &str) -> Result<String, ChallengeError> {
    if challenge.is_empty() {
        return Err(ChallengeError::EmptyChallenge);
    }
    if challenge.starts_with("2$") {
        return pbkdf2_response(challenge, password);
    }
    Ok(legacy_md5_response(challenge, password))
}

fn legacy_md5_response(challenge: &str, password: &str) -> String {
    let clear = format!("{challenge}-{password}");
    let mut utf16le = Vec::with_capacity(clear.len() * 2);
    for code_unit in clear.encode_utf16() {
        utf16le.extend_from_slice(&code_unit.to_le_bytes());
    }
    format!("{challenge}-{}", md5_hex(&utf16le))
}

fn pbkdf2_response(challenge: &str, password: &str) -> Result<String, ChallengeError> {
    let parts: Vec<_> = challenge.split('$').collect();
    if parts.len() != 5 {
        return Err(ChallengeError::MalformedPbkdf2Challenge);
    }

    let iterations_1 = parts[1]
        .parse::<i64>()
        .map_err(|_| ChallengeError::MalformedPbkdf2IterationCount)?;
    let iterations_2 = parts[3]
        .parse::<i64>()
        .map_err(|_| ChallengeError::MalformedPbkdf2IterationCount)?;
    let iterations_1 = u32::try_from(iterations_1.max(0))
        .map_err(|_| ChallengeError::MalformedPbkdf2IterationCount)?;
    let iterations_2 = u32::try_from(iterations_2.max(0))
        .map_err(|_| ChallengeError::MalformedPbkdf2IterationCount)?;

    let salt_1 = hex::decode(parts[2]).map_err(|_| ChallengeError::MalformedPbkdf2Salt)?;
    let salt_2 = hex::decode(parts[4]).map_err(|_| ChallengeError::MalformedPbkdf2Salt)?;

    let mut hash_1 = [0_u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt_1, iterations_1, &mut hash_1);
    let mut hash_2 = [0_u8; 32];
    pbkdf2_hmac::<Sha256>(&hash_1, &salt_2, iterations_2, &mut hash_2);

    Ok(format!("{}${}", parts[4], hex::encode(hash_2)))
}

/// Parse a `WWW-Authenticate` value using the Go implementation's rules.
///
/// The boolean is false when the Digest prefix or nonce is absent. The parsed
/// fields are still returned because the Go parser exposes them to its caller.
pub fn parse_digest_challenge(header: &str) -> (DigestChallenge, bool) {
    const PREFIX: &str = "Digest ";
    let Some(index) = header.find(PREFIX) else {
        return (DigestChallenge::default(), false);
    };

    let mut challenge = DigestChallenge::default();
    for part in split_digest_fields(&header[index + PREFIX.len()..]) {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_owned();
        match key.trim() {
            "realm" => challenge.realm = value,
            "nonce" => challenge.nonce = value,
            "qop" => challenge.qop = value,
            "algorithm" => challenge.algorithm = value,
            "opaque" => challenge.opaque = value,
            _ => {}
        }
    }
    let valid = !challenge.nonce.is_empty();
    (challenge, valid)
}

fn split_digest_fields(value: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    for character in value.chars() {
        match character {
            '"' => {
                in_quote = !in_quote;
                current.push(character);
            }
            ',' if !in_quote => {
                fields.push(current);
                current = String::new();
            }
            _ => current.push(character),
        }
    }
    if !current.is_empty() {
        fields.push(current);
    }
    fields
}

/// Build a deterministic HTTP Digest Authorization header.
///
/// Production callers must provide a fresh cryptographically random cnonce.
/// Tests pass a fixed value so Go↔Rust wire bytes can be compared exactly.
pub fn digest_authorization_header(
    challenge: &DigestChallenge,
    user: &str,
    password: &str,
    method: &str,
    uri: &str,
    nonce_count: u32,
    cnonce: &str,
) -> String {
    let nonce_count = format!("{nonce_count:08x}");
    let ha1 = md5_hex(format!("{user}:{}:{password}", challenge.realm).as_bytes());
    let ha2 = md5_hex(format!("{method}:{uri}").as_bytes());
    let use_auth = qop_offers_auth(&challenge.qop);

    let response = if use_auth {
        md5_hex(
            format!(
                "{ha1}:{}:{nonce_count}:{cnonce}:auth:{ha2}",
                challenge.nonce
            )
            .as_bytes(),
        )
    } else {
        md5_hex(format!("{ha1}:{}:{ha2}", challenge.nonce).as_bytes())
    };

    let mut parts = vec![
        format!("username=\"{user}\""),
        format!("realm=\"{}\"", challenge.realm),
        format!("nonce=\"{}\"", challenge.nonce),
        format!("uri=\"{uri}\""),
        format!("response=\"{response}\""),
    ];
    if use_auth {
        parts.extend([
            "qop=auth".to_owned(),
            format!("nc={nonce_count}"),
            format!("cnonce=\"{cnonce}\""),
        ]);
    }
    if !challenge.opaque.is_empty() {
        parts.push(format!("opaque=\"{}\"", challenge.opaque));
    }
    format!("Digest {}", parts.join(", "))
}

fn qop_offers_auth(qop: &str) -> bool {
    qop.split(',').any(|option| option.trim() == "auth")
}

fn md5_hex(input: &[u8]) -> String {
    hex::encode(Md5::digest(input))
}

#[cfg(test)]
mod tests {
    use super::{challenge_response, parse_digest_challenge, split_digest_fields};

    #[test]
    fn quoted_comma_is_not_a_separator() {
        assert_eq!(
            split_digest_fields(r#"realm="a,b", nonce="c""#),
            [r#"realm="a,b""#, r#" nonce="c""#]
        );
    }

    #[test]
    fn empty_challenge_is_rejected() {
        assert_eq!(
            challenge_response("", "x").unwrap_err().to_string(),
            "empty challenge from box"
        );
    }

    #[test]
    fn basic_auth_is_not_digest() {
        let (challenge, valid) = parse_digest_challenge(r#"Basic realm="x""#);
        assert!(!valid);
        assert!(challenge.nonce.is_empty());
    }
}
