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
    Pbkdf2IterationCountOutOfBounds,
}

impl fmt::Display for ChallengeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyChallenge => "empty challenge from box",
            Self::MalformedPbkdf2Challenge => "malformed PBKDF2 challenge",
            Self::MalformedPbkdf2IterationCount => "malformed PBKDF2 iteration count",
            Self::MalformedPbkdf2Salt => "malformed PBKDF2 salt",
            Self::Pbkdf2IterationCountOutOfBounds => {
                return write!(
                    formatter,
                    "PBKDF2 iteration count exceeds supported maximum of {}",
                    MAX_PBKDF2_ITERATIONS
                );
            }
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

/// Highest iteration count accepted in either PBKDF2 challenge field.
///
/// Compatibility evidence: AVM's official session-ID note
/// (<https://fritz.support/resources/HTTP_Session-ID_EN.pdf>) documents the
/// two-stage challenge as `2$<iter1>$<salt1>$<iter2>$<salt2>`, uses the
/// example counts 10000/2000 (the same counts frozen in
/// `testdata/port/auth/auth-vectors.json`), and states that both counts may
/// change in future FRITZ!OS releases to keep PBKDF2-based login
/// future-proof. Field-captured live FRITZ!Box `login_sid.lua` responses have
/// reached 60000/6000, and the OWASP password-storage guidance for
/// PBKDF2-HMAC-SHA256 recommends 600,000 iterations. One million therefore
/// accepts every documented and observed FRITZ!OS work factor with headroom
/// for the increases AVM announces, while capping a hostile two-stage
/// challenge at 2,000,000 HMAC-SHA256 iterations instead of the previous
/// unbounded 2 x u32::MAX. A value above the bound in either field is
/// rejected with [`ChallengeError::Pbkdf2IterationCountOutOfBounds`] before
/// any key derivation starts.
pub const MAX_PBKDF2_ITERATIONS: u32 = 1_000_000;

/// Parse and bound-check one challenge iteration field.
///
/// Zero and negative values stay accepted as zero iterations to preserve the
/// frozen zero/negative vectors; unparseable text stays
/// [`ChallengeError::MalformedPbkdf2IterationCount`]. Values above
/// [`MAX_PBKDF2_ITERATIONS`] are rejected with
/// [`ChallengeError::Pbkdf2IterationCountOutOfBounds`].
fn parse_iteration_count(field: &str) -> Result<u32, ChallengeError> {
    let count = field
        .parse::<i64>()
        .map_err(|_| ChallengeError::MalformedPbkdf2IterationCount)?;
    if count > i64::from(MAX_PBKDF2_ITERATIONS) {
        return Err(ChallengeError::Pbkdf2IterationCountOutOfBounds);
    }
    u32::try_from(count.max(0)).map_err(|_| ChallengeError::MalformedPbkdf2IterationCount)
}

fn pbkdf2_response(challenge: &str, password: &str) -> Result<String, ChallengeError> {
    let parts: Vec<_> = challenge.split('$').collect();
    if parts.len() != 5 {
        return Err(ChallengeError::MalformedPbkdf2Challenge);
    }

    // Both iteration fields are parsed and checked against
    // `MAX_PBKDF2_ITERATIONS` before any PBKDF2 work starts, so an excessive
    // value in either position (including a valid first field paired with an
    // excessive second field) is rejected before the first KDF runs.
    let iterations_1 = parse_iteration_count(parts[1])?;
    let iterations_2 = parse_iteration_count(parts[3])?;

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
    use super::{
        ChallengeError, MAX_PBKDF2_ITERATIONS, challenge_response, parse_digest_challenge,
        parse_iteration_count, split_digest_fields,
    };

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

    #[test]
    fn iteration_count_boundary_is_accepted() {
        assert_eq!(MAX_PBKDF2_ITERATIONS, 1_000_000);
        assert_eq!(parse_iteration_count("1000000"), Ok(MAX_PBKDF2_ITERATIONS));
        assert_eq!(
            parse_iteration_count(&MAX_PBKDF2_ITERATIONS.to_string()),
            Ok(MAX_PBKDF2_ITERATIONS)
        );
    }

    #[test]
    fn zero_and_negative_iteration_counts_remain_accepted() {
        assert_eq!(parse_iteration_count("0"), Ok(0));
        assert_eq!(parse_iteration_count("-1"), Ok(0));
    }

    #[test]
    fn iteration_count_above_boundary_is_rejected() {
        let above = MAX_PBKDF2_ITERATIONS + 1;
        assert_eq!(
            parse_iteration_count(&above.to_string()),
            Err(ChallengeError::Pbkdf2IterationCountOutOfBounds)
        );
        assert_eq!(
            challenge_response(&format!("2${above}$5A1B$2000$5A1C"), "x"),
            Err(ChallengeError::Pbkdf2IterationCountOutOfBounds)
        );
    }

    #[test]
    fn max_u32_iteration_count_is_rejected_promptly() {
        // The hostile probe from issue #259: previously this requested up to
        // 2 x u32::MAX iterations unbounded. Correct code rejects it in
        // microseconds; the generous guard turns a regression back to
        // unbounded work into a failed assertion instead of a hang.
        let started = std::time::Instant::now();
        assert_eq!(
            challenge_response("2$4294967295$0a0b$1$0c0d", "password"),
            Err(ChallengeError::Pbkdf2IterationCountOutOfBounds)
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "hostile iteration count was not rejected before key derivation"
        );
    }

    #[test]
    fn both_iteration_fields_are_validated_before_either_kdf() {
        // Valid first field at the bound paired with an excessive second
        // field. When both fields are validated up front this never reaches
        // either KDF, so the whole test stays microsecond-scale; the guard
        // only exists to catch a regression that starts doing real work.
        let started = std::time::Instant::now();
        assert_eq!(
            challenge_response("2$1000000$0a0b$1000001$0c0d", "password"),
            Err(ChallengeError::Pbkdf2IterationCountOutOfBounds)
        );
        // Excessive first field paired with an ordinary second field.
        assert_eq!(
            challenge_response("2$1000001$0a0b$2000$0c0d", "password"),
            Err(ChallengeError::Pbkdf2IterationCountOutOfBounds)
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "iteration fields were not both validated before any KDF work"
        );
    }

    #[test]
    fn out_of_bounds_error_names_the_supported_limit() {
        assert_eq!(
            ChallengeError::Pbkdf2IterationCountOutOfBounds.to_string(),
            format!(
                "PBKDF2 iteration count exceeds supported maximum of {}",
                MAX_PBKDF2_ITERATIONS
            )
        );
    }
}
