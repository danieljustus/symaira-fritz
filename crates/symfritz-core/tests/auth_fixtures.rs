#![deny(unsafe_code)]

use std::{fs, path::PathBuf};

use serde::Deserialize;
use symfritz_core::auth::{
    DigestChallenge, challenge_response, digest_authorization_header, parse_digest_challenge,
};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: String,
    session: Vec<SessionVector>,
    digest_parse: Vec<DigestParseVector>,
    digest_header: Vec<DigestHeaderVector>,
}

#[derive(Debug, Deserialize)]
struct SessionVector {
    id: String,
    challenge: String,
    password: String,
    #[serde(default)]
    response: String,
    #[serde(default)]
    error: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
struct ChallengeVector {
    realm: String,
    nonce: String,
    qop: String,
    algorithm: String,
    opaque: String,
}

#[derive(Debug, Deserialize)]
struct DigestParseVector {
    id: String,
    header: String,
    parsed: bool,
    challenge: ChallengeVector,
}

#[derive(Debug, Deserialize)]
struct DigestHeaderVector {
    id: String,
    challenge: ChallengeVector,
    user: String,
    password: String,
    method: String,
    uri: String,
    nc: u32,
    cnonce: String,
    header: String,
}

impl From<ChallengeVector> for DigestChallenge {
    fn from(value: ChallengeVector) -> Self {
        Self {
            realm: value.realm,
            nonce: value.nonce,
            qop: value.qop,
            algorithm: value.algorithm,
            opaque: value.opaque,
        }
    }
}

impl From<DigestChallenge> for ChallengeVector {
    fn from(value: DigestChallenge) -> Self {
        Self {
            realm: value.realm,
            nonce: value.nonce,
            qop: value.qop,
            algorithm: value.algorithm,
            opaque: value.opaque,
        }
    }
}

fn fixture() -> Fixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/port/auth/auth-vectors.json");
    let bytes = fs::read(path).expect("read Go authentication fixture");
    serde_json::from_slice(&bytes).expect("parse Go authentication fixture")
}

#[test]
fn fixture_metadata_is_current() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.oracle,
        "Go internal/fritz production authentication functions"
    );
}

#[test]
fn session_challenges_match_go() {
    for vector in fixture().session {
        let actual = challenge_response(&vector.challenge, &vector.password);
        if vector.error.is_empty() {
            assert_eq!(
                actual.unwrap_or_else(|error| panic!("{}: {error}", vector.id)),
                vector.response,
                "{}",
                vector.id
            );
        } else {
            assert_eq!(
                actual
                    .expect_err(&format!("{}: expected error", vector.id))
                    .to_string(),
                vector.error,
                "{}",
                vector.id
            );
        }
    }
}

#[test]
fn digest_parser_matches_go() {
    for vector in fixture().digest_parse {
        let (challenge, parsed) = parse_digest_challenge(&vector.header);
        assert_eq!(parsed, vector.parsed, "{} parsed", vector.id);
        assert_eq!(
            ChallengeVector::from(challenge),
            vector.challenge,
            "{}",
            vector.id
        );
    }
}

#[test]
fn digest_headers_match_go_byte_for_byte() {
    for vector in fixture().digest_header {
        let actual = digest_authorization_header(
            &DigestChallenge::from(vector.challenge),
            &vector.user,
            &vector.password,
            &vector.method,
            &vector.uri,
            vector.nc,
            &vector.cnonce,
        );
        assert_eq!(actual, vector.header, "{}", vector.id);
    }
}
