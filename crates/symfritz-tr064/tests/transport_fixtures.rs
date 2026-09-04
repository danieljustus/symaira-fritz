#![deny(unsafe_code)]

use std::{collections::BTreeMap, fs, path::PathBuf};

use serde::Deserialize;
use symfritz_tr064::{endpoint_unreachable_message, redact_url};
use url::Url;

#[derive(Deserialize)]
struct Fixture {
    safe_urls: Vec<SafeUrlVector>,
    fallback: Vec<FallbackVector>,
}

#[derive(Deserialize)]
struct SafeUrlVector {
    id: String,
    raw: String,
    redacted: String,
}

#[derive(Deserialize)]
struct FallbackVector {
    id: String,
    message: String,
    #[serde(default)]
    canceled: bool,
    expected: bool,
}

fn fixture() -> Fixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/port/transport/contracts.json");
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn url_redaction_preserves_go_semantics_without_leaking_more() {
    for vector in fixture().safe_urls {
        let Ok(raw) = Url::parse(&vector.raw) else {
            assert_eq!(vector.redacted, vector.raw, "{} Go invalid URL", vector.id);
            continue;
        };
        let rust = Url::parse(&redact_url(&raw)).unwrap();
        let go = Url::parse(&vector.redacted).unwrap();
        assert_eq!(rust.host_str(), go.host_str(), "{} host", vector.id);
        assert_eq!(rust.path(), go.path(), "{} path", vector.id);
        assert_eq!(query_map(&rust), query_map(&go), "{} query", vector.id);
        assert!(rust.password().is_none(), "{} password", vector.id);
        for secret in ["abc123", "salt", "hash", "plain-value"] {
            assert!(
                !rust.as_str().contains(secret),
                "{} leaked {secret}",
                vector.id
            );
        }
    }
}

#[test]
fn fallback_message_classification_matches_go_when_not_canceled() {
    for vector in fixture().fallback {
        if vector.canceled {
            continue;
        }
        assert_eq!(
            endpoint_unreachable_message(&vector.message),
            vector.expected,
            "{}",
            vector.id
        );
    }
}

fn query_map(url: &Url) -> BTreeMap<String, String> {
    url.query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}
