#![deny(unsafe_code)]

use std::{cell::Cell, fs, path::PathBuf};

use serde::Deserialize;
use symfritz_core::secret::{
    CredentialSource, KEYCHAIN_SERVICE, KeychainCommand, SecretBackend, SecretError, SecretOptions,
    SymvaultCommand, resolve_with_backend,
};

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: String,
    credential_cases: Vec<CredentialVector>,
    subprocess_contracts: Vec<SubprocessVector>,
}

#[derive(Deserialize)]
struct CredentialVector {
    id: String,
    #[serde(default)]
    env_password: String,
    #[serde(default)]
    r#ref: String,
    keychain: bool,
    #[serde(default)]
    keychain_account: String,
    #[serde(default)]
    plaintext: String,
    #[serde(default)]
    mock_vault_pass: String,
    #[serde(default)]
    mock_vault_err: String,
    #[serde(default)]
    mock_keychain_pass: String,
    #[serde(default)]
    mock_keychain_err: String,
    expected_pass: String,
    expected_source: String,
    #[serde(default)]
    expected_error: String,
}

#[derive(Deserialize)]
struct SubprocessVector {
    id: String,
    executable: String,
    args: Vec<String>,
    stdin_payload: String,
    exposes_secret_in_argv: bool,
}

struct StubBackend<'a> {
    vector: &'a CredentialVector,
    vault_calls: Cell<u32>,
    keychain_calls: Cell<u32>,
}

impl SecretBackend for StubBackend<'_> {
    fn symvault_get(&self, _reference: &str) -> Result<String, SecretError> {
        self.vault_calls.set(self.vault_calls.get() + 1);
        if self.vector.mock_vault_err.is_empty() {
            Ok(self.vector.mock_vault_pass.clone())
        } else {
            Err(SecretError::Symvault(self.vector.mock_vault_err.clone()))
        }
    }

    fn keychain_get(&self, _service: &str, _account: Option<&str>) -> Result<String, SecretError> {
        self.keychain_calls.set(self.keychain_calls.get() + 1);
        if self.vector.mock_keychain_err.is_empty() {
            Ok(self.vector.mock_keychain_pass.clone())
        } else {
            Err(SecretError::Keychain(self.vector.mock_keychain_err.clone()))
        }
    }
}

fn fixture() -> Fixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/port/config/secret-vectors.json");
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn optional(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

#[test]
fn credential_resolution_matches_go_and_stops_after_first_backend() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.oracle, "Go internal/secret production functions");

    for vector in fixture.credential_cases {
        let backend = StubBackend {
            vector: &vector,
            vault_calls: Cell::new(0),
            keychain_calls: Cell::new(0),
        };
        let options = SecretOptions {
            env_var: Some("SYMFRITZ_PASSWORD".to_owned()),
            password_ref: optional(&vector.r#ref),
            keychain: vector.keychain,
            keychain_account: optional(&vector.keychain_account),
            plaintext: optional(&vector.plaintext),
        };
        let result = resolve_with_backend(&options, &backend, |key| {
            (key == "SYMFRITZ_PASSWORD" && !vector.env_password.is_empty())
                .then(|| vector.env_password.clone())
        });

        if vector.expected_error.is_empty() {
            let result = result.unwrap_or_else(|error| panic!("{}: {error}", vector.id));
            assert_eq!(result.password, vector.expected_pass, "{}", vector.id);
            assert_eq!(
                result.source.to_string(),
                vector.expected_source,
                "{}",
                vector.id
            );
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                vector.expected_error,
                "{}",
                vector.id
            );
        }

        if !vector.env_password.is_empty() {
            assert_eq!(backend.vault_calls.get(), 0, "{} vault calls", vector.id);
            assert_eq!(
                backend.keychain_calls.get(),
                0,
                "{} keychain calls",
                vector.id
            );
        } else if !vector.r#ref.is_empty() {
            assert_eq!(backend.vault_calls.get(), 1, "{} vault calls", vector.id);
            assert_eq!(
                backend.keychain_calls.get(),
                0,
                "{} keychain calls",
                vector.id
            );
        } else if vector.keychain {
            assert_eq!(
                backend.keychain_calls.get(),
                1,
                "{} keychain calls",
                vector.id
            );
        }
    }
}

#[test]
fn subprocess_contracts_match_go_and_keep_values_out_of_argv() {
    let fixture = fixture();
    for vector in fixture.subprocess_contracts {
        let (executable, args, stdin) = match vector.id.as_str() {
            "symvault-get" => (
                "symvault",
                SymvaultCommand::get_args("{ref}"),
                String::new(),
            ),
            "symvault-set" => (
                "symvault",
                SymvaultCommand::set_args("{ref}"),
                SymvaultCommand::set_stdin_payload("{value}"),
            ),
            "keychain-get-with-account" => (
                "security",
                KeychainCommand::get_args(KEYCHAIN_SERVICE, Some("{account}")),
                String::new(),
            ),
            "keychain-get-without-account" => (
                "security",
                KeychainCommand::get_args(KEYCHAIN_SERVICE, None),
                String::new(),
            ),
            "keychain-set-with-account" => (
                "security",
                KeychainCommand::set_args(),
                KeychainCommand::set_stdin_payload(KEYCHAIN_SERVICE, Some("{account}"), "{value}"),
            ),
            "keychain-set-without-account" => (
                "security",
                KeychainCommand::set_args(),
                KeychainCommand::set_stdin_payload(KEYCHAIN_SERVICE, None, "{value}"),
            ),
            other => panic!("unknown subprocess fixture {other}"),
        };
        assert_eq!(executable, vector.executable, "{} executable", vector.id);
        assert_eq!(args, vector.args, "{} args", vector.id);
        assert_eq!(stdin, vector.stdin_payload, "{} stdin", vector.id);
        assert!(!vector.exposes_secret_in_argv, "{} fixture", vector.id);
        assert!(
            !args.iter().any(|arg| arg.contains("{value}")),
            "{} leaked value",
            vector.id
        );
    }
}

#[test]
fn debug_output_redacts_secret_values() {
    let options = SecretOptions {
        plaintext: Some("sensitive-option".to_owned()),
        ..SecretOptions::default()
    };
    let result = symfritz_core::secret::SecretResult {
        password: "sensitive-result".to_owned(),
        source: CredentialSource::Config,
    };
    let debug = format!("{options:?} {result:?}");
    assert!(!debug.contains("sensitive-option"));
    assert!(!debug.contains("sensitive-result"));
    assert!(debug.contains("REDACTED"));
}
