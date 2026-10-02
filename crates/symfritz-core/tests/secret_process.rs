#![deny(unsafe_code)]
#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use symfritz_core::secret::{
    CredentialSource, SecretError, SecretOptions, keychain_available, symvault_available,
    symvault_get, symvault_set,
};

#[cfg(target_os = "macos")]
use symfritz_core::secret::KeychainCommand;

const VALUE: &str = "synthetic-probe-value";
const REFERENCE: &str = "test.router";

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!("symfritz-backend-{}", hex::encode(nonce)));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// PATH is changed only in a child test process. Real vault/keychain binaries
// cannot be reached; the fake executables capture the actual argv and stdin.
#[test]
fn backend_process_contracts_use_isolated_executables() {
    for mode in [
        "success",
        "empty",
        "failure",
        "quiet-failure",
        "missing",
        "timeout",
    ] {
        let root = TestDir::new();
        let calls = root.0.join("calls");
        let input = root.0.join("stdin");
        if mode != "missing" {
            for program in ["symvault", "security"] {
                let path = root.0.join(program);
                fs::write(&path, SCRIPT).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        let stdout = root.0.join("stdout");
        let stderr = root.0.join("stderr");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "isolated_backend_probe", "--nocapture"])
            .env("PATH", &root.0)
            .env("SYMFRITZ_TEST_BACKEND_MODE", mode)
            .env("SYMFRITZ_TEST_CALLS", &calls)
            .env("SYMFRITZ_TEST_STDIN", &input)
            .env_remove("SYMFRITZ_PASSWORD")
            .stdin(Stdio::null())
            .stdout(fs::File::create(&stdout).unwrap())
            .stderr(fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if started.elapsed() > Duration::from_secs(20) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{mode}: isolated backend test exceeded deadline");
            }
            thread::sleep(Duration::from_millis(10));
        };
        assert!(
            status.success(),
            "{mode}: stdout={} stderr={}",
            fs::read_to_string(stdout).unwrap(),
            fs::read_to_string(stderr).unwrap()
        );
        if calls.exists() {
            let arguments = fs::read_to_string(&calls).unwrap();
            assert!(
                !arguments.contains(VALUE),
                "secret appeared in argv: {mode}"
            );
            assert!(
                !arguments.contains(&hex::encode(VALUE)),
                "hex secret in argv: {mode}"
            );
        }
    }
}

#[test]
fn isolated_backend_probe() {
    let Ok(mode) = std::env::var("SYMFRITZ_TEST_BACKEND_MODE") else {
        return; // Invoked only by the bounded parent subprocess test above.
    };
    match mode.as_str() {
        "success" => {
            assert!(symvault_available());
            assert_eq!(symvault_get(REFERENCE).unwrap(), VALUE);
            let resolved = symfritz_core::secret::resolve(&SecretOptions {
                password_ref: Some(REFERENCE.to_owned()),
                plaintext: Some("must-not-fall-back".to_owned()),
                ..SecretOptions::default()
            })
            .unwrap();
            assert_eq!(resolved.source, CredentialSource::Symvault);
            assert_eq!(resolved.password, VALUE);
            symvault_set(REFERENCE, VALUE).unwrap();
            let input = PathBuf::from(std::env::var_os("SYMFRITZ_TEST_STDIN").unwrap());
            assert_eq!(fs::read_to_string(&input).unwrap(), format!("{VALUE}\n"));
            let calls =
                fs::read_to_string(std::env::var_os("SYMFRITZ_TEST_CALLS").unwrap()).unwrap();
            assert!(calls.contains("get\ntest.router\n--print\n"));
            assert!(calls.contains("set\ntest.router\n--stdin-value\n"));
            #[cfg(target_os = "macos")]
            {
                assert!(keychain_available());
                for account in [None, Some(""), Some("test-account")] {
                    assert_eq!(
                        symfritz_core::secret::keychain_get("test-service", account).unwrap(),
                        VALUE
                    );
                    symfritz_core::secret::keychain_set("test-service", account, VALUE).unwrap();
                    assert_eq!(
                        fs::read_to_string(&input).unwrap(),
                        KeychainCommand::set_stdin_payload("test-service", account, VALUE)
                    );
                }
            }
        }
        "empty" => {
            assert_eq!(
                symvault_get(REFERENCE).unwrap_err(),
                SecretError::Symvault(
                    "symvault returned an empty value for \"test.router\"".to_owned()
                )
            );
            #[cfg(target_os = "macos")]
            assert_eq!(
                symfritz_core::secret::keychain_get("test-service", None).unwrap(),
                ""
            );
        }
        "failure" | "quiet-failure" => {
            let get = symvault_get(REFERENCE).unwrap_err();
            let set = symvault_set(REFERENCE, VALUE).unwrap_err();
            assert!(matches!(get, SecretError::Symvault(_)));
            assert!(matches!(set, SecretError::Symvault(_)));
            for error in [get, set] {
                let message = error.to_string();
                if mode == "failure" {
                    assert!(message.contains("REDACTED"));
                    assert!(!message.contains(VALUE));
                    assert!(!message.contains(&hex::encode(VALUE)));
                } else {
                    assert!(message.contains("exit status"));
                }
            }
            let error = symfritz_core::secret::resolve(&SecretOptions {
                password_ref: Some(REFERENCE.to_owned()),
                plaintext: Some("must-not-fall-back".to_owned()),
                ..SecretOptions::default()
            })
            .unwrap_err();
            assert!(matches!(error, SecretError::Symvault(_)));
            #[cfg(target_os = "macos")]
            {
                let get = symfritz_core::secret::keychain_get("test-service", Some("test-account"))
                    .unwrap_err();
                assert_eq!(
                    get.to_string(),
                    "keychain entry not found (service \"test-service\" account \"test-account\")"
                );
                let set =
                    symfritz_core::secret::keychain_set("test-service", None, VALUE).unwrap_err();
                assert!(matches!(set, SecretError::Keychain(_)));
                assert!(set.to_string().starts_with("keychain store failed: "));
                assert!(!set.to_string().contains(VALUE));
            }
        }
        "missing" => {
            assert!(!symvault_available());
            assert!(!keychain_available());
            assert!(matches!(
                symvault_get(REFERENCE),
                Err(SecretError::NotInstalled(_))
            ));
            assert!(matches!(
                symvault_set(REFERENCE, VALUE),
                Err(SecretError::NotInstalled(_))
            ));
            #[cfg(target_os = "macos")]
            {
                assert!(matches!(
                    symfritz_core::secret::keychain_get("test-service", None),
                    Err(SecretError::NotInstalled(_))
                ));
                assert!(matches!(
                    symfritz_core::secret::keychain_set("test-service", None, VALUE),
                    Err(SecretError::NotInstalled(_))
                ));
            }
        }
        "timeout" => {
            assert_eq!(
                symvault_get(REFERENCE).unwrap_err().to_string(),
                "symvault command timed out"
            );
            assert_eq!(
                symvault_set(REFERENCE, VALUE).unwrap_err().to_string(),
                "symvault command timed out"
            );
            #[cfg(target_os = "macos")]
            {
                assert_eq!(
                    symfritz_core::secret::keychain_get("test-service", None)
                        .unwrap_err()
                        .to_string(),
                    "keychain command timed out"
                );
                assert_eq!(
                    symfritz_core::secret::keychain_set("test-service", None, VALUE)
                        .unwrap_err()
                        .to_string(),
                    "keychain command timed out"
                );
            }
        }
        other => panic!("unknown isolated backend mode {other}"),
    }
}

const SCRIPT: &str = r#"#!/bin/sh
printf '%s\n' "$@" >> "$SYMFRITZ_TEST_CALLS"
case "$1" in
    set|-i) IFS= read -r value; printf '%s\n' "$value" > "$SYMFRITZ_TEST_STDIN" ;;
esac
case "$SYMFRITZ_TEST_BACKEND_MODE" in
    success) printf 'synthetic-probe-value\r\n' ;;
    empty) printf '\r\n' ;;
    failure)
        printf 'synthetic-probe-value\n'
        printf 'synthetic-probe-value 73796e7468657469632d70726f62652d76616c7565\n' >&2
        exit 7 ;;
    quiet-failure) exit 7 ;;
    timeout) exec /bin/sleep 10 ;;
    *) exit 99 ;;
esac
"#;
