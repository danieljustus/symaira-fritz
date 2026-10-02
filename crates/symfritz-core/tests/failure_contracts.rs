#![deny(unsafe_code)]

use std::{error::Error, fs, path::PathBuf};

use symfritz_core::{
    config::{BoxConfig, ConfigError, default_config_path, init_config, load_config_with},
    pins::{PinStore, PinStoreError},
    secret::SecretOptions,
};

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!("symfritz-failures-{}", hex::encode(nonce)));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn pin_load_failure_is_reported_and_never_overwritten() {
    let root = TestDir::new();
    let path = root.0.join("pins.json");
    fs::create_dir(&path).unwrap();
    fs::write(path.join("keep"), b"foreign data").unwrap();
    let store = PinStore::new(&path);
    assert_eq!(store.path(), path);
    assert_eq!(store.get_pin("router"), None);
    let error = store.load_error().unwrap();
    assert!(matches!(&error, PinStoreError::Unusable { path: p, .. } if p == &path));
    assert!(error.to_string().starts_with("cannot update pin store "));
    assert_eq!(store.set("router", "new-pin").unwrap_err(), error);
    assert_eq!(fs::read(path.join("keep")).unwrap(), b"foreign data");
}

#[cfg(unix)]
#[test]
fn failed_pin_replace_keeps_cached_pin_and_cleans_temporary_files() {
    let root = TestDir::new();
    let path = root.0.join("pins.json");
    let store = PinStore::new(&path);
    store.set("router", "trusted-pin").unwrap();
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    // POSIX rename cannot replace a nonempty destination directory with a file.
    fs::write(path.join("keep"), b"foreign data").unwrap();
    let error = store.set("router", "replacement-pin").unwrap_err();
    assert!(matches!(error, PinStoreError::Io { .. }));
    assert_eq!(store.get_pin("router").as_deref(), Some("trusted-pin"));
    assert_eq!(fs::read(path.join("keep")).unwrap(), b"foreign data");
    let names: Vec<_> = fs::read_dir(&root.0)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, ["pins.json"]);
}

#[test]
fn reset_failure_marks_store_unusable_until_successful_repair() {
    let root = TestDir::new();
    let path = root.0.join("blocked/pins.json");
    fs::create_dir(root.0.join("blocked")).unwrap();
    fs::write(&path, b"invalid JSON").unwrap();
    let store = PinStore::new(&path);
    assert!(store.load_error().is_some());
    fs::remove_dir_all(root.0.join("blocked")).unwrap();
    fs::write(root.0.join("blocked"), b"not a directory").unwrap();
    assert!(matches!(
        store.reset("router"),
        Err(PinStoreError::Io { .. })
    ));
    assert!(store.load_error().is_some());
    assert!(matches!(
        store.set("router", "pin"),
        Err(PinStoreError::Unusable { .. })
    ));
    assert_eq!(
        fs::read(root.0.join("blocked")).unwrap(),
        b"not a directory"
    );
    fs::remove_file(root.0.join("blocked")).unwrap();
    assert!(store.reset("router").unwrap());
    assert!(store.load_error().is_none());
    assert_eq!(fs::read_to_string(path).unwrap(), "{\n  \"pins\": {}\n}");
}

#[test]
fn configuration_errors_preserve_path_and_underlying_cause() {
    let root = TestDir::new();
    let path = default_config_path(&root.0);
    fs::create_dir_all(&path).unwrap();
    let error = load_config_with(&root.0, &root.0, |_| None).unwrap_err();
    assert!(matches!(&error, ConfigError::Io { path: p, .. } if p == &path));
    assert!(error.to_string().contains(&path.display().to_string()));
    assert!(error.source().is_some());
    fs::remove_dir(&path).unwrap();
    fs::write(&path, "[box]\nhost = [broken").unwrap();
    let error = load_config_with(&root.0, &root.0, |_| None).unwrap_err();
    assert!(matches!(&error, ConfigError::Toml { path: p, .. } if p == &path));
    assert!(error.to_string().starts_with("failed to parse "));
    assert!(error.source().is_some());
}

#[test]
fn invalid_environment_values_report_the_exact_key_and_value() {
    let root = TestDir::new();
    for key in [
        "SYMFRITZ_BOX_KEYCHAIN",
        "SYMFRITZ_BOX_USE_TLS",
        "SYMFRITZ_BOX_ALLOW_HTTP_FALLBACK",
        "SYMFRITZ_BOX_INSECURE_TLS",
    ] {
        let error = load_config_with(&root.0, &root.0, |name| {
            (name == key).then(|| "invalid-boolean".to_owned())
        })
        .unwrap_err();
        assert!(
            matches!(&error, ConfigError::InvalidEnvBool { key: k, value } if k == key && value == "invalid-boolean")
        );
        assert_eq!(
            error.to_string(),
            format!("cannot parse \"invalid-boolean\" as bool for env {key}")
        );
        assert!(error.source().is_none());
    }
    let error = load_config_with(&root.0, &root.0, |key| {
        (key == "SYMFRITZ_BOX_TIMEOUT_SECONDS").then(|| "not-an-integer".to_owned())
    })
    .unwrap_err();
    assert!(
        matches!(&error, ConfigError::InvalidEnvInt { key, value, .. } if key == "SYMFRITZ_BOX_TIMEOUT_SECONDS" && value == "not-an-integer")
    );
    assert!(
        error
            .to_string()
            .contains("cannot parse \"not-an-integer\" as int")
    );
    assert!(error.source().is_some());
}

#[test]
fn config_init_refuses_unwritable_targets_without_destroying_existing_data() {
    let root = TestDir::new();
    let blocker = root.0.join("blocker");
    fs::write(&blocker, b"keep this file").unwrap();
    let error = init_config(&blocker.join("config.toml"), false).unwrap_err();
    assert!(matches!(&error, ConfigError::Io { path, .. } if path == &blocker));
    assert_eq!(fs::read(blocker).unwrap(), b"keep this file");
    let directory = root.0.join("config.toml");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("keep"), b"keep this child").unwrap();
    let error = init_config(&directory, true).unwrap_err();
    assert!(matches!(&error, ConfigError::Io { path, .. } if path == &directory));
    assert_eq!(
        fs::read(directory.join("keep")).unwrap(),
        b"keep this child"
    );
}

#[test]
fn secret_options_use_explicit_account_before_host_and_normalize_empty_fields() {
    let mut config = BoxConfig {
        host: String::new(),
        ..BoxConfig::default()
    };
    let options = SecretOptions::from(&config);
    assert_eq!(options.env_var.as_deref(), Some("SYMFRITZ_PASSWORD"));
    assert_eq!(options.keychain_account, None);
    assert_eq!(options.password_ref, None);
    assert_eq!(options.plaintext, None);
    config.host = "router.example".to_owned();
    assert_eq!(
        SecretOptions::from(&config).keychain_account.as_deref(),
        Some("router.example")
    );
    config.keychain_account = "explicit-account".to_owned();
    config.password_ref = "test.entry".to_owned();
    config.password = "synthetic-test-value".to_owned();
    config.keychain = true;
    let options = SecretOptions::from(&config);
    assert_eq!(
        options.keychain_account.as_deref(),
        Some("explicit-account")
    );
    assert_eq!(options.password_ref.as_deref(), Some("test.entry"));
    assert_eq!(options.plaintext.as_deref(), Some("synthetic-test-value"));
    assert!(options.keychain);
}
