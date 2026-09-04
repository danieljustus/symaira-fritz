#![deny(unsafe_code)]

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::Deserialize;
use symfritz_core::config::{
    BoxConfig, Config, DEFAULT_CONFIG_TOML, default_config_path, init_config, load_config_with,
    map_env, project_config_path,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: String,
    defaults: BoxVector,
    path_suffix: String,
    project_file_name: String,
    template_toml: String,
    timeout_cases: Vec<TimeoutVector>,
    precedence_cases: Vec<PrecedenceVector>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct BoxVector {
    host: String,
    user: String,
    password: String,
    password_ref: String,
    keychain: bool,
    keychain_account: String,
    use_tls: bool,
    insecure_tls: bool,
    timeout_seconds: i64,
}

#[derive(Deserialize)]
struct TimeoutVector {
    input_seconds: i64,
    expected_seconds: u64,
}

#[derive(Deserialize)]
struct PrecedenceVector {
    id: String,
    #[serde(default)]
    global_toml: String,
    #[serde(default)]
    project_toml: String,
    #[serde(default)]
    env: HashMap<String, String>,
    expected: Option<BoxVector>,
    #[serde(default)]
    expected_timeout_sec: u64,
    #[serde(default)]
    error: bool,
}

#[derive(Deserialize)]
struct InitFixture {
    schema_version: u32,
    oracle: String,
    cases: Vec<InitVector>,
}

#[derive(Deserialize)]
struct InitVector {
    id: String,
    file_exists: bool,
    #[serde(default)]
    initial_content: String,
    #[serde(default)]
    initial_mode: String,
    force: bool,
    stdout: String,
    stderr: String,
    body: String,
    #[serde(default)]
    mode: String,
}

impl From<BoxConfig> for BoxVector {
    fn from(value: BoxConfig) -> Self {
        Self {
            host: value.host,
            user: value.user,
            password: value.password,
            password_ref: value.password_ref,
            keychain: value.keychain,
            keychain_account: value.keychain_account,
            use_tls: value.use_tls,
            insecure_tls: value.insecure_tls,
            timeout_seconds: value.timeout_seconds,
        }
    }
}

struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "symfritz-config-test-{}-{name}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_json<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = repository_root().join("testdata/port/config").join(name);
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn configuration_vectors_match_go() {
    let fixture: Fixture = load_json("config-vectors.json");
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.oracle,
        "Go internal/config and configkit production functions"
    );
    assert_eq!(BoxVector::from(BoxConfig::default()), fixture.defaults);
    assert_eq!(fixture.template_toml, DEFAULT_CONFIG_TOML);

    let root = TestDir::new("paths");
    assert!(default_config_path(&root.0).ends_with(Path::new(&fixture.path_suffix)));
    assert_eq!(
        project_config_path(&root.0).file_name().unwrap(),
        fixture.project_file_name.as_str()
    );

    for vector in fixture.timeout_cases {
        let config = BoxConfig {
            timeout_seconds: vector.input_seconds,
            ..BoxConfig::default()
        };
        assert_eq!(config.timeout().as_secs(), vector.expected_seconds);
    }

    for vector in fixture.precedence_cases {
        let root = TestDir::new(&vector.id);
        let home = root.0.join("home");
        let cwd = root.0.join("cwd");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&cwd).unwrap();
        if !vector.global_toml.is_empty() {
            let path = default_config_path(&home);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, &vector.global_toml).unwrap();
        }
        if !vector.project_toml.is_empty() {
            fs::write(project_config_path(&cwd), &vector.project_toml).unwrap();
        }

        let actual = load_config_with(&home, &cwd, map_env(&vector.env));
        if vector.error {
            assert!(actual.is_err(), "{}: expected error", vector.id);
        } else {
            let Config { box_config } = actual.unwrap();
            assert_eq!(
                BoxVector::from(box_config.clone()),
                vector.expected.unwrap(),
                "{}",
                vector.id
            );
            assert_eq!(
                box_config.timeout().as_secs(),
                vector.expected_timeout_sec,
                "{} timeout",
                vector.id
            );
        }
    }
}

#[test]
fn config_init_vectors_match_go() {
    let fixture: InitFixture = load_json("config-init-vectors.json");
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.oracle,
        "Go cmd/symfritz initConfigFile production helper"
    );

    for vector in fixture.cases {
        let root = TestDir::new(&vector.id);
        let path = root.0.join(".config/symfritz/config.toml");
        if vector.file_exists {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, &vector.initial_content).unwrap();
            set_mode(&path, &vector.initial_mode);
        }
        let outcome = init_config(&path, vector.force).unwrap();
        assert_eq!(
            outcome
                .stdout()
                .replace(&path.display().to_string(), "{path}"),
            vector.stdout,
            "{} stdout",
            vector.id
        );
        assert_eq!(
            outcome
                .stderr()
                .replace(&path.display().to_string(), "{path}"),
            vector.stderr,
            "{} stderr",
            vector.id
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            vector.body,
            "{}",
            vector.id
        );
        assert_mode(&path, &vector.mode, &vector.id);
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: &str) {
    use std::os::unix::fs::PermissionsExt;
    let mode = u32::from_str_radix(mode, 8).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: &str) {}

#[cfg(unix)]
fn assert_mode(path: &Path, expected: &str, id: &str) {
    use std::os::unix::fs::PermissionsExt;
    let actual = format!(
        "{:04o}",
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    );
    assert_eq!(actual, expected, "{id} mode");
}

#[cfg(not(unix))]
fn assert_mode(_path: &Path, _expected: &str, _id: &str) {}

#[test]
fn debug_output_redacts_plaintext_password() {
    let config = BoxConfig {
        password: "sensitive-test-value".to_owned(),
        ..BoxConfig::default()
    };
    let debug = format!("{config:?}");
    assert!(!debug.contains("sensitive-test-value"));
    assert!(debug.contains("REDACTED"));
}
