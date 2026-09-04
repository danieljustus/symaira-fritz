//! Configuration loading and initialization contracts.

use std::{
    collections::HashMap,
    error::Error,
    fmt, fs,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};

/// Exact template written by `symfritz config init`.
pub const DEFAULT_CONFIG_TOML: &str = r#"# symfritz configuration

[box]
# FRITZ!Box address (hostname or IP), without scheme.
host = "fritz.box"

# FRITZ!Box username. Leave empty for legacy password-only boxes.
user = ""

# Credential resolution order (highest first):
#   1. SYMFRITZ_PASSWORD environment variable
#   2. password_ref  — a symvault entry, resolved at runtime via 'symvault get'
#   3. keychain      — the macOS Keychain (service "symfritz")
#   4. password      — plaintext below (least secure)
#
# Recommended: store the password once with 'symfritz auth login', which writes
# it to the Keychain (macOS) or symvault, and leave 'password' empty here.

# symvault entry path, e.g. "fritz.password". Empty = disabled.
password_ref = ""

# Read the password from the macOS Keychain (service "symfritz").
keychain = false

# Keychain account name; defaults to the box host when empty.
keychain_account = ""

# Plaintext password (least secure — prefer the options above).
password = ""

# Use the TLS TR-064 endpoint (https, port 49443).
use_tls = true

# Skip TLS certificate verification (disables TOFU certificate pinning;
# optional opt-out for legacy setups).
insecure_tls = false

# Per-request HTTP timeout in seconds.
timeout_seconds = 15
"#;

/// Connection and credential configuration for one FRITZ!Box.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BoxConfig {
    pub host: String,
    pub user: String,
    pub password: String,
    pub password_ref: String,
    pub keychain: bool,
    pub keychain_account: String,
    pub use_tls: bool,
    pub insecure_tls: bool,
    pub timeout_seconds: i64,
}

impl Default for BoxConfig {
    fn default() -> Self {
        Self {
            host: "fritz.box".to_owned(),
            user: String::new(),
            password: String::new(),
            password_ref: String::new(),
            keychain: false,
            keychain_account: String::new(),
            use_tls: true,
            insecure_tls: false,
            timeout_seconds: 15,
        }
    }
}

impl fmt::Debug for BoxConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoxConfig")
            .field("host", &self.host)
            .field("user", &self.user)
            .field("password", &redacted(&self.password))
            .field("password_ref", &self.password_ref)
            .field("keychain", &self.keychain)
            .field("keychain_account", &self.keychain_account)
            .field("use_tls", &self.use_tls)
            .field("insecure_tls", &self.insecure_tls)
            .field("timeout_seconds", &self.timeout_seconds)
            .finish()
    }
}

impl BoxConfig {
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        if self.timeout_seconds <= 0 {
            Duration::from_secs(15)
        } else {
            Duration::from_secs(self.timeout_seconds as u64)
        }
    }
}

/// Top-level symfritz configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Config {
    #[serde(rename = "box")]
    pub box_config: BoxConfig,
}

#[derive(Debug)]
pub enum ConfigError {
    HomeNotFound,
    CurrentDirectory(std::io::Error),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Toml {
        path: PathBuf,
        source: toml::de::Error,
    },
    InvalidEnvBool {
        key: String,
        value: String,
    },
    InvalidEnvInt {
        key: String,
        value: String,
        source: std::num::ParseIntError,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HomeNotFound => formatter.write_str("cannot determine home directory"),
            Self::CurrentDirectory(error) => {
                write!(formatter, "cannot determine current directory: {error}")
            }
            Self::Io { path, source } => {
                write!(formatter, "failed to access {}: {source}", path.display())
            }
            Self::Toml { path, source } => {
                write!(formatter, "failed to parse {}: {source}", path.display())
            }
            Self::InvalidEnvBool { key, value } => {
                write!(formatter, "cannot parse {value:?} as bool for env {key}")
            }
            Self::InvalidEnvInt { key, value, source } => {
                write!(
                    formatter,
                    "cannot parse {value:?} as int for env {key}: {source}"
                )
            }
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CurrentDirectory(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::Toml { source, .. } => Some(source),
            Self::InvalidEnvInt { source, .. } => Some(source),
            Self::HomeNotFound | Self::InvalidEnvBool { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InitOutcome {
    Written { path: PathBuf },
    AlreadyExists { path: PathBuf },
}

impl InitOutcome {
    #[must_use]
    pub fn stdout(&self) -> String {
        match self {
            Self::Written { path } => format!("Config written to {}\n", path.display()),
            Self::AlreadyExists { .. } => String::new(),
        }
    }

    #[must_use]
    pub fn stderr(&self) -> String {
        match self {
            Self::Written { .. } => String::new(),
            Self::AlreadyExists { path } => format!(
                "config already exists at {} (use --force to overwrite)\n",
                path.display()
            ),
        }
    }
}

#[must_use]
pub fn default_config_path(home: &Path) -> PathBuf {
    home.join(".config").join("symfritz").join("config.toml")
}

#[must_use]
pub fn project_config_path(cwd: &Path) -> PathBuf {
    cwd.join(".symfritz.toml")
}

/// Initialize a config file with the same create/overwrite behavior as Go.
pub fn init_config(path: &Path, force: bool) -> Result<InitOutcome, ConfigError> {
    if path.exists() && !force {
        return Ok(InitOutcome::AlreadyExists {
            path: path.to_path_buf(),
        });
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| ConfigError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    write_config(path)?;
    Ok(InitOutcome::Written {
        path: path.to_path_buf(),
    })
}

#[cfg(unix)]
fn write_config(path: &Path) -> Result<(), ConfigError> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(DEFAULT_CONFIG_TOML.as_bytes())
        .map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(not(unix))]
fn write_config(path: &Path) -> Result<(), ConfigError> {
    fs::write(path, DEFAULT_CONFIG_TOML).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[derive(Default, Deserialize)]
struct RawConfig {
    #[serde(rename = "box")]
    box_config: Option<RawBoxConfig>,
}

#[derive(Default, Deserialize)]
struct RawBoxConfig {
    host: Option<String>,
    user: Option<String>,
    password: Option<String>,
    password_ref: Option<String>,
    keychain: Option<bool>,
    keychain_account: Option<String>,
    use_tls: Option<bool>,
    insecure_tls: Option<bool>,
    timeout_seconds: Option<i64>,
}

/// Load defaults, global TOML, project TOML and environment in precedence order.
pub fn load_config_with<E>(home: &Path, cwd: &Path, get_env: E) -> Result<Config, ConfigError>
where
    E: Fn(&str) -> Option<String>,
{
    let mut config = Config::default();
    merge_file(&mut config, &default_config_path(home))?;
    merge_file(&mut config, &project_config_path(cwd))?;
    apply_env(&mut config, get_env)?;
    Ok(config)
}

pub fn load_config() -> Result<Config, ConfigError> {
    let home = home_directory().ok_or(ConfigError::HomeNotFound)?;
    let cwd = std::env::current_dir().map_err(ConfigError::CurrentDirectory)?;
    load_config_with(&home, &cwd, |key| std::env::var(key).ok())
}

fn merge_file(config: &mut Config, path: &Path) -> Result<(), ConfigError> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(ConfigError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let raw: RawConfig = toml::from_str(&content).map_err(|source| ConfigError::Toml {
        path: path.to_path_buf(),
        source,
    })?;
    if let Some(raw) = raw.box_config {
        apply_nonzero_file_values(&mut config.box_config, raw);
    }
    Ok(())
}

fn apply_nonzero_file_values(config: &mut BoxConfig, raw: RawBoxConfig) {
    if let Some(value) = raw.host.filter(|value| !value.is_empty()) {
        config.host = value;
    }
    if let Some(value) = raw.user.filter(|value| !value.is_empty()) {
        config.user = value;
    }
    if let Some(value) = raw.password.filter(|value| !value.is_empty()) {
        config.password = value;
    }
    if let Some(value) = raw.password_ref.filter(|value| !value.is_empty()) {
        config.password_ref = value;
    }
    if raw.keychain == Some(true) {
        config.keychain = true;
    }
    if let Some(value) = raw.keychain_account.filter(|value| !value.is_empty()) {
        config.keychain_account = value;
    }
    if raw.use_tls == Some(true) {
        config.use_tls = true;
    }
    if raw.insecure_tls == Some(true) {
        config.insecure_tls = true;
    }
    if let Some(value) = raw.timeout_seconds.filter(|value| *value != 0) {
        config.timeout_seconds = value;
    }
}

fn apply_env<E>(config: &mut Config, get_env: E) -> Result<(), ConfigError>
where
    E: Fn(&str) -> Option<String>,
{
    apply_string(&mut config.box_config.host, get_env("SYMFRITZ_BOX_HOST"));
    apply_string(&mut config.box_config.user, get_env("SYMFRITZ_BOX_USER"));
    apply_string(
        &mut config.box_config.password,
        get_env("SYMFRITZ_BOX_PASSWORD"),
    );
    apply_string(
        &mut config.box_config.password_ref,
        get_env("SYMFRITZ_BOX_PASSWORD_REF"),
    );
    apply_string(
        &mut config.box_config.keychain_account,
        get_env("SYMFRITZ_BOX_KEYCHAIN_ACCOUNT"),
    );
    apply_bool(
        &mut config.box_config.keychain,
        "SYMFRITZ_BOX_KEYCHAIN",
        get_env("SYMFRITZ_BOX_KEYCHAIN"),
    )?;
    apply_bool(
        &mut config.box_config.use_tls,
        "SYMFRITZ_BOX_USE_TLS",
        get_env("SYMFRITZ_BOX_USE_TLS"),
    )?;
    apply_bool(
        &mut config.box_config.insecure_tls,
        "SYMFRITZ_BOX_INSECURE_TLS",
        get_env("SYMFRITZ_BOX_INSECURE_TLS"),
    )?;
    if let Some(value) = nonempty(get_env("SYMFRITZ_BOX_TIMEOUT_SECONDS")) {
        config.box_config.timeout_seconds =
            value
                .trim()
                .parse()
                .map_err(|source| ConfigError::InvalidEnvInt {
                    key: "SYMFRITZ_BOX_TIMEOUT_SECONDS".to_owned(),
                    value,
                    source,
                })?;
    }
    apply_string(&mut config.box_config.host, get_env("SYMFRITZ_HOST"));
    apply_string(&mut config.box_config.user, get_env("SYMFRITZ_USER"));
    Ok(())
}

fn apply_string(target: &mut String, value: Option<String>) {
    if let Some(value) = nonempty(value) {
        *target = value;
    }
}

fn apply_bool(target: &mut bool, key: &str, value: Option<String>) -> Result<(), ConfigError> {
    let Some(value) = nonempty(value) else {
        return Ok(());
    };
    *target = match value.trim().to_ascii_lowercase().as_str() {
        "1" | "t" | "true" => true,
        "0" | "f" | "false" => false,
        _ => {
            return Err(ConfigError::InvalidEnvBool {
                key: key.to_owned(),
                value,
            });
        }
    };
    Ok(())
}

fn nonempty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

fn home_directory() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .or_else(|| {
            let drive = std::env::var_os("HOMEDRIVE")?;
            let path = std::env::var_os("HOMEPATH")?;
            Some(PathBuf::from(drive).join(path))
        })
}

fn redacted(value: &str) -> &'static str {
    if value.is_empty() { "" } else { "REDACTED" }
}

/// Map-backed environment provider for deterministic tests.
pub fn map_env<'a>(map: &'a HashMap<String, String>) -> impl Fn(&str) -> Option<String> + 'a {
    move |key| map.get(key).cloned()
}
