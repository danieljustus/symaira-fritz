//! Persistent SHA-256 SPKI pins used for trust-on-first-use TLS.
//!
//! The on-disk format intentionally matches the Go client:
//! `{ "pins": { "host:port": "base64-sha256-spki" } }`.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug, Serialize, Deserialize)]
struct PinFile {
    #[serde(default)]
    pins: BTreeMap<String, String>,
}

#[derive(Debug, Default)]
struct State {
    pins: BTreeMap<String, String>,
    load_error: Option<String>,
}

/// A synchronized, fail-closed persistent pin store.
#[derive(Clone, Debug)]
pub struct PinStore {
    path: PathBuf,
    state: Arc<Mutex<State>>,
}

/// Pin-store failures, including refusal to overwrite an unreadable store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PinStoreError {
    Io { path: PathBuf, message: String },
    Corrupt { path: PathBuf, message: String },
    Unusable { path: PathBuf, message: String },
}

impl fmt::Display for PinStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, message } => write!(formatter, "{}: {message}", path.display()),
            Self::Corrupt { path, message } => {
                write!(formatter, "corrupt pin store {}: {message}", path.display())
            }
            Self::Unusable { path, message } => {
                write!(
                    formatter,
                    "cannot update pin store {}: {message}",
                    path.display()
                )
            }
        }
    }
}

impl Error for PinStoreError {}

impl PinStore {
    /// Opens a store. A missing file is the normal first-contact state; other
    /// load failures are retained and make `set` fail closed until `reset`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let state = load_state(&path);
        Self {
            path,
            state: Arc::new(Mutex::new(state)),
        }
    }

    /// Returns the default per-user store path.
    #[must_use]
    pub fn default_path() -> Option<PathBuf> {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .map(|home| home.join(".config").join("symfritz").join("pins.json"))
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the load failure, if any, without exposing a secret value.
    #[must_use]
    pub fn load_error(&self) -> Option<PinStoreError> {
        let state = self.state.lock().expect("pin store mutex poisoned");
        state
            .load_error
            .as_ref()
            .map(|message| PinStoreError::Unusable {
                path: self.path.clone(),
                message: message.clone(),
            })
    }

    #[must_use]
    pub fn get(&self, host: &str) -> Option<String> {
        let state = self.state.lock().expect("pin store mutex poisoned");
        state.pins.get(host).cloned()
    }

    /// Go naming-compatible accessor.
    #[must_use]
    pub fn get_pin(&self, host: &str) -> Option<String> {
        self.get(host)
    }

    /// Records a pin, refusing to replace data that could not be read.
    pub fn set(
        &self,
        host: impl Into<String>,
        pin: impl Into<String>,
    ) -> Result<(), PinStoreError> {
        let mut state = self.state.lock().expect("pin store mutex poisoned");
        if let Some(message) = &state.load_error {
            return Err(PinStoreError::Unusable {
                path: self.path.clone(),
                message: message.clone(),
            });
        }
        let mut pins = state.pins.clone();
        pins.insert(host.into(), pin.into());
        write_state(&self.path, &pins)?;
        state.pins = pins;
        Ok(())
    }

    /// Removes a pin. Reset also repairs a corrupt/unreadable store.
    pub fn reset(&self, host: &str) -> Result<bool, PinStoreError> {
        let mut state = self.state.lock().expect("pin store mutex poisoned");
        let was_unusable = state.load_error.take().is_some();
        let existed = state.pins.remove(host).is_some();
        if !was_unusable && !existed {
            return Ok(false);
        }
        if let Err(error) = write_state(&self.path, &state.pins) {
            state.load_error = Some(error.to_string());
            return Err(error);
        }
        Ok(true)
    }
}

fn load_state(path: &Path) -> State {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return State::default(),
        Err(error) => {
            return State {
                load_error: Some(error.to_string()),
                ..State::default()
            };
        }
    };
    match serde_json::from_slice::<PinFile>(&data) {
        Ok(file) => State {
            pins: file.pins,
            load_error: None,
        },
        Err(error) => State {
            load_error: Some(error.to_string()),
            ..State::default()
        },
    }
}

fn write_state(path: &Path, pins: &BTreeMap<String, String>) -> Result<(), PinStoreError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent_was_missing = !parent.exists();
    fs::create_dir_all(parent).map_err(|error| io_error(parent, error))?;
    if parent_was_missing {
        set_directory_mode(parent).map_err(|error| io_error(parent, error))?;
    }

    let data = serde_json::to_vec_pretty(&PinFile { pins: pins.clone() }).map_err(|error| {
        PinStoreError::Io {
            path: path.to_path_buf(),
            message: error.to_string(),
        }
    })?;
    let temp = path.with_extension(format!(
        "json.tmp.{}.{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        set_file_mode(&mut options);
        let mut file = options
            .open(&temp)
            .map_err(|error| io_error(&temp, error))?;
        file.write_all(&data)
            .map_err(|error| io_error(&temp, error))?;
        file.sync_all().map_err(|error| io_error(&temp, error))?;
        set_existing_file_mode(&temp).map_err(|error| io_error(&temp, error))?;
        replace_file(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn io_error(path: &Path, error: io::Error) -> PinStoreError {
    PinStoreError::Io {
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(not(windows))]
fn replace_file(temp: &Path, path: &Path) -> Result<(), PinStoreError> {
    fs::rename(temp, path).map_err(|error| io_error(path, error))
}

#[cfg(windows)]
fn replace_file(temp: &Path, path: &Path) -> Result<(), PinStoreError> {
    if path.exists() {
        fs::remove_file(path).map_err(|error| io_error(path, error))?;
    }
    fs::rename(temp, path).map_err(|error| io_error(path, error))
}

#[cfg(unix)]
fn set_directory_mode(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_directory_mode(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(options: &mut fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_file_mode(_options: &mut fs::OpenOptions) {}

#[cfg(unix)]
fn set_existing_file_mode(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_existing_file_mode(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Computes the Go-compatible `base64(SHA-256(SubjectPublicKeyInfo))` pin.
pub fn calculate_spki_pin(cert_der: &[u8]) -> Result<String, PinStoreError> {
    let (_, certificate) =
        X509Certificate::from_der(cert_der).map_err(|error| PinStoreError::Corrupt {
            path: PathBuf::from("<certificate>"),
            message: format!("invalid certificate: {error}"),
        })?;
    let mut digest = Sha256::new();
    digest.update(certificate.tbs_certificate.subject_pki.raw);
    Ok(STANDARD.encode(digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_path(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("symfritz-pins-{suffix}-{name}"))
    }

    #[test]
    fn missing_store_round_trips_go_shape() {
        let path = temp_path("missing/pins.json");
        let store = PinStore::new(&path);
        assert!(store.load_error().is_none());
        store.set("fritz.box:49443", "AQID").unwrap();
        let bytes = fs::read(&path).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "{\n  \"pins\": {\n    \"fritz.box:49443\": \"AQID\"\n  }\n}"
        );
        assert_eq!(
            PinStore::new(&path).get("fritz.box:49443").as_deref(),
            Some("AQID")
        );
        let _ = fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn corrupt_store_refuses_set_but_reset_recovers() {
        let path = temp_path("pins.json");
        fs::write(&path, b"not json").unwrap();
        let store = PinStore::new(&path);
        assert!(store.set("host", "pin").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"not json");
        assert!(store.reset("host").unwrap());
        assert!(store.load_error().is_none());
        assert_eq!(PinStore::new(&path).get("host"), None);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn malformed_certificate_is_rejected() {
        assert!(calculate_spki_pin(b"bad certificate").is_err());
    }
}
