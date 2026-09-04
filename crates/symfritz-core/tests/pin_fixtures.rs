#![deny(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use symfritz_core::pins::{PinStore, calculate_spki_pin};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: String,
    certificate: CertificateVector,
    pin_store: PinStoreVector,
}

#[derive(Deserialize)]
struct CertificateVector {
    input_file: String,
    spki_pin: String,
}

#[derive(Deserialize)]
struct PinStoreVector {
    host: String,
    pin: String,
    written_json: String,
    file_mode: String,
    directory_mode: String,
    corrupt_set_fails: bool,
    reset_repairs: bool,
    repaired_json: String,
    missing_reset_noop: bool,
}

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("symfritz-pin-fixture-{}-{id}", std::process::id()));
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

fn fixture() -> Fixture {
    let path = repository_root().join("testdata/port/transport/contracts.json");
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn certificate_spki_pin_matches_go() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.oracle,
        "Go internal/fritz pin, URL redaction and fallback production functions"
    );
    let encoded =
        fs::read_to_string(repository_root().join(fixture.certificate.input_file)).unwrap();
    let certificate = STANDARD.decode(encoded.trim()).unwrap();
    assert_eq!(
        calculate_spki_pin(&certificate).unwrap(),
        fixture.certificate.spki_pin
    );
}

#[test]
fn pin_store_bytes_modes_and_recovery_match_go() {
    let fixture = fixture().pin_store;
    let root = TestDir::new();
    let path = root.0.join("nested/pins.json");
    let store = PinStore::new(&path);
    store.set(&fixture.host, &fixture.pin).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), fixture.written_json);
    assert_mode(&path, &fixture.file_mode);
    assert_mode(path.parent().unwrap(), &fixture.directory_mode);
    assert_eq!(
        store.get(&fixture.host).as_deref(),
        Some(fixture.pin.as_str())
    );

    fs::write(&path, "not json").unwrap();
    let corrupt = PinStore::new(&path);
    assert_eq!(
        corrupt.set("other", "pin").is_err(),
        fixture.corrupt_set_fails
    );
    assert_eq!(corrupt.reset("other").unwrap(), fixture.reset_repairs);
    assert_eq!(fs::read_to_string(&path).unwrap(), fixture.repaired_json);

    let missing = PinStore::new(root.0.join("missing.json"));
    assert_eq!(!missing.reset("none").unwrap(), fixture.missing_reset_noop);
}

#[cfg(unix)]
fn assert_mode(path: &Path, expected: &str) {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
    let expected_mode = symbolic_mode(expected);
    assert_eq!(mode, expected_mode, "mode for {}", path.display());
}

#[cfg(not(unix))]
fn assert_mode(_path: &Path, _expected: &str) {}

#[cfg(unix)]
fn symbolic_mode(value: &str) -> u32 {
    let permissions = value.as_bytes();
    assert_eq!(permissions.len(), 10);
    let mut mode = 0_u32;
    for (index, bit) in [
        0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001,
    ]
    .into_iter()
    .enumerate()
    {
        if permissions[index + 1] != b'-' {
            mode |= bit;
        }
    }
    mode
}

#[test]
fn serialized_pin_shape_has_only_the_go_contract_key() {
    let value: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(&fixture().pin_store.written_json).unwrap();
    assert_eq!(value.keys().collect::<Vec<_>>(), ["pins"]);
}
