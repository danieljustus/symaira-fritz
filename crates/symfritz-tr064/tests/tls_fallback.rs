#![deny(unsafe_code)]

//! HTTPS→HTTP fallback tests that need the fixed FRITZ!Box ports 49443/49000.
//!
//! They live in their own test binary on purpose: other transport tests bind
//! ephemeral listeners (`127.0.0.1:0`), and the macOS ephemeral range starts at
//! 49152 (Linux at 32768), so a concurrent test in the same process could be
//! handed port 49443 between the "port is free" probe and the connect. Cargo
//! runs test binaries one after another, which removes that race.
//!
//! Both tests also need 127.0.0.1:49443 to refuse connections. Some hosted
//! macOS runners do not guarantee that (connects fail with EINVAL or are
//! accepted and reset), so the tests skip with a message instead of asserting
//! on an environment they cannot control.
// ponytail: skip instead of injecting the fallback port; upgrade path is a
// test-only fallback-port override in HttpTransportConfig.

use std::{
    collections::BTreeMap,
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    thread,
    time::Duration,
};

use symfritz_core::pins::PinStore;
use symfritz_tr064::{BlockingHttpTransport, HttpTransportConfig, Method, Request, Transport};
use url::Url;

static FALLBACK_PORT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "symfritz-tls-fallback-{}-{:?}",
            std::process::id(),
            thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn request(origin: &Url) -> Request {
    Request {
        method: Method::Get,
        url: origin.join("health").unwrap().to_string(),
        headers: BTreeMap::new(),
        body: Vec::new(),
        response_limit: 1024,
    }
}

/// Returns true when 127.0.0.1:49443 actively refuses connections, which is
/// the "TLS endpoint unreachable" situation these tests model.
fn tls_port_refuses_connections() -> bool {
    let address = "127.0.0.1:49443".parse().unwrap();
    match TcpStream::connect_timeout(&address, Duration::from_millis(300)) {
        Err(error) if error.kind() == ErrorKind::ConnectionRefused => true,
        outcome => {
            eprintln!(
                "skipping: 127.0.0.1:49443 does not refuse connections on this host ({outcome:?})"
            );
            false
        }
    }
}

fn spawn_plain_http_server(request_count: usize) -> thread::JoinHandle<()> {
    let listener = TcpListener::bind("127.0.0.1:49000").unwrap();
    thread::spawn(move || {
        for _ in 0..request_count {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut request = [0_u8; 4096];
            if stream.read(&mut request).is_err() {
                return;
            }
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
            let _ = stream.flush();
        }
    })
}

#[test]
fn endpoint_unreachable_falls_back_once_and_reuses_http() {
    let _guard = FALLBACK_PORT_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let tls_probe = TcpListener::bind("127.0.0.1:49443")
        .expect("test requires the FRITZ!Box TLS fallback port to be free");
    drop(tls_probe);
    if !tls_port_refuses_connections() {
        return;
    }

    let root = TestDir::new();
    let warnings = Arc::new(Mutex::new(Vec::new()));
    let warning_values = warnings.clone();
    let http_server = spawn_plain_http_server(2);
    let origin = Url::parse("https://127.0.0.1:49443").unwrap();
    let mut transport = BlockingHttpTransport::new(HttpTransportConfig {
        origin: origin.clone(),
        pin_store: PinStore::new(root.0.join("pins.json")),
        insecure_tls: false,
        allow_http_fallback: true,
        timeout: Duration::from_millis(300),
        warning_sink: Some(Arc::new(move |warning| {
            warning_values.lock().unwrap().push(warning.to_owned());
        })),
    })
    .unwrap();

    for _ in 0..2 {
        let response = transport.send(request(&origin)).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"OK");
    }
    http_server.join().unwrap();
    assert!(!transport.tls_enabled());
    let warnings = warnings.lock().unwrap();
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("falling back to"));
}

#[test]
fn endpoint_unreachable_requires_explicit_http_fallback_opt_in() {
    let _guard = FALLBACK_PORT_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let tls_probe = TcpListener::bind("127.0.0.1:49443")
        .expect("test requires the FRITZ!Box TLS fallback port to be free");
    drop(tls_probe);
    if !tls_port_refuses_connections() {
        return;
    }
    let http_probe = TcpListener::bind("127.0.0.1:49000")
        .expect("test requires the FRITZ!Box HTTP fallback port to be free");

    let root = TestDir::new();
    let origin = Url::parse("https://127.0.0.1:49443").unwrap();
    let mut transport = BlockingHttpTransport::new(HttpTransportConfig {
        origin: origin.clone(),
        pin_store: PinStore::new(root.0.join("pins.json")),
        insecure_tls: false,
        allow_http_fallback: false,
        timeout: Duration::from_millis(300),
        warning_sink: None,
    })
    .unwrap();

    let error = transport.send(request(&origin)).unwrap_err().to_string();
    assert!(error.contains("refusing unencrypted HTTP fallback"));
    assert!(error.contains("[box].allow_http_fallback = true"));
    assert!(transport.tls_enabled());
    drop(http_probe);
}
