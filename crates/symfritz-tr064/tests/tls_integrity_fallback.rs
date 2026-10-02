#![deny(unsafe_code)]

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::{
    ServerConfig, ServerConnection, StreamOwned, crypto,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use symfritz_core::pins::PinStore;
use symfritz_tr064::{BlockingHttpTransport, HttpTransportConfig, Method, Request, Transport};
use url::Url;

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "symfritz-tls-integrity-fallback-{}",
            std::process::id()
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

fn tls_server() -> (Url, thread::JoinHandle<bool>) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate = CertificateDer::from(cert.der().to_vec());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let provider = Arc::new(crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut tls = StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), stream);
        let mut request = [0_u8; 2048];
        if tls.read(&mut request).is_err() {
            return false;
        }
        let _ =
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
        let _ = tls.flush();
        true
    });
    (Url::parse(&format!("https://{address}")).unwrap(), handle)
}

fn request(origin: &Url) -> Request {
    Request {
        method: Method::Get,
        url: origin
            .join("health?sid=session-secret")
            .unwrap()
            .to_string(),
        headers: BTreeMap::new(),
        body: Vec::new(),
        response_limit: 1024,
    }
}

#[test]
fn certificate_pin_mismatch_never_downgrades_or_dispatches_fallback() {
    let root = TestDir::new();
    let pins = PinStore::new(root.0.join("pins.json"));

    let (first_origin, first_server) = tls_server();
    let mut first = BlockingHttpTransport::new(HttpTransportConfig {
        origin: first_origin.clone(),
        pin_store: pins.clone(),
        insecure_tls: false,
        allow_http_fallback: false,
        timeout: Duration::from_secs(3),
        warning_sink: None,
    })
    .unwrap();
    assert_eq!(first.send(request(&first_origin)).unwrap().body, b"OK");
    assert!(first_server.join().unwrap());
    let pinned = pins.get("127.0.0.1").expect("initial pin persisted");

    let warnings = Arc::new(Mutex::new(Vec::new()));
    let warning_sink = Arc::clone(&warnings);
    let (changed_origin, changed_server) = tls_server();
    let mut changed = BlockingHttpTransport::new(HttpTransportConfig {
        origin: changed_origin.clone(),
        pin_store: pins.clone(),
        insecure_tls: false,
        allow_http_fallback: true,
        timeout: Duration::from_secs(3),
        warning_sink: Some(Arc::new(move |warning| {
            warning_sink.lock().unwrap().push(warning.to_owned())
        })),
    })
    .unwrap();
    let error = changed
        .send(request(&changed_origin))
        .unwrap_err()
        .to_string();
    assert!(error.contains("certificate pin mismatch"), "{error}");
    assert!(!error.contains("session-secret"), "query leaked: {error}");
    assert!(
        changed.tls_enabled(),
        "integrity failure must not disable TLS"
    );
    assert!(
        warnings.lock().unwrap().is_empty(),
        "integrity failure is not a fallback warning"
    );
    assert!(
        !changed_server.join().unwrap(),
        "server must not receive an HTTP request after TLS rejection"
    );
    assert_eq!(pins.get("127.0.0.1").as_deref(), Some(pinned.as_str()));
}
