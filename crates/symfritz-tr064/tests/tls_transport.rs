#![deny(unsafe_code)]

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
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
            "symfritz-tls-transport-{}-{:?}",
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

fn spawn_tls_server(respond: bool) -> (Url, thread::JoinHandle<()>) {
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
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let mut tls = StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), stream);
        let mut request = [0_u8; 4096];
        if tls.read(&mut request).is_err() {
            return;
        }
        if respond {
            let _ = tls
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
            let _ = tls.flush();
        }
    });
    (Url::parse(&format!("https://{address}")).unwrap(), handle)
}

fn spawn_tls_close_delimited_server() -> (Url, thread::JoinHandle<()>) {
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
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let mut tls = StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), stream);
        let mut request = [0_u8; 4096];
        if tls.read(&mut request).is_err() {
            return;
        }
        let _ = tls
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nConnection: close\r\n\r\nOK");
        let _ = tls.flush();
        // FRITZ!OS closes these response streams without TLS close_notify.
    });
    (Url::parse(&format!("https://{address}")).unwrap(), handle)
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

fn spawn_redirect_server() -> (Url, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut request = [0_u8; 4096];
        if stream.read(&mut request).is_err() {
            return;
        }
        let _ = stream.write_all(
            b"HTTP/1.1 302 Found\r\nLocation: http://8.8.8.8/blocked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let _ = stream.flush();
    });
    (Url::parse(&format!("http://{address}")).unwrap(), handle)
}

#[test]
fn tofu_accepts_first_certificate_and_rejects_changed_certificate() {
    let root = TestDir::new();
    let pin_store = PinStore::new(root.0.join("pins.json"));

    let (first_origin, first_server) = spawn_tls_server(true);
    let mut first_transport = BlockingHttpTransport::new(HttpTransportConfig {
        origin: first_origin.clone(),
        pin_store: pin_store.clone(),
        insecure_tls: false,
        timeout: Duration::from_secs(5),
        warning_sink: None,
    })
    .unwrap();
    let response = first_transport.send(request(&first_origin)).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"OK");
    first_server.join().unwrap();

    let stored = pin_store
        .get("127.0.0.1")
        .expect("first certificate pinned");
    let (changed_origin, changed_server) = spawn_tls_server(true);
    let mut changed_transport = BlockingHttpTransport::new(HttpTransportConfig {
        origin: changed_origin.clone(),
        pin_store: pin_store.clone(),
        insecure_tls: false,
        timeout: Duration::from_secs(5),
        warning_sink: None,
    })
    .unwrap();
    let error = changed_transport
        .send(request(&changed_origin))
        .unwrap_err();
    assert!(
        error.to_string().contains("certificate pin mismatch"),
        "unexpected error: {error}"
    );
    changed_server.join().unwrap();
    assert_eq!(pin_store.get("127.0.0.1").as_deref(), Some(stored.as_str()));
}

#[test]
fn unclean_tls_close_delimited_body_is_accepted() {
    let root = TestDir::new();
    let (origin, server) = spawn_tls_close_delimited_server();
    let mut transport = BlockingHttpTransport::new(HttpTransportConfig {
        origin: origin.clone(),
        pin_store: PinStore::new(root.0.join("pins.json")),
        insecure_tls: true,
        timeout: Duration::from_secs(5),
        warning_sink: None,
    })
    .unwrap();
    let response = transport.send(request(&origin)).unwrap();
    server.join().unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"OK");
}

#[test]
fn first_certificate_is_not_persisted_until_http_response_arrives() {
    let root = TestDir::new();
    let pin_store = PinStore::new(root.0.join("pins.json"));
    let (origin, server) = spawn_tls_server(false);
    let mut transport = BlockingHttpTransport::new(HttpTransportConfig {
        origin: origin.clone(),
        pin_store: pin_store.clone(),
        insecure_tls: false,
        timeout: Duration::from_secs(5),
        warning_sink: None,
    })
    .unwrap();

    assert!(transport.send(request(&origin)).is_err());
    server.join().unwrap();
    assert_eq!(pin_store.get("127.0.0.1"), None);
}

#[test]
fn endpoint_unreachable_falls_back_once_and_reuses_http() {
    static PORT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = PORT_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let tls_probe = TcpListener::bind("127.0.0.1:49443")
        .expect("test requires the FRITZ!Box TLS fallback port to be free");
    drop(tls_probe);

    let root = TestDir::new();
    let warnings = Arc::new(Mutex::new(Vec::new()));
    let warning_values = warnings.clone();
    let http_server = spawn_plain_http_server(2);
    let origin = Url::parse("https://127.0.0.1:49443").unwrap();
    let mut transport = BlockingHttpTransport::new(HttpTransportConfig {
        origin: origin.clone(),
        pin_store: PinStore::new(root.0.join("pins.json")),
        insecure_tls: false,
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
fn redirects_are_returned_without_following_cross_origin_location() {
    let root = TestDir::new();
    let (origin, server) = spawn_redirect_server();
    let mut transport = BlockingHttpTransport::new(HttpTransportConfig::new(
        origin.clone(),
        PinStore::new(root.0.join("pins.json")),
    ))
    .unwrap();

    let response = transport.send(request(&origin)).unwrap();
    server.join().unwrap();
    assert_eq!(response.status, 302);
    assert!(response.body.is_empty());
}

#[test]
fn network_error_does_not_expose_sensitive_query_values() {
    let root = TestDir::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let origin = Url::parse(&format!("http://{address}")).unwrap();
    let mut transport = BlockingHttpTransport::new(HttpTransportConfig::new(
        origin.clone(),
        PinStore::new(root.0.join("pins.json")),
    ))
    .unwrap();
    let mut request = request(&origin);
    request.url = origin
        .join("health?sid=sensitive-session-value&password=sensitive-password")
        .unwrap()
        .to_string();

    let error = transport.send(request).unwrap_err().to_string();
    assert!(!error.contains("sensitive-session-value"));
    assert!(!error.contains("sensitive-password"));
}

#[test]
fn concrete_transport_truncates_without_content_length_probe() {
    let limit = 1024;
    let mut body = b"OK\n".to_vec();
    body.resize(limit + 16, b'x');
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let body_len = body.len();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 4096];
        let _bytes_read = stream.read(&mut request).unwrap();
        let headers =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n");
        stream.write_all(headers.as_bytes()).unwrap();
        stream.write_all(&body).unwrap();
        stream.flush().unwrap();
    });

    let root = TestDir::new();
    let origin = Url::parse(&format!("http://{address}")).unwrap();
    let mut transport = BlockingHttpTransport::new(HttpTransportConfig::new(
        origin.clone(),
        PinStore::new(root.0.join("pins.json")),
    ))
    .unwrap();
    let response = transport
        .send(Request {
            method: Method::Get,
            url: origin.join("health").unwrap().to_string(),
            headers: BTreeMap::new(),
            body: Vec::new(),
            response_limit: limit,
        })
        .unwrap();
    server.join().unwrap();
    assert_eq!(response.body.len(), limit);
    assert!(response.body.starts_with(b"OK\n"));
}
