#![deny(unsafe_code)]

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    thread,
    time::Duration,
};

use symfritz_core::pins::PinStore;
use symfritz_tr064::{BlockingHttpTransport, HttpTransportConfig, Method, Request, Transport};
use url::Url;

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "symfritz-transport-contracts-{}-{:?}",
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

fn server_with_response(response: &'static [u8]) -> (Url, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let count = stream.read(&mut buffer).unwrap();
            assert_ne!(count, 0, "request ended before headers arrived");
            request.extend_from_slice(&buffer[..count]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        stream.write_all(response).unwrap();
        stream.flush().unwrap();
        request
    });
    (Url::parse(&format!("http://{address}")).unwrap(), server)
}

fn transport(origin: &Url, pins: &TestDir) -> BlockingHttpTransport {
    let mut config =
        HttpTransportConfig::new(origin.clone(), PinStore::new(pins.0.join("pins.json")));
    config.timeout = Duration::from_secs(2);
    BlockingHttpTransport::new(config).unwrap()
}

fn request(url: &Url) -> Request {
    Request {
        method: Method::Get,
        url: url.as_str().to_owned(),
        headers: BTreeMap::new(),
        body: Vec::new(),
        response_limit: 1024,
    }
}

#[test]
fn response_parser_rejects_malformed_status_header_and_body_framing() {
    let cases: &[(&[u8], &str)] = &[
        (
            b"HTTP/2 200 OK\r\nContent-Length: 0\r\n\r\n",
            "unsupported HTTP response version",
        ),
        (
            b"HTTP/1.1 200 OK\r\nbroken-header\r\n\r\n",
            "response header is malformed",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n",
            "duplicate content-length header",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
            "both Content-Length and Transfer-Encoding",
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
            "unsupported response transfer encoding",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n",
            "Content-Length is malformed",
        ),
        (
            b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n",
            "no framing or connection close",
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nz;ext=x\r\n",
            "chunk size is malformed",
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nxZZ\r\n",
            "chunk terminator is malformed",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nxy",
            "unexpected EOF while reading response body",
        ),
    ];
    let pins = TestDir::new();
    for (wire, expected) in cases {
        let (origin, server) = server_with_response(wire);
        let mut client = transport(&origin, &pins);
        let target = origin.join("health?sid=transport-secret").unwrap();
        let error = client.send(request(&target)).unwrap_err().to_string();
        let request_line = String::from_utf8(server.join().unwrap()).unwrap();
        assert!(request_line.starts_with("GET /health?sid=transport-secret HTTP/1.1"));
        assert!(
            error.contains(expected),
            "expected {expected:?}, got {error:?}"
        );
        assert!(
            !error.contains("transport-secret"),
            "secret leaked: {error}"
        );
    }
}

#[test]
fn empty_status_response_needs_no_body_framing() {
    let (origin, server) = server_with_response(b"HTTP/1.1 204 No Content\r\n\r\n");
    let pins = TestDir::new();
    let mut client = transport(&origin, &pins);
    let response = client
        .send(request(&origin.join("health").unwrap()))
        .unwrap();
    assert_eq!(response.status, 204);
    assert!(response.body.is_empty());
    server.join().unwrap();
}

#[test]
fn transport_rejects_cross_origin_and_userinfo_before_dispatch() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let origin = Url::parse(&format!("http://{address}")).unwrap();
    let pins = TestDir::new();
    let mut client = transport(&origin, &pins);

    let cross_origin = Url::parse(&format!("http://localhost:{}/blocked", address.port())).unwrap();
    let error = client.send(request(&cross_origin)).unwrap_err().to_string();
    assert!(error.contains("outside configured origin"));
    assert!(error.contains("localhost"));

    let credentialed = Url::parse(&format!("http://admin:secret@{address}/blocked")).unwrap();
    let error = client.send(request(&credentialed)).unwrap_err().to_string();
    assert!(error.contains("userinfo is not allowed"));
    assert!(!error.contains("admin"));
    assert!(!error.contains("secret"));
    drop(listener);
}
