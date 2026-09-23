#![deny(unsafe_code)]
#![cfg(unix)]

//! Readiness-synchronized cancellation regression for the reboot side effect.
//!
//! `symfritz reboot --yes --json` posts `Reboot` to the DeviceConfig control
//! URL without credentials first; the box answers that first POST with an
//! HTTP 401 carrying the Digest challenge, and the client repeats the POST
//! authenticated.
//!
//! Each case here holds that first unauthenticated POST — the 401 has not
//! been released yet — and delivers SIGINT, SIGTERM or SIGHUP while the
//! challenge is still in flight (`ctrlc`'s `termination` feature handles all
//! three on Unix), releasing the 401 only afterwards. The documented contract
//! (`docs/rust-port/contract-matrix.md`, CLI-010 and MCP-004) requires the
//! cancellation to win over the in-flight challenge:
//!
//! * no second, authenticated Reboot POST may reach the box,
//! * no success payload may be printed,
//! * the process exits with the documented cancel exit 130,
//! * termination stays bounded.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Condvar, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

/// DeviceConfig control URL that `symfritz reboot` posts `Reboot` to.
const REBOOT_CONTROL: &str = "/upnp/control/deviceconfig";
/// Challenge header mirroring the loopback doubles used by the other tests.
const DIGEST_CHALLENGE: &str =
    "Digest realm=\"symfritz-test\", nonce=\"fixed-test-nonce\", qop=\"auth\", algorithm=MD5";
/// Successful `Reboot` answer, shaped like the other loopback doubles.
const REBOOT_RESPONSE: &str = "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:RebootResponse xmlns:u=\"urn:dslforum-org:service:DeviceConfig:1\"></u:RebootResponse></s:Body></s:Envelope>";
/// Discovery answer so an unexpected description fetch cannot mask the run.
const DESCRIPTION: &str = "<root xmlns=\"urn:dslforum-org:device-1-0\"><device><serviceList><service><serviceType>urn:dslforum-org:service:DeviceConfig:1</serviceType><controlURL>/upnp/control/deviceconfig</controlURL></service></serviceList></device></root>";

/// Bound on the held challenge request reaching the mock box.
const READY_BOUND: Duration = Duration::from_secs(30);
/// Bound on child termination after the signal and the challenge release.
const EXIT_BOUND: Duration = Duration::from_secs(20);
/// Grace for the signal handler thread to record cancellation before the
/// challenge is released; the CLI is blocked reading the held response.
const HANDLER_SETTLE: Duration = Duration::from_millis(250);
/// Safety bound so a failed run never blocks a server thread forever.
const RELEASE_BOUND: Duration = Duration::from_secs(60);

/// A loopback FRITZ!Box double that holds the first unauthenticated Reboot
/// POST until the test releases it.
struct ChallengeBox {
    port: u16,
    home: PathBuf,
    ready: mpsc::Receiver<()>,
    release: Arc<(Mutex<bool>, Condvar)>,
    requests: Arc<Mutex<Vec<(String, bool)>>>,
}

impl ChallengeBox {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind challenge box");
        let port = listener.local_addr().expect("challenge box address").port();
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let requests: Arc<Mutex<Vec<(String, bool)>>> = Arc::default();

        let accept_release = Arc::clone(&release);
        let accept_requests = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else {
                    return;
                };
                let ready = ready_tx.clone();
                let release = Arc::clone(&accept_release);
                let requests = Arc::clone(&accept_requests);
                thread::spawn(move || {
                    let _ = serve(stream, ready, release, requests);
                });
            }
        });

        let home = std::env::temp_dir().join(format!(
            "symfritz-reboot-cancel-{}-{port}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join("tmp")).expect("isolated test home");

        Self {
            port,
            home,
            ready: ready_rx,
            release,
            requests,
        }
    }

    /// Requests seen so far, as `(path, authorized)` pairs.
    fn requests(&self) -> Vec<(String, bool)> {
        self.requests.lock().expect("request log").clone()
    }

    fn release_challenge(&self) {
        let (flag, condvar) = &*self.release;
        *flag.lock().expect("release flag") = true;
        condvar.notify_all();
    }

    /// Point a child process at this box, isolated from the host config.
    fn command(&self, binary: &str) -> Command {
        let mut command = Command::new(binary);
        command
            .current_dir(&self.home)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join("config"))
            .env("TMPDIR", self.home.join("tmp"))
            .env("SYMFRITZ_BOX_HOST", format!("127.0.0.1:{}", self.port))
            .env("SYMFRITZ_BOX_USER", "admin")
            .env("SYMFRITZ_BOX_USE_TLS", "false")
            .env("SYMFRITZ_PASSWORD", "test-password")
            .env("SYMFRITZ_BOX_TIMEOUT_SECONDS", "15")
            .env_remove("SYMFRITZ_HOST")
            .env_remove("SYMFRITZ_USER")
            .env_remove("SYMFRITZ_BOX_PASSWORD_REF")
            .env_remove("SYMFRITZ_BOX_KEYCHAIN")
            .env_remove("SYMFRITZ_BOX_INSECURE_TLS")
            .env_remove("SYMFRITZ_BOX_ALLOW_HTTP_FALLBACK");
        command
    }
}

impl Drop for ChallengeBox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

/// Serve one connection: hold the unauthenticated Reboot POST, challenge it
/// only after the release, and answer an authenticated retry with success.
fn serve(
    mut stream: TcpStream,
    ready: mpsc::Sender<()>,
    release: Arc<(Mutex<bool>, Condvar)>,
    requests: Arc<Mutex<Vec<(String, bool)>>>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut head_lines = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" || line.is_empty() {
            break;
        }
        head_lines.push(line);
    }

    let request_line = head_lines.first().cloned().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();

    let mut content_length = 0_usize;
    let mut authorized = false;
    for line in head_lines.iter().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => content_length = value.parse().unwrap_or(0),
            "authorization" => authorized = !value.is_empty(),
            _ => {}
        }
    }
    if content_length > 0 {
        // Drain the Reboot body (it carries no arguments) so the parse
        // mirrors a real request before any response is written.
        let mut body = vec![0_u8; content_length];
        reader.read_exact(&mut body)?;
    }

    if method == "GET" && path == "/tr64desc.xml" {
        return respond(&mut stream, "200 OK", "text/xml", DESCRIPTION, &[]);
    }

    if method == "POST" && path == REBOOT_CONTROL {
        requests
            .lock()
            .expect("request log")
            .push((path.clone(), authorized));
        if authorized {
            return respond(&mut stream, "200 OK", "text/xml", REBOOT_RESPONSE, &[]);
        }
        // First unauthenticated Reboot POST: announce readiness and hold the
        // connection so the test can signal the CLI before the 401 Digest
        // challenge is released.
        let _ = ready.send(());
        let (flag, condvar) = &*release;
        let mut released = flag.lock().expect("release flag");
        while !*released {
            let (guard, timeout) = condvar
                .wait_timeout(released, RELEASE_BOUND)
                .expect("release state");
            released = guard;
            if timeout.timed_out() {
                break;
            }
        }
        return respond(
            &mut stream,
            "401 Unauthorized",
            "text/xml",
            "",
            &[("WWW-Authenticate", DIGEST_CHALLENGE)],
        );
    }

    respond(&mut stream, "404 Not Found", "text/plain", "not found", &[])
}

fn respond(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> std::io::Result<()> {
    let mut response =
        format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nConnection: close\r\n");
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    response.push_str(body);
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

/// The CLI under test; never left behind when an assertion fails first.
struct RebootProcess {
    child: Child,
}

impl Drop for RebootProcess {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn send_signal(pid: u32, signal: &str) {
    let status = Command::new("kill")
        .args(["-s", signal, &pid.to_string()])
        .status()
        .expect("kill(1) must exist on unix");
    assert!(
        status.success(),
        "kill -s {signal} {pid} must reach the CLI: {status:?}"
    );
}

/// Poll for exit up to `bound`; returns the status and whether it timed out.
fn wait_bounded(child: &mut Child, bound: Duration) -> (std::process::ExitStatus, bool) {
    let deadline = Instant::now() + bound;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return (status, false),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let status = child.wait().expect("reap timed-out reboot");
                return (status, true);
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => panic!("waiting for symfritz reboot: {error}"),
        }
    }
}

/// Deliver `signal` during the held first challenge and assert the
/// cancellation contract for `symfritz reboot --yes --json`.
fn assert_cancelled_reboot(signal: &str) {
    let box_ = ChallengeBox::start();
    let binary = env!("CARGO_BIN_EXE_symfritz");
    let mut process = RebootProcess {
        child: box_
            .command(binary)
            .args(["reboot", "--yes", "--json"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start symfritz reboot"),
    };
    let pid = process.child.id();
    let mut stdout = process.child.stdout.take().expect("stdout pipe");
    let mut stderr = process.child.stderr.take().expect("stderr pipe");

    // Readiness: the first, still-unauthenticated Reboot POST is held and no
    // 401 has been written yet.
    box_.ready
        .recv_timeout(READY_BOUND)
        .expect("the first unauthenticated Reboot POST must reach the box");

    send_signal(pid, signal);
    thread::sleep(HANDLER_SETTLE);
    box_.release_challenge();

    let (status, timed_out) = wait_bounded(&mut process.child, EXIT_BOUND);

    let mut out = Vec::new();
    stdout.read_to_end(&mut out).expect("read stdout");
    let mut err = Vec::new();
    stderr.read_to_end(&mut err).expect("read stderr");
    let stdout_text = String::from_utf8_lossy(&out);
    let stderr_text = String::from_utf8_lossy(&err);
    let requests = box_.requests();
    let reboot_posts = requests
        .iter()
        .filter(|(path, _)| path == REBOOT_CONTROL)
        .count();
    let context = format!(
        "after {signal} during the held 401 challenge: status={status:?}, \
         reboot_posts={reboot_posts}, requests={requests:?}, \
         stdout={stdout_text:?}, stderr={stderr_text:?}"
    );

    assert!(
        !timed_out,
        "reboot must terminate within {EXIT_BOUND:?} of the cancelled \
         challenge — {context}"
    );
    assert!(
        !requests.iter().any(|(_, authorized)| *authorized),
        "a cancelled reboot must never send the second authenticated Reboot \
         POST — {context}"
    );
    assert_eq!(
        reboot_posts, 1,
        "exactly the held unauthenticated Reboot POST may reach the box — \
         {context}"
    );
    assert!(
        !stdout_text.contains("\"ok\": true")
            && !stdout_text.contains("\"triggered\": true")
            && !stdout_text.contains("Reboot triggered"),
        "a cancelled reboot must print no success output — {context}"
    );
    assert_eq!(
        status.code(),
        Some(130),
        "cancellation must exit with the documented cancel exit 130 — \
         {context}"
    );
}

#[test]
fn sigint_during_reboot_challenge_cancels_before_the_authenticated_retry() {
    assert_cancelled_reboot("INT");
}

#[test]
fn sigterm_during_reboot_challenge_cancels_before_the_authenticated_retry() {
    assert_cancelled_reboot("TERM");
}

/// SIGHUP is covered where the platform supports it: `ctrlc`'s `termination`
/// feature installs a SIGHUP handler on Unix.
#[test]
fn sighup_during_reboot_challenge_cancels_before_the_authenticated_retry() {
    assert_cancelled_reboot("HUP");
}
