//! Bounded, read-only resolver configuration snapshots, not OS/NSS lookups.

use symfritz_tr064::dns::SystemDnsEvidence;

#[cfg(any(target_os = "macos", target_os = "linux", test))]
use {std::net::IpAddr, symfritz_tr064::dns::DnsEvidence};

#[cfg(any(target_os = "macos", target_os = "linux", test))]
const MAX_OUTPUT: usize = 65_536;

pub fn collect(cancelled: &dyn Fn() -> bool) -> SystemDnsEvidence {
    if cancelled() {
        return SystemDnsEvidence::default();
    }
    #[cfg(target_os = "macos")]
    {
        let mut command = std::process::Command::new("/usr/sbin/scutil");
        command.arg("--dns");
        match bounded_output(command, std::time::Duration::from_secs(2), cancelled) {
            Ok(text) => parse_scutil(&text),
            Err(reason) => SystemDnsEvidence {
                resolvers: DnsEvidence::unknown(reason),
                search_domains: DnsEvidence::unknown(reason),
            },
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;
        let text = (|| {
            let path = std::path::Path::new("/etc/resolv.conf");
            if !std::fs::metadata(path).ok()?.is_file() {
                return None;
            }
            let mut bytes = Vec::new();
            std::fs::File::open(path)
                .ok()?
                .take((MAX_OUTPUT + 1) as u64)
                .read_to_end(&mut bytes)
                .ok()?;
            if bytes.len() > MAX_OUTPUT {
                return None;
            }
            String::from_utf8(bytes).ok()
        })();
        text.map_or_else(SystemDnsEvidence::default, |text| parse_resolv_conf(&text))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    SystemDnsEvidence::default()
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn snapshot(resolvers: Vec<String>, domains: Vec<String>, source: &str) -> SystemDnsEvidence {
    let mut ips = Vec::new();
    let valid = resolvers.iter().all(|value| {
        if let Ok(ip) = value.parse::<IpAddr>() {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
            true
        } else {
            false
        }
    });
    let mut unique_domains = Vec::new();
    for domain in domains {
        if !unique_domains.contains(&domain) {
            unique_domains.push(domain);
        }
    }
    SystemDnsEvidence {
        resolvers: if valid && !ips.is_empty() && ips.len() <= 4 {
            DnsEvidence::known(ips, source)
        } else {
            DnsEvidence::unknown(
                "resolver snapshot missing, invalid/scoped, or exceeds four addresses",
            )
        },
        search_domains: if unique_domains.len() <= 6 {
            DnsEvidence::known(unique_domains, source)
        } else {
            DnsEvidence::unknown("search snapshot exceeds six domains")
        },
    }
}

#[cfg(any(target_os = "macos", test))]
fn parse_scutil(text: &str) -> SystemDnsEvidence {
    if text.len() > MAX_OUTPUT || !text.contains("resolver #") {
        return SystemDnsEvidence::default();
    }
    let mut resolvers = Vec::new();
    let mut domains = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        // Split on " : " rather than ':' inside an IPv6 address.
        let Some((key, value)) = line.split_once(" : ") else {
            continue;
        };
        if key.trim().starts_with("nameserver[") {
            resolvers.push(value.trim().to_owned());
        } else if key.trim().starts_with("search domain[") {
            domains.push(value.trim().to_owned());
        }
        // A resolver's routing "domain" is NOT a DHCP/search suffix.
    }
    snapshot(
        resolvers,
        domains,
        "scutil --dns configured resolver union; scoped/VPN routing and OS/NSS selection not inferred",
    )
}

#[cfg(any(target_os = "linux", test))]
fn parse_resolv_conf(text: &str) -> SystemDnsEvidence {
    if text.len() > MAX_OUTPUT {
        return SystemDnsEvidence::default();
    }
    let mut resolvers = Vec::new();
    let mut domains = Vec::new();
    for line in text.lines() {
        let mut fields = line
            .split(['#', ';'])
            .next()
            .unwrap_or("")
            .split_whitespace();
        match fields.next() {
            Some("nameserver") => {
                if let Some(value) = fields.next() {
                    resolvers.push(value.to_owned());
                }
            }
            Some("search") => domains = fields.map(str::to_owned).collect(),
            Some("domain") => domains = fields.take(1).map(str::to_owned).collect(),
            _ => (),
        }
    }
    snapshot(
        resolvers,
        domains,
        "/etc/resolv.conf snapshot; stub, VPN, split DNS and OS/NSS selection not inferred",
    )
}

/// Only the fixed, trusted, non-forking scutil utility is used in production.
/// A nonblocking socket avoids pipe-reader threads or inherited-pipe EOF hangs.
#[cfg(all(unix, any(target_os = "macos", test)))]
fn bounded_output(
    mut command: std::process::Command,
    timeout: std::time::Duration,
    cancelled: &dyn Fn() -> bool,
) -> Result<String, &'static str> {
    use std::{
        io::{ErrorKind, Read},
        os::{fd::OwnedFd, unix::net::UnixStream},
        process::Stdio,
        time::Instant,
    };
    let (mut reader, writer) = UnixStream::pair().map_err(|_| "resolver capture unavailable")?;
    reader
        .set_nonblocking(true)
        .map_err(|_| "resolver capture unavailable")?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "resolver utility unavailable")?;
    // Command retains its configured socket descriptor after spawning.
    drop(command);
    let mut exited = None;
    let result = (|| {
        let started = Instant::now();
        let mut bytes = Vec::new();
        let mut eof = false;
        loop {
            if cancelled() || started.elapsed() >= timeout {
                return Err("resolver snapshot cancelled or timed out");
            }
            let mut buffer = [0_u8; 4096];
            match reader.read(&mut buffer) {
                Ok(0) => eof = true,
                Ok(count) => {
                    bytes.extend_from_slice(&buffer[..count]);
                    if bytes.len() > MAX_OUTPUT {
                        return Err("resolver snapshot exceeds output bound");
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => (),
                Err(_) => return Err("resolver capture failed"),
            }
            if exited.is_none() {
                exited = child
                    .try_wait()
                    .map_err(|_| "resolver utility wait failed")?;
            }
            if let Some(status) = exited
                && eof
            {
                if !status.success() {
                    return Err("resolver utility failed");
                }
                return String::from_utf8(bytes).map_err(|_| "resolver snapshot is not UTF-8");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    })();
    if exited.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_keep_search_routing_and_missing_evidence_distinct() {
        let report = parse_scutil(
            "DNS configuration\nresolver #1\n  nameserver[0] : 192.168.50.2\n  search domain[0] : fritz.box\nresolver #2\n  domain : local\n  options : mdns\nresolver #3\n  nameserver[0] : 192.168.50.2\n",
        );
        assert_eq!(report.resolvers.value.unwrap().len(), 1);
        assert_eq!(report.search_domains.value.unwrap(), ["fritz.box"]);
        assert!(
            parse_scutil("No DNS configuration available")
                .resolvers
                .value
                .is_none()
        );
        let no_suffix = parse_scutil("resolver #1\n  nameserver[0] : fd00::2\n  domain : local\n");
        assert_eq!(no_suffix.search_domains.value, Some(vec![]));
        assert_eq!(
            no_suffix.resolvers.value.unwrap(),
            ["fd00::2".parse::<IpAddr>().unwrap()]
        );
        assert!(
            parse_scutil("resolver #1\n  nameserver[0] : fe80::1%en0\n")
                .resolvers
                .value
                .is_none()
        );
        let linux =
            parse_resolv_conf("nameserver 127.0.0.53 # stub\nsearch old.zone\ndomain fritz.box\n");
        assert_eq!(linux.search_domains.value.unwrap(), ["fritz.box"]);
        assert!(
            linux
                .resolvers
                .source
                .contains("OS/NSS selection not inferred")
        );
        let many = (1..=5)
            .map(|n| format!("nameserver 192.168.50.{n}\n"))
            .collect::<String>();
        assert!(parse_resolv_conf(&many).resolvers.value.is_none());
        assert!(collect(&|| true).resolvers.value.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn utility_capture_bounds_time_output_and_cancellation_without_reader_threads() {
        use std::{
            process::Command,
            time::{Duration, Instant},
        };
        let mut success = Command::new("/bin/sh");
        success.args(["-c", "printf 'captured'"]);
        assert_eq!(
            bounded_output(success, Duration::from_secs(1), &|| false).unwrap(),
            "captured"
        );
        let mut noisy = Command::new("/bin/sh");
        noisy.args([
            "-c",
            "while :; do printf '0123456789012345678901234567890123456789'; done",
        ]);
        assert_eq!(
            bounded_output(noisy, Duration::from_secs(1), &|| false),
            Err("resolver snapshot exceeds output bound")
        );
        for cancel in [false, true] {
            let mut idle = Command::new("/bin/sleep");
            idle.arg("5");
            let started = Instant::now();
            assert!(bounded_output(idle, Duration::from_millis(50), &|| cancel).is_err());
            assert!(started.elapsed() < Duration::from_secs(1));
        }
    }
}
