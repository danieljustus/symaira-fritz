//! Opt-in, read-only DNS-path diagnostics. No inventory-wide DNS lookups, NSS
//! lookups, subprocesses, resolver discovery by DNS, or configuration writes.
//!
//! System/lease evidence is supplied by the caller: a TR-064 domain name is NOT
//! DHCP option 15, and resolv.conf is not authoritative on every platform. Native
//! probes query one exact absolute name over UDP; they do not emulate OS search,
//! hosts-file, mDNS, VPN routing, DoH, or split-resolver selection.

use std::collections::{BTreeMap, hash_map::RandomState};
use std::hash::BuildHasher;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::{Client, CnonceSource, Transport, is_private_ip};

const MAX_RESOLVERS: usize = 4;
const MAX_SEARCH_DOMAINS: usize = 6;
const MAX_PROBE_TIME: Duration = Duration::from_millis(500);
const DNS_BUDGET: Duration = Duration::from_secs(5);

/// `None` means unobserved, unavailable, or unsupported, never false/empty.
/// `Some(vec![])` is explicit evidence of an empty list.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DnsEvidence<T> {
    pub value: Option<T>,
    pub source: String,
}

impl<T> DnsEvidence<T> {
    pub fn known(value: T, source: impl Into<String>) -> Self {
        Self {
            value: Some(value),
            source: source.into(),
        }
    }

    pub fn unknown(reason: impl Into<String>) -> Self {
        Self {
            value: None,
            source: reason.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SystemDnsEvidence {
    pub resolvers: DnsEvidence<Vec<IpAddr>>,
    pub search_domains: DnsEvidence<Vec<String>>,
}

impl Default for SystemDnsEvidence {
    fn default() -> Self {
        Self {
            resolvers: DnsEvidence::unknown("effective system resolvers not observed"),
            search_domains: DnsEvidence::unknown("effective system search domains not observed"),
        }
    }
}

/// Explicit inputs; constructing these does not perform I/O.
#[derive(Clone, Debug)]
pub struct DnsDiagnosticOptions {
    pub hostname: String,
    /// Enables a single typed host-table lookup by IP. No table enumeration.
    pub expected_host_ip: Option<IpAddr>,
    /// Needed when the configured router is a hostname. Never resolve it via NSS.
    pub router_dns_ip: Option<IpAddr>,
    pub system: SystemDnsEvidence,
    /// Actual lease/capture evidence supplied by a caller, NOT GetInfo.DomainName.
    pub dhcp_option15: DnsEvidence<String>,
    pub query_timeout: Duration,
}

impl DnsDiagnosticOptions {
    pub fn new(hostname: impl Into<String>) -> Self {
        Self {
            hostname: hostname.into(),
            expected_host_ip: None,
            router_dns_ip: None,
            system: SystemDnsEvidence::default(),
            dhcp_option15: DnsEvidence::unknown("DHCP option 15 not observed"),
            query_timeout: Duration::from_millis(200),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsNameKind {
    Bare,
    Fqdn,
    Mdns,
}

#[derive(Clone, Debug, Serialize)]
pub struct DhcpDnsEvidence {
    pub enabled: DnsEvidence<bool>,
    pub resolvers: DnsEvidence<Vec<IpAddr>>,
    /// Informational router field; never used as a suffix or option-15 evidence.
    pub tr064_domain_name: DnsEvidence<String>,
    pub option15: DnsEvidence<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DnsSelectedHost {
    pub expected_ip: Option<IpAddr>,
    pub table_name: DnsEvidence<String>,
    /// Host-table activity is not a reachability test.
    pub table_active: DnsEvidence<bool>,
    /// DNS diagnosis deliberately performs no ping/TCP host probe.
    pub ip_connectivity: DnsEvidence<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsResolverRole {
    Router,
    Dhcp,
    System,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsRecordType {
    A,
    Aaaa,
}

impl DnsRecordType {
    fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }
    fn matches(self, ip: IpAddr) -> bool {
        matches!(
            (self, ip),
            (Self::A, IpAddr::V4(_)) | (Self::Aaaa, IpAddr::V6(_))
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsOutcome {
    LocalAnswer,
    PublicAnswer,
    MixedAnswer,
    #[serde(rename = "nxdomain")]
    NxDomain,
    NoData,
    Timeout,
    Unknown,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsAddressMatch {
    Match,
    Mismatch,
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
pub struct DnsLookupResult {
    pub resolver: IpAddr,
    pub roles: Vec<DnsResolverRole>,
    pub name: String,
    pub record_type: DnsRecordType,
    pub outcome: DnsOutcome,
    pub addresses: Vec<IpAddr>,
    /// Compared only with an explicit expectation of the same address family.
    /// Local scope alone never implies a correct host answer.
    pub address_match: DnsAddressMatch,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DnsDiagnostic {
    /// Host portion only: no credentials, URL userinfo, or transport URL logged.
    pub configured_router: String,
    pub router_dns: DnsEvidence<IpAddr>,
    pub selected_hostname: String,
    pub name_kind: DnsNameKind,
    pub dhcp: DhcpDnsEvidence,
    pub system: SystemDnsEvidence,
    pub selected_host: DnsSelectedHost,
    pub lookups: Vec<DnsLookupResult>,
    pub dns_filter_enabled: DnsEvidence<bool>,
    /// Actual OS/NSS resolution is not inferred from direct UDP probes.
    pub system_name_resolution: DnsEvidence<Vec<IpAddr>>,
    pub cancelled: bool,
    pub explanations: Vec<String>,
}

/// Probe seam for offline tests and platform adapters. Implementations MUST
/// honor `timeout`, bound their output, and finish without detached work.
pub trait DnsProbe {
    fn query(
        &mut self,
        resolver: IpAddr,
        name: &str,
        record_type: DnsRecordType,
        timeout: Duration,
    ) -> DnsProbeAnswer;
}

#[derive(Clone, Debug, Serialize)]
pub struct DnsProbeAnswer {
    pub outcome: DnsOutcome,
    pub addresses: Vec<IpAddr>,
    pub detail: String,
}

impl DnsProbeAnswer {
    fn status(outcome: DnsOutcome, detail: impl Into<String>) -> Self {
        Self {
            outcome,
            addresses: Vec::new(),
            detail: detail.into(),
        }
    }

    /// Scope classification is not an assertion of host identity or ownership.
    pub fn addresses(addresses: Vec<IpAddr>) -> Self {
        let local = addresses
            .iter()
            .any(|ip| is_private_ip(*ip) || ip.is_loopback());
        let public = addresses
            .iter()
            .any(|ip| !is_private_ip(*ip) && !ip.is_loopback());
        let outcome = match (local, public) {
            (true, false) => DnsOutcome::LocalAnswer,
            (false, true) => DnsOutcome::PublicAnswer,
            (true, true) => DnsOutcome::MixedAnswer,
            _ => DnsOutcome::NoData,
        };
        Self {
            outcome,
            addresses,
            detail: "address scope; compare expected IP separately".into(),
        }
    }
}

impl<T: Transport, C: CnonceSource> Client<T, C> {
    /// Explicit opt-in diagnostic; never called as part of normal status.
    ///
    /// TR-064 steps inherit the existing Transport's finite deadline (configure
    /// HttpTransportConfig.timeout to a small value, e.g. 2 seconds). This API
    /// cannot interrupt an arbitrary injected synchronous Transport. Cancellation
    /// is checked between discovery, GetInfo, the one host lookup, and each DNS
    /// query. DNS time is at most five seconds plus scheduling overhead; each
    /// native query is capped at 500 ms. No worker threads/subprocesses are used.
    pub fn diagnose_dns(
        &mut self,
        options: &DnsDiagnosticOptions,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<DnsDiagnostic, String> {
        self.diagnose_dns_with_probe(options, &mut NativeDnsProbe, cancelled)
    }

    pub fn diagnose_dns_with_probe<P: DnsProbe>(
        &mut self,
        options: &DnsDiagnosticOptions,
        probe: &mut P,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<DnsDiagnostic, String> {
        // Validate everything before the first router or DNS operation.
        let name = dns_name(&options.hostname)?;
        validate_evidence(options)?;
        let router =
            url::Url::parse(self.base_url()).map_err(|_| "invalid configured router URL")?;
        let configured_router = router
            .host_str()
            .ok_or("configured router has no host")?
            .to_owned();
        let router_ip = options.router_dns_ip.or_else(|| match router.host() {
            Some(url::Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
            Some(url::Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
            _ => None,
        });
        let name_kind = if name == "local" || name.ends_with(".local") {
            DnsNameKind::Mdns
        } else if name.contains('.') {
            DnsNameKind::Fqdn
        } else {
            DnsNameKind::Bare
        };
        let mut report = DnsDiagnostic {
            configured_router,
            router_dns: router_ip.map_or_else(
                || DnsEvidence::unknown("router hostname requires an explicit router DNS IP"),
                |ip| {
                    DnsEvidence::known(
                        ip,
                        if options.router_dns_ip.is_some() {
                            "explicit router DNS IP"
                        } else {
                            "configured router literal IP"
                        },
                    )
                },
            ),
            selected_hostname: name.clone(),
            name_kind,
            dhcp: DhcpDnsEvidence {
                enabled: DnsEvidence::unknown("LANHostConfigManagement.GetInfo not observed"),
                resolvers: DnsEvidence::unknown("DHCP DNS resolvers not observed"),
                tr064_domain_name: DnsEvidence::unknown("TR-064 domain name not observed"),
                option15: options.dhcp_option15.clone(),
            },
            system: options.system.clone(),
            selected_host: DnsSelectedHost {
                expected_ip: options.expected_host_ip,
                table_name: DnsEvidence::unknown(
                    "single host-table lookup requires expected_host_ip",
                ),
                table_active: DnsEvidence::unknown("host activity not observed"),
                ip_connectivity: DnsEvidence::unknown("IP connectivity not probed"),
            },
            lookups: Vec::new(),
            dns_filter_enabled: DnsEvidence::unknown(
                "DNS filter state is not exposed by this diagnostic",
            ),
            system_name_resolution: DnsEvidence::unknown(
                "OS/NSS lookup unsupported by bounded native probe",
            ),
            cancelled: false,
            explanations: Vec::new(),
        };
        if !cancelled() {
            match self.service_by_name("LANHostConfigManagement:1") {
                Ok(service)
                    if service.service_type
                        == "urn:dslforum-org:service:LANHostConfigManagement:1" =>
                {
                    if !cancelled() {
                        match self.call(&service, "GetInfo", &BTreeMap::new()) {
                            Ok(info) => apply_dhcp(&mut report.dhcp, &info),
                            Err(_) => {
                                report.dhcp.resolvers =
                                    DnsEvidence::unknown("LANHostConfigManagement.GetInfo failed")
                            }
                        }
                    }
                }
                _ => {
                    report.dhcp.resolvers =
                        DnsEvidence::unknown("LANHostConfigManagement:1 unavailable")
                }
            }
        }
        if !cancelled()
            && let Some(ip) = options.expected_host_ip
        {
            match self.host_by_ip(&ip.to_string()) {
                Ok(host) => {
                    if !host.name.is_empty() {
                        report.selected_host.table_name =
                            DnsEvidence::known(host.name, "typed host_by_ip; caller-selected IP");
                    }
                    // Host::active defaults missing fields to false. A true
                    // value is evidence; false cannot distinguish absent data.
                    if host.active {
                        report.selected_host.table_active =
                            DnsEvidence::known(true, "host-table active flag; not IP connectivity");
                    }
                }
                Err(_) => {
                    report.selected_host.table_name =
                        DnsEvidence::unknown("typed host_by_ip failed; no inventory fallback")
                }
            }
        }
        let mut resolvers = Vec::new();
        if let Some(ip) = router_ip {
            add_resolver(&mut resolvers, ip, DnsResolverRole::Router);
        }
        for (evidence, role) in [
            (&report.dhcp.resolvers, DnsResolverRole::Dhcp),
            (&report.system.resolvers, DnsResolverRole::System),
        ] {
            if let Some(ips) = &evidence.value {
                for &ip in ips {
                    add_resolver(&mut resolvers, ip, role);
                }
            }
        }
        let started = Instant::now();
        let timeout = options
            .query_timeout
            .clamp(Duration::from_millis(1), MAX_PROBE_TIME);
        for (resolver, roles) in resolvers {
            for record_type in [DnsRecordType::A, DnsRecordType::Aaaa] {
                if cancelled() {
                    report.cancelled = true;
                    break;
                }
                let remaining = DNS_BUDGET.saturating_sub(started.elapsed());
                let answer = if name_kind == DnsNameKind::Mdns {
                    DnsProbeAnswer::status(
                        DnsOutcome::Unsupported,
                        ".local requires mDNS; no unicast query sent",
                    )
                } else if remaining.is_zero() {
                    DnsProbeAnswer::status(
                        DnsOutcome::Unknown,
                        "overall DNS probe budget exhausted; query not sent",
                    )
                } else {
                    probe.query(resolver, &name, record_type, timeout.min(remaining))
                };
                let expected = options
                    .expected_host_ip
                    .filter(|ip| record_type.matches(*ip));
                let address_match = if answer.addresses.is_empty() {
                    DnsAddressMatch::Unknown
                } else if let Some(ip) = expected {
                    if answer.addresses.iter().all(|answer| *answer == ip) {
                        DnsAddressMatch::Match
                    } else {
                        DnsAddressMatch::Mismatch
                    }
                } else {
                    DnsAddressMatch::Unknown
                };
                report.lookups.push(DnsLookupResult {
                    resolver,
                    roles: roles.clone(),
                    name: name.clone(),
                    record_type,
                    outcome: answer.outcome,
                    addresses: answer.addresses,
                    address_match,
                    detail: answer.detail,
                });
            }
            if report.cancelled {
                break;
            }
        }
        report.cancelled |= cancelled();
        explain(&mut report);
        Ok(report)
    }
}

fn add_resolver(
    resolvers: &mut Vec<(IpAddr, Vec<DnsResolverRole>)>,
    ip: IpAddr,
    role: DnsResolverRole,
) {
    if let Some((_, roles)) = resolvers.iter_mut().find(|(existing, _)| *existing == ip) {
        if !roles.contains(&role) {
            roles.push(role);
        }
    } else {
        resolvers.push((ip, vec![role]));
    }
}

fn validate_evidence(options: &DnsDiagnosticOptions) -> Result<(), String> {
    if options
        .system
        .resolvers
        .value
        .as_ref()
        .is_some_and(|ips| ips.len() > MAX_RESOLVERS)
    {
        return Err("at most four system resolvers may be probed".into());
    }
    if let Some(domains) = &options.system.search_domains.value {
        if domains.len() > MAX_SEARCH_DOMAINS {
            return Err("at most six system search domains".into());
        }
        for domain in domains {
            dns_name(domain)?;
        }
    }
    if let Some(domain) = &options.dhcp_option15.value {
        // An explicitly observed empty option is useful evidence of no suffix.
        if !domain.is_empty() {
            dns_name(domain)?;
        }
    }
    Ok(())
}

fn dns_name(input: &str) -> Result<String, String> {
    let name = input.strip_suffix('.').unwrap_or(input);
    if name.is_empty()
        || name.len() > 253
        || name.parse::<IpAddr>().is_ok()
        || !name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err("select one valid ASCII DNS hostname (1..253 bytes); IPs, wildcards, URLs and IDNs are unsupported".into());
    }
    Ok(name.to_ascii_lowercase())
}

fn apply_dhcp(dhcp: &mut DhcpDnsEvidence, info: &BTreeMap<String, String>) {
    let source = "LANHostConfigManagement:1.GetInfo";
    if let Some(enabled) = info
        .get("NewDHCPServerEnable")
        .and_then(|s| match s.as_str() {
            "1" | "true" => Some(true),
            "0" | "false" => Some(false),
            _ => None,
        })
    {
        dhcp.enabled = DnsEvidence::known(enabled, source);
    }
    if let Some(domain) = info.get("NewDomainName").filter(|s| s.len() <= 253) {
        dhcp.tr064_domain_name = DnsEvidence::known(
            domain.clone(),
            "GetInfo.NewDomainName; NOT authoritative DHCP option 15",
        );
    }
    if let Some(raw) = info.get("NewDNSServers") {
        let parsed: Result<Vec<IpAddr>, _> = raw
            .split(|c: char| c == ',' || c.is_ascii_whitespace())
            .filter(|s| !s.is_empty())
            .take(MAX_RESOLVERS + 1)
            .map(str::parse)
            .collect();
        dhcp.resolvers = match parsed {
            Ok(ips) if !ips.is_empty() && ips.len() <= MAX_RESOLVERS => DnsEvidence::known(
                ips,
                "GetInfo.NewDNSServers; router configuration, not a captured client lease",
            ),
            _ => {
                DnsEvidence::unknown("NewDNSServers empty, invalid, or exceeds four-resolver bound")
            }
        };
    }
}

fn explain(report: &mut DnsDiagnostic) {
    report.explanations.push("TR-064 NewDomainName, captured DHCP option 15 and effective system search domains are independent evidence; no suffix is inferred from the router name.".into());
    report.explanations.push("Direct probes query the selected absolute name only. Bare-name OS search, FQDN DNS, mDNS and host-table/IP connectivity are separate paths.".into());
    if report
        .system
        .search_domains
        .value
        .as_ref()
        .is_some_and(Vec::is_empty)
    {
        report.explanations.push("Observed system search list is empty: bare local names may need an explicit FQDN or optional DHCP suffix restoration, followed by lease renewal. Verify actual client DHCP/search evidence first.".into());
    }
    report.explanations.push("If router-local DNS answers correctly while a separate resolver (for example AdGuard Home) fails or answers publicly, configure conditional forwarding for the verified local zone to router-local DNS. Optional DHCP suffix restoration addresses bare-name search separately; this diagnostic changes neither setting.".into());
    report.explanations.push("A split local/public DNS path can be an existing configuration gap; these observations do not prove a FRITZ!OS 8.50 regression. DNS filter state remains unknown and cannot imply protection for queries handled by another resolver.".into());
}

/// Dependency-free bounded UDP A/AAAA probes. No TCP retry, EDNS, or recursive
/// CNAME follow-up queries: truncated/unsupported responses remain explicit.
#[derive(Default)]
pub struct NativeDnsProbe;

impl DnsProbe for NativeDnsProbe {
    fn query(
        &mut self,
        resolver: IpAddr,
        name: &str,
        record_type: DnsRecordType,
        timeout: Duration,
    ) -> DnsProbeAnswer {
        let name = match dns_name(name) {
            Ok(name) => name,
            Err(_) => {
                return DnsProbeAnswer::status(
                    DnsOutcome::Unknown,
                    "invalid DNS name; no query sent",
                );
            }
        };
        if name == "local" || name.ends_with(".local") {
            return DnsProbeAnswer::status(
                DnsOutcome::Unsupported,
                "mDNS unsupported; no unicast query sent",
            );
        }
        if resolver.is_unspecified()
            || resolver.is_multicast()
            || matches!(resolver, IpAddr::V6(ip) if ip.is_unicast_link_local())
        {
            return DnsProbeAnswer::status(
                DnsOutcome::Unsupported,
                "invalid or scope-dependent resolver; IPv6 link-local needs an interface scope",
            );
        }
        let timeout = timeout.clamp(Duration::from_millis(1), MAX_PROBE_TIME);
        let started = Instant::now();
        let result = (|| -> std::io::Result<DnsProbeAnswer> {
            let bind = if resolver.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(bind)?;
            socket.set_write_timeout(Some(timeout))?;
            socket.connect(SocketAddr::new(resolver, 53))?;
            let id = RandomState::new().hash_one((&name, resolver, Instant::now())) as u16;
            let request = dns_request(id, &name, record_type);
            socket.send(&request)?;
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Ok(DnsProbeAnswer::status(
                    DnsOutcome::Timeout,
                    "DNS deadline elapsed",
                ));
            }
            socket.set_read_timeout(Some(remaining))?;
            let mut response = [0_u8; 4096];
            let count = socket.recv(&mut response)?;
            Ok(parse_dns_answer(&response[..count], id, &name, record_type))
        })();
        match result {
            Ok(answer) => answer,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                DnsProbeAnswer::status(DnsOutcome::Timeout, "DNS UDP deadline elapsed")
            }
            Err(error) if error.kind() == std::io::ErrorKind::Unsupported => {
                DnsProbeAnswer::status(
                    DnsOutcome::Unsupported,
                    "address family/UDP unsupported by this platform",
                )
            }
            Err(_) => DnsProbeAnswer::status(
                DnsOutcome::Unknown,
                "DNS UDP operation failed; not evidence of NXDOMAIN or host connectivity",
            ),
        }
    }
}

fn dns_request(id: u16, name: &str, record_type: DnsRecordType) -> Vec<u8> {
    let mut packet = Vec::with_capacity(272);
    for word in [id, 0x0100, 1, 0, 0, 0] {
        packet.extend_from_slice(&word.to_be_bytes());
    }
    for label in name.trim_end_matches('.').split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&record_type.code().to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet
}

fn word(packet: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *packet.get(offset)?,
        *packet.get(offset + 1)?,
    ]))
}

// Compression pointers are bounded by packet length and a hop limit; no
// recursive parsing, unchecked indexing, or allocations from wire counts.
fn read_name(packet: &[u8], cursor: &mut usize) -> Option<String> {
    let mut position = *cursor;
    let mut jumped = false;
    let mut labels = Vec::new();
    let mut length = 0;
    for _ in 0..128 {
        let size = *packet.get(position)?;
        if size & 0xc0 == 0xc0 {
            let pointer = usize::from(word(packet, position)? & 0x3fff);
            if !jumped {
                *cursor = position + 2;
                jumped = true;
            }
            position = pointer;
        } else if size & 0xc0 != 0 {
            return None;
        } else if size == 0 {
            if !jumped {
                *cursor = position + 1;
            }
            return Some(labels.join("."));
        } else {
            let size = usize::from(size);
            let label = packet.get(position + 1..position + 1 + size)?;
            length += size + 1;
            if length > 254 || !label.iter().all(u8::is_ascii) {
                return None;
            }
            labels.push(std::str::from_utf8(label).ok()?.to_ascii_lowercase());
            position += size + 1;
        }
    }
    None
}

fn parse_dns_answer(
    packet: &[u8],
    id: u16,
    name: &str,
    record_type: DnsRecordType,
) -> DnsProbeAnswer {
    parse_dns_packet(packet, id, name, record_type).unwrap_or_else(|| {
        DnsProbeAnswer::status(
            DnsOutcome::Unknown,
            "malformed, unrelated or unsupported DNS response",
        )
    })
}

fn parse_dns_packet(
    packet: &[u8],
    id: u16,
    name: &str,
    record_type: DnsRecordType,
) -> Option<DnsProbeAnswer> {
    let flags = word(packet, 2)?;
    if word(packet, 0)? != id || flags & 0xf800 != 0x8000 || word(packet, 4)? != 1 {
        return None;
    }
    let mut cursor = 12;
    if read_name(packet, &mut cursor)? != dns_name(name).ok()?
        || word(packet, cursor)? != record_type.code()
        || word(packet, cursor + 2)? != 1
    {
        return None;
    }
    cursor += 4;
    if flags & 0x0200 != 0 {
        return Some(DnsProbeAnswer::status(
            DnsOutcome::Unsupported,
            "truncated UDP reply; no TCP fallback",
        ));
    }
    match flags & 0x000f {
        3 => {
            return Some(DnsProbeAnswer::status(
                DnsOutcome::NxDomain,
                "resolver returned NXDOMAIN",
            ));
        }
        0 => (),
        _ => {
            return Some(DnsProbeAnswer::status(
                DnsOutcome::Unknown,
                "resolver returned an error RCODE",
            ));
        }
    }
    let count = word(packet, 6)?;
    if count > 64 {
        return None;
    }
    let mut aliases = Vec::new();
    let mut records = Vec::new();
    for _ in 0..count {
        let owner = read_name(packet, &mut cursor)?;
        let kind = word(packet, cursor)?;
        let class = word(packet, cursor + 2)?;
        let length = usize::from(word(packet, cursor + 8)?);
        cursor += 10;
        let data = packet.get(cursor..cursor.checked_add(length)?)?;
        if class == 1 && kind == record_type.code() {
            let address = match (record_type, data) {
                (DnsRecordType::A, [a, b, c, d]) => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
                (DnsRecordType::Aaaa, bytes) if bytes.len() == 16 => {
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?))
                }
                _ => return None,
            };
            records.push((owner, address));
        } else if class == 1 && kind == 5 {
            let mut alias_cursor = cursor;
            let target = read_name(packet, &mut alias_cursor)?;
            if alias_cursor != cursor + length {
                return None;
            }
            aliases.push((owner, target));
        }
        cursor += length;
    }
    let mut owner = dns_name(name).ok()?;
    for _ in 0..16 {
        let mut addresses: Vec<_> = records
            .iter()
            .filter(|(host, _)| *host == owner)
            .map(|(_, ip)| *ip)
            .collect();
        if !addresses.is_empty() {
            if addresses
                .iter()
                .any(|ip| ip.is_unspecified() || ip.is_multicast())
            {
                return None;
            }
            addresses.sort();
            addresses.dedup();
            return Some(DnsProbeAnswer::addresses(addresses));
        }
        match aliases.iter().find(|(host, _)| *host == owner) {
            Some((_, target)) => owner = target.clone(),
            None if aliases.is_empty() => {
                return Some(DnsProbeAnswer::status(
                    DnsOutcome::NoData,
                    "NOERROR with no selected-family address",
                ));
            }
            None => {
                return Some(DnsProbeAnswer::status(
                    DnsOutcome::Unknown,
                    "CNAME has no in-packet address; no additional query sent",
                ));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Request, Response, TransportError};
    use std::cell::Cell;
    use std::collections::VecDeque;

    // Entirely synthetic protocol evidence. No live router/resolver is queried.
    const DISCOVERY: &str = r#"<root><device><serviceList><service>
        <serviceType>urn:dslforum-org:service:LANHostConfigManagement:1</serviceType>
        <controlURL>/discovered/lanhostconfig</controlURL>
        </service></serviceList></device></root>"#;

    #[derive(Default)]
    struct MockTransport {
        replies: VecDeque<Response>,
        requests: Vec<Request>,
    }
    impl Transport for MockTransport {
        fn send(&mut self, request: Request) -> Result<Response, TransportError> {
            self.requests.push(request);
            self.replies
                .pop_front()
                .ok_or_else(|| TransportError("unexpected router request".into()))
        }
    }
    struct Nonce;
    impl CnonceSource for Nonce {
        fn next_cnonce(&mut self) -> Result<String, String> {
            Ok("offline-test".into())
        }
    }
    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }
    fn response(body: impl Into<String>) -> Response {
        Response {
            status: 200,
            body: body.into().into_bytes(),
            ..Response::default()
        }
    }
    fn soap(action: &str, fields: &str) -> Response {
        response(format!(
            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:{action}Response xmlns:u=\"urn:test\">{fields}</u:{action}Response></s:Body></s:Envelope>"
        ))
    }
    fn client(dns: &str) -> Client<MockTransport, Nonce> {
        let replies = VecDeque::from([
            response(DISCOVERY),
            soap(
                "GetInfo",
                &format!(
                    "<NewDHCPServerEnable>1</NewDHCPServerEnable><NewDNSServers>{dns}</NewDNSServers><NewDomainName>router-label</NewDomainName>"
                ),
            ),
            soap(
                "X_AVM-DE_GetSpecificHostEntryByIP",
                "<NewHostName>homeassistant</NewHostName><NewActive>1</NewActive>",
            ),
        ]);
        Client::new(
            MockTransport {
                replies,
                ..MockTransport::default()
            },
            Nonce,
            "http://192.168.50.1:49000",
            "synthetic-user",
            "synthetic-password",
        )
    }
    #[derive(Default)]
    struct MockProbe {
        answers: VecDeque<DnsProbeAnswer>,
        calls: Vec<(IpAddr, String, DnsRecordType, Duration)>,
    }
    impl DnsProbe for MockProbe {
        fn query(
            &mut self,
            resolver: IpAddr,
            name: &str,
            kind: DnsRecordType,
            timeout: Duration,
        ) -> DnsProbeAnswer {
            self.calls.push((resolver, name.into(), kind, timeout));
            self.answers.pop_front().unwrap_or_else(|| {
                DnsProbeAnswer::status(DnsOutcome::NoData, "synthetic empty answer")
            })
        }
    }
    fn empty() -> DnsProbeAnswer {
        DnsProbeAnswer::status(DnsOutcome::NoData, "synthetic NODATA")
    }

    #[test]
    fn separate_adguard_nxdomain_keeps_host_and_ip_connectivity_independent() {
        let mut client = client("192.168.50.2");
        let mut options = DnsDiagnosticOptions::new("homeassistant.fritz.box");
        options.expected_host_ip = Some(ip("192.168.50.9"));
        options.system.resolvers =
            DnsEvidence::known(vec![ip("192.168.50.2")], "synthetic client evidence");
        let mut probe = MockProbe {
            answers: VecDeque::from([
                DnsProbeAnswer::addresses(vec![ip("192.168.50.9")]),
                empty(),
                DnsProbeAnswer::status(DnsOutcome::NxDomain, "synthetic AdGuard NXDOMAIN"),
                empty(),
            ]),
            ..MockProbe::default()
        };
        let report = client
            .diagnose_dns_with_probe(&options, &mut probe, &|| false)
            .unwrap();
        assert_eq!(report.lookups.len(), 4);
        assert_eq!(report.lookups[0].outcome, DnsOutcome::LocalAnswer);
        assert_eq!(report.lookups[0].address_match, DnsAddressMatch::Match);
        assert_eq!(report.lookups[2].outcome, DnsOutcome::NxDomain);
        assert_eq!(
            report.lookups[2].roles,
            vec![DnsResolverRole::Dhcp, DnsResolverRole::System]
        );
        assert_eq!(
            report.selected_host.table_name.value.as_deref(),
            Some("homeassistant")
        );
        assert_eq!(report.selected_host.table_active.value, Some(true));
        assert_eq!(report.selected_host.ip_connectivity.value, None);
        assert_eq!(report.dns_filter_enabled.value, None);
        let transport = client.into_transport();
        assert_eq!(transport.requests.len(), 3);
        assert!(
            transport.requests[1]
                .url
                .ends_with("/discovered/lanhostconfig")
        );
        assert!(
            transport.requests[2].headers["SoapAction"]
                .ends_with("#X_AVM-DE_GetSpecificHostEntryByIP")
        );
        assert!(
            report
                .explanations
                .iter()
                .any(|s| s.contains("conditional forwarding"))
        );
        assert!(
            report
                .explanations
                .iter()
                .any(|s| s.contains("do not prove a FRITZ!OS 8.50 regression"))
        );
        assert!(
            serde_json::to_string(&report)
                .unwrap()
                .contains("\"dns_filter_enabled\":{\"value\":null")
        );
    }

    #[test]
    fn tr064_domain_is_neither_real_dhcp_option15_nor_system_search_list() {
        let mut client = client("192.168.50.2");
        let mut options = DnsDiagnosticOptions::new("homeassistant");
        options.dhcp_option15 = DnsEvidence::known("fritz.box".into(), "synthetic lease capture");
        options.system.search_domains =
            DnsEvidence::known(vec![], "synthetic effective search list");
        let mut probe = MockProbe::default();
        let report = client
            .diagnose_dns_with_probe(&options, &mut probe, &|| false)
            .unwrap();
        assert_eq!(report.name_kind, DnsNameKind::Bare);
        assert_eq!(
            report.dhcp.tr064_domain_name.value.as_deref(),
            Some("router-label")
        );
        assert_eq!(report.dhcp.option15.value.as_deref(), Some("fritz.box"));
        assert_eq!(report.system.search_domains.value, Some(vec![]));
        assert!(
            report
                .explanations
                .iter()
                .any(|s| s.contains("search list is empty"))
        );
        assert!(
            probe
                .calls
                .iter()
                .all(|(_, name, _, _)| name == "homeassistant")
        );
        assert_eq!(client.into_transport().requests.len(), 2); // no table enumeration
    }

    #[test]
    fn absent_evidence_is_unknown_and_not_an_empty_or_disabled_claim() {
        let mut client = client("");
        let report = client
            .diagnose_dns_with_probe(
                &DnsDiagnosticOptions::new("host.fritz.box"),
                &mut MockProbe::default(),
                &|| false,
            )
            .unwrap();
        assert!(report.system.resolvers.value.is_none());
        assert!(report.system.search_domains.value.is_none());
        assert!(report.dhcp.option15.value.is_none());
        assert!(report.dhcp.resolvers.value.is_none());
        assert!(report.selected_host.table_active.value.is_none());
        assert!(
            !report
                .explanations
                .iter()
                .any(|s| s.contains("search list is empty"))
        );
    }

    #[test]
    fn public_fritz_box_and_wrong_private_address_are_not_correct_answers() {
        let mut client = client("192.168.50.2");
        let mut options = DnsDiagnosticOptions::new("fritz.box");
        options.expected_host_ip = Some(ip("192.168.50.1"));
        let mut probe = MockProbe {
            answers: VecDeque::from([
                DnsProbeAnswer::addresses(vec![ip("192.168.50.99")]),
                empty(),
                DnsProbeAnswer::addresses(vec![ip("8.8.8.8")]),
                empty(),
            ]),
            ..MockProbe::default()
        };
        let report = client
            .diagnose_dns_with_probe(&options, &mut probe, &|| false)
            .unwrap();
        assert_eq!(report.lookups[0].outcome, DnsOutcome::LocalAnswer);
        assert_eq!(report.lookups[0].address_match, DnsAddressMatch::Mismatch);
        assert_eq!(report.lookups[2].outcome, DnsOutcome::PublicAnswer);
        assert_eq!(report.lookups[2].address_match, DnsAddressMatch::Mismatch);
        // The IP here is a synthetic response, not a claim about live fritz.box.
    }

    #[test]
    fn timeout_differs_from_nxdomain_and_budget_is_clamped() {
        let mut client = client("192.168.50.1");
        let mut options = DnsDiagnosticOptions::new("host.fritz.box");
        options.query_timeout = Duration::MAX;
        let mut probe = MockProbe {
            answers: VecDeque::from([
                DnsProbeAnswer::status(DnsOutcome::Timeout, "synthetic timeout"),
                DnsProbeAnswer::status(DnsOutcome::NxDomain, "synthetic negative reply"),
            ]),
            ..MockProbe::default()
        };
        let report = client
            .diagnose_dns_with_probe(&options, &mut probe, &|| false)
            .unwrap();
        assert_eq!(probe.calls.len(), 2); // router/DHCP endpoint deduplicated
        assert!(probe.calls.iter().all(|call| call.3 <= MAX_PROBE_TIME));
        assert_eq!(report.lookups[0].outcome, DnsOutcome::Timeout);
        assert_eq!(report.lookups[1].outcome, DnsOutcome::NxDomain);
        assert!(
            report
                .lookups
                .iter()
                .all(|answer| answer.address_match == DnsAddressMatch::Unknown)
        );
    }

    #[test]
    fn ipv6_answer_matches_only_ipv6_expectation_and_scoped_resolver_is_unsupported() {
        let mut client = client("fd00::2");
        let mut options = DnsDiagnosticOptions::new("host.fritz.box");
        options.router_dns_ip = Some(ip("fd00::1"));
        options.expected_host_ip = Some(ip("fd00::9"));
        let mut probe = MockProbe {
            answers: VecDeque::from([
                empty(),
                DnsProbeAnswer::addresses(vec![ip("fd00::9")]),
                empty(),
                empty(),
            ]),
            ..MockProbe::default()
        };
        let report = client
            .diagnose_dns_with_probe(&options, &mut probe, &|| false)
            .unwrap();
        assert_eq!(report.lookups[1].outcome, DnsOutcome::LocalAnswer);
        assert_eq!(report.lookups[1].address_match, DnsAddressMatch::Match);
        assert!(probe.calls.iter().all(|call| call.0.is_ipv6()));
        let answer = NativeDnsProbe.query(
            ip("fe80::1"),
            "host.fritz.box",
            DnsRecordType::Aaaa,
            Duration::from_millis(1),
        );
        assert_eq!(answer.outcome, DnsOutcome::Unsupported); // no socket operation
    }

    #[test]
    fn only_explicit_name_is_queried_even_with_public_client_resolver() {
        let mut client = client("8.8.8.8");
        let mut options = DnsDiagnosticOptions::new("Selected.Fritz.Box.");
        options.system.search_domains =
            DnsEvidence::known(vec!["private.example".into()], "synthetic search evidence");
        let mut probe = MockProbe::default();
        let report = client
            .diagnose_dns_with_probe(&options, &mut probe, &|| false)
            .unwrap();
        assert!(
            probe
                .calls
                .iter()
                .all(|(_, name, _, _)| name == "selected.fritz.box")
        );
        assert_eq!(probe.calls.len(), 4); // no public fallback or suffix expansion
        assert_eq!(client.into_transport().requests.len(), 2); // no inventory
        assert_eq!(report.selected_host.expected_ip, None);
    }

    #[test]
    fn invalid_names_and_excess_resolvers_fail_before_any_io() {
        for name in [
            "",
            ".",
            "*.fritz.box",
            "a..box",
            "-bad.box",
            "bad-.box",
            "http://host",
            "host\nbox",
            "foo bar",
            "münchen.box",
            "192.168.1.1",
            "::1",
        ] {
            let mut client = client("192.168.50.2");
            let mut probe = MockProbe::default();
            assert!(
                client
                    .diagnose_dns_with_probe(&DnsDiagnosticOptions::new(name), &mut probe, &|| {
                        false
                    })
                    .is_err(),
                "{name:?}"
            );
            assert!(probe.calls.is_empty());
            assert!(client.into_transport().requests.is_empty());
        }
        assert!(dns_name(&format!("{}.box", "a".repeat(64))).is_err());
        let mut options = DnsDiagnosticOptions::new("host.fritz.box");
        options.system.resolvers.value = Some(vec![ip("192.168.50.2"); 5]);
        let mut client = client("192.168.50.2");
        assert!(
            client
                .diagnose_dns_with_probe(&options, &mut MockProbe::default(), &|| false)
                .is_err()
        );
        assert!(client.into_transport().requests.is_empty());
    }

    #[test]
    fn cancellation_stops_between_discovery_and_getinfo_without_detached_work() {
        let mut client = client("192.168.50.2");
        let checks = Cell::new(0);
        let cancelled = || {
            let count = checks.get();
            checks.set(count + 1);
            count >= 1
        };
        let mut probe = MockProbe::default();
        let report = client
            .diagnose_dns_with_probe(
                &DnsDiagnosticOptions::new("host.fritz.box"),
                &mut probe,
                &cancelled,
            )
            .unwrap();
        assert!(report.cancelled);
        assert!(probe.calls.is_empty());
        assert_eq!(client.into_transport().requests.len(), 1);
    }

    #[test]
    fn mdns_never_falls_through_to_unicast_dns() {
        let mut client = client("8.8.8.8");
        let mut probe = MockProbe::default();
        let report = client
            .diagnose_dns_with_probe(
                &DnsDiagnosticOptions::new("host.local"),
                &mut probe,
                &|| false,
            )
            .unwrap();
        assert_eq!(report.name_kind, DnsNameKind::Mdns);
        assert!(probe.calls.is_empty());
        assert!(
            report
                .lookups
                .iter()
                .all(|result| result.outcome == DnsOutcome::Unsupported)
        );
        assert_eq!(
            NativeDnsProbe
                .query(
                    ip("8.8.8.8"),
                    "Host.LOCAL.",
                    DnsRecordType::A,
                    Duration::from_millis(1)
                )
                .outcome,
            DnsOutcome::Unsupported
        );
    }

    fn reply(name: &str, kind: DnsRecordType, flags: u16, data: Option<&[u8]>) -> Vec<u8> {
        let mut bytes = dns_request(123, name, kind);
        bytes[2..4].copy_from_slice(&flags.to_be_bytes());
        if let Some(data) = data {
            bytes[6..8].copy_from_slice(&1_u16.to_be_bytes());
            bytes.extend_from_slice(&[0xc0, 0x0c]);
            bytes.extend_from_slice(&kind.code().to_be_bytes());
            bytes.extend_from_slice(&[0, 1, 0, 0, 0, 1]);
            bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
            bytes.extend_from_slice(data);
        }
        bytes
    }

    #[test]
    fn wire_parser_distinguishes_ipv4_ipv6_nxdomain_truncation_and_malformed() {
        let name = "host.fritz.box";
        let v4 = reply(name, DnsRecordType::A, 0x8180, Some(&[192, 168, 50, 9]));
        assert_eq!(
            parse_dns_answer(&v4, 123, name, DnsRecordType::A).addresses,
            vec![ip("192.168.50.9")]
        );
        let v6 = reply(
            name,
            DnsRecordType::Aaaa,
            0x8180,
            Some(&"fd00::9".parse::<Ipv6Addr>().unwrap().octets()),
        );
        assert_eq!(
            parse_dns_answer(&v6, 123, name, DnsRecordType::Aaaa).addresses,
            vec![ip("fd00::9")]
        );
        for (flags, expected) in [
            (0x8183, DnsOutcome::NxDomain),
            (0x8380, DnsOutcome::Unsupported),
            (0x8182, DnsOutcome::Unknown),
            (0x8180, DnsOutcome::NoData),
        ] {
            let bytes = reply(name, DnsRecordType::A, flags, None);
            assert_eq!(
                parse_dns_answer(&bytes, 123, name, DnsRecordType::A).outcome,
                expected
            );
        }
        assert_eq!(
            parse_dns_answer(&v4, 124, name, DnsRecordType::A).outcome,
            DnsOutcome::Unknown
        );
        assert_eq!(
            parse_dns_answer(&v4, 123, "other.fritz.box", DnsRecordType::A).outcome,
            DnsOutcome::Unknown
        );
        for length in 0..v4.len() {
            assert_eq!(
                parse_dns_answer(&v4[..length], 123, name, DnsRecordType::A).outcome,
                DnsOutcome::Unknown
            );
        }
        let mut cyclic = reply(name, DnsRecordType::A, 0x8180, None);
        cyclic[12..14].copy_from_slice(&[0xc0, 0x0c]);
        assert_eq!(
            parse_dns_answer(&cyclic, 123, name, DnsRecordType::A).outcome,
            DnsOutcome::Unknown
        );
    }

    #[test]
    fn malformed_dhcp_resolvers_do_not_trigger_partial_or_default_public_lookups() {
        for raw in [
            "8.8.8.8,garbage",
            "1.1.1.1,8.8.8.8,9.9.9.9,192.168.1.1,192.168.1.2",
        ] {
            let mut client = client(raw);
            let mut probe = MockProbe::default();
            let report = client
                .diagnose_dns_with_probe(
                    &DnsDiagnosticOptions::new("host.fritz.box"),
                    &mut probe,
                    &|| false,
                )
                .unwrap();
            assert!(report.dhcp.resolvers.value.is_none());
            assert_eq!(probe.calls.len(), 2);
            assert!(probe.calls.iter().all(|call| call.0 == ip("192.168.50.1")));
        }
    }

    #[test]
    fn missing_host_activity_cannot_be_reported_as_inactive() {
        let mut transport = client("192.168.50.1").into_transport();
        transport.replies.pop_back();
        transport.replies.push_back(soap(
            "X_AVM-DE_GetSpecificHostEntryByIP",
            "<NewHostName>host</NewHostName>",
        ));
        let mut client = Client::new(transport, Nonce, "http://192.168.50.1:49000", "", "");
        let mut options = DnsDiagnosticOptions::new("host.fritz.box");
        options.expected_host_ip = Some(ip("192.168.50.9"));
        let report = client
            .diagnose_dns_with_probe(&options, &mut MockProbe::default(), &|| false)
            .unwrap();
        assert_eq!(report.selected_host.table_active.value, None);
        assert_eq!(report.selected_host.ip_connectivity.value, None);
    }

    #[test]
    fn cname_uses_only_in_packet_address_and_rejects_unrelated_answer_owners() {
        let name = "alias.fritz.box";
        let kind = DnsRecordType::A;
        let target = "target.fritz.box";
        let target_question = dns_request(0, target, kind);
        let encoded_target = &target_question[12..target_question.len() - 4];
        let mut packet = reply(name, kind, 0x8180, None);
        packet[6..8].copy_from_slice(&2_u16.to_be_bytes());
        packet.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 1]);
        packet.extend_from_slice(&(encoded_target.len() as u16).to_be_bytes());
        let target_offset = packet.len() as u16;
        packet.extend_from_slice(encoded_target);
        packet.extend_from_slice(&(0xc000 | target_offset).to_be_bytes());
        packet.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 168, 50, 9]);
        let answer = parse_dns_answer(&packet, 123, name, kind);
        assert_eq!(answer.addresses, vec![ip("192.168.50.9")]);

        // A CNAME alone does not initiate a second lookup.
        packet.truncate(packet.len() - 16);
        packet[6..8].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            parse_dns_answer(&packet, 123, name, kind).outcome,
            DnsOutcome::Unknown
        );

        let mut unrelated = reply(name, kind, 0x8180, Some(&[8, 8, 8, 8]));
        let owner_offset = dns_request(0, name, kind).len();
        // Pointer into the question's second label yields fritz.box, not alias.fritz.box.
        unrelated[owner_offset..owner_offset + 2].copy_from_slice(&[0xc0, 0x12]);
        assert!(
            parse_dns_answer(&unrelated, 123, name, kind)
                .addresses
                .is_empty()
        );
    }
}
