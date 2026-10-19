//! Conservative online firmware workflow. No image URL is ever submitted.
//!
//! Field names follow FRITZ! UserInterface TR-064 v25 (2026-01-30).
//! Poll deadlines stop new calls; an in-flight synchronous call remains bounded
//! by the configured transport timeout. Injected transports must also be bounded.
use crate::{
    Client, ClientError, CnonceSource, Service, Transport, parse_description, validate_request_url,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, thread,
    time::{Duration, Instant},
};

/// A forwarding safety adapter for the existing transport, with no retries.
/// It enforces cancellation at *each* HTTP dispatch (including Digest auth)
/// and requires a real SOAP action response rather than accepting HTML/empty XML.
/// Use the same cancellation source for this adapter and the workflow callback.
/// The inner transport must have bounded calls and automatic fallback disabled.
pub struct FirmwareTransport<T> {
    inner: T,
    cancelled: Box<dyn Fn() -> bool + Send + Sync>,
}
impl<T> FirmwareTransport<T> {
    pub fn new(inner: T, cancelled: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        Self {
            inner,
            cancelled: Box::new(cancelled),
        }
    }
    pub fn into_inner(self) -> T {
        self.inner
    }
}
impl<T: Transport> Transport for FirmwareTransport<T> {
    fn send(&mut self, request: crate::Request) -> Result<crate::Response, crate::TransportError> {
        if (self.cancelled)() {
            return Err(crate::TransportError(
                "firmware cancelled before HTTP dispatch".into(),
            ));
        }
        let action = request
            .headers
            .get("SoapAction")
            .and_then(|s| s.rsplit_once('#'))
            .map(|(_, a)| a.to_owned());
        let limit = request.response_limit;
        let mut response = self.inner.send(request)?;
        response.body.truncate(limit);
        if response.status == 200
            && let Some(action) = action
        {
            let expected = format!("{action}Response");
            let valid = std::str::from_utf8(&response.body)
                .ok()
                .and_then(|text| roxmltree::Document::parse(text).ok())
                .is_some_and(|doc| {
                    doc.descendants()
                        .any(|n| n.is_element() && n.tag_name().name() == expected)
                });
            if !valid {
                return Err(crate::TransportError(
                    "invalid firmware SOAP action response; mutation outcome may be unknown".into(),
                ));
            }
        }
        Ok(response)
    }
}

pub const FIRMWARE_PREFLIGHT: &str = "Create and verify a configuration backup first. Keep local wired access and stable power. Installation interrupts internet, WLAN and telephony; do not disconnect power. A successful request only means accepted. Never automatically repeat an install after a disconnect or unknown outcome.";
const UI: &str = "urn:dslforum-org:service:UserInterface:1";
const DEVICE: &str = "urn:dslforum-org:service:DeviceInfo:1";
const CHECK: &str = "X_AVM-DE_CheckUpdate";
const INSTALL: &str = "X_AVM-DE_DoUpdate";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirmwareAvailability {
    Available,
    Unavailable,
    Unknown,
    Checking,
    Failed,
    Unsupported,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct FirmwareIdentity {
    pub model: Option<String>,
    pub serial: Option<String>,
    pub current_version: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FirmwareStatus {
    pub identity: FirmwareIdentity,
    pub availability: FirmwareAvailability,
    pub offered_version: Option<String>,
    pub update_state: Option<String>,
    /// Current build/channel reported by the box, not a guessed image channel.
    pub build_type: Option<String>,
    pub auto_update_mode: Option<String>,
    pub previous_version: Option<String>,
    pub reported_current_version: Option<String>,
    pub last_result: Option<String>,
    pub last_update_time: Option<String>,
    pub can_check: bool,
    pub can_install: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct FirmwarePollOptions {
    pub max_polls: u32,
    pub interval: Duration,
    pub max_elapsed: Duration,
}
impl Default for FirmwarePollOptions {
    fn default() -> Self {
        Self {
            max_polls: 30,
            interval: Duration::from_secs(2),
            max_elapsed: Duration::from_secs(120),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirmwareCheckOutcome {
    Complete,
    Timeout,
}
#[derive(Clone, Debug, Serialize)]
pub struct FirmwareCheck {
    pub outcome: FirmwareCheckOutcome,
    pub status: FirmwareStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirmwareInstallOutcome {
    Accepted,
    Rebooting,
    VerifiedInstalled,
    Timeout,
    Unknown,
    Rejected,
}
#[derive(Clone, Debug, Serialize)]
pub struct FirmwareInstall {
    pub outcome: FirmwareInstallOutcome,
    pub history: Vec<FirmwareInstallOutcome>,
    pub original: FirmwareStatus,
    pub readback: Option<FirmwareIdentity>,
    pub detail: String,
    pub preflight: &'static str,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct FirmwareInstallOptions {
    pub confirmed: bool,
    pub verify: bool,
    pub polling: FirmwarePollOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FirmwareError {
    Client(ClientError),
    Unsupported(String),
    Unsafe(String),
    Cancelled,
    Timeout,
}
impl fmt::Display for FirmwareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(e) => e.fmt(f),
            Self::Unsupported(s) => write!(f, "firmware unsupported: {s}"),
            Self::Unsafe(s) => write!(f, "firmware refused: {s}"),
            Self::Cancelled => f.write_str("firmware operation cancelled before dispatch"),
            Self::Timeout => f.write_str("firmware deadline reached before dispatch"),
        }
    }
}
impl std::error::Error for FirmwareError {}
impl From<ClientError> for FirmwareError {
    fn from(e: ClientError) -> Self {
        Self::Client(e)
    }
}

struct Budget {
    start: Instant,
    limit: Duration,
    polls: u32,
    interval: Duration,
}
impl Budget {
    fn new(o: FirmwarePollOptions) -> Self {
        Self {
            start: Instant::now(),
            limit: o.max_elapsed.min(Duration::from_secs(600)),
            polls: o.max_polls.clamp(1, 60),
            interval: o.interval.min(Duration::from_secs(10)),
        }
    }
    fn boundary(&self, cancel: &impl Fn() -> bool) -> Result<(), FirmwareError> {
        if cancel() {
            Err(FirmwareError::Cancelled)
        } else if self.start.elapsed() >= self.limit {
            Err(FirmwareError::Timeout)
        } else {
            Ok(())
        }
    }
    fn pause(&self, cancel: &impl Fn() -> bool) -> Result<(), FirmwareError> {
        let start = Instant::now();
        while start.elapsed() < self.interval {
            self.boundary(cancel)?;
            thread::sleep(
                Duration::from_millis(25)
                    .min(self.interval.saturating_sub(start.elapsed()))
                    .min(self.limit.saturating_sub(self.start.elapsed())),
            );
        }
        self.boundary(cancel)
    }
}
struct Endpoints {
    ui: Service,
    device: Service,
    actions: BTreeSet<String>,
}
fn value(m: &BTreeMap<String, String>, key: &str) -> Option<String> {
    m.get(key)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}
fn identity(m: &BTreeMap<String, String>) -> FirmwareIdentity {
    FirmwareIdentity {
        model: value(m, "NewModelName"),
        serial: value(m, "NewSerialNumber"),
        current_version: value(m, "NewSoftwareVersion"),
    }
}
fn root_error(e: &ClientError) -> &ClientError {
    if let ClientError::Call { source, .. } = e {
        root_error(source)
    } else {
        e
    }
}
fn unsupported(e: &ClientError) -> bool {
    matches!(
        root_error(e),
        ClientError::SoapFault {
            code: 401,
            status: 500,
            ..
        }
    )
}
fn disconnected(e: &ClientError) -> bool {
    matches!(root_error(e), ClientError::Transport(message) if !message.starts_with("invalid firmware SOAP") && !message.starts_with("firmware cancelled"))
}

impl<T: Transport, C: CnonceSource> Client<FirmwareTransport<T>, C> {
    fn firmware_endpoints(
        &mut self,
        b: &Budget,
        cancel: &impl Fn() -> bool,
    ) -> Result<Endpoints, FirmwareError> {
        b.boundary(cancel)?;
        let xml = self
            .authenticated_get_with_limit(&format!("{}/tr64desc.xml", self.base_url()), 4 << 20)?
            .body;
        let services = parse_description(&xml).map_err(ClientError::from)?;
        let ui = services
            .iter()
            .find(|s| s.service_type == UI)
            .cloned()
            .ok_or_else(|| {
                FirmwareError::Unsupported("UserInterface:1 is not advertised".into())
            })?;
        let device = services
            .into_iter()
            .find(|s| s.service_type == DEVICE)
            .ok_or_else(|| FirmwareError::Unsupported("DeviceInfo:1 is not advertised".into()))?;
        let input = std::str::from_utf8(&xml)
            .map_err(|_| FirmwareError::Unsafe("invalid discovery encoding".into()))?;
        let doc = roxmltree::Document::parse(input)
            .map_err(|_| FirmwareError::Unsafe("invalid discovery XML".into()))?;
        let scpd = doc
            .descendants()
            .filter(|n| n.has_tag_name("service"))
            .find(|n| {
                n.children()
                    .any(|c| c.has_tag_name("serviceType") && c.text() == Some(UI))
            })
            .and_then(|n| n.children().find(|c| c.has_tag_name("SCPDURL")))
            .and_then(|n| n.text())
            .ok_or_else(|| FirmwareError::Unsupported("UserInterface SCPDURL is missing".into()))?;
        let origin = url::Url::parse(self.base_url())
            .map_err(|_| FirmwareError::Unsafe("invalid origin".into()))?;
        let url = origin
            .join(scpd)
            .map_err(|_| FirmwareError::Unsafe("invalid SCPDURL".into()))?;
        validate_request_url(&origin, &url)
            .map_err(|_| FirmwareError::Unsafe("SCPDURL outside router origin".into()))?;
        b.boundary(cancel)?;
        let response = self.authenticated_get_with_limit(url.as_str(), 1 << 20)?;
        let input = std::str::from_utf8(&response.body)
            .map_err(|_| FirmwareError::Unsafe("invalid SCPD encoding".into()))?;
        let doc = roxmltree::Document::parse(input)
            .map_err(|_| FirmwareError::Unsafe("invalid SCPD XML".into()))?;
        let actions = doc
            .descendants()
            .filter(|n| n.has_tag_name("action"))
            .filter_map(|n| {
                n.children()
                    .find(|c| c.has_tag_name("name"))
                    .and_then(|n| n.text())
                    .map(str::to_owned)
            })
            .collect();
        Ok(Endpoints {
            ui,
            device,
            actions,
        })
    }
    fn firmware_read(
        &mut self,
        e: &Endpoints,
        b: &Budget,
        cancel: &impl Fn() -> bool,
    ) -> Result<FirmwareStatus, FirmwareError> {
        b.boundary(cancel)?;
        let device = self.call(&e.device, "GetInfo", &BTreeMap::new())?;
        let mut status = FirmwareStatus {
            identity: identity(&device),
            availability: FirmwareAvailability::Unsupported,
            offered_version: None,
            update_state: None,
            build_type: None,
            auto_update_mode: None,
            previous_version: None,
            reported_current_version: None,
            last_result: None,
            last_update_time: None,
            can_check: e.actions.contains(CHECK),
            can_install: e.actions.contains(INSTALL),
        };
        if !e.actions.contains("GetInfo") {
            return Ok(status);
        }
        b.boundary(cancel)?;
        let info = match self.call(&e.ui, "GetInfo", &BTreeMap::new()) {
            Err(err) if unsupported(&err) => return Ok(status),
            result => result?,
        };
        status.offered_version = value(&info, "NewX_AVM-DE_Version");
        status.update_state = value(&info, "NewX_AVM-DE_UpdateState");
        status.build_type = value(&info, "NewX_AVM-DE_BuildType");
        status.availability = match (
            status.update_state.as_deref(),
            value(&info, "NewUpgradeAvailable").as_deref(),
        ) {
            (Some("Started"), _) => FirmwareAvailability::Checking,
            (Some("Error"), _) => FirmwareAvailability::Failed,
            (Some("NoUpdate"), Some("0" | "false")) => FirmwareAvailability::Unavailable,
            (Some("UpdateAvailable"), Some("1" | "true")) => FirmwareAvailability::Available,
            _ => FirmwareAvailability::Unknown,
        };
        if e.actions.contains("X_AVM-DE_GetInfo") {
            b.boundary(cancel)?;
            match self.call(&e.ui, "X_AVM-DE_GetInfo", &BTreeMap::new()) {
                Ok(m) => {
                    status.auto_update_mode = value(&m, "NewX_AVM-DE_AutoUpdateMode");
                    status.previous_version = value(&m, "NewX_AVM-DE_LastFwVersion");
                    status.reported_current_version = value(&m, "NewX_AVM-DE_CurrentFwVersion");
                    status.last_result = value(&m, "NewX_AVM-DE_UpdateSuccessful");
                    status.last_update_time = value(&m, "NewX_AVM-DE_UpdateTime");
                }
                Err(err) if unsupported(&err) => {}
                Err(err) => return Err(err.into()),
            }
        }
        Ok(status)
    }
    pub fn firmware_status(
        &mut self,
        cancel: impl Fn() -> bool,
    ) -> Result<FirmwareStatus, FirmwareError> {
        let b = Budget::new(FirmwarePollOptions::default());
        let e = self.firmware_endpoints(&b, &cancel)?;
        self.firmware_read(&e, &b, &cancel)
    }
    pub fn firmware_check(
        &mut self,
        polling: FirmwarePollOptions,
        cancel: impl Fn() -> bool,
    ) -> Result<FirmwareCheck, FirmwareError> {
        let b = Budget::new(polling);
        let e = self.firmware_endpoints(&b, &cancel)?;
        if !e.actions.contains(CHECK) {
            return Err(FirmwareError::Unsupported(CHECK.into()));
        }
        // Fetch metadata before the mutation; do not interpret a stale result as a fresh check.
        let mut status = self.firmware_read(&e, &b, &cancel)?;
        b.boundary(&cancel)?;
        self.call(&e.ui, CHECK, &BTreeMap::new()).map_err(|err| {
            if unsupported(&err) {
                FirmwareError::Unsupported(CHECK.into())
            } else {
                err.into()
            }
        })?;
        for poll in 0..b.polls {
            if poll > 0 {
                match b.pause(&cancel) {
                    Err(FirmwareError::Timeout) => break,
                    result => result?,
                }
            }
            match self.firmware_read(&e, &b, &cancel) {
                Ok(next) => status = next,
                Err(FirmwareError::Timeout) => break,
                Err(err) => return Err(err),
            }
            if status.availability != FirmwareAvailability::Checking
                && status.availability != FirmwareAvailability::Unknown
            {
                return Ok(FirmwareCheck {
                    outcome: FirmwareCheckOutcome::Complete,
                    status,
                });
            }
        }
        Ok(FirmwareCheck {
            outcome: FirmwareCheckOutcome::Timeout,
            status,
        })
    }
    pub fn firmware_install(
        &mut self,
        options: FirmwareInstallOptions,
        cancel: impl Fn() -> bool,
    ) -> Result<FirmwareInstall, FirmwareError> {
        if !options.confirmed {
            return Err(FirmwareError::Unsafe("explicit confirmation required; back up configuration and expect connectivity loss".into()));
        }
        let b = Budget::new(options.polling);
        let e = self.firmware_endpoints(&b, &cancel)?;
        if !e.actions.contains(INSTALL) {
            return Err(FirmwareError::Unsupported(INSTALL.into()));
        }
        let original = self.firmware_read(&e, &b, &cancel)?;
        safe_offer(&original)?;
        b.boundary(&cancel)?;
        // One application-level invocation only. A Digest 401 handshake is the
        // existing client's authentication protocol, never an install retry.
        let result = self.call(&e.ui, INSTALL, &BTreeMap::new());
        let mut report = FirmwareInstall {
            outcome: FirmwareInstallOutcome::Unknown,
            history: vec![],
            original,
            readback: None,
            detail: String::new(),
            preflight: FIRMWARE_PREFLIGHT,
        };
        match result {
            Ok(m)
                if value(&m, "NewX_AVM-DE_UpdateState").as_deref() == Some("Started")
                    && matches!(
                        value(&m, "NewUpgradeAvailable").as_deref(),
                        Some("0" | "1" | "false" | "true")
                    ) =>
            {
                report.outcome = FirmwareInstallOutcome::Accepted;
                report.history.push(report.outcome);
                report.detail = "Request accepted; installation is not yet verified".into();
            }
            Ok(m)
                if matches!(
                    value(&m, "NewX_AVM-DE_UpdateState").as_deref(),
                    Some("Error" | "NoUpdate" | "Stopped")
                ) =>
            {
                report.outcome = FirmwareInstallOutcome::Rejected;
                report.detail = "Router did not start installation".into();
                return Ok(report);
            }
            Ok(_) => {
                report.detail = "Ambiguous install response; do not retry automatically".into();
                return Ok(report);
            }
            Err(err) if matches!(root_error(&err), ClientError::SoapFault { code, .. } if *code != 0) =>
            {
                return Err(err.into());
            }
            Err(err) => {
                report.detail =
                    format!("Install outcome unknown: {err}; do not retry automatically");
                return Ok(report);
            }
        }
        if !options.verify {
            return Ok(report);
        }
        for _ in 0..b.polls {
            match b.pause(&cancel) {
                Err(FirmwareError::Cancelled) => {
                    report.outcome = FirmwareInstallOutcome::Unknown;
                    report.detail =
                        "Verification cancelled after dispatch; installation outcome unknown"
                            .into();
                    return Ok(report);
                }
                Err(_) => break,
                Ok(()) => {}
            }
            match self.call(&e.device, "GetInfo", &BTreeMap::new()) {
                Ok(m) => {
                    let readback = identity(&m);
                    let same = readback.model == report.original.identity.model
                        && readback.serial == report.original.identity.serial;
                    let same_version_family = readback
                        .current_version
                        .as_deref()
                        .zip(report.original.identity.current_version.as_deref())
                        .and_then(|(r, o)| comparable(r, o))
                        .is_some()
                        && report
                            .original
                            .reported_current_version
                            .as_deref()
                            .is_none_or(|v| {
                                readback
                                    .current_version
                                    .as_deref()
                                    .and_then(|r| comparable(r, v))
                                    .is_some()
                            });
                    let installed = same
                        && same_version_family
                        && readback
                            .current_version
                            .as_deref()
                            .zip(report.original.offered_version.as_deref())
                            .and_then(|(c, o)| comparable(c, o))
                            .is_some_and(|(c, o)| c == o);
                    report.readback = Some(readback);
                    if !same {
                        report.outcome = FirmwareInstallOutcome::Unknown;
                        report.detail =
                            "Router identity changed; installation cannot be verified".into();
                        return Ok(report);
                    }
                    if installed && !cancel() {
                        report.outcome = FirmwareInstallOutcome::VerifiedInstalled;
                        report.history.push(report.outcome);
                        report.detail =
                            "Original model and serial reachable with the offered firmware version"
                                .into();
                        return Ok(report);
                    }
                }
                Err(err) if disconnected(&err) => {
                    if report.outcome != FirmwareInstallOutcome::Rebooting {
                        report.outcome = FirmwareInstallOutcome::Rebooting;
                        report.history.push(report.outcome);
                    }
                    report.detail =
                        "Router unreachable after acceptance; reboot may be in progress".into();
                }
                Err(err) => {
                    report.outcome = FirmwareInstallOutcome::Unknown;
                    report.detail = format!("Verification failed: {err}");
                    return Ok(report);
                }
            }
        }
        report.outcome = FirmwareInstallOutcome::Timeout;
        report.detail = "Verification budget exhausted; installation outcome remains unverified; do not retry automatically".into();
        Ok(report)
    }
}

// AVM versions may include the model prefix (261.08.25) or just 08.25.
// Never infer an image URL or compare unrecognised version suffixes.
fn version(s: &str) -> Option<(Option<u32>, u32, u32)> {
    let parts: Vec<_> = s
        .split('.')
        .map(str::parse::<u32>)
        .collect::<Result<_, _>>()
        .ok()?;
    match parts.as_slice() {
        [major, minor] => Some((None, *major, *minor)),
        [model, major, minor] => Some((Some(*model), *major, *minor)),
        _ => None,
    }
}
fn comparable(current: &str, offered: &str) -> Option<((u32, u32), (u32, u32))> {
    let (cmodel, cmajor, cminor) = version(current)?;
    let (omodel, omajor, ominor) = version(offered)?;
    if cmodel.is_some() && omodel.is_some() && cmodel != omodel {
        return None;
    }
    Some(((cmajor, cminor), (omajor, ominor)))
}
fn safe_offer(s: &FirmwareStatus) -> Result<(), FirmwareError> {
    let current = s.identity.current_version.as_deref();
    let offered = s.offered_version.as_deref();
    let newer = current
        .zip(offered)
        .and_then(|(c, o)| comparable(c, o))
        .is_some_and(|(c, o)| o > c);
    let identity_known = s.identity.model.is_some() && s.identity.serial.is_some();
    let metadata_consistent = s.reported_current_version.as_deref().is_none_or(|v| {
        current
            .and_then(|c| comparable(c, v))
            .is_some_and(|(c, v)| c == v)
            && offered.and_then(|o| comparable(v, o)).is_some()
    });
    if s.availability != FirmwareAvailability::Available
        || s.build_type.as_deref() != Some("Release")
        || !newer
        || !identity_known
        || !metadata_consistent
    {
        return Err(FirmwareError::Unsafe("need an unambiguous newer box-selected Release offer, original model/serial/version and consistent metadata".into()));
    }
    Ok(())
}
