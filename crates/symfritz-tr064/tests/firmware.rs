#![deny(unsafe_code)]
use serde_json::Value;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::{collections::VecDeque, time::Duration};
use symfritz_tr064::firmware::*;
use symfritz_tr064::{Client, CnonceSource, Request, Response, Transport, TransportError};

type Step = (&'static str, Result<Response, TransportError>);
struct Mock {
    steps: VecDeque<Step>,
    calls: Arc<AtomicUsize>,
    cancel_after: Option<usize>,
    cancelled: Arc<AtomicBool>,
}
impl Transport for Mock {
    fn send(&mut self, req: Request) -> Result<Response, TransportError> {
        let (expected, response) = self.steps.pop_front().expect("unexpected dispatch");
        let action = req
            .headers
            .get("SoapAction")
            .map(|s| s.split('#').next_back().unwrap())
            .unwrap_or(&req.url);
        assert!(
            action.ends_with(expected),
            "expected {expected}, got {action}"
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.cancel_after == Some(self.calls.load(Ordering::SeqCst)) {
            self.cancelled.store(true, Ordering::SeqCst);
        }
        response
    }
}
struct Nonce;
impl CnonceSource for Nonce {
    fn next_cnonce(&mut self) -> Result<String, String> {
        Ok("0123456789abcdef".into())
    }
}
fn response(body: String) -> Result<Response, TransportError> {
    Ok(Response {
        status: 200,
        body: body.into_bytes(),
        ..Default::default()
    })
}
fn soap(action: &str, fields: &[(&str, &str)]) -> Result<Response, TransportError> {
    response(format!(
        "<s:Envelope xmlns:s='urn:soap'><s:Body><u:{action}Response xmlns:u='urn:test'>{}</u:{action}Response></s:Body></s:Envelope>",
        fields
            .iter()
            .map(|(k, v)| format!("<{k}>{v}</{k}>"))
            .collect::<String>()
    ))
}
fn discovery(actions: &[&str]) -> Vec<Step> {
    vec![
        ("tr64desc.xml", response("<root><device><serviceList><service><serviceType>urn:dslforum-org:service:UserInterface:1</serviceType><controlURL>/ui</controlURL><SCPDURL>/ui.xml</SCPDURL></service><service><serviceType>urn:dslforum-org:service:DeviceInfo:1</serviceType><controlURL>/device</controlURL></service></serviceList></device></root>".into())),
        ("ui.xml", response(format!("<scpd><actionList>{}</actionList></scpd>", actions.iter().map(|a|format!("<action><name>{a}</name></action>")).collect::<String>())))
    ]
}
fn standard() -> Vec<Step> {
    discovery(&[
        "GetInfo",
        "X_AVM-DE_GetInfo",
        "X_AVM-DE_CheckUpdate",
        "X_AVM-DE_DoUpdate",
    ])
}
fn device(serial: &str, version: &str) -> Step {
    (
        "GetInfo",
        soap(
            "GetInfo",
            &[
                ("NewModelName", "FRITZ!Box 4060"),
                ("NewSerialNumber", serial),
                ("NewSoftwareVersion", version),
            ],
        ),
    )
}
fn info(state: &str, flag: &str, offered: &str, build: &str) -> Step {
    (
        "GetInfo",
        soap(
            "GetInfo",
            &[
                ("NewX_AVM-DE_UpdateState", state),
                ("NewUpgradeAvailable", flag),
                ("NewX_AVM-DE_Version", offered),
                ("NewX_AVM-DE_BuildType", build),
            ],
        ),
    )
}
fn extra() -> Step {
    (
        "X_AVM-DE_GetInfo",
        soap(
            "X_AVM-DE_GetInfo",
            &[
                ("NewX_AVM-DE_AutoUpdateMode", "notify"),
                ("NewX_AVM-DE_LastFwVersion", "261.08.24"),
                ("NewX_AVM-DE_CurrentFwVersion", "261.08.25"),
                ("NewX_AVM-DE_UpdateSuccessful", "succeeded"),
            ],
        ),
    )
}
fn snapshot(state: &str, flag: &str) -> Vec<Step> {
    vec![
        device("original", "261.08.25"),
        info(state, flag, "08.26", "Release"),
        extra(),
    ]
}
fn fault(status: u16, code: i32) -> Result<Response, TransportError> {
    Ok(Response {status,body:format!("<Fault><detail><UPnPError><errorCode>{code}</errorCode><errorDescription>test rejection</errorDescription></UPnPError></detail></Fault>").into_bytes(),..Default::default()})
}
fn client(steps: Vec<Step>) -> Client<FirmwareTransport<Mock>, Nonce> {
    Client::new(
        FirmwareTransport::new(
            Mock {
                steps: steps.into(),
                calls: Arc::new(AtomicUsize::new(0)),
                cancel_after: None,
                cancelled: Arc::new(AtomicBool::new(false)),
            },
            || false,
        ),
        Nonce,
        "http://mock.invalid:49000",
        "",
        "",
    )
}
fn polling(n: u32) -> FirmwarePollOptions {
    FirmwarePollOptions {
        max_polls: n,
        interval: Duration::ZERO,
        max_elapsed: Duration::from_secs(1),
    }
}
fn install(verify: bool, n: u32) -> FirmwareInstallOptions {
    FirmwareInstallOptions {
        confirmed: true,
        verify,
        polling: polling(n),
    }
}
fn available() -> Vec<Step> {
    let mut s = standard();
    s.extend(snapshot("UpdateAvailable", "1"));
    s
}
fn accepted() -> Step {
    (
        "X_AVM-DE_DoUpdate",
        soap(
            "X_AVM-DE_DoUpdate",
            &[
                ("NewX_AVM-DE_UpdateState", "Started"),
                ("NewUpgradeAvailable", "1"),
            ],
        ),
    )
}

#[test]
fn firmware_availability_contract_and_optional_metadata() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/firmware/contracts.json"
    ))
    .unwrap();
    for case in fixture["availability"].as_array().unwrap() {
        let mut steps = standard();
        steps.extend(snapshot(
            case["state"].as_str().unwrap(),
            case["flag"].as_str().unwrap(),
        ));
        let mut c = client(steps);
        let status = c.firmware_status(|| false).unwrap();
        assert_eq!(
            serde_json::to_value(status.availability).unwrap(),
            case["expected"]
        );
        assert_eq!(status.identity.serial.as_deref(), Some("original"));
        assert_eq!(status.auto_update_mode.as_deref(), Some("notify"));
        assert_eq!(status.previous_version.as_deref(), Some("261.08.24"));
        assert_eq!(status.last_result.as_deref(), Some("succeeded"));
        assert!(c.into_transport().into_inner().steps.is_empty());
    }
}
#[test]
fn available_without_version_is_not_no_update_but_install_refuses() {
    let mut steps = standard();
    steps.extend([
        device("original", "261.08.25"),
        info("UpdateAvailable", "1", "", "Release"),
        extra(),
    ]);
    let mut c = client(steps);
    assert!(matches!(
        c.firmware_install(install(false, 1), || false),
        Err(FirmwareError::Unsafe(_))
    ));
    assert_eq!(
        c.into_transport().into_inner().calls.load(Ordering::SeqCst),
        5
    );
}
#[test]
fn firmware_check_triggers_once_then_completes_after_checking() {
    let mut s = standard();
    s.extend(snapshot("NoUpdate", "0"));
    s.push(("X_AVM-DE_CheckUpdate", soap("X_AVM-DE_CheckUpdate", &[])));
    s.extend(snapshot("Started", "0"));
    s.extend(snapshot("NoUpdate", "0"));
    let mut c = client(s);
    let result = c.firmware_check(polling(2), || false).unwrap();
    assert_eq!(result.outcome, FirmwareCheckOutcome::Complete);
    assert_eq!(
        result.status.availability,
        FirmwareAvailability::Unavailable
    );
    assert!(c.into_transport().into_inner().steps.is_empty());
}
#[test]
fn firmware_check_timeout_bounds_unknown_and_checking_polls() {
    for state in ["Started", "Unknown"] {
        let mut s = standard();
        s.extend(snapshot("NoUpdate", "0"));
        s.push(("X_AVM-DE_CheckUpdate", soap("X_AVM-DE_CheckUpdate", &[])));
        s.extend(snapshot(state, "0"));
        s.extend(snapshot(state, "0"));
        let mut c = client(s);
        assert_eq!(
            c.firmware_check(polling(2), || false).unwrap().outcome,
            FirmwareCheckOutcome::Timeout
        );
        assert!(c.into_transport().into_inner().steps.is_empty());
    }
}
#[test]
fn unsupported_and_auth_and_invalid_xml_are_distinct() {
    let mut c = client(discovery(&["GetInfo"]));
    assert!(matches!(
        c.firmware_check(polling(1), || false),
        Err(FirmwareError::Unsupported(_))
    ));
    let mut s = standard();
    s.push(device("original", "261.08.25"));
    s.push(("GetInfo", fault(500, 606)));
    let mut c = client(s);
    assert!(matches!(
        c.firmware_status(|| false),
        Err(FirmwareError::Client(_))
    ));
    let mut s = standard();
    s.push(device("original", "261.08.25"));
    s.push(("GetInfo", fault(500, 401)));
    let mut c = client(s);
    assert_eq!(
        c.firmware_status(|| false).unwrap().availability,
        FirmwareAvailability::Unsupported
    );
    let mut s = standard();
    s.push(device("original", "261.08.25"));
    s.push(("GetInfo", response("<broken>".into())));
    let mut c = client(s);
    assert!(matches!(
        c.firmware_status(|| false),
        Err(FirmwareError::Client(_))
    ));
    let mut s = standard();
    s.push(device("original", "261.08.25"));
    s.push((
        "GetInfo",
        Ok(Response {
            status: 401,
            ..Default::default()
        }),
    ));
    let mut c = client(s);
    assert!(matches!(
        c.firmware_status(|| false),
        Err(FirmwareError::Client(_))
    ));
}
#[test]
fn optional_action_absence_is_not_auth_error_suppression() {
    let mut s = discovery(&["GetInfo"]);
    s.extend([
        device("original", "261.08.25"),
        info("NoUpdate", "0", "", "Release"),
    ]);
    let mut c = client(s);
    let status = c.firmware_status(|| false).unwrap();
    assert_eq!(status.auto_update_mode, None);
    assert!(!status.can_check);
    let mut s = standard();
    s.extend([
        device("original", "261.08.25"),
        info("NoUpdate", "0", "", "Release"),
        ("X_AVM-DE_GetInfo", fault(500, 606)),
    ]);
    let mut c = client(s);
    assert!(matches!(
        c.firmware_status(|| false),
        Err(FirmwareError::Client(_))
    ));
}
#[test]
fn no_confirmation_or_precancel_or_expired_budget_dispatches_nothing() {
    let mut c = client(vec![]);
    assert!(c.firmware_install(Default::default(), || false).is_err());
    assert_eq!(
        c.firmware_check(polling(1), || true).unwrap_err(),
        FirmwareError::Cancelled
    );
    let mut p = polling(1);
    p.max_elapsed = Duration::ZERO;
    assert_eq!(
        c.firmware_check(p, || false).unwrap_err(),
        FirmwareError::Timeout
    );
    assert_eq!(
        c.into_transport().into_inner().calls.load(Ordering::SeqCst),
        0
    );
}
#[test]
fn cancellation_after_preflight_prevents_install_and_check_mutations() {
    for check in [false, true] {
        let (mut c, cancel) = cancellable(available(), 5);
        let err = if check {
            c.firmware_check(polling(1), || cancel.load(Ordering::SeqCst))
                .unwrap_err()
        } else {
            c.firmware_install(install(false, 1), || cancel.load(Ordering::SeqCst))
                .unwrap_err()
        };
        assert_eq!(err, FirmwareError::Cancelled);
        assert!(c.into_transport().into_inner().steps.is_empty());
    }
}

fn cancellable(
    steps: Vec<Step>,
    after: usize,
) -> (Client<FirmwareTransport<Mock>, Nonce>, Arc<AtomicBool>) {
    let cancel = Arc::new(AtomicBool::new(false));
    (
        Client::new(
            FirmwareTransport::new(
                Mock {
                    steps: steps.into(),
                    calls: Arc::new(AtomicUsize::new(0)),
                    cancel_after: Some(after),
                    cancelled: cancel.clone(),
                },
                {
                    let cancel = cancel.clone();
                    move || cancel.load(Ordering::SeqCst)
                },
            ),
            Nonce,
            "http://mock.invalid:49000",
            "",
            "",
        ),
        cancel,
    )
}
#[test]
fn install_fails_closed_for_unsafe_offers() {
    for (state, flag, offered, build, serial, current) in [
        ("NoUpdate", "0", "08.26", "Release", "original", "261.08.25"),
        ("Unknown", "1", "08.26", "Release", "original", "261.08.25"),
        ("Started", "1", "08.26", "Release", "original", "261.08.25"),
        ("Error", "1", "08.26", "Release", "original", "261.08.25"),
        (
            "UpdateAvailable",
            "1",
            "08.24",
            "Release",
            "original",
            "261.08.25",
        ),
        (
            "UpdateAvailable",
            "1",
            "08.25",
            "Release",
            "original",
            "261.08.25",
        ),
        (
            "UpdateAvailable",
            "1",
            "999.08.26",
            "Release",
            "original",
            "261.08.25",
        ),
        (
            "UpdateAvailable",
            "1",
            "08.26-Lab",
            "Release",
            "original",
            "261.08.25",
        ),
        (
            "UpdateAvailable",
            "1",
            "08.26",
            "Labor",
            "original",
            "261.08.25",
        ),
        ("UpdateAvailable", "1", "08.26", "", "original", "261.08.25"),
        ("UpdateAvailable", "1", "08.26", "Release", "", "261.08.25"),
        (
            "UpdateAvailable",
            "1",
            "08.26",
            "Release",
            "original",
            "261.08.23",
        ),
    ] {
        let mut s = standard();
        s.extend([
            device(serial, current),
            info(state, flag, offered, build),
            extra(),
        ]);
        let mut c = client(s);
        assert!(
            matches!(
                c.firmware_install(install(false, 1), || false),
                Err(FirmwareError::Unsafe(_))
            ),
            "{state}/{offered}/{build}"
        );
        assert!(c.into_transport().into_inner().steps.is_empty());
    }
}
#[test]
fn install_accepted_is_never_installed_without_readback() {
    let mut s = available();
    s.push(accepted());
    let mut c = client(s);
    let r = c.firmware_install(install(false, 1), || false).unwrap();
    assert_eq!(r.outcome, FirmwareInstallOutcome::Accepted);
    assert_eq!(r.readback, None);
    assert!(r.preflight.contains("backup"));
    assert!(c.into_transport().into_inner().steps.is_empty());
}
#[test]
fn install_rejection_and_unknown_disconnect_never_retry() {
    for result in [fault(500, 501), fault(500, 606)] {
        let mut s = available();
        s.push(("X_AVM-DE_DoUpdate", result));
        let mut c = client(s);
        assert!(matches!(
            c.firmware_install(install(false, 1), || false),
            Err(FirmwareError::Client(_))
        ));
        assert!(c.into_transport().into_inner().steps.is_empty());
    }
    for result in [
        Err(TransportError("connection closed after write".into())),
        response("<broken>".into()),
        soap("X_AVM-DE_DoUpdate", &[]),
        fault(502, 0),
    ] {
        let mut s = available();
        s.push(("X_AVM-DE_DoUpdate", result));
        let mut c = client(s);
        let r = c.firmware_install(install(true, 1), || false).unwrap();
        assert_eq!(r.outcome, FirmwareInstallOutcome::Unknown);
        assert!(c.into_transport().into_inner().steps.is_empty());
    }
    let mut s = available();
    s.push((
        "X_AVM-DE_DoUpdate",
        soap(
            "X_AVM-DE_DoUpdate",
            &[("NewX_AVM-DE_UpdateState", "NoUpdate")],
        ),
    ));
    let mut c = client(s);
    assert_eq!(
        c.firmware_install(install(true, 1), || false)
            .unwrap()
            .outcome,
        FirmwareInstallOutcome::Rejected
    );
}
#[test]
fn post_reboot_verification_requires_original_identity_and_offered_version() {
    let mut s = available();
    s.extend([
        accepted(),
        ("GetInfo", Err(TransportError("reboot disconnect".into()))),
        device("original", "261.08.26"),
    ]);
    let mut c = client(s);
    let r = c.firmware_install(install(true, 2), || false).unwrap();
    assert_eq!(r.outcome, FirmwareInstallOutcome::VerifiedInstalled);
    assert_eq!(
        r.history,
        [
            FirmwareInstallOutcome::Accepted,
            FirmwareInstallOutcome::Rebooting,
            FirmwareInstallOutcome::VerifiedInstalled
        ]
    );
    assert!(c.into_transport().into_inner().steps.is_empty());
    for (serial, ver, expected) in [
        ("replacement", "261.08.26", FirmwareInstallOutcome::Unknown),
        ("", "261.08.26", FirmwareInstallOutcome::Unknown),
        ("original", "261.08.25", FirmwareInstallOutcome::Timeout),
        ("original", "999.08.26", FirmwareInstallOutcome::Timeout),
        ("original", "", FirmwareInstallOutcome::Timeout),
    ] {
        let mut s = available();
        s.extend([accepted(), device(serial, ver)]);
        let mut c = client(s);
        assert_eq!(
            c.firmware_install(install(true, 1), || false)
                .unwrap()
                .outcome,
            expected
        );
        assert!(c.into_transport().into_inner().steps.is_empty());
    }
}
#[test]
fn verification_auth_failure_is_unknown_and_cancellation_stops_polls() {
    let mut s = available();
    s.extend([accepted(), ("GetInfo", fault(500, 606))]);
    let mut c = client(s);
    let r = c.firmware_install(install(true, 2), || false).unwrap();
    assert_eq!(r.outcome, FirmwareInstallOutcome::Unknown);
    assert!(r.detail.contains("606"));
    assert!(c.into_transport().into_inner().steps.is_empty());
    let mut s = available();
    s.push(accepted());
    let (mut c, cancel) = cancellable(s, 6);
    let r = c
        .firmware_install(install(true, 2), || cancel.load(Ordering::SeqCst))
        .unwrap();
    assert_eq!(r.outcome, FirmwareInstallOutcome::Unknown);
    assert!(c.into_transport().into_inner().steps.is_empty());
    let mut s = standard();
    s.extend(snapshot("NoUpdate", "0"));
    s.push(("X_AVM-DE_CheckUpdate", soap("X_AVM-DE_CheckUpdate", &[])));
    s.extend(snapshot("Started", "0"));
    let (mut c, cancel) = cancellable(s, 9);
    assert_eq!(
        c.firmware_check(polling(2), || cancel.load(Ordering::SeqCst))
            .unwrap_err(),
        FirmwareError::Cancelled
    );
    assert!(c.into_transport().into_inner().steps.is_empty());
}
#[test]
fn missing_advertised_service_and_action_do_not_dispatch_a_mutation() {
    let mut c = client(vec![(
        "tr64desc.xml",
        response("<root><device><serviceList/></device></root>".into()),
    )]);
    assert!(matches!(
        c.firmware_status(|| false),
        Err(FirmwareError::Unsupported(_))
    ));
    let mut c = client(discovery(&["GetInfo"]));
    assert!(matches!(
        c.firmware_install(install(false, 1), || false),
        Err(FirmwareError::Unsupported(_))
    ));
    assert!(c.into_transport().into_inner().steps.is_empty());
}

#[test]
fn cancellation_during_digest_challenge_never_dispatches_authenticated_mutation() {
    let mut s = available();
    s.push((
        "X_AVM-DE_DoUpdate",
        Ok(Response {
            status: 401,
            headers: std::collections::BTreeMap::from([(
                "WWW-Authenticate".into(),
                "Digest realm=\"test\", nonce=\"n\", qop=\"auth\"".into(),
            )]),
            ..Default::default()
        }),
    ));
    let (mut c, cancel) = cancellable(s, 6);
    let r = c
        .firmware_install(install(true, 1), || cancel.load(Ordering::SeqCst))
        .unwrap();
    assert_eq!(r.outcome, FirmwareInstallOutcome::Unknown);
    assert_eq!(
        c.into_transport().into_inner().calls.load(Ordering::SeqCst),
        6
    );
}
#[test]
fn invalid_check_ack_is_error_without_polling_or_unsupported_classification() {
    let mut s = standard();
    s.extend(snapshot("NoUpdate", "0"));
    s.push(("X_AVM-DE_CheckUpdate", response("<html/>".into())));
    let mut c = client(s);
    assert!(matches!(
        c.firmware_check(polling(2), || false),
        Err(FirmwareError::Client(_))
    ));
    assert!(c.into_transport().into_inner().steps.is_empty());
}

#[test]
fn malformed_readback_is_unknown_rather_than_reboot_or_verified() {
    let mut s = available();
    s.extend([accepted(), ("GetInfo", response("<html/>".into()))]);
    let mut c = client(s);
    let r = c.firmware_install(install(true, 1), || false).unwrap();
    assert_eq!(r.outcome, FirmwareInstallOutcome::Unknown);
    assert_eq!(r.history, [FirmwareInstallOutcome::Accepted]);
    assert!(r.detail.contains("invalid firmware SOAP"));
}
#[test]
fn poll_count_is_finite_even_for_untrusted_large_options() {
    let mut s = standard();
    s.extend(snapshot("NoUpdate", "0"));
    s.push(("X_AVM-DE_CheckUpdate", soap("X_AVM-DE_CheckUpdate", &[])));
    for _ in 0..60 {
        s.extend(snapshot("Started", "0"));
    }
    let mut c = client(s);
    let mut p = polling(u32::MAX);
    p.max_elapsed = Duration::from_secs(600);
    let r = c.firmware_check(p, || false).unwrap();
    assert_eq!(r.outcome, FirmwareCheckOutcome::Timeout);
    let t = c.into_transport().into_inner();
    assert!(t.steps.is_empty());
    assert_eq!(t.calls.load(Ordering::SeqCst), 186);
}

#[test]
fn explicit_check_can_discover_a_new_offer() {
    let mut s = standard();
    s.extend(snapshot("NoUpdate", "0"));
    s.push(("X_AVM-DE_CheckUpdate", soap("X_AVM-DE_CheckUpdate", &[])));
    s.extend(snapshot("UpdateAvailable", "1"));
    let mut c = client(s);
    let r = c.firmware_check(polling(1), || false).unwrap();
    assert_eq!(r.outcome, FirmwareCheckOutcome::Complete);
    assert_eq!(r.status.availability, FirmwareAvailability::Available);
    assert_eq!(r.status.offered_version.as_deref(), Some("08.26"));
    assert!(c.into_transport().into_inner().steps.is_empty());
}
