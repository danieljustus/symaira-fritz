//! Firmware adapters keep legacy status rendering and transports unchanged.
use super::*;
use symfritz_cli::cli::FirmwareCommand;
use symfritz_tr064::firmware::{
    FIRMWARE_PREFLIGHT, FirmwareAvailability, FirmwareCheckOutcome, FirmwareError,
    FirmwareInstallOptions, FirmwareInstallOutcome, FirmwarePollOptions, FirmwareTransport,
};

pub(super) fn cancelled() -> bool {
    CANCEL_REQUESTED.load(Ordering::SeqCst)
        || MCP_CANCELLATION
            .get()
            .is_some_and(CancellationToken::is_cancelled)
}

pub(super) type FirmwareClient =
    Tr064Client<FirmwareTransport<BlockingHttpTransport>, RandomCnonce>;
pub(super) fn client(config: &BoxConfig, password: &str) -> Result<FirmwareClient, HandlerError> {
    let origin = origin_url(config, true)?;
    let pin_store = PinStore::default_path()
        .ok_or_else(|| HandlerError::config("cannot determine home directory"))?;
    let transport = BlockingHttpTransport::new(HttpTransportConfig {
        origin: origin.clone(),
        pin_store: PinStore::new(pin_store),
        insecure_tls: config.insecure_tls,
        // Never issue a fallback dispatch after an ambiguous mutation failure.
        allow_http_fallback: false,
        timeout: Duration::from_secs(config.timeout_seconds.clamp(1, 15) as u64),
        warning_sink: None,
    })
    .map_err(|e| HandlerError::from_operation("firmware transport", e))?;
    Ok(Tr064Client::new(
        FirmwareTransport::new(transport, cancelled),
        RandomCnonce,
        origin.as_str(),
        &config.user,
        password,
    ))
}

fn handler_error(error: FirmwareError) -> HandlerError {
    match error {
        FirmwareError::Client(ref e) => HandlerError::from_client("firmware", e),
        FirmwareError::Cancelled => HandlerError::cancelled(),
        other => HandlerError::operation(other.to_string()),
    }
}

pub(super) fn execute(command: FirmwareCommand, format: OutputFormat) -> Result<(), HandlerError> {
    if matches!(command, FirmwareCommand::Install { yes: false, .. }) {
        return Err(HandlerError::config(format!(
            "confirmation required: firmware install needs --yes. {FIRMWARE_PREFLIGHT}"
        )));
    }
    if matches!(command, FirmwareCommand::Install { .. }) {
        eprintln!("{FIRMWARE_PREFLIGHT}");
    }
    let (config, password) = load_connection()?;
    let mut client = client(&config.box_config, &password)?;
    let (payload, incomplete) = match command {
        FirmwareCommand::Status => (
            serde_json::to_value(client.firmware_status(cancelled).map_err(handler_error)?)
                .expect("firmware status serializes"),
            false,
        ),
        FirmwareCommand::Check => {
            let result = client
                .firmware_check(FirmwarePollOptions::default(), cancelled)
                .map_err(handler_error)?;
            let incomplete = result.outcome == FirmwareCheckOutcome::Timeout
                || matches!(
                    result.status.availability,
                    FirmwareAvailability::Failed | FirmwareAvailability::Unsupported
                );
            (
                serde_json::to_value(result).expect("firmware check serializes"),
                incomplete,
            )
        }
        FirmwareCommand::Install { yes, verify } => {
            let result = client
                .firmware_install(
                    FirmwareInstallOptions {
                        confirmed: yes,
                        verify,
                        ..Default::default()
                    },
                    cancelled,
                )
                .map_err(handler_error)?;
            let incomplete = matches!(
                result.outcome,
                FirmwareInstallOutcome::Unknown
                    | FirmwareInstallOutcome::Timeout
                    | FirmwareInstallOutcome::Rejected
            );
            (
                serde_json::to_value(result).expect("firmware install serializes"),
                incomplete,
            )
        }
    };
    // New text mode uses the same explicit field names as structured output.
    let render_format = if format == OutputFormat::Text {
        OutputFormat::Json
    } else {
        format
    };
    output::write(&mut io::stdout(), &payload, render_format)
        .map_err(|e| HandlerError::operation(e.to_string()))?;
    if incomplete {
        // Preserve the outcome document even on failure; do not append a second
        // JSON error document or imply a safe retry of an uncertain mutation.
        return Err(HandlerError { message: "firmware outcome is incomplete; inspect outcome and detail; do not retry install automatically".into(), exit_code: if cancelled() { EXIT_CANCEL } else { EXIT_OPERATION }, kind: "firmware_incomplete".into(), hint: None, status: false, service: String::new(), action: String::new(), raw: String::new() });
    }
    Ok(())
}

pub(super) fn mcp_check(client: &mut FirmwareClient) -> Result<serde_json::Value, String> {
    client
        .firmware_check(FirmwarePollOptions::default(), cancelled)
        .map(|s| mcp_serialized(&s))
        .map_err(|e| e.to_string())
}
pub(super) fn mcp_install(
    client: &mut FirmwareClient,
    verify: bool,
) -> Result<serde_json::Value, String> {
    client
        .firmware_install(
            FirmwareInstallOptions {
                confirmed: true,
                verify,
                ..Default::default()
            },
            cancelled,
        )
        .map(|s| mcp_serialized(&s))
        .map_err(|e| e.to_string())
}
