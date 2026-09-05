#![deny(unsafe_code)]

use std::{
    collections::BTreeMap,
    fmt::Display,
    io::{self, Read, Write},
    net::{IpAddr, ToSocketAddrs},
    process::{Command as ProcessCommand, ExitCode},
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use clap::CommandFactory;
use clap_complete::{generate, shells};
use serde::{Deserialize, Serialize};
use symfritz_aha::{
    Client as AhaClient, ClientError as AhaClientError, Device as AhaDevice, Group as AhaGroup,
    SystemClock,
};
use symfritz_cli::{
    OutputFormat, TOOL,
    cli::{
        AuthCommand, AuthStoreArgs, AuthSubcommand, CallArgs, CallsArgs, Cli, Command,
        CompletionCommand, ConfigCommand, DiagnoseArgs, DiagnoseSubcommand, HomeCommand,
        HomeListArgs, HomeSwitchArgs, HomeTempArgs, HostGetArgs, LogArgs, RebootArgs, ScrapeArgs,
        StatusArgs, TrafficArgs, TrustArgs, VersionArgs, WlanGuestCommand, WlanSubcommand, WolArgs,
    },
    output, render_version, resolve_output_format,
};
use symfritz_core::{
    PinStore,
    config::{BoxConfig, Config, ConfigError},
    secret::{CredentialSource, SecretError, SecretOptions, resolve},
};
use symfritz_mcp::{CancellationToken, Capabilities as McpCapabilities, Server as McpServer};
use symfritz_tr064::{
    BlockingHttpTransport, Call as TrCall, Client as Tr064Client, CnonceSource, Diagnosis,
    DslLineStats, ErrorKind, Host, HttpTransportConfig, LogEvent, Radio, Service, Status,
    StatusFailure, TrafficData, WlanClient,
};
use url::Url;

const VERSION: &str = match option_env!("SYMFRITZ_VERSION") {
    Some(version) => version,
    None => "dev",
};
const EXIT_CONFIG: u8 = 9;
const EXIT_OPERATION: u8 = 1;
const EXIT_NO_AUTH: u8 = 3;
static CANCEL_REQUESTED: AtomicBool = AtomicBool::new(false);
static MCP_CANCELLATION: OnceLock<CancellationToken> = OnceLock::new();

#[derive(Debug)]
struct HandlerError {
    message: String,
    exit_code: u8,
    kind: String,
    hint: Option<String>,
    status: bool,
}

impl HandlerError {
    fn operation(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: EXIT_OPERATION,
            kind: "unavailable".to_owned(),
            hint: None,
            status: false,
        }
    }

    fn auth(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: EXIT_NO_AUTH,
            kind: "auth".to_owned(),
            hint: Some("Run: symfritz auth login".to_owned()),
            status: false,
        }
    }

    fn config(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: EXIT_CONFIG,
            kind: "validation".to_owned(),
            hint: None,
            status: false,
        }
    }

    fn from_operation(context: &str, error: impl Display) -> Self {
        Self {
            message: format!("{context}: {error}"),
            exit_code: EXIT_OPERATION,
            kind: "unavailable".to_owned(),
            hint: None,
            status: false,
        }
    }

    fn from_aha(context: &str, error: &AhaClientError) -> Self {
        match error {
            AhaClientError::NoCredential
            | AhaClientError::InvalidCredentials
            | AhaClientError::RateLimited(_)
            | AhaClientError::AhaForbiddenAfterRelogin
            | AhaClientError::AhaHttpStatus { status: 401, .. } => {
                Self::auth(format!("{context}: {error}"))
            }
            _ => Self::from_operation(context, error),
        }
    }

    fn from_client(context: &str, error: &symfritz_tr064::ClientError) -> Self {
        let kind = match symfritz_tr064::error_kind(error) {
            ErrorKind::Unauthorized => "unauthorized",
            ErrorKind::ServiceUnavailable => "unavailable",
            ErrorKind::UnsupportedAction => "not_found",
            ErrorKind::Timeout => "timeout",
            ErrorKind::Transport => "unavailable",
            ErrorKind::Internal => "internal",
            ErrorKind::Unknown => "unavailable",
        };
        let unauthorized = symfritz_tr064::error_kind(error) == ErrorKind::Unauthorized;
        Self {
            message: format!("{context}: {error}"),
            exit_code: if unauthorized {
                EXIT_NO_AUTH
            } else {
                EXIT_OPERATION
            },
            kind: kind.to_owned(),
            hint: unauthorized.then(|| "Run: symfritz auth login".to_owned()),
            status: false,
        }
    }
}

impl std::fmt::Display for HandlerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

#[derive(Serialize)]
struct ErrorOutput<'a> {
    error: ErrorDetails<'a>,
}

#[derive(Serialize)]
struct ErrorDetails<'a> {
    kind: &'a str,
    message: &'a str,
}

#[derive(Clone, Copy, Debug, Default)]
struct RandomCnonce;

impl CnonceSource for RandomCnonce {
    fn next_cnonce(&mut self) -> Result<String, String> {
        let mut bytes = [0_u8; 16];
        getrandom::getrandom(&mut bytes).map_err(|error| error.to_string())?;
        Ok(hex::encode(bytes))
    }
}

fn main() -> ExitCode {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).is_some_and(|arg| arg == "--help") && args.len() == 2 {
        let mut command = Cli::command();
        if let Err(error) = command.print_long_help() {
            eprintln!("Error: {error}");
            return ExitCode::from(EXIT_OPERATION);
        }
        println!();
        return ExitCode::SUCCESS;
    }
    let cli = match symfritz_cli::cli::parse_args(&args) {
        Ok(cli) => cli,
        Err(symfritz_cli::cli::ParseError::Help(message)) => {
            print!("{message}");
            if !message.ends_with('\n') {
                println!();
            }
            return ExitCode::SUCCESS;
        }
        Err(symfritz_cli::cli::ParseError::Invalid(message)) => {
            eprintln!("Error: {message}");
            return ExitCode::from(EXIT_OPERATION);
        }
    };
    if let Err(error) = install_signal_handler() {
        eprintln!("Error: {}", error.message);
        return ExitCode::from(EXIT_OPERATION);
    }
    if cli.show_version {
        println!("{TOOL} version {VERSION}");
        return ExitCode::SUCCESS;
    }

    if let Some(Command::Diagnose(args)) = &cli.command
        && args.host.is_none()
        && args.command.is_none()
    {
        eprintln!("Error: accepts 1 arg(s), received 0");
        return ExitCode::from(2);
    }

    let format = match resolve_output_format(&cli.output, cli.json) {
        Ok(format) => format,
        Err(message) => {
            eprintln!("Error: {message}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };

    match execute(cli, format) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if CANCEL_REQUESTED.load(Ordering::SeqCst) {
                return ExitCode::from(130);
            }
            if format != OutputFormat::Text && error.exit_code != EXIT_CONFIG && !error.status {
                let payload = ErrorOutput {
                    error: ErrorDetails {
                        kind: &error.kind,
                        message: &error.message,
                    },
                };
                if let Err(render_error) = output::write(&mut std::io::stdout(), &payload, format) {
                    eprintln!("Error: {render_error}");
                }
            } else {
                eprintln!("Error: {}", error.message);
                if let Some(hint) = &error.hint {
                    eprintln!("Hint: {hint}");
                }
            }
            ExitCode::from(error.exit_code)
        }
    }
}

fn install_signal_handler() -> Result<(), HandlerError> {
    CANCEL_REQUESTED.store(false, Ordering::Relaxed);
    let cancellation = MCP_CANCELLATION.get_or_init(CancellationToken::new).clone();
    cancellation.reset();
    ctrlc::set_handler(move || {
        CANCEL_REQUESTED.store(true, Ordering::SeqCst);
        cancellation.cancel();
    })
    .map_err(|error| HandlerError::operation(format!("failed to install signal handler: {error}")))
}

fn execute(cli: Cli, format: OutputFormat) -> Result<(), HandlerError> {
    match cli.command {
        None => {
            let mut command = Cli::command();
            command
                .print_long_help()
                .map_err(|error| HandlerError::operation(error.to_string()))?;
            println!();
            Ok(())
        }
        Some(Command::Version(args)) => execute_version(args, format),
        Some(Command::Help(args)) => print_help(&args.command),
        Some(Command::Status(args)) => execute_status(args, format),
        Some(Command::Hosts(command)) => execute_hosts(command, format),
        Some(Command::Wlan(command)) => execute_wlan(command, format),
        Some(Command::Dsl(_)) => execute_dsl(format),
        Some(Command::Traffic(args)) => execute_traffic(args, format),
        Some(Command::Calls(args)) => execute_calls(args, format),
        Some(Command::Log(args)) => execute_log(args, format),
        Some(Command::Services(_)) => execute_services(format),
        Some(Command::Call(args)) => execute_call(args, format),
        Some(Command::Detect(_)) => execute_detect(format),
        Some(Command::Config(ConfigCommand::Detect(_))) => execute_detect(format),
        Some(Command::Config(ConfigCommand::Init(args))) => execute_config_init(args),
        Some(Command::Diagnose(args)) => execute_diagnose(args, format),
        Some(Command::Doctor) => execute_doctor(format),
        Some(Command::Mcp) => execute_mcp(),
        Some(Command::Mesh(_)) => execute_mesh(format),
        Some(Command::Home(command)) => execute_home(command, format),
        Some(Command::Dial(args)) => execute_dial(args),
        Some(Command::Hangup) => execute_hangup(),
        Some(Command::Reboot(args)) => execute_reboot(args),
        Some(Command::Wol(args)) => execute_wol(args),
        Some(Command::Auth(command)) => execute_auth(command),
        Some(Command::Scrape(args)) => execute_scrape(args),
        Some(Command::Completion(command)) => execute_completion(command),
    }
}

fn print_help(path: &[String]) -> Result<(), HandlerError> {
    let mut command = Cli::command();
    for part in path {
        command = command
            .find_subcommand_mut(part)
            .ok_or_else(|| HandlerError::config(format!("unknown command {part:?}")))?
            .clone();
    }
    if !path.is_empty() {
        command = command.bin_name(format!("symfritz {}", path.join(" ")));
    }
    if path == [String::from("auth")] {
        command = command.long_about("Resolve, verify, and store the FRITZ!Box password.\n\nResolution order: SYMFRITZ_PASSWORD env → symvault (password_ref) → macOS\nKeychain → plaintext config. 'auth login' captures the password once, verifies\nit against the box, and stores it in the Keychain or symvault so nothing sits in\na dotfile.");
    }
    command
        .print_long_help()
        .map_err(|error| HandlerError::operation(error.to_string()))?;
    println!();
    Ok(())
}

fn execute_status(args: StatusArgs, format: OutputFormat) -> Result<(), HandlerError> {
    let (config, password) = load_connection()?;
    let mut tr064 = make_tr064(&config.box_config, &password)?;
    let result = tr064.status();
    let (status, failure) = match result {
        Ok(status) => (status, None),
        Err(StatusFailure { status, source }) => (status, Some(source)),
    };

    let cpu = if args.cpu && failure.is_none() {
        let mut web = make_web(&config.box_config, &password)?;
        web.cpu_temperatures().unwrap_or_default()
    } else {
        Vec::new()
    };
    let payload = status_payload(&status, &cpu);

    if format != OutputFormat::Text {
        output::write(&mut std::io::stdout(), &payload, format)
            .map_err(|error| HandlerError::operation(error.to_string()))?;
        if let Some(source) = failure {
            let mut error = HandlerError::from_client("status failed", &source);
            error.status = true;
            return Err(error);
        }
        return Ok(());
    }
    if let Some(source) = failure {
        return Err(HandlerError::from_client("status failed", &source));
    }

    println!("Model:       {}", or_dash(&status.model_name));
    let mut firmware = or_dash(&status.firmware_version).to_owned();
    if !status.update_available.is_empty() {
        firmware.push_str(&format!(" (Update available: {})", status.update_available));
    }
    println!("Firmware:    {firmware}");
    println!("Connection:  {}", or_dash(&status.connection_state));
    println!("External IP: {}", or_dash(&status.external_ip));
    println!("Uptime (s):  {}", or_dash(&status.uptime));
    if args.cpu {
        if cpu.is_empty() {
            println!("CPU Temp:    —");
        } else {
            println!(
                "CPU Temp:    {} °C",
                cpu.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    if status.partial {
        eprintln!("\nWarning: {} sub-queries failed:", status.errors.len());
        for error in &status.errors {
            eprintln!("  • {}/{}: {}", error.service, error.action, error.message);
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct StatusPayload<'a> {
    model_name: &'a str,
    firmware_version: &'a str,
    external_ip: &'a str,
    connection_state: &'a str,
    uptime: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    update_available: &'a str,
    #[serde(skip_serializing_if = "slice_is_empty")]
    cpu_temperatures: &'a [i64],
    partial: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<StatusErrorPayload<'a>>,
}

#[derive(Serialize)]
struct StatusErrorPayload<'a> {
    service: &'a str,
    action: &'a str,
    message: &'a str,
    kind: ErrorKind,
    error: &'a str,
}

fn slice_is_empty<T>(value: &&[T]) -> bool {
    value.is_empty()
}

fn status_payload<'a>(status: &'a Status, cpu: &'a [i64]) -> StatusPayload<'a> {
    StatusPayload {
        model_name: &status.model_name,
        firmware_version: &status.firmware_version,
        external_ip: &status.external_ip,
        connection_state: &status.connection_state,
        uptime: &status.uptime,
        update_available: &status.update_available,
        cpu_temperatures: cpu,
        partial: status.partial,
        errors: status
            .errors
            .iter()
            .map(|error| StatusErrorPayload {
                service: &error.service,
                action: &error.action,
                message: &error.message,
                kind: error.kind,
                error: &error.message,
            })
            .collect(),
    }
}

fn execute_hosts(
    command: symfritz_cli::cli::HostsCommand,
    format: OutputFormat,
) -> Result<(), HandlerError> {
    let (config, password) = load_connection()?;
    let mut client = make_tr064(&config.box_config, &password)?;
    match command {
        symfritz_cli::cli::HostsCommand::List => {
            let hosts = client
                .hosts()
                .map_err(|error| HandlerError::from_client("hosts list failed", &error))?;
            render_hosts(&hosts, format)
        }
        symfritz_cli::cli::HostsCommand::Active => {
            let hosts = client
                .active_hosts()
                .map_err(|error| HandlerError::from_client("hosts list failed", &error))?;
            render_hosts(&hosts, format)
        }
        symfritz_cli::cli::HostsCommand::Get(args) => execute_host_get(&mut client, args, format),
    }
}

fn execute_host_get(
    client: &mut Tr064Client<BlockingHttpTransport, RandomCnonce>,
    args: HostGetArgs,
    format: OutputFormat,
) -> Result<(), HandlerError> {
    let result = if let Some(mac) = args.mac.as_deref() {
        client.host_by_mac(mac)
    } else if let Some(ip) = args.ip.as_deref() {
        client.host_by_ip(ip)
    } else if let Some(name) = args.name.as_deref() {
        client.resolve_host(name)
    } else {
        return Err(HandlerError::config(
            "provide a name argument or --mac/--ip",
        ));
    };
    let host = result.map_err(|error| HandlerError::from_client("host lookup failed", &error))?;
    if format != OutputFormat::Text {
        output::write(&mut std::io::stdout(), &host, format)
            .map_err(|error| HandlerError::operation(error.to_string()))?;
    } else {
        println!("Name:    {}", or_dash(&host.name));
        println!("IP:      {}", or_dash(&host.ip));
        println!("MAC:     {}", or_dash(&host.mac));
        println!("Active:  {}", host.active);
        println!("Link:    {}", host.link());
        println!("Source:  {}", or_dash(&host.address_source));
        println!("Lease:   {}s", host.lease_time_remaining);
    }
    Ok(())
}

fn render_hosts(hosts: &[Host], format: OutputFormat) -> Result<(), HandlerError> {
    if format != OutputFormat::Text {
        output::write(&mut std::io::stdout(), &hosts, format)
            .map_err(|error| HandlerError::operation(error.to_string()))?;
    } else if hosts.is_empty() {
        println!("No hosts found.");
    } else {
        println!(
            "{:<24} {:<15} {:<17} {:<6} {:<5} SOURCE",
            "NAME", "IP", "MAC", "STATE", "LINK"
        );
        for host in hosts {
            println!(
                "{:<24} {:<15} {:<17} {:<6} {:<5} {}",
                truncate(&host.name, 24),
                host.ip,
                host.mac,
                if host.active { "up" } else { "down" },
                host.link(),
                host.address_source
            );
        }
    }
    Ok(())
}

fn execute_wlan(
    command: symfritz_cli::cli::WlanCommand,
    format: OutputFormat,
) -> Result<(), HandlerError> {
    let Some(subcommand) = command.command else {
        return Err(HandlerError::operation(
            "internal handler for 'wlan' is not implemented",
        ));
    };
    let (config, password) = load_connection()?;
    let mut client = make_tr064(&config.box_config, &password)?;
    match subcommand {
        WlanSubcommand::Radios => {
            let radios = client
                .radios(3)
                .map_err(|error| HandlerError::from_client("wlan radios failed", &error))?;
            if format != OutputFormat::Text {
                output::write(&mut std::io::stdout(), &radios, format)
                    .map_err(|error| HandlerError::operation(error.to_string()))?;
            } else {
                println!(
                    "{:<3} {:<24} {:<8} {:<8} STANDARD",
                    "IDX", "SSID", "ENABLED", "CHANNEL"
                );
                for radio in radios {
                    println!(
                        "{:<3} {:<24} {:<8} {:<8} {}",
                        radio.index,
                        truncate(&radio.ssid, 24),
                        radio.enabled,
                        radio.channel,
                        radio.standard
                    );
                }
            }
            Ok(())
        }
        WlanSubcommand::Clients => {
            let clients = client
                .all_wlan_clients(3)
                .map_err(|error| HandlerError::from_client("wlan clients failed", &error))?;
            if format != OutputFormat::Text {
                output::write(&mut std::io::stdout(), &clients, format)
                    .map_err(|error| HandlerError::operation(error.to_string()))?;
            } else {
                println!(
                    "{:<3} {:<17} {:<15} {:<7} SPEED",
                    "RAD", "MAC", "IP", "SIGNAL"
                );
                for client in clients {
                    println!(
                        "{:<3} {:<17} {:<15} {:<7} {}",
                        client.radio_index,
                        client.mac,
                        client.ip,
                        dash_if(&client.signal),
                        dash_if(&client.speed)
                    );
                }
            }
            Ok(())
        }
        WlanSubcommand::Guest(guest) => match guest {
            WlanGuestCommand::Status => {
                let radio = client
                    .guest_wlan_status(usize::from(command.guest_index))
                    .map_err(|error| HandlerError::from_client("guest status failed", &error))?;
                if format != OutputFormat::Text {
                    output::write(&mut std::io::stdout(), &radio, format)
                        .map_err(|error| HandlerError::operation(error.to_string()))?;
                } else {
                    println!(
                        "Guest WLAN (index {}): SSID={:?} enabled={}",
                        radio.index, radio.ssid, radio.enabled
                    );
                }
                Ok(())
            }
            WlanGuestCommand::On | WlanGuestCommand::Off => {
                let enable = matches!(guest, WlanGuestCommand::On);
                client
                    .set_guest_wlan(usize::from(command.guest_index), enable)
                    .map_err(|error| HandlerError::from_client("guest toggle failed", &error))?;
                println!(
                    "Guest WLAN (index {}) {}.",
                    command.guest_index,
                    if enable { "enabled" } else { "disabled" }
                );
                Ok(())
            }
        },
    }
}

fn execute_dsl(format: OutputFormat) -> Result<(), HandlerError> {
    let (config, password) = load_connection()?;
    let mut client = make_tr064(&config.box_config, &password)?;
    let stats = client
        .dsl_line_stats()
        .map_err(|error| HandlerError::from_client("dsl stats failed", &error))?;
    if format != OutputFormat::Text {
        output::write(&mut std::io::stdout(), &stats, format)
            .map_err(|error| HandlerError::operation(error.to_string()))?;
    } else {
        println!("DSL Line Statistics:");
        println!(
            "Noise Margin:   {} dB (Up) / {} dB (Down)",
            stats.upstream_noise_margin / 10,
            stats.downstream_noise_margin / 10
        );
        println!(
            "Attenuation:    {} dB (Up) / {} dB (Down)",
            stats.upstream_attenuation / 10,
            stats.downstream_attenuation / 10
        );
        println!(
            "Max Bit Rate:   {} (Up) / {} (Down)",
            format_bit_rate(stats.upstream_max_bit_rate),
            format_bit_rate(stats.downstream_max_bit_rate)
        );
    }
    Ok(())
}

fn execute_traffic(args: TrafficArgs, format: OutputFormat) -> Result<(), HandlerError> {
    let (config, password) = load_connection()?;
    let mut client = make_tr064(&config.box_config, &password)?;

    loop {
        let stats = client
            .online_monitor()
            .map_err(|error| HandlerError::from_client("traffic failed", &error))?;
        if args.watch {
            write_traffic_watch_snapshot(&stats, format)?;
        } else if format != OutputFormat::Text {
            output::write(&mut io::stdout(), &stats, format)
                .map_err(|error| HandlerError::operation(error.to_string()))?;
        } else {
            print_traffic(&stats);
            io::stdout()
                .flush()
                .map_err(|error| HandlerError::operation(error.to_string()))?;
        }

        if !args.watch {
            return Ok(());
        }
        if CANCEL_REQUESTED.load(Ordering::SeqCst) || wait_for_interval(args.interval) {
            return Err(HandlerError::operation("traffic watch canceled"));
        }
    }
}

fn wait_for_interval(interval: Duration) -> bool {
    let deadline = std::time::Instant::now() + interval;
    while !CANCEL_REQUESTED.load(Ordering::SeqCst) {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        std::thread::sleep(remaining.min(Duration::from_millis(25)));
    }
    true
}

fn write_traffic_watch_snapshot(
    stats: &TrafficData,
    format: OutputFormat,
) -> Result<(), HandlerError> {
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    match format {
        OutputFormat::Json => {
            serde_json::to_writer(&mut writer, stats)
                .map_err(|error| HandlerError::operation(error.to_string()))?;
            writer
                .write_all(b"\n")
                .and_then(|()| writer.flush())
                .map_err(|error| HandlerError::operation(error.to_string()))?;
        }
        OutputFormat::Text => {
            drop(writer);
            print_traffic(stats);
            io::stdout()
                .flush()
                .map_err(|error| HandlerError::operation(error.to_string()))?;
        }
        OutputFormat::Yaml => {
            let rendered = output::render(stats, format)
                .map_err(|error| HandlerError::operation(error.to_string()))?;
            writer
                .write_all(rendered.as_bytes())
                .and_then(|()| writer.flush())
                .map_err(|error| HandlerError::operation(error.to_string()))?;
        }
    }
    Ok(())
}

fn execute_calls(args: CallsArgs, format: OutputFormat) -> Result<(), HandlerError> {
    let call_type = match args.call_type.to_ascii_lowercase().as_str() {
        "all" => symfritz_tr064::CALL_ALL,
        "incoming" => symfritz_tr064::CALL_INCOMING,
        "missed" => symfritz_tr064::CALL_MISSED,
        "outgoing" => symfritz_tr064::CALL_OUTGOING,
        "rejected" => symfritz_tr064::CALL_REJECTED,
        other => {
            return Err(HandlerError::config(format!(
                "invalid call type: unknown call type: {other}"
            )));
        }
    };
    let (config, password) = load_connection()?;
    let mut client = make_tr064(&config.box_config, &password)?;
    let calls = client
        .calls(
            call_type,
            args.limit.unwrap_or_default().max(0) as usize,
            args.days.unwrap_or_default().max(0) as usize,
        )
        .map_err(|error| HandlerError::from_client("calls failed", &error))?;
    let calls: Vec<CallOutput<'_>> = calls.iter().map(CallOutput::from).collect();
    if format != OutputFormat::Text {
        output::write(&mut std::io::stdout(), &calls, format)
            .map_err(|error| HandlerError::operation(error.to_string()))?;
    } else if calls.is_empty() {
        println!("No calls found.");
    } else {
        println!(
            "{:<18}  {:<8}  {:<24}  {:<16}  DURATION",
            "DATE", "TYPE", "NAME", "NUMBER"
        );
        for call in &calls {
            println!(
                "{:<18}  {:<8}  {:<24}  {:<16}  {}",
                call.date_text(),
                call_type_text(call.call_type),
                truncate(call.caller, 24),
                if call.caller_number.is_empty() {
                    call.called_number
                } else {
                    call.caller_number
                },
                duration_text(call.duration)
            );
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct CallOutput<'a> {
    #[serde(rename = "Type")]
    call_type: i32,
    #[serde(rename = "Date")]
    date: &'a str,
    #[serde(rename = "Caller")]
    caller: &'a str,
    #[serde(rename = "CallerNumber")]
    caller_number: &'a str,
    #[serde(rename = "CalledNumber")]
    called_number: &'a str,
    #[serde(rename = "Name")]
    name: &'a str,
    #[serde(rename = "Duration")]
    duration: i64,
}

impl<'a> From<&'a TrCall> for CallOutput<'a> {
    fn from(call: &'a TrCall) -> Self {
        Self {
            call_type: call.call_type,
            date: &call.date,
            caller: &call.caller,
            caller_number: &call.caller_number,
            called_number: &call.called_number,
            name: &call.name,
            duration: call.duration,
        }
    }
}
impl CallOutput<'_> {
    fn date_text(&self) -> String {
        let parts: Vec<_> = self.date.split(['T', '-', ':', 'Z']).collect();
        if parts.len() >= 6 {
            format!(
                "{}.{}.{} {}:{}",
                parts[2],
                parts[1],
                parts[0].get(2..).unwrap_or(parts[0]),
                parts[3],
                parts[4]
            )
        } else {
            "—".to_owned()
        }
    }
}

fn execute_log(args: LogArgs, format: OutputFormat) -> Result<(), HandlerError> {
    let (config, password) = load_connection()?;
    let mut client = make_tr064(&config.box_config, &password)?;
    let events = client
        .device_log(&args.filter)
        .map_err(|error| HandlerError::from_client("log failed", &error))?;
    if format != OutputFormat::Text {
        output::write(&mut std::io::stdout(), &events, format)
            .map_err(|error| HandlerError::operation(error.to_string()))?;
    } else if events.is_empty() {
        println!("No log events found.");
    } else {
        for event in events {
            println!(
                "{} [{}] {}",
                log_time_text(&event.time),
                event.group,
                event.msg
            );
        }
    }
    Ok(())
}

fn execute_services(format: OutputFormat) -> Result<(), HandlerError> {
    let config = symfritz_core::config::load_config().map_err(config_error)?;
    let mut client = make_tr064(&config.box_config, "")?;
    let services = client
        .discover()
        .map_err(|error| HandlerError::from_client("discovery failed", &error))?;
    let services: Vec<ServiceOutput<'_>> = services.iter().map(ServiceOutput::from).collect();
    if format != OutputFormat::Text {
        output::write(&mut std::io::stdout(), &services, format)
            .map_err(|error| HandlerError::operation(error.to_string()))?;
    } else {
        for service in &services {
            println!("{:<60} {}", service.service_type, service.control_url);
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct ServiceOutput<'a> {
    #[serde(rename = "Type")]
    service_type: &'a str,
    #[serde(rename = "ControlURL")]
    control_url: &'a str,
}
impl<'a> From<&'a Service> for ServiceOutput<'a> {
    fn from(service: &'a Service) -> Self {
        Self {
            service_type: &service.service_type,
            control_url: &service.control_url,
        }
    }
}

fn execute_call(args: CallArgs, format: OutputFormat) -> Result<(), HandlerError> {
    let format = if format == OutputFormat::Text {
        OutputFormat::Json
    } else {
        format
    };
    let mut arguments = BTreeMap::new();
    for argument in args.arguments {
        let Some((key, value)) = argument.split_once('=') else {
            return Err(HandlerError::config(format!(
                "bad argument: argument {argument:?} is not Key=Value"
            )));
        };
        arguments.insert(key.to_owned(), value.to_owned());
    }
    let (config, password) = load_connection()?;
    let mut client = make_tr064(&config.box_config, &password)?;
    let service = if let Some(service) = service_by_shortcut(&args.service) {
        service
    } else {
        client.service_by_name(&args.service).map_err(|error| {
            HandlerError::config(format!("unknown service {:?}: {error}", args.service))
        })?
    };
    let values = client
        .call(&service, &args.action, &arguments)
        .map_err(|error| HandlerError::from_client("tr064 call failed", &error))?;
    output::write(&mut std::io::stdout(), &values, format)
        .map_err(|error| HandlerError::operation(error.to_string()))
}

fn service_by_shortcut(name: &str) -> Option<Service> {
    match name.to_ascii_lowercase().as_str() {
        "deviceinfo" => Some(Service::device_info()),
        "wanip" => Some(Service::wan_ip_connection()),
        "wanppp" => Some(Service::wan_ppp_connection()),
        "wancommon" => Some(Service::wan_common_interface()),
        "hosts" => Some(Service::hosts()),
        "wlan1" => Some(Service {
            service_type: "urn:dslforum-org:service:WLANConfiguration:1".to_owned(),
            control_url: "/upnp/control/wlanconfig1".to_owned(),
        }),
        _ => None,
    }
}

fn execute_dial(args: symfritz_cli::cli::OneArg) -> Result<(), HandlerError> {
    let (config, password) = load_connection()?;
    let mut client = make_tr064(&config.box_config, &password)?;
    client
        .dial(&args.number)
        .map_err(|error| HandlerError::from_client("dial failed", &error))?;
    println!("Dialing {}...", args.number);
    Ok(())
}

fn execute_hangup() -> Result<(), HandlerError> {
    let (config, password) = load_connection()?;
    let mut client = make_tr064(&config.box_config, &password)?;
    client
        .hangup()
        .map_err(|error| HandlerError::from_client("hangup failed", &error))?;
    println!("Hanging up...");
    Ok(())
}

fn execute_reboot(args: RebootArgs) -> Result<(), HandlerError> {
    if !args.yes {
        return Err(HandlerError::config(
            "confirmation required: refusing to reboot without --yes",
        ));
    }
    let (config, password) = load_connection()?;
    let mut client = make_tr064(&config.box_config, &password)?;
    client
        .reboot()
        .map_err(|error| HandlerError::from_client("reboot failed", &error))?;
    println!("Reboot triggered.");
    Ok(())
}

fn execute_wol(args: WolArgs) -> Result<(), HandlerError> {
    if args.mac.is_none() && args.host.is_none() {
        return Err(HandlerError::config("provide a host argument or --mac"));
    }
    let (config, password) = load_connection()?;
    let mut client = make_tr064(&config.box_config, &password)?;
    let mac = if let Some(mac) = args.mac {
        mac
    } else {
        let reference = args
            .host
            .ok_or_else(|| HandlerError::config("provide a host argument or --mac"))?;
        client
            .resolve_host(&reference)
            .map_err(|error| HandlerError::from_client("host lookup failed", &error))?
            .mac
    };
    if mac.is_empty() {
        return Err(HandlerError::operation(
            "no MAC address resolved for target",
        ));
    }
    client
        .wake_on_lan(&mac)
        .map_err(|error| HandlerError::from_client("wol failed", &error))?;
    println!("Wake-on-LAN packet sent to {mac}.");
    Ok(())
}

fn execute_config_init(args: symfritz_cli::cli::InitArgs) -> Result<(), HandlerError> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .ok_or_else(|| HandlerError::config("cannot determine home directory"))?;
    let path = symfritz_core::config::default_config_path(&home);
    let outcome = symfritz_core::config::init_config(&path, args.force).map_err(config_error)?;
    let stdout = outcome.stdout();
    if !stdout.is_empty() {
        print!("{stdout}");
    }
    let stderr = outcome.stderr();
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }
    Ok(())
}

fn execute_auth(command: AuthCommand) -> Result<(), HandlerError> {
    match command.command {
        None => print_help(&[String::from("auth")]),
        Some(AuthSubcommand::Test) => execute_auth_test(),
        Some(AuthSubcommand::Trust(args)) => execute_auth_trust(args),
        Some(AuthSubcommand::Login(args)) => execute_auth_login(args.into()),
        Some(AuthSubcommand::Store(args)) => execute_auth_store(args),
    }
}

fn execute_auth_trust(args: TrustArgs) -> Result<(), HandlerError> {
    let Some(host) = args.reset.filter(|host| !host.is_empty()) else {
        return print_help(&[String::from("auth"), String::from("trust")]);
    };
    let path = PinStore::default_path()
        .ok_or_else(|| HandlerError::config("cannot determine home directory"))?;
    let store = PinStore::new(path);
    let reset = store
        .reset(&host)
        .map_err(|error| HandlerError::operation(format!("failed to reset pin: {error}")))?;
    if reset {
        println!(
            "Reset certificate pin for {host}.\nNext TLS connection will pin the current certificate."
        );
    } else {
        println!("No pin recorded for {host}.");
    }
    Ok(())
}

fn execute_auth_test() -> Result<(), HandlerError> {
    let config = symfritz_core::config::load_config().map_err(config_error)?;
    let result = resolve(&SecretOptions::from(&config.box_config)).map_err(secret_error)?;
    if result.source == CredentialSource::None || result.password.trim().is_empty() {
        return Err(HandlerError::auth(
            "no credential: no password configured (run 'symfritz auth login')",
        ));
    }
    println!("Credential source: {}", result.source);
    println!(
        "Box:               {} (user {:?})",
        config.box_config.host, config.box_config.user
    );
    let (session_ok, tr064_ok) = verify_credential(&config.box_config, &result.password);
    println!(
        "  {} Web session login (login_sid.lua)",
        bool_glyph(session_ok)
    );
    println!("  {} TR-064 access (DeviceInfo)", bool_glyph(tr064_ok));
    if !tr064_ok {
        println!(
            "\nNote: TR-064 must be enabled on the box: Home Network → Network →\nNetwork Settings → \"Allow access for applications\"."
        );
    }
    if !session_ok {
        return Err(HandlerError::auth(
            "invalid credential: credential rejected by box",
        ));
    }
    println!("\nOK: credential is valid.");
    Ok(())
}

fn verify_credential(box_config: &BoxConfig, password: &str) -> (bool, bool) {
    let session_ok = make_web(box_config, password)
        .and_then(|mut client| {
            client
                .sid()
                .map(|_| ())
                .map_err(|_| HandlerError::operation("session"))
        })
        .is_ok();
    let tr064_ok = make_tr064(box_config, password)
        .and_then(|mut client| {
            client
                .call(&Service::device_info(), "GetInfo", &BTreeMap::new())
                .map(|_| ())
                .map_err(|_| HandlerError::operation("tr064"))
        })
        .is_ok();
    (session_ok, tr064_ok)
}

fn execute_auth_login(args: AuthStoreArgs) -> Result<(), HandlerError> {
    let config = symfritz_core::config::load_config().map_err(config_error)?;
    let password = prompt_hidden(&format!(
        "FRITZ!Box password for {}@{}: ",
        or_dash(&config.box_config.user),
        config.box_config.host
    ))?;
    if password.trim().is_empty() {
        return Err(HandlerError::config("empty password"));
    }
    let (session_ok, tr064_ok) = verify_credential(&config.box_config, &password);
    if !session_ok {
        return Err(HandlerError::auth("box rejected the password"));
    }
    println!(
        "Verified: web login ✓  TR-064 {}",
        if tr064_ok {
            "✓"
        } else {
            "✗ (disabled or unavailable)"
        }
    );
    let (backend, hint) = store_credential(&config.box_config, &password, &args)?;
    println!("Stored in {backend}.");
    if !hint.is_empty() {
        println!("{hint}");
    }
    Ok(())
}

fn execute_auth_store(args: AuthStoreArgs) -> Result<(), HandlerError> {
    let config = symfritz_core::config::load_config().map_err(config_error)?;
    let password = match std::env::var("SYMFRITZ_PASSWORD") {
        Ok(password) if !password.is_empty() => password,
        _ => prompt_hidden(&format!(
            "Password to store for {}: ",
            config.box_config.host
        ))?,
    };
    if password.trim().is_empty() {
        return Err(HandlerError::config("empty password"));
    }
    let (backend, hint) = store_credential(&config.box_config, &password, &args)?;
    println!("Stored in {backend}.");
    if !hint.is_empty() {
        println!("{hint}");
    }
    Ok(())
}

fn store_credential(
    box_config: &BoxConfig,
    password: &str,
    args: &AuthStoreArgs,
) -> Result<(String, String), HandlerError> {
    if let Some(reference) = args.symvault.as_deref() {
        symfritz_core::secret::symvault_set(reference, password)
            .map_err(|error| HandlerError::operation(format!("store failed: {error}")))?;
        return Ok((
            format!("symvault ({reference})"),
            format!(
                "Set 'password_ref = \"{reference}\"' in ~/.config/symfritz/config.toml to use it."
            ),
        ));
    }
    if args.keychain || symfritz_core::secret::keychain_available() {
        let account = if box_config.keychain_account.is_empty() {
            box_config.host.as_str()
        } else {
            box_config.keychain_account.as_str()
        };
        symfritz_core::secret::keychain_set(
            symfritz_core::secret::KEYCHAIN_SERVICE,
            Some(account),
            password,
        )
        .map_err(|error| HandlerError::operation(format!("store failed: {error}")))?;
        return Ok((
            format!(
                "macOS Keychain (service {:?}, account {:?})",
                symfritz_core::secret::KEYCHAIN_SERVICE,
                account
            ),
            String::from("Set 'keychain = true' in ~/.config/symfritz/config.toml to use it."),
        ));
    }
    Err(HandlerError::operation(
        "no storage backend available; use --symvault <path> (symvault not required to be running for storage on macOS Keychain)",
    ))
}

#[cfg(unix)]
struct TerminalEchoGuard {
    saved: String,
}

#[cfg(unix)]
impl TerminalEchoGuard {
    fn new() -> Result<Self, HandlerError> {
        let saved = ProcessCommand::new("stty")
            .arg("-g")
            .output()
            .map_err(|error| {
                HandlerError::operation(format!("cannot read terminal settings: {error}"))
            })?;
        if !saved.status.success() {
            return Err(HandlerError::operation("cannot read terminal settings"));
        }
        let saved = String::from_utf8_lossy(&saved.stdout).trim().to_owned();
        let disabled = ProcessCommand::new("stty")
            .arg("-echo")
            .status()
            .map_err(|error| {
                HandlerError::operation(format!("cannot disable password echo: {error}"))
            })?;
        if !disabled.success() {
            return Err(HandlerError::operation("cannot disable password echo"));
        }
        Ok(Self { saved })
    }
}

#[cfg(unix)]
impl Drop for TerminalEchoGuard {
    fn drop(&mut self) {
        // Drop is the final safety net for read errors, cancellation, and panic
        // unwinding. Never replace the user's terminal mode with a guess.
        let _ = ProcessCommand::new("stty").arg(&self.saved).status();
    }
}

fn prompt_hidden(prompt: &str) -> Result<String, HandlerError> {
    use std::io::IsTerminal;
    eprint!("{prompt}");
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return Err(HandlerError::operation(
            "cannot prompt for password: stdin is not a terminal (set SYMFRITZ_PASSWORD instead)",
        ));
    }
    #[cfg(unix)]
    {
        let _echo_guard = TerminalEchoGuard::new()?;
        let mut value = String::new();
        let read_result = stdin.read_line(&mut value);
        eprintln!();
        read_result
            .map_err(|error| HandlerError::operation(format!("reading password: {error}")))?;
        Ok(value.trim().to_owned())
    }
    #[cfg(not(unix))]
    {
        let _ = stdin;
        let _ = std::io::stdout().flush();
        Err(HandlerError::operation(
            "cannot prompt for password: hidden terminal input is unsupported on this platform",
        ))
    }
}

fn bool_glyph(value: bool) -> &'static str {
    if value { "✓" } else { "✗" }
}

struct FritzMcpCapabilities {
    tr064: Tr064Client<BlockingHttpTransport, RandomCnonce>,
    web: AhaClient<BlockingHttpTransport, SystemClock>,
}

#[derive(Serialize)]
struct McpStatusOutput {
    #[serde(rename = "ModelName")]
    model_name: String,
    #[serde(rename = "FirmwareVersion")]
    firmware_version: String,
    #[serde(rename = "ExternalIP")]
    external_ip: String,
    #[serde(rename = "ConnectionState")]
    connection_state: String,
    #[serde(rename = "Uptime")]
    uptime: String,
    #[serde(rename = "UpdateAvailable")]
    update_available: String,
    #[serde(rename = "Partial")]
    partial: bool,
    #[serde(rename = "Errors")]
    errors: Option<Vec<McpStatusError>>,
}

#[derive(Serialize)]
struct McpStatusError {
    service: String,
    action: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<ErrorKind>,
}

fn mcp_serialized<T: Serialize>(value: &T) -> serde_json::Value {
    serde_json::Value::String(
        serde_json::to_string_pretty(value).expect("MCP backend output is serializable"),
    )
}

fn mcp_status_value(status: &Status) -> serde_json::Value {
    let errors = (!status.errors.is_empty()).then(|| {
        status
            .errors
            .iter()
            .map(|error| McpStatusError {
                service: error.service.clone(),
                action: error.action.clone(),
                message: error.message.clone(),
                kind: (error.kind != ErrorKind::Unknown).then_some(error.kind),
            })
            .collect()
    });
    mcp_serialized(&McpStatusOutput {
        model_name: status.model_name.clone(),
        firmware_version: status.firmware_version.clone(),
        external_ip: status.external_ip.clone(),
        connection_state: status.connection_state.clone(),
        uptime: status.uptime.clone(),
        update_available: status.update_available.clone(),
        partial: status.partial,
        errors,
    })
}

impl McpCapabilities for FritzMcpCapabilities {
    fn status(&mut self) -> Result<serde_json::Value, String> {
        let status = self
            .tr064
            .status()
            .map_err(|error| format!("status: {error}"))?;
        Ok(mcp_status_value(&status))
    }

    fn host_list(&mut self, active_only: bool) -> Result<serde_json::Value, String> {
        let hosts = if active_only {
            self.tr064.active_hosts()
        } else {
            self.tr064.hosts()
        }
        .map_err(|error| format!("host_list: {error}"))?;
        Ok(mcp_serialized(&hosts))
    }

    fn host_get(
        &mut self,
        name: Option<&str>,
        mac: Option<&str>,
        ip: Option<&str>,
    ) -> Result<serde_json::Value, String> {
        let host = if let Some(mac) = mac {
            self.tr064.host_by_mac(mac)
        } else if let Some(ip) = ip {
            self.tr064.host_by_ip(ip)
        } else if let Some(name) = name {
            self.tr064.resolve_host(name)
        } else {
            return Err("provide one of name, mac, or ip".to_owned());
        }
        .map_err(|error| format!("host_get: {error}"))?;
        Ok(mcp_serialized(&host))
    }

    fn diagnose(&mut self, host: &str, ports: &[i64]) -> Result<serde_json::Value, String> {
        let probes = ports
            .iter()
            .map(|port| {
                let port = u16::try_from(*port).map_err(|_| format!("invalid port: {port}"))?;
                Ok(symfritz_tr064::PortProbe {
                    port,
                    label: "custom".to_owned(),
                    probe_type: "tcp".to_owned(),
                    optional: false,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let diagnosis = self.tr064.diagnose(
            host,
            symfritz_tr064::DiagnoseOptions {
                ports: probes,
                dial_timeout_ms: 0,
            },
        );
        Ok(mcp_serialized(&diagnosis))
    }

    fn mesh(&mut self) -> Result<serde_json::Value, String> {
        let mesh = self
            .web
            .mesh_topology(&mut self.tr064)
            .map_err(|error| format!("mesh: {error}"))?;
        Ok(mcp_serialized(&mesh))
    }

    fn wlan_clients(&mut self) -> Result<serde_json::Value, String> {
        let clients = self
            .tr064
            .all_wlan_clients(3)
            .map_err(|error| format!("wlan_clients: {error}"))?;
        Ok(mcp_serialized(&clients))
    }

    fn wake_on_lan(
        &mut self,
        host: Option<&str>,
        mac: Option<&str>,
    ) -> Result<serde_json::Value, String> {
        let mac = if let Some(mac) = mac {
            mac.to_owned()
        } else if let Some(host) = host {
            self.tr064
                .resolve_host(host)
                .map_err(|error| format!("wake_on_lan: {error}"))?
                .mac
        } else {
            return Err("provide host or mac".to_owned());
        };
        self.tr064
            .wake_on_lan(&mac)
            .map_err(|error| format!("wake_on_lan: {error}"))?;
        Ok(mcp_serialized(&serde_json::json!({"woke": mac})))
    }

    fn home_list(&mut self) -> Result<serde_json::Value, String> {
        let devices = self
            .web
            .devices()
            .map_err(|error| format!("home_list: {error}"))?;
        let payload: Vec<_> = devices.iter().map(AhaDeviceOutput::from).collect();
        Ok(mcp_serialized(&payload))
    }

    fn home_switch(&mut self, ain: &str, on: bool) -> Result<serde_json::Value, String> {
        if on {
            self.web
                .switch_on(ain)
                .map_err(|error| format!("home_switch: {error}"))?;
        } else {
            self.web
                .switch_off(ain)
                .map_err(|error| format!("home_switch: {error}"))?;
        }
        Ok(mcp_serialized(&serde_json::json!({"ain": ain, "on": on})))
    }
}

fn execute_mcp() -> Result<(), HandlerError> {
    let (config, password) = load_connection()?;
    let tr064 = make_tr064(&config.box_config, &password)?;
    let web = make_web(&config.box_config, &password)?;
    let cancellation = MCP_CANCELLATION.get_or_init(CancellationToken::new).clone();
    McpServer::new(TOOL, VERSION, FritzMcpCapabilities { tr064, web })
        .serve_stdio_with_context(&cancellation)
        .map_err(|error| HandlerError::from_operation("mcp server failed", error))
}

fn load_connection() -> Result<(Config, String), HandlerError> {
    let config = symfritz_core::config::load_config().map_err(config_error)?;
    let result = resolve(&SecretOptions::from(&config.box_config)).map_err(secret_error)?;
    if result.source == CredentialSource::None || result.password.trim().is_empty() {
        return Err(HandlerError::auth(
            "no password configured (run 'symfritz auth login')",
        ));
    }
    if result.source == CredentialSource::Config {
        eprintln!(
            "warning: password loaded from plaintext config. Consider 'symfritz auth login' for Keychain/symvault storage."
        );
    }
    Ok((config, result.password))
}

fn make_tr064(
    box_config: &BoxConfig,
    password: &str,
) -> Result<Tr064Client<BlockingHttpTransport, RandomCnonce>, HandlerError> {
    let origin = origin_url(box_config, true)?;
    let pin_store = PinStore::default_path()
        .ok_or_else(|| HandlerError::config("cannot determine home directory"))?;
    let transport = BlockingHttpTransport::new(HttpTransportConfig {
        origin: origin.clone(),
        pin_store: PinStore::new(pin_store),
        insecure_tls: box_config.insecure_tls,
        timeout: box_config.timeout(),
        warning_sink: Some(std::sync::Arc::new(|message| {
            eprintln!("warning: {message}")
        })),
    })
    .map_err(|error| HandlerError::from_operation("failed to create TR-064 transport", error))?;
    Ok(Tr064Client::new(
        transport,
        RandomCnonce,
        origin.as_str(),
        &box_config.user,
        password,
    ))
}

fn make_web(
    box_config: &BoxConfig,
    password: &str,
) -> Result<AhaClient<BlockingHttpTransport, SystemClock>, HandlerError> {
    let origin = origin_url(box_config, false)?;
    let pin_store = PinStore::default_path()
        .ok_or_else(|| HandlerError::config("cannot determine home directory"))?;
    let transport = BlockingHttpTransport::new(HttpTransportConfig {
        origin: origin.clone(),
        pin_store: PinStore::new(pin_store),
        insecure_tls: box_config.insecure_tls,
        timeout: box_config.timeout(),
        warning_sink: Some(std::sync::Arc::new(|message| {
            eprintln!("warning: {message}")
        })),
    })
    .map_err(|error| HandlerError::from_operation("failed to create web transport", error))?;
    Ok(AhaClient::new(
        transport,
        SystemClock,
        origin.as_str(),
        &box_config.user,
        password,
    ))
}

fn origin_url(box_config: &BoxConfig, tr064: bool) -> Result<Url, HandlerError> {
    let mut host = box_config.host.trim().trim_end_matches('/').to_owned();
    host = host
        .strip_prefix("http://")
        .or_else(|| host.strip_prefix("https://"))
        .unwrap_or(&host)
        .to_owned();
    let (host, explicit_port) = match host.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.parse::<u16>().is_ok() => {
            (host.to_owned(), port.parse::<u16>().ok())
        }
        _ => (host, None),
    };
    let (scheme, default_port) = if box_config.use_tls {
        if tr064 {
            ("https", 49443)
        } else {
            ("https", 443)
        }
    } else if tr064 {
        ("http", 49000)
    } else {
        ("http", 80)
    };
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host
    };
    let port = explicit_port.unwrap_or(default_port);
    Url::parse(&format!("{scheme}://{host}:{port}"))
        .map_err(|error| HandlerError::config(format!("invalid configured box origin: {error}")))
}

fn config_error(error: ConfigError) -> HandlerError {
    HandlerError::config(error.to_string())
}
fn secret_error(error: SecretError) -> HandlerError {
    HandlerError::config(format!("could not resolve password: {error}"))
}

fn or_dash(value: &str) -> &str {
    if value.trim().is_empty() {
        "—"
    } else {
        value
    }
}
fn dash_if(value: &str) -> &str {
    or_dash(value)
}
fn truncate(value: &str, max: usize) -> String {
    let mut chars = value.chars();
    let truncated: String = chars.by_ref().take(max).collect();
    if chars.next().is_none() {
        value.to_owned()
    } else if max <= 1 {
        truncated
    } else {
        let prefix: String = value.chars().take(max - 1).collect();
        format!("{prefix}…")
    }
}
fn format_bit_rate(value: i64) -> String {
    if value == 0 {
        "—".to_owned()
    } else if value >= 1_000_000 {
        format!("{:.2} Mbit/s", value as f64 / 1_000_000.0)
    } else if value >= 1_000 {
        format!("{:.2} kbit/s", value as f64 / 1_000.0)
    } else {
        format!("{value} bit/s")
    }
}
fn format_speed(value: f64) -> String {
    if value == 0.0 {
        "—".to_owned()
    } else if value >= 1_000_000.0 {
        format!("{:.2} Mbit/s", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.2} kbit/s", value / 1_000.0)
    } else {
        format!("{value:.0} bit/s")
    }
}
fn duration_text(value: i64) -> String {
    if value <= 0 {
        return "—".to_owned();
    }
    let total = (value + 500_000_000) / 1_000_000_000;
    if total >= 60 {
        format!("{}m{}s", total / 60, total % 60)
    } else {
        format!("{total}s")
    }
}
fn call_type_text(value: i32) -> &'static str {
    match value {
        symfritz_tr064::CALL_INCOMING => "incoming",
        symfritz_tr064::CALL_MISSED => "missed",
        symfritz_tr064::CALL_OUTGOING => "outgoing",
        symfritz_tr064::CALL_REJECTED => "rejected",
        _ => "unknown",
    }
}
fn log_time_text(value: &str) -> String {
    let parts: Vec<_> = value.split(['T', '-', ':', 'Z']).collect();
    if parts.len() >= 7 {
        format!(
            "{}.{}.{} {}:{}:{}",
            parts[2],
            parts[1],
            parts[0].get(2..).unwrap_or(parts[0]),
            parts[3],
            parts[4],
            parts[5]
        )
    } else {
        "—".to_owned()
    }
}

fn print_traffic(stats: &TrafficData) {
    println!("WAN Traffic Statistics:");
    println!("┌─ Downstream ────────────────────────────────────────┐");
    print_traffic_category("Internet", &stats.downstream_internet);
    print_traffic_category("Media", &stats.downstream_media);
    print_traffic_category("Guest", &stats.downstream_guest);
    println!("├─ Upstream ───────────────────────────────────────────┤");
    print_traffic_category("Realtime", &stats.upstream_realtime);
    print_traffic_category("High Priority", &stats.upstream_high_priority);
    print_traffic_category("Default", &stats.upstream_default_priority);
    print_traffic_category("Low Priority", &stats.upstream_low_priority);
    print_traffic_category("Guest", &stats.upstream_guest);
    println!("└──────────────────────────────────────────────────────┘");
}
fn print_traffic_category(name: &str, values: &[f64]) {
    let value = values.first().copied().unwrap_or_default();
    println!("│  {name:<50} {:>12} │", format_speed(value));
}

// Keep these imports and model names visible to rustdoc users of the binary crate.
#[allow(dead_code)]
fn _model_markers(_: (DslLineStats, LogEvent, Radio, WlanClient)) {}

#[cfg(test)]
mod tests {
    use super::{duration_text, format_bit_rate, format_speed, service_by_shortcut, truncate};

    #[test]
    fn formatting_matches_go_boundaries() {
        assert_eq!(format_speed(0.0), "—");
        assert_eq!(format_speed(1_234.0), "1.23 kbit/s");
        assert_eq!(format_speed(1_234_567.0), "1.23 Mbit/s");
        assert_eq!(format_bit_rate(1_234), "1.23 kbit/s");
        assert_eq!(duration_text(1_500_000_000), "2s");
        assert_eq!(duration_text(90_000_000_000), "1m30s");
    }

    #[test]
    fn truncation_is_utf8_safe() {
        assert_eq!(truncate("äbcdef", 4), "äbc…");
        assert_eq!(truncate("abc", 4), "abc");
    }

    #[test]
    fn raw_call_shortcuts_are_case_insensitive_and_complete() {
        for shortcut in [
            "deviceinfo",
            "wanip",
            "wanppp",
            "wancommon",
            "hosts",
            "wlan1",
        ] {
            assert!(service_by_shortcut(shortcut).is_some());
            assert!(service_by_shortcut(&shortcut.to_ascii_uppercase()).is_some());
        }
        assert!(service_by_shortcut("unknown").is_none());
    }
}

fn execute_diagnose(args: DiagnoseArgs, format: OutputFormat) -> Result<(), HandlerError> {
    match args.command {
        Some(DiagnoseSubcommand::Router(router)) => execute_diagnose_router(router.ports, format),
        None => {
            let reference = args.host.ok_or_else(|| {
                HandlerError::config("diagnose requires a host or the router subcommand")
            })?;
            let mut client = {
                let (config, password) = load_connection()?;
                make_tr064(&config.box_config, &password)?
            };
            let diagnosis = client.diagnose(
                &reference,
                symfritz_tr064::DiagnoseOptions {
                    ports: custom_probes(args.ports, false),
                    dial_timeout_ms: 2_000,
                },
            );
            render_diagnosis(
                &diagnosis,
                format,
                &format!("Diagnose {}", diagnosis.reference),
            )?;
            if diagnosis.ok {
                Ok(())
            } else {
                Err(HandlerError::operation("host not fully reachable"))
            }
        }
    }
}

fn execute_diagnose_router(ports: Vec<u16>, format: OutputFormat) -> Result<(), HandlerError> {
    let mut config = symfritz_core::config::load_config().map_err(config_error)?;
    let password = resolve(&SecretOptions::from(&config.box_config))
        .map_err(secret_error)?
        .password;
    let configured_host = config.box_config.host.clone();
    let mut detector = SystemDetectionRuntime::new()?;
    let router_host = match std::env::var("SYMFRITZ_HOST") {
        Ok(value) if !value.is_empty() => value,
        _ => discover_box_with(&mut detector, &configured_host)?,
    };
    config.box_config.host = router_host.clone();
    let mut client = make_tr064(&config.box_config, &password)?;
    let diagnosis = client.diagnose(
        &router_host,
        symfritz_tr064::DiagnoseOptions {
            ports: if ports.is_empty() {
                router_probes()
            } else {
                custom_probes(ports, true)
            },
            dial_timeout_ms: 2_000,
        },
    );
    render_diagnosis(
        &diagnosis,
        format,
        &format!("Diagnose router  →  {router_host}"),
    )?;
    if diagnosis.ok {
        Ok(())
    } else {
        Err(HandlerError::operation("router not fully reachable"))
    }
}

fn render_diagnosis(
    diagnosis: &Diagnosis,
    format: OutputFormat,
    title: &str,
) -> Result<(), HandlerError> {
    if format != OutputFormat::Text {
        output::write(&mut std::io::stdout(), diagnosis, format)
            .map_err(|error| HandlerError::operation(error.to_string()))?;
    } else {
        println!("{title}");
        for check in &diagnosis.checks {
            println!(
                "  {} {:<26} {}",
                check_glyph(check.status),
                check.name,
                check.detail
            );
        }
        println!(
            "\nResult: {}",
            if diagnosis.ok {
                "reachable (no failed checks)"
            } else {
                "problems detected"
            }
        );
    }
    Ok(())
}

fn check_glyph(status: symfritz_tr064::CheckStatus) -> &'static str {
    match status {
        symfritz_tr064::CheckStatus::Ok => "✓",
        symfritz_tr064::CheckStatus::Fail => "✗",
        symfritz_tr064::CheckStatus::Warn => "!",
        symfritz_tr064::CheckStatus::Skip => "·",
    }
}

fn custom_probes(ports: Vec<u16>, router: bool) -> Vec<symfritz_tr064::PortProbe> {
    if ports.is_empty() {
        return if router { router_probes() } else { Vec::new() };
    }
    ports
        .into_iter()
        .map(|port| symfritz_tr064::PortProbe {
            port,
            label: String::from("custom"),
            probe_type: String::from("tcp"),
            optional: router,
        })
        .collect()
}

fn router_probes() -> Vec<symfritz_tr064::PortProbe> {
    [
        (49_000, "TR-064 HTTP"),
        (49_443, "TR-064 HTTPS"),
        (80, "web UI HTTP"),
        (443, "web UI HTTPS"),
    ]
    .into_iter()
    .map(|(port, label)| symfritz_tr064::PortProbe {
        port,
        label: label.to_owned(),
        probe_type: String::from("tcp"),
        optional: true,
    })
    .collect()
}

trait DetectionRuntime {
    fn resolve(&mut self, host: &str) -> Vec<IpAddr>;
    fn gateway(&mut self) -> Option<IpAddr>;
    fn probe(&mut self, ip: IpAddr, port: u16) -> bool;
}

struct SystemDetectionRuntime {
    client: reqwest::blocking::Client,
}
impl SystemDetectionRuntime {
    fn new() -> Result<Self, HandlerError> {
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| {
                HandlerError::from_operation("failed to create discovery client", error)
            })?;
        Ok(Self { client })
    }
}
impl DetectionRuntime for SystemDetectionRuntime {
    fn resolve(&mut self, host: &str) -> Vec<IpAddr> {
        if let Ok(ip) = host.parse() {
            return vec![ip];
        }
        (host, 0)
            .to_socket_addrs()
            .map(|addresses| addresses.map(|address| address.ip()).collect())
            .unwrap_or_default()
    }
    fn gateway(&mut self) -> Option<IpAddr> {
        let output = if cfg!(target_os = "macos") {
            ProcessCommand::new("route")
                .args(["-n", "get", "default"])
                .output()
                .ok()
        } else if cfg!(target_os = "windows") {
            ProcessCommand::new("route")
                .args(["print", "-4"])
                .output()
                .ok()
        } else {
            ProcessCommand::new("ip")
                .args(["route", "show", "default"])
                .output()
                .ok()
        }?;
        let text = String::from_utf8_lossy(&output.stdout);
        if cfg!(target_os = "macos") {
            text.lines().find_map(|line| {
                line.trim()
                    .strip_prefix("gateway:")
                    .and_then(|value| value.trim().parse().ok())
            })
        } else if cfg!(target_os = "windows") {
            symfritz_tr064::parse_windows_default_gateway(&text)
        } else {
            symfritz_tr064::parse_linux_default_gateway(&text)
        }
    }
    fn probe(&mut self, ip: IpAddr, port: u16) -> bool {
        let host = match ip {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        };
        let url = format!(
            "{}://{host}:{port}/tr64desc.xml",
            if port == 49_443 { "https" } else { "http" }
        );
        let Ok(response) = self.client.get(url).send() else {
            return false;
        };
        if response.status() != reqwest::StatusCode::OK {
            return false;
        }
        let mut body = Vec::with_capacity(4096);
        if response.take(4096).read_to_end(&mut body).is_err() {
            return false;
        }
        body.windows(b"urn:schemas-upnp-org:device-1-0".len())
            .any(|window| window == b"urn:schemas-upnp-org:device-1-0")
            || body
                .windows(b"urn:dslforum-org:device-1-0".len())
                .any(|window| window == b"urn:dslforum-org:device-1-0")
    }
}

fn discover_box_with<R: DetectionRuntime>(
    runtime: &mut R,
    configured_host: &str,
) -> Result<String, HandlerError> {
    if !configured_host.is_empty() {
        for ip in runtime.resolve(configured_host) {
            if symfritz_tr064::is_private_ip(ip)
                && (runtime.probe(ip, 49_000) || runtime.probe(ip, 49_443))
            {
                return Ok(ip.to_string());
            }
        }
    }
    let gateway = runtime.gateway();
    if let Some(ip) = gateway
        && (runtime.probe(ip, 49_000) || runtime.probe(ip, 49_443))
    {
        return Ok(ip.to_string());
    }
    for candidate in [
        "192.168.178.1",
        "192.168.1.1",
        "192.168.0.1",
        "192.168.188.1",
    ] {
        let ip: IpAddr = candidate.parse().expect("static discovery candidate");
        if Some(ip) != gateway && (runtime.probe(ip, 49_000) || runtime.probe(ip, 49_443)) {
            return Ok(candidate.to_owned());
        }
    }
    let hint = gateway.map_or_else(String::new, |ip| {
        format!(" or set SYMFRITZ_HOST={ip} (your default gateway)")
    });
    Err(HandlerError::operation(format!(
        "discover: could not find a FRITZ!Box on the local network; run 'symfritz detect' to troubleshoot{hint}"
    )))
}

#[derive(Serialize)]
struct DetectOutput {
    host: String,
    ip: String,
    ready: bool,
    #[serde(skip_serializing_if = "is_zero_i32")]
    downstream_max_bit_rate: i32,
    #[serde(skip_serializing_if = "is_zero_i32")]
    upstream_max_bit_rate: i32,
    #[serde(skip_serializing_if = "is_zero_f64")]
    current_downstream_bps: f64,
    #[serde(skip_serializing_if = "is_zero_f64")]
    current_upstream_bps: f64,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    is_reduced_dataset: bool,
}
fn is_zero_i32(value: &i32) -> bool {
    *value == 0
}
fn is_zero_f64(value: &f64) -> bool {
    *value == 0.0
}

fn execute_detect(format: OutputFormat) -> Result<(), HandlerError> {
    let config = match symfritz_core::config::load_config() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("warning: config error: {error}");
            Config::default()
        }
    };
    let configured_host = config.box_config.host;
    let mut runtime = SystemDetectionRuntime::new()?;
    let ip = discover_box_with(&mut runtime, &configured_host)?;
    if format != OutputFormat::Text {
        output::write(
            &mut std::io::stdout(),
            &DetectOutput {
                host: configured_host,
                ip,
                ready: true,
                downstream_max_bit_rate: 0,
                upstream_max_bit_rate: 0,
                current_downstream_bps: 0.0,
                current_upstream_bps: 0.0,
                is_reduced_dataset: false,
            },
            format,
        )
        .map_err(|error| HandlerError::operation(error.to_string()))?;
    } else {
        println!("Detected FRITZ!Box at: {ip}");
        if ip != configured_host {
            println!(
                "Configured host: {configured_host}\n\nSuggested config snippet:\n  [box]\n  host = \"{ip}\""
            );
        }
        println!("\nVerifying connection... ok");
    }
    Ok(())
}

fn execute_mesh(format: OutputFormat) -> Result<(), HandlerError> {
    let (config, password) = load_connection()?;
    let mut tr064 = make_tr064(&config.box_config, &password)?;
    let mut web = make_web(&config.box_config, &password)?;
    let topology = web
        .mesh_topology(&mut tr064)
        .map_err(|error| HandlerError::from_operation("mesh failed", error))?;
    if format != OutputFormat::Text {
        output::write(&mut std::io::stdout(), &topology, format)
            .map_err(|error| HandlerError::operation(error.to_string()))?;
        return Ok(());
    }
    for node in &topology.nodes {
        let role = if node.mesh_role.is_empty() {
            "client"
        } else {
            &node.mesh_role
        };
        println!(
            "● {}  [{}{}]",
            or_dash(&node.device_name),
            role,
            model_suffix(&node.device_model)
        );
        for interface in &node.node_interfaces {
            for link in &interface.node_links {
                if link.state.is_empty() {
                    continue;
                }
                let mut peer = topology.node_name(&link.node_2);
                if peer == node.device_name || peer == link.node_2 {
                    peer = topology.node_name(&link.node_1);
                }
                println!(
                    "    {:<5} {:<9} → {:<20} {}",
                    interface.interface_type,
                    link.state,
                    peer,
                    mesh_data_rate(link)
                );
            }
        }
    }
    Ok(())
}
fn mesh_data_rate(link: &symfritz_tr064::MeshLink) -> String {
    if link.cur_data_rate_rx == 0 && link.cur_data_rate_tx == 0 {
        String::new()
    } else {
        format!(
            "({}/{}) Mbit/s",
            link.cur_data_rate_rx, link.cur_data_rate_tx
        )
    }
}
fn model_suffix(model: &str) -> String {
    if model.trim().is_empty() {
        String::new()
    } else {
        format!(" {model}")
    }
}

fn execute_home(command: HomeCommand, format: OutputFormat) -> Result<(), HandlerError> {
    match command {
        HomeCommand::List(args) => execute_home_list(args, format),
        HomeCommand::Switch(args) => execute_home_switch(args),
        HomeCommand::Temp(args) => execute_home_temp(args),
    }
}

fn execute_home_switch(args: HomeSwitchArgs) -> Result<(), HandlerError> {
    let state = match args.state.to_ascii_lowercase().as_str() {
        "on" => true,
        "off" => false,
        _ => return Err(HandlerError::config("state must be on or off")),
    };
    let (config, password) = load_connection()?;
    if args.tr064 {
        let mut client = make_tr064(&config.box_config, &password)?;
        client
            .homeauto_switch(&args.ain, state)
            .map_err(|error| HandlerError::from_client("switch failed", &error))?;
    } else {
        let mut client = make_web(&config.box_config, &password)?;
        if state {
            client
                .switch_on(&args.ain)
                .map_err(|error| HandlerError::from_aha("switch failed", &error))?;
        } else {
            client
                .switch_off(&args.ain)
                .map_err(|error| HandlerError::from_aha("switch failed", &error))?;
        }
    }
    println!("OK: {} -> {}", args.ain, if state { "on" } else { "off" });
    Ok(())
}

fn execute_home_temp(args: HomeTempArgs) -> Result<(), HandlerError> {
    let value = match args.temperature.to_ascii_lowercase().as_str() {
        "on" => 254.0,
        "off" => 253.0,
        _ => args.temperature.parse::<f64>().map_err(|_| {
            HandlerError::config("temperature must be 'on', 'off', or a number (e.g. 20.5)")
        })?,
    };
    if !value.is_finite() {
        return Err(HandlerError::config(
            "temperature must be 'on', 'off', or a number (e.g. 20.5)",
        ));
    }
    let (config, password) = load_connection()?;
    let mut client = make_web(&config.box_config, &password)?;
    client
        .set_hkr_temp(&args.ain, value)
        .map_err(|error| HandlerError::from_aha("set temp failed", &error))?;
    println!("OK: {} -> {}", args.ain, args.temperature);
    Ok(())
}
fn execute_home_list(args: HomeListArgs, format: OutputFormat) -> Result<(), HandlerError> {
    let (config, password) = load_connection()?;
    if args.tr064 {
        let mut client = make_tr064(&config.box_config, &password)?;
        let devices = client
            .homeauto_devices()
            .map_err(|error| HandlerError::from_client("device list failed", &error))?;
        if format != OutputFormat::Text {
            let values: Vec<_> = devices.iter().map(HomeautoOutput::from).collect();
            output::write(&mut std::io::stdout(), &values, format)
                .map_err(|error| HandlerError::operation(error.to_string()))?;
        } else if devices.is_empty() {
            println!("No TR-064 smart-home devices found.");
        } else {
            println!(
                "{:<16}  {:<24}  {:<16}  VERSION",
                "AIN", "PRODUCT NAME", "MANUFACTURER"
            );
            for device in devices {
                println!(
                    "{:<16}  {:<24}  {:<16}  {}",
                    device.ain,
                    truncate(&device.product_name, 24),
                    truncate(&device.manufacturer, 16),
                    device.firmware_version
                );
            }
        }
        return Ok(());
    }
    let mut web = make_web(&config.box_config, &password)?;
    let devices = web
        .devices()
        .map_err(|error| HandlerError::from_aha("device list failed", &error))?;
    let groups = web.groups().unwrap_or_default();
    if format != OutputFormat::Text {
        let payload = AhaCombinedOutput {
            devices: devices.iter().map(AhaDeviceOutput::from).collect(),
            groups: groups.iter().map(AhaGroupOutput::from).collect(),
        };
        output::write(&mut std::io::stdout(), &payload, format)
            .map_err(|error| HandlerError::operation(error.to_string()))?;
        return Ok(());
    }
    if devices.is_empty() && groups.is_empty() {
        println!("No DECT smart-home actors found.");
        return Ok(());
    }
    if !devices.is_empty() {
        println!(
            "Devices:\n{:<16}  {:<20}  {:<8}  {:<8}  INFO",
            "AIN", "NAME", "STATE", "PRESENT"
        );
        for device in &devices {
            let state = match device.switch.state.as_str() {
                "1" => "on",
                "0" => "off",
                _ => "n/a",
            };
            let present = if device.present == 1 {
                "online"
            } else {
                "offline"
            };
            let mut extra = Vec::new();
            if !device.hkr.tsoll.is_empty() {
                extra.push(format!(
                    "temp: {}°C (target {}°C)",
                    parse_hkr_temp(&device.hkr.tist),
                    parse_hkr_temp(&device.hkr.tsoll)
                ));
                if !device.hkr.battery.is_empty() {
                    extra.push(format!("bat: {}%", device.hkr.battery));
                }
                if device.hkr.windowopenactiv == "1" {
                    extra.push(String::from("window: open"));
                }
                if device.hkr.errorcode != "0" && !device.hkr.errorcode.is_empty() {
                    extra.push(
                        symfritz_aha::hkr_error_description(&device.hkr.errorcode)
                            .unwrap_or("unknown error")
                            .to_owned(),
                    );
                }
            }
            if !device.powermeter.power.is_empty() {
                let power = device.powermeter.power.parse::<f64>().unwrap_or(0.0) / 1000.0;
                let energy = device.powermeter.energy.parse::<f64>().unwrap_or(0.0);
                extra.push(format!("power: {power:.2}W (total {energy:.1}Wh)"));
            }
            let info = if extra.is_empty() {
                String::new()
            } else {
                format!("({})", extra.join(", "))
            };
            println!(
                "{:<16}  {:<20}  {:<8}  {:<8}  {}",
                device.identifier,
                truncate(&device.name, 20),
                state,
                present,
                info
            );
        }
    }
    if !groups.is_empty() {
        println!("\nGroups:\n{:<16}  {:<20}  MEMBERS", "AIN", "NAME");
        for group in groups {
            println!(
                "{:<16}  {:<20}  {}",
                group.identifier,
                truncate(&group.name, 20),
                group.members.join(", ")
            );
        }
    }
    Ok(())
}
fn parse_hkr_temp(value: &str) -> String {
    let Ok(value) = value.parse::<i32>() else {
        return String::from("—");
    };
    match value {
        254 => String::from("ON"),
        253 => String::from("OFF"),
        value => format!("{:.1}", value as f64 / 2.0),
    }
}

#[derive(Serialize)]
struct HomeautoOutput<'a> {
    #[serde(rename = "AIN")]
    ain: &'a str,
    #[serde(rename = "FunctionBitMask")]
    function_bit_mask: i32,
    #[serde(rename = "Manufacturer")]
    manufacturer: &'a str,
    #[serde(rename = "ProductName")]
    product_name: &'a str,
    #[serde(rename = "FirmwareVersion")]
    firmware_version: &'a str,
}
impl<'a> From<&'a symfritz_tr064::HomeautoDevice> for HomeautoOutput<'a> {
    fn from(value: &'a symfritz_tr064::HomeautoDevice) -> Self {
        Self {
            ain: &value.ain,
            function_bit_mask: value.function_bit_mask,
            manufacturer: &value.manufacturer,
            product_name: &value.product_name,
            firmware_version: &value.firmware_version,
        }
    }
}

#[derive(Serialize)]
struct AhaCombinedOutput {
    devices: Vec<AhaDeviceOutput>,
    groups: Vec<AhaGroupOutput>,
}
#[derive(Serialize)]
struct AhaDeviceOutput {
    #[serde(rename = "Identifier")]
    identifier: String,
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Present")]
    present: i32,
    #[serde(rename = "Switch")]
    switch: AhaSwitchOutput,
    #[serde(rename = "Temperature")]
    temperature: AhaTemperatureOutput,
    #[serde(rename = "Hkr")]
    hkr: AhaHkrOutput,
    #[serde(rename = "PowerMeter")]
    power_meter: AhaPowerOutput,
}
#[derive(Serialize)]
struct AhaSwitchOutput {
    #[serde(rename = "State")]
    state: String,
}
#[derive(Serialize)]
struct AhaTemperatureOutput {
    #[serde(rename = "Celsius")]
    celsius: String,
}
#[derive(Serialize)]
struct AhaHkrOutput {
    #[serde(rename = "Tist")]
    tist: String,
    #[serde(rename = "Tsoll")]
    tsoll: String,
    #[serde(rename = "BatteryLow")]
    battery_low: String,
    #[serde(rename = "BatteryCharge")]
    battery_charge: String,
    #[serde(rename = "WindowOpen")]
    window_open: String,
    #[serde(rename = "ErrorCode")]
    error_code: String,
    #[serde(rename = "NextChange")]
    next_change: AhaNextChangeOutput,
}
#[derive(Serialize)]
struct AhaNextChangeOutput {
    #[serde(rename = "End")]
    end: String,
    #[serde(rename = "Start")]
    start: String,
    #[serde(rename = "TChange")]
    t_change: i32,
}
#[derive(Serialize)]
struct AhaPowerOutput {
    #[serde(rename = "Power")]
    power: String,
    #[serde(rename = "Energy")]
    energy: String,
}
impl From<&AhaDevice> for AhaDeviceOutput {
    fn from(value: &AhaDevice) -> Self {
        Self {
            identifier: value.identifier.clone(),
            id: value.id.clone(),
            name: value.name.clone(),
            present: value.present,
            switch: AhaSwitchOutput {
                state: value.switch.state.clone(),
            },
            temperature: AhaTemperatureOutput {
                celsius: value.temperature.celsius.clone(),
            },
            hkr: AhaHkrOutput {
                tist: value.hkr.tist.clone(),
                tsoll: value.hkr.tsoll.clone(),
                battery_low: value.hkr.batterylow.clone(),
                battery_charge: value.hkr.battery.clone(),
                window_open: value.hkr.windowopenactiv.clone(),
                error_code: value.hkr.errorcode.clone(),
                next_change: AhaNextChangeOutput {
                    end: value.hkr.nextchange.end.clone(),
                    start: value.hkr.nextchange.start.clone(),
                    t_change: value.hkr.nextchange.tchange,
                },
            },
            power_meter: AhaPowerOutput {
                power: value.powermeter.power.clone(),
                energy: value.powermeter.energy.clone(),
            },
        }
    }
}
#[derive(Serialize)]
struct AhaGroupOutput {
    #[serde(rename = "Identifier")]
    identifier: String,
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Members")]
    members: Vec<String>,
    #[serde(rename = "GroupInfo")]
    group_info: AhaGroupInfoOutput,
}
#[derive(Serialize)]
struct AhaGroupInfoOutput {
    #[serde(rename = "MasterDeviceID")]
    master_device_id: String,
    #[serde(rename = "MembersStr")]
    members_str: String,
}
impl From<&AhaGroup> for AhaGroupOutput {
    fn from(value: &AhaGroup) -> Self {
        Self {
            identifier: value.identifier.clone(),
            id: value.id.clone(),
            name: value.name.clone(),
            members: value.members.clone(),
            group_info: AhaGroupInfoOutput {
                master_device_id: value.master_device_id.clone(),
                members_str: value.members.join(","),
            },
        }
    }
}

fn execute_scrape(args: ScrapeArgs) -> Result<(), HandlerError> {
    let mut params = BTreeMap::new();
    for argument in args.arguments {
        let Some((key, value)) = argument.split_once('=') else {
            return Err(HandlerError::config(format!(
                "bad argument: argument {argument:?} is not Key=Value"
            )));
        };
        params
            .entry(key.to_owned())
            .or_insert_with(Vec::new)
            .push(value.to_owned());
    }
    let (config, password) = load_connection()?;
    let mut client = make_web(&config.box_config, &password)?;
    let raw = client
        .scrape_data_lua(&args.page, &params)
        .map_err(|error| HandlerError::operation(format!("scrape failed: {error}")))?;
    println!("{raw}");
    Ok(())
}

#[derive(Default, Serialize)]
struct DoctorReport {
    config_path: String,
    host: String,
    checks: Vec<DoctorCheck>,
    healthy: bool,
}
#[derive(Serialize)]
struct DoctorCheck {
    name: String,
    status: String,
    detail: String,
}
fn execute_doctor(format: OutputFormat) -> Result<(), HandlerError> {
    let config_path = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .map(|home| symfritz_core::config::default_config_path(&home))
        .unwrap_or_else(|| std::path::PathBuf::from(".config/symfritz/config.toml"));
    let mut report = DoctorReport {
        config_path: config_path.display().to_string(),
        healthy: true,
        ..DoctorReport::default()
    };
    let config_missing = matches!(
        std::fs::metadata(&config_path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    );
    let mut add = |name: &str, status: &str, detail: String| {
        if status == "fail" {
            report.healthy = false;
        }
        report.checks.push(DoctorCheck {
            name: name.to_owned(),
            status: status.to_owned(),
            detail,
        });
    };
    match std::fs::metadata(&config_path) {
        Ok(metadata) if metadata.is_dir() => {
            add("config file", "fail", String::from("path is a directory"))
        }
        Ok(_) => add("config file", "ok", report.config_path.clone()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => add(
            "config file",
            "fail",
            String::from("not found; run 'symfritz config init'"),
        ),
        Err(error) => add(
            "config file",
            "fail",
            format!("cannot inspect configuration file: {error}"),
        ),
    }
    let mut config = match symfritz_core::config::load_config() {
        Ok(config) => {
            if config_missing {
                add(
                    "config parse",
                    "skip",
                    String::from("not checked because the config file is missing"),
                );
            } else {
                add("config parse", "ok", String::from("configuration is valid"));
            }
            config
        }
        Err(error) => {
            add(
                "config parse",
                "fail",
                format!("configuration is not parseable: {error}"),
            );
            Config::default()
        }
    };
    if let Ok(host) = std::env::var("SYMFRITZ_HOST")
        && !host.is_empty()
    {
        config.box_config.host = host;
    }
    if let Ok(user) = std::env::var("SYMFRITZ_USER")
        && !user.is_empty()
    {
        config.box_config.user = user;
    }
    report.host = config.box_config.host.clone();
    let credential = match resolve(&SecretOptions::from(&config.box_config)) {
        Ok(result) if result.source != CredentialSource::None && !result.password.is_empty() => {
            add(
                "credentials",
                "ok",
                format!("resolved from {}", result.source),
            );
            Some(result.password)
        }
        Ok(_) => {
            add(
                "credentials",
                "fail",
                String::from("no credential resolved; run 'symfritz auth login'"),
            );
            None
        }
        Err(error) => {
            add(
                "credentials",
                "fail",
                format!("credential resolution failed: {error}"),
            );
            None
        }
    };
    let (mut discovery_ok, mut session_ok) = (false, false);
    if let Some(password) = credential {
        let mut tr064 = make_tr064(&config.box_config, &password)?;
        match tr064.discover() {
            Ok(services) => {
                discovery_ok = true;
                add(
                    "box reachable",
                    "ok",
                    String::from("TR-064 service description responded"),
                );
                if services.is_empty() {
                    add(
                        "TR-064 enabled",
                        "fail",
                        String::from("no services advertised"),
                    );
                } else {
                    add(
                        "TR-064 enabled",
                        "ok",
                        format!("{} service(s) advertised", services.len()),
                    );
                }
            }
            Err(error) => {
                add(
                    "box reachable",
                    "fail",
                    format!("TR-064 discovery request failed: {error}"),
                );
                add(
                    "TR-064 enabled",
                    "fail",
                    format!("service description unavailable: {error}"),
                );
            }
        }
        let mut web = make_web(&config.box_config, &password)?;
        match web.sid() {
            Ok(_) => {
                session_ok = true;
                add("session login", "ok", String::from("session established"));
            }
            Err(error) => add(
                "session login",
                "fail",
                format!("FRITZ!Box session login failed: {error}"),
            ),
        }
        if discovery_ok && session_ok {
            match web.devices() {
                Ok(devices) if !devices.is_empty() => add(
                    "AHA endpoint",
                    "ok",
                    format!("{} actor(s) reachable", devices.len()),
                ),
                Ok(_) => add(
                    "AHA endpoint",
                    "skip",
                    String::from("no smart-home actors reported"),
                ),
                Err(_) => add(
                    "AHA endpoint",
                    "skip",
                    String::from("no smart-home actors configured or endpoint unavailable"),
                ),
            }
        } else {
            add(
                "AHA endpoint",
                "skip",
                String::from("requires a reachable box and successful session login"),
            );
        }
    } else {
        add(
            "box reachable",
            "skip",
            String::from("requires resolved credentials"),
        );
        add(
            "TR-064 enabled",
            "skip",
            String::from("requires a reachable box"),
        );
        add(
            "session login",
            "skip",
            String::from("requires resolved credentials"),
        );
        add(
            "AHA endpoint",
            "skip",
            String::from("requires a reachable box and successful session login"),
        );
    }
    if format == OutputFormat::Text {
        println!("symfritz doctor ({})", report.host);
        for check in &report.checks {
            let glyph = match check.status.as_str() {
                "ok" => "✓",
                "fail" => "✗",
                _ => "·",
            };
            println!("  {glyph} {:<18} {}", check.name, check.detail);
        }
        println!(
            "\nResult: {}",
            if report.healthy {
                "healthy"
            } else {
                "problems detected"
            }
        );
    } else {
        output::write(&mut std::io::stdout(), &report, format)
            .map_err(|error| HandlerError::operation(error.to_string()))?;
    }
    if report.healthy {
        Ok(())
    } else {
        let mut error = HandlerError::operation("doctor found failing checks");
        error.status = true;
        Err(error)
    }
}

fn execute_version(args: VersionArgs, format: OutputFormat) -> Result<(), HandlerError> {
    print!("{}", render_version(format, VERSION));
    if format == OutputFormat::Text && args.check {
        match check_for_update(VERSION) {
            Ok(Some(release)) => println!(
                "Update available: {}\nDownload: {}",
                release.tag_name, release.html_url
            ),
            Ok(None) => println!("Already up to date."),
            Err(error) => eprintln!("update check failed: {error}"),
        }
    }
    Ok(())
}
#[derive(Deserialize)]
struct LatestRelease {
    tag_name: String,
    html_url: String,
    draft: bool,
    prerelease: bool,
}
fn check_for_update(current: &str) -> Result<Option<LatestRelease>, String> {
    let Some(current) = parse_stable_version(current) else {
        return Ok(None);
    };
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .get("https://api.github.com/repos/danieljustus/symaira-fritz/releases/latest")
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", format!("symfritz-updatecheck/{VERSION}"))
        .send()
        .map_err(|error| error.to_string())?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!("GitHub API returned HTTP {}", response.status()));
    }
    let mut body = Vec::new();
    response
        .take(1 << 20)
        .read_to_end(&mut body)
        .map_err(|error| error.to_string())?;
    let release: LatestRelease = serde_json::from_slice(&body)
        .map_err(|error| format!("decode latest release response: {error}"))?;
    if release.draft {
        return Err(String::from(
            "latest release response returned a draft release",
        ));
    }
    if release.prerelease {
        return Err(String::from(
            "latest release response returned a prerelease",
        ));
    }
    let latest = parse_stable_version(&release.tag_name).ok_or_else(|| {
        format!(
            "latest release tag {:?} is not a stable semantic version",
            release.tag_name
        )
    })?;
    if latest > current && !(current.0 == 0 && latest.0 > 0) {
        Ok(Some(release))
    } else {
        Ok(None)
    }
}
fn parse_stable_version(raw: &str) -> Option<(u64, u64, u64)> {
    let raw = raw.trim();
    if raw.is_empty() || raw.contains(['-', '+']) {
        return None;
    }
    let raw = raw.strip_prefix('v').unwrap_or(raw);
    let mut parts = raw.split('.');
    Some((
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ))
}

fn execute_completion(command: CompletionCommand) -> Result<(), HandlerError> {
    let mut root = Cli::command();
    match command {
        CompletionCommand::Bash(args) => {
            if args.no_descriptions {
                strip_command_descriptions(&mut root);
            }
            generate(shells::Bash, &mut root, "symfritz", &mut std::io::stdout());
        }
        CompletionCommand::Fish(args) => {
            if args.no_descriptions {
                strip_command_descriptions(&mut root);
            }
            generate(shells::Fish, &mut root, "symfritz", &mut std::io::stdout());
        }
        CompletionCommand::Powershell(args) => {
            if args.no_descriptions {
                strip_command_descriptions(&mut root);
            }
            generate(
                shells::PowerShell,
                &mut root,
                "symfritz",
                &mut std::io::stdout(),
            );
        }
        CompletionCommand::Zsh(args) => {
            if args.no_descriptions {
                strip_command_descriptions(&mut root);
            }
            generate(shells::Zsh, &mut root, "symfritz", &mut std::io::stdout());
        }
    }
    Ok(())
}
fn strip_command_descriptions(command: &mut clap::Command) {
    *command = std::mem::take(command)
        .about(Option::<&str>::None)
        .long_about(Option::<&str>::None);
    for child in command.get_subcommands_mut() {
        strip_command_descriptions(child);
    }
}

#[cfg(test)]
mod mcp_output_tests {
    use super::*;

    fn render(value: serde_json::Value) -> String {
        symfritz_mcp::to_json(&value).unwrap()
    }

    #[test]
    fn production_backend_models_match_go_to_json_names_and_bytes() {
        let status = Status {
            model_name: "FRITZ!Box 7590".to_owned(),
            firmware_version: "7.57".to_owned(),
            external_ip: "203.0.113.1".to_owned(),
            connection_state: "Connected".to_owned(),
            uptime: "3600".to_owned(),
            update_available: String::new(),
            partial: false,
            errors: Vec::new(),
        };
        assert_eq!(
            render(mcp_status_value(&status)),
            "{\n  \"ModelName\": \"FRITZ!Box 7590\",\n  \"FirmwareVersion\": \"7.57\",\n  \"ExternalIP\": \"203.0.113.1\",\n  \"ConnectionState\": \"Connected\",\n  \"Uptime\": \"3600\",\n  \"UpdateAvailable\": \"\",\n  \"Partial\": false,\n  \"Errors\": null\n}"
        );

        let host = Host {
            name: "my-host".to_owned(),
            ip: "192.168.178.20".to_owned(),
            mac: "00:11:22:33:44:55".to_owned(),
            active: true,
            interface_type: "Ethernet".to_owned(),
            address_source: "DHCP".to_owned(),
            lease_time_remaining: 120,
        };
        assert_eq!(
            render(mcp_serialized(&host)),
            "{\n  \"name\": \"my-host\",\n  \"ip\": \"192.168.178.20\",\n  \"mac\": \"00:11:22:33:44:55\",\n  \"active\": true,\n  \"interface_type\": \"Ethernet\",\n  \"address_source\": \"DHCP\",\n  \"lease_time_remaining\": 120\n}"
        );

        let diagnosis = Diagnosis {
            reference: "my-host".to_owned(),
            host: Some(host),
            target: "192.168.178.20".to_owned(),
            checks: vec![symfritz_tr064::Check {
                name: "Host active".to_owned(),
                status: symfritz_tr064::CheckStatus::Ok,
                detail: String::new(),
            }],
            ok: true,
        };
        assert_eq!(
            render(mcp_serialized(&diagnosis)),
            "{\n  \"ref\": \"my-host\",\n  \"host\": {\n    \"name\": \"my-host\",\n    \"ip\": \"192.168.178.20\",\n    \"mac\": \"00:11:22:33:44:55\",\n    \"active\": true,\n    \"interface_type\": \"Ethernet\",\n    \"address_source\": \"DHCP\",\n    \"lease_time_remaining\": 120\n  },\n  \"target\": \"192.168.178.20\",\n  \"checks\": [\n    {\n      \"name\": \"Host active\",\n      \"status\": \"ok\"\n    }\n  ],\n  \"ok\": true\n}"
        );

        let mesh = symfritz_tr064::MeshTopology {
            schema_version: "1".to_owned(),
            nodes: Vec::new(),
        };
        assert_eq!(
            render(mcp_serialized(&mesh)),
            "{\n  \"schema_version\": \"1\",\n  \"nodes\": []\n}"
        );
        let wlan = WlanClient {
            radio_index: 1,
            mac: "00:11:22:33:44:55".to_owned(),
            ip: "192.168.178.20".to_owned(),
            signal: "80".to_owned(),
            speed: "866".to_owned(),
            authorized: true,
        };
        assert_eq!(
            render(mcp_serialized(&vec![wlan])),
            "[\n  {\n    \"radio_index\": 1,\n    \"mac\": \"00:11:22:33:44:55\",\n    \"ip\": \"192.168.178.20\",\n    \"signal_strength\": \"80\",\n    \"speed\": \"866\",\n    \"authorized\": true\n  }\n]"
        );

        assert_eq!(
            render(serde_json::json!({"woke": "00:11:22:33:44:55"})),
            "{\n  \"woke\": \"00:11:22:33:44:55\"\n}"
        );
        assert_eq!(
            render(serde_json::json!({"ain": "123", "on": true})),
            "{\n  \"ain\": \"123\",\n  \"on\": true\n}"
        );
    }

    #[test]
    fn aha_device_output_uses_exported_go_field_names_recursively() {
        let device = AhaDevice {
            identifier: "123".to_owned(),
            id: "dev-1".to_owned(),
            name: "Switch 1".to_owned(),
            present: 1,
            switch: symfritz_aha::Switch {
                state: "1".to_owned(),
            },
            temperature: symfritz_aha::Temperature {
                celsius: "215".to_owned(),
            },
            hkr: symfritz_aha::Hkr {
                tist: "42".to_owned(),
                tsoll: "44".to_owned(),
                batterylow: "0".to_owned(),
                battery: "90".to_owned(),
                windowopenactiv: "0".to_owned(),
                errorcode: "0".to_owned(),
                nextchange: symfritz_aha::NextChange {
                    end: "0".to_owned(),
                    start: "0".to_owned(),
                    tchange: 0,
                },
            },
            powermeter: symfritz_aha::PowerMeter {
                power: "1500".to_owned(),
                energy: "100".to_owned(),
            },
        };
        let rendered = render(serde_json::to_value(AhaDeviceOutput::from(&device)).unwrap());
        assert!(rendered.contains("\"Identifier\": \"123\""));
        assert!(rendered.contains("\"PowerMeter\": {"));
        assert!(rendered.contains("\"NextChange\": {"));
        assert!(!rendered.contains("identifier"));
        assert!(!rendered.contains("power_meter"));
    }
}

#[cfg(test)]
mod signal_tests {
    use super::{CANCEL_REQUESTED, Duration, Ordering, wait_for_interval};

    #[test]
    fn cancellation_cooperatively_interrupts_watch_interval() {
        CANCEL_REQUESTED.store(true, Ordering::SeqCst);
        assert!(wait_for_interval(Duration::from_secs(5)));
        CANCEL_REQUESTED.store(false, Ordering::SeqCst);
    }
}
