#![deny(unsafe_code)]

use std::{collections::BTreeMap, fmt::Display, process::ExitCode};

use clap::{CommandFactory, Parser};
use serde::Serialize;
use symfritz_aha::{Client as AhaClient, SystemClock};
use symfritz_cli::{
    OutputFormat, TOOL,
    cli::{
        CallArgs, CallsArgs, Cli, Command, HostGetArgs, LogArgs, StatusArgs, TrafficArgs,
        WlanSubcommand,
    },
    output, render_version, resolve_output_format,
};
use symfritz_core::{
    PinStore,
    config::{BoxConfig, Config, ConfigError},
    secret::{CredentialSource, SecretError, SecretOptions, resolve},
};
use symfritz_tr064::{
    BlockingHttpTransport, Call as TrCall, Client as Tr064Client, CnonceSource, DslLineStats,
    ErrorKind, Host, HttpTransportConfig, LogEvent, Radio, Service, Status, StatusFailure,
    TrafficData, WlanClient,
};
use url::Url;

const VERSION: &str = match option_env!("SYMFRITZ_VERSION") {
    Some(version) => version,
    None => "dev",
};
const EXIT_CONFIG: u8 = 9;
const EXIT_OPERATION: u8 = 1;

#[derive(Debug)]
struct HandlerError {
    message: String,
    config: bool,
    kind: String,
    status: bool,
}

impl HandlerError {
    fn operation(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            config: false,
            kind: "unavailable".to_owned(),
            status: false,
        }
    }

    fn config(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            config: true,
            kind: "validation".to_owned(),
            status: false,
        }
    }

    fn from_operation(context: &str, error: impl Display) -> Self {
        let message = format!("{context}: {error}");
        Self {
            message,
            config: false,
            kind: "unavailable".to_owned(),
            status: false,
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
        Self {
            message: format!("{context}: {error}"),
            config: false,
            kind: kind.to_owned(),
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
    let cli = Cli::parse();
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
            if format != OutputFormat::Text && !error.config && !error.status {
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
            }
            if error.config {
                ExitCode::from(EXIT_CONFIG)
            } else {
                ExitCode::from(EXIT_OPERATION)
            }
        }
    }
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
        Some(Command::Version(_)) => {
            print!("{}", render_version(format, VERSION));
            Ok(())
        }
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
        Some(command) => Err(HandlerError::operation(format!(
            "internal handler for '{}' is not implemented",
            command_name(&command)
        ))),
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
    command
        .print_help()
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
            symfritz_cli::cli::WlanGuestCommand::Status => {
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
            symfritz_cli::cli::WlanGuestCommand::On | symfritz_cli::cli::WlanGuestCommand::Off => {
                Err(HandlerError::operation(
                    "internal handler for WLAN mutation is not implemented",
                ))
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
    if args.watch {
        return Err(HandlerError::operation(
            "traffic watch is not implemented in this read-only slice",
        ));
    }
    let (config, password) = load_connection()?;
    let mut client = make_tr064(&config.box_config, &password)?;
    let stats = client
        .online_monitor()
        .map_err(|error| HandlerError::from_client("traffic failed", &error))?;
    if format != OutputFormat::Text {
        output::write(&mut std::io::stdout(), &stats, format)
            .map_err(|error| HandlerError::operation(error.to_string()))?;
    } else {
        print_traffic(&stats);
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

fn load_connection() -> Result<(Config, String), HandlerError> {
    let config = symfritz_core::config::load_config().map_err(config_error)?;
    let result = resolve(&SecretOptions::from(&config.box_config)).map_err(secret_error)?;
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
    let (scheme, port) = if box_config.use_tls {
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
    Url::parse(&format!("{scheme}://{host}:{port}"))
        .map_err(|error| HandlerError::config(format!("invalid configured box origin: {error}")))
}

fn config_error(error: ConfigError) -> HandlerError {
    HandlerError::config(error.to_string())
}
fn secret_error(error: SecretError) -> HandlerError {
    HandlerError::config(format!("could not resolve password: {error}"))
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Auth(_) => "auth",
        Command::Call(_) => "call",
        Command::Calls(_) => "calls",
        Command::Completion(_) => "completion",
        Command::Config(_) => "config",
        Command::Detect(_) => "detect",
        Command::Diagnose(_) => "diagnose",
        Command::Dial(_) => "dial",
        Command::Doctor => "doctor",
        Command::Dsl(_) => "dsl",
        Command::Hangup => "hangup",
        Command::Help(_) => "help",
        Command::Home(_) => "home",
        Command::Hosts(_) => "hosts",
        Command::Log(_) => "log",
        Command::Mcp => "mcp",
        Command::Mesh(_) => "mesh",
        Command::Reboot(_) => "reboot",
        Command::Scrape(_) => "scrape",
        Command::Services(_) => "services",
        Command::Status(_) => "status",
        Command::Traffic(_) => "traffic",
        Command::Version(_) => "version",
        Command::Wlan(_) => "wlan",
        Command::Wol(_) => "wol",
    }
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
