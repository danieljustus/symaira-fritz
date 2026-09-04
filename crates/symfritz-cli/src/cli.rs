#![deny(unsafe_code)]

//! Complete clap command tree for the `symfritz` CLI.
//!
//! This module owns parsing and help metadata only. Network, credential, MCP,
//! and filesystem handlers belong to later port slices.

use clap::{Args, CommandFactory, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "symfritz",
    bin_name = "symfritz",
    about = "Administer, analyse, and control an AVM FRITZ!Box",
    long_about = "symfritz talks to a FRITZ!Box over its documented interfaces:\n\n  TR-064  (SOAP)  administration: status, WAN/IP, WLAN, hosts, mesh, reboot\n  AHA-HTTP        DECT smart-home actors (switches, thermostats)\n  Session login   for AHA and (later) web-UI data scraping\n\nConfigure the box once with 'symfritz config init', then set the password via\nthe SYMFRITZ_PASSWORD environment variable.",
    disable_version_flag = true,
    disable_help_subcommand = true,
    propagate_version = false
)]
pub struct Cli {
    #[arg(
        long,
        global = true,
        default_value = "text",
        help = "Output format: text|json|yaml (--json is shorthand for --output json)"
    )]
    pub output: String,

    #[arg(
        long,
        global = true,
        help = "Output as JSON (shorthand for --output json)"
    )]
    pub json: bool,

    #[arg(
        short = 'v',
        long = "version",
        global = true,
        help = "version for symfritz"
    )]
    pub show_version: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Manage FRITZ!Box credentials (test, login, store)")]
    Auth(AuthCommand),
    #[command(
        about = "Invoke a raw TR-064 action (power user)",
        long_about = "Invoke any TR-064 action by service shortcut and action name.\n\nKnown shortcuts: deviceinfo, wanip, wanppp, wancommon, hosts, wlan1. Any other service\nname is resolved via tr64desc.xml discovery (e.g. \"WLANConfiguration:2\").\nArguments are passed as Key=Value pairs (TR-064 input arguments).\n\nExamples:\n  symfritz call deviceinfo GetInfo\n  symfritz call wanip GetExternalIPAddress\n  symfritz call hosts GetGenericHostEntry NewIndex=0"
    )]
    Call(CallArgs),
    #[command(about = "Show FRITZ!Box call list")]
    Calls(CallsArgs),
    #[command(about = "Generate the autocompletion script for the specified shell")]
    #[command(subcommand)]
    Completion(CompletionCommand),
    #[command(about = "Manage symfritz configuration")]
    #[command(subcommand)]
    Config(ConfigCommand),
    #[command(
        about = "Detect the local FRITZ!Box on the network",
        long_about = "Detect attempts to find a FRITZ!Box on the local network by:\n  1. Checking if the configured host resolves to a private IP\n  2. Probing the system default gateway\n  3. Trying common FRITZ!Box default IPs\n\nThis is useful when 'fritz.box' resolves to a public IP instead of your local\nFRITZ!Box, causing connection timeouts."
    )]
    Detect(FormatArgs),
    #[command(
        about = "End-to-end reachability check for a host (name, MAC, or IP)",
        long_about = "Diagnose resolves a host via the FRITZ!Box host table, then checks it\nend-to-end from this machine: is it known, active, on LAN or WLAN, does its name\nresolve via DNS, and are the relevant TCP ports reachable.\n\nDefault ports probed: 22 (SSH), 5900 (VNC/Screen Sharing), 8001 (Paperless).\nOverride with --port (repeatable)."
    )]
    Diagnose(DiagnoseArgs),
    #[command(about = "Instruct the FRITZ!Box to dial a phone number")]
    Dial(OneArg),
    #[command(
        about = "Check symfritz configuration, credentials, and box connectivity",
        long_about = "Check the local symfritz setup and its FRITZ!Box connection.\n\nThe command verifies the global config file, credential resolution, TR-064\nservice discovery, and session login. Smart-home availability is probed when\nthe authenticated AHA endpoint reports actors."
    )]
    Doctor,
    #[command(about = "Show DSL line statistics (noise margin, attenuation, max bit rate)")]
    Dsl(FormatArgs),
    #[command(about = "Hang up any active call initiated by dial")]
    Hangup,
    #[command(about = "Help about any command")]
    Help(HelpArgs),
    #[command(about = "DECT smart-home actors (switches, thermostats)")]
    #[command(subcommand)]
    Home(HomeCommand),
    #[command(about = "FRITZ!Box host table (LAN/WLAN devices)")]
    #[command(subcommand)]
    Hosts(HostsCommand),
    #[command(about = "Show FRITZ!Box system event log")]
    Log(LogArgs),
    #[command(
        name = "mcp",
        visible_alias = "serve",
        about = "Start the MCP stdio server",
        long_about = "Start a JSON-RPC 2.0 MCP server over stdin/stdout for use with AI agents."
    )]
    Mcp,
    #[command(about = "Show the mesh topology (nodes, repeaters, links)")]
    Mesh(FormatArgs),
    #[command(about = "Reboot the FRITZ!Box")]
    Reboot(RebootArgs),
    #[command(
        about = "Fetch a data.lua page (best-effort, fragile)",
        long_about = "Fetch raw JSON from the FRITZ!Box internal data.lua endpoint.\n\nWARNING: This is a best-effort, version-fragile API.\nAVM frequently changes the data.lua structure, endpoints, and variables\nacross FRITZ!OS updates. Use TR-064 or AHA whenever possible instead.\n\nArguments are passed as Key=Value POST parameters.\n\nExamples:\n  symfritz scrape netDev\n  symfritz scrape dslStats"
    )]
    Scrape(ScrapeArgs),
    #[command(about = "Discover TR-064 services advertised by the box (tr64desc.xml)")]
    Services(FormatArgs),
    #[command(
        about = "Show a box overview (model, firmware, connection, external IP, CPU temperature)"
    )]
    Status(StatusArgs),
    #[command(
        about = "Show WAN traffic statistics",
        long_about = "Show downstream/upstream traffic by category. When --watch is set,\nre-poll and append snapshots at the configured --interval until Ctrl-C.\nIn JSON mode (--json or --output json), --watch streams one compact JSON object\nper line (NDJSON).\n\nExamples:\n  symfritz traffic                     # one-shot snapshot\n  symfritz traffic --watch             # append snapshots periodically (exits on Ctrl-C)\n  symfritz traffic --watch --json      # stream NDJSON objects (one per line)\n  symfritz traffic --watch --interval 5s"
    )]
    Traffic(TrafficArgs),
    #[command(about = "Print version")]
    Version(VersionArgs),
    #[command(about = "WLAN radios, clients, and guest network")]
    Wlan(WlanCommand),
    #[command(
        about = "Send a Wake-on-LAN packet via the FRITZ!Box",
        long_about = "Wake a host by name/IP (resolved via the host table) or by explicit --mac."
    )]
    Wol(WolArgs),
}

#[derive(Debug, Args)]
pub struct AuthCommand {
    #[command(subcommand)]
    pub command: Option<AuthSubcommand>,
}

#[derive(Debug, Subcommand)]
pub enum AuthSubcommand {
    #[command(about = "Prompt for the password, verify it, and store it securely")]
    Login(AuthStoreArgs),
    #[command(about = "Store a password (from prompt or SYMFRITZ_PASSWORD) without verifying")]
    Store(AuthStoreArgs),
    #[command(about = "Resolve the password and verify it against the box")]
    Test,
    #[command(
        about = "Manage trusted TLS certificate pins (TOFU)",
        long_about = "Display or reset trusted host TLS public key pins."
    )]
    Trust(TrustArgs),
}

#[derive(Debug, Args)]
pub struct AuthStoreArgs {
    #[arg(long, help = "Store in the macOS Keychain (default on macOS)")]
    pub keychain: bool,
    #[arg(
        long,
        help = "Store in symvault at this entry path (e.g. fritz.password)"
    )]
    pub symvault: Option<String>,
}

#[derive(Debug, Args)]
pub struct TrustArgs {
    #[arg(long, help = "Reset the pinned TLS certificate for the specified host")]
    pub reset: Option<String>,
}

#[derive(Debug, Args)]
pub struct CallArgs {
    #[arg(value_name = "service")]
    pub service: String,
    #[arg(value_name = "action")]
    pub action: String,
    #[arg(
        value_name = "Key=Value",
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 0..
    )]
    pub arguments: Vec<String>,
}

#[derive(Debug, Args)]
pub struct CallsArgs {
    #[arg(
        long,
        default_value = "all",
        help = "Filter by type (incoming, missed, outgoing, rejected, all)"
    )]
    pub call_type: String,
    #[arg(long, help = "Limit to calls in the last N days")]
    pub days: Option<i32>,
    #[arg(long, help = "Limit the number of returned calls")]
    pub limit: Option<i32>,
}

#[derive(Debug, Subcommand)]
pub enum CompletionCommand {
    #[command(about = "Generate the autocompletion script for bash")]
    Bash(CompletionArgs),
    #[command(about = "Generate the autocompletion script for fish")]
    Fish(CompletionArgs),
    #[command(about = "Generate the autocompletion script for powershell")]
    Powershell(CompletionArgs),
    #[command(about = "Generate the autocompletion script for zsh")]
    Zsh(CompletionArgs),
}

#[derive(Debug, Args)]
pub struct CompletionArgs {
    #[arg(long, help = "disable completion descriptions")]
    pub no_descriptions: bool,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    #[command(about = "Detect the local FRITZ!Box on the network")]
    Detect(FormatArgs),
    #[command(about = "Write default config to ~/.config/symfritz/config.toml")]
    Init(InitArgs),
}

#[derive(Debug, Args)]
pub struct InitArgs {
    #[arg(long, help = "overwrite existing config file")]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct FormatArgs {}

#[derive(Debug, Args)]
pub struct DiagnoseArgs {
    #[arg(value_name = "host")]
    pub host: Option<String>,
    #[arg(
        long = "port",
        value_name = "port",
        value_delimiter = ',',
        num_args = 1..,
        help = "TCP port to probe (repeatable; replaces default ports 22, 5900, 8001)"
    )]
    pub ports: Vec<u16>,
    #[command(subcommand)]
    pub command: Option<DiagnoseSubcommand>,
}

#[derive(Debug, Subcommand)]
pub enum DiagnoseSubcommand {
    #[command(
        about = "Detect and diagnose the local FRITZ!Box router",
        long_about = "Detect the local FRITZ!Box and run end-to-end diagnosis on it.\n\nWhen SYMFRITZ_HOST is set, skips discovery and diagnoses that explicit host\ndirectly."
    )]
    Router(RouterDiagnoseArgs),
}

#[derive(Debug, Args)]
pub struct RouterDiagnoseArgs {
    #[arg(
        long = "port",
        value_name = "port",
        value_delimiter = ',',
        num_args = 1..,
        help = "TCP port to probe (repeatable; replaces router defaults 49000, 49443, 80, 443)"
    )]
    pub ports: Vec<u16>,
}

#[derive(Debug, Args)]
pub struct OneArg {
    #[arg(value_name = "nummer")]
    pub number: String,
}

#[derive(Debug, Args)]
pub struct HelpArgs {
    #[arg(value_name = "command", trailing_var_arg = true, num_args = 0..)]
    pub command: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub enum HomeCommand {
    #[command(about = "List DECT actors with AIN, name, and state")]
    List(HomeListArgs),
    #[command(about = "Turn a switch actor on or off")]
    Switch(HomeSwitchArgs),
    #[command(about = "Set the target temperature for a thermostat")]
    Temp(HomeTempArgs),
}

#[derive(Debug, Args)]
pub struct HomeListArgs {
    #[arg(long, help = "Use TR-064 Homeauto API")]
    pub tr064: bool,
}

#[derive(Debug, Args)]
pub struct HomeSwitchArgs {
    #[arg(value_name = "ain")]
    pub ain: String,
    #[arg(value_name = "on|off")]
    pub state: String,
    #[arg(long, help = "Use TR-064 Homeauto API")]
    pub tr064: bool,
}

#[derive(Debug, Args)]
pub struct HomeTempArgs {
    #[arg(value_name = "ain")]
    pub ain: String,
    #[arg(value_name = "celsius|on|off")]
    pub temperature: String,
}

#[derive(Debug, Subcommand)]
pub enum HostsCommand {
    #[command(about = "List only currently active hosts")]
    Active,
    #[command(about = "Show one host by name, --mac, or --ip")]
    Get(HostGetArgs),
    #[command(about = "List all known hosts")]
    List,
}

#[derive(Debug, Args)]
pub struct HostGetArgs {
    #[arg(value_name = "name")]
    pub name: Option<String>,
    #[arg(long, help = "Look up by MAC address")]
    pub mac: Option<String>,
    #[arg(long, help = "Look up by IP address")]
    pub ip: Option<String>,
}

#[derive(Debug, Args)]
pub struct LogArgs {
    #[arg(
        long = "filter",
        default_value = "all",
        help = "Filter by category (all, sys, net, fon, wlan, usb)"
    )]
    pub filter: String,
}

#[derive(Debug, Args)]
pub struct RebootArgs {
    #[arg(long, help = "Confirm the reboot")]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct ScrapeArgs {
    #[arg(value_name = "page")]
    pub page: String,
    #[arg(
        value_name = "Key=Value",
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 0..
    )]
    pub arguments: Vec<String>,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    #[arg(long, help = "Show CPU temperatures (experimental)")]
    pub cpu: bool,
}

#[derive(Debug, Args)]
pub struct TrafficArgs {
    #[arg(long, help = "Continuously re-poll and append snapshots until Ctrl-C")]
    pub watch: bool,
    #[arg(
        long,
        default_value = "2s",
        value_parser = parse_duration,
        help = "Polling interval for --watch mode"
    )]
    pub interval: std::time::Duration,
}

#[derive(Debug, Args)]
pub struct VersionArgs {
    #[arg(long, help = "Check for updates on GitHub")]
    pub check: bool,
    #[arg(hide = true, trailing_var_arg = true, allow_hyphen_values = false, num_args = 0..)]
    pub extra: Vec<String>,
}

#[derive(Debug, Args)]
pub struct WlanCommand {
    #[arg(
        long = "guest-index",
        global = true,
        default_value_t = 3,
        help = "WLANConfiguration index of the guest radio"
    )]
    pub guest_index: u16,
    #[command(subcommand)]
    pub command: Option<WlanSubcommand>,
}

#[derive(Debug, Subcommand)]
pub enum WlanSubcommand {
    #[command(about = "List devices associated with the WLAN radios")]
    Clients,
    #[command(about = "Guest WLAN status/enable/disable", subcommand)]
    Guest(WlanGuestCommand),
    #[command(about = "List WLAN radios (SSID, band, channel, state)")]
    Radios,
}

#[derive(Debug, Subcommand)]
pub enum WlanGuestCommand {
    #[command(about = "Disable guest WLAN")]
    Off,
    #[command(about = "Enable guest WLAN")]
    On,
    #[command(about = "Show guest WLAN state")]
    Status,
}

#[derive(Debug, Args)]
pub struct WolArgs {
    #[arg(value_name = "host")]
    pub host: Option<String>,
    #[arg(long, help = "Target MAC address")]
    pub mac: Option<String>,
}

/// Parse the Go-compatible duration forms used by `--interval`.
fn parse_duration(value: &str) -> Result<std::time::Duration, String> {
    let mut rest = value.trim();
    if rest.is_empty() {
        return Err("duration must not be empty".to_owned());
    }
    let mut total_nanos = 0.0_f64;
    while !rest.is_empty() {
        let number_end = rest
            .find(|character: char| !character.is_ascii_digit() && character != '.')
            .unwrap_or(rest.len());
        if number_end == 0 {
            return Err(format!("invalid duration: {value:?}"));
        }
        let number: f64 = rest[..number_end]
            .parse()
            .map_err(|_| format!("invalid duration: {value:?}"))?;
        rest = &rest[number_end..];
        let unit = ["ns", "us", "µs", "ms", "s", "m", "h"]
            .iter()
            .find(|unit| rest.starts_with(**unit))
            .ok_or_else(|| format!("invalid duration: {value:?}"))?;
        let multiplier = match *unit {
            "ns" => 1.0,
            "us" | "µs" => 1_000.0,
            "ms" => 1_000_000.0,
            "s" => 1_000_000_000.0,
            "m" => 60.0 * 1_000_000_000.0,
            "h" => 3_600.0 * 1_000_000_000.0,
            _ => unreachable!(),
        };
        total_nanos += number * multiplier;
        rest = &rest[unit.len()..];
    }
    if !total_nanos.is_finite() || total_nanos < 0.0 {
        return Err(format!("invalid duration: {value:?}"));
    }
    let nanos = total_nanos.round() as u128;
    if nanos > u64::MAX as u128 {
        return Err(format!("duration is too large: {value:?}"));
    }
    Ok(std::time::Duration::from_nanos(nanos as u64))
}

/// Command tree constructor used by the binary and contract tests.
pub fn command() -> clap::Command {
    Cli::command()
}
