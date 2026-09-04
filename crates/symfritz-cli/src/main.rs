#![deny(unsafe_code)]

use std::process::ExitCode;

use clap::{CommandFactory, Parser};
use symfritz_cli::{
    TOOL,
    cli::{Cli, Command},
    render_version, resolve_output_format,
};

const VERSION: &str = match option_env!("SYMFRITZ_VERSION") {
    Some(version) => version,
    None => "dev",
};
const EXIT_CONFIG: u8 = 9;
const EXIT_PARSE: u8 = 2;
const EXIT_UNIMPLEMENTED: u8 = 1;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let output = cli.output;
    let json = cli.json;

    if cli.show_version {
        println!("{TOOL} version {VERSION}");
        return ExitCode::SUCCESS;
    }

    match cli.command {
        Some(Command::Version(_)) => match resolve_output_format(&output, json) {
            Ok(format) => {
                print!("{}", render_version(format, VERSION));
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("Error: {message}");
                ExitCode::from(EXIT_CONFIG)
            }
        },
        Some(Command::Help(args)) => {
            if let Err(message) = print_help(&args.command) {
                eprintln!("Error: {message}");
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        None => {
            if let Err(error) = Cli::command().print_long_help() {
                eprintln!("Error: {error}");
                return ExitCode::FAILURE;
            }
            println!();
            ExitCode::SUCCESS
        }
        Some(Command::Diagnose(args)) => {
            if args.host.is_none() && args.command.is_none() {
                print_diagnose_missing_host();
                ExitCode::from(EXIT_PARSE)
            } else {
                unimplemented_command(&Command::Diagnose(args), &output, json)
            }
        }
        Some(command) => unimplemented_command(&command, &output, json),
    }
}

fn print_help(path: &[String]) -> Result<(), String> {
    let mut command = Cli::command();
    for part in path {
        command = command
            .find_subcommand_mut(part)
            .ok_or_else(|| format!("unknown command {part:?}"))?
            .clone();
    }
    if !path.is_empty() {
        command = command.bin_name(format!("symfritz {}", path.join(" ")));
    }
    command.print_help().map_err(|error| error.to_string())?;
    println!();
    Ok(())
}

fn unimplemented_command(command: &Command, output: &str, json: bool) -> ExitCode {
    if let Err(message) = resolve_output_format(output, json) {
        eprintln!("Error: {message}");
        return ExitCode::from(EXIT_CONFIG);
    }
    eprintln!(
        "Error: internal handler for '{}' is not implemented",
        command_name(command)
    );
    ExitCode::from(EXIT_UNIMPLEMENTED)
}

fn print_diagnose_missing_host() {
    eprintln!(
        "error: the following arguments were not provided:\n  <host>\n\nUsage: symfritz diagnose <host> [OPTIONS]\n\nFor more information, try '--help'."
    );
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
