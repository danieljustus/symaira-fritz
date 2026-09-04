#![deny(unsafe_code)]

use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use symfritz_cli::{TOOL, render_version, resolve_output_format};

const VERSION: &str = match option_env!("SYMFRITZ_VERSION") {
    Some(version) => version,
    None => "dev",
};
const EXIT_CONFIG: u8 = 9;

#[derive(Debug, Parser)]
#[command(
    name = "symfritz",
    about = "Administer, analyse, and control an AVM FRITZ!Box",
    disable_version_flag = true
)]
struct Cli {
    #[arg(
        long,
        global = true,
        default_value = "text",
        help = "Output format: text|json|yaml (--json is shorthand for --output json)"
    )]
    output: String,

    #[arg(
        long,
        global = true,
        help = "Output as JSON (shorthand for --output json)"
    )]
    json: bool,

    #[arg(
        short = 'v',
        long = "version",
        global = true,
        help = "version for symfritz"
    )]
    show_version: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Print version")]
    Version {
        #[arg(hide = true, trailing_var_arg = true)]
        extra: Vec<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.show_version {
        println!("{TOOL} version {VERSION}");
        return ExitCode::SUCCESS;
    }

    match cli.command {
        Some(Command::Version { extra: _ }) => match resolve_output_format(&cli.output, cli.json) {
            Ok(format) => {
                print!("{}", render_version(format, VERSION));
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("Error: {message}");
                ExitCode::from(EXIT_CONFIG)
            }
        },
        None => {
            let mut command = Cli::command();
            if let Err(error) = command.print_help() {
                eprintln!("Error: {error}");
                return ExitCode::FAILURE;
            }
            println!();
            ExitCode::SUCCESS
        }
    }
}
