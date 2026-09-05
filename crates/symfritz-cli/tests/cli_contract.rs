#![deny(unsafe_code)]

use std::process::Command as ProcessCommand;

use clap::Command;
use serde::Deserialize;
use symfritz_cli::cli;

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    commands: Vec<CommandCase>,
    validation: Vec<ValidationCase>,
}

#[derive(Debug, Deserialize)]
struct CommandCase {
    path: String,
    help_args: Vec<String>,
    exit_code: i32,
    stdout: String,
    stderr: String,
    comparison: String,
}

#[derive(Debug, Deserialize)]
struct ValidationCase {
    id: String,
    args: Vec<String>,
    exit_code: i32,
    stdout: String,
    stderr: String,
    comparison: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "../../../testdata/port/cli/command-contracts.json"
    ))
    .expect("valid Go CLI contract fixture")
}

fn has_command(command: &Command, name: &str) -> bool {
    command.get_name() == name || command.get_all_aliases().any(|alias| alias == name)
}

fn lookup(root: &Command, path: &str) -> Option<Command> {
    let mut current = root.clone();
    for component in path.split_whitespace().skip(1) {
        let next = current
            .get_subcommands()
            .find(|candidate| has_command(candidate, component))?
            .clone();
        current = next;
    }
    Some(current)
}

fn flatten_paths(command: &Command, prefix: &str, result: &mut Vec<String>) {
    for child in command.get_subcommands() {
        let path = format!("{prefix} {}", child.get_name());
        result.push(path.clone());
        flatten_paths(child, &path, result);
    }
}

#[test]
fn generated_fixture_covers_every_documented_command() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.commands.len(), 49);
    assert!(fixture.commands.iter().all(|case| case.exit_code == 0
        && case.comparison == "semantic-help"
        && !case.help_args.is_empty()
        && !case.stdout.is_empty()
        && case.stderr.is_empty()));

    let root = cli::command();
    let mut actual = vec!["symfritz".to_owned()];
    flatten_paths(&root, "symfritz", &mut actual);
    let mut expected: Vec<_> = fixture
        .commands
        .iter()
        .map(|case| case.path.clone())
        .collect();
    actual.sort();
    expected.sort();
    assert_eq!(
        actual, expected,
        "Rust command tree drifted from Go fixture"
    );

    let binary = env!("CARGO_BIN_EXE_symfritz-rust");
    for case in &fixture.commands {
        let output = ProcessCommand::new(binary)
            .args(&case.help_args)
            .output()
            .unwrap_or_else(|error| panic!("run help {}: {error}", case.path));
        assert_eq!(output.status.code(), Some(0), "help failed: {}", case.path);
        assert!(
            !output.stdout.is_empty(),
            "help emitted no stdout: {}",
            case.path
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("Usage:"),
            "help has no usage line: {}",
            case.path
        );
    }

    for case in &fixture.commands {
        let selected = lookup(&root, &case.path).expect("fixture command exists in Rust tree");
        assert!(
            selected.get_about().is_some(),
            "missing help metadata: {}",
            case.path
        );
    }
}

#[test]
fn command_tree_preserves_aliases_defaults_and_argument_metadata() {
    let root = cli::command();
    let mcp = lookup(&root, "symfritz mcp").expect("mcp command");
    assert!(mcp.get_all_aliases().any(|alias| alias == "serve"));

    let output = root
        .get_arguments()
        .find(|argument| argument.get_id().as_str() == "output")
        .expect("global output argument");
    assert_eq!(output.get_default_values(), ["text"]);
    assert!(
        root.get_arguments()
            .any(|argument| argument.get_id().as_str() == "json")
    );
    assert!(
        root.get_arguments()
            .any(|argument| argument.get_id().as_str() == "show_version")
    );

    let version = lookup(&root, "symfritz version").expect("version command");
    assert!(
        version
            .get_arguments()
            .any(|argument| argument.get_id().as_str() == "check")
    );
    assert!(
        version
            .get_arguments()
            .any(|argument| argument.is_positional() && argument.is_trailing_var_arg_set())
    );

    let call = lookup(&root, "symfritz call").expect("call command");
    assert_eq!(
        call.get_arguments()
            .filter(|argument| argument.is_positional())
            .count(),
        3
    );
    let hosts_get = lookup(&root, "symfritz hosts get").expect("hosts get command");
    assert!(
        hosts_get
            .get_arguments()
            .any(|argument| argument.get_id().as_str() == "mac")
    );
    assert!(
        hosts_get
            .get_arguments()
            .any(|argument| argument.get_id().as_str() == "ip")
    );
}

#[test]
fn generated_argument_cases_match_go_fixtures_byte_for_byte() {
    let fixture = fixture();
    assert_eq!(fixture.validation.len(), 17);
    assert!(fixture.validation.iter().all(|case| {
        case.comparison == "bytes" && case.exit_code == 1 && case.stdout.is_empty()
    }));

    let binary = env!("CARGO_BIN_EXE_symfritz-rust");
    for case in fixture.validation {
        let output = ProcessCommand::new(binary)
            .args(&case.args)
            .output()
            .unwrap_or_else(|error| panic!("run {}: {error}", case.id));
        assert_eq!(
            output.status.code(),
            Some(case.exit_code),
            "{} exit status",
            case.id
        );
        assert_eq!(output.stdout, case.stdout.as_bytes(), "{} stdout", case.id);
        assert_eq!(output.stderr, case.stderr.as_bytes(), "{} stderr", case.id);
    }
}

#[test]
fn completion_handlers_generate_all_shells() {
    let binary = env!("CARGO_BIN_EXE_symfritz-rust");
    for shell in ["bash", "fish", "powershell", "zsh"] {
        let output = ProcessCommand::new(binary)
            .args(["completion", shell, "--no-descriptions"])
            .output()
            .unwrap_or_else(|error| panic!("run completion {shell}: {error}"));
        assert_eq!(output.status.code(), Some(0), "completion failed: {shell}");
        assert!(
            !output.stdout.is_empty(),
            "completion emitted no script: {shell}"
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("internal handler"),
            "completion fell through to the placeholder: {shell}"
        );
    }
}

#[test]
fn diagnostic_and_detection_commands_are_wired_to_the_rust_tree() {
    let root = cli::command();
    for path in [
        "symfritz detect",
        "symfritz config detect",
        "symfritz diagnose",
        "symfritz diagnose router",
        "symfritz doctor",
        "symfritz mesh",
        "symfritz home list",
        "symfritz scrape",
    ] {
        assert!(lookup(&root, path).is_some(), "missing command: {path}");
    }
}

#[test]
fn documented_command_list_does_not_drift_from_fixture() {
    let fixture_paths: std::collections::BTreeSet<_> = fixture()
        .commands
        .into_iter()
        .map(|case| case.path)
        .collect();
    let documented_paths: std::collections::BTreeSet<_> = include_str!("../../../docs/cli.md")
        .lines()
        .filter_map(|line| {
            line.strip_prefix("- [")
                .and_then(|line| line.split_once("](#"))
        })
        .map(|(path, _)| path.to_owned())
        .collect();
    assert_eq!(
        documented_paths, fixture_paths,
        "docs/cli.md command list drifted"
    );
}

#[test]
fn help_flags_precede_positional_validation_and_exit_successfully() {
    let binary = env!("CARGO_BIN_EXE_symfritz-rust");
    for args in [
        vec!["status", "--help"],
        vec!["status", "-h"],
        vec!["call", "--help"],
        vec!["call", "-h"],
        vec!["hosts", "get", "--help"],
        vec!["wlan", "guest", "status", "--help"],
        vec!["--help"],
        vec!["-h"],
    ] {
        let output = ProcessCommand::new(binary)
            .args(args.iter().copied())
            .output()
            .unwrap_or_else(|error| panic!("run help {:?}: {error}", args));
        assert_eq!(output.status.code(), Some(0), "help failed: {args:?}");
        assert!(
            !output.stdout.is_empty(),
            "help emitted no stdout: {args:?}"
        );
        assert!(output.stderr.is_empty(), "help emitted stderr: {args:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("Usage:"),
            "help has no usage line: {args:?}"
        );
    }
}
