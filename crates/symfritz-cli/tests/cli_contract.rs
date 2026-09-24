#![deny(unsafe_code)]

use std::{fs, process::Command as ProcessCommand};

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

    let binary = env!("CARGO_BIN_EXE_symfritz");
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

    let binary = env!("CARGO_BIN_EXE_symfritz");
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
    let binary = env!("CARGO_BIN_EXE_symfritz");
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
    let binary = env!("CARGO_BIN_EXE_symfritz");
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

#[test]
fn diagnose_parser_accepts_router_and_trailing_output_flags() {
    for args in [
        vec!["symfritz", "diagnose", "router", "--json"],
        vec!["symfritz", "diagnose", "router", "--output", "json"],
        vec!["symfritz", "diagnose", "host", "--json"],
        vec!["symfritz", "diagnose", "host", "--output", "json"],
    ] {
        assert!(
            symfritz_cli::cli::parse_args(
                &args.iter().map(ToString::to_string).collect::<Vec<_>>(),
            )
            .is_ok(),
            "parser rejected valid arguments: {args:?}"
        );
    }
}

#[test]
fn diagnose_parser_preserves_extra_positional_error() {
    let args = ["symfritz", "diagnose", "host", "extra"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    match symfritz_cli::cli::parse_args(&args) {
        Err(symfritz_cli::cli::ParseError::Invalid(message)) => {
            assert_eq!(message, "accepts 1 arg(s), received 2");
        }
        other => panic!("expected the Go-compatible positional error, got {other:?}"),
    }
}

#[test]
fn selector_validation_rejects_zero_and_multiple_cli_selectors_before_execution() {
    let binary = env!("CARGO_BIN_EXE_symfritz");
    let hosts_zero = "Error: exactly one of name, --mac, or --ip is required\n";
    let hosts_many = "Error: only one of name, --mac, or --ip may be specified\n";
    let wol_zero = "Error: exactly one of host or --mac is required\n";
    let wol_many = "Error: only one of host or --mac may be specified\n";
    let two_positional = "Error: accepts at most 1 arg(s), received 2\n";
    // The invariant must hold wherever the global output flags sit relative
    // to the command, for both `--flag value` and `--flag=value` selectors.
    let cases: &[(&[&str], &str)] = &[
        // Zero selectors.
        (&["hosts", "get"], hosts_zero),
        (&["--json", "hosts", "get"], hosts_zero),
        (&["hosts", "get", "--json"], hosts_zero),
        (&["--output", "json", "hosts", "get"], hosts_zero),
        (&["hosts", "get", "--output", "json"], hosts_zero),
        (&["--output=json", "hosts", "get"], hosts_zero),
        (&["hosts", "get", "--output=json"], hosts_zero),
        (&["hosts", "--json", "get"], hosts_zero),
        (&["wol"], wol_zero),
        (&["--json", "wol"], wol_zero),
        (&["wol", "--json"], wol_zero),
        (&["--output", "json", "wol"], wol_zero),
        (&["wol", "--output", "json"], wol_zero),
        (&["--output=json", "wol"], wol_zero),
        (&["wol", "--output=json"], wol_zero),
        // Multiple selectors.
        (
            &["hosts", "get", "name", "--mac", "AA:BB:CC:DD:EE:FF"],
            hosts_many,
        ),
        (
            &[
                "--json",
                "hosts",
                "get",
                "name",
                "--mac",
                "AA:BB:CC:DD:EE:FF",
            ],
            hosts_many,
        ),
        (
            &[
                "hosts",
                "get",
                "name",
                "--mac",
                "AA:BB:CC:DD:EE:FF",
                "--json",
            ],
            hosts_many,
        ),
        (
            &[
                "--output",
                "json",
                "hosts",
                "get",
                "name",
                "--ip",
                "192.0.2.1",
            ],
            hosts_many,
        ),
        (&["hosts", "get", "--mac=X", "--ip=192.0.2.1"], hosts_many),
        (
            &["--output=json", "hosts", "get", "--mac=X", "--ip=192.0.2.1"],
            hosts_many,
        ),
        (
            &[
                "hosts",
                "get",
                "--output",
                "json",
                "--mac=X",
                "--ip=192.0.2.1",
            ],
            hosts_many,
        ),
        (
            &["--json", "hosts", "get", "--mac=X", "--ip=192.0.2.1"],
            hosts_many,
        ),
        (&["wol", "host", "--mac", "AA:BB:CC:DD:EE:FF"], wol_many),
        (
            &["--json", "wol", "host", "--mac", "AA:BB:CC:DD:EE:FF"],
            wol_many,
        ),
        (
            &["wol", "host", "--mac=AA:BB:CC:DD:EE:FF", "--output", "json"],
            wol_many,
        ),
        (
            &["--output", "json", "wol", "--mac=AA:BB:CC:DD:EE:FF", "host"],
            wol_many,
        ),
        // Excess positionals keep the Go-compatible message at any position.
        (&["hosts", "get", "one", "two"], two_positional),
        (&["--json", "hosts", "get", "one", "two"], two_positional),
        (&["hosts", "--json", "get", "one", "two"], two_positional),
        (&["--output", "json", "wol", "one", "two"], two_positional),
        (&["wol", "one", "two", "--json"], two_positional),
    ];
    // Isolate HOME so a validation regression cannot resolve credentials or
    // reach a router: the only passing outcome is the parse-stage rejection,
    // and no request can be issued without credentials.
    let home = std::env::temp_dir().join("symfritz-selector-224-home");
    std::fs::create_dir_all(home.join(".config")).expect("isolated test HOME");
    for &(args, expected) in cases {
        let output = ProcessCommand::new(binary)
            .args(args)
            .env_remove("SYMFRITZ_BOX_HOST")
            .env_remove("SYMFRITZ_HOST")
            .env_remove("SYMFRITZ_PASSWORD")
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("APPDATA", home.join(".config"))
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .output()
            .unwrap_or_else(|error| panic!("run invalid selector {args:?}: {error}"));
        assert_eq!(
            output.status.code(),
            Some(1),
            "selector must fail during argument parsing: {args:?}"
        );
        assert!(
            output.stdout.is_empty(),
            "selector validation wrote output before execution: {args:?}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            expected,
            "selector stderr mismatch: {args:?}"
        );
    }
}

#[test]
fn selector_validation_accepts_equals_syntax() {
    for args in [
        ["symfritz", "hosts", "get", "--mac=AA:BB:CC:DD:EE:FF"].as_slice(),
        ["symfritz", "hosts", "get", "--ip=192.0.2.1"].as_slice(),
        ["symfritz", "wol", "--mac=AA:BB:CC:DD:EE:FF"].as_slice(),
        // Valid single selectors parse whatever the global output-flag position.
        [
            "symfritz",
            "--json",
            "hosts",
            "get",
            "--mac=AA:BB:CC:DD:EE:FF",
        ]
        .as_slice(),
        [
            "symfritz",
            "hosts",
            "get",
            "--mac=AA:BB:CC:DD:EE:FF",
            "--output",
            "json",
        ]
        .as_slice(),
        ["symfritz", "--output=json", "hosts", "get", "laptop"].as_slice(),
        ["symfritz", "hosts", "--json", "get", "laptop"].as_slice(),
        [
            "symfritz",
            "--output",
            "json",
            "wol",
            "--mac=AA:BB:CC:DD:EE:FF",
        ]
        .as_slice(),
        ["symfritz", "wol", "laptop", "--json"].as_slice(),
    ] {
        let args = args.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert!(
            symfritz_cli::cli::parse_args(&args).is_ok(),
            "parser rejected valid equals syntax: {args:?}"
        );
    }
}

#[test]
fn structured_success_outputs_use_real_cli() {
    let binary = env!("CARGO_BIN_EXE_symfritz");
    let home =
        std::env::temp_dir().join(format!("symfritz-structured-output-{}", std::process::id()));
    fs::create_dir_all(&home).expect("create isolated HOME");

    let output = ProcessCommand::new(binary)
        .args(["auth", "trust", "--reset", "no-pin-recorded", "--json"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env_remove("SYMFRITZ_HOST")
        .env_remove("SYMFRITZ_BOX_HOST")
        .output()
        .expect("run real auth trust handler");
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());

    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("real handler emitted JSON");
    let object = value.as_object().expect("structured success object");
    assert_eq!(object.len(), 4, "minimal ok-only output must not pass");
    assert_eq!(object.get("ok"), Some(&serde_json::Value::Bool(true)));
    assert_eq!(
        object.get("action").and_then(|value| value.as_str()),
        Some("auth_trust")
    );
    assert_eq!(
        object.get("host").and_then(|value| value.as_str()),
        Some("no-pin-recorded")
    );
    assert_eq!(object.get("reset"), Some(&serde_json::Value::Bool(false)));

    fs::remove_dir_all(home).expect("remove isolated HOME");
}

#[test]
fn selector_validation_counts_parsed_groups_not_flag_positions() {
    let args = [
        "symfritz",
        "--json",
        "hosts",
        "get",
        "--mac=AA:BB:CC:DD:EE:FF",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    let cli = symfritz_cli::cli::parse_args(&args).expect("single selector must parse");
    assert!(cli.json);
    match cli.command {
        Some(symfritz_cli::cli::Command::Hosts(symfritz_cli::cli::HostsCommand::Get(get))) => {
            assert_eq!(get.mac.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
            assert!(get.name.is_none());
            assert!(get.ip.is_none());
        }
        other => panic!("expected parsed 'hosts get', got {other:?}"),
    }
}
