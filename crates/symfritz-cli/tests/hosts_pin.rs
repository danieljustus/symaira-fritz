#![deny(unsafe_code)]
use std::process::Command;
use symfritz_cli::cli;

#[test]
fn hosts_pin_surface_is_registered() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/hosts-pin/contracts.json"
    ))
    .unwrap();
    let tree = cli::command();
    let hosts = tree
        .get_subcommands()
        .find(|command| command.get_name() == "hosts")
        .unwrap();
    for (name, about) in fixture["hosts_help_additions"].as_object().unwrap() {
        let command = hosts
            .get_subcommands()
            .find(|command| command.get_name() == name)
            .unwrap_or_else(|| panic!("missing hosts {name}"));
        assert_eq!(command.get_about().unwrap().to_string(), *about);
        assert!(command.get_all_aliases().next().is_none());
        let help = Command::new(env!("CARGO_BIN_EXE_symfritz"))
            .args(["hosts", name, "--help"])
            .output()
            .unwrap();
        assert!(help.status.success());
        assert!(help.stderr.is_empty());
        assert!(String::from_utf8_lossy(&help.stdout).contains("version-fragile"));
    }
    assert_eq!(
        fixture["cli_paths"],
        serde_json::json!(["symfritz hosts pin", "symfritz hosts unpin"])
    );
    for args in [
        vec!["symfritz", "hosts", "pin"],
        vec![
            "symfritz",
            "hosts",
            "unpin",
            "desk",
            "--mac",
            "aa:bb:cc:dd:ee:25",
        ],
    ] {
        let parsed = cli::parse_args(&args.iter().map(ToString::to_string).collect::<Vec<_>>());
        assert!(
            matches!(parsed, Err(cli::ParseError::Invalid(_))),
            "selector validation must reject {args:?} before router access"
        );
    }
}
