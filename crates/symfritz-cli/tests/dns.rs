#![deny(unsafe_code)]
use std::process::Command;
use symfritz_cli::cli;

#[test]
fn dns_surface_and_validation_preserve_read_only_scope() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/dns/contracts.json")).unwrap();
    let tree = cli::command();
    let dns = tree
        .get_subcommands()
        .find(|c| c.get_name() == "dns")
        .unwrap();
    assert_eq!(
        dns.get_about().unwrap().to_string(),
        fixture["root_help_additions"]["dns"]
    );
    assert_eq!(fixture["cli_paths"], serde_json::json!(["symfritz dns"]));
    assert_eq!(fixture["read_only"], true);
    let help = Command::new(env!("CARGO_BIN_EXE_symfritz"))
        .args(["dns", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(help.stderr.is_empty());
    for args in [
        vec!["symfritz", "dns", "Host.Fritz.Box.", "--json"],
        vec![
            "symfritz",
            "--output",
            "yaml",
            "dns",
            "host",
            "--expected-ip",
            "192.0.2.20",
        ],
        vec![
            "symfritz",
            "dns",
            "host.fritz.box",
            "--router-dns-ip",
            "fd00::1",
        ],
    ] {
        assert!(cli::parse_args(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_ok());
    }
    // All fail at parsing, before configuration, credentials or network access.
    for args in [
        vec!["dns"],
        vec!["dns", "*.fritz.box"],
        vec!["dns", "192.168.1.1"],
        vec!["dns", "host", "--expected-ip", "bad"],
        vec!["dns", "host", "--router-dns-ip", "fe80::1%en0"],
        vec!["dns", "host", "--set-upstream", "8.8.8.8"],
        vec!["dns", "host", "extra"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_symfritz"))
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(!output.stderr.is_empty());
    }
}
