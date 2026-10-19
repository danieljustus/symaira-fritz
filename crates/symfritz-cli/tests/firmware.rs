#![deny(unsafe_code)]
use clap::CommandFactory;
use serde_json::Value;
use std::{
    fs,
    net::TcpListener,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use symfritz_cli::cli::{Cli, FirmwareCommand};
fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/firmware/contracts.json"
    ))
    .unwrap()
}
#[test]
fn firmware_surface_is_registered() {
    let root = Cli::command();
    let fixture = contract();
    let firmware = root
        .get_subcommands()
        .find(|c| c.get_name() == "firmware")
        .unwrap();
    assert_eq!(
        firmware.get_about().unwrap().to_string(),
        fixture["root_help_additions"]["firmware"].as_str().unwrap()
    );
    assert_eq!(
        firmware
            .get_subcommands()
            .map(|c| c.get_name())
            .collect::<Vec<_>>(),
        ["status", "check", "install"]
    );
    for path in fixture["cli_paths"].as_array().unwrap() {
        let mut args = path
            .as_str()
            .unwrap()
            .split_whitespace()
            .collect::<Vec<_>>();
        args.push("--help");
        let output = Command::new(env!("CARGO_BIN_EXE_symfritz"))
            .args(&args[1..])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
    }
    let _type_contract: Option<FirmwareCommand> = None;
}
#[test]
fn unconfirmed_install_performs_no_network_or_credential_resolution() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let root = std::env::temp_dir().join(format!(
        "symfritz-firmware-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    // Missing config and empty password would fail credential loading. The
    // confirmation error must happen first, even with a reachable mock endpoint.
    for flags in [
        vec![],
        vec!["--json"],
        vec!["--output", "yaml"],
        vec!["--verify"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_symfritz"))
            .args(["firmware", "install"])
            .args(flags)
            .env("HOME", &root)
            .env("XDG_CONFIG_HOME", &root)
            .env("SYMFRITZ_HOST", listener.local_addr().unwrap().to_string())
            .env("SYMFRITZ_PASSWORD", "")
            .current_dir(&root)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(9));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("confirmation required"));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn firmware_cli_rejects_image_and_channel_overrides() {
    for args in [
        [
            "firmware",
            "install",
            "--url",
            "https://example.invalid/image",
        ],
        ["firmware", "install", "--channel", "lab"],
        ["firmware", "install", "--downgrade", "true"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_symfritz"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
    }
}
