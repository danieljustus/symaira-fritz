#![deny(unsafe_code)]

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_symfritz-rust"))
        .args(args)
        .output()
        .expect("run symfritz-rust")
}

#[test]
fn version_text_matches_go_contract() {
    let output = run(&["version"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"symfritz dev\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn version_flag_matches_go_contract() {
    let output = run(&["--version"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"symfritz version dev\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn version_json_matches_go_contract() {
    for args in [
        &["version", "--json"][..],
        &["version", "--output", "json"][..],
        &["version", "--output", "JSON"][..],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(
            output.stdout,
            b"{\"tool\":\"symfritz\",\"version\":\"dev\",\"schema_version\":1}\n"
        );
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn version_yaml_matches_go_contract() {
    let output = run(&["version", "--output", "yaml"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        b"schema_version: 1\ntool: symfritz\nversion: dev\n"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn output_errors_match_go_contract() {
    let invalid = run(&["--output", "wat", "version"]);
    assert_eq!(invalid.status.code(), Some(9));
    assert!(invalid.stdout.is_empty());
    assert_eq!(
        invalid.stderr,
        b"Error: invalid output format: unsupported output format \"wat\" (want text, json, or yaml)\n"
    );

    let conflict = run(&["version", "--json", "--output", "yaml"]);
    assert_eq!(conflict.status.code(), Some(9));
    assert!(conflict.stdout.is_empty());
    assert_eq!(
        conflict.stderr,
        b"Error: conflicting output formats: conflicting output formats \"yaml\" and \"json\"\n"
    );
}

#[test]
fn version_keeps_cobra_extra_argument_behavior() {
    let output = run(&["version", "extra"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"symfritz dev\n");
    assert!(output.stderr.is_empty());
}
