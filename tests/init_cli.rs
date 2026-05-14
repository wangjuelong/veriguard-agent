//! Integration tests for the `veriguard-agent init` subcommand.
//!
//! These build and invoke the actual binary so we exercise clap routing,
//! arg validation, and the offline provisioning flow end-to-end.

use assert_cmd::Command;
use std::path::PathBuf;
use tempfile::tempdir;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/install_pack_valid.json")
}

#[test]
fn test_cli_init_install_pack_provisions_state_dir() {
    let state_dir = tempdir().unwrap();
    Command::cargo_bin("veriguard-agent")
        .expect("binary builds")
        .arg("init")
        .arg("--install-pack")
        .arg(fixture_path())
        .arg("--state-dir")
        .arg(state_dir.path())
        .assert()
        .success();

    assert!(state_dir.path().join("keys/sign.key").exists());
    assert!(state_dir.path().join("keys/enc.key").exists());
    assert!(state_dir.path().join("install-pack.json").exists());
}

#[test]
fn test_cli_init_without_subargs_fails() {
    let state_dir = tempdir().unwrap();
    Command::cargo_bin("veriguard-agent")
        .expect("binary builds")
        .arg("init")
        .arg("--state-dir")
        .arg(state_dir.path())
        .assert()
        .failure();
}

#[test]
fn test_cli_init_bootstrap_until_platform_pubs_wired_fails_clearly() {
    // C1-Agent-2 implements Mode A bootstrap (HTTP fetch of platform pubs).
    // Until then the synthesised pack has empty platform pubs and validate()
    // returns a structured error — confirm we exit non-zero with a clean
    // failure (not a panic).
    let state_dir = tempdir().unwrap();
    let output = Command::cargo_bin("veriguard-agent")
        .expect("binary builds")
        .arg("init")
        .arg("--bootstrap")
        .arg("--platform-url")
        .arg("https://veriguard.example.com")
        .arg("--onboard-token")
        .arg("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        .arg("--platform-cert-pin")
        .arg("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        .arg("--state-dir")
        .arg(state_dir.path())
        .assert()
        .failure()
        .get_output()
        .clone();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bootstrap") || stderr.contains("install pack"),
        "stderr should mention bootstrap/install pack, got: {stderr}"
    );
}

#[test]
fn test_cli_init_bootstrap_rejects_http_url() {
    let state_dir = tempdir().unwrap();
    Command::cargo_bin("veriguard-agent")
        .expect("binary builds")
        .arg("init")
        .arg("--bootstrap")
        .arg("--platform-url")
        .arg("http://insecure.example.com")
        .arg("--onboard-token")
        .arg("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        .arg("--platform-cert-pin")
        .arg("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        .arg("--state-dir")
        .arg(state_dir.path())
        .assert()
        .failure();
}

#[test]
fn test_cli_init_help_prints_usage() {
    Command::cargo_bin("veriguard-agent")
        .expect("binary builds")
        .args(["init", "--help"])
        .assert()
        .success();
}
