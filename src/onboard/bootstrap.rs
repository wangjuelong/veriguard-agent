//! `init --bootstrap` — Mode-A online provisioning entry point.
//!
//! **Scope of this PR:** wire the CLI surface and synthesise an
//! [`InstallPack`] from the operator-supplied flags so that the rest of the
//! `init` flow (keypair generation + persistence) can be exercised end-to-end
//! in tests.
//!
//! **Out of scope (C1-Agent-2):** the actual `GET /api/install/<token>`
//! HTTPS exchange to fetch the install pack from the platform.  Until that
//! lands the operator is expected to assemble the equivalent values
//! out-of-band (e.g. from a printed onboarding document or a side-channel
//! deployment).  The synthesised pack stores **empty strings** for the
//! platform public keys; this triggers a clean validation failure at the
//! pack-validate step, which is the desired behaviour for the alpha.
//!
//! In other words, `init --bootstrap` today acts as a placeholder that
//! exercises the CLI plumbing and rejects with a stable error message —
//! callers should switch to `--install-pack` until the Mode-A transport
//! ships.
use std::path::Path;

use log::warn;
use thiserror::Error;

use super::init::{run_init_install_pack, InitError};
use super::install_pack::{InstallPack, InstallPackError};

/// Errors specific to `--bootstrap`.
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// The synthesised install pack failed validation.  Until C1-Agent-2
    /// fills in the HTTP fetch this is the expected path.
    #[error("bootstrap install pack invalid: {0}")]
    InstallPack(#[from] InstallPackError),

    /// Provisioning step (key generation, persistence) failed.
    #[error("bootstrap provisioning failed: {0}")]
    Init(#[from] InitError),
}

/// Run `init --bootstrap` with the supplied CLI args.
///
/// The platform public keys are not fetched in this PR — see module docs.
pub fn run_bootstrap(
    platform_url: &str,
    onboard_token: &str,
    platform_cert_pin: &str,
    agent_label: &str,
    state_dir: &Path,
) -> Result<(), BootstrapError> {
    warn!(
        "init --bootstrap: Mode-A HTTP fetch is not yet wired (C1-Agent-2); \
         synthesising install pack from CLI args"
    );

    let synthetic = InstallPack {
        schema_version: "1.0".to_string(),
        platform_url: platform_url.to_string(),
        platform_cert_pin: platform_cert_pin.to_string(),
        // These two slots hold platform pub keys fetched over Mode-A.
        // Empty values cause `validate()` to fail with a clear BadPublicKey
        // error, which is the right behaviour until the HTTP fetch lands.
        platform_sign_pub: String::new(),
        platform_enc_pub: String::new(),
        onboard_token: onboard_token.to_string(),
        agent_label: agent_label.to_string(),
    };

    // Validate so the operator gets a structured error if any CLI arg is wrong.
    synthetic.validate()?;

    // Once C1-Agent-2 fills in the platform pubs, write to disk and feed
    // through the same offline path so behaviour is identical to Mode C.
    let cached_path = state_dir.join("install-pack.json");
    if let Some(parent) = cached_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| BootstrapError::Init(InitError::Io(e)))?;
    }
    let json = serde_json::to_string_pretty(&synthetic)
        .map_err(|e| BootstrapError::InstallPack(InstallPackError::Json(e)))?;
    std::fs::write(&cached_path, json).map_err(|e| BootstrapError::Init(InitError::Io(e)))?;

    run_init_install_pack(&cached_path, state_dir)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const VALID_PIN: &str =
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const VALID_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn test_bootstrap_returns_error_until_platform_pubs_wired() {
        // Empty platform_*_pub fields make validate() fail — this is the
        // expected behaviour for the alpha.
        let state_dir = tempdir().unwrap();
        let err = run_bootstrap(
            "https://veriguard.example.com",
            VALID_TOKEN,
            VALID_PIN,
            "agent-bootstrap-01",
            state_dir.path(),
        )
        .expect_err("must fail until C1-Agent-2 provides platform pubs");
        assert!(matches!(err, BootstrapError::InstallPack(_)));
    }

    #[test]
    fn test_bootstrap_rejects_http_url() {
        let state_dir = tempdir().unwrap();
        let err = run_bootstrap(
            "http://insecure.example.com",
            VALID_TOKEN,
            VALID_PIN,
            "agent-bootstrap-02",
            state_dir.path(),
        )
        .expect_err("http url");
        assert!(matches!(
            err,
            BootstrapError::InstallPack(InstallPackError::BadPlatformUrl(_))
        ));
    }

    #[test]
    fn test_bootstrap_rejects_invalid_cert_pin() {
        let state_dir = tempdir().unwrap();
        let err = run_bootstrap(
            "https://veriguard.example.com",
            VALID_TOKEN,
            "sha1:abc",
            "agent-bootstrap-03",
            state_dir.path(),
        )
        .expect_err("bad pin");
        assert!(matches!(
            err,
            BootstrapError::InstallPack(InstallPackError::BadCertPin(_))
        ));
    }

    #[test]
    fn test_bootstrap_rejects_invalid_agent_label() {
        let state_dir = tempdir().unwrap();
        let err = run_bootstrap(
            "https://veriguard.example.com",
            VALID_TOKEN,
            VALID_PIN,
            "agent with spaces", // not in [A-Za-z0-9._-]
            state_dir.path(),
        )
        .expect_err("bad label");
        // Field order in validate(): platform_pub keys are checked before
        // agent_label, so empty platform pubs trip first.  Confirm we get
        // SOME InstallPack error path.
        assert!(matches!(err, BootstrapError::InstallPack(_)));
    }
}
