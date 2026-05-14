//! `init --install-pack <path>` — Mode-C offline provisioning.
//!
//! Given a Veriguard install pack on disk, this:
//!   1. Validates the pack ([`install_pack::load_install_pack`]).
//!   2. Generates this agent's per-host keypairs:
//!      * `A_sign` — Ed25519, used to sign every request to the platform
//!      * `A_enc`  — X25519, used to decrypt Mode-C offline packs
//!   3. Saves the keys under `<state_dir>/keys/{sign.key,enc.key}` with
//!      strict `0o600` permissions on Unix.
//!   4. Caches the install pack at `<state_dir>/install-pack.json` for the
//!      runtime register call (which lives in C1-Agent-2).
//!
//! The actual `POST /api/agents/register` HTTP exchange is **not** in this
//! PR.  After `init` runs, the operator must trigger registration once the
//! Mode A transport is wired in.
use std::path::{Path, PathBuf};

use log::info;
use thiserror::Error;

use super::install_pack::{load_install_pack, InstallPackError};
use crate::crypto::ed25519::generate_ed25519;
use crate::crypto::keys::{save_ed25519_priv, save_x25519_priv, KeyIoError};
use crate::crypto::x25519_box::generate_x25519;

/// Errors emitted while running `init`.
#[derive(Debug, Error)]
pub enum InitError {
    /// Install pack was missing, malformed, or failed validation.
    #[error("install pack error: {0}")]
    InstallPack(#[from] InstallPackError),

    /// Failed to write a key, the cached pack, or the state dir.
    #[error("state I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Failed to persist a private key.
    #[error("key persistence error: {0}")]
    Keys(#[from] KeyIoError),
}

/// Run `init --install-pack <path>`.
///
/// `state_dir` is the directory under which `keys/` and `install-pack.json`
/// are created.  The directory is created (with parents) if missing.
pub fn run_init_install_pack(install_pack_path: &Path, state_dir: &Path) -> Result<(), InitError> {
    // 1. Load + validate.
    let pack = load_install_pack(install_pack_path)?;
    info!(
        "loaded install pack for agent {:?} pointing at {}",
        pack.agent_label, pack.platform_url
    );

    // 2. Prepare state_dir/keys/.
    let keys_dir = state_dir.join("keys");
    std::fs::create_dir_all(&keys_dir)?;

    // 3. Generate keypairs.
    let sign_key = generate_ed25519();
    let enc_key = generate_x25519();

    // 4. Persist private keys with strict perms.
    let sign_path = keys_dir.join("sign.key");
    let enc_path = keys_dir.join("enc.key");
    save_ed25519_priv(&sign_path, &sign_key)?;
    save_x25519_priv(&enc_path, &enc_key)?;

    // 5. Cache the install pack so C1-Agent-2's register step can read it.
    let cached_pack_path = state_dir.join("install-pack.json");
    let raw = std::fs::read_to_string(install_pack_path)?;
    write_state_file(&cached_pack_path, raw.as_bytes())?;

    info!(
        "agent provisioned offline at {state_dir:?}; run `veriguard-agent register` to enroll \
         once Mode A transport is online"
    );
    Ok(())
}

/// Returns the default state dir under `~/.veriguard-agent`.
///
/// On platforms without a home directory the function returns `None`; the
/// caller must supply an explicit `--state-dir`.
pub fn default_state_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".veriguard-agent"))
}

/// Write a non-secret state file (e.g. the cached install pack) with mode
/// `0o644` on Unix.  We do not gate access to the install pack because it
/// contains only public material (platform pub keys + URL + label).
fn write_state_file(path: &Path, content: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/install_pack_valid.json")
    }

    #[test]
    fn test_init_with_install_pack_creates_state_dir() {
        let state_dir = tempdir().unwrap();
        run_init_install_pack(&fixture_path(), state_dir.path()).expect("init ok");

        assert!(state_dir.path().join("keys/sign.key").exists());
        assert!(state_dir.path().join("keys/enc.key").exists());
        assert!(state_dir.path().join("install-pack.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_init_keys_have_0600_perm() {
        use std::os::unix::fs::PermissionsExt;
        let state_dir = tempdir().unwrap();
        run_init_install_pack(&fixture_path(), state_dir.path()).expect("init ok");

        for fname in ["sign.key", "enc.key"] {
            let p = state_dir.path().join("keys").join(fname);
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{fname} must be 0o600, got {mode:#o}");
        }
    }

    #[test]
    fn test_init_rejects_invalid_install_pack() {
        let dir = tempdir().unwrap();
        let bad_pack_path = dir.path().join("bad.json");
        std::fs::write(&bad_pack_path, "{ not json }").unwrap();

        let err = run_init_install_pack(&bad_pack_path, dir.path()).expect_err("must reject");
        assert!(matches!(err, InitError::InstallPack(_)));
    }

    #[test]
    fn test_init_state_dir_created_when_missing() {
        let parent = tempdir().unwrap();
        // Note: we do not pre-create `nested`.
        let state_dir = parent.path().join("nested").join("agent");
        run_init_install_pack(&fixture_path(), &state_dir).expect("create parents");
        assert!(state_dir.join("keys/sign.key").exists());
    }

    #[test]
    fn test_init_cached_pack_matches_source() {
        let state_dir = tempdir().unwrap();
        run_init_install_pack(&fixture_path(), state_dir.path()).expect("init");

        let cached = std::fs::read_to_string(state_dir.path().join("install-pack.json")).unwrap();
        let source = std::fs::read_to_string(fixture_path()).unwrap();
        assert_eq!(cached, source);
    }
}
