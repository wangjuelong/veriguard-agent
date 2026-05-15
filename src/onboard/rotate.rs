//! Agent keypair rotation (A.8.5).
//!
//! Generates fresh Ed25519 (request-signing) + X25519 (Mode C decrypt)
//! keypairs and moves the previous private keys aside with a UTC
//! timestamp suffix.  Returns the new *public* keys (base64) so the
//! operator can re-enroll with the platform.
//!
//! ## Important post-rotation step
//!
//! After rotation, **the platform no longer recognizes this agent** —
//! it still holds the previous Ed25519 verifying key on file, and every
//! Mode A poll (`GET /api/agent/poll`) signed with the *new* private key
//! will fail at the platform's signature-verification step.
//!
//! The operator must either:
//!
//! 1. Re-run `veriguard-agent init --bootstrap …` (Mode A on-line
//!    re-enrolment), or
//! 2. Hand the new `new_sign_pub_b64` + `new_enc_pub_b64` to the
//!    platform admin who updates the `agent_sign_pubkey` /
//!    `agent_enc_pubkey` columns out-of-band.
//!
//! The previous keys are kept on disk as `sign.key.bak.<timestamp>` /
//! `enc.key.bak.<timestamp>` so an operator who immediately notices a
//! mistake can `mv` them back into place.
//!
//! ## What is *not* affected
//!
//! - `install-pack.json` is preserved — platform URL + cert pin +
//!   platform pubs do not change.
//! - `executed-packs.json` is preserved — replay-prevention still
//!   applies to packs the platform may have already issued under the
//!   old keys (those packs would now fail decrypt anyway).

use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::Utc;
use log::info;
use thiserror::Error;

use crate::crypto::ed25519::generate_ed25519;
use crate::crypto::keys::{save_ed25519_priv, save_x25519_priv, KeyIoError};
use crate::crypto::x25519_box::generate_x25519;

/// Summary returned by [`run_rotate_keys`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationReport {
    /// State directory the rotation operated on.
    pub state_dir: PathBuf,
    /// Base64 (standard alphabet) of the new 32-byte Ed25519 public key.
    /// Hand this to the platform so future Mode A polls verify.
    pub new_sign_pub_b64: String,
    /// Base64 (standard alphabet) of the new 32-byte X25519 public key.
    /// Hand this to the platform so future `.vpack` envelopes can be
    /// encrypted to this agent.
    pub new_enc_pub_b64: String,
    /// Path the previous `sign.key` was renamed to (e.g.
    /// `keys/sign.key.bak.20260515T143000Z`).  `None` when there was no
    /// pre-existing key file or when `dry_run == true`.
    pub backed_up_sign_path: Option<PathBuf>,
    /// Path the previous `enc.key` was renamed to.  Same `None`
    /// conditions as `backed_up_sign_path`.
    pub backed_up_enc_path: Option<PathBuf>,
    /// True when nothing was written to disk.
    pub dry_run: bool,
}

/// Errors emitted by [`run_rotate_keys`].
#[derive(Debug, Error)]
pub enum RotateError {
    /// `state_dir/keys/` is missing or unreadable.  Without it we have
    /// no canonical location to write the new private keys.
    #[error("agent keys directory missing or unreadable at {path:?}: {source}")]
    KeysDir {
        /// Path that failed to stat.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// `rename` of an existing key to its `.bak.<timestamp>` failed.
    #[error("backup rename {path:?} → {target:?}: {source}")]
    Rename {
        /// Original key path.
        path: PathBuf,
        /// Backup target path.
        target: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// `save_*_priv` failed (typically a permission error).
    #[error("agent key persistence: {0}")]
    KeyIo(#[from] KeyIoError),
}

/// Generate fresh Ed25519 + X25519 keypairs and (unless `dry_run`)
/// install them at `<state_dir>/keys/sign.key` and `enc.key` after
/// renaming any existing files to a timestamped backup.
pub fn run_rotate_keys(state_dir: &Path, dry_run: bool) -> Result<RotationReport, RotateError> {
    let keys_dir = state_dir.join("keys");
    fs::metadata(&keys_dir).map_err(|e| RotateError::KeysDir {
        path: keys_dir.clone(),
        source: e,
    })?;

    let sign_path = keys_dir.join("sign.key");
    let enc_path = keys_dir.join("enc.key");

    // Generate the new keypairs up front so we can return the new pubs
    // even in dry-run mode (operator can see what they'd get).
    let new_sign = generate_ed25519();
    let new_enc = generate_x25519();
    let new_sign_pub_b64 = B64.encode(new_sign.public_key().to_bytes());
    let new_enc_pub_b64 = B64.encode(new_enc.public_key().to_bytes());

    if dry_run {
        info!(
            "rotate-keys dry-run: new sign_pub={} enc_pub={} (no files touched)",
            new_sign_pub_b64, new_enc_pub_b64
        );
        return Ok(RotationReport {
            state_dir: state_dir.to_path_buf(),
            new_sign_pub_b64,
            new_enc_pub_b64,
            backed_up_sign_path: None,
            backed_up_enc_path: None,
            dry_run: true,
        });
    }

    // A single timestamp shared by both backups so an operator who reads
    // the listing can correlate them as one rotation event.
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let backed_up_sign = backup_if_exists(&sign_path, &stamp)?;
    let backed_up_enc = backup_if_exists(&enc_path, &stamp)?;

    save_ed25519_priv(&sign_path, &new_sign)?;
    save_x25519_priv(&enc_path, &new_enc)?;

    info!(
        "rotate-keys: new sign_pub={} enc_pub={} (old keys backed up to {:?} and {:?})",
        new_sign_pub_b64, new_enc_pub_b64, backed_up_sign, backed_up_enc
    );

    Ok(RotationReport {
        state_dir: state_dir.to_path_buf(),
        new_sign_pub_b64,
        new_enc_pub_b64,
        backed_up_sign_path: backed_up_sign,
        backed_up_enc_path: backed_up_enc,
        dry_run: false,
    })
}

/// Rename `path` to `<path>.bak.<stamp>` if it exists, returning the new
/// path.  Returns `Ok(None)` when there's nothing to back up — a fresh
/// rotation on an empty `keys/` directory is allowed (the call just
/// installs new keys and returns).
fn backup_if_exists(path: &Path, stamp: &str) -> Result<Option<PathBuf>, RotateError> {
    if !path.exists() {
        return Ok(None);
    }
    let mut bak = path.as_os_str().to_os_string();
    bak.push(format!(".bak.{stamp}"));
    let bak = PathBuf::from(bak);
    fs::rename(path, &bak).map_err(|e| RotateError::Rename {
        path: path.to_path_buf(),
        target: bak.clone(),
        source: e,
    })?;
    Ok(Some(bak))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Build a state dir with pre-existing `keys/sign.key` + `keys/enc.key`
    /// generated via the real persistence helpers, so the format matches
    /// what `load_ed25519_priv` / `load_x25519_priv` would accept.
    fn seeded_state_dir() -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        let keys = dir.path().join("keys");
        fs::create_dir_all(&keys).unwrap();
        let old_sign = generate_ed25519();
        let old_enc = generate_x25519();
        save_ed25519_priv(&keys.join("sign.key"), &old_sign).unwrap();
        save_x25519_priv(&keys.join("enc.key"), &old_enc).unwrap();
        dir
    }

    #[test]
    fn test_rotate_keys_creates_backups_and_writes_new() {
        let dir = seeded_state_dir();
        let report = run_rotate_keys(dir.path(), false).expect("rotate");

        assert!(!report.dry_run);
        let backed_sign = report.backed_up_sign_path.expect("sign backed up");
        let backed_enc = report.backed_up_enc_path.expect("enc backed up");
        assert!(backed_sign.exists());
        assert!(backed_enc.exists());
        assert!(dir.path().join("keys/sign.key").exists());
        assert!(dir.path().join("keys/enc.key").exists());

        // Backup filenames carry the canonical `.bak.` separator + 16-char
        // UTC timestamp (`YYYYMMDDTHHMMSSZ`).
        let backed_sign_name = backed_sign.file_name().unwrap().to_str().unwrap();
        assert!(
            backed_sign_name.starts_with("sign.key.bak."),
            "{backed_sign_name}"
        );
        assert_eq!(
            backed_sign_name.len(),
            "sign.key.bak.20260515T143000Z".len(),
            "stamp length: {backed_sign_name}"
        );
    }

    #[test]
    fn test_rotate_keys_dry_run_does_not_touch_disk() {
        let dir = seeded_state_dir();
        let old_sign_bytes = fs::read(dir.path().join("keys/sign.key")).unwrap();
        let old_enc_bytes = fs::read(dir.path().join("keys/enc.key")).unwrap();

        let report = run_rotate_keys(dir.path(), true).unwrap();
        assert!(report.dry_run);
        assert!(report.backed_up_sign_path.is_none());
        assert!(report.backed_up_enc_path.is_none());

        // Original key files are byte-for-byte unchanged.
        assert_eq!(
            fs::read(dir.path().join("keys/sign.key")).unwrap(),
            old_sign_bytes
        );
        assert_eq!(
            fs::read(dir.path().join("keys/enc.key")).unwrap(),
            old_enc_bytes
        );
    }

    #[test]
    fn test_rotate_keys_returns_base64_32_byte_pubs() {
        let dir = seeded_state_dir();
        let report = run_rotate_keys(dir.path(), true).unwrap();
        let sign_pub = B64.decode(&report.new_sign_pub_b64).unwrap();
        let enc_pub = B64.decode(&report.new_enc_pub_b64).unwrap();
        assert_eq!(sign_pub.len(), 32);
        assert_eq!(enc_pub.len(), 32);
    }

    #[test]
    fn test_rotate_keys_changes_private_key_bytes() {
        let dir = seeded_state_dir();
        let old_sign_bytes = fs::read(dir.path().join("keys/sign.key")).unwrap();
        let old_enc_bytes = fs::read(dir.path().join("keys/enc.key")).unwrap();

        run_rotate_keys(dir.path(), false).unwrap();

        let new_sign_bytes = fs::read(dir.path().join("keys/sign.key")).unwrap();
        let new_enc_bytes = fs::read(dir.path().join("keys/enc.key")).unwrap();
        assert_ne!(old_sign_bytes, new_sign_bytes, "sign key must rotate");
        assert_ne!(old_enc_bytes, new_enc_bytes, "enc key must rotate");
    }

    #[test]
    fn test_rotate_keys_missing_keys_dir_errors() {
        let dir = tempdir().unwrap();
        // No keys/ subdir created — first rotation cannot proceed.
        let err = run_rotate_keys(dir.path(), false).unwrap_err();
        match err {
            RotateError::KeysDir { path, .. } => {
                assert!(path.ends_with("keys"));
            }
            other => panic!("expected KeysDir, got {other:?}"),
        }
    }

    #[test]
    fn test_rotate_keys_no_existing_keys_still_writes_new() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("keys")).unwrap();
        // keys/ exists but is empty — operator may have wiped pre-rotation.
        let report = run_rotate_keys(dir.path(), false).unwrap();
        assert!(report.backed_up_sign_path.is_none());
        assert!(report.backed_up_enc_path.is_none());
        assert!(dir.path().join("keys/sign.key").exists());
        assert!(dir.path().join("keys/enc.key").exists());
    }

    #[test]
    fn test_rotate_keys_dry_run_yields_fresh_keypair_each_call() {
        let dir = seeded_state_dir();
        let r1 = run_rotate_keys(dir.path(), true).unwrap();
        let r2 = run_rotate_keys(dir.path(), true).unwrap();
        // Two dry runs generate different new keypairs (each call freshly
        // randomizes), so the pubs DIFFER — confirming the function isn't
        // accidentally caching.  Bytes on disk are unchanged regardless.
        assert_ne!(r1.new_sign_pub_b64, r2.new_sign_pub_b64);
        assert_ne!(r1.new_enc_pub_b64, r2.new_enc_pub_b64);
    }

    #[test]
    fn test_backup_if_exists_preserves_extension_chain() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("sign.key");
        fs::write(&p, b"old").unwrap();
        let bak = backup_if_exists(&p, "20260515T143000Z").unwrap().unwrap();
        assert_eq!(
            bak.file_name().unwrap().to_str().unwrap(),
            "sign.key.bak.20260515T143000Z"
        );
        assert!(bak.exists());
        assert!(!p.exists(), "original must have been renamed away");
    }

    #[test]
    fn test_backup_if_exists_returns_none_for_missing() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("nope");
        let res = backup_if_exists(&missing, "stamp").unwrap();
        assert!(res.is_none());
    }
}
