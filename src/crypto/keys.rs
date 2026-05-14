//! On-disk persistence for Ed25519 / X25519 private keys.
//!
//! ## File format
//!
//! Each file stores exactly the raw 32-byte private scalar (no PEM, no JSON,
//! no version header).  Length is fixed so a corrupted file is detected
//! immediately on load.
//!
//! ## Atomicity
//!
//! `save_*` writes to `<path>.tmp`, fsyncs it, then renames into place.  A
//! crash mid-write leaves the previous file (or nothing) — never a half
//! written file.
//!
//! ## POSIX permissions
//!
//! Files are saved with mode `0o600` (owner read-write only).  `load_*` on
//! Unix refuses to read a key whose mode does not equal `0o600` exactly — a
//! world-readable key file is a configuration error the operator must fix
//! manually before we touch it.  On Windows POSIX permissions are not
//! enforced; ACL hardening is tracked for a follow-up PR.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;

use super::ed25519::Ed25519PrivateKey;
use super::x25519_box::X25519PrivateKey;

/// Errors emitted by the key save / load API.
#[derive(Debug, Error)]
pub enum KeyIoError {
    /// Underlying filesystem error.
    #[error("key I/O failed at {path:?}: {source}")]
    Io {
        /// The path that was being read or written.
        path: PathBuf,
        /// The underlying OS error.
        #[source]
        source: io::Error,
    },

    /// File contents had the wrong length for the requested key type.
    #[error("key file {path:?} has invalid length: expected {expected}, got {actual}")]
    WrongLength {
        /// The path that was being read.
        path: PathBuf,
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },

    /// File permissions are not `0o600`.  Reject before reading to avoid
    /// caching a leaked key.
    #[cfg(unix)]
    #[error("key file {path:?} has insecure permissions {mode:#o}; expected 0o600")]
    InsecurePermissions {
        /// The path that was being read.
        path: PathBuf,
        /// Actual mode bits (low 9 bits).
        mode: u32,
    },
}

/// Expected length for both Ed25519 and X25519 private keys (the raw scalar).
const PRIVATE_KEY_LEN: usize = 32;

/// Save an Ed25519 private key to disk with mode `0o600` (Unix).
pub fn save_ed25519_priv(path: &Path, key: &Ed25519PrivateKey) -> Result<(), KeyIoError> {
    save_raw(path, &key.to_bytes())
}

/// Load an Ed25519 private key from disk.  On Unix the file must have
/// permissions `0o600` exactly.
pub fn load_ed25519_priv(path: &Path) -> Result<Ed25519PrivateKey, KeyIoError> {
    let bytes = load_raw(path)?;
    Ok(Ed25519PrivateKey::from_bytes(&bytes))
}

/// Save an X25519 private key to disk with mode `0o600` (Unix).
pub fn save_x25519_priv(path: &Path, key: &X25519PrivateKey) -> Result<(), KeyIoError> {
    save_raw(path, &key.to_bytes())
}

/// Load an X25519 private key from disk.  On Unix the file must have
/// permissions `0o600` exactly.
pub fn load_x25519_priv(path: &Path) -> Result<X25519PrivateKey, KeyIoError> {
    let bytes = load_raw(path)?;
    Ok(X25519PrivateKey::from_bytes(&bytes))
}

/// RAII guard that removes a file on drop unless [`Self::disarm`] has been
/// called.  Used by [`save_raw`] so that any error between `OpenOptions::open`
/// and the successful `fs::rename` leaves no half-written tmp key file on
/// disk (which would either confuse a subsequent retry or, worse, persist
/// half of a secret in a world-readable cache).
struct TmpFileGuard {
    path: Option<PathBuf>,
}

impl TmpFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    /// Cancel cleanup — call after the tmp file has been successfully
    /// renamed into its final location.
    fn disarm(mut self) {
        self.path.take();
    }
}

impl Drop for TmpFileGuard {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            // Best-effort cleanup; we never want a cleanup failure to mask
            // the real error that triggered the drop.
            let _ = fs::remove_file(&p);
        }
    }
}

fn save_raw(path: &Path, bytes: &[u8; PRIVATE_KEY_LEN]) -> Result<(), KeyIoError> {
    let tmp_path = tmp_path_for(path);

    // Make sure the parent directory exists.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| KeyIoError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    // Open the tmp file *first* and arm the cleanup guard immediately so any
    // subsequent error (write / sync / permission / rename) leaves no
    // residual tmp file on disk.
    let mut opts = OpenOptions::new();
    opts.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&tmp_path).map_err(|source| KeyIoError::Io {
        path: tmp_path.clone(),
        source,
    })?;

    // From here on, on any early-return the `guard` deletes `tmp_path`.
    let guard = TmpFileGuard::new(tmp_path.clone());

    file.write_all(bytes).map_err(|source| KeyIoError::Io {
        path: tmp_path.clone(),
        source,
    })?;
    file.sync_all().map_err(|source| KeyIoError::Io {
        path: tmp_path.clone(),
        source,
    })?;
    drop(file);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Re-assert 0o600 in case umask trimmed bits on existing platforms.
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&tmp_path, perms).map_err(|source| KeyIoError::Io {
            path: tmp_path.clone(),
            source,
        })?;
    }

    fs::rename(&tmp_path, path).map_err(|source| KeyIoError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    // Successful rename — disarm the guard so its Drop does NOT delete the
    // file we just moved into place.
    guard.disarm();

    Ok(())
}

fn load_raw(path: &Path) -> Result<[u8; PRIVATE_KEY_LEN], KeyIoError> {
    let metadata = fs::metadata(path).map_err(|source| KeyIoError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(KeyIoError::InsecurePermissions {
                path: path.to_path_buf(),
                mode,
            });
        }
    }

    let actual_len = metadata.len() as usize;
    if actual_len != PRIVATE_KEY_LEN {
        return Err(KeyIoError::WrongLength {
            path: path.to_path_buf(),
            expected: PRIVATE_KEY_LEN,
            actual: actual_len,
        });
    }

    let mut file = File::open(path).map_err(|source| KeyIoError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut buf = [0u8; PRIVATE_KEY_LEN];
    file.read_exact(&mut buf).map_err(|source| KeyIoError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(buf)
}

fn tmp_path_for(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".tmp");
    PathBuf::from(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::generate_ed25519;
    use crate::crypto::x25519_box::generate_x25519;
    use tempfile::tempdir;

    #[test]
    fn test_save_load_ed25519_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ed25519.key");

        let original = generate_ed25519();
        let original_pub = original.public_key();
        save_ed25519_priv(&path, &original).expect("save");

        let loaded = load_ed25519_priv(&path).expect("load");
        let sig = loaded.sign(b"after-load");
        assert!(original_pub.verify(b"after-load", &sig));
    }

    #[test]
    fn test_save_load_x25519_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("x25519.key");

        let original = generate_x25519();
        let original_pub = original.public_key();
        save_x25519_priv(&path, &original).expect("save");

        let loaded = load_x25519_priv(&path).expect("load");
        assert_eq!(loaded.public_key(), original_pub);
    }

    #[cfg(unix)]
    #[test]
    fn test_save_sets_0600_perm() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("perm.key");

        save_ed25519_priv(&path, &generate_ed25519()).expect("save");

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "saved key must be 0o600, got {mode:#o}");
    }

    #[cfg(unix)]
    #[test]
    fn test_load_rejects_world_readable_perm() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("loose.key");

        save_ed25519_priv(&path, &generate_ed25519()).expect("save");
        // Tighten then loosen to 0o644 to simulate operator mistake.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let err = load_ed25519_priv(&path).expect_err("must reject 0o644");
        assert!(matches!(err, KeyIoError::InsecurePermissions { mode, .. } if mode == 0o644));
    }

    #[cfg(unix)]
    #[test]
    fn test_load_rejects_wrong_length() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("short.key");

        // 16 bytes is too short.
        fs::write(&path, [0u8; 16]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let err = load_ed25519_priv(&path).expect_err("must reject short key");
        assert!(matches!(
            err,
            KeyIoError::WrongLength {
                expected: 32,
                actual: 16,
                ..
            }
        ));
    }

    #[test]
    fn test_save_creates_missing_parent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested").join("subdir").join("key.bin");

        save_ed25519_priv(&path, &generate_ed25519()).expect("save creates parents");
        assert!(path.exists());
    }

    #[test]
    fn test_tmp_file_guard_removes_file_on_drop_when_armed() {
        // White-box test that the RAII guard cleans up the tmp file when
        // its owner returns early without disarming.  We construct a guard
        // directly because exercising the "rename fails" branch
        // deterministically across platforms is brittle.
        let dir = tempdir().unwrap();
        let tmp = dir.path().join("dangling.tmp");
        std::fs::write(&tmp, b"sensitive").unwrap();
        assert!(tmp.exists(), "fixture must be present");

        {
            let _g = TmpFileGuard::new(tmp.clone());
            // No `g.disarm()` — simulate an early-return from save_raw.
        }
        assert!(
            !tmp.exists(),
            "armed guard must delete the tmp file when dropped"
        );
    }

    #[test]
    fn test_tmp_file_guard_keeps_file_when_disarmed() {
        let dir = tempdir().unwrap();
        let tmp = dir.path().join("dangling.tmp");
        std::fs::write(&tmp, b"sensitive").unwrap();

        let g = TmpFileGuard::new(tmp.clone());
        g.disarm();
        assert!(
            tmp.exists(),
            "disarmed guard must NOT delete the tmp file (Drop is a no-op)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_save_rename_failure_cleans_up_tmp_file() {
        // Simulate a rename failure: make the parent directory read-only
        // AFTER the tmp file is written.  The rename should fail because we
        // cannot create the destination dentry inside a read-only dir.
        //
        // POSIX gives us no clean "rename fails" injection so we approximate
        // with a directory chmod 0500 (read+exec only).  This works on
        // tmpfs / ext4 / APFS used by `tempdir()`.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let restricted = dir.path().join("ro_parent");
        std::fs::create_dir(&restricted).unwrap();
        let path = restricted.join("key.bin");

        // Make the dir read-only, so the eventual `fs::rename` cannot land
        // a new dentry inside it.  We still need write to allow the
        // OpenOptions::open(tmp_path) line; the test order matters here
        // because save_raw opens the tmp INSIDE the same dir as `path`.
        //
        // To exercise the cleanup branch we need the tmp file write to
        // succeed but the rename to fail.  Easiest cross-FS trick: pre-
        // create `path` as a directory, so `fs::rename(tmp, dir)` returns
        // EISDIR / EEXIST.
        std::fs::create_dir(&path).unwrap();

        let err = save_ed25519_priv(&path, &generate_ed25519()).expect_err("rename must fail");
        match err {
            KeyIoError::Io { .. } => {}
            other => panic!("expected Io variant, got {other:?}"),
        }
        let tmp = tmp_path_for(&path);
        assert!(
            !tmp.exists(),
            "tmp file {tmp:?} must be cleaned up when rename fails"
        );
        // The pre-existing directory at `path` must still be there (we did
        // not touch it on the failure path).
        assert!(path.is_dir(), "pre-existing dentry preserved");
        // Reset perms so tempdir teardown succeeds.
        std::fs::set_permissions(&restricted, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
