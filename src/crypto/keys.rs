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

fn save_raw(path: &Path, bytes: &[u8; PRIVATE_KEY_LEN]) -> Result<(), KeyIoError> {
    let tmp_path = tmp_path_for(path);

    // Make sure the parent directory exists.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| KeyIoError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    // Write to tmp file, then rename into place.
    {
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
        file.write_all(bytes).map_err(|source| KeyIoError::Io {
            path: tmp_path.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| KeyIoError::Io {
            path: tmp_path.clone(),
            source,
        })?;
    }

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
}
