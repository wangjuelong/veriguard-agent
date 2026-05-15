//! Errors raised by service-install routines.
//!
//! Variants are intentionally surfaced for tests + diagnostic output;
//! callers should map any error to "install failed — re-run with `sudo`
//! or check `journalctl -u veriguard-agent`".

use std::path::PathBuf;

use thiserror::Error;

/// Errors from `install_*` paths.
#[derive(Debug, Error)]
pub enum InstallError {
    /// A required config field was empty.
    #[error("install config field {0:?} must not be empty")]
    EmptyField(&'static str),

    /// An identifier field exceeded the 64-char unit-file limit.
    #[error("install config field {field:?} too long: {len} > 64")]
    IdentifierTooLong {
        /// Field name (alphabetic only, no whitespace).
        field: &'static str,
        /// Actual length in bytes.
        len: usize,
    },

    /// An identifier field contained a non-`[A-Za-z0-9_-]` character.
    /// Rejecting these blocks `\n`, `=`, ` ` and quoting from smuggling
    /// alternate directives into the rendered unit file.
    #[error("install config field {field:?} contains disallowed character {ch:?}")]
    IdentifierBadChar {
        /// Field name (alphabetic only, no whitespace).
        field: &'static str,
        /// First disallowed character encountered.
        ch: char,
    },

    /// A path field was relative; we require absolute paths so the
    /// resulting unit file works regardless of cwd at boot time.
    #[error("install config field {field:?} must be absolute, got {path:?}")]
    PathNotAbsolute {
        /// Field name.
        field: &'static str,
        /// Offending path.
        path: PathBuf,
    },

    /// A path contained bytes that don't decode to UTF-8; the systemd
    /// unit-file format is byte-oriented but our renderer requires UTF-8
    /// so the file is human-readable.
    #[error("install config field {0:?} is not valid UTF-8")]
    NonUtf8Path(&'static str),

    /// Filesystem error while writing the unit file or creating its
    /// parent directory.
    #[error("install I/O ({op}) on {path:?}: {err}")]
    Io {
        /// Operation name (short, alphabetic — no whitespace).
        op: &'static str,
        /// Path being operated on.
        path: PathBuf,
        /// Wrapped `std::io::Error` rendered via `to_string`.
        err: String,
    },

    /// `systemctl` could not be exec'd (likely not installed or PATH
    /// missing).  Re-running under a Linux host with systemd resolves.
    #[error("failed to spawn systemctl: {0}")]
    SystemctlSpawn(String),

    /// `systemctl` exited non-zero.  Usually a permission error (no
    /// sudo) or invalid unit file — both already surfaced by systemd's
    /// own stderr.
    #[error("systemctl {args:?} exited non-zero (code: {code:?})")]
    SystemctlNonZero {
        /// Command-line args passed to systemctl (joined with spaces).
        args: String,
        /// Exit code if available (`None` for signal-terminated).
        code: Option<i32>,
    },
}
