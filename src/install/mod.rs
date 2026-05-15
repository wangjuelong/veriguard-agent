//! Service install + (future) uninstall + rotate-keys (A.8.1–A.8.5).
//!
//! Currently implements **Linux systemd** (A.8.1).  macOS launchd (A.8.2)
//! and Windows SCM (A.8.3) land in subsequent commits; uninstall (A.8.4)
//! and rotate-keys (A.8.5) follow.
//!
//! ## Platform dispatch
//!
//! The public [`install_service`] entry point selects an implementation
//! by `cfg(target_os = ...)`:
//!
//! | host        | impl              | status |
//! |-------------|-------------------|--------|
//! | `linux`     | `systemd`         | ✅ A.8.1 |
//! | `macos`     | `launchd`         | ⏳ A.8.2 |
//! | `windows`   | `windows_service` | ⏳ A.8.3 |
//! | other unix  | (unsupported)     | — returns `InstallError` |
//!
//! Non-Linux hosts currently surface a clear "not yet implemented"
//! error so operators on macOS / Windows know to wait for A.8.2 / A.8.3
//! rather than silently no-op.

pub mod error;
pub mod systemd;

// Re-exports for downstream callers — `#[allow(unused_imports)]` because
// the binary only consumes `install_service` + `SystemdConfig` directly;
// the helpers below are public surface for C1-Integration tests + future
// platform implementations (A.8.2 / A.8.3).
#[allow(unused_imports)]
pub use error::InstallError;
#[allow(unused_imports)]
pub use systemd::{
    install_systemd, render_unit_file, SystemdConfig, SystemdInstallReport, DEFAULT_BINARY_PATH,
    DEFAULT_SERVICE_NAME, DEFAULT_SERVICE_USER, DEFAULT_STATE_DIR,
};

/// Cross-platform install entry point.  Dispatches to the platform impl
/// at compile time; on unsupported platforms returns a clear error.
#[cfg(target_os = "linux")]
pub fn install_service(config: &SystemdConfig) -> Result<SystemdInstallReport, InstallError> {
    install_systemd(config)
}

/// macOS placeholder — A.8.2 implements launchd plist install.
#[cfg(target_os = "macos")]
pub fn install_service(_config: &SystemdConfig) -> Result<SystemdInstallReport, InstallError> {
    Err(InstallError::SystemctlSpawn(
        "macOS launchd install is implemented in A.8.2 (pending)".into(),
    ))
}

/// Windows placeholder — A.8.3 implements SCM service install.
#[cfg(target_os = "windows")]
pub fn install_service(_config: &SystemdConfig) -> Result<SystemdInstallReport, InstallError> {
    Err(InstallError::SystemctlSpawn(
        "Windows SCM install is implemented in A.8.3 (pending)".into(),
    ))
}

/// Catch-all for unsupported Unix variants (FreeBSD, illumos, ...).
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn install_service(_config: &SystemdConfig) -> Result<SystemdInstallReport, InstallError> {
    Err(InstallError::SystemctlSpawn(
        "service install is not supported on this platform; \
         run `veriguard-agent run` directly under your own init system"
            .into(),
    ))
}
