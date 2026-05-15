//! Service install + uninstall + rotate-keys (A.8.1 / A.8.4 / A.8.5).
//!
//! Currently implements **Linux systemd** for install + uninstall.
//! macOS launchd (A.8.2) and Windows SCM (A.8.3) land in subsequent
//! commits.
//!
//! ## Platform dispatch
//!
//! Both [`install_service`] and [`uninstall_service`] select an
//! implementation by `cfg(target_os = ...)`:
//!
//! | host        | impl              | status |
//! |-------------|-------------------|--------|
//! | `linux`     | `systemd`         | ✅ A.8.1 install / A.8.4 uninstall |
//! | `macos`     | `launchd`         | ⏳ A.8.2 |
//! | `windows`   | `windows_service` | ⏳ A.8.3 |
//! | other unix  | (unsupported)     | — returns `InstallError` |
//!
//! Non-Linux hosts currently surface a clear "not yet implemented"
//! error so operators on macOS / Windows know to wait for A.8.2 / A.8.3
//! rather than silently no-op.

pub mod error;
pub mod systemd;
pub mod uninstall;

// Re-exports for downstream callers — `#[allow(unused_imports)]` because
// the binary only consumes a few entry points directly; the rest is
// public surface for C1-Integration tests + future platform impls
// (A.8.2 / A.8.3).
#[allow(unused_imports)]
pub use error::InstallError;
#[allow(unused_imports)]
pub use systemd::{
    install_systemd, render_unit_file, SystemdConfig, SystemdInstallReport, DEFAULT_BINARY_PATH,
    DEFAULT_SERVICE_NAME, DEFAULT_SERVICE_USER, DEFAULT_STATE_DIR,
};
#[allow(unused_imports)]
pub use uninstall::{uninstall_systemd, SystemdUninstallConfig, SystemdUninstallReport};

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

/// Cross-platform uninstall entry point — symmetric to [`install_service`].
#[cfg(target_os = "linux")]
pub fn uninstall_service(
    config: &SystemdUninstallConfig,
) -> Result<SystemdUninstallReport, InstallError> {
    uninstall_systemd(config)
}

/// macOS placeholder — A.8.2 implements launchd plist uninstall.
#[cfg(target_os = "macos")]
pub fn uninstall_service(
    _config: &SystemdUninstallConfig,
) -> Result<SystemdUninstallReport, InstallError> {
    Err(InstallError::SystemctlSpawn(
        "macOS launchd uninstall is implemented in A.8.2 (pending)".into(),
    ))
}

/// Windows placeholder — A.8.3 implements SCM service uninstall.
#[cfg(target_os = "windows")]
pub fn uninstall_service(
    _config: &SystemdUninstallConfig,
) -> Result<SystemdUninstallReport, InstallError> {
    Err(InstallError::SystemctlSpawn(
        "Windows SCM uninstall is implemented in A.8.3 (pending)".into(),
    ))
}

/// Catch-all for unsupported Unix variants (FreeBSD, illumos, ...).
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn uninstall_service(
    _config: &SystemdUninstallConfig,
) -> Result<SystemdUninstallReport, InstallError> {
    Err(InstallError::SystemctlSpawn(
        "service uninstall is not supported on this platform".into(),
    ))
}
