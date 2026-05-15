//! Service install + uninstall + rotate-keys (A.8.1 / A.8.2 / A.8.3 /
//! A.8.4 / A.8.5).
//!
//! All three host platforms (Linux systemd, macOS launchd, Windows SCM)
//! share the same [`SystemdConfig`] / [`SystemdUninstallConfig`] input
//! types and report shapes. The naming reflects the original A.8.1 design;
//! the field set (binary_path, state_dir, service_name, service_user,
//! enable_on_install, dry_run) is cross-platform in spirit.
//!
//! ## Platform dispatch
//!
//! Both [`install_service`] and [`uninstall_service`] select an
//! implementation by `cfg(target_os = ...)`:
//!
//! | host        | impl              | status |
//! |-------------|-------------------|--------|
//! | `linux`     | `systemd`         | ✅ A.8.1 install / A.8.4 uninstall |
//! | `macos`     | `launchd`         | ✅ A.8.2 (plist + `launchctl`) |
//! | `windows`   | `windows_service` | ✅ A.8.3 (`sc.exe` create/start/delete) |
//! | other unix  | (unsupported)     | — returns `InstallError` |

pub mod error;
pub mod launchd;
pub mod systemd;
pub mod uninstall;
pub mod windows_service;

// Re-exports for downstream callers — `#[allow(unused_imports)]` because
// the binary only consumes a few entry points directly; the rest is
// public surface for C1-Integration tests + cross-platform helpers.
#[allow(unused_imports)]
pub use error::InstallError;
#[allow(unused_imports)]
pub use launchd::{
    default_plist_path, install_launchd, launchd_label, render_plist, uninstall_launchd,
    DEFAULT_LAUNCHD_PLIST_DIR, LABEL_PREFIX,
};
#[allow(unused_imports)]
pub use systemd::{
    install_systemd, render_unit_file, SystemdConfig, SystemdInstallReport, DEFAULT_BINARY_PATH,
    DEFAULT_SERVICE_NAME, DEFAULT_SERVICE_USER, DEFAULT_STATE_DIR,
};
#[allow(unused_imports)]
pub use uninstall::{uninstall_systemd, SystemdUninstallConfig, SystemdUninstallReport};
#[allow(unused_imports)]
pub use windows_service::{
    install_windows, render_sc_create_args, uninstall_windows, DEFAULT_DESCRIPTION,
    DEFAULT_DISPLAY_NAME, DEFAULT_SERVICE_ACCOUNT,
};

/// Cross-platform install entry point.  Dispatches to the platform impl
/// at compile time; on unsupported platforms returns a clear error.
#[cfg(target_os = "linux")]
pub fn install_service(config: &SystemdConfig) -> Result<SystemdInstallReport, InstallError> {
    install_systemd(config)
}

/// macOS launchd install (A.8.2) — `launchctl bootstrap system <plist>`.
#[cfg(target_os = "macos")]
pub fn install_service(config: &SystemdConfig) -> Result<SystemdInstallReport, InstallError> {
    install_launchd(config)
}

/// Windows SCM install (A.8.3) — `sc.exe create` + (optionally) `sc.exe start`.
#[cfg(target_os = "windows")]
pub fn install_service(config: &SystemdConfig) -> Result<SystemdInstallReport, InstallError> {
    install_windows(config)
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

/// macOS launchd uninstall (A.8.2) — `launchctl bootout system/<label>`.
#[cfg(target_os = "macos")]
pub fn uninstall_service(
    config: &SystemdUninstallConfig,
) -> Result<SystemdUninstallReport, InstallError> {
    uninstall_launchd(config)
}

/// Windows SCM uninstall (A.8.3) — `sc.exe stop` + `sc.exe delete`.
#[cfg(target_os = "windows")]
pub fn uninstall_service(
    config: &SystemdUninstallConfig,
) -> Result<SystemdUninstallReport, InstallError> {
    uninstall_windows(config)
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
