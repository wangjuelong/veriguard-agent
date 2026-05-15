//! Linux `systemd` service **uninstall** (A.8.4) — symmetric companion
//! to [`super::systemd`].
//!
//! Reverses an A.8.1 install by:
//!
//! 1. (Optional) `systemctl disable --now <name>.service` to stop the
//!    running daemon and remove the multi-user.target symlink.
//! 2. Removing `/etc/systemd/system/<name>.service`.
//! 3. `systemctl daemon-reload` so systemd forgets the unit.
//! 4. (Optional, **DESTRUCTIVE**) `rm -r <state_dir>` to wipe keys,
//!    install pack, and the executed-packs blacklist.
//!
//! Identifier validation reuses [`super::systemd::validate_identifier`]
//! so the same hardening (no `\n`, `=`, shell metachars) applies.
//!
//! ## Hooked-up macOS / Windows
//!
//! The [`super::uninstall_service`] dispatcher returns a clear
//! "not yet implemented" error on non-Linux hosts; the launchd and
//! Windows SCM uninstall paths land in A.8.2 / A.8.3 respectively.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use log::warn;

use super::error::InstallError;
use super::systemd::{
    default_unit_path, validate_identifier, DEFAULT_SERVICE_NAME, DEFAULT_STATE_DIR,
};

/// Configuration for a systemd uninstall.
#[derive(Debug, Clone)]
pub struct SystemdUninstallConfig {
    /// Systemd unit name to remove (no `.service` suffix).
    pub service_name: String,
    /// State directory to optionally purge (matches the install's
    /// `--state-dir`).  Only deleted when `purge_state == true`.
    pub state_dir: PathBuf,
    /// If true, run `systemctl disable --now` before removing the unit
    /// file.  Stop-then-disable is the operator-friendly default.
    pub disable_first: bool,
    /// **DESTRUCTIVE** — when true, recursively delete `state_dir` after
    /// removing the service.  This wipes the agent's Ed25519 + X25519
    /// private keys, the install pack, and the executed-packs blacklist.
    /// Always defaults to `false`.
    pub purge_state: bool,
    /// If true, print the planned actions and return without touching
    /// disk or invoking `systemctl`.
    pub dry_run: bool,
}

impl Default for SystemdUninstallConfig {
    fn default() -> Self {
        Self {
            service_name: DEFAULT_SERVICE_NAME.to_string(),
            state_dir: PathBuf::from(DEFAULT_STATE_DIR),
            disable_first: true,
            purge_state: false,
            dry_run: false,
        }
    }
}

/// Outcome of a systemd uninstall run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdUninstallReport {
    /// Path of the unit file the uninstall targeted.
    pub unit_path: PathBuf,
    /// Whether `systemctl disable --now` was actually invoked (and
    /// succeeded).  False in dry-run or when `disable_first == false`.
    pub disabled: bool,
    /// Whether the unit file was actually removed.  False if the file
    /// didn't exist (already uninstalled) — a no-op uninstall is OK and
    /// is *not* surfaced as an error.
    pub removed_unit: bool,
    /// Whether `systemctl daemon-reload` ran after removal.
    pub daemon_reloaded: bool,
    /// Whether `state_dir` was purged.  False in dry-run, when
    /// `purge_state == false`, or when the directory didn't exist.
    pub purged_state: bool,
}

/// Disable + remove the systemd unit, optionally purge `state_dir`.
///
/// In `dry_run` mode this prints the planned actions and returns a
/// zero-flag report without touching the host.
pub fn uninstall_systemd(
    config: &SystemdUninstallConfig,
) -> Result<SystemdUninstallReport, InstallError> {
    validate_identifier(&config.service_name, "service_name")?;
    let unit_path = default_unit_path(&config.service_name);

    if config.dry_run {
        println!("--- uninstall dry-run plan ({}) ---", config.service_name);
        if config.disable_first {
            println!(
                "would run: systemctl disable --now {}.service",
                config.service_name
            );
        }
        println!("would remove: {}", unit_path.display());
        println!("would run: systemctl daemon-reload");
        if config.purge_state {
            println!("would remove (recursively): {}", config.state_dir.display());
        }
        return Ok(SystemdUninstallReport {
            unit_path,
            disabled: false,
            removed_unit: false,
            daemon_reloaded: false,
            purged_state: false,
        });
    }

    // 1. Disable first.  We do NOT error out if disable fails — the
    //    common reason is "service was never enabled", in which case we
    //    still want to clean up the stale unit file.  A genuine
    //    permission error will resurface when we try to remove the unit
    //    file (which lives under /etc and also needs root).
    let disabled = if config.disable_first {
        match systemctl_disable_now(&config.service_name) {
            Ok(()) => true,
            Err(e) => {
                warn!("uninstall: systemctl disable --now failed (continuing): {e}");
                false
            }
        }
    } else {
        false
    };

    // 2. Remove the unit file.  Missing file is OK (already uninstalled).
    let removed_unit = remove_unit_file(&unit_path)?;

    // 3. daemon-reload so systemd forgets the unit.  Best-effort — the
    //    only way this fails is if systemctl itself is gone (no systemd
    //    on this host), in which case the unit file was already a no-op.
    let daemon_reloaded = systemctl_daemon_reload_optional();

    // 4. Optional state-dir purge — explicit operator opt-in only.
    let purged_state = if config.purge_state {
        purge_state_dir(&config.state_dir)?
    } else {
        false
    };

    Ok(SystemdUninstallReport {
        unit_path,
        disabled,
        removed_unit,
        daemon_reloaded,
        purged_state,
    })
}

fn systemctl_disable_now(service_name: &str) -> Result<(), InstallError> {
    let status = Command::new("systemctl")
        .args(["disable", "--now", &format!("{service_name}.service")])
        .status()
        .map_err(|e| InstallError::SystemctlSpawn(e.to_string()))?;
    if !status.success() {
        return Err(InstallError::SystemctlNonZero {
            args: format!("disable --now {service_name}.service"),
            code: status.code(),
        });
    }
    Ok(())
}

fn systemctl_daemon_reload_optional() -> bool {
    Command::new("systemctl")
        .arg("daemon-reload")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn remove_unit_file(path: &Path) -> Result<bool, InstallError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(InstallError::Io {
            op: "remove unit file",
            path: path.to_path_buf(),
            err: e.to_string(),
        }),
    }
}

fn purge_state_dir(path: &Path) -> Result<bool, InstallError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(InstallError::Io {
            op: "remove_dir_all state dir",
            path: path.to_path_buf(),
            err: e.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn cfg() -> SystemdUninstallConfig {
        SystemdUninstallConfig::default()
    }

    #[test]
    fn test_uninstall_dry_run_does_not_touch_disk() {
        let mut c = cfg();
        c.dry_run = true;
        let report = uninstall_systemd(&c).unwrap();
        assert!(!report.disabled);
        assert!(!report.removed_unit);
        assert!(!report.daemon_reloaded);
        assert!(!report.purged_state);
        assert_eq!(
            report.unit_path,
            PathBuf::from("/etc/systemd/system/veriguard-agent.service")
        );
    }

    #[test]
    fn test_uninstall_dry_run_with_purge() {
        let mut c = cfg();
        c.dry_run = true;
        c.purge_state = true;
        c.state_dir = PathBuf::from("/srv/veriguard");
        let report = uninstall_systemd(&c).unwrap();
        // Dry-run never actually purges, but the config flag flows through.
        assert!(!report.purged_state);
        assert_eq!(
            report.unit_path.parent().unwrap(),
            Path::new("/etc/systemd/system")
        );
    }

    #[test]
    fn test_uninstall_rejects_empty_service_name() {
        let mut c = cfg();
        c.service_name = "".to_string();
        let err = uninstall_systemd(&c).unwrap_err();
        assert!(matches!(err, InstallError::EmptyField("service_name")));
    }

    #[test]
    fn test_uninstall_rejects_injection_in_service_name() {
        let mut c = cfg();
        c.service_name = "evil; rm -rf /".to_string();
        let err = uninstall_systemd(&c).unwrap_err();
        assert!(matches!(
            err,
            InstallError::IdentifierBadChar {
                field: "service_name",
                ..
            }
        ));
    }

    #[test]
    fn test_uninstall_rejects_oversized_service_name() {
        let mut c = cfg();
        c.service_name = "x".repeat(65);
        let err = uninstall_systemd(&c).unwrap_err();
        assert!(matches!(
            err,
            InstallError::IdentifierTooLong {
                field: "service_name",
                len: 65
            }
        ));
    }

    #[test]
    fn test_remove_unit_file_returns_false_for_missing() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("nope.service");
        let removed = remove_unit_file(&missing).unwrap();
        assert!(!removed, "missing unit must return Ok(false), not error");
    }

    #[test]
    fn test_remove_unit_file_removes_existing() {
        let dir = tempdir().unwrap();
        let existing = dir.path().join("svc.service");
        fs::write(&existing, b"stub unit").unwrap();
        let removed = remove_unit_file(&existing).unwrap();
        assert!(removed);
        assert!(!existing.exists());
    }

    #[test]
    fn test_purge_state_dir_handles_missing() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("vanish");
        let purged = purge_state_dir(&missing).unwrap();
        assert!(!purged);
    }

    #[test]
    fn test_purge_state_dir_removes_recursive_tree() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("state");
        fs::create_dir_all(target.join("keys")).unwrap();
        fs::write(target.join("keys/sign.key"), b"x").unwrap();
        fs::write(target.join("keys/enc.key"), b"y").unwrap();
        fs::write(target.join("install-pack.json"), b"{}").unwrap();
        fs::write(target.join("executed-packs.json"), b"{}").unwrap();
        let purged = purge_state_dir(&target).unwrap();
        assert!(purged);
        assert!(!target.exists());
    }

    #[test]
    fn test_default_config_does_not_purge() {
        let c = SystemdUninstallConfig::default();
        assert!(!c.purge_state, "purge_state must default to false");
        assert!(c.disable_first, "disable_first must default to true");
        assert!(!c.dry_run);
        assert_eq!(c.service_name, "veriguard-agent");
        assert_eq!(c.state_dir, PathBuf::from("/var/lib/veriguard"));
    }
}
