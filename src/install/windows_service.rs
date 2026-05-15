//! Windows Service Control Manager (SCM) install (A.8.3) — symmetric
//! companion to [`super::systemd`] and [`super::launchd`] for hosts
//! running Windows.
//!
//! Drives the built-in `sc.exe` CLI rather than linking the Windows
//! service-management Win32 API directly. The CLI route keeps the agent
//! crate platform-independent at compile time (cargo on Linux / macOS
//! still type-checks this module via the dispatcher's `cfg` switch) and
//! matches what most install scripts use anyway.
//!
//! ## Service account
//!
//! Windows services run under a Windows principal, not a POSIX uid. We
//! default to `NT AUTHORITY\NetworkService` — a built-in, less-privileged
//! account with network access (sufficient for HTTP poll + DNS). The
//! `SystemdConfig::service_user` field is **ignored on Windows** because
//! its Linux/macOS spelling (`veriguard`) is not a valid Windows account
//! identifier; operators who need a domain account or local user must
//! edit the generated sc.exe args (which this module exposes as
//! [`render_sc_create_args`] for inspection).
//!
//! ## Hardening
//!
//! - `start= auto` — service starts at boot.
//! - `obj= "NT AUTHORITY\NetworkService"` — minimal-privilege built-in.
//! - The `binPath=` argument quotes the binary path so spaces inside
//!   `C:\Program Files\Veriguard\` survive sc.exe's tokenizer.

use std::path::PathBuf;
use std::process::Command;

use super::error::InstallError;
use super::systemd::{validate_absolute, validate_identifier, SystemdConfig, SystemdInstallReport};
use super::uninstall::{SystemdUninstallConfig, SystemdUninstallReport};

/// Windows service display name shown in `services.msc`.
pub const DEFAULT_DISPLAY_NAME: &str = "Veriguard Agent (C1)";

/// Windows service description shown in `services.msc`.
pub const DEFAULT_DESCRIPTION: &str =
    "Veriguard 平台 Mode A 在线轮询 + Mode C 离线包执行 Agent (forked from OpenAEV-Platform/agent).";

/// Default Windows service principal — built-in, less-privileged account
/// with network access. Overridable post-install by editing sc.exe's
/// `obj=` field.
pub const DEFAULT_SERVICE_ACCOUNT: &str = "NT AUTHORITY\\NetworkService";

/// Render the `sc.exe create` argument vector. Pure — no I/O.
///
/// Output is a `Vec<String>` ready to pass to [`std::process::Command::args`].
/// The first element is the subcommand ("create"); subsequent elements
/// follow sc.exe's `key= value` convention (space **after** the `=` — sc
/// is one of the few CLIs where that matters).
///
/// Fails on invalid `service_name` characters or non-absolute paths so
/// a malicious caller cannot smuggle extra sc.exe options past us.
pub fn render_sc_create_args(config: &SystemdConfig) -> Result<Vec<String>, InstallError> {
    validate_identifier(&config.service_name, "service_name")?;
    validate_absolute(&config.binary_path, "binary_path")?;
    validate_absolute(&config.state_dir, "state_dir")?;

    let binary = config
        .binary_path
        .to_str()
        .ok_or(InstallError::NonUtf8Path("binary_path"))?;
    let state_dir = config
        .state_dir
        .to_str()
        .ok_or(InstallError::NonUtf8Path("state_dir"))?;

    // sc.exe binPath wants the binary + args as ONE quoted string so the
    // service manager records the exact ImagePath. We double-quote the
    // binary and the state_dir so embedded spaces (Program Files /
    // ProgramData) survive sc.exe's tokenizer.
    let bin_path = format!("\"{binary}\" run --state-dir \"{state_dir}\"");

    Ok(vec![
        "create".to_string(),
        config.service_name.clone(),
        "binPath=".to_string(),
        bin_path,
        "start=".to_string(),
        "auto".to_string(),
        "obj=".to_string(),
        DEFAULT_SERVICE_ACCOUNT.to_string(),
        "DisplayName=".to_string(),
        DEFAULT_DISPLAY_NAME.to_string(),
    ])
}

/// Install the Windows service via `sc.exe create`, then `sc.exe
/// description` to set the operator-visible description, then optionally
/// `sc.exe start` if `enable_on_install`.
///
/// In `dry_run` mode this prints the planned sc.exe commands and returns
/// without invoking anything.
///
/// The returned [`SystemdInstallReport`] reuses Linux field names; on
/// Windows `unit_path` holds the synthetic value
/// `sc:<service_name>` to give callers an identifier-shaped reference
/// without a filesystem path (Windows services are SCM registry rows,
/// not files on disk).
pub fn install_windows(config: &SystemdConfig) -> Result<SystemdInstallReport, InstallError> {
    let args = render_sc_create_args(config)?;
    let unit_path = PathBuf::from(format!("sc:{}", config.service_name));
    let unit_contents = format!("sc.exe {}", args.join(" "));

    if config.dry_run {
        println!("--- sc.exe create (dry-run, not executed) ---");
        println!("{unit_contents}");
        if config.enable_on_install {
            println!("--- sc.exe start {} (dry-run) ---", config.service_name);
        }
        return Ok(SystemdInstallReport {
            unit_path,
            unit_contents,
            wrote_unit_file: false,
            enabled: false,
        });
    }

    sc_run(&args)?;
    sc_set_description(&config.service_name, DEFAULT_DESCRIPTION)?;

    let enabled = if config.enable_on_install {
        sc_start(&config.service_name)?;
        true
    } else {
        false
    };

    Ok(SystemdInstallReport {
        unit_path,
        unit_contents,
        wrote_unit_file: true, // SCM accepted the create — analogous to "unit written"
        enabled,
    })
}

/// Stop + delete the Windows service, optionally purge `state_dir`.
pub fn uninstall_windows(
    config: &SystemdUninstallConfig,
) -> Result<SystemdUninstallReport, InstallError> {
    validate_identifier(&config.service_name, "service_name")?;
    let unit_path = PathBuf::from(format!("sc:{}", config.service_name));

    if config.dry_run {
        println!(
            "--- Windows service uninstall dry-run plan ({}) ---",
            config.service_name
        );
        if config.disable_first {
            println!("would run: sc.exe stop {}", config.service_name);
        }
        println!("would run: sc.exe delete {}", config.service_name);
        if config.purge_state {
            println!(
                "would recursively delete state dir: {}",
                config.state_dir.display()
            );
        }
        return Ok(SystemdUninstallReport {
            unit_path,
            disabled: false,
            removed_unit: false,
            daemon_reloaded: false,
            purged_state: false,
        });
    }

    let disabled = if config.disable_first {
        match sc_stop(&config.service_name) {
            Ok(()) => true,
            Err(InstallError::ToolNonZero { code, .. }) => {
                // sc stop returns 1062 (ERROR_SERVICE_NOT_ACTIVE) if the
                // service is already stopped — idempotent, log + skip.
                log::warn!(
                    "sc.exe stop {} returned {code:?} — service likely already stopped",
                    config.service_name
                );
                false
            }
            Err(other) => return Err(other),
        }
    } else {
        false
    };

    sc_delete(&config.service_name)?;

    let purged_state = if config.purge_state {
        purge_state_dir(&config.state_dir)?
    } else {
        false
    };

    Ok(SystemdUninstallReport {
        unit_path,
        disabled,
        removed_unit: true,
        daemon_reloaded: false, // No SCM equivalent of daemon-reload
        purged_state,
    })
}

// ---- private I/O helpers ----------------------------------------------------

fn sc_run(args: &[String]) -> Result<(), InstallError> {
    let status =
        Command::new("sc.exe")
            .args(args)
            .status()
            .map_err(|e| InstallError::ToolSpawn {
                tool: "sc.exe",
                err: e.to_string(),
            })?;
    if !status.success() {
        return Err(InstallError::ToolNonZero {
            tool: "sc.exe",
            args: args.join(" "),
            code: status.code(),
        });
    }
    Ok(())
}

fn sc_set_description(service_name: &str, description: &str) -> Result<(), InstallError> {
    let args = [
        "description".to_string(),
        service_name.to_string(),
        description.to_string(),
    ];
    sc_run(&args)
}

fn sc_start(service_name: &str) -> Result<(), InstallError> {
    let args = ["start".to_string(), service_name.to_string()];
    sc_run(&args)
}

fn sc_stop(service_name: &str) -> Result<(), InstallError> {
    let args = ["stop".to_string(), service_name.to_string()];
    sc_run(&args)
}

fn sc_delete(service_name: &str) -> Result<(), InstallError> {
    let args = ["delete".to_string(), service_name.to_string()];
    sc_run(&args)
}

fn purge_state_dir(state_dir: &std::path::Path) -> Result<bool, InstallError> {
    if !state_dir.exists() {
        return Ok(false);
    }
    log::warn!(
        "windows uninstall: purging state dir {} (destructive — keys wiped)",
        state_dir.display()
    );
    std::fs::remove_dir_all(state_dir).map_err(|e| InstallError::Io {
        op: "purge state_dir",
        path: state_dir.to_path_buf(),
        err: e.to_string(),
    })?;
    Ok(true)
}

// ---- tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SystemdConfig {
        SystemdConfig {
            binary_path: PathBuf::from("/usr/local/bin/veriguard-agent"),
            state_dir: PathBuf::from("/var/lib/veriguard"),
            service_name: "veriguard-agent".to_string(),
            service_user: "veriguard".to_string(),
            enable_on_install: true,
            dry_run: false,
        }
    }

    #[test]
    fn test_render_sc_args_contains_required_pairs() {
        let args = render_sc_create_args(&cfg()).unwrap();
        // Subcommand + service name come first.
        assert_eq!(args[0], "create");
        assert_eq!(args[1], "veriguard-agent");
        // sc.exe's key= value convention — pairs must be adjacent.
        assert!(args.windows(2).any(|w| w[0] == "binPath="
            && w[1].contains("/usr/local/bin/veriguard-agent")
            && w[1].contains("run")
            && w[1].contains("--state-dir")
            && w[1].contains("/var/lib/veriguard")));
        assert!(args.windows(2).any(|w| w[0] == "start=" && w[1] == "auto"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "obj=" && w[1] == DEFAULT_SERVICE_ACCOUNT));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "DisplayName=" && w[1] == DEFAULT_DISPLAY_NAME));
    }

    #[test]
    fn test_render_sc_args_quotes_paths() {
        let mut c = cfg();
        c.binary_path = PathBuf::from("/opt/program files/veriguard/agent");
        c.state_dir = PathBuf::from("/opt/program data/veriguard");
        let args = render_sc_create_args(&c).unwrap();
        let bin_path_arg = args
            .iter()
            .enumerate()
            .find_map(|(i, a)| {
                if a == "binPath=" {
                    Some(&args[i + 1])
                } else {
                    None
                }
            })
            .unwrap();
        // Quoted binary so embedded spaces survive sc.exe's tokenizer.
        assert!(bin_path_arg.contains("\"/opt/program files/veriguard/agent\""));
        // Quoted state_dir argument inside the same binPath= string.
        assert!(bin_path_arg.contains("\"/opt/program data/veriguard\""));
    }

    #[test]
    fn test_render_rejects_bad_service_name() {
        let mut c = cfg();
        c.service_name = "bad name\\evil".into();
        let err = render_sc_create_args(&c).unwrap_err();
        match err {
            InstallError::IdentifierBadChar { field, .. } => {
                assert_eq!(field, "service_name");
            }
            other => panic!("expected IdentifierBadChar, got {other:?}"),
        }
    }

    #[test]
    fn test_render_rejects_relative_binary_path() {
        let mut c = cfg();
        c.binary_path = PathBuf::from("relative/agent.exe");
        let err = render_sc_create_args(&c).unwrap_err();
        match err {
            InstallError::PathNotAbsolute { field, .. } => {
                assert_eq!(field, "binary_path");
            }
            other => panic!("expected PathNotAbsolute, got {other:?}"),
        }
    }

    #[test]
    fn test_install_dry_run_does_not_invoke_sc() {
        let mut c = cfg();
        c.dry_run = true;
        let report = install_windows(&c).unwrap();
        assert!(!report.wrote_unit_file);
        assert!(!report.enabled);
        assert!(report.unit_contents.contains("sc.exe create"));
        assert!(report.unit_contents.contains("veriguard-agent"));
    }

    #[test]
    fn test_uninstall_dry_run_emits_plan() {
        let c = SystemdUninstallConfig {
            dry_run: true,
            ..SystemdUninstallConfig::default()
        };
        let report = uninstall_windows(&c).unwrap();
        assert!(!report.disabled);
        assert!(!report.removed_unit);
        assert!(!report.purged_state);
    }

    #[test]
    fn test_unit_path_uses_sc_prefix() {
        let mut c = cfg();
        c.dry_run = true;
        let report = install_windows(&c).unwrap();
        assert_eq!(report.unit_path, PathBuf::from("sc:veriguard-agent"));
    }
}
