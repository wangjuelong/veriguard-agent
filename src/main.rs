mod api;
mod common;
mod config;
mod process;
mod windows;

// Veriguard 二开 (C1-Agent-1 + C1-Agent-2): 非对称密码学 + 离线包 onboarding
// + Mode A 在线 transport + capabilities + implant 子进程 — 通过 `run`
// 子命令统一对外。`crypto` / `onboard` 暴露的完整 API 还有
// X25519 box / install pack validation 等扩展面留给 C1-Integration 调用，
// `state` 预留给 Mode C 离线包回放，本 PR 暂未消费。
#[allow(dead_code)]
mod crypto;
#[allow(dead_code)]
mod onboard;
#[allow(dead_code)]
mod state;

// Veriguard 二开 (C1-Agent-3): Mode C `.vpack` / `.vresults` envelope
// serdes — wire-compatible with Java VpackSerializer / VresultsSerializer.
// Consumed by an upcoming `pack` subcommand executor; the API is already
// plumbed so C1-Integration can cross-language fixture-test against it.
#[allow(dead_code)]
mod pack;

// Veriguard 二开 (C1-Agent-3): service install (A.8.1 Linux systemd; A.8.2
// launchd / A.8.3 Windows-SCM stubs return clear "not yet implemented").
// `dead_code` allow is needed because cargo on non-Linux dev hosts sees
// the Linux-only systemd helpers as unreachable; the test suite still
// exercises them on every CI run.
#[allow(dead_code)]
mod install;

mod attribution;
mod capabilities;
mod implant;
mod target;
mod transport;

#[cfg(test)]
mod tests;

use log::{error, info};
use rolling_file::{BasicRollingFileAppender, RollingConditionBasic};
use std::env;
use std::fs::create_dir_all;
use std::ops::Deref;
use std::panic;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::thread::JoinHandle;

use crate::common::error_model::Error;
use crate::config::execution_details::ExecutionDetails;
use crate::config::settings::Settings;
use crate::process::agent_job;
use crate::process::{agent_cleanup, keep_alive};
use crate::windows::service::service_stub;

pub static THREADS_CONTROL: AtomicBool = AtomicBool::new(true);
const VERSION: &str = env!("CARGO_PKG_VERSION");
const PREFIX_LOG_NAME: &str = "openaev-agent.log";

// Get and log all errors from the agent execution
pub fn set_error_hook() {
    panic::set_hook(Box::new(|panic_info| {
        let (filename, line) = panic_info
            .location()
            .map(|loc| (loc.file(), loc.line()))
            .unwrap_or(("<unknown>", 0));

        let cause = panic_info
            .payload()
            .downcast_ref::<String>()
            .map(String::deref);

        let cause = cause.unwrap_or_else(|| {
            panic_info
                .payload()
                .downcast_ref::<&str>()
                .copied()
                .unwrap_or("<cause unknown>")
        });

        error!("An error occurred in file {filename:?} line {line:?}: {cause:?}");
    }));
}

fn compute_working_dir() -> PathBuf {
    let current_exe_path = env::current_exe().unwrap();
    current_exe_path.parent().unwrap().to_path_buf()
}

fn agent_start(settings_data: Settings, is_service: bool) -> Result<Vec<JoinHandle<()>>, Error> {
    let url = settings_data.openaev.url;
    let token = settings_data.openaev.token;
    let unsecured_certificate = settings_data.openaev.unsecured_certificate;
    let with_proxy = settings_data.openaev.with_proxy;
    let installation_mode = settings_data.openaev.installation_mode;
    let service_name = settings_data.openaev.service_name;
    let execution_details = ExecutionDetails::new(is_service).unwrap();
    info!(
        "ExecutionDetails : user {:?} -- is_elevated {:?} -- is_service {:?} ",
        execution_details.executed_by_user,
        execution_details.is_elevated,
        execution_details.is_service
    );

    let working_dir = compute_working_dir();
    create_dir_all(working_dir.join("runtimes")).expect("Failed to create runtimes directory");
    create_dir_all(working_dir.join("payloads")).expect("Failed to create payloads directory");

    let keep_alive_thread = keep_alive::ping(
        url.clone(),
        token.clone(),
        unsecured_certificate,
        with_proxy,
        installation_mode,
        service_name,
        execution_details.clone(),
    );
    // Starts the agent listening thread
    let agent_job_thread = agent_job::listen(
        url.clone(),
        token.clone(),
        unsecured_certificate,
        with_proxy,
        execution_details.clone(),
    );
    // Starts the cleanup thread
    let cleanup_thread = agent_cleanup::clean(settings_data.cleanup.clone());
    // Don't stop the exec until the listening thread is done
    Ok(vec![
        keep_alive_thread.unwrap(),
        agent_job_thread.unwrap(),
        cleanup_thread.unwrap(),
    ])
}

/// Veriguard 二开 CLI subcommand dispatch.
///
/// We retain upstream's zero-arg daemon path (so existing systemd /
/// Windows-service launchers keep working) and only route off if the user
/// passes a known subcommand.  This keeps the surface clearly partitioned
/// between "legacy daemon" and "二开 init/register" flows.
fn try_dispatch_subcommand() -> Option<Result<(), Error>> {
    use clap::Parser;

    let args: Vec<String> = env::args().collect();
    // Treat as legacy daemon when no args at all.
    if args.len() < 2 {
        return None;
    }
    // Only intercept subcommands we know about; everything else falls through
    // to the daemon path (which itself raises a clear error if it disagrees).
    match args[1].as_str() {
        "init" => Some(run_init_cli(VeriguardCli::parse())),
        "run" => Some(run_run_cli(VeriguardCli::parse())),
        "install" => Some(run_install_cli(VeriguardCli::parse())),
        "uninstall" => Some(run_uninstall_cli(VeriguardCli::parse())),
        "rotate-keys" => Some(run_rotate_keys_cli(VeriguardCli::parse())),
        "pack" => Some(run_pack_cli(VeriguardCli::parse())),
        _ => None,
    }
}

#[derive(clap::Parser, Debug)]
#[command(
    name = "veriguard-agent",
    version,
    about = "Veriguard 平台自有验证 Agent — `init` provisioning + daemon mode"
)]
struct VeriguardCli {
    #[command(subcommand)]
    cmd: VeriguardCmd,
}

#[derive(clap::Subcommand, Debug)]
enum VeriguardCmd {
    /// First-run provisioning: load an install pack and generate keys.
    Init(InitArgs),
    /// Mode-A daemon mode: poll the Veriguard platform for tasks and run them.
    Run(RunArgs),
    /// Install the agent as a system service (Linux systemd in A.8.1).
    Install(InstallArgs),
    /// Reverse an install (A.8.4): disable + remove the systemd unit,
    /// optionally purge the state directory.
    Uninstall(UninstallArgs),
    /// Rotate the agent's Ed25519 + X25519 keypairs (A.8.5).  Backs the
    /// old keys aside and prints new pubs so the operator can re-enroll
    /// with the platform.
    RotateKeys(RotateKeysArgs),
    /// Mode-C offline pack execution: single-pack (A.7.3) or directory
    /// scan with replay blacklist (A.7.4).
    Pack(PackArgs),
}

#[derive(clap::Args, Debug)]
struct InitArgs {
    /// Path to a Mode-C offline install pack (JSON).
    #[arg(long, conflicts_with = "bootstrap")]
    install_pack: Option<PathBuf>,

    /// Run Mode-A online bootstrap (HTTP fetch is implemented in C1-Agent-2).
    #[arg(long, default_value_t = false)]
    bootstrap: bool,

    /// Required with `--bootstrap`: HTTPS URL of the Veriguard platform.
    #[arg(long, requires = "bootstrap")]
    platform_url: Option<String>,

    /// Required with `--bootstrap`: 64-hex single-use enrolment token.
    #[arg(long, requires = "bootstrap")]
    onboard_token: Option<String>,

    /// Required with `--bootstrap`: TLS cert pin (`sha256:<hex>`).
    #[arg(long, requires = "bootstrap")]
    platform_cert_pin: Option<String>,

    /// Optional with `--bootstrap`: agent label.  Defaults to `agent-bootstrap`.
    #[arg(long, requires = "bootstrap")]
    agent_label: Option<String>,

    /// State directory; defaults to `~/.veriguard-agent`.
    #[arg(long)]
    state_dir: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct RunArgs {
    /// State directory containing `keys/{sign,enc}.key` + `install-pack.json`.
    /// Defaults to `~/.veriguard-agent`.
    #[arg(long)]
    state_dir: Option<PathBuf>,

    /// Override polling interval (seconds).  Defaults to 5s.
    #[arg(long)]
    poll_interval_secs: Option<u64>,

    /// Override exponential-backoff cap (seconds).  Defaults to 300s.
    #[arg(long)]
    max_backoff_secs: Option<u64>,
}

#[derive(clap::Args, Debug)]
struct PackArgs {
    /// Path to a single platform-built `.vpack` envelope on disk.
    /// Mutually exclusive with `--scan-dir`.  Requires `--output`.
    #[arg(long, conflicts_with = "scan_dir", requires = "output")]
    input: Option<PathBuf>,

    /// Path the agent-built `.vresults` envelope will be written to
    /// (single-pack mode only).  Refuses to overwrite an existing file.
    #[arg(long, requires = "input")]
    output: Option<PathBuf>,

    /// Directory to scan for `*.vpack` files.  Each file is executed
    /// serially in lexicographic order; previously-executed packs (by
    /// `pack_id`) are skipped via the persistent
    /// `executed-packs.json` blacklist.  Mutually exclusive with
    /// `--input`.
    #[arg(long, conflicts_with = "input")]
    scan_dir: Option<PathBuf>,

    /// Directory to write `.vresults` files into when using
    /// `--scan-dir`.  Defaults to the scan directory itself (each
    /// `<x>.vpack` becomes `<x>.vresults` next to it).
    #[arg(long, requires = "scan_dir")]
    output_dir: Option<PathBuf>,

    /// State directory containing `install-pack.json`,
    /// `keys/{sign,enc}.key`, and `executed-packs.json`.  Defaults to
    /// `~/.veriguard-agent`.
    #[arg(long)]
    state_dir: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct UninstallArgs {
    /// Systemd unit name (no `.service` suffix).  Defaults to `veriguard-agent`.
    #[arg(long)]
    service_name: Option<String>,

    /// State directory that the install pack + agent keys live under.
    /// Only consulted when `--purge` is also passed.  Defaults to
    /// `/var/lib/veriguard`.
    #[arg(long)]
    state_dir: Option<PathBuf>,

    /// Skip `systemctl disable --now` (useful when the service was never
    /// enabled — uninstall still removes the stale unit file).
    #[arg(long, default_value_t = false)]
    no_disable: bool,

    /// **DESTRUCTIVE** — recursively delete `--state-dir` after removing
    /// the service.  Wipes agent keys, install pack, and
    /// `executed-packs.json`.
    #[arg(long, default_value_t = false)]
    purge: bool,

    /// Print the planned actions without touching disk or invoking
    /// systemctl.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

#[derive(clap::Args, Debug)]
struct RotateKeysArgs {
    /// State directory containing `keys/{sign,enc}.key`.  Defaults to
    /// `~/.veriguard-agent`.
    #[arg(long)]
    state_dir: Option<PathBuf>,

    /// Print the new public keys without writing anything to disk.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

#[derive(clap::Args, Debug)]
struct InstallArgs {
    /// Path to the agent binary the service unit will exec.  Defaults to
    /// `/usr/local/bin/veriguard-agent` (matches the one-line curl install).
    #[arg(long)]
    binary_path: Option<PathBuf>,

    /// State directory passed to `veriguard-agent run --state-dir`.
    /// Defaults to `/var/lib/veriguard`.
    #[arg(long)]
    state_dir: Option<PathBuf>,

    /// Systemd unit name (no `.service` suffix).  Defaults to `veriguard-agent`.
    #[arg(long)]
    service_name: Option<String>,

    /// Service `User=` (also used for `Group=`).  Defaults to `veriguard`.
    #[arg(long)]
    service_user: Option<String>,

    /// Write the unit file but skip `systemctl daemon-reload && enable --now`.
    #[arg(long, default_value_t = false)]
    no_enable: bool,

    /// Render the unit file to stdout without writing or running systemctl.
    /// Useful for pre-prod review or air-gapped operators.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

fn run_init_cli(cli: VeriguardCli) -> Result<(), Error> {
    let VeriguardCmd::Init(args) = cli.cmd else {
        unreachable!("dispatcher only routes init args here")
    };
    let state_dir = match args.state_dir.clone() {
        Some(p) => p,
        None => onboard::default_state_dir().ok_or_else(|| {
            Error::Internal("could not resolve $HOME; pass --state-dir explicitly".to_string())
        })?,
    };

    if let Some(pack_path) = args.install_pack {
        onboard::run_init_install_pack(&pack_path, &state_dir)
            .map_err(|e| Error::Internal(format!("init --install-pack failed: {e}")))
    } else if args.bootstrap {
        // Default agent label for bootstrap when not supplied.
        let agent_label = args.agent_label.as_deref().unwrap_or("agent-bootstrap");
        onboard::run_bootstrap(
            args.platform_url.as_deref().unwrap_or(""),
            args.onboard_token.as_deref().unwrap_or(""),
            args.platform_cert_pin.as_deref().unwrap_or(""),
            agent_label,
            &state_dir,
        )
        .map_err(|e| Error::Internal(format!("init --bootstrap failed: {e}")))
    } else {
        Err(Error::Internal(
            "init requires either --install-pack <path> or --bootstrap ...".to_string(),
        ))
    }
}

/// Run the Mode-A daemon loop.  Loads keys + install pack from `state_dir`,
/// constructs the capability registry, and hands off to the poll loop.
fn run_run_cli(cli: VeriguardCli) -> Result<(), Error> {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::Duration;

    let VeriguardCmd::Run(args) = cli.cmd else {
        unreachable!("dispatcher only routes run args here")
    };
    let state_dir = match args.state_dir {
        Some(p) => p,
        None => onboard::default_state_dir().ok_or_else(|| {
            Error::Internal("could not resolve $HOME; pass --state-dir explicitly".to_string())
        })?,
    };

    let pack_path = state_dir.join("install-pack.json");
    let pack = onboard::load_install_pack(&pack_path)
        .map_err(|e| Error::Internal(format!("install pack missing or invalid: {e}")))?;

    // For the alpha the install pack does not carry `agent_id` — that field
    // is populated by the platform during `POST /api/agent/onboard/register`
    // (C1-Platform-3).  Until that lands we use `agent_label` as the agent_id
    // surrogate; the platform's scaffold AgentTaskQueueApi accepts whatever
    // value the agent self-reports.
    let agent_id = pack.agent_label.clone();
    let onboard_token = pack.onboard_token.clone();
    let platform_url = pack.platform_url.clone();

    let sign_path = state_dir.join("keys").join("sign.key");
    let sign_priv = crypto::load_ed25519_priv(&sign_path)
        .map_err(|e| Error::Internal(format!("loading sign key: {e}")))?;

    let poll_interval = Duration::from_secs(args.poll_interval_secs.unwrap_or(5));
    let max_backoff = Duration::from_secs(args.max_backoff_secs.unwrap_or(300));

    // Build capability registry.
    let implant_manager = Arc::new(implant::ImplantManager::new(
        platform_url.clone(),
        state_dir.clone(),
    ));
    // spec §四 L1 强归因 Ed25519 attribution signer —— 启动时一次性从 env 加载.
    // 未配置 → `None`，HttpAttackCapability 跳过 sig 注入（兼容旧栈）.
    // 解码失败 → 启动早早失败.
    let attribution_signer = attribution::AttributionSigner::from_env()
        .map_err(|e| Error::Internal(format!("attribution signer init failed: {e}")))?
        .map(Arc::new);
    // 招标 §3.5 / §6.1 allowed-cidr pre-flight policy (C-2 双层防御 agent 侧)；
    // env `VERIGUARD_TARGET_ALLOWED_CIDR` 未配 → `None`，HttpAttackCapability 跳过校验.
    let allowed_cidr_policy = target::AllowedCidrPolicy::from_env()
        .map_err(|e| Error::Internal(format!("allowed-cidr policy init failed: {e}")))?
        .map(Arc::new);

    let mut registry = capabilities::Registry::new();
    let mut http_attack = capabilities::HttpAttackCapability::new();
    if let Some(signer) = &attribution_signer {
        http_attack = http_attack.with_attribution_signer(signer.clone());
    }
    if let Some(policy) = &allowed_cidr_policy {
        http_attack = http_attack.with_allowed_cidr_policy(policy.clone());
    }
    registry.register(Box::new(http_attack));
    registry.register(Box::new(
        capabilities::PcapReplayCapability::with_state_dir(state_dir.join("pcaps")),
    ));
    registry.register(Box::new(capabilities::CommandInjectCapability::new(
        implant_manager.clone(),
    )));
    registry.register(Box::new(capabilities::ImplantDropCapability::new(
        implant_manager,
    )));
    let advertised = registry.names();

    info!(
        "veriguard-agent run: agent_id={agent_id:?} platform_url={platform_url:?} \
         capabilities={advertised:?} attribution_signer={} allowed_cidr={}",
        attribution_signer.is_some(),
        allowed_cidr_policy
            .as_ref()
            .map(|p| p.allowed_cidrs().len())
            .unwrap_or(0)
    );

    let poller = transport::Poller {
        platform_url,
        agent_id,
        onboard_token,
        capabilities: advertised,
        sign_priv,
        http_client: transport::http_client_with_proxy_env(),
        poll_interval,
        max_backoff,
        stop: Arc::new(AtomicBool::new(false)),
    };
    poller
        .run(&registry)
        .map_err(|e| Error::Internal(format!("poll loop exited with error: {e}")))?;
    Ok(())
}

/// Execute offline `.vpack` workloads.  Two modes:
///
/// * `--input <file> --output <file>` — single-pack: verify platform
///   signature, decrypt, dispatch the task list through the standard
///   capability registry, and emit one `.vresults`.  Refuses to overwrite
///   an existing `--output`.
/// * `--scan-dir <dir> [--output-dir <dir>]` — multi-pack drain:
///   serially execute every `*.vpack` in `--scan-dir` in lexicographic
///   order, skipping any pack whose `pack_id` is already recorded in
///   `state_dir/executed-packs.json` (the persistent replay-prevention
///   blacklist).  Every attempt is recorded back into the blacklist.
///
/// Both modes read the install pack + agent keys from `--state-dir`
/// (defaults to the same path `init` / `run` use).  The capability
/// registry is identical to Mode A so online/offline dispatch behaves
/// identically.
fn run_pack_cli(cli: VeriguardCli) -> Result<(), Error> {
    use std::sync::Arc;

    let VeriguardCmd::Pack(args) = cli.cmd else {
        unreachable!("dispatcher only routes pack args here")
    };
    let state_dir = match args.state_dir {
        Some(p) => p,
        None => onboard::default_state_dir().ok_or_else(|| {
            Error::Internal("could not resolve $HOME; pass --state-dir explicitly".to_string())
        })?,
    };

    // Both modes need the install pack (for capability wiring) and the
    // same Registry the Mode-A daemon uses so offline dispatch matches
    // online behavior exactly.
    let install_pack = onboard::load_install_pack(&state_dir.join("install-pack.json"))
        .map_err(|e| Error::Internal(format!("install pack missing or invalid: {e}")))?;
    let implant_manager = Arc::new(implant::ImplantManager::new(
        install_pack.platform_url.clone(),
        state_dir.clone(),
    ));
    // Mode C 同 Mode A：加载可选 attribution signer 让离线 dispatch 也注 sig.
    let attribution_signer = attribution::AttributionSigner::from_env()
        .map_err(|e| Error::Internal(format!("attribution signer init failed: {e}")))?
        .map(Arc::new);
    // Mode C 同 Mode A：加载可选 allowed-cidr policy 让离线 dispatch 也 pre-flight.
    let allowed_cidr_policy = target::AllowedCidrPolicy::from_env()
        .map_err(|e| Error::Internal(format!("allowed-cidr policy init failed: {e}")))?
        .map(Arc::new);

    let mut registry = capabilities::Registry::new();
    let mut http_attack = capabilities::HttpAttackCapability::new();
    if let Some(signer) = &attribution_signer {
        http_attack = http_attack.with_attribution_signer(signer.clone());
    }
    if let Some(policy) = &allowed_cidr_policy {
        http_attack = http_attack.with_allowed_cidr_policy(policy.clone());
    }
    registry.register(Box::new(http_attack));
    registry.register(Box::new(
        capabilities::PcapReplayCapability::with_state_dir(state_dir.join("pcaps")),
    ));
    registry.register(Box::new(capabilities::CommandInjectCapability::new(
        implant_manager.clone(),
    )));
    registry.register(Box::new(capabilities::ImplantDropCapability::new(
        implant_manager,
    )));

    match (args.input, args.scan_dir) {
        (Some(input), None) => {
            // Single-pack mode.  `requires = "output"` on PackArgs::input
            // means clap rejects the CLI before we get here if --output
            // is missing, but we still guard explicitly so a future
            // attribute removal doesn't silently break the contract.
            let output = args.output.ok_or_else(|| {
                Error::Internal("--input requires --output (single-pack mode)".to_string())
            })?;
            let report = pack::execute_vpack(&input, &output, &state_dir, &registry)
                .map_err(|e| Error::Internal(format!("pack execution failed: {e}")))?;
            info!(
                "pack {} executed: {} task(s) → {} result(s); wrote {} bytes to {}",
                report.pack_id,
                report.task_count,
                report.result_count,
                report.vresults_bytes_written,
                output.display()
            );
            Ok(())
        }
        (None, Some(scan_dir)) => {
            let opts = pack::ScanOptions {
                scan_dir: &scan_dir,
                output_dir: args.output_dir.as_deref(),
                state_dir: &state_dir,
                registry: &registry,
            };
            let report =
                pack::scan(opts).map_err(|e| Error::Internal(format!("scan failed: {e}")))?;
            info!(
                "scan complete: total={} executed_ok={} executed_failed={} \
                 skipped_blacklisted={} failed_to_read={}",
                report.total_found,
                report.executed_ok,
                report.executed_failed,
                report.skipped_blacklisted,
                report.failed_to_read,
            );
            Ok(())
        }
        (None, None) => Err(Error::Internal(
            "pack requires either --input <file> + --output <file>, or --scan-dir <dir>"
                .to_string(),
        )),
        (Some(_), Some(_)) => {
            // clap `conflicts_with` on PackArgs prevents this combination
            // from ever reaching here; keep an explicit error in case
            // the attribute is ever removed.
            Err(Error::Internal(
                "--input and --scan-dir are mutually exclusive".to_string(),
            ))
        }
    }
}

/// Reverse a previous install (A.8.4).  Disables the service, removes
/// the unit file, runs `daemon-reload`, and optionally purges
/// `--state-dir`.  Dry-run prints the plan without touching the host.
fn run_uninstall_cli(cli: VeriguardCli) -> Result<(), Error> {
    let VeriguardCmd::Uninstall(args) = cli.cmd else {
        unreachable!("dispatcher only routes uninstall args here")
    };
    let mut config = install::SystemdUninstallConfig::default();
    if let Some(n) = args.service_name {
        config.service_name = n;
    }
    if let Some(p) = args.state_dir {
        config.state_dir = p;
    }
    config.disable_first = !args.no_disable;
    config.purge_state = args.purge;
    config.dry_run = args.dry_run;

    let report = install::uninstall_service(&config)
        .map_err(|e| Error::Internal(format!("uninstall failed: {e}")))?;

    if config.dry_run {
        info!(
            "uninstall --dry-run: would target {} (purge={})",
            report.unit_path.display(),
            args.purge
        );
    } else {
        info!(
            "uninstall: unit={} removed={} disabled={} daemon_reloaded={} purged_state={}",
            report.unit_path.display(),
            report.removed_unit,
            report.disabled,
            report.daemon_reloaded,
            report.purged_state,
        );
        if !report.removed_unit {
            info!("uninstall: unit file was already absent (idempotent)");
        }
    }
    Ok(())
}

/// Rotate the agent's local Ed25519 + X25519 keypairs (A.8.5).  Old
/// keys are renamed to `<name>.bak.<UTC timestamp>`; new pubs are
/// printed for the operator to re-enroll with the platform.
fn run_rotate_keys_cli(cli: VeriguardCli) -> Result<(), Error> {
    let VeriguardCmd::RotateKeys(args) = cli.cmd else {
        unreachable!("dispatcher only routes rotate-keys args here")
    };
    let state_dir = match args.state_dir {
        Some(p) => p,
        None => onboard::default_state_dir().ok_or_else(|| {
            Error::Internal("could not resolve $HOME; pass --state-dir explicitly".to_string())
        })?,
    };
    let report = onboard::run_rotate_keys(&state_dir, args.dry_run)
        .map_err(|e| Error::Internal(format!("rotate-keys failed: {e}")))?;

    let mode = if report.dry_run { "dry-run" } else { "applied" };
    info!(
        "rotate-keys ({mode}): state_dir={} new_sign_pub_b64={} new_enc_pub_b64={}",
        report.state_dir.display(),
        report.new_sign_pub_b64,
        report.new_enc_pub_b64,
    );
    if let Some(p) = &report.backed_up_sign_path {
        info!("rotate-keys: backed up sign.key → {}", p.display());
    }
    if let Some(p) = &report.backed_up_enc_path {
        info!("rotate-keys: backed up enc.key → {}", p.display());
    }
    if !report.dry_run {
        info!(
            "rotate-keys: IMPORTANT — re-run `veriguard-agent init --bootstrap …` \
             or hand the new public keys to the platform admin before the next \
             poll, or Mode A will fail at signature verification."
        );
    }
    Ok(())
}

/// Render + (optionally) install the systemd unit file for the agent.
///
/// On Linux this writes `/etc/systemd/system/<name>.service` and runs
/// `systemctl daemon-reload && enable --now` unless `--no-enable` or
/// `--dry-run` is passed.  On macOS / Windows the underlying dispatcher
/// returns a clear "not yet implemented" error pointing at the future
/// A.8.2 / A.8.3 commits.
fn run_install_cli(cli: VeriguardCli) -> Result<(), Error> {
    let VeriguardCmd::Install(args) = cli.cmd else {
        unreachable!("dispatcher only routes install args here")
    };
    let mut config = install::SystemdConfig::default();
    if let Some(p) = args.binary_path {
        config.binary_path = p;
    }
    if let Some(p) = args.state_dir {
        config.state_dir = p;
    }
    if let Some(n) = args.service_name {
        config.service_name = n;
    }
    if let Some(u) = args.service_user {
        config.service_user = u;
    }
    config.enable_on_install = !args.no_enable;
    config.dry_run = args.dry_run;

    let report = install::install_service(&config)
        .map_err(|e| Error::Internal(format!("install failed: {e}")))?;

    if !report.wrote_unit_file {
        info!(
            "install --dry-run: would write {} ({} bytes)",
            report.unit_path.display(),
            report.unit_contents.len()
        );
    } else {
        info!(
            "wrote unit file: {} ({} bytes); enabled={}",
            report.unit_path.display(),
            report.unit_contents.len(),
            report.enabled
        );
        if !report.enabled {
            info!(
                "re-run `systemctl daemon-reload && systemctl enable --now {}.service` when ready",
                config.service_name
            );
        }
    }
    Ok(())
}

fn main() -> Result<(), Error> {
    set_error_hook();
    // region Init logger
    let current_exe_patch = env::current_exe().unwrap();
    let parent_path = current_exe_patch.parent().unwrap();
    let log_file = parent_path.join(PREFIX_LOG_NAME);
    let condition = RollingConditionBasic::new().daily();
    let file_appender = BasicRollingFileAppender::new(log_file, condition, 3).unwrap();
    let (file_writer, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .json()
        .with_writer(file_writer)
        .init();
    // endregion

    // 二开 CLI: 当用户传 `init ...` 子命令时短路 daemon 路径。
    if let Some(result) = try_dispatch_subcommand() {
        return result;
    }

    // region Process execution
    info!("Starting OpenAEV agent {} ({})", VERSION, Settings::mode());
    let settings = Settings::new();
    let settings_data = settings.unwrap();
    if service_stub::is_windows_service() {
        // Running as a Windows service
        agent_start(settings_data, true).unwrap();
        // Service stub is a blocking thread managed by Windows service
        service_stub::run().unwrap();
    } else {
        // Standalone execution
        let agent_handle = agent_start(settings_data, false).unwrap();
        // In this mode, we need to wait for end of threads execution
        agent_handle
            .into_iter()
            .for_each(|handle| handle.join().unwrap());
    }
    // endregion
    Ok(())
}
