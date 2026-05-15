//! Multi-pack scanner: drains a directory of `.vpack` files serially,
//! gates each pack against the persistent [`blacklist`](super::blacklist),
//! and records every attempt back into it.
//!
//! ## Lifecycle (per call to [`scan`])
//!
//! 1. List `*.vpack` files in `scan_dir`, lexicographically sorted by
//!    file name.  Non-files / non-`.vpack` entries are silently filtered
//!    (operator may keep other artifacts alongside).
//! 2. Load the current blacklist via [`blacklist::load`]; a missing file
//!    is treated as an empty blacklist (first-ever scan).
//! 3. For each `.vpack`, in lexicographic order: shallow-parse the
//!    envelope JSON to extract `metadata_plaintext.pack_id` (no signature
//!    verification at this step — the goal is purely to look up the
//!    blacklist key cheaply).  If `pack_id` is already in the blacklist,
//!    record a skip.  Otherwise compute the `.vresults` output path
//!    ([`compute_output_path`]) and hand off to
//!    [`super::executor::execute_vpack`] which does full envelope
//!    verification + decrypt + capability dispatch + encrypt + write.
//!    Either way, append a blacklist entry (success or failure) via
//!    [`blacklist::append`] so a crash on the *next* pack still retains
//!    the proof of the completed one.
//! 4. Return a [`ScanReport`] summarizing what happened.
//!
//! Returning `Ok(_)` from this function does **not** mean every pack
//! succeeded — the caller should inspect `ScanReport.executed_failed`
//! and the per-item outcomes.  A `ScanError` is reserved for "scan
//! could not start" failures (unreadable scan dir, broken blacklist).
//!
//! ## Why peek instead of full parse for the blacklist check
//!
//! [`super::executor::execute_vpack`] does the full signature verify
//! anyway, so duplicating that work in the scanner would waste roughly
//! one Ed25519 verify per already-executed pack — exactly the case we
//! expect to be hot when an operator drops the same `inbox/` into a
//! second scan.  Peeking just for `pack_id` keeps the steady-state cost
//! O(1 JSON parse) per skip.
//!
//! Threat-model note: an attacker who drops a tampered `.vpack` whose
//! `metadata_plaintext.pack_id` matches an already-executed pack will be
//! *skipped* (saving the agent the work).  Their attack does not
//! actually run.  If the same attacker drops a fresh `pack_id` then
//! `execute_vpack` will reject the signature on the verify step and the
//! attempt is recorded as `signature_failed`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use chrono::Utc;
use log::{info, warn};
use serde_json::Value;
use thiserror::Error;

use crate::capabilities::Registry;

use super::blacklist::{self, BlacklistError, Entry, Outcome};
use super::executor::{execute_vpack, ExecError, ExecuteReport};

/// Bundle of inputs needed for [`scan`].  Using a struct (vs positional
/// args) keeps the call sites self-documenting as we add knobs in
/// future passes.
pub struct ScanOptions<'a> {
    /// Directory to enumerate for `*.vpack` files.
    pub scan_dir: &'a Path,
    /// Directory to write `.vresults` into.  `None` writes each result
    /// next to its source `.vpack` (changing the extension).
    pub output_dir: Option<&'a Path>,
    /// State dir for the install pack, agent keys, and blacklist file.
    pub state_dir: &'a Path,
    /// Capability registry the executor dispatches into.
    pub registry: &'a Registry,
}

/// Aggregate result of one [`scan`] pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ScanReport {
    /// Number of `.vpack` files found in `scan_dir`.
    pub total_found: usize,
    /// Number of packs that executed end-to-end (outcome=Success).
    pub executed_ok: usize,
    /// Number of packs whose `execute_vpack` call returned an error.
    pub executed_failed: usize,
    /// Number of packs whose `pack_id` was already in the blacklist.
    pub skipped_blacklisted: usize,
    /// Number of packs whose envelope JSON could not be peeked for
    /// `pack_id` (corrupt JSON, missing field).  Such packs are NOT
    /// recorded in the blacklist because there is no reliable key to
    /// record them under.
    pub failed_to_read: usize,
    /// Per-pack item records, in the order they were processed.
    pub items: Vec<ScanItem>,
}

/// One element of [`ScanReport::items`].
#[derive(Debug, PartialEq, Eq)]
pub struct ScanItem {
    /// Filesystem path of the source `.vpack`.
    pub vpack_path: PathBuf,
    /// `pack_id` extracted via shallow peek (`None` if peek failed).
    pub pack_id: Option<String>,
    /// What happened for this pack.
    pub outcome: ScanItemOutcome,
}

/// Per-pack outcome, richer than the persisted [`Outcome`] (e.g. carries
/// the `ExecError` message for failed executes).
#[derive(Debug, PartialEq, Eq)]
pub enum ScanItemOutcome {
    /// Pack executed successfully; a `.vresults` file was written.
    ExecutedOk {
        /// `task_count` echoed from the envelope.
        task_count: usize,
        /// Number of `TaskResult`s emitted.
        result_count: usize,
        /// Final `.vresults` path.
        vresults_path: PathBuf,
    },
    /// Execute returned an error.  Error message is captured for
    /// operator review; the precise [`Outcome`] variant is recorded in
    /// the persistent blacklist.
    ExecutedFailed {
        /// Persisted outcome classification.
        outcome: Outcome,
        /// Human-readable message from the `ExecError`.
        message: String,
    },
    /// Pack was already in the blacklist; nothing was executed.
    SkippedBlacklisted {
        /// Outcome recorded the first time this pack was processed.
        prior_outcome: Outcome,
    },
    /// Envelope JSON could not be parsed enough to extract `pack_id`.
    /// Pack is NOT added to the blacklist (no reliable key).
    UnreadableEnvelope {
        /// Human-readable parse error.
        message: String,
    },
}

/// Errors that abort the whole scan (as opposed to per-pack failures
/// which appear inside `ScanReport.items`).
#[derive(Debug, Error)]
pub enum ScanError {
    /// `scan_dir` could not be enumerated (missing, permission denied, …).
    #[error("scan directory I/O at {path:?}: {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
    /// Blacklist on disk could not be loaded.  Refuse to scan rather
    /// than silently disable replay prevention.
    #[error("blacklist load failed: {0}")]
    Blacklist(#[from] BlacklistError),
}

/// Drain every `.vpack` in `opts.scan_dir`, gating each by the
/// persistent blacklist.  See module docs for the lifecycle.
pub fn scan(opts: ScanOptions) -> Result<ScanReport, ScanError> {
    let vpack_paths = list_vpacks(opts.scan_dir)?;
    let blacklist_map = blacklist::load(opts.state_dir)?;

    let mut report = ScanReport {
        total_found: vpack_paths.len(),
        ..Default::default()
    };

    for vpack_path in vpack_paths {
        // 1. Shallow peek to learn the pack_id (cheap, no verify).
        let pack_id = match peek_pack_id(&vpack_path) {
            Ok(id) => id,
            Err(e) => {
                warn!(
                    "scan: could not extract pack_id from {}: {e}",
                    vpack_path.display()
                );
                report.failed_to_read += 1;
                report.items.push(ScanItem {
                    vpack_path: vpack_path.clone(),
                    pack_id: None,
                    outcome: ScanItemOutcome::UnreadableEnvelope {
                        message: e.to_string(),
                    },
                });
                continue;
            }
        };

        // 2. Blacklist gate.
        if let Some(existing) = blacklist_map.get(&pack_id) {
            info!(
                "scan: skipped {} (already in blacklist; prior outcome={:?})",
                pack_id, existing.outcome
            );
            report.skipped_blacklisted += 1;
            report.items.push(ScanItem {
                vpack_path: vpack_path.clone(),
                pack_id: Some(pack_id),
                outcome: ScanItemOutcome::SkippedBlacklisted {
                    prior_outcome: existing.outcome,
                },
            });
            continue;
        }

        // 3. Decide where the `.vresults` goes.
        let output_path = compute_output_path(&vpack_path, opts.output_dir);

        // 4. Hand off to the single-pack executor.
        let exec_result = execute_vpack(&vpack_path, &output_path, opts.state_dir, opts.registry);
        let (entry, item_outcome) = build_entry(&vpack_path, &pack_id, &output_path, &exec_result);

        // 5. Persist the per-attempt outcome.  We log + continue on
        //    persistence failures so a transient EROFS doesn't cost us
        //    the rest of the batch — but the operator will see a
        //    warning so the inconsistency isn't silent.
        if let Err(persist_err) = blacklist::append(opts.state_dir, entry) {
            warn!("scan: failed to persist blacklist entry for {pack_id}: {persist_err}");
        }

        match exec_result {
            Ok(_) => report.executed_ok += 1,
            Err(_) => report.executed_failed += 1,
        }
        report.items.push(ScanItem {
            vpack_path: vpack_path.clone(),
            pack_id: Some(pack_id),
            outcome: item_outcome,
        });
    }

    info!(
        "scan complete: total={} ok={} failed={} skipped={} unreadable={}",
        report.total_found,
        report.executed_ok,
        report.executed_failed,
        report.skipped_blacklisted,
        report.failed_to_read
    );

    Ok(report)
}

/// List all `*.vpack` *files* in `dir`, sorted by file name (lexicographic).
fn list_vpacks(dir: &Path) -> Result<Vec<PathBuf>, ScanError> {
    let read = fs::read_dir(dir).map_err(|e| ScanError::Io {
        path: dir.to_path_buf(),
        source: e,
    })?;
    let mut out: Vec<PathBuf> = read
        .filter_map(|entry| entry.ok().map(|de| de.path()))
        .filter(|p| p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("vpack"))
        .collect();
    out.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    Ok(out)
}

/// Errors raised during the shallow envelope peek.  Internal — surfaced
/// as `ScanItemOutcome::UnreadableEnvelope { message }`.
#[derive(Debug, Error)]
enum PeekError {
    #[error("I/O at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("envelope is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("envelope missing metadata_plaintext.pack_id")]
    MissingPackId,
}

/// Read a `.vpack` envelope and pull `metadata_plaintext.pack_id` out of
/// the JSON tree.  Does NOT verify the signature; the caller relies on
/// the executor to do that on the next step.
fn peek_pack_id(path: &Path) -> Result<String, PeekError> {
    let bytes = fs::read(path).map_err(|e| PeekError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let v: Value = serde_json::from_slice(&bytes)?;
    let pack_id = v
        .get("metadata_plaintext")
        .and_then(|m| m.get("pack_id"))
        .and_then(|p| p.as_str())
        .ok_or(PeekError::MissingPackId)?;
    Ok(pack_id.to_string())
}

/// Compute the `.vresults` output path for a given `.vpack` and optional
/// override output directory.
///
/// * `output_dir = None` → write next to the source, swapping `.vpack`
///   for `.vresults` (`/inbox/foo.vpack` → `/inbox/foo.vresults`).
/// * `output_dir = Some(dir)` → put the result under `dir` with the
///   same basename (`/inbox/foo.vpack`, `dir=/outbox` →
///   `/outbox/foo.vresults`).
pub fn compute_output_path(vpack_path: &Path, output_dir: Option<&Path>) -> PathBuf {
    match output_dir {
        Some(dir) => {
            let stem = vpack_path.file_stem().unwrap_or_default();
            let mut name = stem.to_os_string();
            name.push(".vresults");
            dir.join(name)
        }
        None => vpack_path.with_extension("vresults"),
    }
}

/// Build the blacklist `Entry` + a richer `ScanItemOutcome` from one
/// `execute_vpack` result.
fn build_entry(
    vpack_path: &Path,
    pack_id: &str,
    output_path: &Path,
    exec_result: &Result<ExecuteReport, ExecError>,
) -> (Entry, ScanItemOutcome) {
    let executed_at = Utc::now();
    match exec_result {
        Ok(report) => (
            Entry {
                pack_id: pack_id.to_string(),
                executed_at,
                vpack_path: vpack_path.to_path_buf(),
                vresults_path: Some(output_path.to_path_buf()),
                task_count: Some(report.task_count as i32),
                result_count: Some(report.result_count as i32),
                outcome: Outcome::Success,
            },
            ScanItemOutcome::ExecutedOk {
                task_count: report.task_count,
                result_count: report.result_count,
                vresults_path: output_path.to_path_buf(),
            },
        ),
        Err(e) => {
            let outcome = classify_exec_error(e);
            (
                Entry {
                    pack_id: pack_id.to_string(),
                    executed_at,
                    vpack_path: vpack_path.to_path_buf(),
                    vresults_path: None,
                    task_count: None,
                    result_count: None,
                    outcome,
                },
                ScanItemOutcome::ExecutedFailed {
                    outcome,
                    message: e.to_string(),
                },
            )
        }
    }
}

/// Map an [`ExecError`] variant onto the persisted [`Outcome`] enum.
/// Match is exhaustive so adding an `ExecError` variant in the future
/// causes a compile error here, forcing the author to pick the right
/// outcome label rather than silently bucketing it as "Other".
fn classify_exec_error(err: &ExecError) -> Outcome {
    match err {
        ExecError::OutputExists(_) => Outcome::OutputExists,
        ExecError::Io { .. } => Outcome::IoError,
        ExecError::InstallPack(_)
        | ExecError::BadInstallKey { .. }
        | ExecError::BadPlatformSignKey(_) => Outcome::InstallPackInvalid,
        ExecError::Pack(_) => Outcome::SignatureFailed,
        ExecError::AgentKey(_) => Outcome::KeyLoadFailed,
        ExecError::Aead(_) => Outcome::AeadFailed,
        ExecError::TaskListJson(_) => Outcome::TaskListParseFailed,
        ExecError::ResultListJson(_) => Outcome::ResultListSerializeFailed,
        ExecError::AgentIdMismatch { .. } => Outcome::AgentIdMismatch,
        ExecError::TaskCountMismatch { .. } => Outcome::TaskCountMismatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Capability;
    use crate::crypto::ed25519::{generate_ed25519, Ed25519PrivateKey};
    use crate::crypto::keys::{save_ed25519_priv, save_x25519_priv};
    use crate::crypto::x25519_box::{generate_x25519, seal_box, X25519PrivateKey};
    use crate::pack::common::EncryptedEnvelope;
    use crate::pack::vpack::{build_vpack, VpackMetadata};
    use crate::transport::poll::{Task, TaskResult};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use tempfile::tempdir;

    /// Echo capability — copies the task_id into stdout so the test can
    /// observe each per-task identity in the produced `.vresults`.
    struct EchoCap;
    impl Capability for EchoCap {
        fn name(&self) -> &str {
            "http_attack"
        }
        fn execute(&self, task: &Task) -> TaskResult {
            TaskResult {
                status: "SUCCESS".to_string(),
                exit_code: 0,
                stdout: Some(task.task_id.clone()),
                stderr: None,
                started_at: None,
                finished_at: None,
                error_message: None,
            }
        }
    }

    /// Test fixture shared across scanner tests.  Holds the platform +
    /// agent keypairs plus a populated `state_dir` with a valid
    /// install pack on disk.
    struct Fixture {
        state_dir: tempfile::TempDir,
        scan_dir: tempfile::TempDir,
        platform_sign_priv: Ed25519PrivateKey,
        platform_enc_priv: X25519PrivateKey,
        agent_enc_priv: X25519PrivateKey,
        agent_label: String,
    }

    impl Fixture {
        fn new(agent_label: &str) -> Self {
            let state_dir = tempdir().unwrap();
            let scan_dir = tempdir().unwrap();
            let platform_sign_priv = generate_ed25519();
            let platform_enc_priv = generate_x25519();
            let agent_sign_priv = generate_ed25519();
            let agent_enc_priv = generate_x25519();

            let install_pack_json = serde_json::json!({
                "schema_version": "1.0",
                "platform_url": "https://veriguard.example.com",
                "platform_cert_pin":
                    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "platform_sign_pub": B64.encode(platform_sign_priv.public_key().to_bytes()),
                "platform_enc_pub": B64.encode(platform_enc_priv.public_key().to_bytes()),
                "onboard_token":
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "agent_label": agent_label,
            });
            fs::write(
                state_dir.path().join("install-pack.json"),
                serde_json::to_string(&install_pack_json).unwrap(),
            )
            .unwrap();

            let keys_dir = state_dir.path().join("keys");
            fs::create_dir_all(&keys_dir).unwrap();
            save_ed25519_priv(&keys_dir.join("sign.key"), &agent_sign_priv).unwrap();
            save_x25519_priv(&keys_dir.join("enc.key"), &agent_enc_priv).unwrap();

            Self {
                state_dir,
                scan_dir,
                platform_sign_priv,
                platform_enc_priv,
                agent_enc_priv,
                agent_label: agent_label.to_string(),
            }
        }

        /// Build a `.vpack` envelope sealed to this fixture's agent and
        /// drop it into the scan directory under `filename`.
        fn drop_vpack(&self, filename: &str, pack_id: &str, tasks: &[Task]) -> PathBuf {
            let plaintext = serde_json::to_vec(tasks).unwrap();
            let agent_enc_pub = self.agent_enc_priv.public_key();
            let (ciphertext, nonce) =
                seal_box(&plaintext, &agent_enc_pub, &self.platform_enc_priv).unwrap();
            let envelope = EncryptedEnvelope {
                sender_x25519_pub: self.platform_enc_priv.public_key().to_bytes(),
                nonce: *nonce.as_bytes(),
                ciphertext,
            };
            let metadata = VpackMetadata {
                pack_id: pack_id.to_string(),
                platform_id: "plt_test".to_string(),
                agent_id: self.agent_label.clone(),
                issued_at: Utc::now(),
                task_count: tasks.len() as i32,
                schema_version_payload: "1.0".to_string(),
                exported_by: "alice@platform".to_string(),
            };
            let bytes = build_vpack(&metadata, &envelope, &self.platform_sign_priv).unwrap();
            let path = self.scan_dir.path().join(filename);
            fs::write(&path, bytes).unwrap();
            path
        }

        /// Build a `.vpack` deliberately signed with the WRONG platform
        /// key so its signature fails verification.
        fn drop_bad_sig_vpack(&self, filename: &str, pack_id: &str) -> PathBuf {
            let attacker_sign = generate_ed25519();
            let plaintext = serde_json::to_vec::<Vec<Task>>(&vec![]).unwrap();
            let (ciphertext, nonce) = seal_box(
                &plaintext,
                &self.agent_enc_priv.public_key(),
                &self.platform_enc_priv,
            )
            .unwrap();
            let envelope = EncryptedEnvelope {
                sender_x25519_pub: self.platform_enc_priv.public_key().to_bytes(),
                nonce: *nonce.as_bytes(),
                ciphertext,
            };
            let metadata = VpackMetadata {
                pack_id: pack_id.to_string(),
                platform_id: "plt_test".to_string(),
                agent_id: self.agent_label.clone(),
                issued_at: Utc::now(),
                task_count: 0,
                schema_version_payload: "1.0".to_string(),
                exported_by: "attacker".to_string(),
            };
            let bytes = build_vpack(&metadata, &envelope, &attacker_sign).unwrap();
            let path = self.scan_dir.path().join(filename);
            fs::write(&path, bytes).unwrap();
            path
        }

        fn registry() -> Registry {
            let mut r = Registry::new();
            r.register(Box::new(EchoCap));
            r
        }
    }

    fn sample_task(task_id: &str) -> Task {
        Task {
            task_id: task_id.to_string(),
            capability: "http_attack".to_string(),
            injector_type: "x".to_string(),
            payload: "{}".to_string(),
            expectations: vec![],
        }
    }

    #[test]
    fn test_scan_executes_three_packs_in_lexicographic_order() {
        let fx = Fixture::new("agent-prod-01");
        fx.drop_vpack(
            "a.vpack",
            "11111111-1111-1111-1111-111111111111",
            &[sample_task("t-a")],
        );
        fx.drop_vpack(
            "m.vpack",
            "22222222-2222-2222-2222-222222222222",
            &[sample_task("t-m")],
        );
        fx.drop_vpack(
            "z.vpack",
            "33333333-3333-3333-3333-333333333333",
            &[sample_task("t-z")],
        );

        let registry = Fixture::registry();
        let opts = ScanOptions {
            scan_dir: fx.scan_dir.path(),
            output_dir: None,
            state_dir: fx.state_dir.path(),
            registry: &registry,
        };
        let report = scan(opts).expect("scan");
        assert_eq!(report.total_found, 3);
        assert_eq!(report.executed_ok, 3);
        assert_eq!(report.executed_failed, 0);
        assert_eq!(report.skipped_blacklisted, 0);
        assert_eq!(report.failed_to_read, 0);

        let names: Vec<_> = report
            .items
            .iter()
            .map(|i| {
                i.vpack_path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(names, vec!["a.vpack", "m.vpack", "z.vpack"]);

        for name in ["a.vresults", "m.vresults", "z.vresults"] {
            assert!(fx.scan_dir.path().join(name).exists(), "missing {name}");
        }
    }

    #[test]
    fn test_scan_skips_packs_already_in_blacklist() {
        let fx = Fixture::new("agent-prod-01");
        fx.drop_vpack(
            "a.vpack",
            "11111111-1111-1111-1111-111111111111",
            &[sample_task("t-a")],
        );
        fx.drop_vpack(
            "b.vpack",
            "22222222-2222-2222-2222-222222222222",
            &[sample_task("t-b")],
        );

        let registry = Fixture::registry();

        let first = scan(ScanOptions {
            scan_dir: fx.scan_dir.path(),
            output_dir: None,
            state_dir: fx.state_dir.path(),
            registry: &registry,
        })
        .expect("first scan");
        assert_eq!(first.executed_ok, 2);

        let second = scan(ScanOptions {
            scan_dir: fx.scan_dir.path(),
            output_dir: None,
            state_dir: fx.state_dir.path(),
            registry: &registry,
        })
        .expect("second scan");
        assert_eq!(second.total_found, 2);
        assert_eq!(second.executed_ok, 0);
        assert_eq!(second.executed_failed, 0);
        assert_eq!(second.skipped_blacklisted, 2);
        for item in &second.items {
            assert!(matches!(
                item.outcome,
                ScanItemOutcome::SkippedBlacklisted { .. }
            ));
        }
    }

    #[test]
    fn test_scan_mix_new_and_blacklisted() {
        let fx = Fixture::new("agent-prod-01");
        let already_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        blacklist::append(
            fx.state_dir.path(),
            Entry {
                pack_id: already_id.to_string(),
                executed_at: Utc::now(),
                vpack_path: fx.scan_dir.path().join("a.vpack"),
                vresults_path: None,
                task_count: None,
                result_count: None,
                outcome: Outcome::Success,
            },
        )
        .unwrap();

        fx.drop_vpack("a.vpack", already_id, &[sample_task("t-a")]);
        fx.drop_vpack(
            "b.vpack",
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            &[sample_task("t-b")],
        );

        let registry = Fixture::registry();
        let report = scan(ScanOptions {
            scan_dir: fx.scan_dir.path(),
            output_dir: None,
            state_dir: fx.state_dir.path(),
            registry: &registry,
        })
        .expect("scan");

        assert_eq!(report.total_found, 2);
        assert_eq!(report.executed_ok, 1);
        assert_eq!(report.skipped_blacklisted, 1);
        assert!(fx.scan_dir.path().join("b.vresults").exists());
        assert!(!fx.scan_dir.path().join("a.vresults").exists());
    }

    #[test]
    fn test_scan_failing_pack_does_not_abort_batch() {
        let fx = Fixture::new("agent-prod-01");
        fx.drop_vpack(
            "a.vpack",
            "11111111-1111-1111-1111-111111111111",
            &[sample_task("t-a")],
        );
        fx.drop_bad_sig_vpack("b-bad.vpack", "22222222-2222-2222-2222-222222222222");
        fx.drop_vpack(
            "c.vpack",
            "33333333-3333-3333-3333-333333333333",
            &[sample_task("t-c")],
        );

        let registry = Fixture::registry();
        let report = scan(ScanOptions {
            scan_dir: fx.scan_dir.path(),
            output_dir: None,
            state_dir: fx.state_dir.path(),
            registry: &registry,
        })
        .expect("scan");

        assert_eq!(report.total_found, 3);
        assert_eq!(report.executed_ok, 2);
        assert_eq!(report.executed_failed, 1);
        assert_eq!(report.skipped_blacklisted, 0);

        let bad_item = report
            .items
            .iter()
            .find(|i| i.vpack_path.file_name().unwrap() == "b-bad.vpack")
            .expect("bad pack present");
        match &bad_item.outcome {
            ScanItemOutcome::ExecutedFailed { outcome, .. } => {
                assert_eq!(*outcome, Outcome::SignatureFailed);
            }
            other => panic!("expected ExecutedFailed, got {other:?}"),
        }

        // Re-scan: the bad pack is now in blacklist, so it's skipped.
        let report2 = scan(ScanOptions {
            scan_dir: fx.scan_dir.path(),
            output_dir: None,
            state_dir: fx.state_dir.path(),
            registry: &registry,
        })
        .expect("scan2");
        assert_eq!(report2.skipped_blacklisted, 3);
        assert_eq!(report2.executed_ok, 0);
        assert_eq!(report2.executed_failed, 0);
    }

    #[test]
    fn test_scan_filters_non_vpack_files() {
        let fx = Fixture::new("agent-prod-01");
        fx.drop_vpack(
            "real.vpack",
            "11111111-1111-1111-1111-111111111111",
            &[sample_task("t-1")],
        );
        // Drop sibling files with non-`.vpack` extensions.
        fs::write(fx.scan_dir.path().join("ignored.vresults"), b"junk").unwrap();
        fs::write(fx.scan_dir.path().join("readme.txt"), b"hi").unwrap();
        fs::write(fx.scan_dir.path().join("staging.vpack.tmp"), b"wip").unwrap();

        let registry = Fixture::registry();
        let report = scan(ScanOptions {
            scan_dir: fx.scan_dir.path(),
            output_dir: None,
            state_dir: fx.state_dir.path(),
            registry: &registry,
        })
        .expect("scan");
        assert_eq!(report.total_found, 1);
        assert_eq!(report.executed_ok, 1);
    }

    #[test]
    fn test_scan_unreadable_vpack_recorded_as_failed_to_read() {
        let fx = Fixture::new("agent-prod-01");
        fs::write(
            fx.scan_dir.path().join("garbage.vpack"),
            b"definitely not valid JSON",
        )
        .unwrap();

        let registry = Fixture::registry();
        let report = scan(ScanOptions {
            scan_dir: fx.scan_dir.path(),
            output_dir: None,
            state_dir: fx.state_dir.path(),
            registry: &registry,
        })
        .expect("scan");
        assert_eq!(report.total_found, 1);
        assert_eq!(report.failed_to_read, 1);
        assert_eq!(report.executed_ok, 0);
        assert_eq!(report.executed_failed, 0);

        let item = &report.items[0];
        assert!(matches!(
            item.outcome,
            ScanItemOutcome::UnreadableEnvelope { .. }
        ));
        assert!(item.pack_id.is_none());

        // Blacklist NOT touched (we never had a reliable key).
        let map = blacklist::load(fx.state_dir.path()).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn test_scan_returns_error_when_scan_dir_missing() {
        let fx = Fixture::new("agent-prod-01");
        let registry = Fixture::registry();
        let bogus = fx.scan_dir.path().join("does-not-exist");
        let err = scan(ScanOptions {
            scan_dir: &bogus,
            output_dir: None,
            state_dir: fx.state_dir.path(),
            registry: &registry,
        })
        .expect_err("must surface missing scan dir");
        assert!(matches!(err, ScanError::Io { .. }));
    }

    #[test]
    fn test_scan_returns_error_when_blacklist_corrupt() {
        let fx = Fixture::new("agent-prod-01");
        fs::write(blacklist::path(fx.state_dir.path()), b"{ broken").unwrap();
        let registry = Fixture::registry();
        let err = scan(ScanOptions {
            scan_dir: fx.scan_dir.path(),
            output_dir: None,
            state_dir: fx.state_dir.path(),
            registry: &registry,
        })
        .expect_err("must surface corrupt blacklist");
        assert!(matches!(err, ScanError::Blacklist(_)));
    }

    #[test]
    fn test_scan_with_output_dir_redirects_vresults() {
        let fx = Fixture::new("agent-prod-01");
        let output_dir = tempdir().unwrap();
        fx.drop_vpack(
            "p.vpack",
            "11111111-1111-1111-1111-111111111111",
            &[sample_task("t-p")],
        );

        let registry = Fixture::registry();
        let report = scan(ScanOptions {
            scan_dir: fx.scan_dir.path(),
            output_dir: Some(output_dir.path()),
            state_dir: fx.state_dir.path(),
            registry: &registry,
        })
        .expect("scan");
        assert_eq!(report.executed_ok, 1);

        assert!(output_dir.path().join("p.vresults").exists());
        assert!(!fx.scan_dir.path().join("p.vresults").exists());
    }

    #[test]
    fn test_compute_output_path_default_uses_sibling() {
        let p = compute_output_path(Path::new("/inbox/foo.vpack"), None);
        assert_eq!(p, PathBuf::from("/inbox/foo.vresults"));
    }

    #[test]
    fn test_compute_output_path_with_override_dir() {
        let p = compute_output_path(Path::new("/inbox/foo.vpack"), Some(Path::new("/outbox")));
        assert_eq!(p, PathBuf::from("/outbox/foo.vresults"));
    }

    #[test]
    fn test_classify_exec_error_covers_common_variants() {
        use crate::pack::executor::ExecError as E;
        assert_eq!(
            classify_exec_error(&E::OutputExists(PathBuf::from("/x"))),
            Outcome::OutputExists
        );
        assert_eq!(
            classify_exec_error(&E::AgentIdMismatch {
                install: "a".into(),
                vpack: "b".into(),
            }),
            Outcome::AgentIdMismatch
        );
        assert_eq!(
            classify_exec_error(&E::TaskCountMismatch {
                declared: 3,
                actual: 2,
            }),
            Outcome::TaskCountMismatch
        );
    }
}
