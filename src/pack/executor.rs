//! `.vpack` Mode C **single-pack** execution (spec § 3.5.2 execute path).
//!
//! Wraps the [`vpack`](super::vpack) / [`vresults`](super::vresults)
//! envelope layer with the actual capability dispatch that turns a
//! platform-built pack into an agent-built result pack.
//!
//! ## Flow
//!
//! ```text
//!   .vpack on disk
//!       │
//!       ▼
//!   parse_vpack ──── verify Ed25519 signature against
//!       │           install pack's platform_sign_pub
//!       ▼
//!   open_box ─────── decrypt payload with agent's X25519 priv
//!       │           (sender_pub from envelope, no KDF — see x25519_box)
//!       ▼
//!   serde_json ────▶ Vec<Task>
//!       │
//!       ▼
//!   for each task: Registry::execute  ──▶  TaskResult
//!       │
//!       ▼
//!   serde_json ────▶ Vec<TaskResult> bytes
//!       │
//!       ▼
//!   seal_box ─────── encrypt to install pack's platform_enc_pub,
//!       │           using a freshly drawn 12-byte nonce
//!       ▼
//!   build_vresults ─ sign with agent's Ed25519 priv
//!       │
//!       ▼
//!   .vresults on disk
//! ```
//!
//! ## Cross-language plaintext schema (Rust-locks-it)
//!
//! Per the C1-Integration handover note, **Rust authoritatively defines the
//! plaintext layout** inside the encrypted envelope so the Java
//! `VpackSerializer` round-trip can adopt the same wire form without
//! re-litigating field names.
//!
//! * Plaintext inside `.vpack` ciphertext — a JSON **array** of
//!   [`Task`](crate::transport::poll::Task):
//!
//!   ```json
//!   [
//!     {
//!       "task_id": "<server-issued id>",
//!       "capability": "<capability name e.g. http_attack>",
//!       "injector_type": "<subtype routing>",
//!       "payload": "<opaque JSON string the capability parses>",
//!       "expectations": ["<id>", ...]
//!     },
//!     ...
//!   ]
//!   ```
//!
//! * Plaintext inside `.vresults` ciphertext — a JSON array of
//!   [`TaskResult`](crate::transport::poll::TaskResult), emitted in the
//!   same order as the input tasks (1-to-1; the platform correlates by
//!   index):
//!
//!   ```json
//!   [
//!     {
//!       "status": "SUCCESS|FAILED|TIMEOUT",
//!       "exit_code": <i32>,
//!       "stdout": "<string or null>",
//!       "stderr": "<string or null>",
//!       "started_at": "<RFC3339 or null>",
//!       "finished_at": "<RFC3339 or null>",
//!       "error_message": "<string or null>"
//!     },
//!     ...
//!   ]
//!   ```
//!
//! Both sides serialize with default `serde_json` behavior (Java side:
//! Jackson with default include-null).  Field names match
//! [`Task`](crate::transport::poll::Task) /
//! [`TaskResult`](crate::transport::poll::TaskResult) verbatim.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::Utc;
use log::info;
use thiserror::Error;

use crate::capabilities::Registry;
use crate::crypto::{
    load_ed25519_priv, load_x25519_priv, open_box, seal_box, BoxError, Ed25519Error,
    Ed25519PublicKey, KeyIoError, Nonce, X25519PublicKey,
};
use crate::onboard::{load_install_pack, InstallPackError};
use crate::transport::poll::{Task, TaskDispatcher, TaskResult};

use super::common::EncryptedEnvelope;
use super::error::PackError;
use super::vpack::{parse_vpack, VpackContents};
use super::vresults::{build_vresults, VresultsMetadata};

/// Report returned by [`execute_vpack`] on success — purely informational,
/// the side-effect of interest is the `.vresults` file written to disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecuteReport {
    /// `pack_id` echoed from the `.vpack` metadata (same UUID is set on the
    /// emitted `.vresults` so the platform can correlate request ↔ response).
    pub pack_id: String,
    /// Number of tasks parsed from the decrypted payload.
    pub task_count: usize,
    /// Number of results emitted (always equal to `task_count` — the registry
    /// always returns a `TaskResult` even on unknown-capability failure).
    pub result_count: usize,
    /// Length of the canonical `.vresults` bytes written to disk.
    pub vresults_bytes_written: usize,
}

/// Errors emitted by [`execute_vpack`].  Variants are intentionally fine-grained
/// for ops/debugging; **callers should treat every variant as a flat
/// "reject this pack" decision** when it comes to security policy.
#[derive(Debug, Error)]
pub enum ExecError {
    /// Output file already exists — refusing to overwrite per the
    /// "fail visibly when assumptions break" rule.  Operator must delete
    /// the existing `.vresults` (or pick a different output path) before
    /// re-running.
    #[error("output path already exists; refusing to overwrite: {0}")]
    OutputExists(PathBuf),

    /// Filesystem I/O failed.
    #[error("I/O failed at {path:?}: {source}")]
    Io {
        /// Path that triggered the failure.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },

    /// Install pack at `state_dir/install-pack.json` missing or invalid.
    #[error("install pack: {0}")]
    InstallPack(#[from] InstallPackError),

    /// `.vpack` envelope failed to parse / verify.
    #[error("vpack envelope: {0}")]
    Pack(#[from] PackError),

    /// Agent private key on disk missing or unreadable.
    #[error("agent key on disk: {0}")]
    AgentKey(#[from] KeyIoError),

    /// X25519/ChaCha20-Poly1305 decrypt or encrypt failed.
    #[error("AEAD: {0}")]
    Aead(#[from] BoxError),

    /// Decoding a base64 install-pack public key failed.  Carries the field
    /// name (`platform_sign_pub` | `platform_enc_pub`) so operators can
    /// see which key in the pack was malformed.
    #[error("install pack public key {field}: {detail}")]
    BadInstallKey {
        /// Field name in the install pack JSON.
        field: &'static str,
        /// Decode error from base64 / length check.
        detail: String,
    },

    /// Platform's Ed25519 verifying key was malformed (passed length check
    /// but Curve25519 rejected the encoding).
    #[error("Ed25519 platform key: {0}")]
    BadPlatformSignKey(#[from] Ed25519Error),

    /// Plaintext payload inside `.vpack` ciphertext is not a JSON array
    /// of [`Task`].
    #[error("plaintext task-list JSON: {0}")]
    TaskListJson(#[source] serde_json::Error),

    /// Failed to serialize the result list back to JSON.  Should never
    /// happen with the canonical `TaskResult` types, kept for completeness.
    #[error("plaintext result-list JSON: {0}")]
    ResultListJson(#[source] serde_json::Error),

    /// The pack was built for a different agent than this one (the `vpack`
    /// metadata's `agent_id` did not match the install pack's
    /// `agent_label`).  Refuse silently executing for the wrong target.
    #[error("agent_id mismatch: install pack `{install}` vs vpack metadata `{vpack}`")]
    AgentIdMismatch {
        /// Agent label this host was provisioned with.
        install: String,
        /// agent_id the pack claims to target.
        vpack: String,
    },

    /// Metadata `task_count` did not match the actual length of the
    /// decoded payload array.  A tampered envelope would fail signature
    /// first, but a producer bug should still be loud.
    #[error("task_count {declared} does not match payload list length {actual}")]
    TaskCountMismatch {
        /// `task_count` from the envelope metadata.
        declared: i32,
        /// Length of the decoded `Vec<Task>`.
        actual: usize,
    },
}

/// Execute a single `.vpack` file end-to-end and write a `.vresults` file
/// to `output_path`.
///
/// `state_dir` is the agent's per-host state directory (the same one
/// `init` populates) — this function reads:
///
/// * `state_dir/install-pack.json` — platform pub keys + this agent's
///   `agent_label`.
/// * `state_dir/keys/sign.key` — agent's Ed25519 private key (for signing
///   the emitted `.vresults`).
/// * `state_dir/keys/enc.key` — agent's X25519 private key (for decrypting
///   the `.vpack` ciphertext).
///
/// Replay prevention (a per-pack-id blacklist that prevents running the
/// same pack twice) lands in **A.7.4** along with the multi-pack scan;
/// this single-pack entry point intentionally does not gate by `pack_id`.
pub fn execute_vpack(
    input_path: &Path,
    output_path: &Path,
    state_dir: &Path,
    registry: &Registry,
) -> Result<ExecuteReport, ExecError> {
    // "Fail visibly when assumptions break" — never silently clobber a
    // previous run's `.vresults`.
    if output_path.exists() {
        return Err(ExecError::OutputExists(output_path.to_path_buf()));
    }

    // Load install pack to recover platform pub keys + this agent's label.
    let install_pack_path = state_dir.join("install-pack.json");
    let install_pack = load_install_pack(&install_pack_path)?;
    let platform_sign_pub_bytes =
        decode_install_pub_key(&install_pack.platform_sign_pub, "platform_sign_pub")?;
    let platform_sign_pub = Ed25519PublicKey::from_bytes(&platform_sign_pub_bytes)?;
    let platform_enc_pub_bytes =
        decode_install_pub_key(&install_pack.platform_enc_pub, "platform_enc_pub")?;
    let platform_enc_pub = X25519PublicKey::from_bytes(&platform_enc_pub_bytes);

    // Load this agent's private keys.
    let agent_sign_priv = load_ed25519_priv(&state_dir.join("keys").join("sign.key"))?;
    let agent_enc_priv = load_x25519_priv(&state_dir.join("keys").join("enc.key"))?;

    // Read + parse + verify the .vpack envelope.
    let envelope_bytes = read_file(input_path)?;
    let VpackContents {
        metadata,
        encrypted_envelope,
        ..
    } = parse_vpack(&envelope_bytes, &platform_sign_pub)?;

    // Cross-check agent_id matches the install pack so a wrong-target pack
    // is rejected before we burn cycles dispatching capabilities.
    if metadata.agent_id != install_pack.agent_label {
        return Err(ExecError::AgentIdMismatch {
            install: install_pack.agent_label.clone(),
            vpack: metadata.agent_id.clone(),
        });
    }

    // Decrypt the ciphertext.  Sender pub comes from the envelope (the
    // platform's ephemeral or static X25519 pub for this pack); recipient
    // is this agent's static X25519 priv.
    let sender_pub = X25519PublicKey::from_bytes(&encrypted_envelope.sender_x25519_pub);
    let nonce = Nonce::from_bytes(encrypted_envelope.nonce);
    let plaintext = open_box(
        &encrypted_envelope.ciphertext,
        &nonce,
        &sender_pub,
        &agent_enc_priv,
    )?;

    // Decode task list and sanity-check task_count.
    let tasks: Vec<Task> = serde_json::from_slice(&plaintext).map_err(ExecError::TaskListJson)?;
    if tasks.len() != metadata.task_count as usize {
        return Err(ExecError::TaskCountMismatch {
            declared: metadata.task_count,
            actual: tasks.len(),
        });
    }

    // Dispatch every task; `Registry` already routes "unknown capability"
    // to a `FAILED` result, so the result list is always 1-to-1 with the
    // input list.
    let results: Vec<TaskResult> = tasks.iter().map(|t| registry.execute(t)).collect();

    // Encrypt the result list to the platform.
    let result_plaintext = serde_json::to_vec(&results).map_err(ExecError::ResultListJson)?;
    let (result_ciphertext, result_nonce) =
        seal_box(&result_plaintext, &platform_enc_pub, &agent_enc_priv)?;
    let result_envelope = EncryptedEnvelope {
        sender_x25519_pub: agent_enc_priv.public_key().to_bytes(),
        nonce: *result_nonce.as_bytes(),
        ciphertext: result_ciphertext,
    };

    // Build the .vresults envelope.  `result_count` is bounded by
    // `tasks.len()`, which itself was validated against `task_count` (an
    // `i32` from the envelope) — therefore `results.len()` cannot exceed
    // `i32::MAX` and the cast is safe.
    let vresults_metadata = VresultsMetadata {
        pack_id: metadata.pack_id.clone(),
        agent_id: metadata.agent_id.clone(),
        executed_at: Utc::now(),
        result_count: results.len() as i32,
    };
    let vresults_bytes = build_vresults(&vresults_metadata, &result_envelope, &agent_sign_priv)?;

    // Persist.
    write_file(output_path, &vresults_bytes)?;

    info!(
        "executed vpack {} (tasks={}, results={}, vresults={} bytes) → {}",
        metadata.pack_id,
        tasks.len(),
        results.len(),
        vresults_bytes.len(),
        output_path.display()
    );

    Ok(ExecuteReport {
        pack_id: metadata.pack_id,
        task_count: tasks.len(),
        result_count: results.len(),
        vresults_bytes_written: vresults_bytes.len(),
    })
}

// ---- Helpers ----

/// Decode a base64 32-byte install-pack public key, returning a
/// field-tagged error on failure.  Mirrors the private decoder inside
/// [`crate::onboard::install_pack`] without taking a dependency on it.
fn decode_install_pub_key(b64: &str, field: &'static str) -> Result<[u8; 32], ExecError> {
    let raw = B64.decode(b64).map_err(|e| ExecError::BadInstallKey {
        field,
        detail: e.to_string(),
    })?;
    if raw.len() != 32 {
        return Err(ExecError::BadInstallKey {
            field,
            detail: format!("expected 32 bytes, got {}", raw.len()),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn read_file(path: &Path) -> Result<Vec<u8>, ExecError> {
    fs::read(path).map_err(|e| ExecError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

fn write_file(path: &Path, content: &[u8]) -> Result<(), ExecError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| ExecError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
    }
    fs::write(path, content).map_err(|e| ExecError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Capability;
    use crate::crypto::ed25519::{generate_ed25519, Ed25519PrivateKey};
    use crate::crypto::keys::{save_ed25519_priv, save_x25519_priv};
    use crate::crypto::x25519_box::{generate_x25519, X25519PrivateKey};
    use crate::pack::vpack::{build_vpack, VpackMetadata};
    use crate::pack::vresults::parse_vresults;
    use tempfile::tempdir;

    /// In-test capability that echoes its task_id back through stdout so a
    /// per-task identity is observable in the result list.
    struct EchoCap {
        my_name: &'static str,
    }

    impl Capability for EchoCap {
        fn name(&self) -> &str {
            self.my_name
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

    /// Fixture: keys + populated `state_dir` plus helpers for building
    /// fresh `.vpack` bytes ready to feed into `execute_vpack`.
    struct Fixture {
        state_dir: tempfile::TempDir,
        platform_sign_priv: Ed25519PrivateKey,
        platform_enc_priv: X25519PrivateKey,
        agent_sign_priv: Ed25519PrivateKey,
        agent_enc_priv: X25519PrivateKey,
        agent_label: String,
    }

    impl Fixture {
        fn new(agent_label: &str) -> Self {
            let state_dir = tempdir().expect("tempdir");
            let platform_sign_priv = generate_ed25519();
            let platform_enc_priv = generate_x25519();
            let agent_sign_priv = generate_ed25519();
            let agent_enc_priv = generate_x25519();

            // Write install-pack.json (real platform pubs so signature and
            // decrypt actually work against this state dir).
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

            // Persist agent keys with the same layout init.rs produces.
            let keys_dir = state_dir.path().join("keys");
            fs::create_dir_all(&keys_dir).unwrap();
            save_ed25519_priv(&keys_dir.join("sign.key"), &agent_sign_priv).unwrap();
            save_x25519_priv(&keys_dir.join("enc.key"), &agent_enc_priv).unwrap();

            Self {
                state_dir,
                platform_sign_priv,
                platform_enc_priv,
                agent_sign_priv,
                agent_enc_priv,
                agent_label: agent_label.to_string(),
            }
        }

        /// Build a `.vpack` byte string sealed for this fixture's agent
        /// from `tasks`, signed by the fixture's platform.
        fn build_vpack_for(&self, pack_id: &str, tasks: &[Task]) -> Vec<u8> {
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
            build_vpack(&metadata, &envelope, &self.platform_sign_priv).unwrap()
        }

        /// Decrypt + verify the agent-produced `.vresults` bytes back into
        /// the `Vec<TaskResult>` the test can assert against.
        fn decode_vresults(&self, bytes: &[u8]) -> Vec<TaskResult> {
            let parsed =
                parse_vresults(bytes, &self.agent_sign_priv.public_key()).expect("parse vresults");
            let nonce = Nonce::from_bytes(parsed.encrypted_envelope.nonce);
            let sender_pub =
                X25519PublicKey::from_bytes(&parsed.encrypted_envelope.sender_x25519_pub);
            let plaintext = open_box(
                &parsed.encrypted_envelope.ciphertext,
                &nonce,
                &sender_pub,
                &self.platform_enc_priv,
            )
            .expect("decrypt vresults");
            serde_json::from_slice(&plaintext).expect("parse Vec<TaskResult>")
        }
    }

    fn echo_registry() -> Registry {
        let mut r = Registry::new();
        r.register(Box::new(EchoCap {
            my_name: "http_attack",
        }));
        r.register(Box::new(EchoCap {
            my_name: "pcap_replay",
        }));
        r
    }

    fn sample_task(task_id: &str, capability: &str) -> Task {
        Task {
            task_id: task_id.to_string(),
            capability: capability.to_string(),
            injector_type: "x".to_string(),
            payload: "{}".to_string(),
            expectations: vec![],
        }
    }

    #[test]
    fn test_execute_round_trip_three_tasks() {
        let fixture = Fixture::new("agent-prod-01");
        let pack_id = "550e8400-e29b-41d4-a716-446655440000";
        let tasks = vec![
            sample_task("t-001", "http_attack"),
            sample_task("t-002", "pcap_replay"),
            sample_task("t-003", "http_attack"),
        ];
        let vpack_bytes = fixture.build_vpack_for(pack_id, &tasks);

        let input_path = fixture.state_dir.path().join("input.vpack");
        let output_path = fixture.state_dir.path().join("output.vresults");
        fs::write(&input_path, &vpack_bytes).unwrap();

        let registry = echo_registry();
        let report = execute_vpack(
            &input_path,
            &output_path,
            fixture.state_dir.path(),
            &registry,
        )
        .expect("execute");

        assert_eq!(report.pack_id, pack_id);
        assert_eq!(report.task_count, 3);
        assert_eq!(report.result_count, 3);
        assert!(report.vresults_bytes_written > 0);
        assert!(output_path.exists());

        // Decrypt + verify the produced .vresults.
        let results = fixture.decode_vresults(&fs::read(&output_path).unwrap());
        assert_eq!(results.len(), 3);
        for (i, r) in results.iter().enumerate() {
            assert_eq!(r.status, "SUCCESS");
            assert_eq!(r.exit_code, 0);
            assert_eq!(r.stdout.as_deref(), Some(tasks[i].task_id.as_str()));
        }
    }

    #[test]
    fn test_execute_empty_task_list() {
        let fixture = Fixture::new("agent-prod-01");
        let vpack_bytes = fixture.build_vpack_for("550e8400-e29b-41d4-a716-446655440001", &[]);

        let input_path = fixture.state_dir.path().join("empty.vpack");
        let output_path = fixture.state_dir.path().join("empty.vresults");
        fs::write(&input_path, &vpack_bytes).unwrap();

        let report = execute_vpack(
            &input_path,
            &output_path,
            fixture.state_dir.path(),
            &echo_registry(),
        )
        .expect("execute empty");
        assert_eq!(report.task_count, 0);
        assert_eq!(report.result_count, 0);

        let results = fixture.decode_vresults(&fs::read(&output_path).unwrap());
        assert!(results.is_empty());
    }

    #[test]
    fn test_execute_unknown_capability_yields_failed_result() {
        // Registry has nothing registered, so every task should come back
        // FAILED via Registry's default route.
        let fixture = Fixture::new("agent-prod-01");
        let tasks = vec![sample_task("t-001", "definitely_not_registered")];
        let vpack_bytes = fixture.build_vpack_for("550e8400-e29b-41d4-a716-446655440002", &tasks);

        let input_path = fixture.state_dir.path().join("unknown.vpack");
        let output_path = fixture.state_dir.path().join("unknown.vresults");
        fs::write(&input_path, &vpack_bytes).unwrap();

        let empty_registry = Registry::new();
        let report = execute_vpack(
            &input_path,
            &output_path,
            fixture.state_dir.path(),
            &empty_registry,
        )
        .expect("execute still succeeds at envelope level");
        assert_eq!(report.result_count, 1);

        let results = fixture.decode_vresults(&fs::read(&output_path).unwrap());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, "FAILED");
        assert!(results[0]
            .error_message
            .as_ref()
            .unwrap()
            .contains("definitely_not_registered"));
    }

    #[test]
    fn test_execute_rejects_overwrite() {
        let fixture = Fixture::new("agent-prod-01");
        let vpack_bytes = fixture.build_vpack_for("550e8400-e29b-41d4-a716-446655440003", &[]);

        let input_path = fixture.state_dir.path().join("ow.vpack");
        let output_path = fixture.state_dir.path().join("ow.vresults");
        fs::write(&input_path, &vpack_bytes).unwrap();
        // Pre-create the output to trigger the overwrite guard.
        fs::write(&output_path, b"pre-existing").unwrap();

        let err = execute_vpack(
            &input_path,
            &output_path,
            fixture.state_dir.path(),
            &echo_registry(),
        )
        .expect_err("must refuse overwrite");
        assert!(matches!(err, ExecError::OutputExists(_)), "got {err:?}");
    }

    #[test]
    fn test_execute_rejects_wrong_platform_signer() {
        // Build a .vpack with a DIFFERENT platform sign key than the one
        // recorded in install-pack.json → signer mismatch.
        let fixture = Fixture::new("agent-prod-01");
        let attacker_sign = generate_ed25519();
        let plaintext = serde_json::to_vec::<Vec<Task>>(&vec![]).unwrap();
        let agent_enc_pub = fixture.agent_enc_priv.public_key();
        let (ciphertext, nonce) =
            seal_box(&plaintext, &agent_enc_pub, &fixture.platform_enc_priv).unwrap();
        let envelope = EncryptedEnvelope {
            sender_x25519_pub: fixture.platform_enc_priv.public_key().to_bytes(),
            nonce: *nonce.as_bytes(),
            ciphertext,
        };
        let metadata = VpackMetadata {
            pack_id: "550e8400-e29b-41d4-a716-446655440004".to_string(),
            platform_id: "plt_test".to_string(),
            agent_id: "agent-prod-01".to_string(),
            issued_at: Utc::now(),
            task_count: 0,
            schema_version_payload: "1.0".to_string(),
            exported_by: "attacker".to_string(),
        };
        // Sign with the WRONG (attacker) key.
        let vpack_bytes = build_vpack(&metadata, &envelope, &attacker_sign).unwrap();

        let input_path = fixture.state_dir.path().join("bad-sig.vpack");
        let output_path = fixture.state_dir.path().join("bad-sig.vresults");
        fs::write(&input_path, &vpack_bytes).unwrap();

        let err = execute_vpack(
            &input_path,
            &output_path,
            fixture.state_dir.path(),
            &echo_registry(),
        )
        .expect_err("must reject wrong signer");
        assert!(matches!(err, ExecError::Pack(_)), "got {err:?}");
        // No output should have been created.
        assert!(!output_path.exists());
    }

    #[test]
    fn test_execute_rejects_agent_id_mismatch() {
        // Build a valid .vpack but targeting a DIFFERENT agent than this
        // host's install pack.
        let fixture = Fixture::new("agent-host-A");
        let plaintext = serde_json::to_vec::<Vec<Task>>(&vec![]).unwrap();
        let agent_enc_pub = fixture.agent_enc_priv.public_key();
        let (ciphertext, nonce) =
            seal_box(&plaintext, &agent_enc_pub, &fixture.platform_enc_priv).unwrap();
        let envelope = EncryptedEnvelope {
            sender_x25519_pub: fixture.platform_enc_priv.public_key().to_bytes(),
            nonce: *nonce.as_bytes(),
            ciphertext,
        };
        let metadata = VpackMetadata {
            pack_id: "550e8400-e29b-41d4-a716-446655440005".to_string(),
            platform_id: "plt_test".to_string(),
            agent_id: "agent-host-B".to_string(), // wrong target
            issued_at: Utc::now(),
            task_count: 0,
            schema_version_payload: "1.0".to_string(),
            exported_by: "alice@platform".to_string(),
        };
        let vpack_bytes = build_vpack(&metadata, &envelope, &fixture.platform_sign_priv).unwrap();

        let input_path = fixture.state_dir.path().join("wrong-target.vpack");
        let output_path = fixture.state_dir.path().join("wrong-target.vresults");
        fs::write(&input_path, &vpack_bytes).unwrap();

        let err = execute_vpack(
            &input_path,
            &output_path,
            fixture.state_dir.path(),
            &echo_registry(),
        )
        .expect_err("must reject wrong agent");
        match err {
            ExecError::AgentIdMismatch { install, vpack } => {
                assert_eq!(install, "agent-host-A");
                assert_eq!(vpack, "agent-host-B");
            }
            other => panic!("expected AgentIdMismatch, got {other:?}"),
        }
        assert!(!output_path.exists());
    }

    #[test]
    fn test_execute_rejects_when_install_pack_missing() {
        let state_dir = tempdir().unwrap();
        // No install-pack.json written.
        let input_path = state_dir.path().join("foo.vpack");
        let output_path = state_dir.path().join("foo.vresults");
        fs::write(&input_path, b"unused").unwrap();

        let err = execute_vpack(
            &input_path,
            &output_path,
            state_dir.path(),
            &echo_registry(),
        )
        .expect_err("must surface missing install pack");
        assert!(matches!(err, ExecError::InstallPack(_)), "got {err:?}");
    }

    #[test]
    fn test_execute_rejects_when_vpack_input_missing() {
        let fixture = Fixture::new("agent-prod-01");
        let missing = fixture.state_dir.path().join("does-not-exist.vpack");
        let output_path = fixture.state_dir.path().join("out.vresults");

        let err = execute_vpack(
            &missing,
            &output_path,
            fixture.state_dir.path(),
            &echo_registry(),
        )
        .expect_err("must surface missing input");
        match err {
            ExecError::Io { path, .. } => assert_eq!(path, missing),
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn test_execute_rejects_when_agent_enc_key_wrong() {
        // Build a .vpack sealed to a *different* agent enc key — open_box
        // should fail in AEAD.
        let fixture = Fixture::new("agent-prod-01");
        let other_agent_enc = generate_x25519();
        let plaintext = serde_json::to_vec::<Vec<Task>>(&vec![]).unwrap();
        let (ciphertext, nonce) = seal_box(
            &plaintext,
            &other_agent_enc.public_key(),
            &fixture.platform_enc_priv,
        )
        .unwrap();
        let envelope = EncryptedEnvelope {
            sender_x25519_pub: fixture.platform_enc_priv.public_key().to_bytes(),
            nonce: *nonce.as_bytes(),
            ciphertext,
        };
        let metadata = VpackMetadata {
            pack_id: "550e8400-e29b-41d4-a716-446655440006".to_string(),
            platform_id: "plt_test".to_string(),
            agent_id: "agent-prod-01".to_string(),
            issued_at: Utc::now(),
            task_count: 0,
            schema_version_payload: "1.0".to_string(),
            exported_by: "alice@platform".to_string(),
        };
        let vpack_bytes = build_vpack(&metadata, &envelope, &fixture.platform_sign_priv).unwrap();

        let input_path = fixture.state_dir.path().join("wrong-enc.vpack");
        let output_path = fixture.state_dir.path().join("wrong-enc.vresults");
        fs::write(&input_path, &vpack_bytes).unwrap();

        let err = execute_vpack(
            &input_path,
            &output_path,
            fixture.state_dir.path(),
            &echo_registry(),
        )
        .expect_err("must surface AEAD failure");
        assert!(matches!(err, ExecError::Aead(_)), "got {err:?}");
        assert!(!output_path.exists());
    }

    #[test]
    fn test_execute_pack_id_preserved_in_vresults() {
        let fixture = Fixture::new("agent-prod-01");
        let pack_id = "11111111-2222-3333-4444-555555555555";
        let vpack_bytes = fixture.build_vpack_for(pack_id, &[]);

        let input_path = fixture.state_dir.path().join("preserve.vpack");
        let output_path = fixture.state_dir.path().join("preserve.vresults");
        fs::write(&input_path, &vpack_bytes).unwrap();

        execute_vpack(
            &input_path,
            &output_path,
            fixture.state_dir.path(),
            &echo_registry(),
        )
        .unwrap();

        let parsed = parse_vresults(
            &fs::read(&output_path).unwrap(),
            &fixture.agent_sign_priv.public_key(),
        )
        .unwrap();
        assert_eq!(parsed.metadata.pack_id, pack_id);
        assert_eq!(parsed.metadata.agent_id, "agent-prod-01");
    }

    #[test]
    fn test_execute_creates_output_parent_directory() {
        let fixture = Fixture::new("agent-prod-01");
        let vpack_bytes = fixture.build_vpack_for("550e8400-e29b-41d4-a716-446655440007", &[]);

        let input_path = fixture.state_dir.path().join("nested.vpack");
        // Output parent does NOT exist yet — execute_vpack must create it.
        let output_path = fixture
            .state_dir
            .path()
            .join("outputs")
            .join("subdir")
            .join("nested.vresults");
        fs::write(&input_path, &vpack_bytes).unwrap();

        execute_vpack(
            &input_path,
            &output_path,
            fixture.state_dir.path(),
            &echo_registry(),
        )
        .unwrap();
        assert!(output_path.exists());
    }

    #[test]
    fn test_decode_install_pub_key_rejects_wrong_length() {
        // 16 bytes base64 — install pack should reject before reaching
        // this helper, but the helper itself must be loud either way.
        let too_short = B64.encode([0u8; 16]);
        let err = decode_install_pub_key(&too_short, "platform_sign_pub")
            .expect_err("must reject 16-byte key");
        match err {
            ExecError::BadInstallKey { field, detail } => {
                assert_eq!(field, "platform_sign_pub");
                assert!(detail.contains("32 bytes"), "{detail}");
            }
            other => panic!("expected BadInstallKey, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_install_pub_key_rejects_bad_base64() {
        let err = decode_install_pub_key("not-base64!!!", "platform_enc_pub")
            .expect_err("must reject garbage");
        match err {
            ExecError::BadInstallKey { field, .. } => {
                assert_eq!(field, "platform_enc_pub");
            }
            other => panic!("expected BadInstallKey, got {other:?}"),
        }
    }
}
