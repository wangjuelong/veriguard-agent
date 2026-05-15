//! Persistent agent-side replay-prevention store for Mode C offline packs.
//!
//! Records every `.vpack` the agent has *attempted* to execute, keyed by
//! `pack_id`.  The [`super::scanner`] consults this on every directory
//! pass to skip already-seen packs, preventing accidental double-execution
//! of the same attack workload.
//!
//! ## File layout
//!
//! `<state_dir>/executed-packs.json`:
//!
//! ```json
//! {
//!   "schema_version": "1.0",
//!   "entries": [
//!     {
//!       "pack_id":         "550e8400-e29b-41d4-a716-446655440000",
//!       "executed_at":     "2026-05-15T10:30:00Z",
//!       "vpack_path":      "/var/lib/veriguard/inbox/foo.vpack",
//!       "vresults_path":   "/var/lib/veriguard/inbox/foo.vresults",
//!       "task_count":      3,
//!       "result_count":    3,
//!       "outcome":         "success"
//!     }
//!   ]
//! }
//! ```
//!
//! Fields are not alphabetical (this file is operator-readable state, not
//! a cross-language wire artifact — `serde_json::to_vec_pretty` is allowed
//! to use struct-declaration order).  `entries` is sorted by
//! `(executed_at, pack_id)` on every write to keep the file
//! `diff`-friendly across runs.
//!
//! ## ACID
//!
//! [`save`] writes to a `.tmp` sibling first and then atomic-renames into
//! place, so a crash mid-write can never leave a half-flushed JSON.  This
//! is the same idiom the spec calls out for `state/` files.
//!
//! ## Strict-replay policy
//!
//! Every attempt — success, signature failure, AEAD failure, refusal to
//! overwrite — records an entry.  To re-execute a previously-seen pack
//! the operator must manually edit `executed-packs.json` to drop the
//! offending entry **and** delete any leftover `.vresults` file.  This
//! intentional friction prevents accidental re-execution of attacks and
//! matches the platform-side `executed_packs` PRIMARY KEY semantics
//! recorded in `project_veriguard_wire_contract_locked.md`.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use log::warn;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Filename inside `state_dir` that holds the blacklist.
pub const FILE_NAME: &str = "executed-packs.json";

/// Current `schema_version` value embedded in the blacklist file.
pub const SCHEMA_VERSION: &str = "1.0";

/// Outcome label recorded per pack.  Variants map 1-to-1 onto
/// [`super::executor::ExecError`] so the post-mortem JSON is self-documenting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Pack executed end-to-end, `.vresults` written.
    Success,
    /// `.vpack` Ed25519 signature verify failed or envelope metadata invalid.
    SignatureFailed,
    /// X25519 ECDH / ChaCha20-Poly1305 decrypt or encrypt failed.
    AeadFailed,
    /// Pack targeted a different `agent_id` than this host.
    AgentIdMismatch,
    /// Envelope `task_count` did not match the decoded payload list length.
    TaskCountMismatch,
    /// `.vresults` output path already existed — scanner refused to clobber.
    OutputExists,
    /// `install-pack.json` was missing, malformed, or contained an invalid
    /// platform public key.  Covers `InstallPack` / `BadInstallKey` /
    /// `BadPlatformSignKey` variants of `ExecError`.
    InstallPackInvalid,
    /// Agent's private key on disk was unreadable or malformed.
    KeyLoadFailed,
    /// Decrypted payload was not a JSON array of `Task`.
    TaskListParseFailed,
    /// Serializing the result list back to JSON failed (should not happen
    /// in practice; the variant is mirrored from `ExecError` for completeness).
    ResultListSerializeFailed,
    /// Filesystem I/O on `.vpack` or `.vresults` failed.
    IoError,
}

/// One persisted blacklist entry.  Field order matches the on-disk JSON
/// layout (the serializer preserves struct-declaration order via
/// `serde_json::to_vec_pretty`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// `pack_id` from the `.vpack` `metadata_plaintext` (lowercase UUID).
    pub pack_id: String,
    /// When the agent recorded the attempt (RFC 3339 UTC `Z` suffix).
    pub executed_at: DateTime<Utc>,
    /// Filesystem path of the source `.vpack` the entry came from.
    pub vpack_path: PathBuf,
    /// Filesystem path of the produced `.vresults`, if execution succeeded.
    /// `None` for any non-`Success` outcome.
    pub vresults_path: Option<PathBuf>,
    /// `task_count` from the envelope metadata, recorded only on success.
    pub task_count: Option<i32>,
    /// Number of `TaskResult`s emitted, recorded only on success.
    pub result_count: Option<i32>,
    /// Single-word classification of the outcome.
    pub outcome: Outcome,
}

/// Errors returned by the blacklist API.
#[derive(Debug, Error)]
pub enum BlacklistError {
    /// Filesystem operation failed.
    #[error("blacklist I/O at {path:?}: {source}")]
    Io {
        /// Path that triggered the error.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// JSON parse or serialize failed.
    #[error("blacklist JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// `schema_version` was not `"1.0"`.  Refuse-and-shout — silently
    /// upgrading a forward-incompatible file would risk replay-prevention
    /// holes.
    #[error("unsupported blacklist schema_version: expected \"1.0\", got {0:?}")]
    UnsupportedSchemaVersion(String),
}

/// On-disk wrapper struct.  Internal — callers should use [`load`],
/// [`save`], [`append`].
#[derive(Debug, Serialize, Deserialize)]
struct FileV1 {
    schema_version: String,
    entries: Vec<Entry>,
}

/// Compute the canonical blacklist path for a given state directory.
pub fn path(state_dir: &Path) -> PathBuf {
    state_dir.join(FILE_NAME)
}

/// Load the blacklist into a `HashMap<pack_id, Entry>` keyed by `pack_id`.
///
/// A missing file is treated as an empty blacklist (first-ever scan) and
/// returns an empty map without surfacing an I/O error.  Every other
/// failure (corrupt JSON, wrong schema version, permission denied) is
/// surfaced — callers should treat those as scan-aborting.
pub fn load(state_dir: &Path) -> Result<HashMap<String, Entry>, BlacklistError> {
    let p = path(state_dir);
    if !p.exists() {
        return Ok(HashMap::new());
    }
    let bytes = fs::read(&p).map_err(|e| BlacklistError::Io {
        path: p.clone(),
        source: e,
    })?;
    let file: FileV1 = serde_json::from_slice(&bytes)?;
    if file.schema_version != SCHEMA_VERSION {
        return Err(BlacklistError::UnsupportedSchemaVersion(
            file.schema_version,
        ));
    }
    Ok(file
        .entries
        .into_iter()
        .map(|e| (e.pack_id.clone(), e))
        .collect())
}

/// Append (or replace) a single entry and atomically persist the
/// resulting blacklist.
///
/// "Replace" semantics: if `entry.pack_id` already exists in the
/// blacklist, the new entry overwrites the old one.  Re-recording the
/// same pack_id is not expected during a healthy scan (scanner gates by
/// blacklist before calling this), but it can happen if an operator
/// drops a duplicate-id pack into the scan dir.
pub fn append(state_dir: &Path, entry: Entry) -> Result<(), BlacklistError> {
    let mut map = load(state_dir)?;
    map.insert(entry.pack_id.clone(), entry);
    save(state_dir, &map)
}

/// Atomically rewrite the blacklist file from a map.  Used internally by
/// [`append`] and exposed for tests / future bulk-edit tools.
pub fn save(state_dir: &Path, map: &HashMap<String, Entry>) -> Result<(), BlacklistError> {
    fs::create_dir_all(state_dir).map_err(|e| BlacklistError::Io {
        path: state_dir.to_path_buf(),
        source: e,
    })?;

    let final_path = path(state_dir);
    let tmp_path = with_suffix(&final_path, ".tmp");

    let mut entries: Vec<Entry> = map.values().cloned().collect();
    entries.sort_by(|a, b| {
        a.executed_at
            .cmp(&b.executed_at)
            .then_with(|| a.pack_id.cmp(&b.pack_id))
    });

    let file = FileV1 {
        schema_version: SCHEMA_VERSION.to_string(),
        entries,
    };
    let bytes = serde_json::to_vec_pretty(&file)?;

    // Write to tmp first; rename is the only step that touches the
    // canonical filename so an interrupted run cannot leave a partially
    // written `executed-packs.json`.
    fs::write(&tmp_path, &bytes).map_err(|e| BlacklistError::Io {
        path: tmp_path.clone(),
        source: e,
    })?;
    if let Err(e) = fs::rename(&tmp_path, &final_path) {
        // Best-effort cleanup of the orphaned tmp so a future save's
        // `fs::write` doesn't see a stale file.  We log but do not fail
        // here — the rename error is the operationally important signal.
        if let Err(cleanup_err) = fs::remove_file(&tmp_path) {
            warn!(
                "failed to clean up orphan blacklist tmp file {}: {cleanup_err}",
                tmp_path.display()
            );
        }
        return Err(BlacklistError::Io {
            path: final_path.clone(),
            source: e,
        });
    }
    Ok(())
}

/// Append `suffix` to the file name (`foo.json` → `foo.json.tmp`).  Uses
/// the path's `OsString` representation so non-UTF8 components survive.
fn with_suffix(p: &Path, suffix: &str) -> PathBuf {
    let mut buf = p.as_os_str().to_os_string();
    buf.push(suffix);
    PathBuf::from(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::tempdir;

    fn entry(pack_id: &str, outcome: Outcome) -> Entry {
        Entry {
            pack_id: pack_id.to_string(),
            executed_at: Utc.with_ymd_and_hms(2026, 5, 15, 10, 30, 0).unwrap(),
            vpack_path: PathBuf::from("/tmp/x.vpack"),
            vresults_path: if matches!(outcome, Outcome::Success) {
                Some(PathBuf::from("/tmp/x.vresults"))
            } else {
                None
            },
            task_count: if matches!(outcome, Outcome::Success) {
                Some(3)
            } else {
                None
            },
            result_count: if matches!(outcome, Outcome::Success) {
                Some(3)
            } else {
                None
            },
            outcome,
        }
    }

    #[test]
    fn test_load_missing_file_returns_empty_map() {
        let dir = tempdir().unwrap();
        let map = load(dir.path()).expect("load missing");
        assert!(map.is_empty());
        assert!(!path(dir.path()).exists());
    }

    #[test]
    fn test_append_then_load_round_trips_one_entry() {
        let dir = tempdir().unwrap();
        let e = entry("550e8400-e29b-41d4-a716-446655440000", Outcome::Success);
        append(dir.path(), e.clone()).expect("append");

        let map = load(dir.path()).expect("reload");
        assert_eq!(map.len(), 1);
        let got = map.get(&e.pack_id).expect("present");
        assert_eq!(got, &e);
    }

    #[test]
    fn test_append_multiple_entries_persist_all() {
        let dir = tempdir().unwrap();
        let a = entry("11111111-1111-1111-1111-111111111111", Outcome::Success);
        let b = entry(
            "22222222-2222-2222-2222-222222222222",
            Outcome::SignatureFailed,
        );
        let c = entry("33333333-3333-3333-3333-333333333333", Outcome::AeadFailed);
        append(dir.path(), a.clone()).unwrap();
        append(dir.path(), b.clone()).unwrap();
        append(dir.path(), c.clone()).unwrap();

        let map = load(dir.path()).unwrap();
        assert_eq!(map.len(), 3);
        assert!(map.contains_key(&a.pack_id));
        assert!(map.contains_key(&b.pack_id));
        assert!(map.contains_key(&c.pack_id));
    }

    #[test]
    fn test_append_same_pack_id_overwrites() {
        let dir = tempdir().unwrap();
        let mut first = entry(
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            Outcome::SignatureFailed,
        );
        first.task_count = None;
        let mut second = first.clone();
        second.outcome = Outcome::Success;
        second.task_count = Some(5);
        second.result_count = Some(5);
        second.vresults_path = Some(PathBuf::from("/tmp/out.vresults"));

        append(dir.path(), first).unwrap();
        append(dir.path(), second.clone()).unwrap();

        let map = load(dir.path()).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.values().next().unwrap(), &second);
    }

    #[test]
    fn test_save_writes_schema_version_constant() {
        let dir = tempdir().unwrap();
        save(dir.path(), &HashMap::new()).unwrap();
        let raw = std::fs::read_to_string(path(dir.path())).unwrap();
        assert!(raw.contains(r#""schema_version": "1.0""#), "raw={raw}");
    }

    #[test]
    fn test_load_rejects_wrong_schema_version() {
        let dir = tempdir().unwrap();
        std::fs::write(
            path(dir.path()),
            br#"{"schema_version":"2.0","entries":[]}"#,
        )
        .unwrap();
        let err = load(dir.path()).expect_err("must reject");
        match err {
            BlacklistError::UnsupportedSchemaVersion(got) => assert_eq!(got, "2.0"),
            other => panic!("expected UnsupportedSchemaVersion, got {other:?}"),
        }
    }

    #[test]
    fn test_load_rejects_corrupt_json() {
        let dir = tempdir().unwrap();
        std::fs::write(path(dir.path()), b"{ not json").unwrap();
        let err = load(dir.path()).expect_err("must reject");
        assert!(matches!(err, BlacklistError::Json(_)), "got {err:?}");
    }

    #[test]
    fn test_save_does_not_leave_tmp_file_on_success() {
        let dir = tempdir().unwrap();
        let mut map = HashMap::new();
        let e = entry("550e8400-e29b-41d4-a716-446655440099", Outcome::Success);
        map.insert(e.pack_id.clone(), e);
        save(dir.path(), &map).unwrap();

        let tmp = with_suffix(&path(dir.path()), ".tmp");
        assert!(!tmp.exists(), "tmp file should have been renamed away");
        assert!(path(dir.path()).exists());
    }

    #[test]
    fn test_save_creates_state_dir_if_missing() {
        let parent = tempdir().unwrap();
        let nested = parent.path().join("does").join("not").join("exist");
        save(&nested, &HashMap::new()).unwrap();
        assert!(path(&nested).exists());
    }

    #[test]
    fn test_save_sorts_entries_by_executed_at_then_pack_id() {
        let dir = tempdir().unwrap();
        let mut map = HashMap::new();
        let mut e1 = entry("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz", Outcome::Success);
        e1.executed_at = Utc.with_ymd_and_hms(2026, 5, 15, 11, 0, 0).unwrap();
        let mut e2 = entry("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Outcome::Success);
        e2.executed_at = Utc.with_ymd_and_hms(2026, 5, 15, 10, 0, 0).unwrap();
        let mut e3 = entry("mmmmmmmm-mmmm-mmmm-mmmm-mmmmmmmmmmmm", Outcome::Success);
        e3.executed_at = Utc.with_ymd_and_hms(2026, 5, 15, 10, 0, 0).unwrap();
        map.insert(e1.pack_id.clone(), e1.clone());
        map.insert(e2.pack_id.clone(), e2.clone());
        map.insert(e3.pack_id.clone(), e3.clone());

        save(dir.path(), &map).unwrap();
        let raw = std::fs::read_to_string(path(dir.path())).unwrap();
        // e2 (10:00 aaaa) < e3 (10:00 mmmm) < e1 (11:00 zzzz).
        let pos_e2 = raw.find(&e2.pack_id).unwrap();
        let pos_e3 = raw.find(&e3.pack_id).unwrap();
        let pos_e1 = raw.find(&e1.pack_id).unwrap();
        assert!(pos_e2 < pos_e3 && pos_e3 < pos_e1, "ordering wrong: {raw}");
    }

    #[test]
    fn test_outcome_serializes_snake_case() {
        let dir = tempdir().unwrap();
        let mut map = HashMap::new();
        let cases = [
            (
                "11111111-1111-1111-1111-111111111111",
                Outcome::SignatureFailed,
            ),
            ("22222222-2222-2222-2222-222222222222", Outcome::AeadFailed),
            (
                "33333333-3333-3333-3333-333333333333",
                Outcome::AgentIdMismatch,
            ),
        ];
        for (id, out) in cases {
            map.insert(id.to_string(), entry(id, out));
        }
        save(dir.path(), &map).unwrap();
        let raw = std::fs::read_to_string(path(dir.path())).unwrap();
        assert!(raw.contains(r#""outcome": "signature_failed""#), "{raw}");
        assert!(raw.contains(r#""outcome": "aead_failed""#));
        assert!(raw.contains(r#""outcome": "agent_id_mismatch""#));
    }

    #[test]
    fn test_path_helper_returns_expected_filename() {
        let dir = tempdir().unwrap();
        let p = path(dir.path());
        assert_eq!(p.file_name().unwrap(), "executed-packs.json");
        assert_eq!(p.parent().unwrap(), dir.path());
    }
}
