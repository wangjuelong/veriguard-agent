//! SQLite-backed local state store.
//!
//! Currently the only table is `executed_packs` — a blacklist of Mode-C
//! offline packs that have already been executed.  The agent consults this
//! table before running a pack so that a replayed pack is silently dropped
//! instead of running twice.
//!
//! ## Schema
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS executed_packs (
//!     pack_id            TEXT NOT NULL PRIMARY KEY,
//!     executed_at        INTEGER NOT NULL,   -- unix epoch seconds
//!     result_count       INTEGER NOT NULL,
//!     ciphertext_sha256  TEXT NOT NULL
//! );
//! CREATE INDEX IF NOT EXISTS idx_executed_packs_executed_at
//!     ON executed_packs(executed_at);
//! ```
//!
//! ## Concurrency
//!
//! `rusqlite::Connection` is `Send` but not `Sync`.  The agent today runs
//! pack execution on a single thread so a non-pooled connection is fine; if
//! future work moves to multi-threaded execution, wrap [`StateStore`] in a
//! `Mutex` or migrate to a connection pool.
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};
use thiserror::Error;

/// Errors emitted by the state store.
#[derive(Debug, Error)]
pub enum StateError {
    /// Failed to open the SQLite database file at `path`.  This is distinct
    /// from [`StateError::Sql`]: it carries the on-disk path so callers can
    /// surface a meaningful "database file unreadable" message and is only
    /// constructed by the explicit `open` call sites (never by the `?`
    /// operator on query failures).
    #[error("failed to open SQLite database at {path}: {source}")]
    Open {
        /// The filesystem path the agent tried to open.  Use
        /// `<in-memory>` for [`StateStore::open_in_memory`].
        path: PathBuf,
        /// Underlying rusqlite open failure.
        #[source]
        source: rusqlite::Error,
    },

    /// SQL execution / query failure.  Every `?` on a `rusqlite::Error`
    /// inside this module maps here.
    #[error("SQLite query error: {0}")]
    Sql(#[from] rusqlite::Error),
}

/// Lightweight wrapper around a rusqlite [`Connection`].
pub struct StateStore {
    conn: Connection,
}

impl StateStore {
    /// Open (or create) the SQLite database at `path` and apply the schema.
    pub fn open(path: &Path) -> Result<Self, StateError> {
        let conn = Connection::open(path).map_err(|source| StateError::Open {
            path: path.to_path_buf(),
            source,
        })?;
        apply_schema(&conn)?;
        Ok(Self { conn })
    }

    /// Open an in-memory database — useful for tests.
    pub fn open_in_memory() -> Result<Self, StateError> {
        let conn = Connection::open_in_memory().map_err(|source| StateError::Open {
            path: PathBuf::from("<in-memory>"),
            source,
        })?;
        apply_schema(&conn)?;
        Ok(Self { conn })
    }

    /// Mark `pack_id` as executed.  Returns [`rusqlite::Error::SqliteFailure`]
    /// (wrapped in [`StateError::Sql`]) if the same `pack_id` was already
    /// recorded — the primary-key conflict is the replay-protection signal.
    pub fn mark_executed(
        &self,
        pack_id: &str,
        executed_at_unix: i64,
        result_count: u32,
        ciphertext_sha256: &str,
    ) -> Result<(), StateError> {
        self.conn.execute(
            "INSERT INTO executed_packs (pack_id, executed_at, result_count, ciphertext_sha256) \
             VALUES (?1, ?2, ?3, ?4)",
            params![pack_id, executed_at_unix, result_count, ciphertext_sha256],
        )?;
        Ok(())
    }

    /// Returns `true` if the pack with `pack_id` has already been recorded.
    pub fn is_executed(&self, pack_id: &str) -> Result<bool, StateError> {
        let row = self
            .conn
            .query_row(
                "SELECT 1 FROM executed_packs WHERE pack_id = ?1",
                params![pack_id],
                |_| Ok(()),
            )
            .optional()?;
        Ok(row.is_some())
    }

    /// Total number of recorded executions.
    pub fn count_executed(&self) -> Result<u64, StateError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM executed_packs", [], |row| row.get(0))?;
        Ok(n as u64)
    }
}

fn apply_schema(conn: &Connection) -> Result<(), StateError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS executed_packs (\
            pack_id            TEXT NOT NULL PRIMARY KEY,\
            executed_at        INTEGER NOT NULL,\
            result_count       INTEGER NOT NULL,\
            ciphertext_sha256  TEXT NOT NULL\
         );\
         CREATE INDEX IF NOT EXISTS idx_executed_packs_executed_at \
             ON executed_packs(executed_at);",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fixture() -> (tempfile::TempDir, StateStore) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        let store = StateStore::open(&path).expect("open");
        (dir, store)
    }

    #[test]
    fn test_state_open_creates_schema() {
        let (_dir, store) = fixture();
        // Schema applied if a SELECT against the table parses.
        let count = store.count_executed().expect("count");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_state_mark_and_is_executed_roundtrip() {
        let (_dir, store) = fixture();
        let pack_id = "pack-0001";

        assert!(!store.is_executed(pack_id).unwrap(), "fresh DB: false");
        store
            .mark_executed(pack_id, 1715688000, 3, "deadbeef")
            .unwrap();
        assert!(store.is_executed(pack_id).unwrap(), "after mark: true");
    }

    #[test]
    fn test_state_is_executed_returns_false_for_unknown() {
        let (_dir, store) = fixture();
        assert!(!store.is_executed("nonexistent").unwrap());
    }

    #[test]
    fn test_state_mark_duplicate_pack_returns_err() {
        let (_dir, store) = fixture();
        store
            .mark_executed("pack-dup", 1715688000, 1, "abc")
            .unwrap();
        let err = store
            .mark_executed("pack-dup", 1715688001, 2, "def")
            .expect_err("duplicate must fail");

        // Confirm the underlying SQLite primary-key conflict.
        match err {
            StateError::Sql(rusqlite::Error::SqliteFailure(e, _)) => {
                assert_eq!(e.code, rusqlite::ErrorCode::ConstraintViolation);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }

        // Count must still be 1.
        assert_eq!(store.count_executed().unwrap(), 1);
    }

    #[test]
    fn test_state_count_matches() {
        let (_dir, store) = fixture();
        for i in 0..3 {
            store
                .mark_executed(&format!("pack-{i}"), 1715688000 + i, 1, "x")
                .unwrap();
        }
        assert_eq!(store.count_executed().unwrap(), 3);
    }

    #[test]
    fn test_state_persists_across_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("persist.sqlite");

        {
            let store = StateStore::open(&path).expect("open #1");
            store.mark_executed("p1", 100, 1, "h").unwrap();
        }

        let store2 = StateStore::open(&path).expect("open #2");
        assert!(store2.is_executed("p1").unwrap());
        assert_eq!(store2.count_executed().unwrap(), 1);
    }

    #[test]
    fn test_state_open_invalid_path_returns_open_variant() {
        // Path inside a non-existent directory cannot be opened by rusqlite;
        // confirm the error is the disambiguated `Open { path, .. }` variant,
        // not `Sql(_)`.  This pins the `From<rusqlite::Error>` impl so it
        // can't silently start routing open failures to `StateError::Sql`.
        // `StateStore` doesn't impl `Debug`, so we use `match` on `Result`
        // rather than `expect_err()`.
        let bad_path = Path::new("/nonexistent/dir/does/not/exist/state.sqlite");
        match StateStore::open(bad_path) {
            Ok(_) => panic!("open must fail for unreadable path"),
            Err(StateError::Open { path, .. }) => {
                assert_eq!(path, bad_path);
            }
            Err(other) => panic!("expected StateError::Open, got {other:?}"),
        }
    }
}
