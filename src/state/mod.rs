//! Local agent state (SQLite-backed).
//!
//! Used today to track which Mode-C offline packs have already been
//! executed, so a replayed pack does not run twice.  See [`sqlite`] for the
//! schema and behaviour.

pub mod sqlite;

#[allow(unused_imports)]
pub use sqlite::{StateError, StateStore};
