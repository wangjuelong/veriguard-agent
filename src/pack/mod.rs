//! `.vpack` / `.vresults` Mode C offline pack flow (spec § 3.5).
//!
//! ## Submodules
//!
//! - [`common`] — shared helpers + constants + the [`EncryptedEnvelope`]
//!   structure used by both formats.
//! - [`vpack`] — platform-built, agent-consumed offline packs (spec § 3.5.2).
//!   Contains the 7-field metadata, build + parse, and round-trip tests.
//! - [`vresults`] — agent-built, platform-consumed result packs (spec § 3.5.3).
//!   Contains the 4-field metadata, build + parse, and round-trip tests.
//! - [`executor`] — A.7.3 single-pack end-to-end: parse → decrypt →
//!   dispatch → encrypt → build result.
//! - [`blacklist`] — A.7.4 persistent replay-prevention store
//!   (`executed-packs.json`).
//! - [`scanner`] — A.7.4 multi-pack directory drain with serial
//!   execution + blacklist gating.
//! - [`error`] — flat error enum returned by all envelope parse paths.
//!
//! ## Cross-language byte contract
//!
//! Java side: `io.veriguard.crypto.VpackSerializer` /
//! `VresultsSerializer` (`veriguard-api` module).  Both implementations
//! produce / consume the same canonical UTF-8 JSON bytes:
//!
//! - Keys at every level alphabetically sorted (Rust uses
//!   `serde_json`'s default-feature `Map = BTreeMap`; Java uses
//!   `ORDER_MAP_ENTRIES_BY_KEYS=true`).
//! - No whitespace.
//! - 2-key signature input `{"envelope_encrypted":...,"metadata_plaintext":...}`.
//! - IETF ChaCha20-Poly1305 with a 12-byte nonce (`crypto::x25519_box`
//!   handles encryption upstream).
//! - Ed25519 RFC 8032 pure signatures.
//! - Base64 standard (RFC 4648 §4) alphabet for all binary fields.
//!
//! See [`docs/superpowers/specs/2026-05-14-veriguard-agent-implant-fork-c1-c2-design.md`](../../../docs/superpowers/specs/2026-05-14-veriguard-agent-implant-fork-c1-c2-design.md)
//! § 3.5 for the spec and `project_veriguard_wire_contract_locked.md`
//! for the byte-level invariants pinned during C1-Agent-2 review.

pub mod blacklist;
pub mod common;
pub mod error;
pub mod executor;
pub mod scanner;
pub mod vpack;
pub mod vresults;

// Re-exports for callers.  The `executor` + `scanner` surfaces are
// consumed by the `pack` CLI subcommand in `main.rs`; the lower-level
// envelope APIs remain re-exported with `#[allow(unused_imports)]`
// because they are not all used by the binary path itself — they are
// the published surface for C1-Integration cross-language fixture
// tests.
#[allow(unused_imports)]
pub use blacklist::{
    append as blacklist_append, load as blacklist_load, save as blacklist_save, BlacklistError,
    Entry as BlacklistEntry, Outcome as BlacklistOutcome,
};
#[allow(unused_imports)]
pub use common::EncryptedEnvelope;
#[allow(unused_imports)]
pub use error::PackError;
#[allow(unused_imports)]
pub use executor::{execute_vpack, ExecError, ExecuteReport};
#[allow(unused_imports)]
pub use scanner::{scan, ScanError, ScanItem, ScanItemOutcome, ScanOptions, ScanReport};
#[allow(unused_imports)]
pub use vpack::{build_vpack, parse_vpack, VpackContents, VpackMetadata, FORMAT_VPACK};
#[allow(unused_imports)]
pub use vresults::{
    build_vresults, parse_vresults, VresultsContents, VresultsMetadata, FORMAT_VRESULTS,
};
