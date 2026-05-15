//! Errors raised when parsing or building `.vpack` / `.vresults` envelopes.
//!
//! Mirrors the Java exception hierarchy in `VpackSerializer` /
//! `VresultsSerializer`:
//!
//! * `SchemaVersion*` — `schema_version` or `format` mismatched.
//! * `Signer* / SignatureInvalid` — `signer_pub_b64` did not match the
//!   expected key, or Ed25519 verify failed (caller treats these as the
//!   same trust failure but they are kept distinct here to aid debugging).
//! * `Parse*` — malformed JSON, missing or wrong-typed fields, bad
//!   base64, bad lengths, malformed UUIDs / timestamps.
//!
//! Caller upstream should map any [`PackError`] to a single audit decision:
//! "reject this pack and record the reason"; do **not** branch the
//! security policy on the error variant (the variants are debugging
//! detail, not a trust signal).

use thiserror::Error;

/// Errors from `.vpack` / `.vresults` parsing or building.
#[derive(Debug, Error)]
pub enum PackError {
    /// Envelope bytes were not valid JSON.
    #[error("malformed JSON envelope: {0}")]
    Json(#[from] serde_json::Error),

    /// JSON root was not an object.
    #[error("envelope root must be a JSON object")]
    NotAnObject,

    /// A required field was missing or had a non-string value.
    #[error("missing or non-textual field: {0}")]
    MissingTextField(&'static str),

    /// A required field was missing or had a non-integer value.
    #[error("missing or non-integer field: {0}")]
    MissingIntField(&'static str),

    /// A required field was missing or had a non-object value.
    #[error("missing or non-object field: {0}")]
    MissingObjectField(&'static str),

    /// A base64-encoded field failed to decode.
    #[error("invalid base64 in field {field:?}: {detail}")]
    BadBase64 {
        /// Field name (alphabetic only, no whitespace).
        field: &'static str,
        /// Human-readable decode error (does not include base64 contents).
        detail: String,
    },

    /// A decoded byte slice did not have the expected fixed length.
    #[error("invalid length in field {field:?}: expected {expected}, got {got}")]
    BadLength {
        /// Field name (alphabetic only, no whitespace).
        field: &'static str,
        /// Expected length in bytes.
        expected: usize,
        /// Actual decoded length.
        got: usize,
    },

    /// `schema_version` did not equal the expected constant.
    #[error("unsupported schema_version: expected {expected:?}, got {got:?}")]
    UnsupportedSchemaVersion {
        /// What this parser accepts.
        expected: &'static str,
        /// What the envelope claimed.
        got: String,
    },

    /// `format` did not equal the expected constant for this serializer.
    #[error("unsupported format: expected {expected:?}, got {got:?}")]
    UnsupportedFormat {
        /// What this parser accepts (`"vpack"` or `"vresults"`).
        expected: &'static str,
        /// What the envelope claimed.
        got: String,
    },

    /// `pack_id` was not a valid lowercase 8-4-4-4-12 UUID.
    #[error("invalid pack_id: {0:?}")]
    BadPackId(String),

    /// A timestamp field (`issued_at` / `executed_at`) was not valid
    /// ISO-8601 / RFC 3339 with a `Z` suffix.
    #[error("invalid timestamp in field {field:?}: {detail}")]
    BadTimestamp {
        /// Field name (alphabetic only, no whitespace).
        field: &'static str,
        /// Human-readable parse error.
        detail: String,
    },

    /// `task_count` (or `result_count`) was outside `[0, i32::MAX]`.
    #[error("count field {field:?} out of range [0, i32::MAX]: {got}")]
    BadCount {
        /// Field name (alphabetic only, no whitespace).
        field: &'static str,
        /// Actual JSON-decoded value.
        got: i64,
    },

    /// `signer_pub_b64` decoded but did not match the expected key.
    #[error("signer public key does not match expected key")]
    SignerMismatch,

    /// Ed25519 verify returned `false` — the signature does not bind the
    /// envelope to the included signer public key.
    #[error("Ed25519 signature verification failed")]
    SignatureInvalid,

    /// Serializing the envelope failed.  Should never happen for the
    /// canonical builders since all primitives serialize successfully;
    /// kept for completeness so the builder API can return `Result`.
    #[error("failed to serialize envelope: {0}")]
    Serialize(String),
}
