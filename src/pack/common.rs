//! Helpers shared between `.vpack` and `.vresults` envelopes.
//!
//! Both formats share the same encrypted envelope shape, the same
//! canonical signature input (2-key alphabetical JSON), the same
//! base64 / UUID / ISO-8601 validators, and the same JSON-field
//! extraction primitives.  Only the `format` constant and the metadata
//! field set differ between them.
//!
//! ## Canonical bytes guarantee
//!
//! `serde_json`'s default-feature `Map` is backed by `BTreeMap`, which
//! iterates keys in lexicographic order — that matches Jackson's
//! `ORDER_MAP_ENTRIES_BY_KEYS=true`.  Enabling the `preserve_order`
//! feature would silently switch to `IndexMap` (insertion order) and
//! break the wire contract; a `compile_error!` guard is included in
//! both [`vpack`](super::vpack) and [`vresults`](super::vresults).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value};

use super::error::PackError;

/// Envelope `schema_version` constant — incremented only on a
/// breaking wire change (would require coordinated Java + Rust roll-out).
pub const SCHEMA_VERSION: &str = "1.0";

/// Encryption scheme label embedded in the envelope.
pub const ENCRYPT_SCHEME: &str = "nacl-box";

/// Key derivation label (raw X25519 ECDH, no KDF — NaCl convention).
pub const ENCRYPT_KDF: &str = "x25519";

/// AEAD cipher label — IETF ChaCha20-Poly1305 with 12-byte nonce.
pub const ENCRYPT_CIPHER: &str = "chacha20-poly1305";

/// Signature scheme label.
pub const SIGN_SCHEME: &str = "Ed25519";

/// Length of an X25519 public key in bytes.
pub const X25519_PUB_LEN: usize = 32;

/// Length of the IETF ChaCha20-Poly1305 nonce in bytes.
pub const NONCE_LEN: usize = 12;

/// Length of an Ed25519 public key in bytes.
pub const ED25519_PUB_LEN: usize = 32;

/// Length of an Ed25519 signature in bytes.
pub const ED25519_SIG_LEN: usize = 64;

/// Maximum value for `task_count` / `result_count` — caps at Java's
/// signed-int upper bound so JSON numbers stay within `i32` range
/// (downstream batch executors enforce a stricter per-pack limit).
pub const COUNT_MAX: i64 = i32::MAX as i64;

/// Encrypted envelope body — the same structure for `.vpack` (platform
/// → agent) and `.vresults` (agent → platform).  This module never
/// performs the encryption; callers run
/// [`crate::crypto::x25519_box::seal_box`] before passing the
/// resulting bytes here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedEnvelope {
    /// Static or ephemeral X25519 public key the sender used.
    pub sender_x25519_pub: [u8; X25519_PUB_LEN],
    /// 12-byte IETF ChaCha20-Poly1305 nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext concatenated with the 16-byte Poly1305 tag, as
    /// produced by [`chacha20poly1305::aead::Aead::encrypt`].
    pub ciphertext: Vec<u8>,
}

/// Serialize an encrypted envelope to canonical JSON.
pub fn envelope_to_value(e: &EncryptedEnvelope) -> Value {
    let mut obj = Map::new();
    obj.insert("cipher".into(), Value::String(ENCRYPT_CIPHER.into()));
    obj.insert(
        "ciphertext_b64".into(),
        Value::String(B64.encode(&e.ciphertext)),
    );
    obj.insert("kdf".into(), Value::String(ENCRYPT_KDF.into()));
    obj.insert("nonce_b64".into(), Value::String(B64.encode(e.nonce)));
    obj.insert("scheme".into(), Value::String(ENCRYPT_SCHEME.into()));
    obj.insert(
        "sender_x25519_pub_b64".into(),
        Value::String(B64.encode(e.sender_x25519_pub)),
    );
    Value::Object(obj)
}

/// Parse an envelope JSON node back into [`EncryptedEnvelope`].
pub fn value_to_envelope(node: &Map<String, Value>) -> Result<EncryptedEnvelope, PackError> {
    let sender_pub_b64 = required_text(node, "sender_x25519_pub_b64")?;
    let sender_pub_vec = decode_base64(sender_pub_b64, "sender_x25519_pub_b64")?;
    let sender_x25519_pub =
        decode_fixed::<X25519_PUB_LEN>(&sender_pub_vec, "sender_x25519_pub_b64")?;

    let nonce_b64 = required_text(node, "nonce_b64")?;
    let nonce_vec = decode_base64(nonce_b64, "nonce_b64")?;
    let nonce = decode_fixed::<NONCE_LEN>(&nonce_vec, "nonce_b64")?;

    let ciphertext_b64 = required_text(node, "ciphertext_b64")?;
    let ciphertext = decode_base64(ciphertext_b64, "ciphertext_b64")?;

    Ok(EncryptedEnvelope {
        sender_x25519_pub,
        nonce,
        ciphertext,
    })
}

/// Build the canonical 2-key signature input.  Keys are emitted
/// alphabetically by the `BTreeMap`-backed `Map`
/// (`envelope_encrypted` < `metadata_plaintext`), inner nodes re-emitted
/// with the same canonical ordering, no whitespace, UTF-8.
pub fn canonical_sign_input(
    metadata_value: &Value,
    envelope_value: &Value,
) -> Result<Vec<u8>, PackError> {
    let mut sign_root = Map::new();
    sign_root.insert("envelope_encrypted".into(), envelope_value.clone());
    sign_root.insert("metadata_plaintext".into(), metadata_value.clone());
    serde_json::to_vec(&Value::Object(sign_root)).map_err(|e| PackError::Serialize(e.to_string()))
}

/// Format a [`DateTime<Utc>`] the same way Java's `Instant.toString()`
/// formats — `AutoSi` picks whole seconds / milliseconds / microseconds
/// / nanoseconds depending on actual precision, and `use_z = true`
/// emits a `Z` suffix instead of `+00:00`.
pub fn format_iso8601(t: &DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

/// Parse a `Z`-suffixed ISO-8601 / RFC 3339 string back into a
/// [`DateTime<Utc>`].  Tolerates the various fractional widths Java
/// emits.
pub fn parse_iso8601(s: &str, field: &'static str) -> Result<DateTime<Utc>, PackError> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| PackError::BadTimestamp {
            field,
            detail: e.to_string(),
        })
}

/// Validate a lowercase 8-4-4-4-12 UUID string.  Java emits this form
/// via `UUID.toString()` — we accept it verbatim and reject any
/// uppercase / shortened / extended variants so a tampered envelope
/// can't slip a different-case duplicate past the
/// `executed_packs` PRIMARY KEY.
pub fn validate_uuid_format(s: &str) -> Result<(), PackError> {
    if s.len() != 36 {
        return Err(PackError::BadPackId(s.to_string()));
    }
    let bytes = s.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        let ok = match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(b),
        };
        if !ok {
            return Err(PackError::BadPackId(s.to_string()));
        }
    }
    Ok(())
}

/// Constant-time compare for two byte slices.  Hand-rolled instead of
/// pulling in [`subtle`] just for one call site — public-key comparison
/// is the only constant-time consumer in this crate.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extract a required string field, returning [`PackError::MissingTextField`]
/// if missing or non-textual.
pub fn required_text<'a>(
    node: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, PackError> {
    match node.get(field) {
        Some(Value::String(s)) => Ok(s),
        _ => Err(PackError::MissingTextField(field)),
    }
}

/// Extract a required integer field as `i64` (caller checks range).
pub fn required_int(node: &Map<String, Value>, field: &'static str) -> Result<i64, PackError> {
    match node.get(field) {
        Some(Value::Number(n)) => n.as_i64().ok_or(PackError::MissingIntField(field)),
        _ => Err(PackError::MissingIntField(field)),
    }
}

/// Extract a required object field.
pub fn required_object<'a>(
    node: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a Map<String, Value>, PackError> {
    match node.get(field) {
        Some(Value::Object(o)) => Ok(o),
        _ => Err(PackError::MissingObjectField(field)),
    }
}

/// Decode a base64 string, mapping `base64`'s error type to a
/// field-tagged [`PackError::BadBase64`].
pub fn decode_base64(s: &str, field: &'static str) -> Result<Vec<u8>, PackError> {
    B64.decode(s).map_err(|e| PackError::BadBase64 {
        field,
        detail: e.to_string(),
    })
}

/// Convert a variable-length byte vec into a fixed-length array,
/// returning [`PackError::BadLength`] on mismatch.
pub fn decode_fixed<const N: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; N], PackError> {
    if bytes.len() != N {
        return Err(PackError::BadLength {
            field,
            expected: N,
            got: bytes.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    // ---- ISO-8601 formatting ----

    #[test]
    fn test_iso8601_format_zero_fractional() {
        let t = Utc.with_ymd_and_hms(2026, 5, 15, 10, 30, 0).unwrap();
        // Java Instant.toString() omits fractional dot when nanos == 0.
        assert_eq!(format_iso8601(&t), "2026-05-15T10:30:00Z");
    }

    #[test]
    fn test_iso8601_format_millisecond_precision() {
        let t = Utc
            .with_ymd_and_hms(2026, 5, 15, 10, 30, 0)
            .unwrap()
            .checked_add_signed(chrono::Duration::milliseconds(123))
            .unwrap();
        assert_eq!(format_iso8601(&t), "2026-05-15T10:30:00.123Z");
    }

    #[test]
    fn test_iso8601_format_microsecond_precision() {
        let t = Utc
            .with_ymd_and_hms(2026, 5, 15, 10, 30, 0)
            .unwrap()
            .checked_add_signed(chrono::Duration::microseconds(123_456))
            .unwrap();
        assert_eq!(format_iso8601(&t), "2026-05-15T10:30:00.123456Z");
    }

    #[test]
    fn test_iso8601_parse_round_trip_zero_fractional() {
        let original = "2026-05-15T10:30:00Z";
        let parsed = parse_iso8601(original, "issued_at").unwrap();
        assert_eq!(format_iso8601(&parsed), original);
    }

    #[test]
    fn test_iso8601_parse_round_trip_millisecond() {
        let original = "2026-05-15T10:30:00.123Z";
        let parsed = parse_iso8601(original, "issued_at").unwrap();
        assert_eq!(format_iso8601(&parsed), original);
    }

    #[test]
    fn test_iso8601_parse_rejects_garbage() {
        let err = parse_iso8601("not a date", "issued_at").unwrap_err();
        assert!(matches!(
            err,
            PackError::BadTimestamp {
                field: "issued_at",
                ..
            }
        ));
    }

    // ---- UUID validation ----

    #[test]
    fn test_uuid_validator_accepts_lowercase_canonical() {
        assert!(validate_uuid_format("550e8400-e29b-41d4-a716-446655440000").is_ok());
    }

    #[test]
    fn test_uuid_validator_rejects_uppercase() {
        // Java emits lowercase via UUID.toString(); accepting uppercase would
        // create duplicate executed_packs rows on case-insensitive SQLite
        // collations.  Reject explicitly.
        assert!(matches!(
            validate_uuid_format("550E8400-E29B-41D4-A716-446655440000"),
            Err(PackError::BadPackId(_))
        ));
    }

    #[test]
    fn test_uuid_validator_rejects_short() {
        assert!(matches!(
            validate_uuid_format("550e8400-e29b-41d4-a716-44665544000"),
            Err(PackError::BadPackId(_))
        ));
    }

    #[test]
    fn test_uuid_validator_rejects_no_dashes() {
        assert!(matches!(
            validate_uuid_format("550e8400e29b41d4a716446655440000abcd"),
            Err(PackError::BadPackId(_))
        ));
    }

    #[test]
    fn test_uuid_validator_rejects_non_hex_char() {
        assert!(matches!(
            validate_uuid_format("550e8400-e29b-41d4-a716-44665544000z"),
            Err(PackError::BadPackId(_))
        ));
    }

    // ---- Constant-time compare ----

    #[test]
    fn test_constant_time_eq_equal_inputs() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(constant_time_eq(&[], &[]));
        assert!(constant_time_eq(&[0xFF; 32], &[0xFF; 32]));
    }

    #[test]
    fn test_constant_time_eq_unequal_inputs() {
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(&[0u8; 32], &[1u8; 32]));
    }

    // ---- Envelope serdes ----

    fn sample_envelope() -> EncryptedEnvelope {
        EncryptedEnvelope {
            sender_x25519_pub: [0x11; X25519_PUB_LEN],
            nonce: [0x22; NONCE_LEN],
            ciphertext: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        }
    }

    #[test]
    fn test_envelope_round_trip() {
        let original = sample_envelope();
        let value = envelope_to_value(&original);
        let node = value.as_object().expect("object");
        let parsed = value_to_envelope(node).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_envelope_embeds_constants() {
        let value = envelope_to_value(&sample_envelope());
        let obj = value.as_object().unwrap();
        assert_eq!(obj["scheme"], Value::String(ENCRYPT_SCHEME.into()));
        assert_eq!(obj["kdf"], Value::String(ENCRYPT_KDF.into()));
        assert_eq!(obj["cipher"], Value::String(ENCRYPT_CIPHER.into()));
    }

    // ---- Required-field extractors ----

    #[test]
    fn test_required_text_present() {
        let mut node = Map::new();
        node.insert("foo".into(), Value::String("bar".into()));
        assert_eq!(required_text(&node, "foo").unwrap(), "bar");
    }

    #[test]
    fn test_required_text_missing() {
        let node = Map::new();
        assert!(matches!(
            required_text(&node, "foo"),
            Err(PackError::MissingTextField("foo"))
        ));
    }

    #[test]
    fn test_required_text_wrong_type() {
        let mut node = Map::new();
        node.insert("foo".into(), Value::Number(42.into()));
        assert!(matches!(
            required_text(&node, "foo"),
            Err(PackError::MissingTextField("foo"))
        ));
    }

    #[test]
    fn test_required_int_present() {
        let mut node = Map::new();
        node.insert("foo".into(), Value::Number(42.into()));
        assert_eq!(required_int(&node, "foo").unwrap(), 42);
    }

    #[test]
    fn test_required_int_rejects_string() {
        let mut node = Map::new();
        node.insert("foo".into(), Value::String("42".into()));
        assert!(matches!(
            required_int(&node, "foo"),
            Err(PackError::MissingIntField("foo"))
        ));
    }

    #[test]
    fn test_required_object_present() {
        let mut node = Map::new();
        let mut inner = Map::new();
        inner.insert("k".into(), Value::Number(1.into()));
        node.insert("foo".into(), Value::Object(inner));
        let got = required_object(&node, "foo").unwrap();
        assert_eq!(got["k"], Value::Number(1.into()));
    }

    #[test]
    fn test_decode_base64_round_trip() {
        let original = b"\x00\x01\x02\xAA\xBB\xCC";
        let encoded = B64.encode(original);
        let decoded = decode_base64(&encoded, "test_field").unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_decode_base64_rejects_garbage() {
        let err = decode_base64("not valid base64!@#", "test_field").unwrap_err();
        assert!(matches!(
            err,
            PackError::BadBase64 {
                field: "test_field",
                ..
            }
        ));
    }

    #[test]
    fn test_decode_fixed_wrong_length() {
        let err = decode_fixed::<32>(&[0u8; 10], "test").unwrap_err();
        match err {
            PackError::BadLength {
                field,
                expected,
                got,
            } => {
                assert_eq!(field, "test");
                assert_eq!(expected, 32);
                assert_eq!(got, 10);
            }
            other => panic!("expected BadLength, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_fixed_correct_length() {
        let bytes = [7u8; 12];
        let arr: [u8; 12] = decode_fixed(&bytes, "test").unwrap();
        assert_eq!(arr, [7u8; 12]);
    }

    #[test]
    fn test_canonical_sign_input_two_keys_alphabetical() {
        let metadata = Value::Object({
            let mut m = Map::new();
            m.insert("foo".into(), Value::String("bar".into()));
            m
        });
        let envelope = envelope_to_value(&sample_envelope());

        let bytes = canonical_sign_input(&metadata, &envelope).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();

        let env_pos = s.find(r#""envelope_encrypted":"#).unwrap();
        let meta_pos = s.find(r#""metadata_plaintext":"#).unwrap();
        assert!(env_pos < meta_pos);
    }
}
