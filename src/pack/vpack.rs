//! `.vpack` — platform-signed, agent-decrypted offline pack envelope (spec § 3.5.2).
//!
//! Mirror of Java `VpackSerializer`.  Produces / consumes the exact
//! same canonical UTF-8 JSON bytes so a Java-built `.vpack` decodes
//! here and a Rust-built `.vpack` (e.g. test fixtures) decodes there.
//!
//! ## Wire schema
//!
//! ```json
//! {
//!   "envelope_encrypted": {
//!     "cipher": "chacha20-poly1305",
//!     "ciphertext_b64": "<base64 of ciphertext + Poly1305 tag>",
//!     "kdf": "x25519",
//!     "nonce_b64": "<base64 of 12-byte IETF nonce>",
//!     "scheme": "nacl-box",
//!     "sender_x25519_pub_b64": "<base64 of 32-byte X25519 public key>"
//!   },
//!   "format": "vpack",
//!   "metadata_plaintext": {
//!     "agent_id": "<string>",
//!     "exported_by": "<string>",
//!     "issued_at": "<ISO-8601 UTC e.g. 2026-05-15T10:30:00Z>",
//!     "pack_id": "<UUID lowercase 8-4-4-4-12>",
//!     "platform_id": "<string>",
//!     "schema_version_payload": "<string>",
//!     "task_count": <int32>
//!   },
//!   "schema_version": "1.0",
//!   "signature": {
//!     "scheme": "Ed25519",
//!     "sig_b64": "<base64 of 64-byte signature>",
//!     "signer_pub_b64": "<base64 of 32-byte Ed25519 public key>"
//!   }
//! }
//! ```
//!
//! Keys at every level are alphabetically sorted (`serde_json`'s
//! `Map = BTreeMap` default-feature) — matches Jackson's
//! `ORDER_MAP_ENTRIES_BY_KEYS=true` byte-for-byte.

// NOTE: this module relies on `serde_json`'s default-feature `Map =
// BTreeMap`, which iterates keys in lexicographic order.  Enabling the
// `preserve_order` feature (which would switch to `IndexMap` / insertion
// order) would silently break the wire contract with Java.  The
// regression is caught by `test_build_keys_are_alphabetical_*` in the
// test suite, which fails fast if the canonical-byte ordering drifts.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

use crate::crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};

use super::common::{
    canonical_sign_input, constant_time_eq, decode_base64, decode_fixed, envelope_to_value,
    format_iso8601, parse_iso8601, required_int, required_object, required_text,
    validate_uuid_format, value_to_envelope, EncryptedEnvelope, COUNT_MAX, ED25519_PUB_LEN,
    ED25519_SIG_LEN, SCHEMA_VERSION, SIGN_SCHEME,
};
use super::error::PackError;

/// `format` constant for `.vpack` envelopes.
pub const FORMAT_VPACK: &str = "vpack";

/// Plaintext metadata embedded in a `.vpack` envelope.  All fields are
/// "opaque" from the wire's perspective — the agent uses `pack_id` as
/// the replay-prevention key, and the rest is audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpackMetadata {
    /// UUID identifying this pack (lowercase 8-4-4-4-12).
    pub pack_id: String,
    /// Platform identifier (opaque to the agent).
    pub platform_id: String,
    /// Agent identifier this pack is targeted at.
    pub agent_id: String,
    /// When the platform built the pack.
    pub issued_at: DateTime<Utc>,
    /// Number of tasks inside the encrypted payload (`0..=i32::MAX`).
    pub task_count: i32,
    /// Schema version of the *payload* JSON (separate from envelope
    /// `schema_version`).
    pub schema_version_payload: String,
    /// Operator label (e.g. "alice@platform").
    pub exported_by: String,
}

/// Result of [`parse_vpack`] — verified metadata, the encrypted
/// envelope (still to be decrypted by the caller), and the signer pub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpackContents {
    /// Parsed metadata.
    pub metadata: VpackMetadata,
    /// Parsed encrypted envelope (still ciphertext).
    pub encrypted_envelope: EncryptedEnvelope,
    /// The Ed25519 public key that signed this envelope (constant-time
    /// matched against the caller-supplied `expected_signer_pub`).
    pub signer_pub: [u8; ED25519_PUB_LEN],
}

/// Build a complete `.vpack` envelope: canonical JSON over (metadata,
/// envelope) signed by `platform_sign_priv`.
///
/// Returns the UTF-8 bytes of the alphabetically-sorted, no-whitespace
/// JSON envelope.  The caller is expected to write these bytes to disk
/// / transmit over the wire verbatim.
pub fn build_vpack(
    metadata: &VpackMetadata,
    encrypted_envelope: &EncryptedEnvelope,
    platform_sign_priv: &Ed25519PrivateKey,
) -> Result<Vec<u8>, PackError> {
    let metadata_value = metadata_to_value(metadata);
    let envelope_value = envelope_to_value(encrypted_envelope);
    let sign_input = canonical_sign_input(&metadata_value, &envelope_value)?;
    let signature = platform_sign_priv.sign(&sign_input);
    let signer_pub = platform_sign_priv.public_key().to_bytes();

    let mut signature_obj = Map::new();
    signature_obj.insert("scheme".into(), Value::String(SIGN_SCHEME.into()));
    signature_obj.insert(
        "sig_b64".into(),
        Value::String(B64.encode(signature.to_bytes())),
    );
    signature_obj.insert(
        "signer_pub_b64".into(),
        Value::String(B64.encode(signer_pub)),
    );

    let mut root = Map::new();
    root.insert("envelope_encrypted".into(), envelope_value);
    root.insert("format".into(), Value::String(FORMAT_VPACK.into()));
    root.insert("metadata_plaintext".into(), metadata_value);
    root.insert(
        "schema_version".into(),
        Value::String(SCHEMA_VERSION.into()),
    );
    root.insert("signature".into(), Value::Object(signature_obj));

    serde_json::to_vec(&Value::Object(root)).map_err(|e| PackError::Serialize(e.to_string()))
}

/// Parse a `.vpack` envelope and verify its Ed25519 signature against
/// the caller's expected platform signer public key.
///
/// On failure the caller should treat any error variant as a flat
/// "reject this pack" — the variants are debugging detail, not a
/// security signal.
pub fn parse_vpack(
    envelope_bytes: &[u8],
    expected_signer_pub: &Ed25519PublicKey,
) -> Result<VpackContents, PackError> {
    let root_value: Value = serde_json::from_slice(envelope_bytes)?;
    let root = root_value.as_object().ok_or(PackError::NotAnObject)?;

    let schema_version = required_text(root, "schema_version")?;
    if schema_version != SCHEMA_VERSION {
        return Err(PackError::UnsupportedSchemaVersion {
            expected: SCHEMA_VERSION,
            got: schema_version.to_string(),
        });
    }
    let format = required_text(root, "format")?;
    if format != FORMAT_VPACK {
        return Err(PackError::UnsupportedFormat {
            expected: FORMAT_VPACK,
            got: format.to_string(),
        });
    }

    let metadata_node = required_object(root, "metadata_plaintext")?;
    let envelope_node = required_object(root, "envelope_encrypted")?;
    let signature_node = required_object(root, "signature")?;

    let signer_pub_b64 = required_text(signature_node, "signer_pub_b64")?;
    let sig_b64 = required_text(signature_node, "sig_b64")?;
    let signer_pub_vec = decode_base64(signer_pub_b64, "signer_pub_b64")?;
    let signer_pub = decode_fixed::<ED25519_PUB_LEN>(&signer_pub_vec, "signer_pub_b64")?;
    let sig_vec = decode_base64(sig_b64, "sig_b64")?;
    let sig_bytes = decode_fixed::<ED25519_SIG_LEN>(&sig_vec, "sig_b64")?;

    let expected_bytes = expected_signer_pub.to_bytes();
    if !constant_time_eq(&signer_pub, &expected_bytes) {
        return Err(PackError::SignerMismatch);
    }

    let sign_input = canonical_sign_input(
        &Value::Object(metadata_node.clone()),
        &Value::Object(envelope_node.clone()),
    )?;
    let signature = Ed25519Signature::from_bytes(&sig_bytes);
    if !expected_signer_pub.verify(&sign_input, &signature) {
        return Err(PackError::SignatureInvalid);
    }

    // Decode metadata + envelope only after signature verifies so a
    // tampered envelope fails fast on the cryptographic check rather
    // than possibly leaking field-by-field structural detail.
    let metadata = value_to_metadata(metadata_node)?;
    let encrypted_envelope = value_to_envelope(envelope_node)?;

    Ok(VpackContents {
        metadata,
        encrypted_envelope,
        signer_pub,
    })
}

// ---------- Vpack-specific helpers ----------

fn metadata_to_value(m: &VpackMetadata) -> Value {
    let mut obj = Map::new();
    obj.insert("agent_id".into(), Value::String(m.agent_id.clone()));
    obj.insert("exported_by".into(), Value::String(m.exported_by.clone()));
    obj.insert(
        "issued_at".into(),
        Value::String(format_iso8601(&m.issued_at)),
    );
    obj.insert("pack_id".into(), Value::String(m.pack_id.clone()));
    obj.insert("platform_id".into(), Value::String(m.platform_id.clone()));
    obj.insert(
        "schema_version_payload".into(),
        Value::String(m.schema_version_payload.clone()),
    );
    obj.insert("task_count".into(), Value::Number(m.task_count.into()));
    Value::Object(obj)
}

fn value_to_metadata(node: &Map<String, Value>) -> Result<VpackMetadata, PackError> {
    let pack_id = required_text(node, "pack_id")?.to_string();
    validate_uuid_format(&pack_id)?;
    let issued_at = parse_iso8601(required_text(node, "issued_at")?, "issued_at")?;
    let task_count_i64 = required_int(node, "task_count")?;
    if !(0..=COUNT_MAX).contains(&task_count_i64) {
        return Err(PackError::BadCount {
            field: "task_count",
            got: task_count_i64,
        });
    }

    Ok(VpackMetadata {
        pack_id,
        platform_id: required_text(node, "platform_id")?.to_string(),
        agent_id: required_text(node, "agent_id")?.to_string(),
        issued_at,
        task_count: task_count_i64 as i32,
        schema_version_payload: required_text(node, "schema_version_payload")?.to_string(),
        exported_by: required_text(node, "exported_by")?.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::generate_ed25519;
    use chrono::TimeZone;

    fn sample_metadata() -> VpackMetadata {
        VpackMetadata {
            pack_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            platform_id: "plt_test".to_string(),
            agent_id: "agt_test".to_string(),
            issued_at: Utc.with_ymd_and_hms(2026, 5, 15, 10, 30, 0).unwrap(),
            task_count: 3,
            schema_version_payload: "1.0".to_string(),
            exported_by: "alice@platform".to_string(),
        }
    }

    fn sample_envelope() -> EncryptedEnvelope {
        EncryptedEnvelope {
            sender_x25519_pub: [0x11; 32],
            nonce: [0x22; 12],
            ciphertext: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        }
    }

    #[test]
    fn test_build_and_parse_round_trip() {
        let metadata = sample_metadata();
        let envelope = sample_envelope();
        let sign_key = generate_ed25519();
        let signer_pub = sign_key.public_key();

        let bytes = build_vpack(&metadata, &envelope, &sign_key).expect("build");
        let parsed = parse_vpack(&bytes, &signer_pub).expect("parse");

        assert_eq!(parsed.metadata, metadata);
        assert_eq!(parsed.encrypted_envelope, envelope);
        assert_eq!(parsed.signer_pub, signer_pub.to_bytes());
    }

    #[test]
    fn test_build_is_byte_deterministic() {
        let metadata = sample_metadata();
        let envelope = sample_envelope();
        let sign_key = generate_ed25519();

        let bytes1 = build_vpack(&metadata, &envelope, &sign_key).unwrap();
        let bytes2 = build_vpack(&metadata, &envelope, &sign_key).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_build_keys_are_alphabetical_at_root() {
        let bytes =
            build_vpack(&sample_metadata(), &sample_envelope(), &generate_ed25519()).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();

        let positions = [
            (
                "envelope_encrypted",
                s.find(r#""envelope_encrypted":"#).unwrap(),
            ),
            ("format", s.find(r#""format":"#).unwrap()),
            (
                "metadata_plaintext",
                s.find(r#""metadata_plaintext":"#).unwrap(),
            ),
            ("schema_version", s.find(r#""schema_version":"#).unwrap()),
            ("signature", s.find(r#""signature":"#).unwrap()),
        ];
        for w in positions.windows(2) {
            assert!(
                w[0].1 < w[1].1,
                "root keys not alphabetical: {} should precede {}",
                w[0].0,
                w[1].0
            );
        }
    }

    #[test]
    fn test_build_keys_are_alphabetical_in_metadata() {
        let bytes =
            build_vpack(&sample_metadata(), &sample_envelope(), &generate_ed25519()).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();

        let metadata_start = s.find(r#""metadata_plaintext":"#).unwrap();
        let m = &s[metadata_start..];

        let positions = [
            ("agent_id", m.find(r#""agent_id":"#).unwrap()),
            ("exported_by", m.find(r#""exported_by":"#).unwrap()),
            ("issued_at", m.find(r#""issued_at":"#).unwrap()),
            ("pack_id", m.find(r#""pack_id":"#).unwrap()),
            ("platform_id", m.find(r#""platform_id":"#).unwrap()),
            (
                "schema_version_payload",
                m.find(r#""schema_version_payload":"#).unwrap(),
            ),
            ("task_count", m.find(r#""task_count":"#).unwrap()),
        ];
        for w in positions.windows(2) {
            assert!(
                w[0].1 < w[1].1,
                "metadata keys not alphabetical: {} should precede {}",
                w[0].0,
                w[1].0
            );
        }
    }

    #[test]
    fn test_build_has_no_whitespace() {
        let bytes =
            build_vpack(&sample_metadata(), &sample_envelope(), &generate_ed25519()).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(!s.contains(' '), "canonical JSON must not contain spaces");
        assert!(!s.contains('\n'));
        assert!(!s.contains('\t'));
    }

    #[test]
    fn test_build_embeds_correct_constants() {
        let bytes =
            build_vpack(&sample_metadata(), &sample_envelope(), &generate_ed25519()).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains(r#""schema_version":"1.0""#));
        assert!(s.contains(r#""format":"vpack""#));
        assert!(s.contains(r#""scheme":"nacl-box""#));
        assert!(s.contains(r#""kdf":"x25519""#));
        assert!(s.contains(r#""cipher":"chacha20-poly1305""#));
        assert!(s.contains(r#""scheme":"Ed25519""#));
    }

    #[test]
    fn test_parse_rejects_tampered_ciphertext() {
        let sign_key = generate_ed25519();
        let signer_pub = sign_key.public_key();
        let mut bytes = build_vpack(&sample_metadata(), &sample_envelope(), &sign_key).unwrap();

        let s = std::str::from_utf8(&bytes).unwrap().to_string();
        let needle = r#""ciphertext_b64":""#;
        let idx = s.find(needle).expect("ciphertext_b64 present");
        let target = idx + needle.len() + 1;
        bytes[target] = if bytes[target] == b'A' { b'B' } else { b'A' };

        let err = parse_vpack(&bytes, &signer_pub).unwrap_err();
        assert!(
            matches!(err, PackError::SignatureInvalid),
            "expected SignatureInvalid, got {err:?}"
        );
    }

    #[test]
    fn test_parse_rejects_tampered_metadata() {
        let sign_key = generate_ed25519();
        let signer_pub = sign_key.public_key();
        let mut bytes = build_vpack(&sample_metadata(), &sample_envelope(), &sign_key).unwrap();

        let original_val = "alice@platform";
        let tampered_val = "evilXatackerz0";
        assert_eq!(original_val.len(), tampered_val.len());
        let s = std::str::from_utf8(&bytes).unwrap();
        let idx = s.find(original_val).expect("substring present");
        bytes[idx..idx + tampered_val.len()].copy_from_slice(tampered_val.as_bytes());

        let err = parse_vpack(&bytes, &signer_pub).unwrap_err();
        assert!(
            matches!(err, PackError::SignatureInvalid),
            "expected SignatureInvalid, got {err:?}"
        );
    }

    #[test]
    fn test_parse_rejects_wrong_signer_pub() {
        let sign_key = generate_ed25519();
        let bytes = build_vpack(&sample_metadata(), &sample_envelope(), &sign_key).unwrap();
        let other_pub = generate_ed25519().public_key();

        let err = parse_vpack(&bytes, &other_pub).unwrap_err();
        assert!(matches!(err, PackError::SignerMismatch));
    }

    #[test]
    fn test_parse_rejects_wrong_schema_version() {
        let sign_key = generate_ed25519();
        let signer_pub = sign_key.public_key();
        let mut bytes = build_vpack(&sample_metadata(), &sample_envelope(), &sign_key).unwrap();

        let needle = r#""schema_version":"1.0""#;
        let s = std::str::from_utf8(&bytes).unwrap();
        let idx = s.find(needle).expect("schema_version present");
        bytes[idx + needle.len() - 4] = b'2';

        let err = parse_vpack(&bytes, &signer_pub).unwrap_err();
        match err {
            PackError::UnsupportedSchemaVersion { expected, got } => {
                assert_eq!(expected, "1.0");
                assert_eq!(got, "2.0");
            }
            other => panic!("expected UnsupportedSchemaVersion, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_rejects_wrong_format() {
        let sign_key = generate_ed25519();
        let signer_pub = sign_key.public_key();
        let mut bytes = build_vpack(&sample_metadata(), &sample_envelope(), &sign_key).unwrap();

        let needle = r#""format":"vpack""#;
        let s = std::str::from_utf8(&bytes).unwrap();
        let idx = s.find(needle).expect("format present");
        bytes[idx + 10] = b'x';

        let err = parse_vpack(&bytes, &signer_pub).unwrap_err();
        match err {
            PackError::UnsupportedFormat { expected, got } => {
                assert_eq!(expected, "vpack");
                assert_eq!(got, "xpack");
            }
            other => panic!("expected UnsupportedFormat, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_rejects_malformed_json() {
        let signer_pub = generate_ed25519().public_key();
        let err = parse_vpack(b"not a json", &signer_pub).unwrap_err();
        assert!(matches!(err, PackError::Json(_)));
    }

    #[test]
    fn test_parse_rejects_root_not_object() {
        let signer_pub = generate_ed25519().public_key();
        let err = parse_vpack(br#"[1,2,3]"#, &signer_pub).unwrap_err();
        assert!(matches!(err, PackError::NotAnObject));
    }

    #[test]
    fn test_parse_rejects_bad_pack_id() {
        // 36 chars with correct dash positions (8, 13, 18, 23) but
        // non-hex chars at the tail — fails the per-char hex check.
        let sign_key = generate_ed25519();
        let signer_pub = sign_key.public_key();
        let mut bad = sample_metadata();
        bad.pack_id = "550e8400-e29b-41d4-a716-4466554400zz".to_string();
        assert_eq!(bad.pack_id.len(), 36, "test invariant");
        let bytes = build_vpack(&bad, &sample_envelope(), &sign_key).unwrap();
        let err = parse_vpack(&bytes, &signer_pub).unwrap_err();
        assert!(matches!(err, PackError::BadPackId(_)));
    }

    #[test]
    fn test_parse_rejects_negative_task_count() {
        let sign_key = generate_ed25519();
        let signer_pub = sign_key.public_key();
        let mut bad = sample_metadata();
        bad.task_count = -1;
        let bytes = build_vpack(&bad, &sample_envelope(), &sign_key).unwrap();
        let err = parse_vpack(&bytes, &signer_pub).unwrap_err();
        match err {
            PackError::BadCount { field, got } => {
                assert_eq!(field, "task_count");
                assert_eq!(got, -1);
            }
            other => panic!("expected BadCount, got {other:?}"),
        }
    }

    #[test]
    fn test_iso8601_round_trip_in_envelope() {
        let original = sample_metadata();
        let sign_key = generate_ed25519();
        let bytes = build_vpack(&original, &sample_envelope(), &sign_key).unwrap();
        let parsed = parse_vpack(&bytes, &sign_key.public_key()).unwrap();
        assert_eq!(parsed.metadata.issued_at, original.issued_at);
    }

    #[test]
    fn test_renaming_signed_field_invalidates_signature() {
        // Surgically rename agent_id to agent_zz (same length).  The signed
        // input includes this byte position, so verification must fail.
        let sign_key = generate_ed25519();
        let signer_pub = sign_key.public_key();
        let bytes = build_vpack(&sample_metadata(), &sample_envelope(), &sign_key).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap().to_string();

        let from = r#""agent_id":"agt_test""#;
        let to = r#""agent_zz":"agt_test""#;
        assert_eq!(from.len(), to.len());
        let idx = s.find(from).expect("agent_id present");
        let mut bytes_mut = bytes.clone();
        bytes_mut[idx..idx + to.len()].copy_from_slice(to.as_bytes());

        let err = parse_vpack(&bytes_mut, &signer_pub).unwrap_err();
        assert!(matches!(err, PackError::SignatureInvalid), "got {err:?}");
    }
}
