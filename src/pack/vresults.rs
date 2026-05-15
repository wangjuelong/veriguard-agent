//! `.vresults` — agent-signed, platform-decrypted result-pack envelope (spec § 3.5.3).
//!
//! Mirror of Java `VresultsSerializer`.  This is the reverse direction
//! of [`vpack`](super::vpack): the agent builds these (signs with its
//! private key) and the platform decrypts + verifies them.
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
//!   "format": "vresults",
//!   "metadata_plaintext": {
//!     "agent_id": "<string>",
//!     "executed_at": "<ISO-8601 UTC>",
//!     "pack_id": "<UUID lowercase 8-4-4-4-12>",
//!     "result_count": <int32>
//!   },
//!   "schema_version": "1.0",
//!   "signature": {
//!     "scheme": "Ed25519",
//!     "sig_b64": "<base64 of 64-byte signature>",
//!     "signer_pub_b64": "<base64 of 32-byte Ed25519 public key>"
//!   }
//! }
//! ```

// NOTE: this module relies on `serde_json`'s default-feature `Map =
// BTreeMap`.  See `vpack.rs` head-comment for the wire-contract
// rationale; the `test_build_keys_are_alphabetical_*` tests in
// `vpack.rs` cover the canonical-byte invariant for both formats.

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

/// `format` constant for `.vresults` envelopes.
pub const FORMAT_VRESULTS: &str = "vresults";

/// Plaintext metadata embedded in a `.vresults` envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VresultsMetadata {
    /// UUID of the originating `.vpack` (links results back to the
    /// platform's pack-audit row).
    pub pack_id: String,
    /// Agent identifier — must match the signer pubkey on the platform side.
    pub agent_id: String,
    /// When the agent finished executing the pack.
    pub executed_at: DateTime<Utc>,
    /// Number of results inside the encrypted payload (`0..=i32::MAX`).
    pub result_count: i32,
}

/// Result of [`parse_vresults`] — verified metadata, the encrypted
/// envelope (still to be decrypted by the caller), and the signer pub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VresultsContents {
    /// Parsed metadata.
    pub metadata: VresultsMetadata,
    /// Parsed encrypted envelope (still ciphertext).
    pub encrypted_envelope: EncryptedEnvelope,
    /// The Ed25519 public key that signed this envelope (constant-time
    /// matched against the caller-supplied `expected_signer_pub`).
    pub signer_pub: [u8; ED25519_PUB_LEN],
}

/// Build a complete `.vresults` envelope: canonical JSON over
/// (metadata, envelope) signed by `agent_sign_priv`.
pub fn build_vresults(
    metadata: &VresultsMetadata,
    encrypted_envelope: &EncryptedEnvelope,
    agent_sign_priv: &Ed25519PrivateKey,
) -> Result<Vec<u8>, PackError> {
    let metadata_value = metadata_to_value(metadata);
    let envelope_value = envelope_to_value(encrypted_envelope);
    let sign_input = canonical_sign_input(&metadata_value, &envelope_value)?;
    let signature = agent_sign_priv.sign(&sign_input);
    let signer_pub = agent_sign_priv.public_key().to_bytes();

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
    root.insert("format".into(), Value::String(FORMAT_VRESULTS.into()));
    root.insert("metadata_plaintext".into(), metadata_value);
    root.insert(
        "schema_version".into(),
        Value::String(SCHEMA_VERSION.into()),
    );
    root.insert("signature".into(), Value::Object(signature_obj));

    serde_json::to_vec(&Value::Object(root)).map_err(|e| PackError::Serialize(e.to_string()))
}

/// Parse a `.vresults` envelope and verify its Ed25519 signature
/// against the caller's expected agent signer public key.
pub fn parse_vresults(
    envelope_bytes: &[u8],
    expected_signer_pub: &Ed25519PublicKey,
) -> Result<VresultsContents, PackError> {
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
    if format != FORMAT_VRESULTS {
        return Err(PackError::UnsupportedFormat {
            expected: FORMAT_VRESULTS,
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

    let metadata = value_to_metadata(metadata_node)?;
    let encrypted_envelope = value_to_envelope(envelope_node)?;

    Ok(VresultsContents {
        metadata,
        encrypted_envelope,
        signer_pub,
    })
}

// ---------- Vresults-specific helpers ----------

fn metadata_to_value(m: &VresultsMetadata) -> Value {
    let mut obj = Map::new();
    obj.insert("agent_id".into(), Value::String(m.agent_id.clone()));
    obj.insert(
        "executed_at".into(),
        Value::String(format_iso8601(&m.executed_at)),
    );
    obj.insert("pack_id".into(), Value::String(m.pack_id.clone()));
    obj.insert("result_count".into(), Value::Number(m.result_count.into()));
    Value::Object(obj)
}

fn value_to_metadata(node: &Map<String, Value>) -> Result<VresultsMetadata, PackError> {
    let pack_id = required_text(node, "pack_id")?.to_string();
    validate_uuid_format(&pack_id)?;
    let executed_at = parse_iso8601(required_text(node, "executed_at")?, "executed_at")?;
    let count_i64 = required_int(node, "result_count")?;
    if !(0..=COUNT_MAX).contains(&count_i64) {
        return Err(PackError::BadCount {
            field: "result_count",
            got: count_i64,
        });
    }

    Ok(VresultsMetadata {
        pack_id,
        agent_id: required_text(node, "agent_id")?.to_string(),
        executed_at,
        result_count: count_i64 as i32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::generate_ed25519;
    use chrono::TimeZone;

    fn sample_metadata() -> VresultsMetadata {
        VresultsMetadata {
            pack_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            agent_id: "agt_test".to_string(),
            executed_at: Utc.with_ymd_and_hms(2026, 5, 15, 10, 30, 0).unwrap(),
            result_count: 3,
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

        let bytes = build_vresults(&metadata, &envelope, &sign_key).expect("build");
        let parsed = parse_vresults(&bytes, &signer_pub).expect("parse");

        assert_eq!(parsed.metadata, metadata);
        assert_eq!(parsed.encrypted_envelope, envelope);
        assert_eq!(parsed.signer_pub, signer_pub.to_bytes());
    }

    #[test]
    fn test_build_is_byte_deterministic() {
        let metadata = sample_metadata();
        let envelope = sample_envelope();
        let sign_key = generate_ed25519();

        let bytes1 = build_vresults(&metadata, &envelope, &sign_key).unwrap();
        let bytes2 = build_vresults(&metadata, &envelope, &sign_key).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_build_keys_are_alphabetical_in_metadata() {
        let bytes =
            build_vresults(&sample_metadata(), &sample_envelope(), &generate_ed25519()).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();

        let metadata_start = s.find(r#""metadata_plaintext":"#).unwrap();
        let m = &s[metadata_start..];

        let positions = [
            ("agent_id", m.find(r#""agent_id":"#).unwrap()),
            ("executed_at", m.find(r#""executed_at":"#).unwrap()),
            ("pack_id", m.find(r#""pack_id":"#).unwrap()),
            ("result_count", m.find(r#""result_count":"#).unwrap()),
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
    fn test_build_format_constant_is_vresults() {
        let bytes =
            build_vresults(&sample_metadata(), &sample_envelope(), &generate_ed25519()).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains(r#""format":"vresults""#));
        assert!(!s.contains(r#""format":"vpack""#));
    }

    #[test]
    fn test_parse_rejects_tampered_ciphertext() {
        let sign_key = generate_ed25519();
        let signer_pub = sign_key.public_key();
        let mut bytes = build_vresults(&sample_metadata(), &sample_envelope(), &sign_key).unwrap();

        let s = std::str::from_utf8(&bytes).unwrap().to_string();
        let needle = r#""ciphertext_b64":""#;
        let idx = s.find(needle).expect("ciphertext_b64 present");
        let target = idx + needle.len() + 1;
        bytes[target] = if bytes[target] == b'A' { b'B' } else { b'A' };

        let err = parse_vresults(&bytes, &signer_pub).unwrap_err();
        assert!(matches!(err, PackError::SignatureInvalid));
    }

    #[test]
    fn test_parse_rejects_wrong_signer_pub() {
        let sign_key = generate_ed25519();
        let bytes = build_vresults(&sample_metadata(), &sample_envelope(), &sign_key).unwrap();
        let other_pub = generate_ed25519().public_key();

        let err = parse_vresults(&bytes, &other_pub).unwrap_err();
        assert!(matches!(err, PackError::SignerMismatch));
    }

    #[test]
    fn test_parse_rejects_vpack_format_byte_for_byte() {
        // A `.vresults` parser must refuse a `.vpack` envelope even though
        // the wire schema is structurally identical apart from the format
        // string.  This guards against operator confusion / wrong-direction
        // pack upload.
        let sign_key = generate_ed25519();
        let signer_pub = sign_key.public_key();
        let mut bytes = build_vresults(&sample_metadata(), &sample_envelope(), &sign_key).unwrap();

        let s = std::str::from_utf8(&bytes).unwrap();
        let idx = s.find(r#""format":"vresults""#).unwrap();
        // Overwrite "vresults" with "vpack...." (same length).  This will
        // also invalidate the sig (good — defense in depth) but the
        // *first* rejection should be UnsupportedFormat.
        bytes[idx + 10..idx + 10 + 5].copy_from_slice(b"vpack");
        // Pad remaining 3 characters of "vresults" with closing-quote bytes
        // to keep JSON valid; this is purely for the structural rejection
        // test (signature will also fail but format check runs first).
        bytes[idx + 10 + 5] = b'X';
        bytes[idx + 10 + 6] = b'X';
        bytes[idx + 10 + 7] = b'X';

        let err = parse_vresults(&bytes, &signer_pub).unwrap_err();
        assert!(matches!(err, PackError::UnsupportedFormat { .. }));
    }

    #[test]
    fn test_parse_rejects_bad_pack_id() {
        // 36 chars with correct dash positions but non-hex tail.
        let sign_key = generate_ed25519();
        let signer_pub = sign_key.public_key();
        let mut bad = sample_metadata();
        bad.pack_id = "550e8400-e29b-41d4-a716-4466554400zz".to_string();
        assert_eq!(bad.pack_id.len(), 36);
        let bytes = build_vresults(&bad, &sample_envelope(), &sign_key).unwrap();
        let err = parse_vresults(&bytes, &signer_pub).unwrap_err();
        assert!(matches!(err, PackError::BadPackId(_)));
    }

    #[test]
    fn test_parse_rejects_negative_result_count() {
        let sign_key = generate_ed25519();
        let signer_pub = sign_key.public_key();
        let mut bad = sample_metadata();
        bad.result_count = -5;
        let bytes = build_vresults(&bad, &sample_envelope(), &sign_key).unwrap();
        let err = parse_vresults(&bytes, &signer_pub).unwrap_err();
        match err {
            PackError::BadCount { field, got } => {
                assert_eq!(field, "result_count");
                assert_eq!(got, -5);
            }
            other => panic!("expected BadCount, got {other:?}"),
        }
    }

    #[test]
    fn test_iso8601_round_trip_in_envelope() {
        let original = sample_metadata();
        let sign_key = generate_ed25519();
        let bytes = build_vresults(&original, &sample_envelope(), &sign_key).unwrap();
        let parsed = parse_vresults(&bytes, &sign_key.public_key()).unwrap();
        assert_eq!(parsed.metadata.executed_at, original.executed_at);
    }
}
