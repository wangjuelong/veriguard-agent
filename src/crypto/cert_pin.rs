//! TLS leaf certificate SHA-256 pin verifier.
//!
//! Veriguard's install pack encodes the platform's expected leaf certificate
//! fingerprint as a `sha256:<hex>` string.  This module provides:
//!
//! * [`cert_sha256`] — compute SHA-256 over raw DER bytes
//! * [`verify_cert_pin`] — case-insensitive hex compare against the pinned
//!   value, returning a typed error on mismatch
//!
//! The actual reqwest TLS hook is wired in by C1-Agent-2 (Mode A transport);
//! this module only provides the comparison primitive.
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors emitted by certificate pin verification.
#[derive(Debug, Error)]
pub enum CertPinError {
    /// Pin string did not start with the required `sha256:` algorithm prefix.
    #[error("certificate pin must start with 'sha256:', got {0:?}")]
    BadAlgorithm(String),

    /// Pin hex segment was not exactly 64 lowercase hex characters.
    #[error("certificate pin hex must be 64 hex characters, got {0} chars")]
    BadHexLength(usize),

    /// Pin contained non-hex characters.
    #[error("certificate pin hex contains non-hex character {0:?}")]
    BadHexCharacter(char),

    /// Computed digest did not match the pinned value.
    #[error("certificate pin mismatch: expected {expected}, got {actual}")]
    Mismatch {
        /// Expected fingerprint (lowercase hex).
        expected: String,
        /// Computed fingerprint (lowercase hex).
        actual: String,
    },
}

/// SHA-256 digest size in bytes.
pub const DIGEST_BYTES: usize = 32;

/// Compute SHA-256 over raw DER certificate bytes.
pub fn cert_sha256(der_bytes: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(der_bytes);
    hasher.finalize().into()
}

/// Verify that the DER-encoded leaf certificate matches `expected_pin`.
///
/// `expected_pin` must be of the form `sha256:<64 hex chars>`.  Hex compare
/// is case-insensitive; the error message echoes both sides in lowercase.
pub fn verify_cert_pin(der_bytes: &[u8], expected_pin: &str) -> Result<(), CertPinError> {
    let expected_hex = parse_pin(expected_pin)?;
    let digest = cert_sha256(der_bytes);
    let actual_hex = hex_lower(&digest);

    if actual_hex == expected_hex {
        Ok(())
    } else {
        Err(CertPinError::Mismatch {
            expected: expected_hex,
            actual: actual_hex,
        })
    }
}

/// Parse a `sha256:<hex>` pin string, returning the lowercased hex segment.
fn parse_pin(pin: &str) -> Result<String, CertPinError> {
    let Some(hex) = pin.strip_prefix("sha256:") else {
        return Err(CertPinError::BadAlgorithm(pin.to_string()));
    };
    if hex.len() != DIGEST_BYTES * 2 {
        return Err(CertPinError::BadHexLength(hex.len()));
    }
    let mut out = String::with_capacity(hex.len());
    for ch in hex.chars() {
        if !ch.is_ascii_hexdigit() {
            return Err(CertPinError::BadHexCharacter(ch));
        }
        out.push(ch.to_ascii_lowercase());
    }
    Ok(out)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256("abc") is a famous fixed vector — guards against accidental
    /// algorithm swap (e.g. SHA-1 / SHA-512).
    const ABC_DIGEST_HEX: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn test_cert_sha256_known_vector() {
        let d = cert_sha256(b"abc");
        assert_eq!(hex_lower(&d), ABC_DIGEST_HEX);
    }

    #[test]
    fn test_verify_cert_pin_match_lowercase() {
        let pin = format!("sha256:{ABC_DIGEST_HEX}");
        assert!(verify_cert_pin(b"abc", &pin).is_ok());
    }

    #[test]
    fn test_verify_cert_pin_match_uppercase() {
        let pin = format!("sha256:{}", ABC_DIGEST_HEX.to_uppercase());
        assert!(
            verify_cert_pin(b"abc", &pin).is_ok(),
            "uppercase hex must still match"
        );
    }

    #[test]
    fn test_verify_cert_pin_mismatch_returns_error() {
        // Flip the last hex pair.
        let mut bad_hex = ABC_DIGEST_HEX.to_string();
        bad_hex.pop();
        bad_hex.pop();
        bad_hex.push_str("00");
        let pin = format!("sha256:{bad_hex}");
        let err = verify_cert_pin(b"abc", &pin).expect_err("must mismatch");
        assert!(matches!(err, CertPinError::Mismatch { .. }));
    }

    #[test]
    fn test_verify_cert_pin_bad_algorithm() {
        let pin = format!("sha1:{}", "0".repeat(40));
        let err = verify_cert_pin(b"abc", &pin).expect_err("must reject sha1");
        assert!(matches!(err, CertPinError::BadAlgorithm(_)));
    }

    #[test]
    fn test_verify_cert_pin_bad_hex_length() {
        let pin = "sha256:abcd".to_string();
        let err = verify_cert_pin(b"abc", &pin).expect_err("must reject short hex");
        assert!(matches!(err, CertPinError::BadHexLength(4)));
    }

    #[test]
    fn test_verify_cert_pin_bad_hex_character() {
        // 64 chars but one is non-hex.
        let pin = format!("sha256:{}", "z".repeat(64));
        let err = verify_cert_pin(b"abc", &pin).expect_err("must reject non-hex");
        assert!(matches!(err, CertPinError::BadHexCharacter('z')));
    }
}
