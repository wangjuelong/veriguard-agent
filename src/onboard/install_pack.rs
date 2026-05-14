//! `InstallPack` — the JSON document an operator ships to a fresh agent host.
//!
//! See spec § 3.5.1.  The file is consumed by `init --install-pack <path>`
//! (Mode C, offline) or synthesised in-process by `init --bootstrap` (Mode A,
//! online; HTTP fetch is C1-Agent-2 territory).
//!
//! ## Wire schema
//!
//! ```json
//! {
//!     "schema_version": "1.0",
//!     "platform_url": "https://veriguard.example.com",
//!     "platform_cert_pin": "sha256:<64-hex>",
//!     "platform_sign_pub": "<base64 of 32-byte Ed25519 verifying key>",
//!     "platform_enc_pub":  "<base64 of 32-byte X25519 public key>",
//!     "onboard_token": "<64-hex single-use token>",
//!     "agent_label": "agent-prod-01"
//! }
//! ```
//!
//! All fields are required.  Unknown fields are rejected (`deny_unknown_fields`)
//! so a stale extra field cannot silently shadow the intended behaviour.
use std::fs;
use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors raised while parsing or validating an `InstallPack`.
#[derive(Debug, Error)]
pub enum InstallPackError {
    /// Underlying filesystem error when loading from disk.
    #[error("install pack I/O: {0}")]
    Io(#[from] std::io::Error),

    /// JSON could not be deserialised.
    #[error("install pack JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    /// schema_version is not `"1.0"`.
    #[error("unsupported install pack schema_version: {0:?}")]
    UnsupportedSchemaVersion(String),

    /// platform_url is not HTTPS.
    #[error("platform_url must start with https://, got {0:?}")]
    BadPlatformUrl(String),

    /// platform_cert_pin is not in `sha256:<64-hex>` form.
    #[error("invalid platform_cert_pin: {0}")]
    BadCertPin(String),

    /// base64 public-key field could not decode to 32 bytes.
    #[error("invalid public key {field:?}: {detail}")]
    BadPublicKey {
        /// Which field failed (`platform_sign_pub` | `platform_enc_pub`).
        field: &'static str,
        /// Human-readable detail (length mismatch, base64 decode error, ...).
        detail: String,
    },

    /// onboard_token is not 64 lowercase hex characters.
    #[error("invalid onboard_token: {0}")]
    BadOnboardToken(String),

    /// agent_label is empty, too long, or contains disallowed characters.
    #[error("invalid agent_label: {0}")]
    BadAgentLabel(String),
}

/// Maximum length of `agent_label`.
const AGENT_LABEL_MAX_LEN: usize = 64;
/// Expected length for both ed25519 verifying keys and x25519 public keys.
const PUB_KEY_LEN: usize = 32;
/// Expected length of `onboard_token` in hex characters.
const ONBOARD_TOKEN_HEX_LEN: usize = 64;

/// An `InstallPack` JSON document — see module docs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallPack {
    /// Schema version; only `"1.0"` is accepted.
    pub schema_version: String,
    /// HTTPS URL of the Veriguard platform.
    pub platform_url: String,
    /// TLS leaf cert SHA-256 pin in `sha256:<64-hex>` form.
    pub platform_cert_pin: String,
    /// Base64 of the platform's 32-byte Ed25519 verifying key.
    pub platform_sign_pub: String,
    /// Base64 of the platform's 32-byte X25519 public key.
    pub platform_enc_pub: String,
    /// 64-hex single-use enrolment token.
    pub onboard_token: String,
    /// Operator-supplied label for this agent.
    pub agent_label: String,
}

/// Parse an [`InstallPack`] from JSON text and run [`InstallPack::validate`].
pub fn parse_install_pack(json: &str) -> Result<InstallPack, InstallPackError> {
    let pack: InstallPack = serde_json::from_str(json)?;
    pack.validate()?;
    Ok(pack)
}

/// Maximum size of an `install-pack.json` we will accept on disk.
///
/// An install pack is a small JSON document (~1 KiB in production); anything
/// larger is almost certainly a corrupt or malicious file. The cap is checked
/// BEFORE `fs::read_to_string` so a pathological multi-MiB input cannot
/// allocate memory on the agent.
const INSTALL_PACK_MAX_BYTES: u64 = 64 * 1024;

/// Read an [`InstallPack`] from disk and parse + validate it.
///
/// Rejects files larger than [`INSTALL_PACK_MAX_BYTES`] (64 KiB) with a
/// structured I/O error before any allocation, so a malicious or corrupt
/// file cannot exhaust agent memory.
pub fn load_install_pack(path: &Path) -> Result<InstallPack, InstallPackError> {
    let metadata = fs::metadata(path)?;
    let len = metadata.len();
    if len > INSTALL_PACK_MAX_BYTES {
        return Err(InstallPackError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "install pack at {path:?} is too large: {len} bytes (max {INSTALL_PACK_MAX_BYTES})"
            ),
        )));
    }
    let raw = fs::read_to_string(path)?;
    parse_install_pack(&raw)
}

impl InstallPack {
    /// Run all field-level invariants.  Called automatically by
    /// [`parse_install_pack`] and [`load_install_pack`].
    pub fn validate(&self) -> Result<(), InstallPackError> {
        // schema_version
        if self.schema_version != "1.0" {
            return Err(InstallPackError::UnsupportedSchemaVersion(
                self.schema_version.clone(),
            ));
        }

        // platform_url
        if !self.platform_url.starts_with("https://") {
            return Err(InstallPackError::BadPlatformUrl(self.platform_url.clone()));
        }

        // platform_cert_pin: sha256:<64 lowercase or uppercase hex>
        validate_cert_pin(&self.platform_cert_pin)?;

        // platform_sign_pub: 32 bytes base64
        decode_pub_key(&self.platform_sign_pub, "platform_sign_pub")?;
        // platform_enc_pub: 32 bytes base64
        decode_pub_key(&self.platform_enc_pub, "platform_enc_pub")?;

        // onboard_token: ^[0-9a-f]{64}$ (strict lowercase to keep wire form predictable)
        validate_onboard_token(&self.onboard_token)?;

        // agent_label: non-empty, ≤ 64, [A-Za-z0-9._-]
        validate_agent_label(&self.agent_label)?;

        Ok(())
    }
}

fn validate_cert_pin(pin: &str) -> Result<(), InstallPackError> {
    let Some(hex) = pin.strip_prefix("sha256:") else {
        return Err(InstallPackError::BadCertPin(format!(
            "missing 'sha256:' prefix: {pin:?}"
        )));
    };
    if hex.len() != 64 {
        return Err(InstallPackError::BadCertPin(format!(
            "hex must be 64 chars, got {}",
            hex.len()
        )));
    }
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(InstallPackError::BadCertPin(format!(
            "non-hex character in {hex:?}"
        )));
    }
    Ok(())
}

fn decode_pub_key(b64: &str, field: &'static str) -> Result<[u8; PUB_KEY_LEN], InstallPackError> {
    let bytes = B64_STANDARD
        .decode(b64)
        .map_err(|e| InstallPackError::BadPublicKey {
            field,
            detail: format!("base64 decode failed: {e}"),
        })?;
    if bytes.len() != PUB_KEY_LEN {
        return Err(InstallPackError::BadPublicKey {
            field,
            detail: format!("expected {PUB_KEY_LEN} bytes, got {}", bytes.len()),
        });
    }
    let mut out = [0u8; PUB_KEY_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn validate_onboard_token(token: &str) -> Result<(), InstallPackError> {
    if token.len() != ONBOARD_TOKEN_HEX_LEN {
        return Err(InstallPackError::BadOnboardToken(format!(
            "expected {ONBOARD_TOKEN_HEX_LEN} hex chars, got {}",
            token.len()
        )));
    }
    for ch in token.chars() {
        if !(ch.is_ascii_digit() || ('a'..='f').contains(&ch)) {
            return Err(InstallPackError::BadOnboardToken(format!(
                "non-lowercase-hex character {ch:?}"
            )));
        }
    }
    Ok(())
}

fn validate_agent_label(label: &str) -> Result<(), InstallPackError> {
    if label.is_empty() {
        return Err(InstallPackError::BadAgentLabel("empty label".to_string()));
    }
    if label.len() > AGENT_LABEL_MAX_LEN {
        return Err(InstallPackError::BadAgentLabel(format!(
            "label length {} exceeds max {AGENT_LABEL_MAX_LEN}",
            label.len()
        )));
    }
    for ch in label.chars() {
        let allowed = ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-';
        if !allowed {
            return Err(InstallPackError::BadAgentLabel(format!(
                "disallowed character {ch:?}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/install_pack_valid.json")
    }

    fn valid_json() -> String {
        std::fs::read_to_string(fixture_path()).expect("fixture must exist")
    }

    #[test]
    fn test_install_pack_valid_parses() {
        let pack = parse_install_pack(&valid_json()).expect("valid fixture");
        assert_eq!(pack.schema_version, "1.0");
        assert!(pack.platform_url.starts_with("https://"));
        assert_eq!(pack.agent_label, "agent-prod-01");
    }

    #[test]
    fn test_load_install_pack_from_path() {
        let pack = load_install_pack(&fixture_path()).expect("load fixture");
        assert_eq!(pack.schema_version, "1.0");
    }

    #[test]
    fn test_install_pack_unknown_field_rejects() {
        let mut json: serde_json::Value = serde_json::from_str(&valid_json()).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("extra".to_string(), serde_json::json!("nope"));
        let err = parse_install_pack(&json.to_string()).expect_err("unknown field must fail");
        assert!(matches!(err, InstallPackError::Json(_)));
    }

    #[test]
    fn test_install_pack_missing_field_rejects() {
        let mut json: serde_json::Value = serde_json::from_str(&valid_json()).unwrap();
        json.as_object_mut().unwrap().remove("agent_label");
        let err = parse_install_pack(&json.to_string()).expect_err("missing field");
        assert!(matches!(err, InstallPackError::Json(_)));
    }

    #[test]
    fn test_install_pack_http_url_rejects() {
        let mut json: serde_json::Value = serde_json::from_str(&valid_json()).unwrap();
        json["platform_url"] = serde_json::json!("http://insecure.example.com");
        let err = parse_install_pack(&json.to_string()).expect_err("http url");
        assert!(matches!(err, InstallPackError::BadPlatformUrl(_)));
    }

    #[test]
    fn test_install_pack_bad_cert_pin_missing_prefix() {
        let mut json: serde_json::Value = serde_json::from_str(&valid_json()).unwrap();
        json["platform_cert_pin"] =
            serde_json::json!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let err = parse_install_pack(&json.to_string()).expect_err("missing prefix");
        assert!(matches!(err, InstallPackError::BadCertPin(_)));
    }

    #[test]
    fn test_install_pack_bad_cert_pin_wrong_length() {
        let mut json: serde_json::Value = serde_json::from_str(&valid_json()).unwrap();
        json["platform_cert_pin"] = serde_json::json!("sha256:abcd");
        let err = parse_install_pack(&json.to_string()).expect_err("short hex");
        assert!(matches!(err, InstallPackError::BadCertPin(_)));
    }

    #[test]
    fn test_install_pack_bad_token_short_rejects() {
        let mut json: serde_json::Value = serde_json::from_str(&valid_json()).unwrap();
        json["onboard_token"] = serde_json::json!("0123abcd");
        let err = parse_install_pack(&json.to_string()).expect_err("short token");
        assert!(matches!(err, InstallPackError::BadOnboardToken(_)));
    }

    #[test]
    fn test_install_pack_bad_token_uppercase_rejects() {
        let mut json: serde_json::Value = serde_json::from_str(&valid_json()).unwrap();
        // 64 hex but uppercase.
        json["onboard_token"] =
            serde_json::json!("ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789");
        let err = parse_install_pack(&json.to_string()).expect_err("uppercase token");
        assert!(matches!(err, InstallPackError::BadOnboardToken(_)));
    }

    #[test]
    fn test_install_pack_bad_label_empty_rejects() {
        let mut json: serde_json::Value = serde_json::from_str(&valid_json()).unwrap();
        json["agent_label"] = serde_json::json!("");
        let err = parse_install_pack(&json.to_string()).expect_err("empty label");
        assert!(matches!(err, InstallPackError::BadAgentLabel(_)));
    }

    #[test]
    fn test_install_pack_bad_label_special_chars_rejects() {
        let mut json: serde_json::Value = serde_json::from_str(&valid_json()).unwrap();
        json["agent_label"] = serde_json::json!("agent prod 01"); // spaces
        let err = parse_install_pack(&json.to_string()).expect_err("space");
        assert!(matches!(err, InstallPackError::BadAgentLabel(_)));
    }

    #[test]
    fn test_install_pack_bad_label_too_long_rejects() {
        let mut json: serde_json::Value = serde_json::from_str(&valid_json()).unwrap();
        json["agent_label"] = serde_json::json!("a".repeat(65));
        let err = parse_install_pack(&json.to_string()).expect_err("too long");
        assert!(matches!(err, InstallPackError::BadAgentLabel(_)));
    }

    #[test]
    fn test_install_pack_bad_pub_key_short_rejects() {
        let mut json: serde_json::Value = serde_json::from_str(&valid_json()).unwrap();
        // 16 bytes base64-encoded = 24 chars (no padding) — too short.
        json["platform_sign_pub"] = serde_json::json!(B64_STANDARD.encode([0u8; 16]));
        let err = parse_install_pack(&json.to_string()).expect_err("short pub");
        assert!(
            matches!(err, InstallPackError::BadPublicKey { field, .. } if field == "platform_sign_pub")
        );
    }

    #[test]
    fn test_install_pack_bad_schema_version_rejects() {
        let mut json: serde_json::Value = serde_json::from_str(&valid_json()).unwrap();
        json["schema_version"] = serde_json::json!("2.0");
        let err = parse_install_pack(&json.to_string()).expect_err("version");
        assert!(matches!(err, InstallPackError::UnsupportedSchemaVersion(_)));
    }

    #[test]
    fn test_install_pack_rejects_oversized_file() {
        // Write 100 KiB of whitespace (well over the 64 KiB cap) and confirm
        // `load_install_pack` refuses to even read the file.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.json");
        let big = " ".repeat(100 * 1024);
        std::fs::write(&path, big).unwrap();

        let err = load_install_pack(&path).expect_err("oversized must fail");
        match err {
            InstallPackError::Io(io_err) => {
                let msg = io_err.to_string();
                assert!(
                    msg.contains("too large"),
                    "error must mention the cap: {msg}"
                );
            }
            other => panic!("expected Io error, got {other:?}"),
        }
    }
}
