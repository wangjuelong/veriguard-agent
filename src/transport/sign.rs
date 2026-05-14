//! X-Veriguard request signing.
//!
//! ## What this module does
//!
//! Build the three header pairs every Mode A request must carry:
//!
//! * `X-Veriguard-Signature`      base64 of the 64-byte Ed25519 signature
//! * `X-Veriguard-Timestamp`      decimal Unix epoch millis (e.g. `"1715688000000"`)
//! * `X-Veriguard-Onboard-Token`  the 64-hex onboard token
//!
//! ## Wire contract
//!
//! The signature input is **`utf8(timestamp) || rawBody`**, mirroring
//! `AgentTaskQueueApi.verifyAgentSignature` on the Java side:
//!
//! * `GET`: `rawBody` is empty, so signed bytes are just the timestamp.
//! * `POST` (result upload): `rawBody` is the canonical JSON form built by
//!   [`build_canonical_result_bytes`] — 8 fields sorted alphabetically with
//!   nulls coerced to empty strings, no whitespace.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use crate::crypto::ed25519::Ed25519PrivateKey;

use super::poll::TaskResult;

/// HTTP header carrying the base64 Ed25519 signature.
pub const SIG_HEADER: &str = "X-Veriguard-Signature";

/// HTTP header carrying the Unix epoch millis (decimal).
pub const TS_HEADER: &str = "X-Veriguard-Timestamp";

/// HTTP header carrying the 64-hex onboard token.
pub const TOKEN_HEADER: &str = "X-Veriguard-Onboard-Token";

/// The three headers a signed request must add, plus the raw timestamp
/// string (exposed so tests / poll loops can reuse the same value across
/// retries).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRequest {
    /// `(header_name, header_value)` pairs in stable order: sig, timestamp,
    /// token.  Callers pass these to `reqwest::RequestBuilder::header`.
    pub headers: Vec<(String, String)>,
}

impl SignedRequest {
    /// Borrow the raw `X-Veriguard-Timestamp` value.
    #[allow(dead_code)]
    pub fn timestamp(&self) -> &str {
        // Find by header name rather than positional index.  This stays
        // correct even if [`build`] ever reorders headers, where a hard
        // `&self.headers[1].1` would silently return the wrong value.
        self.headers
            .iter()
            .find(|(k, _)| k == TS_HEADER)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    }
}

/// Sign a GET request.  Signed bytes are `utf8(timestamp)` (no body).
pub fn sign_get(sign_priv: &Ed25519PrivateKey, onboard_token: &str) -> SignedRequest {
    let ts = current_timestamp_millis();
    build(sign_priv, onboard_token, &ts, &[])
}

/// Sign a POST whose canonical body bytes are `canonical_body`.
///
/// Signed bytes are `utf8(timestamp) || canonical_body`.
pub fn sign_post(
    canonical_body: &[u8],
    sign_priv: &Ed25519PrivateKey,
    onboard_token: &str,
) -> SignedRequest {
    let ts = current_timestamp_millis();
    build(sign_priv, onboard_token, &ts, canonical_body)
}

/// Internal helper: build a [`SignedRequest`] for an explicit timestamp.  Kept
/// `pub(crate)` so unit tests in this crate can pin a known timestamp.
pub(crate) fn build(
    sign_priv: &Ed25519PrivateKey,
    onboard_token: &str,
    timestamp_millis: &str,
    body: &[u8],
) -> SignedRequest {
    let mut signed_input = Vec::with_capacity(timestamp_millis.len() + body.len());
    signed_input.extend_from_slice(timestamp_millis.as_bytes());
    signed_input.extend_from_slice(body);
    let sig = sign_priv.sign(&signed_input);
    let sig_b64 = B64.encode(sig.to_bytes());

    SignedRequest {
        headers: vec![
            (SIG_HEADER.to_string(), sig_b64),
            (TS_HEADER.to_string(), timestamp_millis.to_string()),
            (TOKEN_HEADER.to_string(), onboard_token.to_string()),
        ],
    }
}

/// Canonical JSON for the 8-field signature input of a result POST.
///
/// Mirrors `AgentTaskQueueApi.canonicalResultBytes`:
///
/// * Field order is alphabetical: `error_message`, `exit_code`,
///   `finished_at`, `started_at`, `status`, `stderr`, `stdout`, `task_id`.
/// * Null string fields (`error_message`, `finished_at`, `started_at`,
///   `stderr`, `stdout`) are coerced to `""` so the byte representation is
///   deterministic.
/// * Serialised with no whitespace.
pub fn build_canonical_result_bytes(result: &TaskResult, task_id: &str) -> Vec<u8> {
    // BTreeMap iterates keys in lexicographic order, which is what we want.
    let mut map: std::collections::BTreeMap<&str, serde_json::Value> =
        std::collections::BTreeMap::new();
    map.insert(
        "error_message",
        serde_json::Value::String(result.error_message.clone().unwrap_or_default()),
    );
    map.insert(
        "exit_code",
        serde_json::Value::Number(result.exit_code.into()),
    );
    map.insert(
        "finished_at",
        serde_json::Value::String(result.finished_at.clone().unwrap_or_default()),
    );
    map.insert(
        "started_at",
        serde_json::Value::String(result.started_at.clone().unwrap_or_default()),
    );
    map.insert("status", serde_json::Value::String(result.status.clone()));
    map.insert(
        "stderr",
        serde_json::Value::String(result.stderr.clone().unwrap_or_default()),
    );
    map.insert(
        "stdout",
        serde_json::Value::String(result.stdout.clone().unwrap_or_default()),
    );
    map.insert("task_id", serde_json::Value::String(task_id.to_string()));

    serde_json::to_vec(&map).expect("BTreeMap of primitive values must serialize")
}

fn current_timestamp_millis() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis();
    now.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::generate_ed25519;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn test_sign_get_produces_three_headers() {
        let key = generate_ed25519();
        let signed = sign_get(&key, TOKEN);
        assert_eq!(signed.headers.len(), 3);
        assert_eq!(signed.headers[0].0, SIG_HEADER);
        assert_eq!(signed.headers[1].0, TS_HEADER);
        assert_eq!(signed.headers[2].0, TOKEN_HEADER);
    }

    #[test]
    fn test_sign_get_header_names_in_stable_order() {
        let key = generate_ed25519();
        let signed = sign_get(&key, TOKEN);
        let names: Vec<&str> = signed.headers.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, vec![SIG_HEADER, TS_HEADER, TOKEN_HEADER]);
    }

    #[test]
    fn test_sign_get_round_trip_verifies() {
        let key = generate_ed25519();
        let pubk = key.public_key();
        let signed = build(&key, TOKEN, "1715688000000", &[]);
        let sig_b64 = &signed.headers[0].1;
        let ts = &signed.headers[1].1;

        let sig_bytes = B64.decode(sig_b64).expect("b64 decodes");
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = crate::crypto::ed25519::Ed25519Signature::from_bytes(&sig_arr);

        // Verify against `utf8(ts) || body` where body is empty for GET.
        assert!(pubk.verify(ts.as_bytes(), &sig));
    }

    #[test]
    fn test_sign_post_round_trip_verifies() {
        let key = generate_ed25519();
        let pubk = key.public_key();
        let body = br#"{"hello":"world"}"#;
        let signed = build(&key, TOKEN, "1715688000000", body);
        let sig_b64 = &signed.headers[0].1;
        let ts = &signed.headers[1].1;

        let sig_bytes = B64.decode(sig_b64).expect("b64 decodes");
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = crate::crypto::ed25519::Ed25519Signature::from_bytes(&sig_arr);

        // signed input = utf8(timestamp) || body
        let mut expected = Vec::new();
        expected.extend_from_slice(ts.as_bytes());
        expected.extend_from_slice(body);
        assert!(pubk.verify(&expected, &sig));
    }

    #[test]
    fn test_sign_post_does_not_verify_body_alone() {
        // Pin the contract: signed input includes the timestamp; verifying
        // against the body alone must fail.
        let key = generate_ed25519();
        let pubk = key.public_key();
        let body = br#"{"x":1}"#;
        let signed = build(&key, TOKEN, "1715688000000", body);
        let sig_bytes = B64.decode(&signed.headers[0].1).expect("b64");
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = crate::crypto::ed25519::Ed25519Signature::from_bytes(&sig_arr);

        // Verifying body-only must NOT verify — timestamp is required prefix.
        assert!(!pubk.verify(body, &sig));
    }

    #[test]
    fn test_timestamp_accessor_finds_by_name_not_index() {
        // Construct a SignedRequest with headers in a non-default order.
        // The accessor must locate TS_HEADER by name, NOT by index 1.
        let shuffled = SignedRequest {
            headers: vec![
                (TS_HEADER.to_string(), "1715688000000".to_string()),
                (SIG_HEADER.to_string(), "dummy-sig".to_string()),
                (TOKEN_HEADER.to_string(), TOKEN.to_string()),
            ],
        };
        assert_eq!(shuffled.timestamp(), "1715688000000");

        // Reverse order again.
        let other = SignedRequest {
            headers: vec![
                (TOKEN_HEADER.to_string(), TOKEN.to_string()),
                (SIG_HEADER.to_string(), "dummy-sig".to_string()),
                (TS_HEADER.to_string(), "9999999999999".to_string()),
            ],
        };
        assert_eq!(other.timestamp(), "9999999999999");
    }

    #[test]
    fn test_sign_get_timestamp_is_decimal_unix_millis() {
        let key = generate_ed25519();
        let signed = sign_get(&key, TOKEN);
        let ts = signed.timestamp();
        // 13 digits is the millis epoch in 2001..5138; future-proof check.
        assert!(
            ts.chars().all(|c| c.is_ascii_digit()),
            "timestamp must be decimal ASCII, got {ts:?}"
        );
        assert!(
            ts.len() >= 13,
            "timestamp must be at least 13 digits (post-2001 millis), got {ts:?}"
        );
    }

    #[test]
    fn test_canonical_result_bytes_alphabetical_keys() {
        let result = TaskResult {
            status: "SUCCESS".to_string(),
            exit_code: 0,
            stdout: Some("ok".to_string()),
            stderr: Some("".to_string()),
            started_at: Some("2026-05-15T10:30:00Z".to_string()),
            finished_at: Some("2026-05-15T10:30:05Z".to_string()),
            error_message: None,
        };
        let bytes = build_canonical_result_bytes(&result, "task-123");
        let s = std::str::from_utf8(&bytes).unwrap();

        // Order must be alphabetical: error_message, exit_code, finished_at,
        // started_at, status, stderr, stdout, task_id.
        assert!(s.starts_with(r#"{"error_message":""#), "actual: {s}");
        let positions = [
            s.find("error_message").unwrap(),
            s.find("exit_code").unwrap(),
            s.find("finished_at").unwrap(),
            s.find("started_at").unwrap(),
            s.find("\"status\"").unwrap(),
            s.find("stderr").unwrap(),
            s.find("stdout").unwrap(),
            s.find("task_id").unwrap(),
        ];
        for w in positions.windows(2) {
            assert!(w[0] < w[1], "keys must be alphabetically ordered: {s}");
        }
    }

    #[test]
    fn test_canonical_result_bytes_null_coerced_to_empty_string() {
        let result = TaskResult {
            status: "FAILED".to_string(),
            exit_code: 1,
            stdout: None,
            stderr: None,
            started_at: None,
            finished_at: None,
            error_message: None,
        };
        let bytes = build_canonical_result_bytes(&result, "task-x");
        let s = std::str::from_utf8(&bytes).unwrap();
        // All null string fields coerce to empty strings (not JSON `null`).
        assert!(s.contains(r#""error_message":"""#), "{s}");
        assert!(s.contains(r#""stderr":"""#), "{s}");
        assert!(s.contains(r#""stdout":"""#), "{s}");
        assert!(s.contains(r#""started_at":"""#), "{s}");
        assert!(s.contains(r#""finished_at":"""#), "{s}");
        assert!(!s.contains("null"), "no JSON null tokens allowed: {s}");
    }

    #[test]
    fn test_canonical_result_bytes_no_whitespace() {
        let result = TaskResult {
            status: "SUCCESS".to_string(),
            exit_code: 0,
            stdout: Some("hi".to_string()),
            stderr: None,
            started_at: None,
            finished_at: None,
            error_message: None,
        };
        let bytes = build_canonical_result_bytes(&result, "t");
        let s = std::str::from_utf8(&bytes).unwrap();
        // serde_json default has no whitespace between tokens.
        assert!(!s.contains(" : "), "no space-colon-space: {s}");
        assert!(!s.contains(", "), "no comma-space: {s}");
        assert!(!s.contains('\n'), "no newlines: {s}");
    }

    #[test]
    fn test_canonical_result_bytes_includes_task_id() {
        let result = TaskResult {
            status: "SUCCESS".to_string(),
            exit_code: 0,
            stdout: None,
            stderr: None,
            started_at: None,
            finished_at: None,
            error_message: None,
        };
        let bytes = build_canonical_result_bytes(&result, "task-from-url-path");
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains(r#""task_id":"task-from-url-path""#), "{s}");
    }
}
