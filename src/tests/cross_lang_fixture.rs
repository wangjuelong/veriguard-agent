//! Cross-language wire-format regression test (Rust ↔ Java).
//!
//! Builds a `.vpack` and a `.vresults` envelope from a **fixed test vector**
//! (keys + nonces + plaintext + metadata fields hard-coded inline) and asserts
//! the resulting bytes equal an inline base64 constant.
//!
//! The base64 constants are also committed verbatim to the Veriguard (Java)
//! platform fork as test resources in
//! `veriguard-api/src/test/resources/fixtures/cross-lang-c1/*.bin`. A JUnit
//! test on that side loads the same bytes, parses them with
//! `VpackSerializer` / `VresultsTaskResultParser`, and asserts the recovered
//! plaintext matches the expected JSON. Two independent codepaths agreeing on
//! the same byte sequence is byte-level proof of wire-format compatibility.
//!
//! # Regeneration recipe
//!
//! If the wire format intentionally changes:
//!
//! 1. Set the two `EXPECTED_*_B64` constants below to empty strings.
//! 2. Run `cargo test cross_lang_fixture -- --nocapture`.
//! 3. The test will print the new base64 to stderr; copy it back into the
//!    constants here AND into the corresponding files under
//!    `Veriguard/veriguard-api/src/test/resources/fixtures/cross-lang-c1/`.
//! 4. Update the matching `expected.json` (plaintext + key material echo) on
//!    the Java side as well.
//!
//! # Determinism
//!
//! Every input is fixed:
//!
//! - 32-byte Ed25519 + X25519 secrets from constant byte arrays
//! - 12-byte ChaCha20-Poly1305 nonce constant
//! - UUID `pack_id` constant (lowercase 8-4-4-4-12)
//! - `chrono::DateTime<Utc>` constant via `from_timestamp(...).unwrap()`
//! - Plaintext task / result lists constructed inline from constant fields
//!
//! The non-production [`crate::crypto::x25519_box::seal_box_with_nonce`] entry
//! point provides the deterministic-nonce sealer.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::DateTime;

use crate::crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use crate::crypto::x25519_box::{
    open_box, seal_box_with_nonce, Nonce, X25519PrivateKey, X25519PublicKey,
};
use crate::pack::common::EncryptedEnvelope;
use crate::pack::vpack::{build_vpack, parse_vpack, VpackMetadata};
use crate::pack::vresults::{build_vresults, parse_vresults, VresultsMetadata};
use crate::transport::poll::{Task, TaskResult};

// ---- Fixed test vector ------------------------------------------------------

const PLATFORM_SIGN_SEED: [u8; 32] = [
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
];
const PLATFORM_ENC_SCALAR: [u8; 32] = [
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
];
const AGENT_SIGN_SEED: [u8; 32] = [
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
];
const AGENT_ENC_SCALAR: [u8; 32] = [
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
];

const VPACK_NONCE_BYTES: [u8; 12] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
];
const VRESULTS_NONCE_BYTES: [u8; 12] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
];

const PACK_ID: &str = "11111111-2222-3333-4444-555555555555";
const PLATFORM_ID: &str = "veriguard-fixture-platform";
const AGENT_ID: &str = "veriguard-fixture-agent-1";
const SCHEMA_VERSION_PAYLOAD: &str = "1.0";
const EXPORTED_BY: &str = "fixture@platform";

// Fixed instants for deterministic `issued_at` / `executed_at` fields, expressed
// as UNIX epoch seconds → `DateTime<Utc>` via `from_timestamp(secs, 0)`. The
// values below render as `2026-05-07T10:00:00Z` and `2026-05-07T10:00:30Z` in
// ISO-8601 form (a 30-second gap so the envelope round-trip is realistic).
const ISSUED_AT_SECS: i64 = 1_778_148_000; // 2026-05-07T10:00:00Z
const EXECUTED_AT_SECS: i64 = 1_778_148_030; // 2026-05-07T10:00:30Z

// Expected envelope bytes (base64-encoded canonical JSON envelope).
//
// Regenerate by clearing these constants and running:
//   cargo test cross_lang_fixture -- --nocapture
// then paste the printed `vpack_b64` / `vresults_b64` values back here. The
// strings are long (one canonical JSON envelope each, base64-encoded), which is
// intentional — the whole point is a byte-exact freeze.
const EXPECTED_VPACK_B64: &str = "eyJlbnZlbG9wZV9lbmNyeXB0ZWQiOnsiY2lwaGVyIjoiY2hhY2hhMjAtcG9seTEzMDUiLCJjaXBoZXJ0ZXh0X2I2NCI6InZlVjU3UVZrZEJNcGl0ZlRVL3NWUE15TjIwSFJGeEhsWUczV0lNUUY2K2V6UW0rdjRkVSsvbjIyL0pzVlhOQmR6M0cwOG10WnlNNkpvNmZyZXNIeUNYR1JQNnlQNXdJK0NaaXZKUDFFMXVoVGI5ZUZieWVlc0NDQU1qQTBJN2FWd3VsTUIzaUNFVEJma0NtZjR2d2NIRkZDdjRQM3oxcVNyR1dWMENtL2hwWlR3b2x1QTZDNS9IdWZFV2xCblRYdUxrYXlNTU5pcHZkZWl5SEdDNEsrams0REMxcU5LYlozKyt3TzRDRjE4UXRtWnJQdnZrZVJxaC9uL0tQRmRCRXM3anVraGcxSlZvZlV4Q1BOc0ZiVTF4OGNMYnRhWWJFc2dCcnlHVjFtT1lubjU0WTQvNEhheDkyQUU3UFFldTlRcGdWaHJGR3lyN3RCc2Ftdm83STZrLzQvNFI5TTZQNG9xN3pxNjR6eHlQdGhIYjkrQnF3RGpONmoxWmo4L1RqRUpRTThXbXRuaExJejJQZDBJcE1mNDJEOGZjU1FiOHRvN0VyWnNjU1FYSzIvSzBFcmhEdGZWa0FuR2ZNZ0ZGMkJUNE9NbWY4V3JiaTgzanY0YWVRRWV2UVFoUT09Iiwia2RmIjoieDI1NTE5Iiwibm9uY2VfYjY0IjoiRUJFU0V4UVZGaGNZR1JvYiIsInNjaGVtZSI6Im5hY2wtYm94Iiwic2VuZGVyX3gyNTUxOV9wdWJfYjY0Ijoiem8wNjBjeTJNK3g3Y01GNEZLWEhiczBDbG9VRkRUUkhSYm9GaHc1WWZWaz0ifSwiZm9ybWF0IjoidnBhY2siLCJtZXRhZGF0YV9wbGFpbnRleHQiOnsiYWdlbnRfaWQiOiJ2ZXJpZ3VhcmQtZml4dHVyZS1hZ2VudC0xIiwiZXhwb3J0ZWRfYnkiOiJmaXh0dXJlQHBsYXRmb3JtIiwiaXNzdWVkX2F0IjoiMjAyNi0wNS0wN1QxMDowMDowMFoiLCJwYWNrX2lkIjoiMTExMTExMTEtMjIyMi0zMzMzLTQ0NDQtNTU1NTU1NTU1NTU1IiwicGxhdGZvcm1faWQiOiJ2ZXJpZ3VhcmQtZml4dHVyZS1wbGF0Zm9ybSIsInNjaGVtYV92ZXJzaW9uX3BheWxvYWQiOiIxLjAiLCJ0YXNrX2NvdW50IjoyfSwic2NoZW1hX3ZlcnNpb24iOiIxLjAiLCJzaWduYXR1cmUiOnsic2NoZW1lIjoiRWQyNTUxOSIsInNpZ19iNjQiOiI5WUJ0QVdzZ2srL0FtWVdlQzVicWFUTkdNWWxLdmhjUjdHNzgyaWhzcEJUREh2VkNuRC93L3JDdDdoR1dmU3B3OFlCM01PdWRmeGZpVnF0NWNDNTJDQT09Iiwic2lnbmVyX3B1Yl9iNjQiOiJpb2pqM1hRSjhaWDlVdHN0UExwZGNzcG5DYjhkbEJJYjgzU0lBYlFQYjF3PSJ9fQ==";
const EXPECTED_VRESULTS_B64: &str = "eyJlbnZlbG9wZV9lbmNyeXB0ZWQiOnsiY2lwaGVyIjoiY2hhY2hhMjAtcG9seTEzMDUiLCJjaXBoZXJ0ZXh0X2I2NCI6ImRDMWozZExMRERtV1FSWCtYV3hISHpkZFpHckdGU3JYSTBRcXZYNjIxYnhuOE9xcVZyTkZNRXkrUllrM0NCd25EUEtxODBycUw1OEFBUitCMjdsWTViUnlLZkRseUJJMHJYdXFGWlBRM3YyekdQZGRKbFBWQVM3eFNtSU5kQTE3anNMRk91WlZvaTFTRnVoMGoveFpYcnZGdEVjTmhlMDJDMjI3cm1sOEdQN24vVGVzLys3WWV4b0M5T0VoWTlqeXQwWlNTN0xBV2ROVlI4bC9HYlo4Y3lPdFJIMzV1emF5c09TcTFlUnVsOHdHL0w4WEt6NzJxcUlQa1ZremxsejBGYTRPVXV5dDRDTEtWenlXQ1NxTThqRjRocVRJKy9MYXZPVEJwbjVzUkM0K25Tc0dhZ1F0Ujl5TFhwMHpjeFd2akFXeGxTRDNQL3pVR3RSeVVBTi9lVU1JTWxoRm1tc2l3WlQvRklsWXpmUTVkaFNZWTRlOXRWaGVicysxNzJLTFNpS1J4Q1JQRHA5YzF1c20vbE85bkdYdXduT1ZvelIwYVVFY0txdDBGemg2Z05vVXQwUnhnSGppMjJ1R1NNaFZxS3hJV0wwPSIsImtkZiI6IngyNTUxOSIsIm5vbmNlX2I2NCI6IklDRWlJeVFsSmljb0tTb3IiLCJzY2hlbWUiOiJuYWNsLWJveCIsInNlbmRlcl94MjU1MTlfcHViX2I2NCI6InJBR3lJSjZHTlUrNFV5TjdYZUQwK3JFOGY4djBNNlljQVpOcFlYL3M4UXM9In0sImZvcm1hdCI6InZyZXN1bHRzIiwibWV0YWRhdGFfcGxhaW50ZXh0Ijp7ImFnZW50X2lkIjoidmVyaWd1YXJkLWZpeHR1cmUtYWdlbnQtMSIsImV4ZWN1dGVkX2F0IjoiMjAyNi0wNS0wN1QxMDowMDozMFoiLCJwYWNrX2lkIjoiMTExMTExMTEtMjIyMi0zMzMzLTQ0NDQtNTU1NTU1NTU1NTU1IiwicmVzdWx0X2NvdW50IjoyfSwic2NoZW1hX3ZlcnNpb24iOiIxLjAiLCJzaWduYXR1cmUiOnsic2NoZW1lIjoiRWQyNTUxOSIsInNpZ19iNjQiOiJNdlJBY1RFSERtRDZBY291ZldWSjRZYzJMNmFqSHdSRUY3NmZsR2RFaW03SE5FSWliVHJ0cGt3ODE1UXFwVmN3bVZ2TytsZ2lHK1NqWFIzMTJkODJEUT09Iiwic2lnbmVyX3B1Yl9iNjQiOiI3VWtveGlqUndzYnE2UU00a0ZtVllTbFpKenBjWS9rMk5zRkdGS3lITjlFPSJ9fQ==";

// ---- Tests ------------------------------------------------------------------

#[test]
fn vpack_byte_for_byte_matches_committed_fixture() {
    let (vpack_bytes, plaintext_tasks, _, _) = build_fixture_vpack();
    let actual_b64 = B64.encode(&vpack_bytes);

    eprintln!("\n=== Cross-lang fixture: .vpack ===");
    eprintln!("plaintext_b64 = {}", B64.encode(&plaintext_tasks));
    eprintln!("vpack_b64     = {}", actual_b64);
    eprintln!("==================================\n");

    assert_eq!(
        actual_b64, EXPECTED_VPACK_B64,
        "deterministic .vpack envelope bytes drifted — either the wire format changed (regen fixture and re-sync Java side) or a bug snuck in"
    );
}

#[test]
fn vresults_byte_for_byte_matches_committed_fixture() {
    let (vresults_bytes, plaintext_results, _, _) = build_fixture_vresults();
    let actual_b64 = B64.encode(&vresults_bytes);

    eprintln!("\n=== Cross-lang fixture: .vresults ===");
    eprintln!("plaintext_b64 = {}", B64.encode(&plaintext_results));
    eprintln!("vresults_b64  = {}", actual_b64);
    eprintln!("=====================================\n");

    assert_eq!(
        actual_b64, EXPECTED_VRESULTS_B64,
        "deterministic .vresults envelope bytes drifted — either the wire format changed (regen fixture and re-sync Java side) or a bug snuck in"
    );
}

#[test]
fn vpack_round_trips_through_parser() {
    // Independent sanity: the fixture we expose to Java is itself parseable
    // by our own parser. Catches a Rust-side serializer regression even if
    // the Java side is never built.
    let (vpack_bytes, plaintext_tasks, platform_sign_pub, _) = build_fixture_vpack();
    let parsed = parse_vpack(&vpack_bytes, &platform_sign_pub).expect("parse vpack");
    assert_eq!(parsed.metadata.pack_id, PACK_ID);
    assert_eq!(parsed.metadata.agent_id, AGENT_ID);
    assert_eq!(parsed.metadata.platform_id, PLATFORM_ID);
    assert_eq!(parsed.metadata.task_count, 2);
    assert_eq!(parsed.metadata.exported_by, EXPORTED_BY);
    assert_eq!(parsed.encrypted_envelope.nonce, VPACK_NONCE_BYTES);

    // Decrypt and compare to source plaintext.
    let platform_enc_priv = X25519PrivateKey::from_bytes(&PLATFORM_ENC_SCALAR);
    let agent_enc_priv = X25519PrivateKey::from_bytes(&AGENT_ENC_SCALAR);
    let nonce = Nonce::from_bytes(parsed.encrypted_envelope.nonce);
    let recovered = open_box(
        &parsed.encrypted_envelope.ciphertext,
        &nonce,
        &platform_enc_priv.public_key(),
        &agent_enc_priv,
    )
    .expect("open vpack body");
    assert_eq!(recovered, plaintext_tasks);
}

#[test]
fn vresults_round_trips_through_parser() {
    let (vresults_bytes, plaintext_results, agent_sign_pub, _) = build_fixture_vresults();
    let parsed = parse_vresults(&vresults_bytes, &agent_sign_pub).expect("parse vresults");
    assert_eq!(parsed.metadata.pack_id, PACK_ID);
    assert_eq!(parsed.metadata.agent_id, AGENT_ID);
    assert_eq!(parsed.metadata.result_count, 2);
    assert_eq!(parsed.encrypted_envelope.nonce, VRESULTS_NONCE_BYTES);

    let platform_enc_priv = X25519PrivateKey::from_bytes(&PLATFORM_ENC_SCALAR);
    let agent_enc_priv = X25519PrivateKey::from_bytes(&AGENT_ENC_SCALAR);
    let nonce = Nonce::from_bytes(parsed.encrypted_envelope.nonce);
    let recovered = open_box(
        &parsed.encrypted_envelope.ciphertext,
        &nonce,
        &agent_enc_priv.public_key(),
        &platform_enc_priv,
    )
    .expect("open vresults body");
    assert_eq!(recovered, plaintext_results);
}

// ---- Fixture builder helpers -----------------------------------------------

fn build_fixture_vpack() -> (Vec<u8>, Vec<u8>, Ed25519PublicKey, X25519PublicKey) {
    let platform_sign_priv = Ed25519PrivateKey::from_bytes(&PLATFORM_SIGN_SEED);
    let platform_enc_priv = X25519PrivateKey::from_bytes(&PLATFORM_ENC_SCALAR);
    let agent_enc_priv = X25519PrivateKey::from_bytes(&AGENT_ENC_SCALAR);
    let platform_sign_pub = platform_sign_priv.public_key();
    let platform_enc_pub = platform_enc_priv.public_key();
    let agent_enc_pub = agent_enc_priv.public_key();

    let tasks = vec![
        Task {
            task_id: "task-fixture-1".to_string(),
            capability: "http_attack".to_string(),
            injector_type: "veriguard-web-attack".to_string(),
            payload: r#"{"method":"GET","url":"http://example.test/"}"#.to_string(),
            expectations: vec!["exp-1".to_string()],
        },
        Task {
            task_id: "task-fixture-2".to_string(),
            capability: "command_inject".to_string(),
            injector_type: "veriguard-command".to_string(),
            payload: r#"{"cmd":"echo fixture"}"#.to_string(),
            expectations: vec![],
        },
    ];
    let plaintext = serde_json::to_vec(&tasks).expect("serialize tasks");
    let task_count = tasks.len() as i32;

    let nonce = Nonce::from_bytes(VPACK_NONCE_BYTES);
    let ciphertext = seal_box_with_nonce(&plaintext, &nonce, &agent_enc_pub, &platform_enc_priv)
        .expect("seal_box_with_nonce");

    // `X25519PublicKey` implements `Copy`, so `to_bytes(self)` does not move it.
    let envelope = EncryptedEnvelope {
        sender_x25519_pub: platform_enc_pub.to_bytes(),
        nonce: VPACK_NONCE_BYTES,
        ciphertext,
    };
    let metadata = VpackMetadata {
        pack_id: PACK_ID.to_string(),
        platform_id: PLATFORM_ID.to_string(),
        agent_id: AGENT_ID.to_string(),
        issued_at: fixed_issued_at(),
        task_count,
        schema_version_payload: SCHEMA_VERSION_PAYLOAD.to_string(),
        exported_by: EXPORTED_BY.to_string(),
    };
    let vpack_bytes = build_vpack(&metadata, &envelope, &platform_sign_priv).expect("build_vpack");
    (vpack_bytes, plaintext, platform_sign_pub, agent_enc_pub)
}

fn build_fixture_vresults() -> (Vec<u8>, Vec<u8>, Ed25519PublicKey, X25519PublicKey) {
    let agent_sign_priv = Ed25519PrivateKey::from_bytes(&AGENT_SIGN_SEED);
    let agent_enc_priv = X25519PrivateKey::from_bytes(&AGENT_ENC_SCALAR);
    let platform_enc_priv = X25519PrivateKey::from_bytes(&PLATFORM_ENC_SCALAR);
    let agent_sign_pub = agent_sign_priv.public_key();
    let agent_enc_pub = agent_enc_priv.public_key();
    let platform_enc_pub = platform_enc_priv.public_key();

    let results = vec![
        TaskResult {
            status: "SUCCESS".to_string(),
            exit_code: 0,
            stdout: Some("ok-1".to_string()),
            stderr: Some(String::new()),
            started_at: Some("2026-05-15T10:00:10Z".to_string()),
            finished_at: Some("2026-05-15T10:00:11Z".to_string()),
            error_message: None,
        },
        TaskResult {
            status: "FAILED".to_string(),
            exit_code: 1,
            stdout: Some(String::new()),
            stderr: Some("boom".to_string()),
            started_at: Some("2026-05-15T10:00:12Z".to_string()),
            finished_at: Some("2026-05-15T10:00:13Z".to_string()),
            error_message: Some("non-zero exit".to_string()),
        },
    ];
    let plaintext = serde_json::to_vec(&results).expect("serialize results");
    let result_count = results.len() as i32;

    let nonce = Nonce::from_bytes(VRESULTS_NONCE_BYTES);
    let ciphertext = seal_box_with_nonce(&plaintext, &nonce, &platform_enc_pub, &agent_enc_priv)
        .expect("seal_box_with_nonce");

    let envelope = EncryptedEnvelope {
        sender_x25519_pub: agent_enc_pub.to_bytes(),
        nonce: VRESULTS_NONCE_BYTES,
        ciphertext,
    };
    let metadata = VresultsMetadata {
        pack_id: PACK_ID.to_string(),
        agent_id: AGENT_ID.to_string(),
        executed_at: fixed_executed_at(),
        result_count,
    };
    let vresults_bytes =
        build_vresults(&metadata, &envelope, &agent_sign_priv).expect("build_vresults");
    (vresults_bytes, plaintext, agent_sign_pub, agent_enc_pub)
}

fn fixed_issued_at() -> DateTime<chrono::Utc> {
    DateTime::from_timestamp(ISSUED_AT_SECS, 0).expect("issued_at timestamp")
}

fn fixed_executed_at() -> DateTime<chrono::Utc> {
    DateTime::from_timestamp(EXECUTED_AT_SECS, 0).expect("executed_at timestamp")
}
