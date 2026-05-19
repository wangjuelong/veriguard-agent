//! Ed25519 attribution signing —— agent HTTP capability 出口注入 L1 强归因密码学证据.
//!
//! 与 platform 端 `Ed25519AttributionVerifier`（`wangjuelong/Veriguard` 仓
//! `veriguard-api/src/main/java/io/veriguard/crypto/attribution/Ed25519AttributionVerifier.java`）
//! 字节级对偶；与 `wangjuelong/veriguard-implant` 仓 `src/attribution/mod.rs` 同款
//! canonical msg / wire 格式.
//!
//! ```text
//!   msg  = utf8(run_id + "|" + inject_id + "|" + epoch_ms)
//!   sig  = Ed25519::sign(P_attr_priv, msg)          // RFC 8032 pure Ed25519
//!   wire = base64Std(sig)                            // 64-byte raw → 88-char base64
//! ```
//!
//! Platform 用预置的 `P_attr_pub`（`veriguard.attribution.ed25519.pub-key-base64`）
//! 验签命中 → trace `attribution_level=strong` / `confidence=1.00` /
//! `evidence` 含 `sig-verified`.
//!
//! # 私钥加载
//!
//! 读取环境变量 `VERIGUARD_ATTRIBUTION_PRIV_KEY_B64`（base64 标准字母表，
//! 32 字节 Ed25519 seed）.  未设置 → [`AttributionSigner::from_env`] 返回 `Ok(None)`,
//! 调用方按"无签名"路径继续；platform 端 verifier 落 `unsigned`，attribution 保留 strong.
//!
//! # 失败显式
//!
//! 环境变量存在但 base64 解码失败或长度 ≠ 32 字节 → 直接抛 [`AttributionError`]，
//! 不静默回退.  agent 启动早早失败胜过 HTTP capability 执行时奇怪挂掉.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::SECRET_KEY_LENGTH;
use std::env;
use thiserror::Error;

use crate::crypto::ed25519::Ed25519PrivateKey;

/// 私钥加载/解码失败.
#[derive(Debug, Error)]
pub enum AttributionError {
    #[error("VERIGUARD_ATTRIBUTION_PRIV_KEY_B64 base64 解码失败: {0}")]
    BadBase64(String),
    #[error(
        "VERIGUARD_ATTRIBUTION_PRIV_KEY_B64 解码后长度 {got} ≠ {expected} (Ed25519 seed)"
    )]
    BadKeyLength { got: usize, expected: usize },
}

/// 平台署名 ID 与时间戳载荷.
#[derive(Debug, Clone)]
pub struct SignaturePayload<'a> {
    pub run_id: &'a str,
    pub inject_id: &'a str,
    pub epoch_ms: i64,
}

impl<'a> SignaturePayload<'a> {
    /// Canonical sig 输入 —— 与 Java `Ed25519AttributionVerifier.verify` /
    /// implant `attribution::SignaturePayload::canonical_message` 同款.
    pub fn canonical_message(&self) -> Vec<u8> {
        format!("{}|{}|{}", self.run_id, self.inject_id, self.epoch_ms).into_bytes()
    }
}

/// 已装载私钥的签名器；从 [`AttributionSigner::from_env`] 派生.
pub struct AttributionSigner {
    key: Ed25519PrivateKey,
}

impl AttributionSigner {
    /// 从环境变量加载；返回 `Ok(None)` 表示未配置（agent 静默跳过签名）.
    pub fn from_env() -> Result<Option<Self>, AttributionError> {
        match env::var("VERIGUARD_ATTRIBUTION_PRIV_KEY_B64") {
            Ok(b64) if !b64.is_empty() => Self::from_base64(&b64).map(Some),
            _ => Ok(None),
        }
    }

    /// 直接从 base64 字符串构造 —— 单测和命令行注入用.
    pub fn from_base64(b64: &str) -> Result<Self, AttributionError> {
        let bytes = B64
            .decode(b64)
            .map_err(|e| AttributionError::BadBase64(e.to_string()))?;
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(AttributionError::BadKeyLength {
                got: bytes.len(),
                expected: SECRET_KEY_LENGTH,
            });
        }
        let mut seed = [0u8; SECRET_KEY_LENGTH];
        seed.copy_from_slice(&bytes);
        Ok(Self {
            key: Ed25519PrivateKey::from_bytes(&seed),
        })
    }

    /// 签 `<run_id>|<inject_id>|<epoch_ms>` 并返回 base64 编码的 64 字节 sig.
    pub fn sign_base64(&self, payload: &SignaturePayload<'_>) -> String {
        let msg = payload.canonical_message();
        let sig = self.key.sign(&msg);
        B64.encode(sig.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::{Ed25519PublicKey, Ed25519Signature};

    /// RFC 8032 §7.1 Test 1 vector seed —— 公开测试 vector，与 Veriguard PR #83 +
    /// veriguard-implant PR #3 同源用作 deterministic 单测固定值.
    fn rfc8032_test1_seed_b64() -> String {
        let hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        B64.encode(&bytes)
    }

    #[test]
    fn canonical_message_is_pipe_joined_utf8() {
        let payload = SignaturePayload {
            run_id: "run-abc",
            inject_id: "inj-xyz",
            epoch_ms: 1_747_614_000_123,
        };
        assert_eq!(
            payload.canonical_message(),
            b"run-abc|inj-xyz|1747614000123".to_vec()
        );
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let signer = AttributionSigner::from_base64(&rfc8032_test1_seed_b64()).unwrap();
        let payload = SignaturePayload {
            run_id: "run-1",
            inject_id: "inj-1",
            epoch_ms: 1000,
        };
        let sig_b64 = signer.sign_base64(&payload);
        let sig_bytes = B64.decode(&sig_b64).unwrap();
        assert_eq!(sig_bytes.len(), 64);

        let pub_key: Ed25519PublicKey = signer.key.public_key();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = Ed25519Signature::from_bytes(&sig_arr);
        assert!(pub_key.verify(&payload.canonical_message(), &sig));
    }

    #[test]
    fn sign_is_deterministic_rfc8032_pure() {
        let signer1 = AttributionSigner::from_base64(&rfc8032_test1_seed_b64()).unwrap();
        let signer2 = AttributionSigner::from_base64(&rfc8032_test1_seed_b64()).unwrap();
        let payload = SignaturePayload {
            run_id: "run-1",
            inject_id: "inj-1",
            epoch_ms: 1000,
        };
        assert_eq!(signer1.sign_base64(&payload), signer2.sign_base64(&payload));
    }

    #[test]
    fn bad_base64_returns_error() {
        let result = AttributionSigner::from_base64("!!!not-base64!!!");
        assert!(matches!(result, Err(AttributionError::BadBase64(_))));
    }

    #[test]
    fn wrong_length_seed_returns_error() {
        let short = B64.encode(vec![0u8; 16]);
        let result = AttributionSigner::from_base64(&short);
        assert!(matches!(
            result,
            Err(AttributionError::BadKeyLength { got: 16, expected: 32 })
        ));
    }
}
