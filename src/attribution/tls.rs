//! TLS-layer L1 强归因 ALPN marker —— ClientHello 中 advertise 一个稳定的
//! Veriguard ALPN protocol，让 SOC 通过 pcap / DPI 在 TLS 加密前就识别
//! "这是 Veriguard agent 的握手"。
//!
//! 招标 §3.3.4 第 5 L1 强归因通道。与已落地 4 通道关系：
//! - HTTP `X-Veriguard-Sig` header (per-request Ed25519 sig)  ← `super::AttributionSigner`
//! - cmdline / Email / pcap stamp                            ← veriguard-implant + Veriguard #84/#86/#90
//! - TLS ALPN marker (本模块)                                  ← 静态识别 + 与 SOC 预登记 JA3 互补
//!
//! ## Design
//!
//! [`build_attribution_tls_config`] 用 `rustls 0.23 + ring` crypto 构造
//! 一个 `rustls::ClientConfig`，`alpn_protocols = ["h2", "http/1.1", "veriguard-attrib/1"]`：
//! 服务端按 RFC 7301 从前两个里挑（不会挑 marker），但整 list 写在 cleartext
//! ClientHello 里，SOC 通过 DPI / pcap 即可识别。
//!
//! 调用方（[`crate::capabilities::http_attack::HttpAttackCapability`]）用
//! `reqwest::ClientBuilder::use_preconfigured_tls` 把该 config 灌进 reqwest
//! 客户端 —— reqwest 0.12 的 `__rustls` 路径会 `downcast_mut::<Option<rustls::ClientConfig>>`
//! 接 owned ClientConfig，故本模块返 `Arc<_>` 后调用方 `(*cfg).clone()` 解一层即可。
//!
//! ## SNI（为何不动）
//!
//! SNI 仍由 reqwest / rustls 按目标 URL 的 hostname 自动派发 —— 不动 SNI 是
//! 为了不破坏服务端按 SNI 选证书的行为；TLS 层 marker 走 ALPN 通道更稳。
//!
//! ## JA3 / JA4
//!
//! 自构 ClientConfig 走 rustls 0.23 + ring 的确定性顺序（TLS 1.2/1.3 版本、
//! ring 默认 cipher suite 序、固定的 ALPN 列表），输出 ClientHello 字段是
//! deterministic 的，对应 JA3 / JA4 hash 稳定 —— 可提前向 SOC 注册作辅助匹配。
//! ALPN 不参与 JA3 但参与 JA4，本 marker 会显式落到 JA4 字符串里。

use std::sync::Arc;

use rustls::crypto::ring;
use rustls::version::{TLS12, TLS13};

/// Stable ALPN protocol name used as TLS-layer Veriguard L1 marker.
/// 18 字节，符合 RFC 7301 `ProtocolName<1..2^8-1>`。
pub const ALPN_MARKER: &[u8] = b"veriguard-attrib/1";

/// ALPN list advertised in ClientHello：先放标准的 h2 / http/1.1（服务端会挑），
/// 末尾追加 Veriguard marker（SOC 识别用）。
///
/// 顺序固定 —— 影响 JA4 字符串，向 SOC 预登记后期望稳定。
pub fn alpn_protocols() -> Vec<Vec<u8>> {
    vec![b"h2".to_vec(), b"http/1.1".to_vec(), ALPN_MARKER.to_vec()]
}

/// 构造带 native 根证书 + Veriguard ALPN marker 的 rustls 客户端配置.
///
/// 失败显式 —— 系统根证书加载有 error / rustls config builder 异常 → panic
/// （与 `HttpAttackCapability::new` 已有的 `.expect("blocking client")` 行为一致；
/// agent 启动早早失败胜过运行时奇怪挂掉）。
pub fn build_attribution_tls_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        panic!("load native root certs failed: {:?}", native.errors);
    }
    for cert in native.certs {
        roots
            .add(cert)
            .expect("add native root cert into RootCertStore");
    }
    build_attribution_tls_config_with_roots(roots)
}

/// 测试友好入口 —— 接 caller 装好的 `RootCertStore`，不读 OS keychain.
///
/// 拆出来是为了让单测能跑（macOS Security framework 在并行 `cargo test` 下
/// 偶发 `Os Error -36 I/O error`，与本模块行为正确性无关；测试用空 store
/// 即可验证 ALPN / 版本 / 链构造的所有 deterministic 部分）。
pub fn build_attribution_tls_config_with_roots(
    roots: rustls::RootCertStore,
) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13, &TLS12])
        .expect("rustls protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();

    config.alpn_protocols = alpn_protocols();
    Arc::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_protocols_contains_marker_in_last_slot() {
        let protos = alpn_protocols();
        assert_eq!(protos.len(), 3);
        assert_eq!(protos[2], ALPN_MARKER.to_vec());
    }

    #[test]
    fn alpn_protocols_lists_standard_first() {
        let protos = alpn_protocols();
        assert_eq!(protos[0], b"h2".to_vec());
        assert_eq!(protos[1], b"http/1.1".to_vec());
    }

    #[test]
    fn alpn_marker_is_rfc7301_legal_length() {
        // ALPN ProtocolName 长度 1..=255 字节；非空且不能超长。
        assert!(!ALPN_MARKER.is_empty());
        assert!(ALPN_MARKER.len() <= 255);
    }

    #[test]
    fn alpn_marker_is_ascii_graphic() {
        // RFC 7301 推荐 protocol-name 全打印 ASCII，便于 DPI 工具显示。
        assert!(ALPN_MARKER.iter().all(|b| b.is_ascii_graphic()));
    }

    #[test]
    fn build_tls_config_with_empty_roots_sets_alpn_with_marker() {
        let config = build_attribution_tls_config_with_roots(rustls::RootCertStore::empty());
        assert_eq!(config.alpn_protocols.len(), 3);
        assert_eq!(config.alpn_protocols[2], ALPN_MARKER.to_vec());
    }

    #[test]
    fn alpn_protocols_is_deterministic_across_calls() {
        // SOC 预登记 JA4 的前提：ALPN list 顺序在多次构造间一致.
        // 用 alpn_protocols() 而非 build_attribution_tls_config()——
        // 后者会读 OS 根证书 store，macOS Keychain 在快速连续调用下偶发 -36 I/O error，
        // 与"ALPN 顺序确定性"是独立的属性.
        let a = alpn_protocols();
        let b = alpn_protocols();
        assert_eq!(a, b);
    }
}
