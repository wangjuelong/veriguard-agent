//! Veriguard agent 目标白名单 CIDR 校验 —— pre-flight 拦截 HTTP 出网到非白名单 IP
//! (招标 §3.5 / §6.1 "靶机执行硬约束" + 双层防御 agent 侧)。
//!
//! 与 platform 端 `AllowedCidrService` (`wangjuelong/Veriguard` 仓 PR #87
//! `veriguard-api/src/main/java/io/veriguard/target/AllowedCidrService.java`) 字节级对齐的
//! Outcome 语义：
//!
//! - **Allowed** —— 字面 IP 命中白名单某条 CIDR；放行
//! - **Denied** —— 字面 IP 不在任何 CIDR；拒发
//! - **Deferred** —— host 是 hostname；agent 不强解 DNS（与 platform 同款决策），
//!   reqwest 在 send 时会解析；若解析后 IP 仍违规，建议 OS 防火墙 / SOC 兜底
//! - **Malformed** —— URL 无法 parse；放行让 reqwest 自然失败（不替它做 URL 语法校验）
//!
//! # 配置 (方案 C 选型：agent-local env var，与 [`crate::attribution`] 同款 opt-in)
//!
//! 环境变量 `VERIGUARD_TARGET_ALLOWED_CIDR`，逗号分隔，IPv4 + IPv6 双栈：
//!
//! ```text
//! VERIGUARD_TARGET_ALLOWED_CIDR=10.0.0.0/24,2001:db8::/32
//! ```
//!
//! 未设置或空 → [`AllowedCidrPolicy::from_env`] 返回 `Ok(None)`；
//! `HttpAttackCapability` 跳过 pre-flight（与 platform 端"whitelist 空 → 写入 gate no-op"
//! 同款；defense-in-depth 各层独立 opt-in）。
//!
//! # 失败显式
//!
//! 任何一条 CIDR 解析失败（地址非字面 IP / 缺前缀 / 前缀长度越界）→ 直接抛
//! [`AllowedCidrError`]；agent 启动早早失败胜过 capability 执行时奇怪挂掉。

use std::env;
use std::net::IpAddr;
use std::str::FromStr;

use thiserror::Error;

const ENV_VAR: &str = "VERIGUARD_TARGET_ALLOWED_CIDR";
const BITS_PER_BYTE: u32 = 8;

/// 白名单解析失败.
#[derive(Debug, Error)]
pub enum AllowedCidrError {
    #[error("{ENV_VAR} 含空条目")]
    BlankEntry,
    #[error("{ENV_VAR} 条目缺前缀长度 ('/'): {0}")]
    MissingPrefix(String),
    #[error("{ENV_VAR} 条目地址部分非字面 IP: {0}")]
    BadAddress(String),
    #[error("{ENV_VAR} 条目前缀长度非整数: {0}")]
    BadPrefixNumber(String),
    #[error("{ENV_VAR} 条目前缀长度越界 [0, {max}]: {entry}")]
    PrefixOutOfRange { entry: String, max: u32 },
}

/// 单条 target 校验结果 —— 与 platform `TargetValidationResult.Outcome` 同款 4 状态.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Allowed { reason: String },
    Denied { reason: String },
    Deferred { reason: String },
    Malformed { reason: String },
}

/// 单条解析后的 CIDR.  byte 级前缀长度比对 (IPv4 + IPv6 双栈).
#[derive(Debug, Clone)]
struct ParsedCidr {
    network: Vec<u8>,
    prefix_len: u32,
    original: String,
}

impl ParsedCidr {
    fn contains(&self, target: &[u8]) -> bool {
        // family 不匹配 (IPv4 4B vs IPv6 16B) 直接 false —— IPv4-mapped IPv6 ::ffff: 不
        // 隐式跨族判定，与 platform AllowedCidrService 完全一致.
        if target.len() != self.network.len() {
            return false;
        }
        let full_bytes = (self.prefix_len / BITS_PER_BYTE) as usize;
        let remaining_bits = self.prefix_len % BITS_PER_BYTE;
        for (t, n) in target.iter().zip(self.network.iter()).take(full_bytes) {
            if t != n {
                return false;
            }
        }
        if remaining_bits > 0 && full_bytes < target.len() {
            let mask = ((0xFFu32 << (BITS_PER_BYTE - remaining_bits)) & 0xFF) as u8;
            if target[full_bytes] & mask != self.network[full_bytes] & mask {
                return false;
            }
        }
        true
    }
}

/// 已装载白名单的策略；从 [`AllowedCidrPolicy::from_env`] 派生.
#[derive(Debug, Clone)]
pub struct AllowedCidrPolicy {
    original: Vec<String>,
    parsed: Vec<ParsedCidr>,
}

impl AllowedCidrPolicy {
    /// 从环境变量加载；空字符串 / 未设置 → `Ok(None)` (agent 跳过 pre-flight).
    pub fn from_env() -> Result<Option<Self>, AllowedCidrError> {
        match env::var(ENV_VAR) {
            Ok(raw) if !raw.trim().is_empty() => Self::from_csv(&raw).map(Some),
            _ => Ok(None),
        }
    }

    /// 从逗号分隔字符串构造 —— 单测和命令行注入用.
    pub fn from_csv(csv: &str) -> Result<Self, AllowedCidrError> {
        let entries: Vec<String> = csv
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Self::from_entries(&entries)
    }

    /// 从已分割的条目列表构造.
    pub fn from_entries(entries: &[String]) -> Result<Self, AllowedCidrError> {
        let mut parsed = Vec::with_capacity(entries.len());
        for e in entries {
            parsed.push(parse_one(e)?);
        }
        Ok(Self {
            original: entries.to_vec(),
            parsed,
        })
    }

    /// 调试 / log 用 —— 返回原始 CIDR 字符串列表.
    pub fn allowed_cidrs(&self) -> &[String] {
        &self.original
    }

    /// 校验 URL；解析 host 后逐条 CIDR 比对.
    ///
    /// - URL parse 失败 → `Malformed`
    /// - host 是字面 IP → 命中 CIDR `Allowed`，否则 `Denied`
    /// - host 是 domain → `Deferred` (agent 不强解 DNS；与 platform 同款决策)
    pub fn evaluate_url(&self, url: &str) -> Outcome {
        let parsed = match reqwest::Url::parse(url) {
            Ok(u) => u,
            Err(e) => {
                return Outcome::Malformed {
                    reason: format!("URL parse failed for {url:?}: {e}"),
                }
            }
        };
        // reqwest::Url::host_str() 对 IPv6 URL `http://[::1]/` 返带 brackets
        // 字符串 `[::1]`; IpAddr::from_str 不接受 brackets, 需先剥.
        // 不直接用 url::Host 枚举避免引入 url crate 显式依赖.
        let Some(host_str) = parsed.host_str() else {
            return Outcome::Malformed {
                reason: format!("URL has no host: {url:?}"),
            };
        };
        let trimmed = host_str
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(host_str);
        // 优先尝试解析为字面 IP (IPv4 / IPv6); 失败 → 视作 hostname Deferred.
        match IpAddr::from_str(trimmed) {
            Ok(ip) => self.evaluate_ip(ip),
            Err(_) => Outcome::Deferred {
                reason: format!(
                    "host {host_str:?} 是 hostname; reqwest 会解析, 建议 OS / SOC 兜底"
                ),
            },
        }
    }

    /// 直接校验字面 IP —— 给已解析过 host 的调用方用.
    pub fn evaluate_ip(&self, ip: IpAddr) -> Outcome {
        let bytes: Vec<u8> = match ip {
            IpAddr::V4(v) => v.octets().to_vec(),
            IpAddr::V6(v) => v.octets().to_vec(),
        };
        for cidr in &self.parsed {
            if cidr.contains(&bytes) {
                return Outcome::Allowed {
                    reason: format!("{ip} 命中 {}", cidr.original),
                };
            }
        }
        Outcome::Denied {
            reason: format!("{ip} 不在任何 allowed-cidr 内"),
        }
    }
}

fn parse_one(entry: &str) -> Result<ParsedCidr, AllowedCidrError> {
    if entry.is_empty() {
        return Err(AllowedCidrError::BlankEntry);
    }
    let (addr_part, prefix_part) = entry
        .split_once('/')
        .ok_or_else(|| AllowedCidrError::MissingPrefix(entry.to_string()))?;
    if prefix_part.contains('/') {
        return Err(AllowedCidrError::MissingPrefix(entry.to_string()));
    }
    let addr =
        IpAddr::from_str(addr_part).map_err(|_| AllowedCidrError::BadAddress(entry.to_string()))?;
    let prefix_len: u32 = prefix_part
        .parse()
        .map_err(|_| AllowedCidrError::BadPrefixNumber(entry.to_string()))?;
    let max_prefix: u32 = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix_len > max_prefix {
        return Err(AllowedCidrError::PrefixOutOfRange {
            entry: entry.to_string(),
            max: max_prefix,
        });
    }
    let network = match addr {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    };
    Ok(ParsedCidr {
        network,
        prefix_len,
        original: entry.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // fixture 全用 RFC 5737 (10.0.0.0/24, 192.0.2.0/24) + RFC 3849 (2001:db8::/32)
    // 文档保留前缀, 无真实地址泄漏 —— 与 platform PR #87 / #88 同源.

    fn policy(cidrs: &[&str]) -> AllowedCidrPolicy {
        let owned: Vec<String> = cidrs.iter().map(|s| s.to_string()).collect();
        AllowedCidrPolicy::from_entries(&owned).expect("valid CIDR fixture")
    }

    fn outcome_kind(o: &Outcome) -> &'static str {
        match o {
            Outcome::Allowed { .. } => "Allowed",
            Outcome::Denied { .. } => "Denied",
            Outcome::Deferred { .. } => "Deferred",
            Outcome::Malformed { .. } => "Malformed",
        }
    }

    // ---- IPv4 字面 ----

    #[test]
    fn ipv4_in_range_is_allowed() {
        let p = policy(&["10.0.0.0/24"]);
        assert_eq!(
            outcome_kind(&p.evaluate_url("http://10.0.0.5/api")),
            "Allowed"
        );
    }

    #[test]
    fn ipv4_out_of_range_is_denied() {
        let p = policy(&["10.0.0.0/24"]);
        let o = p.evaluate_url("http://10.0.1.5/api");
        assert_eq!(outcome_kind(&o), "Denied");
        if let Outcome::Denied { reason } = o {
            assert!(reason.contains("10.0.1.5"), "reason should name target IP");
        }
    }

    #[test]
    fn ipv4_slash32_exact_match() {
        let p = policy(&["192.0.2.5/32"]);
        assert_eq!(
            outcome_kind(&p.evaluate_url("http://192.0.2.5/")),
            "Allowed"
        );
        assert_eq!(outcome_kind(&p.evaluate_url("http://192.0.2.6/")), "Denied");
    }

    #[test]
    fn ipv4_with_port() {
        let p = policy(&["10.0.0.0/24"]);
        assert_eq!(
            outcome_kind(&p.evaluate_url("http://10.0.0.5:8080/path")),
            "Allowed"
        );
    }

    // ---- IPv6 字面 (招标 IPv6 单栈硬要求) ----

    #[test]
    fn ipv6_in_range_is_allowed() {
        let p = policy(&["2001:db8::/32"]);
        assert_eq!(
            outcome_kind(&p.evaluate_url("http://[2001:db8::1]/")),
            "Allowed"
        );
    }

    #[test]
    fn ipv6_out_of_range_is_denied() {
        let p = policy(&["2001:db8::/32"]);
        assert_eq!(
            outcome_kind(&p.evaluate_url("http://[2001:dead::1]/")),
            "Denied"
        );
    }

    #[test]
    fn ipv6_slash128_exact() {
        let p = policy(&["2001:db8::1/128"]);
        assert_eq!(
            outcome_kind(&p.evaluate_url("http://[2001:db8::1]/")),
            "Allowed"
        );
        assert_eq!(
            outcome_kind(&p.evaluate_url("http://[2001:db8::2]/")),
            "Denied"
        );
    }

    #[test]
    fn ipv6_with_port_brackets() {
        let p = policy(&["2001:db8::/32"]);
        assert_eq!(
            outcome_kind(&p.evaluate_url("https://[2001:db8::1]:8443/api")),
            "Allowed"
        );
    }

    #[test]
    fn mixed_v4_v6_independent_families() {
        let p = policy(&["10.0.0.0/24", "2001:db8::/32"]);
        assert_eq!(outcome_kind(&p.evaluate_url("http://10.0.0.5/")), "Allowed");
        assert_eq!(
            outcome_kind(&p.evaluate_url("http://[2001:db8::1]/")),
            "Allowed"
        );
        assert_eq!(outcome_kind(&p.evaluate_url("http://192.0.2.1/")), "Denied");
    }

    // ---- Hostname / DEFERRED ----

    #[test]
    fn hostname_is_deferred() {
        let p = policy(&["10.0.0.0/24"]);
        let o = p.evaluate_url("https://example.com/api");
        assert_eq!(outcome_kind(&o), "Deferred");
        if let Outcome::Deferred { reason } = o {
            assert!(reason.contains("example.com"));
        }
    }

    // ---- Malformed URL ----

    #[test]
    fn invalid_url_is_malformed() {
        let p = policy(&["10.0.0.0/24"]);
        assert_eq!(
            outcome_kind(&p.evaluate_url("not a url at all")),
            "Malformed"
        );
    }

    // ---- 启动 fail-fast ----

    #[test]
    fn bad_prefix_fails() {
        assert!(matches!(
            AllowedCidrPolicy::from_csv("10.0.0.0/33"),
            Err(AllowedCidrError::PrefixOutOfRange { .. })
        ));
        assert!(matches!(
            AllowedCidrPolicy::from_csv("2001:db8::/129"),
            Err(AllowedCidrError::PrefixOutOfRange { .. })
        ));
    }

    #[test]
    fn missing_prefix_fails() {
        assert!(matches!(
            AllowedCidrPolicy::from_csv("10.0.0.0"),
            Err(AllowedCidrError::MissingPrefix(_))
        ));
    }

    #[test]
    fn not_an_ip_fails() {
        assert!(matches!(
            AllowedCidrPolicy::from_csv("not-an-ip/24"),
            Err(AllowedCidrError::BadAddress(_))
        ));
    }

    #[test]
    fn empty_csv_returns_empty_policy() {
        let p = AllowedCidrPolicy::from_csv("").expect("empty csv is parseable");
        assert!(p.allowed_cidrs().is_empty());
        // 空 policy 对任何字面 IP 返 Denied (whitelist 默认 deny 的策略查询语义；
        // 是否真"拦"由 capability 层决定 —— from_env 空时返 None 直接跳过 pre-flight).
        assert_eq!(outcome_kind(&p.evaluate_url("http://10.0.0.5/")), "Denied");
    }

    // ---- from_env opt-in 语义 ----

    #[test]
    fn from_env_unset_returns_none() {
        // SAFETY: 测试不开启并发 + 立刻清理.
        unsafe { env::remove_var(ENV_VAR) };
        let r = AllowedCidrPolicy::from_env().expect("unset is ok");
        assert!(r.is_none());
    }

    #[test]
    fn from_env_with_value_loads_policy() {
        // SAFETY: 测试不开启并发；用唯一值避免与其他测试 race.
        unsafe { env::set_var(ENV_VAR, "10.0.0.0/24,2001:db8::/32") };
        let r = AllowedCidrPolicy::from_env()
            .expect("valid CSV parses")
            .expect("non-empty CSV yields Some");
        assert_eq!(r.allowed_cidrs().len(), 2);
        unsafe { env::remove_var(ENV_VAR) };
    }
}
