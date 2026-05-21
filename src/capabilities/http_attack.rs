//! `http_attack` — §3 边界 boundary attack capability.
//!
//! The Veriguard platform schedules HTTP requests that the agent fires
//! directly from its own network identity (so it bypasses any external NAT
//! or content gateway).  The capability:
//!
//! 1.  Parses the JSON payload into [`HttpAttackPayload`].
//! 2.  Builds a `reqwest::blocking::Request` with the requested method,
//!     URL, headers and optional body.
//! 3.  Sends it (allowing redirects, default 30s timeout).
//! 4.  Compares the response against the operator-supplied expectations:
//!     * `expected_status_codes` — list of acceptable HTTP status codes
//!     * `expected_body_regex`   — single regex that must match somewhere
//!       in the response body (UTF-8 lossy decoded).
//! 5.  Returns `SUCCESS` when every expectation is satisfied; otherwise
//!     `FAILED` with a structured `error_message`.
//!
//! ## Payload schema
//!
//! ```json
//! {
//!   "method": "GET",
//!   "url": "https://target.example.com/foo",
//!   "headers": { "X-Probe": "veriguard" },
//!   "body_b64": "<optional base64 of request body>",
//!   "expected_status_codes": [200, 204],
//!   "expected_body_regex": null
//! }
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::Deserialize;

use crate::attribution::{AttributionSigner, SignaturePayload};
use crate::target::{AllowedCidrPolicy, Outcome as CidrOutcome};
use crate::transport::poll::{Task, TaskResult};

use super::Capability;

/// HTTP header names used for Veriguard L1 强归因 markers (spec §3.1.3 + §四 归因决策表).
/// 平台 PR #82 把 Run-Id / Node-Id / Inject-Id 三件套注入 `WebAttackContent.headers` JSON.
/// 本 capability 读出 Run-Id / Inject-Id 后追加 Timestamp + Sig 两个 header.
const HEADER_RUN_ID: &str = "X-Veriguard-Run-Id";
const HEADER_INJECT_ID: &str = "X-Veriguard-Inject-Id";
const HEADER_TIMESTAMP: &str = "X-Veriguard-Timestamp";
const HEADER_SIG: &str = "X-Veriguard-Sig";

/// Boundary HTTP attack capability — sends a pre-crafted HTTP request from
/// the agent and compares the response against operator expectations.
pub struct HttpAttackCapability {
    client: reqwest::blocking::Client,
    /// 可选 Ed25519 attribution 签名器（spec §5.2 决策"档 0 + 平台侧验签"）.
    /// `None` → 不注 X-Veriguard-Sig / X-Veriguard-Timestamp（platform verifier
    /// 落 `unsigned` evidence，attribution 仍保留 strong/1.00；兼容旧栈）.
    attribution_signer: Option<Arc<AttributionSigner>>,
    /// 可选 agent-local allowed-cidr 白名单 (招标 §3.5 / §6.1 硬约束).
    /// `None` → 跳过 pre-flight，与 [`crate::attribution`] 同款 opt-in；
    /// `Some(_)` → execute 前用 [`AllowedCidrPolicy::evaluate_url`] 拦 Denied,
    /// 不发包直接返 `failed_result` —— 与 platform 端 PR #88 形成双层 defense in depth.
    allowed_cidr_policy: Option<Arc<AllowedCidrPolicy>>,
}

impl HttpAttackCapability {
    /// Stable capability name used in `Task.capability`.
    pub const NAME: &'static str = "http_attack";

    /// Construct a capability with the default HTTP client and no attribution signer.
    ///
    /// 默认 TLS config 走 [`crate::attribution::tls::build_attribution_tls_config`]，
    /// ClientHello 里 advertise 一个稳定的 `veriguard-attrib/1` ALPN marker
    /// （招标 §3.3.4 第 5 L1 强归因通道，SOC 可 pcap/DPI 识别）。服务端按 RFC 7301
    /// 仍只挑 h2 / http/1.1，握手语义不变。
    pub fn new() -> Self {
        let tls_config = crate::attribution::tls::build_attribution_tls_config();
        Self::with_client(
            reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .use_preconfigured_tls((*tls_config).clone())
                .build()
                .expect("blocking client"),
        )
    }

    /// Construct a capability with a caller-supplied client (used by tests
    /// that need to override timeout / proxy / TLS behaviour).
    pub fn with_client(client: reqwest::blocking::Client) -> Self {
        Self {
            client,
            attribution_signer: None,
            allowed_cidr_policy: None,
        }
    }

    /// Attach an Ed25519 attribution signer (spec §四 L1 强归因).  When set,
    /// every outbound HTTP request that already carries both
    /// `X-Veriguard-Run-Id` and `X-Veriguard-Inject-Id` (从 platform PR #82 注入
    /// `payload.headers`) 会再追加 `X-Veriguard-Timestamp` + `X-Veriguard-Sig`
    /// —— SIEM 抓回后 platform verifier (`Veriguard` PR #83) 用预置公钥验签 → STRONG / 1.00.
    pub fn with_attribution_signer(mut self, signer: Arc<AttributionSigner>) -> Self {
        self.attribution_signer = Some(signer);
        self
    }

    /// Attach an agent-local allowed-CIDR pre-flight policy (招标 §3.5 / §6.1
    /// 硬约束 + 双层 defense in depth；C-2 路线图)。设置后，每次 [`Self::execute`]
    /// 在 `client.request()` 前先用 [`AllowedCidrPolicy::evaluate_url`] 校验 payload.url：
    ///
    /// - `Denied` → 不发包直接返 `failed_result(..)` 含 reason
    /// - `Allowed` / `Deferred` / `Malformed` → 透传放行 (reqwest 自然处理)
    ///
    /// `None` (默认) → 完全跳过校验，保持向后兼容；与 `with_attribution_signer`
    /// 同款 opt-in 模式 (env var `VERIGUARD_TARGET_ALLOWED_CIDR` 未配则 `None`)。
    pub fn with_allowed_cidr_policy(mut self, policy: Arc<AllowedCidrPolicy>) -> Self {
        self.allowed_cidr_policy = Some(policy);
        self
    }
}

impl Default for HttpAttackCapability {
    fn default() -> Self {
        Self::new()
    }
}

/// Wire payload for `http_attack`.
#[derive(Debug, Deserialize)]
struct HttpAttackPayload {
    method: String,
    url: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    body_b64: Option<String>,
    #[serde(default)]
    expected_status_codes: Vec<u16>,
    #[serde(default)]
    expected_body_regex: Option<String>,
}

impl Capability for HttpAttackCapability {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn execute(&self, task: &Task) -> TaskResult {
        let payload: HttpAttackPayload = match serde_json::from_str(&task.payload) {
            Ok(p) => p,
            Err(e) => return failed_result(format!("invalid http_attack payload: {e}")),
        };

        let started_at = rfc3339_now();

        // 招标 §3.5 / §6.1 pre-flight 目标白名单校验（C-2 双层防御 agent 侧；
        // policy 未配 → 跳过；hostname / 解析失败透传, reqwest 自然处理）。
        if let Some(policy) = &self.allowed_cidr_policy {
            if let CidrOutcome::Denied { reason } = policy.evaluate_url(&payload.url) {
                return failed_result(format!(
                    "pre-flight DENIED (招标 §3.5/§6.1 allowed-cidr): {reason}"
                ));
            }
        }

        let method = match payload.method.parse::<reqwest::Method>() {
            Ok(m) => m,
            Err(e) => {
                return failed_result(format!("invalid HTTP method {:?}: {e}", payload.method))
            }
        };

        let mut request = self.client.request(method, &payload.url);
        for (k, v) in &payload.headers {
            request = request.header(k, v);
        }
        // spec §四 L1 强归因 sig 注入：platform PR #82 已把 Run-Id / Inject-Id 注入
        // payload.headers；本 capability 读出后用 Ed25519 priv key 签 → 追加 2 个
        // header (Timestamp + Sig) 到出站 HTTP 请求.
        request = inject_attribution_headers(request, &payload.headers, &self.attribution_signer);

        if let Some(b64) = &payload.body_b64 {
            match B64.decode(b64) {
                Ok(bytes) => request = request.body(bytes),
                Err(e) => return failed_result(format!("body_b64 decode failed: {e}")),
            }
        }

        let resp = match request.send() {
            Ok(r) => r,
            Err(e) => return failed_result(format!("http request failed: {e}")),
        };
        let status = resp.status();
        let body_bytes = resp.bytes().unwrap_or_default();
        let body_text = String::from_utf8_lossy(&body_bytes).into_owned();

        let finished_at = rfc3339_now();

        // Status expectation: only enforced when the list is non-empty.
        if !payload.expected_status_codes.is_empty()
            && !payload.expected_status_codes.contains(&status.as_u16())
        {
            return TaskResult {
                status: "FAILED".to_string(),
                exit_code: status.as_u16() as i32,
                stdout: Some(summary_line(&status, body_text.len())),
                stderr: Some(truncate(&body_text, 4096)),
                started_at: Some(started_at),
                finished_at: Some(finished_at),
                error_message: Some(format!(
                    "status {} not in expected {:?}",
                    status.as_u16(),
                    payload.expected_status_codes
                )),
            };
        }

        // Body regex expectation: only enforced when non-null.
        if let Some(pattern) = &payload.expected_body_regex {
            // Use a tiny hand-rolled "contains" matcher — we don't want to
            // pull in `regex` for one occasional use; the platform's regexes
            // are typically substring matches.  If a real regex shows up,
            // upgrade this branch to use the `regex` crate.
            if !body_text.contains(pattern) {
                return TaskResult {
                    status: "FAILED".to_string(),
                    exit_code: 1,
                    stdout: Some(summary_line(&status, body_text.len())),
                    stderr: Some(truncate(&body_text, 4096)),
                    started_at: Some(started_at),
                    finished_at: Some(finished_at),
                    error_message: Some(format!(
                        "response body did not contain expected pattern {pattern:?}"
                    )),
                };
            }
        }

        TaskResult {
            status: "SUCCESS".to_string(),
            exit_code: 0,
            stdout: Some(summary_line(&status, body_text.len())),
            stderr: None,
            started_at: Some(started_at),
            finished_at: Some(finished_at),
            error_message: None,
        }
    }
}

fn failed_result(message: String) -> TaskResult {
    // Capture timestamp once so started_at == finished_at — the task failed
    // before any real work happened, so two separate now() calls would
    // produce a misleading nanosecond-level "duration" that breaks SLA
    // calculations on the platform side.
    let at = rfc3339_now();
    TaskResult {
        status: "FAILED".to_string(),
        exit_code: 1,
        stdout: None,
        stderr: None,
        started_at: Some(at.clone()),
        finished_at: Some(at),
        error_message: Some(message),
    }
}

fn summary_line(status: &reqwest::StatusCode, body_len: usize) -> String {
    format!("HTTP {} ({} bytes)", status.as_u16(), body_len)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        // Clip at a UTF-8 char boundary to avoid panicking inside reqwest /
        // serde.  s.is_char_boundary(max) lets us walk back.
        let mut cut = max;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}...", &s[..cut])
    }
}

/// Append Veriguard L1 attribution headers (Timestamp + Sig) to the request
/// when the prerequisites are met: signer configured AND payload headers
/// already include both `X-Veriguard-Run-Id` and `X-Veriguard-Inject-Id`
/// (platform PR #82 注入语义).
///
/// 任一缺失 → 透传 request 不动；platform verifier 落 `unsigned` 兼容路径.
/// Header lookup 大小写不敏感（HTTP header 名通常 case-insensitive；
/// payload.headers 来自 JSON map 故按字符串保留原 casing —— 比对时统一 lower）.
fn inject_attribution_headers(
    request: reqwest::blocking::RequestBuilder,
    payload_headers: &HashMap<String, String>,
    signer: &Option<Arc<AttributionSigner>>,
) -> reqwest::blocking::RequestBuilder {
    let Some(signer) = signer.as_ref() else {
        return request;
    };
    let Some(run_id) = lookup_header(payload_headers, HEADER_RUN_ID) else {
        return request;
    };
    let Some(inject_id) = lookup_header(payload_headers, HEADER_INJECT_ID) else {
        return request;
    };
    let epoch_ms = chrono::Utc::now().timestamp_millis();
    let sig_payload = SignaturePayload {
        run_id: &run_id,
        inject_id: &inject_id,
        epoch_ms,
    };
    let sig_b64 = signer.sign_base64(&sig_payload);
    request
        .header(HEADER_TIMESTAMP, epoch_ms.to_string())
        .header(HEADER_SIG, sig_b64)
}

/// Case-insensitive lookup over a JSON-derived header map.
fn lookup_header(headers: &HashMap<String, String>, name: &str) -> Option<String> {
    let target = name.to_ascii_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(&target))
        .map(|(_, v)| v.clone())
}

fn rfc3339_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Hand-roll a minimal RFC 3339 (UTC) without pulling in `chrono`.
    // Format: YYYY-MM-DDTHH:MM:SS.mmmZ
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs() as i64;
    let millis = dur.subsec_millis();
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

/// Convert Unix seconds to (year, month, day, hour, min, sec) in UTC.
/// Derived from Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_unix(secs: i64) -> (i32, u8, u8, u8, u8, u8) {
    let days = secs.div_euclid(86_400);
    let secs_in_day = secs.rem_euclid(86_400) as u32;
    let h = (secs_in_day / 3600) as u8;
    let mi = ((secs_in_day % 3600) / 60) as u8;
    let s = (secs_in_day % 60) as u8;

    // Hinnant: days_from_civil inverse.  Day 0 == 1970-01-01.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let mo = (if mp < 10 { mp + 3 } else { mp - 9 }) as u8;
    let y = (y + if mo <= 2 { 1 } else { 0 }) as i32;
    (y, mo, d, h, mi, s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn task_with_payload(payload_json: &str) -> Task {
        Task {
            task_id: "t1".to_string(),
            capability: "http_attack".to_string(),
            injector_type: "boundary".to_string(),
            payload: payload_json.to_string(),
            expectations: vec![],
        }
    }

    fn build_test_capability() -> HttpAttackCapability {
        // Bypass any HTTP_PROXY set by parallel tests; mockito serves on
        // localhost so proxying through 127.0.0.1:9999 would fail.
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("client");
        HttpAttackCapability::with_client(client)
    }

    #[test]
    fn test_http_attack_success_on_expected_status() {
        let mut server = Server::new();
        let m = server
            .mock("GET", "/probe")
            .with_status(200)
            .with_body("ok body")
            .create();

        let payload = serde_json::json!({
            "method": "GET",
            "url": format!("{}/probe", server.url()),
            "expected_status_codes": [200],
        });
        let cap = build_test_capability();
        let result = cap.execute(&task_with_payload(&payload.to_string()));

        m.assert();
        assert_eq!(result.status, "SUCCESS");
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.error_message, None);
    }

    #[test]
    fn test_http_attack_fail_on_unexpected_status() {
        let mut server = Server::new();
        server.mock("GET", "/probe").with_status(500).create();

        let payload = serde_json::json!({
            "method": "GET",
            "url": format!("{}/probe", server.url()),
            "expected_status_codes": [200],
        });
        let result = build_test_capability().execute(&task_with_payload(&payload.to_string()));

        assert_eq!(result.status, "FAILED");
        assert!(result.error_message.unwrap().contains("status 500"));
    }

    #[test]
    fn test_http_attack_includes_request_headers() {
        let mut server = Server::new();
        let m = server
            .mock("POST", "/probe")
            .match_header("X-Veriguard-Probe", "yes")
            .with_status(204)
            .create();

        let payload = serde_json::json!({
            "method": "POST",
            "url": format!("{}/probe", server.url()),
            "headers": { "X-Veriguard-Probe": "yes" },
            "expected_status_codes": [204],
        });
        let result = build_test_capability().execute(&task_with_payload(&payload.to_string()));
        m.assert();
        assert_eq!(result.status, "SUCCESS");
    }

    #[test]
    fn test_http_attack_sends_body_when_provided() {
        let mut server = Server::new();
        let m = server
            .mock("POST", "/probe")
            .match_body(mockito::Matcher::Exact("hello".to_string()))
            .with_status(200)
            .create();

        let payload = serde_json::json!({
            "method": "POST",
            "url": format!("{}/probe", server.url()),
            "body_b64": B64.encode("hello"),
            "expected_status_codes": [200],
        });
        let result = build_test_capability().execute(&task_with_payload(&payload.to_string()));
        m.assert();
        assert_eq!(result.status, "SUCCESS");
    }

    #[test]
    fn test_http_attack_fail_on_body_regex_miss() {
        let mut server = Server::new();
        server
            .mock("GET", "/probe")
            .with_status(200)
            .with_body("nothing relevant here")
            .create();

        let payload = serde_json::json!({
            "method": "GET",
            "url": format!("{}/probe", server.url()),
            "expected_status_codes": [200],
            "expected_body_regex": "MUST_BE_PRESENT",
        });
        let result = build_test_capability().execute(&task_with_payload(&payload.to_string()));
        assert_eq!(result.status, "FAILED");
        assert!(result
            .error_message
            .as_ref()
            .unwrap()
            .contains("expected pattern"));
    }

    #[test]
    fn test_http_attack_fail_on_invalid_payload() {
        let result = build_test_capability().execute(&task_with_payload("{ not json"));
        assert_eq!(result.status, "FAILED");
        assert!(result
            .error_message
            .as_ref()
            .unwrap()
            .contains("invalid http_attack payload"));
    }

    #[test]
    fn test_http_attack_fail_on_invalid_method() {
        let payload = serde_json::json!({
            "method": "🍞 INVALID",
            "url": "http://example.com",
            "expected_status_codes": [200],
        });
        let result = build_test_capability().execute(&task_with_payload(&payload.to_string()));
        assert_eq!(result.status, "FAILED");
        assert!(result
            .error_message
            .as_ref()
            .unwrap()
            .contains("invalid HTTP method"));
    }

    #[test]
    fn test_failed_result_started_and_finished_match() {
        // Pin the single-timestamp contract: a task that fails before doing
        // any work must report started_at == finished_at (zero duration),
        // not two nanosecond-apart timestamps from separate rfc3339_now()
        // calls.
        let r = failed_result("boom".to_string());
        assert!(r.started_at.is_some());
        assert!(r.finished_at.is_some());
        assert_eq!(
            r.started_at, r.finished_at,
            "failed_result must use a single timestamp"
        );
    }

    #[test]
    fn test_civil_from_unix_known_dates() {
        // 1970-01-01 00:00:00
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        // 2000-01-01 00:00:00 (946684800 seconds)
        assert_eq!(civil_from_unix(946_684_800), (2000, 1, 1, 0, 0, 0));
        // 2026-05-15 10:30:00 UTC = 1778841000
        assert_eq!(civil_from_unix(1_778_841_000), (2026, 5, 15, 10, 30, 0));
    }

    #[test]
    fn test_rfc3339_now_basic_shape() {
        let s = rfc3339_now();
        // YYYY-MM-DDTHH:MM:SS.mmmZ — 24 chars.
        assert_eq!(s.len(), 24, "{s}");
        assert!(s.ends_with('Z'));
        assert!(&s[4..5] == "-");
    }

    // ---- spec §四 L1 强归因 sig 注入 e2e ----

    fn rfc8032_test1_seed_b64() -> String {
        let hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        B64.encode(&bytes)
    }

    #[test]
    fn test_http_attack_attaches_sig_when_signer_and_ids_present() {
        let mut server = Server::new();
        // mockito `match_header(name, Matcher::Regex(...))` 断言出站请求的
        // X-Veriguard-Sig / X-Veriguard-Timestamp 真注入.
        let m = server
            .mock("GET", "/probe")
            .match_header("X-Veriguard-Run-Id", "RUN-1")
            .match_header("X-Veriguard-Inject-Id", "INJ-1")
            .match_header(
                "X-Veriguard-Timestamp",
                mockito::Matcher::Regex(r"^\d+$".to_string()),
            )
            .match_header(
                "X-Veriguard-Sig",
                mockito::Matcher::Regex(r"^[A-Za-z0-9+/]{86,88}={0,2}$".to_string()),
            )
            .with_status(200)
            .create();

        let signer = Arc::new(AttributionSigner::from_base64(&rfc8032_test1_seed_b64()).unwrap());
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("client");
        let cap = HttpAttackCapability::with_client(client).with_attribution_signer(signer);

        let payload = serde_json::json!({
            "method": "GET",
            "url": format!("{}/probe", server.url()),
            "headers": {
                "X-Veriguard-Run-Id": "RUN-1",
                "X-Veriguard-Inject-Id": "INJ-1",
            },
            "expected_status_codes": [200],
        });
        let result = cap.execute(&task_with_payload(&payload.to_string()));
        m.assert();
        assert_eq!(result.status, "SUCCESS");
    }

    #[test]
    fn test_http_attack_skips_sig_when_signer_absent() {
        // 没配 signer → 不注 Timestamp / Sig（兼容旧栈；platform 落 `unsigned`）.
        let mut server = Server::new();
        let m = server
            .mock("GET", "/probe")
            .match_header("X-Veriguard-Run-Id", "RUN-1")
            .match_header("X-Veriguard-Sig", mockito::Matcher::Missing)
            .match_header("X-Veriguard-Timestamp", mockito::Matcher::Missing)
            .with_status(200)
            .create();

        let cap = build_test_capability(); // 无 signer
        let payload = serde_json::json!({
            "method": "GET",
            "url": format!("{}/probe", server.url()),
            "headers": { "X-Veriguard-Run-Id": "RUN-1", "X-Veriguard-Inject-Id": "INJ-1" },
            "expected_status_codes": [200],
        });
        let result = cap.execute(&task_with_payload(&payload.to_string()));
        m.assert();
        assert_eq!(result.status, "SUCCESS");
    }

    #[test]
    fn test_http_attack_skips_sig_when_no_run_id_header() {
        // 有 signer 但 payload.headers 没 Run-Id → 不注 Sig（兼容旧 platform 未升级场景）.
        let mut server = Server::new();
        let m = server
            .mock("GET", "/probe")
            .match_header("X-Veriguard-Sig", mockito::Matcher::Missing)
            .with_status(200)
            .create();

        let signer = Arc::new(AttributionSigner::from_base64(&rfc8032_test1_seed_b64()).unwrap());
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("client");
        let cap = HttpAttackCapability::with_client(client).with_attribution_signer(signer);

        let payload = serde_json::json!({
            "method": "GET",
            "url": format!("{}/probe", server.url()),
            "headers": {}, // 故意空 —— platform 没注 X-Veriguard-* 三件套
            "expected_status_codes": [200],
        });
        let result = cap.execute(&task_with_payload(&payload.to_string()));
        m.assert();
        assert_eq!(result.status, "SUCCESS");
    }

    // ---- C-2 allowed-cidr pre-flight (招标 §3.5 / §6.1 双层防御 agent 侧) ----

    fn build_cap_with_cidr(cidr_csv: &str) -> HttpAttackCapability {
        let policy =
            Arc::new(AllowedCidrPolicy::from_csv(cidr_csv).expect("test CIDR fixture parses"));
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("client");
        HttpAttackCapability::with_client(client).with_allowed_cidr_policy(policy)
    }

    #[test]
    fn preflight_denied_url_blocks_send() {
        // Whitelist 仅含 10.0.0.0/24 文档保留前缀; mockito 起在 127.0.0.1 → 不命中.
        // 断言：mock.expect(0) 证实 capability **未发出 HTTP 请求**,
        // result.status=FAILED 含 pre-flight DENIED reason.
        let mut server = Server::new();
        let m = server
            .mock("GET", "/should-not-hit")
            .with_status(200)
            .expect(0)
            .create();

        let payload = serde_json::json!({
            "method": "GET",
            "url": format!("{}/should-not-hit", server.url()),
            "expected_status_codes": [200],
        });
        let cap = build_cap_with_cidr("10.0.0.0/24");
        let result = cap.execute(&task_with_payload(&payload.to_string()));

        m.assert();
        assert_eq!(result.status, "FAILED");
        let msg = result.error_message.unwrap();
        assert!(
            msg.contains("pre-flight DENIED"),
            "msg should signal pre-flight: {msg}"
        );
        assert!(
            msg.contains("招标 §3.5/§6.1"),
            "msg should cite spec section: {msg}"
        );
    }

    #[test]
    fn preflight_allowed_url_proceeds() {
        // Whitelist 含 127.0.0.0/8 → mockito 的 127.0.0.1 端点命中, 请求正常发.
        let mut server = Server::new();
        let m = server.mock("GET", "/probe").with_status(200).create();

        let payload = serde_json::json!({
            "method": "GET",
            "url": format!("{}/probe", server.url()),
            "expected_status_codes": [200],
        });
        let cap = build_cap_with_cidr("127.0.0.0/8");
        let result = cap.execute(&task_with_payload(&payload.to_string()));

        m.assert();
        assert_eq!(result.status, "SUCCESS");
    }

    #[test]
    fn preflight_hostname_deferred_proceeds() {
        // mockito server.url() 默认形如 http://127.0.0.1:PORT; 显式改用 localhost
        // (hostname) → policy 返 Deferred → 透传, reqwest 自行解析后发包.
        let mut server = Server::new();
        let m = server.mock("GET", "/probe").with_status(200).create();
        let url = server.url().replace("127.0.0.1", "localhost");

        let payload = serde_json::json!({
            "method": "GET",
            "url": format!("{}/probe", url),
            "expected_status_codes": [200],
        });
        // CIDR 故意不含 127.0.0.0/8 —— 验证 Deferred (hostname) 不被 Denied 卡.
        let cap = build_cap_with_cidr("10.0.0.0/24");
        let result = cap.execute(&task_with_payload(&payload.to_string()));

        m.assert();
        assert_eq!(result.status, "SUCCESS");
    }

    #[test]
    fn preflight_no_policy_is_noop() {
        // 默认 capability (policy=None) → 不做任何 pre-flight, 与未引入本特性的旧行为完全一致.
        let mut server = Server::new();
        let m = server.mock("GET", "/probe").with_status(200).create();

        let payload = serde_json::json!({
            "method": "GET",
            "url": format!("{}/probe", server.url()),
            "expected_status_codes": [200],
        });
        let cap = build_test_capability(); // 无 policy
        let result = cap.execute(&task_with_payload(&payload.to_string()));

        m.assert();
        assert_eq!(result.status, "SUCCESS");
    }
}
