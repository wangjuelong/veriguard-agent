//! `HTTPS_PROXY` / `https_proxy` environment-variable awareness.
//!
//! `reqwest` already honours the standard proxy env vars by default; this
//! module exists so that callers (the poll loop, the implant manager) get a
//! single canonical place to construct a `blocking::Client` with the
//! Veriguard-agent defaults — proxy from env, a 30s timeout, and a stable
//! User-Agent.
//!
//! ## Tests + env mutation
//!
//! The upstream `tests::api::client::tests::test_with_proxy_disables_http_proxy`
//! mutates `HTTP_PROXY` without a lock.  To avoid racing it on a parallel
//! test runner, the implementation factors the proxy-URL lookup out into a
//! closure (see [`build_http_client`]) and the in-module unit tests inject
//! a fixed value instead of touching process-global env vars.
use std::env;
use std::time::Duration;

/// Default HTTP request timeout for Mode A traffic.
pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Veriguard agent User-Agent header.
pub const USER_AGENT: &str = concat!("veriguard-agent/", env!("CARGO_PKG_VERSION"));

/// Build a `reqwest::blocking::Client` that:
///
/// * Reads `HTTPS_PROXY` / `https_proxy` (and `HTTP_PROXY` / `http_proxy`)
///   from the environment.  If either is present, the resulting client
///   tunnels through that proxy; otherwise the proxy chain is explicitly
///   disabled so the client cannot inherit a stray system setting.
/// * Applies the [`DEFAULT_HTTP_TIMEOUT`] connect+read timeout.
/// * Sets a stable [`USER_AGENT`] header so platform logs can correlate
///   agent traffic.
///
/// Returns the constructed client.  Panics on programmer-level errors (an
/// invalid proxy URL surfaces here so the operator sees it at startup).
pub fn http_client_with_proxy_env() -> reqwest::blocking::Client {
    build_http_client(&|| read_proxy_env())
}

/// Returns the first defined proxy URL from `HTTPS_PROXY` / `https_proxy` /
/// `HTTP_PROXY` / `http_proxy`, or `None` if none are set.  Used by both
/// [`http_client_with_proxy_env`] and the poll-loop / implant-manager
/// startup log.
pub fn read_proxy_env() -> Option<String> {
    for var in PROXY_ENV_VARS {
        if let Ok(v) = env::var(var) {
            if !v.trim().is_empty() {
                return Some(v);
            }
        }
    }
    None
}

const PROXY_ENV_VARS: &[&str] = &["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];

/// Internal builder accepting an injected proxy-URL lookup closure.  Factored
/// out so tests can pass a fixed value without mutating process-global env
/// vars (which would race with the upstream proxy test).
fn build_http_client(proxy_lookup: &dyn Fn() -> Option<String>) -> reqwest::blocking::Client {
    let builder = reqwest::blocking::Client::builder()
        .timeout(DEFAULT_HTTP_TIMEOUT)
        .user_agent(USER_AGENT);

    let builder = if let Some(proxy_url) = proxy_lookup() {
        match reqwest::Proxy::all(&proxy_url) {
            Ok(p) => builder.proxy(p),
            Err(e) => {
                // Treat a malformed proxy URL as an operator error — fail
                // loud at startup rather than silently disable the proxy.
                panic!("invalid proxy URL {proxy_url:?}: {e}");
            }
        }
    } else {
        builder.no_proxy()
    };

    builder.build().expect("blocking client must build")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_returns_client_without_proxy_lookup() {
        // No env mutation; pass a closure that always returns None.
        let _client = build_http_client(&|| None);
    }

    #[test]
    fn test_build_returns_client_with_https_proxy() {
        // We don't actually hit the proxy — we just confirm the builder
        // accepts a valid proxy URL without panicking.
        let _client = build_http_client(&|| Some("http://proxy.example.com:3128".to_string()));
    }

    #[test]
    #[should_panic(expected = "invalid proxy URL")]
    fn test_build_panics_on_malformed_proxy_url() {
        let _client = build_http_client(&|| Some("not a url at all".to_string()));
    }

    #[test]
    fn test_user_agent_contains_crate_version() {
        // The constant must include the package version; if Cargo.toml's
        // version bumps, this asserts the User-Agent moves with it.
        assert!(USER_AGENT.starts_with("veriguard-agent/"));
        assert_eq!(
            USER_AGENT,
            format!("veriguard-agent/{}", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn test_http_client_with_proxy_env_returns_client() {
        // Smoke test — does not assert behaviour around env vars (those are
        // process-global and would race with parallel tests).
        let _client = http_client_with_proxy_env();
    }
}
