//! Mode A HTTPS poll loop.
//!
//! The poller is a single-threaded blocking loop that calls
//! `GET /api/agent/poll?agent_id=<id>`, dispatches the returned tasks to a
//! [`TaskDispatcher`], and POSTs each result back via
//! `POST /api/agent/task/{task_id}/result?agent_id=<id>`.
//!
//! ## Lifecycle
//!
//! 1.  Sleep `poll_interval` (default 5s).
//! 2.  Fetch tasks; on transport error or 5xx, increment backoff and retry.
//! 3.  For each task, call dispatcher → result → POST result.
//! 4.  Reset backoff after one successful fetch.
//!
//! ## Backoff
//!
//! Exponential, doubling each failed attempt up to [`Poller::max_backoff`].
//! Reset to [`Poller::poll_interval`] on the first successful fetch.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::ed25519::Ed25519PrivateKey;

use super::sign::{build_canonical_result_bytes, sign_get, sign_post};

/// A task fetched from `GET /api/agent/poll`.
///
/// Wire shape mirrors `AgentDtos.AgentTask`:
/// `{ task_id, capability, injector_type, payload, expectations }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    /// Server-issued task identifier — echoed verbatim in the result POST URL.
    pub task_id: String,
    /// Capability name to dispatch this task through (e.g. `"http_attack"`).
    pub capability: String,
    /// Injector type identifier (subtype routing inside a capability).
    pub injector_type: String,
    /// JSON payload as a raw string — the capability is responsible for
    /// parsing.  Using a string (rather than `serde_json::Value`) preserves
    /// the platform's exact bytes, which is useful for debugging.
    pub payload: String,
    /// Optional set of platform-supplied expectation IDs.
    #[serde(default)]
    pub expectations: Vec<String>,
}

/// Result of executing a [`Task`], shipped back via
/// `POST /api/agent/task/{task_id}/result`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskResult {
    /// Free-form status string; convention is `"SUCCESS"` / `"FAILED"` /
    /// `"TIMEOUT"`.
    pub status: String,
    /// Process exit code (or a logical equivalent for non-process work).
    pub exit_code: i32,
    /// Captured stdout, if any.
    pub stdout: Option<String>,
    /// Captured stderr, if any.
    pub stderr: Option<String>,
    /// RFC 3339 start timestamp, if available.
    pub started_at: Option<String>,
    /// RFC 3339 finish timestamp, if available.
    pub finished_at: Option<String>,
    /// Operator-readable error message; carried separately from `stderr` so
    /// the platform can route on it without parsing logs.
    pub error_message: Option<String>,
}

/// A `Capability` dispatcher used by the poll loop.
pub trait TaskDispatcher: Send + Sync {
    /// Execute `task` and return a [`TaskResult`].  Implementations must not
    /// panic; failures should be returned as `TaskResult { status: "FAILED",
    /// ... }`.
    fn execute(&self, task: &Task) -> TaskResult;
}

/// Errors raised by the poll loop.
#[derive(Debug, Error)]
pub enum PollError {
    /// HTTP transport failure.
    #[error("HTTP transport: {0}")]
    Http(#[from] reqwest::Error),
    /// Server returned a non-2xx response we cannot recover from.
    #[error("HTTP status {status} from {endpoint}: {body}")]
    BadStatus {
        /// HTTP method + path of the failing call.
        endpoint: String,
        /// HTTP status code returned.
        status: u16,
        /// Truncated response body for context.
        body: String,
    },
    /// Server returned 2xx but the body did not parse as JSON.
    #[error("JSON decode failed at {endpoint}: {source}")]
    Json {
        /// HTTP method + path that returned the malformed body.
        endpoint: String,
        /// Underlying serde error.
        #[source]
        source: serde_json::Error,
    },
}

/// Mode A HTTPS poller.
///
/// One [`Poller`] = one agent identity = one polling loop.  The poller is
/// blocking; spawn it on a dedicated thread if you need to run other work
/// concurrently.
pub struct Poller {
    /// HTTPS base URL of the Veriguard platform (no trailing slash).
    pub platform_url: String,
    /// Agent UUID issued at onboarding.
    pub agent_id: String,
    /// 64-hex single-use onboard token (current inverse-index design;
    /// will be replaced by `agent_id` lookup in C1-Platform-3).
    pub onboard_token: String,
    /// Capabilities this agent advertises (sent as a query parameter; the
    /// platform may use this to filter pending tasks).
    pub capabilities: Vec<String>,
    /// Private Ed25519 key used to sign every request.
    pub sign_priv: Ed25519PrivateKey,
    /// Blocking HTTP client (constructed via [`super::proxy::http_client_with_proxy_env`]).
    pub http_client: reqwest::blocking::Client,
    /// Interval between consecutive successful poll attempts (default 5s).
    pub poll_interval: Duration,
    /// Upper bound on exponential backoff after transport errors.
    pub max_backoff: Duration,
    /// Cooperative stop flag — when `true`, the next iteration exits the loop.
    pub stop: Arc<AtomicBool>,
}

/// Wire shape of the poll response — must mirror `AgentDtos.PollOutput`.
#[derive(Debug, Deserialize)]
struct PollOutput {
    tasks: Vec<Task>,
}

impl Poller {
    /// Default poll interval (5s).
    #[allow(dead_code)]
    pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);
    /// Default upper bound on backoff (5min).
    #[allow(dead_code)]
    pub const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(300);

    /// Run the poll loop until `self.stop` is set.
    ///
    /// Returns `Ok(())` on cooperative shutdown.  Most transport errors are
    /// logged and retried with exponential backoff; only programmer errors
    /// (e.g. malformed [`Self::platform_url`]) cause an early return.
    pub fn run<D: TaskDispatcher>(&self, dispatcher: &D) -> Result<(), PollError> {
        let mut current_backoff = self.poll_interval;
        while !self.stop.load(Ordering::SeqCst) {
            sleep(current_backoff);
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            match self.fetch_tasks() {
                Ok(tasks) => {
                    // Successful fetch — reset backoff.
                    current_backoff = self.poll_interval;
                    debug!("fetched {} task(s) from platform", tasks.len());
                    for task in &tasks {
                        let result = dispatcher.execute(task);
                        if let Err(err) = self.post_result(&task.task_id, &result) {
                            warn!("failed to POST result for {}: {err}", task.task_id);
                        }
                    }
                }
                Err(err) => {
                    warn!("poll fetch failed: {err}");
                    current_backoff = (current_backoff * 2).min(self.max_backoff);
                }
            }
        }
        info!("poll loop stopped cooperatively");
        Ok(())
    }

    /// Issue a single signed `GET /api/agent/poll` and return the tasks.
    pub fn fetch_tasks(&self) -> Result<Vec<Task>, PollError> {
        let url = self.poll_url();
        let signed = sign_get(&self.sign_priv, &self.onboard_token);
        let mut builder = self.http_client.get(&url);
        for (k, v) in &signed.headers {
            builder = builder.header(k, v);
        }
        let resp = builder.send()?;
        let status = resp.status();
        if !status.is_success() {
            return Err(PollError::BadStatus {
                endpoint: format!("GET {url}"),
                status: status.as_u16(),
                body: truncate(&resp.text().unwrap_or_default(), 256),
            });
        }
        let body = resp.text()?;
        let parsed: PollOutput = serde_json::from_str(&body).map_err(|source| PollError::Json {
            endpoint: format!("GET {url}"),
            source,
        })?;
        Ok(parsed.tasks)
    }

    /// Issue a single signed `POST /api/agent/task/{task_id}/result`.
    pub fn post_result(&self, task_id: &str, result: &TaskResult) -> Result<(), PollError> {
        let canonical = build_canonical_result_bytes(result, task_id);
        let signed = sign_post(&canonical, &self.sign_priv, &self.onboard_token);
        let url = self.result_url(task_id);

        // The HTTP body shipped to the platform is the canonical JSON form so
        // that the platform's `canonicalResultBytes` reconstruction is a no-op
        // (and any future ContentCachingRequestWrapper switch will see the
        // same bytes we signed).
        let body = canonical;

        let mut builder = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body);
        for (k, v) in &signed.headers {
            builder = builder.header(k, v);
        }
        let resp = builder.send()?;
        let status = resp.status();
        if !status.is_success() {
            return Err(PollError::BadStatus {
                endpoint: format!("POST {url}"),
                status: status.as_u16(),
                body: truncate(&resp.text().unwrap_or_default(), 256),
            });
        }
        Ok(())
    }

    fn poll_url(&self) -> String {
        // Capabilities are joined comma-separated; this matches the platform's
        // expected query format.  If empty, omit the parameter to keep the
        // URL clean (a no-capability agent is valid).
        let base = format!(
            "{}/api/agent/poll?agent_id={}",
            self.platform_url.trim_end_matches('/'),
            url_escape(&self.agent_id)
        );
        if self.capabilities.is_empty() {
            base
        } else {
            format!(
                "{}&capabilities={}",
                base,
                url_escape(&self.capabilities.join(","))
            )
        }
    }

    fn result_url(&self, task_id: &str) -> String {
        format!(
            "{}/api/agent/task/{}/result?agent_id={}",
            self.platform_url.trim_end_matches('/'),
            url_escape(task_id),
            url_escape(&self.agent_id),
        )
    }
}

/// Minimal URL-component escaper.  Covers what we need (UUIDs, comma-separated
/// alnum lists) without pulling in `urlencoding`.
fn url_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' | ',' => c.to_string(),
            other => {
                let mut buf = [0u8; 4];
                let bytes = other.encode_utf8(&mut buf).as_bytes();
                bytes
                    .iter()
                    .map(|b| format!("%{b:02X}"))
                    .collect::<String>()
            }
        })
        .collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::generate_ed25519;
    use mockito::Server;
    use std::sync::Mutex;

    /// Build a `blocking::Client` that explicitly bypasses any proxy in the
    /// environment.  The upstream test
    /// `tests::api::client::tests::test_with_proxy_disables_http_proxy`
    /// mutates `HTTP_PROXY` mid-suite, which would otherwise route our
    /// mockito requests off to a non-existent proxy host.  Using `no_proxy`
    /// keeps these tests deterministic when run in parallel with that test.
    fn no_proxy_client() -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("blocking client")
    }

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// In-test dispatcher: returns canned results and records every task it sees.
    struct RecordingDispatcher {
        seen: Mutex<Vec<Task>>,
        canned: Mutex<Vec<TaskResult>>, // pop_front from start
    }

    impl RecordingDispatcher {
        fn new(canned: Vec<TaskResult>) -> Self {
            Self {
                seen: Mutex::new(Vec::new()),
                canned: Mutex::new(canned),
            }
        }
    }

    impl TaskDispatcher for RecordingDispatcher {
        fn execute(&self, task: &Task) -> TaskResult {
            self.seen.lock().unwrap().push(task.clone());
            let mut q = self.canned.lock().unwrap();
            if q.is_empty() {
                TaskResult {
                    status: "SUCCESS".to_string(),
                    exit_code: 0,
                    stdout: None,
                    stderr: None,
                    started_at: None,
                    finished_at: None,
                    error_message: None,
                }
            } else {
                q.remove(0)
            }
        }
    }

    fn poller_for(server: &Server, stop_after: usize) -> (Poller, Arc<AtomicBool>) {
        // stop_after iterations are arranged by the test mocks; we expose
        // the flag so the test can flip it from within the dispatcher.
        let stop = Arc::new(AtomicBool::new(false));
        let p = Poller {
            platform_url: server.url(),
            agent_id: "agent-test".to_string(),
            onboard_token: TOKEN.to_string(),
            capabilities: vec!["http_attack".to_string()],
            sign_priv: generate_ed25519(),
            http_client: no_proxy_client(),
            poll_interval: Duration::from_millis(1),
            max_backoff: Duration::from_millis(8),
            stop: stop.clone(),
        };
        let _ = stop_after;
        (p, stop)
    }

    #[test]
    fn test_poll_fetches_and_executes_tasks() {
        let mut server = Server::new();
        let poll_mock = server
            .mock("GET", mockito::Matcher::Regex(r"^/api/agent/poll.*".to_string()))
            .match_header("X-Veriguard-Signature", mockito::Matcher::Any)
            .match_header("X-Veriguard-Timestamp", mockito::Matcher::Any)
            .match_header("X-Veriguard-Onboard-Token", TOKEN)
            .with_status(200)
            .with_body(
                r#"{"tasks":[{"task_id":"t1","capability":"http_attack","injector_type":"x","payload":"{}","expectations":[]}]}"#,
            )
            .create();
        let result_mock = server
            .mock("POST", "/api/agent/task/t1/result?agent_id=agent-test")
            .match_header("X-Veriguard-Signature", mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{"status":"accepted"}"#)
            .create();

        let (poller, stop) = poller_for(&server, 1);
        let dispatcher = RecordingDispatcher::new(vec![TaskResult {
            status: "SUCCESS".to_string(),
            exit_code: 0,
            stdout: Some("ok".to_string()),
            stderr: None,
            started_at: None,
            finished_at: None,
            error_message: None,
        }]);

        // Single fetch path: call fetch_tasks + post_result directly so we
        // don't depend on loop timing.
        let tasks = poller.fetch_tasks().expect("fetch");
        assert_eq!(tasks.len(), 1);
        let result = dispatcher.execute(&tasks[0]);
        poller
            .post_result(&tasks[0].task_id, &result)
            .expect("post");

        // Set the stop flag so a future test can reuse this poller in a loop.
        stop.store(true, Ordering::SeqCst);

        poll_mock.assert();
        result_mock.assert();
        assert_eq!(dispatcher.seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_poll_signature_header_present_on_every_request() {
        let mut server = Server::new();
        let m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/agent/poll.*".to_string()),
            )
            .match_header("X-Veriguard-Signature", mockito::Matcher::Any)
            .match_header("X-Veriguard-Timestamp", mockito::Matcher::Any)
            .match_header("X-Veriguard-Onboard-Token", TOKEN)
            .with_status(200)
            .with_body(r#"{"tasks":[]}"#)
            .create();

        let (poller, _) = poller_for(&server, 1);
        poller.fetch_tasks().expect("ok");
        m.assert();
    }

    #[test]
    fn test_poll_returns_bad_status_on_5xx() {
        let mut server = Server::new();
        server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/agent/poll.*".to_string()),
            )
            .with_status(503)
            .with_body("temporarily unavailable")
            .create();

        let (poller, _) = poller_for(&server, 1);
        let err = poller.fetch_tasks().expect_err("must surface 503");
        match err {
            PollError::BadStatus { status, .. } => assert_eq!(status, 503),
            other => panic!("expected BadStatus, got {other:?}"),
        }
    }

    #[test]
    fn test_poll_run_exits_on_stop_flag() {
        // Spin up a server that always 200s with empty tasks, then ask the
        // poller to run; flip the stop flag after the first call so the loop
        // exits in deterministic time.
        let mut server = Server::new();
        server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/agent/poll.*".to_string()),
            )
            .with_status(200)
            .with_body(r#"{"tasks":[]}"#)
            .expect_at_least(0)
            .create();

        let (poller, stop) = poller_for(&server, 1);
        // Pre-set stop so the loop exits after at most one iteration.
        stop.store(true, Ordering::SeqCst);

        let dispatcher = RecordingDispatcher::new(vec![]);
        poller.run(&dispatcher).expect("run exits cleanly");
    }

    #[test]
    fn test_poll_url_includes_capabilities() {
        let stop = Arc::new(AtomicBool::new(false));
        let p = Poller {
            platform_url: "https://example.com".to_string(),
            agent_id: "a-1".to_string(),
            onboard_token: TOKEN.to_string(),
            capabilities: vec!["http_attack".to_string(), "pcap_replay".to_string()],
            sign_priv: generate_ed25519(),
            http_client: no_proxy_client(),
            poll_interval: Duration::from_millis(1),
            max_backoff: Duration::from_millis(1),
            stop,
        };
        let url = p.poll_url();
        assert!(
            url.contains("capabilities=http_attack%2Cpcap_replay")
                || url.contains("capabilities=http_attack,pcap_replay"),
            "unexpected URL: {url}"
        );
        assert!(url.contains("agent_id=a-1"), "{url}");
    }

    #[test]
    fn test_poll_url_omits_capabilities_when_empty() {
        let stop = Arc::new(AtomicBool::new(false));
        let p = Poller {
            platform_url: "https://example.com".to_string(),
            agent_id: "a-1".to_string(),
            onboard_token: TOKEN.to_string(),
            capabilities: vec![],
            sign_priv: generate_ed25519(),
            http_client: no_proxy_client(),
            poll_interval: Duration::from_millis(1),
            max_backoff: Duration::from_millis(1),
            stop,
        };
        let url = p.poll_url();
        assert!(!url.contains("capabilities"), "{url}");
    }

    #[test]
    fn test_truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 256), "hello");
    }

    #[test]
    fn test_truncate_long_string_clipped_with_ellipsis() {
        let big = "x".repeat(500);
        let t = truncate(&big, 10);
        assert_eq!(t.len(), 13, "10 chars + '...': {t}");
        assert!(t.ends_with("..."));
    }
}
