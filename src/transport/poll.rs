//! Mode A HTTPS poll loop and shared wire types.
//!
//! Stub for now — full HTTPS poll + dispatch + backoff land in task A.4.2.
//! The [`Task`] and [`TaskResult`] structs are pinned here because they are
//! shared by [`super::sign`] (canonical-bytes builder) and the eventual
//! [`TaskDispatcher`] trait.

use serde::{Deserialize, Serialize};
use thiserror::Error;

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
    pub expectations: Vec<String>,
}

/// Result of executing a [`Task`], shipped back via
/// `POST /api/agent/task/{task_id}/result`.
///
/// Field naming uses `snake_case` to match the Java DTO
/// (`AgentDtos.ResultInput`) — `serde` is configured per-field rather than
/// via a struct-level rename to keep the field names visible inline.
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
///
/// The trait is intentionally generic over a single `execute` call so the
/// concrete implementation (`capabilities::Registry`) can route on
/// `task.capability` without the poller knowing which capability it is.
pub trait TaskDispatcher: Send + Sync {
    /// Execute `task` and return a [`TaskResult`].  Implementations must not
    /// panic; failures should be returned as `TaskResult { status: "FAILED",
    /// ... }`.
    fn execute(&self, task: &Task) -> TaskResult;
}

/// Errors raised by the poll loop.  Full variants land with the A.4.2
/// implementation.
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
