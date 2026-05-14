//! Mode A HTTPS transport — poll loop, request signing, proxy support.
//!
//! See spec §3.5.1 Mode A.  This module wires the Veriguard agent's online
//! polling flow:
//!
//! 1.  [`sign`] — build the three `X-Veriguard-*` headers each platform
//!     request must carry.
//! 2.  [`poll`] — the main loop that calls `GET /api/agent/poll`, dispatches
//!     returned tasks through a [`TaskDispatcher`] trait, and POSTs results
//!     back.
//! 3.  [`proxy`] — `HTTPS_PROXY` / `https_proxy` env var awareness for the
//!     `reqwest::blocking::Client` used by the poller.
//!
//! ## Wire contract — IMPORTANT
//!
//! Mirrored byte-for-byte from
//! `io.veriguard.rest.agent.AgentTaskQueueApi`:
//!
//! * The Ed25519 signature input is `utf8(timestamp_millis_decimal) || rawBody`
//!   where `rawBody` is empty for GET.  Timestamp is **Unix epoch
//!   milliseconds** as a decimal ASCII string (e.g. `"1715688000000"`) — NOT
//!   RFC 3339.
//! * Headers are exactly:
//!     * `X-Veriguard-Signature`     base64 standard alphabet of the 64-byte sig
//!     * `X-Veriguard-Timestamp`     decimal Unix epoch millis
//!     * `X-Veriguard-Onboard-Token` the 64-hex onboard token
//! * Result POST body is canonical JSON over the 8 fields
//!   {`error_message`, `exit_code`, `finished_at`, `started_at`, `status`,
//!   `stderr`, `stdout`, `task_id`} sorted alphabetically, no whitespace.
//!   Null body fields are coerced to empty strings.

pub mod poll;
pub mod proxy;
pub mod sign;

#[allow(unused_imports)]
pub use poll::{PollError, Poller, Task, TaskDispatcher, TaskResult};
#[allow(unused_imports)]
pub use proxy::http_client_with_proxy_env;
#[allow(unused_imports)]
pub use sign::{
    build_canonical_result_bytes, sign_get, sign_post, SignedRequest, SIG_HEADER, TOKEN_HEADER,
    TS_HEADER,
};
