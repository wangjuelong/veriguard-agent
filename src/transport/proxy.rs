//! HTTPS_PROXY environment-variable awareness for the Mode A poll client.
//!
//! Stub for now — full implementation lands in task A.4.3.

use std::time::Duration;

/// Build a `reqwest::blocking::Client` that respects `HTTPS_PROXY` /
/// `https_proxy` if set, otherwise falls back to the system default.
///
/// Implemented in task A.4.3.
pub fn http_client_with_proxy_env() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("default blocking client must build")
}
