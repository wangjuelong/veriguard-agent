//! Implant subprocess manager stub.  Full implementation lands in A.6.2.

use std::path::PathBuf;
use thiserror::Error;

use crate::transport::poll::TaskResult;

/// Errors raised while running a veriguard-implant subprocess.
#[derive(Debug, Error)]
pub enum ImplantError {
    /// Underlying I/O failure (network, FS, subprocess spawn).
    #[error("implant I/O: {0}")]
    Io(#[from] std::io::Error),
    /// The platform returned a non-2xx response when the agent tried to
    /// download the implant binary.
    #[error("implant download failed: HTTP {status} {message}")]
    Download {
        /// HTTP status code returned by the platform.
        status: u16,
        /// Truncated response body (for context).
        message: String,
    },
    /// Implant subprocess exited before the agent could read a
    /// `result_final` event.
    #[error("implant exited prematurely: {0}")]
    PrematureExit(String),
    /// JSON decode of an NDJSON event failed.
    #[error("ndjson decode: {0}")]
    Json(#[from] serde_json::Error),
}

/// Holds the configuration needed to run a veriguard-implant subprocess.
pub struct ImplantManager {
    /// HTTPS base URL of the Veriguard platform.
    pub platform_url: String,
    /// Local state dir.  Implant binaries are cached at
    /// `<state_dir>/implants/<sha>/<name>`.
    pub state_dir: PathBuf,
}

impl ImplantManager {
    /// Construct a new manager.  Real wiring lands in A.6.2.
    pub fn new(platform_url: String, state_dir: PathBuf) -> Self {
        Self {
            platform_url,
            state_dir,
        }
    }

    /// Drop an implant + collect the `result_final` NDJSON event.  Stub.
    pub fn run_implant(
        &self,
        _task_id: &str,
        _payload_type: &str,
        _payload_b64: &str,
        _timeout_secs: u32,
    ) -> Result<TaskResult, ImplantError> {
        Err(ImplantError::PrematureExit(
            "ImplantManager::run_implant not yet implemented (A.6.2)".to_string(),
        ))
    }
}
