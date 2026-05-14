//! `http_attack` — §3 边界 capability stub.  Real implementation lands in A.5.2.

use crate::transport::poll::{Task, TaskResult};

use super::Capability;

/// Boundary HTTP attack capability — sends a pre-crafted HTTP request from
/// the agent and compares the response against operator expectations.
///
/// Full implementation lands in task A.5.2.
pub struct HttpAttackCapability;

impl HttpAttackCapability {
    /// The stable capability name used in `Task.capability` from the platform.
    pub const NAME: &'static str = "http_attack";

    /// Construct a new capability.
    pub fn new() -> Self {
        Self
    }
}

impl Default for HttpAttackCapability {
    fn default() -> Self {
        Self::new()
    }
}

impl Capability for HttpAttackCapability {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn execute(&self, _task: &Task) -> TaskResult {
        TaskResult {
            status: "FAILED".to_string(),
            exit_code: 1,
            stdout: None,
            stderr: None,
            started_at: None,
            finished_at: None,
            error_message: Some("http_attack capability not yet implemented (A.5.2)".to_string()),
        }
    }
}
