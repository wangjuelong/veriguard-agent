//! `command_inject` — §5 主机 Command-payload capability stub.  Real
//! implementation lands in A.5.4.

use crate::transport::poll::{Task, TaskResult};

use super::Capability;

/// Command-inject capability — runs a Command payload through the bundled
/// veriguard-implant subprocess.
///
/// Full implementation lands in task A.5.4.
pub struct CommandInjectCapability;

impl CommandInjectCapability {
    /// Stable capability name used by the platform.
    pub const NAME: &'static str = "command_inject";

    /// Construct a new capability.
    pub fn new() -> Self {
        Self
    }
}

impl Default for CommandInjectCapability {
    fn default() -> Self {
        Self::new()
    }
}

impl Capability for CommandInjectCapability {
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
            error_message: Some(
                "command_inject capability not yet implemented (A.5.4)".to_string(),
            ),
        }
    }
}
