//! `implant_drop` — §5 主机 generic-implant capability stub.  Real
//! implementation lands in A.5.4 alongside `command_inject`.

use crate::transport::poll::{Task, TaskResult};

use super::Capability;

/// Generic implant-drop capability — downloads veriguard-implant and runs
/// any platform-supplied payload type through it.  `command_inject` is a
/// constrained alias for `payload_type=Command`; this capability handles
/// every other payload type.
///
/// Full implementation lands in task A.5.4.
pub struct ImplantDropCapability;

impl ImplantDropCapability {
    /// Stable capability name used by the platform.
    pub const NAME: &'static str = "implant_drop";

    /// Construct a new capability.
    pub fn new() -> Self {
        Self
    }
}

impl Default for ImplantDropCapability {
    fn default() -> Self {
        Self::new()
    }
}

impl Capability for ImplantDropCapability {
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
            error_message: Some("implant_drop capability not yet implemented (A.5.4)".to_string()),
        }
    }
}
