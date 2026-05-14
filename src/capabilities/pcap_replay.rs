//! `pcap_replay` — §4 流量 capability stub.  Real implementation lands in A.5.3.

use crate::transport::poll::{Task, TaskResult};

use super::Capability;

/// Pcap replay capability — invokes `tcpreplay` against a server-supplied
/// pcap to replay attack traffic toward a target interface.
///
/// Full implementation lands in task A.5.3.
pub struct PcapReplayCapability;

impl PcapReplayCapability {
    /// Stable capability name used by the platform.
    pub const NAME: &'static str = "pcap_replay";

    /// Construct a new capability.
    pub fn new() -> Self {
        Self
    }
}

impl Default for PcapReplayCapability {
    fn default() -> Self {
        Self::new()
    }
}

impl Capability for PcapReplayCapability {
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
            error_message: Some("pcap_replay capability not yet implemented (A.5.3)".to_string()),
        }
    }
}
