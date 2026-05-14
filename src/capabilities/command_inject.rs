//! `command_inject` — §5 主机 Command-payload capability.
//!
//! Delegates to [`crate::implant::ImplantManager`] with `payload_type =
//! "Command"`.  This is effectively [`super::implant_drop`] constrained to
//! the Command payload type; we keep them as two separate registry names
//! because the platform's task router differentiates them.
//!
//! ## Payload schema
//!
//! ```json
//! {
//!   "command_b64": "<base64 of platform Command payload JSON>",
//!   "timeout_secs": 30
//! }
//! ```

use std::sync::Arc;

use serde::Deserialize;

use crate::implant::ImplantManager;
use crate::transport::poll::{Task, TaskResult};

use super::Capability;

/// Command-inject capability — runs a Command payload through the bundled
/// veriguard-implant subprocess.
pub struct CommandInjectCapability {
    manager: Arc<ImplantManager>,
}

impl CommandInjectCapability {
    /// Stable capability name used by the platform.
    pub const NAME: &'static str = "command_inject";
    /// Payload type the implant CLI is told to run.
    pub const PAYLOAD_TYPE: &'static str = "Command";

    /// Construct a new capability wired to the supplied implant manager.
    pub fn new(manager: Arc<ImplantManager>) -> Self {
        Self { manager }
    }
}

#[derive(Debug, Deserialize)]
struct CommandInjectPayload {
    command_b64: String,
    #[serde(default = "default_timeout")]
    timeout_secs: u32,
}

fn default_timeout() -> u32 {
    60
}

impl Capability for CommandInjectCapability {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn execute(&self, task: &Task) -> TaskResult {
        super::implant_drop::run_with_payload_type(
            &self.manager,
            task,
            Self::PAYLOAD_TYPE,
            extract_payload,
        )
    }
}

fn extract_payload(raw: &str) -> Result<(String, u32), String> {
    let parsed: CommandInjectPayload =
        serde_json::from_str(raw).map_err(|e| format!("invalid command_inject payload: {e}"))?;
    Ok((parsed.command_b64, parsed.timeout_secs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::implant::ImplantManager;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    /// Build a mock implant that writes a SUCCESS result_final event to the
    /// agent-supplied result pipe.  Records argv so the test can assert the
    /// command_inject capability passed payload_type=Command.
    fn write_recording_implant(dir: &std::path::Path) -> std::path::PathBuf {
        let argv_log = dir.join("argv.txt");
        let path = dir.join("mock-implant.sh");
        let script = format!(
            r##"#!/usr/bin/env bash
echo "$@" > "{argv_log}"
PIPE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --result-pipe) PIPE="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '%s\n' '{{"event_type":"result_final","status":"SUCCESS","exit_code":0,"stdout":"done"}}' > "$PIPE"
exit 0
"##,
            argv_log = argv_log.to_string_lossy()
        );
        std::fs::write(&path, script).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    fn manager_with(dir: &std::path::Path) -> Arc<ImplantManager> {
        let bin = write_recording_implant(dir);
        let mut m = ImplantManager::new("https://x".to_string(), dir.to_path_buf());
        m.implant_path_override = Some(bin);
        m.pipe_parent = dir.join("pipes");
        Arc::new(m)
    }

    #[test]
    fn test_command_inject_returns_success_from_result_final() {
        let dir = tempdir().unwrap();
        let manager = manager_with(dir.path());
        let cap = CommandInjectCapability::new(manager);

        let payload = serde_json::json!({
            "command_b64": "ZWNobyBoaQ==",
            "timeout_secs": 5,
        });
        let task = Task {
            task_id: "ci-1".to_string(),
            capability: "command_inject".to_string(),
            injector_type: "host".to_string(),
            payload: payload.to_string(),
            expectations: vec![],
        };
        let result = cap.execute(&task);
        assert_eq!(result.status, "SUCCESS");
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout.as_deref(), Some("done"));

        // Confirm implant got payload_type=Command.
        let argv = std::fs::read_to_string(dir.path().join("argv.txt")).unwrap();
        assert!(argv.contains("--payload-type"), "{argv}");
        assert!(argv.contains("Command"), "{argv}");
        assert!(argv.contains("ZWNobyBoaQ=="), "{argv}");
    }

    #[test]
    fn test_command_inject_fail_on_invalid_payload() {
        let dir = tempdir().unwrap();
        let manager = manager_with(dir.path());
        let cap = CommandInjectCapability::new(manager);

        let task = Task {
            task_id: "ci-2".to_string(),
            capability: "command_inject".to_string(),
            injector_type: "host".to_string(),
            payload: "{ not json".to_string(),
            expectations: vec![],
        };
        let result = cap.execute(&task);
        assert_eq!(result.status, "FAILED");
        assert!(result
            .error_message
            .as_ref()
            .unwrap()
            .contains("invalid command_inject payload"));
    }
}
