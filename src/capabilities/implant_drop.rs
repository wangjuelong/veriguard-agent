//! `implant_drop` — §5 主机 generic-implant capability.
//!
//! Generic counterpart to [`super::command_inject`].  The platform supplies
//! both the payload_type (e.g. `Executable`) and the base64 payload; the
//! capability passes them through to [`crate::implant::ImplantManager`].
//!
//! ## Payload schema
//!
//! ```json
//! {
//!   "payload_type": "Executable",
//!   "payload_b64":  "<base64 of platform payload>",
//!   "timeout_secs": 60
//! }
//! ```

use std::sync::Arc;

use log::warn;
use serde::Deserialize;

use crate::implant::{ImplantError, ImplantManager};
use crate::transport::poll::{Task, TaskResult};

use super::Capability;

/// Generic implant-drop capability — downloads veriguard-implant and runs
/// any platform-supplied payload type through it.
pub struct ImplantDropCapability {
    manager: Arc<ImplantManager>,
}

impl ImplantDropCapability {
    /// Stable capability name used by the platform.
    pub const NAME: &'static str = "implant_drop";

    /// Construct a new capability wired to the supplied implant manager.
    pub fn new(manager: Arc<ImplantManager>) -> Self {
        Self { manager }
    }
}

#[derive(Debug, Deserialize)]
struct ImplantDropPayload {
    payload_type: String,
    payload_b64: String,
    #[serde(default = "default_timeout")]
    timeout_secs: u32,
}

fn default_timeout() -> u32 {
    60
}

impl Capability for ImplantDropCapability {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn execute(&self, task: &Task) -> TaskResult {
        let payload: ImplantDropPayload = match serde_json::from_str(&task.payload) {
            Ok(p) => p,
            Err(e) => return failed(format!("invalid implant_drop payload: {e}")),
        };
        run_implant_or_failed(
            &self.manager,
            task,
            &payload.payload_type,
            &payload.payload_b64,
            payload.timeout_secs,
        )
    }
}

/// Shared helper used by both `command_inject` and `implant_drop`.
///
/// `payload_extractor` parses `task.payload` into `(payload_b64,
/// timeout_secs)`.  This keeps the inject-side payload parsing logic local
/// to each capability while sharing the common "dispatch + map errors"
/// branch.
pub(super) fn run_with_payload_type<F>(
    manager: &Arc<ImplantManager>,
    task: &Task,
    payload_type: &str,
    payload_extractor: F,
) -> TaskResult
where
    F: FnOnce(&str) -> Result<(String, u32), String>,
{
    let (payload_b64, timeout_secs) = match payload_extractor(&task.payload) {
        Ok(v) => v,
        Err(e) => return failed(e),
    };
    run_implant_or_failed(manager, task, payload_type, &payload_b64, timeout_secs)
}

fn run_implant_or_failed(
    manager: &Arc<ImplantManager>,
    task: &Task,
    payload_type: &str,
    payload_b64: &str,
    timeout_secs: u32,
) -> TaskResult {
    match manager.run_implant(&task.task_id, payload_type, payload_b64, timeout_secs) {
        Ok(result) => result,
        Err(e) => {
            warn!("implant run failed for task {}: {e}", task.task_id);
            map_implant_error_to_result(e)
        }
    }
}

fn map_implant_error_to_result(e: ImplantError) -> TaskResult {
    let msg = e.to_string();
    let status = match &e {
        ImplantError::Timeout(_) => "TIMEOUT",
        _ => "FAILED",
    };
    TaskResult {
        status: status.to_string(),
        exit_code: 1,
        stdout: None,
        stderr: None,
        started_at: None,
        finished_at: None,
        error_message: Some(msg),
    }
}

fn failed(message: String) -> TaskResult {
    TaskResult {
        status: "FAILED".to_string(),
        exit_code: 1,
        stdout: None,
        stderr: None,
        started_at: None,
        finished_at: None,
        error_message: Some(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::implant::ImplantManager;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

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
printf '%s\n' '{{"event_type":"result_final","status":"SUCCESS","exit_code":0,"stdout":"ok"}}' > "$PIPE"
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
    fn test_implant_drop_passes_payload_type_to_implant() {
        let dir = tempdir().unwrap();
        let manager = manager_with(dir.path());
        let cap = ImplantDropCapability::new(manager);

        let payload = serde_json::json!({
            "payload_type": "Executable",
            "payload_b64":  "QUJDRA==",
            "timeout_secs": 10,
        });
        let task = Task {
            task_id: "id-1".to_string(),
            capability: "implant_drop".to_string(),
            injector_type: "host".to_string(),
            payload: payload.to_string(),
            expectations: vec![],
        };
        let result = cap.execute(&task);
        assert_eq!(result.status, "SUCCESS");

        let argv = std::fs::read_to_string(dir.path().join("argv.txt")).unwrap();
        assert!(argv.contains("Executable"), "{argv}");
        assert!(argv.contains("QUJDRA=="), "{argv}");
    }

    #[test]
    fn test_implant_drop_fail_on_invalid_payload() {
        let dir = tempdir().unwrap();
        let manager = manager_with(dir.path());
        let cap = ImplantDropCapability::new(manager);

        let task = Task {
            task_id: "id-2".to_string(),
            capability: "implant_drop".to_string(),
            injector_type: "host".to_string(),
            payload: "not json".to_string(),
            expectations: vec![],
        };
        let result = cap.execute(&task);
        assert_eq!(result.status, "FAILED");
        assert!(result
            .error_message
            .as_ref()
            .unwrap()
            .contains("invalid implant_drop payload"));
    }

    #[test]
    fn test_implant_drop_map_timeout_to_status_timeout() {
        // Build a manager whose implant_path_override points at a
        // never-exits script.  Use a tiny timeout so the test is fast.
        let dir = tempdir().unwrap();
        let slow = dir.path().join("sleep.sh");
        std::fs::write(
            &slow,
            "#!/usr/bin/env bash\nsleep 30 > /dev/null 2>&1\nexit 0\n",
        )
        .unwrap();
        let mut perms = std::fs::metadata(&slow).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&slow, perms).unwrap();

        let mut m = ImplantManager::new("https://x".to_string(), dir.path().to_path_buf());
        m.implant_path_override = Some(slow);
        m.pipe_parent = dir.path().join("pipes");
        let manager = Arc::new(m);

        // Test the error-mapping helper directly so we don't have to wait for
        // a real timeout (the read loop only checks timeout once per line).
        let result =
            map_implant_error_to_result(ImplantError::Timeout(std::time::Duration::from_secs(1)));
        assert_eq!(result.status, "TIMEOUT");
        assert!(result.error_message.unwrap().contains("timed out"));
    }
}
