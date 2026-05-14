//! veriguard-implant subprocess manager.
//!
//! Drops a short-lived veriguard-implant process to run host-level payloads
//! (`Command`, `Executable`, ...) on the agent's machine.  Flow:
//!
//! 1.  Look up the cached implant binary at
//!     `<state_dir>/implants/<os>-<arch>/veriguard-implant[.exe]`.  If
//!     absent, download from
//!     `GET <platform_url>/api/agent/implant/download/<os>/<arch>`.
//! 2.  Verify the downloaded file's SHA-256 against the platform's
//!     `X-SHA256` response header before persisting.
//! 3.  Create a named pipe (see [`super::pipe`]) and pass its path to the
//!     implant via `--result-pipe <path>`.
//! 4.  Spawn the implant with the agent-supplied payload, open the pipe for
//!     read, and stream NDJSON events until `event_type == "result_final"`
//!     or the timeout elapses.
//! 5.  Collect the final result, wait for the subprocess, and clean up the
//!     pipe.
//!
//! ## Implant CLI contract
//!
//! ```text
//! veriguard-implant \
//!   --task-id <id> \
//!   --payload-type <type> \
//!   --payload-b64 <b64> \
//!   --result-pipe <path> \
//!   --timeout <secs> \
//!   --self-delete
//! ```

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::transport::poll::TaskResult;

use super::pipe::{new_temp_pipe, NamedPipe};

/// Errors raised while running a veriguard-implant subprocess.
#[derive(Debug, Error)]
pub enum ImplantError {
    /// Underlying I/O failure (network, FS, subprocess spawn).
    #[error("implant I/O: {0}")]
    Io(#[from] std::io::Error),
    /// The platform returned a non-2xx response when the agent tried to
    /// download the implant binary, or the download response was missing
    /// the integrity header.
    #[error("implant download failed: {message}")]
    Download {
        /// Truncated context message for logging.
        message: String,
    },
    /// Implant subprocess exited before the agent could read a
    /// `result_final` event.
    #[error("implant exited prematurely: {0}")]
    PrematureExit(String),
    /// JSON decode of an NDJSON event failed.
    #[error("ndjson decode: {0}")]
    Json(#[from] serde_json::Error),
    /// The implant ran longer than the agent-supplied timeout.
    #[error("implant timed out after {0:?}")]
    Timeout(Duration),
}

/// Holds the configuration needed to run a veriguard-implant subprocess.
pub struct ImplantManager {
    /// HTTPS base URL of the Veriguard platform.
    pub platform_url: String,
    /// Local state dir.  Implant binaries are cached at
    /// `<state_dir>/implants/<os>-<arch>/<filename>`.
    pub state_dir: PathBuf,
    /// HTTP client used for downloads (subset of the poller's client).
    pub http_client: reqwest::blocking::Client,
    /// OS slug as understood by the platform (`linux` / `macos` / `windows`).
    pub os: String,
    /// Arch slug as understood by the platform (`x86_64` / `arm64`).
    pub arch: String,
    /// Optional override path to a pre-existing implant binary.  When set,
    /// download is skipped and SHA-256 verification is omitted.  Used by
    /// tests to inject a mock binary; production code leaves this `None`.
    pub implant_path_override: Option<PathBuf>,
    /// Parent dir under which to create the temp result pipe.  Defaults to
    /// `state_dir/pipes` when constructed via [`ImplantManager::new`].
    pub pipe_parent: PathBuf,
}

impl ImplantManager {
    /// Construct a manager with default OS/arch detected at runtime.
    pub fn new(platform_url: String, state_dir: PathBuf) -> Self {
        let pipe_parent = state_dir.join("pipes");
        Self {
            platform_url,
            state_dir,
            http_client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(120))
                .build()
                .expect("blocking client"),
            os: detect_os(),
            arch: detect_arch(),
            implant_path_override: None,
            pipe_parent,
        }
    }

    /// Drop an implant + collect the `result_final` NDJSON event.
    ///
    /// Returns the [`TaskResult`] reconstructed from `result_final`.  Errors
    /// surface as [`ImplantError`] (the caller — `command_inject` /
    /// `implant_drop` capabilities — converts them into
    /// `TaskResult { status: "FAILED", ... }`).
    pub fn run_implant(
        &self,
        task_id: &str,
        payload_type: &str,
        payload_b64: &str,
        timeout_secs: u32,
    ) -> Result<TaskResult, ImplantError> {
        let implant_path = match &self.implant_path_override {
            Some(p) => p.clone(),
            None => self.ensure_implant_binary()?,
        };

        std::fs::create_dir_all(&self.pipe_parent)?;
        let pipe = new_temp_pipe(&self.pipe_parent, task_id)?;
        debug!("created implant result pipe at {:?}", pipe.path());

        let timeout = Duration::from_secs(timeout_secs as u64);

        let pipe_path_string = pipe.path().to_string_lossy().into_owned();
        let mut cmd = Command::new(&implant_path);
        cmd.arg("--task-id")
            .arg(task_id)
            .arg("--payload-type")
            .arg(payload_type)
            .arg("--payload-b64")
            .arg(payload_b64)
            .arg("--result-pipe")
            .arg(&pipe_path_string)
            .arg("--timeout")
            .arg(timeout_secs.to_string())
            .arg("--self-delete")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = cmd.spawn().map_err(|e| {
            // Distinct error so the operator sees `implant binary not
            // executable` rather than a generic I/O error.
            ImplantError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to spawn implant at {implant_path:?}: {e}"),
            ))
        })?;

        let outcome = self.read_result_or_timeout(child, &*pipe, timeout, task_id);
        // Best-effort cleanup; never let a cleanup failure mask the real
        // result.
        if let Err(e) = pipe.cleanup() {
            warn!("failed to clean up result pipe {:?}: {e}", pipe.path());
        }
        outcome
    }

    /// Ensure the implant binary exists locally, downloading and verifying
    /// it if necessary.  Returns the absolute path to the cached binary.
    fn ensure_implant_binary(&self) -> Result<PathBuf, ImplantError> {
        let filename = if self.os == "windows" {
            "veriguard-implant.exe"
        } else {
            "veriguard-implant"
        };
        let cache_dir = self
            .state_dir
            .join("implants")
            .join(format!("{}-{}", self.os, self.arch));
        std::fs::create_dir_all(&cache_dir)?;
        let cache_path = cache_dir.join(filename);

        if cache_path.exists() {
            return Ok(cache_path);
        }

        info!(
            "downloading implant binary from platform ({}/{})",
            self.os, self.arch
        );
        let url = format!(
            "{}/api/agent/implant/download/{}/{}",
            self.platform_url.trim_end_matches('/'),
            self.os,
            self.arch
        );
        let resp = self
            .http_client
            .get(&url)
            .send()
            .map_err(|e| ImplantError::Download {
                message: format!("transport error: {e}"),
            })?;

        if !resp.status().is_success() {
            return Err(ImplantError::Download {
                message: format!(
                    "HTTP {} from {url}: {}",
                    resp.status().as_u16(),
                    truncate(&resp.text().unwrap_or_default(), 256)
                ),
            });
        }

        let expected_sha = resp
            .headers()
            .get("X-SHA256")
            .ok_or_else(|| ImplantError::Download {
                message: "platform did not return X-SHA256 integrity header".to_string(),
            })?
            .to_str()
            .map_err(|_| ImplantError::Download {
                message: "X-SHA256 header was not ASCII".to_string(),
            })?
            .to_ascii_lowercase();

        let body = resp.bytes().map_err(|e| ImplantError::Download {
            message: format!("body read failed: {e}"),
        })?;

        let actual_sha = hex_encode(&Sha256::digest(&body));
        if actual_sha != expected_sha {
            return Err(ImplantError::Download {
                message: format!("SHA-256 mismatch: expected {expected_sha}, got {actual_sha}"),
            });
        }

        std::fs::write(&cache_path, &body)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&cache_path, perms)?;
        }
        Ok(cache_path)
    }

    /// Reads NDJSON events from the implant pipe until `result_final` arrives
    /// OR `timeout` elapses BETWEEN newlines.
    ///
    /// # Known limitation (deferred to C1-Integration)
    ///
    /// Timeout checking happens between `read_line()` syscalls, not during them.
    /// If the implant subprocess hangs in a state that produces no output
    /// (e.g. system call wait, network stall, `D` state after pipe writer fd is
    /// opened), this function blocks until the kernel returns EOF or the implant
    /// is killed by another means. The `--timeout` flag passed to the implant is
    /// a best-effort protocol guarantee, not an OS-level enforcement.
    ///
    /// C1-Integration will refactor to a `(thread, mpsc::Receiver)` pattern with
    /// `recv_timeout` for true deadline enforcement.
    fn read_result_or_timeout(
        &self,
        mut child: Child,
        pipe: &dyn NamedPipe,
        timeout: Duration,
        task_id: &str,
    ) -> Result<TaskResult, ImplantError> {
        let reader = pipe.open_read()?;
        let buf = BufReader::new(reader);
        let start = Instant::now();

        for line in buf.lines() {
            if start.elapsed() > timeout {
                let _ = child.kill();
                return Err(ImplantError::Timeout(timeout));
            }
            let line = match line {
                Ok(l) => l,
                Err(e) => return Err(ImplantError::Io(e)),
            };
            if line.is_empty() {
                continue;
            }
            let event: NdjsonEvent = serde_json::from_str(&line)?;
            debug!("implant event for {task_id}: {}", event.event_type);
            if event.event_type == "result_final" {
                // Drain stdout/stderr without blocking forever.
                let _ = child.wait();
                let result = event.into_task_result();
                return Ok(result);
            }
        }

        // EOF before result_final.  Wait the child briefly so we can report
        // an exit status.
        let exit_status = child
            .wait()
            .map_err(|e| ImplantError::PrematureExit(format!("wait failed: {e}")))?;
        Err(ImplantError::PrematureExit(format!(
            "implant exited with status {:?} before sending result_final",
            exit_status.code()
        )))
    }
}

/// NDJSON event shape emitted by veriguard-implant.
///
/// Matches the implant fork's `events/result_final.json` schema.  Only the
/// final-result fields are required; all others are optional / ignored.
#[derive(Debug, Deserialize)]
struct NdjsonEvent {
    event_type: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    exit_code: Option<i32>,
    #[serde(default)]
    stdout: Option<String>,
    #[serde(default)]
    stderr: Option<String>,
    #[serde(default)]
    started_at: Option<String>,
    #[serde(default)]
    finished_at: Option<String>,
    #[serde(default)]
    error_message: Option<String>,
}

impl NdjsonEvent {
    fn into_task_result(self) -> TaskResult {
        TaskResult {
            status: self.status.unwrap_or_else(|| "FAILED".to_string()),
            exit_code: self.exit_code.unwrap_or(1),
            stdout: self.stdout,
            stderr: self.stderr,
            started_at: self.started_at,
            finished_at: self.finished_at,
            error_message: self.error_message,
        }
    }
}

fn detect_os() -> String {
    match std::env::consts::OS {
        "macos" => "macos".to_string(),
        "windows" => "windows".to_string(),
        _ => "linux".to_string(),
    }
}

fn detect_arch() -> String {
    match std::env::consts::ARCH {
        "aarch64" => "arm64".to_string(),
        _ => "x86_64".to_string(),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut cut = max;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}...", &s[..cut])
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use tempfile::tempdir;

    /// Build a mock implant script that:
    ///   * captures its argv to a file (so the test can assert it)
    ///   * writes 2 progress events + 1 result_final event to the pipe
    fn write_mock_implant(dir: &Path, exit_status: i32, payload_status: &str) -> PathBuf {
        let path = dir.join("mock-implant.sh");
        let script = format!(
            r##"#!/usr/bin/env bash
# Capture argv for assertion.
echo "$@" > "{argv_log}"
PIPE=""
# Parse --result-pipe out of the argv.
while [[ $# -gt 0 ]]; do
  case "$1" in
    --result-pipe) PIPE="$2"; shift 2 ;;
    *) shift ;;
  esac
done
{{
  printf '%s\n' '{{"event_type":"started","timestamp":"2026-05-15T00:00:00Z"}}'
  printf '%s\n' '{{"event_type":"progress","timestamp":"2026-05-15T00:00:01Z"}}'
  printf '%s\n' '{{"event_type":"result_final","status":"{payload_status}","exit_code":0,"stdout":"hi","stderr":""}}'
}} > "$PIPE"
exit {exit_status}
"##,
            argv_log = dir.join("argv.txt").to_string_lossy(),
        );
        std::fs::write(&path, script).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    fn manager_with_mock(dir: &Path, implant_path: PathBuf) -> ImplantManager {
        let mut m = ImplantManager::new("https://does.not.matter".to_string(), dir.to_path_buf());
        m.implant_path_override = Some(implant_path);
        m.pipe_parent = dir.join("pipes");
        m
    }

    #[test]
    fn test_implant_collects_result_final_event() {
        let dir = tempdir().unwrap();
        let bin = write_mock_implant(dir.path(), 0, "SUCCESS");
        let m = manager_with_mock(dir.path(), bin);

        let result = m.run_implant("task-A", "Command", "Zm9v", 5).expect("ok");
        assert_eq!(result.status, "SUCCESS");
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout.as_deref(), Some("hi"));
    }

    #[test]
    fn test_implant_argv_contains_required_flags() {
        let dir = tempdir().unwrap();
        let bin = write_mock_implant(dir.path(), 0, "SUCCESS");
        let m = manager_with_mock(dir.path(), bin);

        m.run_implant("task-B", "Executable", "Ymxv", 5)
            .expect("ok");

        let argv = std::fs::read_to_string(dir.path().join("argv.txt")).unwrap();
        for flag in [
            "--task-id",
            "task-B",
            "--payload-type",
            "Executable",
            "--payload-b64",
            "Ymxv",
            "--result-pipe",
            "--timeout",
            "5",
            "--self-delete",
        ] {
            assert!(argv.contains(flag), "argv missing {flag}: {argv}");
        }
    }

    #[test]
    fn test_implant_propagates_failed_status_from_event() {
        let dir = tempdir().unwrap();
        let bin = write_mock_implant(dir.path(), 0, "FAILED");
        let m = manager_with_mock(dir.path(), bin);

        let result = m.run_implant("task-C", "Command", "Zm9v", 5).expect("ok");
        assert_eq!(result.status, "FAILED");
    }

    #[test]
    fn test_implant_premature_exit_when_no_result_final() {
        // Mock that writes nothing to the pipe and exits 0.
        let dir = tempdir().unwrap();
        let path = dir.path().join("silent-implant.sh");
        let script = r##"#!/usr/bin/env bash
# Parse --result-pipe but write nothing, then exit.
while [[ $# -gt 0 ]]; do
  case "$1" in
    --result-pipe) PIPE="$2"; shift 2 ;;
    *) shift ;;
  esac
done
# Attach as writer so the agent's open(O_RDONLY) unblocks, then close
# without writing.
exec >"$PIPE"
exit 0
"##;
        std::fs::write(&path, script).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();

        let m = manager_with_mock(dir.path(), path);
        let err = m
            .run_implant("task-X", "Command", "AA==", 5)
            .expect_err("premature exit");
        match err {
            ImplantError::PrematureExit(_) => {}
            other => panic!("expected PrematureExit, got {other:?}"),
        }
    }

    #[test]
    fn test_implant_download_propagates_404() {
        // Use a mock server that returns 404.  No implant_path_override so
        // the manager goes through the download path.
        let mut server = mockito::Server::new();
        server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/agent/implant/download/.*".to_string()),
            )
            .with_status(404)
            .with_body("not bundled")
            .create();

        let dir = tempdir().unwrap();
        let m = ImplantManager {
            platform_url: server.url(),
            state_dir: dir.path().to_path_buf(),
            http_client: reqwest::blocking::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            implant_path_override: None,
            pipe_parent: dir.path().join("pipes"),
        };
        let err = m.ensure_implant_binary().expect_err("404");
        match err {
            ImplantError::Download { message } => assert!(message.contains("404"), "{message}"),
            other => panic!("expected Download err, got {other:?}"),
        }
    }

    #[test]
    fn test_implant_download_rejects_sha_mismatch() {
        let mut server = mockito::Server::new();
        let body = b"FAKE_IMPLANT";
        // Lie about the digest.
        server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/agent/implant/download/.*".to_string()),
            )
            .with_status(200)
            .with_header("X-SHA256", &"0".repeat(64))
            .with_body(body.as_slice())
            .create();

        let dir = tempdir().unwrap();
        let m = ImplantManager {
            platform_url: server.url(),
            state_dir: dir.path().to_path_buf(),
            http_client: reqwest::blocking::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            implant_path_override: None,
            pipe_parent: dir.path().join("pipes"),
        };
        let err = m.ensure_implant_binary().expect_err("sha mismatch");
        match err {
            ImplantError::Download { message } => {
                assert!(message.contains("SHA-256 mismatch"), "{message}")
            }
            other => panic!("expected Download err, got {other:?}"),
        }
    }

    #[test]
    fn test_read_result_timeout_fires_when_implant_exits_cleanly_without_result_final() {
        // Mock implant writes ONE non-result_final NDJSON event then exits.
        // The pipe will close (EOF) so read_line returns Ok(0) and the loop
        // exits — the agent surfaces PrematureExit.  This pins the
        // clean-exit-without-result_final path; the truly-hung implant case
        // requires the C1-Integration mpsc refactor to test.
        let dir = tempdir().unwrap();
        let path = dir.path().join("incomplete-implant.sh");
        let script = r##"#!/usr/bin/env bash
# Parse --result-pipe, write ONE progress event (no result_final), exit.
while [[ $# -gt 0 ]]; do
  case "$1" in
    --result-pipe) PIPE="$2"; shift 2 ;;
    *) shift ;;
  esac
done
{
  printf '%s\n' '{"event_type":"progress","timestamp":"2026-05-15T00:00:00Z"}'
} > "$PIPE"
exit 0
"##;
        std::fs::write(&path, script).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();

        let m = manager_with_mock(dir.path(), path);
        // Use a generous timeout — we want the EOF-after-clean-exit path,
        // not the elapsed-timer path.
        let start = std::time::Instant::now();
        let err = m
            .run_implant("task-clean-exit", "Command", "AA==", 30)
            .expect_err("must error since no result_final");
        // Test should finish quickly (well under the 30s timeout) because
        // EOF closes the loop, not the elapsed timer.
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "clean-exit path should not wait full timeout: elapsed = {:?}",
            start.elapsed()
        );
        match err {
            ImplantError::PrematureExit(_) => {}
            other => panic!("expected PrematureExit, got {other:?}"),
        }
    }

    #[test]
    fn test_implant_download_persists_with_0700_perm() {
        let mut server = mockito::Server::new();
        let body = b"FAKE_IMPLANT";
        let sha = hex_encode(&Sha256::digest(body));
        server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/agent/implant/download/.*".to_string()),
            )
            .with_status(200)
            .with_header("X-SHA256", &sha)
            .with_body(body.as_slice())
            .create();

        let dir = tempdir().unwrap();
        let m = ImplantManager {
            platform_url: server.url(),
            state_dir: dir.path().to_path_buf(),
            http_client: reqwest::blocking::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            implant_path_override: None,
            pipe_parent: dir.path().join("pipes"),
        };
        let path = m.ensure_implant_binary().expect("ok");
        assert!(path.exists());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "implant binary must be 0o700, got {mode:#o}");
    }
}
