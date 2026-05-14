//! `pcap_replay` — §4 流量 traffic replay capability.
//!
//! Replays a pre-captured pcap (downloaded from the platform) against a
//! local interface using the `tcpreplay` subprocess.  The capability:
//!
//! 1.  Parses the JSON payload into [`PcapReplayPayload`].
//! 2.  Downloads `pcap_url` to a temp file under `state_dir/pcaps/`.
//! 3.  Verifies the file's SHA-256 against the platform-supplied digest.
//! 4.  Invokes `tcpreplay --intf1 <iface> [--mbps <rate>] [--loop <n>] <pcap>`.
//! 5.  Maps the subprocess exit code into the [`TaskResult`].
//!
//! ## Payload schema
//!
//! ```json
//! {
//!   "pcap_url": "https://platform.example.com/pcap/abc.pcap",
//!   "pcap_sha256": "<hex>",
//!   "interface": "eth0",
//!   "rate_mbps": 10,
//!   "loop_count": 1
//! }
//! ```
//!
//! ## tcpreplay availability
//!
//! The capability assumes `tcpreplay` is on `$PATH` on the agent host.  If
//! it is missing, [`Capability::execute`] returns `FAILED` with a clear
//! `error_message`, never panics.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::transport::poll::{Task, TaskResult};

use super::Capability;

/// Pcap replay capability — invokes `tcpreplay` against a server-supplied
/// pcap to replay attack traffic toward a target interface.
pub struct PcapReplayCapability {
    /// Where to cache downloaded pcaps.  Defaults to a tempdir; the
    /// real-world wiring in `main.rs` should pass the agent's `state_dir`.
    state_dir: PathBuf,
    /// HTTP client used to download pcaps.
    http_client: reqwest::blocking::Client,
    /// `tcpreplay` binary path.  Defaults to `"tcpreplay"` (PATH lookup).
    tcpreplay_path: String,
}

impl PcapReplayCapability {
    /// Stable capability name used by the platform.
    pub const NAME: &'static str = "pcap_replay";

    /// Construct a capability with a fresh tempdir state dir and the default
    /// HTTP client.
    pub fn new() -> Self {
        let state_dir = std::env::temp_dir().join("veriguard-pcap");
        Self::with_state_dir(state_dir)
    }

    /// Construct a capability with a caller-supplied state dir (real
    /// deployments pass the agent's state dir; tests pass a tempdir).
    pub fn with_state_dir(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            http_client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(120))
                .build()
                .expect("blocking client"),
            tcpreplay_path: "tcpreplay".to_string(),
        }
    }

    /// Override the HTTP client (used by tests that need `no_proxy()`).
    pub fn with_http_client(mut self, client: reqwest::blocking::Client) -> Self {
        self.http_client = client;
        self
    }

    /// Override the `tcpreplay` binary path.  Tests use this to point at a
    /// stub script so the test doesn't depend on a real `tcpreplay` install.
    pub fn with_tcpreplay_path(mut self, path: String) -> Self {
        self.tcpreplay_path = path;
        self
    }
}

impl Default for PcapReplayCapability {
    fn default() -> Self {
        Self::new()
    }
}

/// Wire payload for `pcap_replay`.
#[derive(Debug, Deserialize)]
struct PcapReplayPayload {
    pcap_url: String,
    pcap_sha256: String,
    interface: String,
    #[serde(default)]
    rate_mbps: Option<u32>,
    #[serde(default)]
    loop_count: Option<u32>,
}

impl Capability for PcapReplayCapability {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn execute(&self, task: &Task) -> TaskResult {
        let payload: PcapReplayPayload = match serde_json::from_str(&task.payload) {
            Ok(p) => p,
            Err(e) => return failed(format!("invalid pcap_replay payload: {e}")),
        };

        let started_at = rfc3339_now();

        // Download to <state_dir>/<sha256>.pcap.
        if let Err(e) = std::fs::create_dir_all(&self.state_dir) {
            return failed(format!("create state dir: {e}"));
        }
        let pcap_path = self.state_dir.join(format!("{}.pcap", payload.pcap_sha256));

        if !pcap_path.exists() {
            if let Err(e) = self.download_pcap(&payload.pcap_url, &pcap_path) {
                return failed(format!("pcap download failed: {e}"));
            }
        }

        // Integrity check.
        match sha256_of_file(&pcap_path) {
            Ok(actual) => {
                if actual.to_ascii_lowercase() != payload.pcap_sha256.to_ascii_lowercase() {
                    return failed(format!(
                        "pcap sha256 mismatch: expected {} got {}",
                        payload.pcap_sha256, actual
                    ));
                }
            }
            Err(e) => return failed(format!("sha256 hash failed: {e}")),
        }

        // Invoke tcpreplay.
        let mut cmd = Command::new(&self.tcpreplay_path);
        cmd.arg("--intf1").arg(&payload.interface);
        if let Some(rate) = payload.rate_mbps {
            cmd.arg("--mbps").arg(rate.to_string());
        }
        if let Some(n) = payload.loop_count {
            cmd.arg("--loop").arg(n.to_string());
        }
        cmd.arg(&pcap_path);

        let output = match cmd.output() {
            Ok(o) => o,
            Err(e) => return failed(format!("failed to spawn {:?}: {e}", self.tcpreplay_path)),
        };

        let finished_at = rfc3339_now();
        let exit_code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

        TaskResult {
            status: if output.status.success() {
                "SUCCESS".to_string()
            } else {
                "FAILED".to_string()
            },
            exit_code,
            stdout: Some(stdout),
            stderr: Some(stderr),
            started_at: Some(started_at),
            finished_at: Some(finished_at),
            error_message: if output.status.success() {
                None
            } else {
                Some(format!("tcpreplay exited with {exit_code}"))
            },
        }
    }
}

impl PcapReplayCapability {
    fn download_pcap(&self, url: &str, dest: &Path) -> Result<(), String> {
        let resp = self
            .http_client
            .get(url)
            .send()
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("download status {}", resp.status().as_u16()));
        }
        let bytes = resp.bytes().map_err(|e| e.to_string())?;
        std::fs::write(dest, &bytes).map_err(|e| e.to_string())?;
        Ok(())
    }
}

fn sha256_of_file(path: &Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    let digest = Sha256::digest(&bytes);
    Ok(hex_encode(&digest))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn failed(message: String) -> TaskResult {
    TaskResult {
        status: "FAILED".to_string(),
        exit_code: 1,
        stdout: None,
        stderr: None,
        started_at: Some(rfc3339_now()),
        finished_at: Some(rfc3339_now()),
        error_message: Some(message),
    }
}

fn rfc3339_now() -> String {
    // Reuse the implementation from http_attack via copy-paste, to avoid
    // exposing a private helper across modules.  If a third capability
    // needs this, lift it into a shared `time` helper.
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs() as i64;
    let millis = dur.subsec_millis();
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

fn civil_from_unix(secs: i64) -> (i32, u8, u8, u8, u8, u8) {
    let days = secs.div_euclid(86_400);
    let secs_in_day = secs.rem_euclid(86_400) as u32;
    let h = (secs_in_day / 3600) as u8;
    let mi = ((secs_in_day % 3600) / 60) as u8;
    let s = (secs_in_day % 60) as u8;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let mo = (if mp < 10 { mp + 3 } else { mp - 9 }) as u8;
    let y = (y + if mo <= 2 { 1 } else { 0 }) as i32;
    (y, mo, d, h, mi, s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn task_for(payload_json: serde_json::Value) -> Task {
        Task {
            task_id: "p1".to_string(),
            capability: "pcap_replay".to_string(),
            injector_type: "traffic".to_string(),
            payload: payload_json.to_string(),
            expectations: vec![],
        }
    }

    /// Build a mock `tcpreplay` script that:
    ///   * prints its argv to stdout
    ///   * exits with the code passed via the `MOCK_EXIT` env variable
    ///   * defaults to 0 if `MOCK_EXIT` is not set
    fn mock_tcpreplay_script(dir: &Path, exit_code: u8) -> PathBuf {
        let path = dir.join("mock-tcpreplay.sh");
        let script = format!(
            "#!/usr/bin/env bash\n\
             echo \"args: $@\"\n\
             exit {exit_code}\n"
        );
        std::fs::write(&path, script).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    #[test]
    #[cfg(unix)]
    fn test_pcap_replay_success_path() {
        let dir = tempdir().unwrap();
        let bin = mock_tcpreplay_script(dir.path(), 0);

        // Serve a tiny pcap (any bytes; we control sha256).
        let pcap_bytes = b"PCAP_CONTENT_FOR_TEST";
        let sha256 = hex_encode(&Sha256::digest(pcap_bytes));

        let mut server = Server::new();
        let m = server
            .mock("GET", "/probe.pcap")
            .with_status(200)
            .with_body(pcap_bytes.as_slice())
            .create();

        let cap = PcapReplayCapability::with_state_dir(dir.path().to_path_buf())
            .with_http_client(no_proxy_client())
            .with_tcpreplay_path(bin.to_string_lossy().into_owned());

        let task = task_for(serde_json::json!({
            "pcap_url": format!("{}/probe.pcap", server.url()),
            "pcap_sha256": sha256,
            "interface": "eth0",
        }));
        let result = cap.execute(&task);
        m.assert();
        assert_eq!(result.status, "SUCCESS", "result: {result:?}");
        assert_eq!(result.exit_code, 0);
        let stdout = result.stdout.unwrap();
        assert!(stdout.contains("eth0"), "expected --intf1 eth0: {stdout}");
    }

    #[test]
    #[cfg(unix)]
    fn test_pcap_replay_argv_includes_rate_and_loop() {
        let dir = tempdir().unwrap();
        let bin = mock_tcpreplay_script(dir.path(), 0);

        let pcap_bytes = b"X";
        let sha256 = hex_encode(&Sha256::digest(pcap_bytes));
        let mut server = Server::new();
        server
            .mock("GET", "/probe.pcap")
            .with_status(200)
            .with_body(pcap_bytes.as_slice())
            .create();

        let cap = PcapReplayCapability::with_state_dir(dir.path().to_path_buf())
            .with_http_client(no_proxy_client())
            .with_tcpreplay_path(bin.to_string_lossy().into_owned());

        let task = task_for(serde_json::json!({
            "pcap_url": format!("{}/probe.pcap", server.url()),
            "pcap_sha256": sha256,
            "interface": "eth0",
            "rate_mbps": 25,
            "loop_count": 3,
        }));
        let result = cap.execute(&task);
        assert_eq!(result.status, "SUCCESS");
        let stdout = result.stdout.unwrap();
        assert!(stdout.contains("--mbps"), "{stdout}");
        assert!(stdout.contains("25"), "{stdout}");
        assert!(stdout.contains("--loop"), "{stdout}");
        assert!(stdout.contains("3"), "{stdout}");
    }

    #[test]
    #[cfg(unix)]
    fn test_pcap_replay_failed_when_tcpreplay_nonzero() {
        let dir = tempdir().unwrap();
        let bin = mock_tcpreplay_script(dir.path(), 17);
        let pcap_bytes = b"X";
        let sha256 = hex_encode(&Sha256::digest(pcap_bytes));
        let mut server = Server::new();
        server
            .mock("GET", "/probe.pcap")
            .with_status(200)
            .with_body(pcap_bytes.as_slice())
            .create();

        let cap = PcapReplayCapability::with_state_dir(dir.path().to_path_buf())
            .with_http_client(no_proxy_client())
            .with_tcpreplay_path(bin.to_string_lossy().into_owned());

        let task = task_for(serde_json::json!({
            "pcap_url": format!("{}/probe.pcap", server.url()),
            "pcap_sha256": sha256,
            "interface": "eth0",
        }));
        let result = cap.execute(&task);
        assert_eq!(result.status, "FAILED");
        assert_eq!(result.exit_code, 17);
        assert!(result.error_message.unwrap().contains("17"));
    }

    #[test]
    fn test_pcap_replay_failed_on_sha_mismatch() {
        let dir = tempdir().unwrap();
        let pcap_bytes = b"BODY";
        // Lie about the digest.
        let wrong_sha = "0".repeat(64);

        let mut server = Server::new();
        server
            .mock("GET", "/probe.pcap")
            .with_status(200)
            .with_body(pcap_bytes.as_slice())
            .create();

        let cap = PcapReplayCapability::with_state_dir(dir.path().to_path_buf())
            .with_http_client(no_proxy_client())
            .with_tcpreplay_path("definitely-not-installed".to_string());

        let task = task_for(serde_json::json!({
            "pcap_url": format!("{}/probe.pcap", server.url()),
            "pcap_sha256": wrong_sha,
            "interface": "eth0",
        }));
        let result = cap.execute(&task);
        assert_eq!(result.status, "FAILED");
        assert!(result
            .error_message
            .as_ref()
            .unwrap()
            .contains("sha256 mismatch"));
    }

    #[test]
    fn test_pcap_replay_failed_on_invalid_payload() {
        let dir = tempdir().unwrap();
        let cap = PcapReplayCapability::with_state_dir(dir.path().to_path_buf());

        let task = Task {
            task_id: "x".to_string(),
            capability: "pcap_replay".to_string(),
            injector_type: "traffic".to_string(),
            payload: "{ not json".to_string(),
            expectations: vec![],
        };
        let result = cap.execute(&task);
        assert_eq!(result.status, "FAILED");
        assert!(result
            .error_message
            .as_ref()
            .unwrap()
            .contains("invalid pcap_replay payload"));
    }

    fn no_proxy_client() -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }
}
