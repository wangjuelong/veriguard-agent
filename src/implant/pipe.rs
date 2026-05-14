//! Cross-platform named pipe abstraction for streaming NDJSON results from
//! the veriguard-implant subprocess back to the agent.
//!
//! ## Unix
//!
//! Backed by a FIFO created with `mkfifo` (via `nix::unistd::mkfifo`).
//! Opening the FIFO for read blocks until a writer attaches — which is the
//! behaviour we want, because the agent opens the pipe BEFORE spawning the
//! implant and the implant attaches as the writer.
//!
//! ## Windows
//!
//! Backed by a `CreateNamedPipeW` server endpoint.  The implementation here
//! is a stub that returns an error if invoked.  Real Windows support lands
//! when the Veriguard implant pipeline is ready to publish Windows
//! artifacts (tracked for C1-Integration); the agent on Windows can still
//! be built but cannot yet run implant-backed capabilities.

use std::io::Read;
use std::path::{Path, PathBuf};

/// Trait describing a named pipe used as the implant's result channel.
pub trait NamedPipe: Send {
    /// Filesystem path the implant should be told to write to.
    fn path(&self) -> &Path;

    /// Open the reader side.  Blocks until a writer attaches (Unix FIFO
    /// semantics).
    fn open_read(&self) -> std::io::Result<Box<dyn Read + Send>>;

    /// Remove the pipe from the filesystem (best-effort).
    fn cleanup(&self) -> std::io::Result<()>;
}

/// Create a new named pipe inside `parent` with `name_hint` baked into the
/// filename.  Returns a [`NamedPipe`] handle the caller should use exactly
/// once before [`NamedPipe::cleanup`].
pub fn new_temp_pipe(parent: &Path, name_hint: &str) -> std::io::Result<Box<dyn NamedPipe>> {
    #[cfg(unix)]
    {
        unix::create(parent, name_hint)
    }
    #[cfg(windows)]
    {
        windows::create(parent, name_hint)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, name_hint);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "named pipe not supported on this platform",
        ))
    }
}

#[cfg(unix)]
mod unix {
    use super::{NamedPipe, PathBuf, Read};
    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;
    use std::fs::OpenOptions;
    use std::io;
    use std::path::Path;

    /// Unix FIFO-backed named pipe.
    pub struct UnixFifoPipe {
        path: PathBuf,
    }

    pub(super) fn create(parent: &Path, name_hint: &str) -> io::Result<Box<dyn NamedPipe>> {
        std::fs::create_dir_all(parent)?;
        // Use a high-entropy filename so concurrent invocations don't
        // collide.  The implant is told the exact path so name visibility
        // outside this process isn't a concern.
        let unique = format!(
            "{name_hint}.{}.fifo",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        );
        let path = parent.join(unique);
        // 0o600 — agent owner only.
        mkfifo(&path, Mode::S_IRUSR | Mode::S_IWUSR).map_err(io::Error::from)?;
        Ok(Box::new(UnixFifoPipe { path }))
    }

    impl NamedPipe for UnixFifoPipe {
        fn path(&self) -> &Path {
            &self.path
        }

        fn open_read(&self) -> io::Result<Box<dyn Read + Send>> {
            // Open in read-only mode; this blocks until a writer attaches —
            // the implant subprocess will be that writer.
            let f = OpenOptions::new().read(true).open(&self.path)?;
            Ok(Box::new(f))
        }

        fn cleanup(&self) -> io::Result<()> {
            // Best-effort: missing file is OK (implant may already have
            // self-deleted on some platforms).
            match std::fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            }
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::{NamedPipe, PathBuf, Read};
    use std::io;
    use std::path::Path;

    pub(super) fn create(_parent: &Path, _name_hint: &str) -> io::Result<Box<dyn NamedPipe>> {
        // Real CreateNamedPipeW support is tracked for C1-Integration; the
        // Windows implant binary is not yet published.  Returning Unsupported
        // here gives the caller a clear, structured error that propagates as
        // status=FAILED in the TaskResult.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows named pipe support pending C1-Integration (CreateNamedPipeW)",
        ))
    }

    /// Placeholder so Drop bounds / impl lookups behave on Windows builds.
    /// Never instantiated.
    pub struct WindowsNamedPipe {
        _path: PathBuf,
    }

    impl NamedPipe for WindowsNamedPipe {
        fn path(&self) -> &Path {
            &self._path
        }

        fn open_read(&self) -> io::Result<Box<dyn Read + Send>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows named pipe support pending C1-Integration",
            ))
        }

        fn cleanup(&self) -> io::Result<()> {
            Ok(())
        }
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::process::Command;
    use std::thread;
    use tempfile::tempdir;

    #[test]
    fn test_unix_fifo_path_exists_after_create() {
        let dir = tempdir().unwrap();
        let pipe = new_temp_pipe(dir.path(), "test").unwrap();
        assert!(pipe.path().exists(), "fifo must be created");
        // Mode is 0o600.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(pipe.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "fifo perm must be 0o600 (got {mode:#o})");
        pipe.cleanup().unwrap();
        assert!(!pipe.path().exists(), "cleanup must remove fifo");
    }

    #[test]
    fn test_unix_fifo_round_trip_via_subshell() {
        // mkfifo can only be opened once the other end is attached.  Spawn a
        // bash writer that prints two lines into the fifo and asserts the
        // reader sees them.
        let dir = tempdir().unwrap();
        let pipe = new_temp_pipe(dir.path(), "rt").unwrap();
        let writer_path = pipe.path().to_string_lossy().into_owned();

        let writer_handle = thread::spawn(move || {
            // Small sleep to ensure the reader is open first.  In practice
            // the implant is told to write _on its first event_ so the
            // synchronisation is implicit; here we mimic it.
            thread::sleep(std::time::Duration::from_millis(50));
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&writer_path)
                .expect("open for write");
            f.write_all(b"line one\nline two\n").expect("write");
        });

        let reader = pipe.open_read().expect("open read");
        let buf = BufReader::new(reader);
        let lines: Vec<String> = buf.lines().take(2).collect::<Result<_, _>>().unwrap();
        assert_eq!(lines, vec!["line one", "line two"]);
        writer_handle.join().unwrap();
        pipe.cleanup().unwrap();
    }

    #[test]
    fn test_cleanup_idempotent_when_file_already_gone() {
        let dir = tempdir().unwrap();
        let pipe = new_temp_pipe(dir.path(), "idempotent").unwrap();
        std::fs::remove_file(pipe.path()).unwrap();
        // Second cleanup must not error.
        pipe.cleanup().unwrap();
    }

    #[test]
    fn test_external_writer_into_fifo() {
        // Sanity: bash subprocess can attach as writer and the reader sees
        // the bytes.  Different from the round-trip test in that the writer
        // is a subprocess, exercising the real implant flow.
        let dir = tempdir().unwrap();
        let pipe = new_temp_pipe(dir.path(), "ext").unwrap();
        let path = pipe.path().to_string_lossy().into_owned();

        let _child = thread::spawn(move || {
            // bash: write to fifo then exit
            let _ = Command::new("bash")
                .arg("-c")
                .arg(format!("printf 'hi\\n' > {path:?}"))
                .status();
        });
        let reader = pipe.open_read().expect("open read");
        let buf = BufReader::new(reader);
        let first = buf.lines().next().expect("at least one line").unwrap();
        assert_eq!(first, "hi");
        pipe.cleanup().unwrap();
    }
}
