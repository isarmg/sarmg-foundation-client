//! Portable bounded capture for one product-owned subprocess. Stderr bytes are
//! returned only to the caller; error messages never reflect their content.

use std::{
    io,
    process::{Output, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
};

const MAX_PIPE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct ProcessLimits {
    pub timeout: Duration,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessCaptureError {
    #[error("invalid subprocess capture limits")]
    InvalidLimits,
    #[error("subprocess could not be started ({0:?})")]
    Spawn(io::ErrorKind),
    #[error("subprocess pipe could not be read ({0:?})")]
    Read(io::ErrorKind),
    #[error("subprocess could not be waited for ({0:?})")]
    Wait(io::ErrorKind),
    #[error("subprocess timed out")]
    Timeout,
    #[error("subprocess output limit exceeded ({0:?})")]
    OutputLimit(OutputStream),
    #[error("subprocess cleanup failed ({0:?})")]
    Cleanup(io::ErrorKind),
}

/// Starts one fixed product command and concurrently drains both pipes. A
/// timeout or byte limit aborts capture, kills the child and waits for it before
/// returning. Dropping a cancelled caller also requests child termination.
pub async fn capture_bounded(
    command: &mut Command,
    limits: ProcessLimits,
) -> Result<Output, ProcessCaptureError> {
    if limits.timeout.is_zero()
        || limits.timeout > Duration::from_secs(600)
        || limits.stdout_bytes == 0
        || limits.stdout_bytes > MAX_PIPE_BYTES
        || limits.stderr_bytes == 0
        || limits.stderr_bytes > MAX_PIPE_BYTES
    {
        return Err(ProcessCaptureError::InvalidLimits);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|error| ProcessCaptureError::Spawn(error.kind()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or(ProcessCaptureError::Read(io::ErrorKind::Other))?;
    let stderr = child
        .stderr
        .take()
        .ok_or(ProcessCaptureError::Read(io::ErrorKind::Other))?;
    let capture = async {
        let (status, stdout, stderr) = tokio::try_join!(
            async {
                wait_for_exit(&mut child)
                    .await
                    .map_err(|error| ProcessCaptureError::Wait(error.kind()))
            },
            read_pipe(stdout, limits.stdout_bytes, OutputStream::Stdout),
            read_pipe(stderr, limits.stderr_bytes, OutputStream::Stderr),
        )?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    };
    let result = match tokio::time::timeout(limits.timeout, capture).await {
        Ok(result) => result,
        Err(_) => Err(ProcessCaptureError::Timeout),
    };
    if result.is_err() {
        stop_and_reap(&mut child).await?;
    }
    result
}

async fn read_pipe(
    reader: impl AsyncRead + Unpin,
    maximum: usize,
    stream: OutputStream,
) -> Result<Vec<u8>, ProcessCaptureError> {
    let mut bytes = Vec::with_capacity((maximum + 1).min(8192));
    reader
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| ProcessCaptureError::Read(error.kind()))?;
    if bytes.len() > maximum {
        return Err(ProcessCaptureError::OutputLimit(stream));
    }
    Ok(bytes)
}

async fn wait_for_exit(child: &mut Child) -> io::Result<std::process::ExitStatus> {
    // Administrative launchers can inherit a blocked SIGCHLD (notably macOS
    // authtrampoline). Keep signal-driven wakeups, but periodically repoll the
    // cancel-safe wait so an exited child cannot depend on signal delivery.
    loop {
        if let Ok(status) = tokio::time::timeout(Duration::from_millis(25), child.wait()).await {
            return status;
        }
    }
}

async fn stop_and_reap(child: &mut Child) -> Result<(), ProcessCaptureError> {
    if child
        .try_wait()
        .map_err(|error| ProcessCaptureError::Cleanup(error.kind()))?
        .is_none()
    {
        child
            .start_kill()
            .map_err(|error| ProcessCaptureError::Cleanup(error.kind()))?;
    }
    wait_for_exit(child)
        .await
        .map_err(|error| ProcessCaptureError::Cleanup(error.kind()))?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn limits() -> ProcessLimits {
        ProcessLimits {
            timeout: Duration::from_secs(3),
            stdout_bytes: 32768,
            stderr_bytes: 32768,
        }
    }

    #[tokio::test]
    async fn both_pipes_are_drained_without_deadlock_and_preserve_exit_status() {
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "head -c 20000 /dev/zero; head -c 20000 /dev/zero >&2; exit 7",
        ]);
        let output = capture_bounded(&mut command, limits()).await.unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout.len(), 20000);
        assert_eq!(output.stderr.len(), 20000);
    }

    #[test]
    #[allow(unsafe_code)]
    fn blocked_child_exit_notifications_do_not_stall_capture_or_cleanup() {
        use std::os::unix::process::CommandExt;
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args([
            "--ignored",
            "--exact",
            "runtime::process::tests::blocked_child_exit_notification_helper",
            "--nocapture",
        ]);
        // Change only the isolated test child's inherited mask, never the
        // parallel test runner. These signal operations are async-signal-safe.
        unsafe {
            command.pre_exec(|| {
                let mut signals = std::mem::zeroed();
                if libc::sigemptyset(&mut signals) != 0
                    || libc::sigaddset(&mut signals, libc::SIGCHLD) != 0
                    || libc::sigprocmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut()) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = command.output().unwrap();
        crate::assert_one_subprocess_test(&output);
        assert!(output.status.success(), "{output:?}");
    }

    #[tokio::test]
    #[ignore = "isolated helper invoked with SIGCHLD blocked by its parent test"]
    async fn blocked_child_exit_notification_helper() {
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "printf ready; exec >/dev/null 2>/dev/null; sleep 0.1; exit 7",
        ]);
        let started = tokio::time::Instant::now();
        let output = capture_bounded(&mut command, limits()).await.unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"ready");
        assert!(started.elapsed() < Duration::from_secs(1));

        let root = tempfile::Builder::new()
            .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
            .unwrap();
        let pidfile = root.path().join("child.pid");
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "echo $$ > \"$1\"; exec sleep 30",
            "capture-test",
            pidfile.to_str().unwrap(),
        ]);
        let mut bounds = limits();
        bounds.timeout = Duration::from_millis(150);
        let failure = tokio::time::timeout(
            Duration::from_secs(1),
            capture_bounded(&mut command, bounds),
        )
        .await
        .expect("cleanup must not wait for a blocked SIGCHLD")
        .unwrap_err();
        assert!(matches!(failure, ProcessCaptureError::Timeout));
        let pid = std::fs::read_to_string(pidfile).unwrap();
        let still_present = std::process::Command::new("/bin/kill")
            .args(["-0", pid.trim()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!still_present.success(), "child still running or unreaped");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn oversized_output_or_timeout_kills_and_reaps_the_actual_child() {
        let root = tempfile::tempdir().unwrap();
        for (label, action, expected) in [
            ("stdout", "exec yes output", "stdout"),
            ("stderr", "exec yes private-credential >&2", "stderr"),
            ("timeout", "exec sleep 30", "timeout"),
        ] {
            let pidfile = root.path().join(label);
            let mut command = Command::new("/bin/sh");
            command.args([
                "-c",
                &format!("echo $$ > '{}'; {action}", pidfile.display()),
            ]);
            let mut bounds = limits();
            bounds.timeout = Duration::from_millis(250);
            let failure = capture_bounded(&mut command, bounds).await.unwrap_err();
            assert!(matches!(
                (&failure, expected),
                (
                    ProcessCaptureError::OutputLimit(OutputStream::Stdout),
                    "stdout"
                ) | (
                    ProcessCaptureError::OutputLimit(OutputStream::Stderr),
                    "stderr"
                ) | (ProcessCaptureError::Timeout, "timeout")
            ));
            assert!(!failure.to_string().contains("private-credential"));
            let pid = std::fs::read_to_string(pidfile).unwrap();
            assert!(
                !std::path::Path::new(&format!("/proc/{}", pid.trim())).exists(),
                "child still running or unreaped"
            );
        }
    }
}
