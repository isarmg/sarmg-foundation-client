//! Native service lifecycle and bounded service-manager output.

#[cfg(not(target_os = "linux"))]
use crate::cli::log_message;
#[cfg(target_os = "linux")]
use crate::cli::sanitize;
use crate::cli::{Args, Failure, Result, fail, input_error, storage_error};
use crate::runtime::process::{ProcessCaptureError, ProcessLimits, capture_bounded};
use serde_json::{Value, json};
#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn command_failure(exit: u8, code: &'static str, output: &std::process::Output) -> Failure {
    let bytes = if output.stderr.is_empty() {
        &output.stdout
    } else {
        &output.stderr
    };
    let reported = String::from_utf8_lossy(bytes);
    let reported = reported.trim();
    let detail = if reported.is_empty() {
        format!("service manager exit status: {}", output.status)
    } else {
        format!("service manager exit status {}: {reported}", output.status)
    };
    fail(exit, code).with_detail(detail)
}
pub struct Service {
    #[cfg(not(target_os = "macos"))]
    pub name: &'static str,
    #[allow(dead_code)]
    pub label: &'static str,
    pub default_config: PathBuf,
    pub binary: &'static str,
    /// Product-owned local service log path used on macOS.
    pub log_path: &'static str,
}
impl Service {
    fn capture(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<std::process::Output> {
        // Service managers are fixed executables and verbs. Run the existing
        // dual-pipe capture on a dedicated reactor, including when a caller is
        // already inside Tokio. The deadline covers EOF as well as child exit.
        let program = program.to_owned();
        let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| fail(8, "output_reader_unavailable"))?;
            let mut command = tokio::process::Command::new(program);
            command.args(args);
            runtime
                .block_on(capture_bounded(
                    &mut command,
                    ProcessLimits {
                        timeout,
                        stdout_bytes: 4 * 1024 * 1024,
                        stderr_bytes: 1024 * 1024,
                    },
                ))
                .map_err(|error| match error {
                    ProcessCaptureError::Timeout => fail(9, "service_timeout"),
                    ProcessCaptureError::OutputLimit(_) => fail(8, "output_budget_exceeded"),
                    ProcessCaptureError::Spawn(_) => fail(6, "service_manager_unavailable"),
                    _ => fail(8, "output_reader_unavailable"),
                })
        })
        .join()
        .map_err(|_| fail(8, "output_reader_unavailable"))?
    }
    #[cfg(target_os = "macos")]
    fn wait_macos_unloaded(&self, target: &str, deadline: Instant) -> Result<()> {
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(|| fail(9, "service_state_unconfirmed"))?;
            let output = self
                .capture("/bin/launchctl", &["print", target], remaining)
                .map_err(|failure| {
                    if failure.code == "service_timeout" {
                        fail(9, "service_state_unconfirmed")
                    } else {
                        failure
                    }
                })?;
            if output.status.code() == Some(113) {
                return Ok(());
            }
            if !output.status.success() {
                return Err(command_failure(6, "service_manager_unavailable", &output));
            }
            std::thread::sleep(
                Duration::from_millis(25).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
    #[cfg(target_os = "macos")]
    fn bootout_macos(&self, target: &str, timeout: Duration) -> Result<std::process::Output> {
        let deadline = Instant::now() + timeout;
        let output = self.capture("/bin/launchctl", &["bootout", target], timeout)?;
        if output.status.success() {
            // bootout returns while launchd may still expose a SIGTERMed job.
            // A stopped process does not prove its definition was removed.
            self.wait_macos_unloaded(target, deadline)?;
        }
        Ok(output)
    }
    pub fn status(&self, timeout: Duration) -> Result<Value> {
        #[cfg(target_os = "linux")]
        {
            let o = self.capture(
                "/usr/bin/systemctl",
                &[
                    "show",
                    self.name,
                    "--property=LoadState,ActiveState,UnitFileState,ExecStart",
                ],
                timeout,
            )?;
            if !o.status.success() {
                return Err(command_failure(6, "service_manager_unavailable", &o));
            }
            let text = String::from_utf8_lossy(&o.stdout);
            let fields: BTreeMap<_, _> = text.lines().filter_map(|l| l.split_once('=')).collect();
            let active = fields.get("ActiveState").copied().unwrap_or("unknown");
            Ok(
                json!({"installed":fields.get("LoadState")==Some(&"loaded"),"state":if active=="active" {"running"} else if active=="inactive" || active=="failed" {"stopped"} else {active},"startup":fields.get("UnitFileState"),"registration":fields.get("ExecStart")}),
            )
        }
        #[cfg(windows)]
        {
            let o = self.capture("sc.exe", &["query", self.name], timeout)?;
            let t = String::from_utf8_lossy(&o.stdout);
            let config = self.capture("sc.exe", &["qc", self.name], timeout)?;
            let config = String::from_utf8_lossy(&config.stdout);
            let registration = config.lines().find_map(|line| {
                line.trim()
                    .strip_prefix("BINARY_PATH_NAME")
                    .and_then(|v| v.trim().strip_prefix(':'))
                    .map(str::trim)
            });
            Ok(
                json!({"installed":o.status.success(),"state":if t.contains("RUNNING"){"running"}else if t.contains("STOPPED"){"stopped"}else{"unknown"},"startup":if config.contains("AUTO_START"){"automatic"}else if config.contains("DEMAND_START"){"manual"}else if config.contains("DISABLED"){"disabled"}else{"unknown"},"registration":registration}),
            )
        }
        #[cfg(target_os = "macos")]
        {
            let target = format!("system/{}", self.label);
            let o = self.capture("/bin/launchctl", &["print", &target], timeout)?;
            let t = String::from_utf8_lossy(&o.stdout);
            let plist = format!("/Library/LaunchDaemons/{}.plist", self.label);
            let policy = self.capture("/bin/launchctl", &["print-disabled", "system"], timeout)?;
            if !policy.status.success() {
                return Err(command_failure(6, "service_manager_unavailable", &policy));
            }
            let policy = String::from_utf8_lossy(&policy.stdout);
            let disabled = policy.lines().any(|line| {
                line.contains(&format!("\"{}\"", self.label))
                    && line
                        .split_once("=>")
                        .is_some_and(|(_, value)| matches!(value.trim(), "true" | "disabled"))
            });
            Ok(json!({
                "installed": Path::new(&plist).is_file(),
                "loaded": o.status.success(),
                "state": if o.status.success() && t.contains("state = running") {"running"} else {"stopped"},
                "startup": if disabled {"disabled"} else {"automatic"}
            }))
        }
    }
    pub fn verified_status(&self, timeout: Duration, selected: &Path) -> Result<Value> {
        if selected != self.default_config {
            return Err(fail(2, "service_config_mismatch"));
        }
        let status = self.status(timeout)?;
        if status["installed"] != true {
            return Err(fail(4, "service_not_installed"));
        }
        #[cfg(any(target_os = "linux", windows))]
        {
            let registration = status["registration"].as_str().unwrap_or("");
            if !registration.contains(self.binary)
                || !registration.contains(self.default_config.to_string_lossy().as_ref())
            {
                return Err(fail(8, "service_registration_mismatch"));
            }
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::MetadataExt;
            let plist = format!("/Library/LaunchDaemons/{}.plist", self.label);
            let meta = std::fs::symlink_metadata(&plist)
                .map_err(|_| fail(8, "unsafe_service_registration"))?;
            if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.nlink() != 1 {
                return Err(fail(8, "unsafe_service_registration"));
            }
            let output = self.capture(
                "/usr/bin/plutil",
                &["-extract", "ProgramArguments", "json", "-o", "-", &plist],
                timeout,
            )?;
            let registered: Vec<String> = serde_json::from_slice(&output.stdout)
                .map_err(|_| fail(8, "service_registration_mismatch"))?;
            let expected_binary = format!("/usr/local/libexec/{}", self.binary);
            if !output.status.success()
                || registered.first() != Some(&expected_binary)
                || registered.len() != 4
                || registered[1] != "run"
                || !["--config", "--state"].contains(&registered[2].as_str())
                || registered[3] != self.default_config.to_string_lossy()
            {
                return Err(fail(8, "service_registration_mismatch"));
            }
        }
        Ok(status)
    }
    pub fn change(&self, args: &Args, action: &str, selected: &Path) -> Result<Value> {
        let before = self.verified_status(args.timeout, selected)?;
        #[cfg(target_os = "linux")]
        let _ = &before;
        if !["start", "stop", "restart", "enable", "disable"].contains(&action) {
            return Err(fail(2, "invalid_service_action"));
        }
        #[cfg(target_os = "linux")]
        let output = {
            let mut cmd = vec![action, self.name];
            if args.has("--now") {
                cmd.push("--now");
            }
            self.capture("/usr/bin/systemctl", &cmd, args.timeout)?
        };
        #[cfg(windows)]
        let output = {
            if action == "start" && before["state"] == "running"
                || action == "stop" && before["state"] == "stopped"
            {
                return Ok(before);
            }
            if action == "restart" && before["state"] != "stopped" {
                let o = self.capture("sc.exe", &["stop", self.name], args.timeout)?;
                if !o.status.success() {
                    return Err(command_failure(3, "service_action_denied", &o));
                }
                self.wait("stopped", args.timeout)?;
            }
            let o = match action {
                "enable" => self.capture(
                    "sc.exe",
                    &["config", self.name, "start=", "auto"],
                    args.timeout,
                )?,
                "disable" => self.capture(
                    "sc.exe",
                    &["config", self.name, "start=", "demand"],
                    args.timeout,
                )?,
                "restart" => self.capture("sc.exe", &["start", self.name], args.timeout)?,
                _ => self.capture("sc.exe", &[action, self.name], args.timeout)?,
            };
            if o.status.success()
                && args.has("--now")
                && ["enable", "disable"].contains(&action)
                && !(action == "enable" && before["state"] == "running"
                    || action == "disable" && before["state"] == "stopped")
            {
                self.capture(
                    "sc.exe",
                    &[if action == "enable" { "start" } else { "stop" }, self.name],
                    args.timeout,
                )?
            } else {
                o
            }
        };
        #[cfg(target_os = "macos")]
        let output = {
            let target = format!("system/{}", self.label);
            let plist = format!("/Library/LaunchDaemons/{}.plist", self.label);
            let loaded = before["loaded"] == true;
            let should_start =
                ["start", "restart"].contains(&action) || action == "enable" && args.has("--now");
            let should_stop = action == "stop" || action == "disable" && args.has("--now");
            let policy_change = ["enable", "disable"].contains(&action);
            let policy_output = if policy_change {
                let o = self.capture("/bin/launchctl", &[action, &target], args.timeout)?;
                if !o.status.success() {
                    return Err(command_failure(3, "service_action_denied", &o));
                }
                Some(o)
            } else {
                None
            };
            if should_start {
                // launchd refuses bootstrap for disabled jobs. Restore startup policy
                // after the explicit one-off start, including when bootstrap fails.
                let restore_disabled = before["startup"] == "disabled" && !policy_change;
                if restore_disabled {
                    let o = self.capture("/bin/launchctl", &["enable", &target], args.timeout)?;
                    if !o.status.success() {
                        return Err(command_failure(3, "service_action_denied", &o));
                    }
                }
                let result = if loaded {
                    let cmd = if action == "restart" {
                        vec!["kickstart", "-k", &target]
                    } else {
                        vec!["kickstart", &target]
                    };
                    self.capture("/bin/launchctl", &cmd, args.timeout)
                } else {
                    self.capture(
                        "/bin/launchctl",
                        &["bootstrap", "system", &plist],
                        args.timeout,
                    )
                };
                if restore_disabled {
                    let restored = self
                        .capture("/bin/launchctl", &["disable", &target], args.timeout)
                        .map_err(|_| fail(11, "startup_policy_restore_failed"))?;
                    if !restored.status.success() {
                        return Err(fail(11, "startup_policy_restore_failed"));
                    }
                }
                result?
            } else if should_stop && loaded {
                self.bootout_macos(&target, args.timeout)?
            } else if let Some(output) = policy_output {
                output
            } else {
                return Ok(before);
            }
        };
        if !output.status.success() {
            return Err(command_failure(3, "service_action_denied", &output));
        }
        if ["start", "restart", "stop"].contains(&action) || args.has("--now") {
            self.wait(
                if ["stop", "disable"].contains(&action) {
                    "stopped"
                } else {
                    "running"
                },
                args.timeout,
            )?;
        }
        self.status(args.timeout)
    }
    fn wait(&self, expected: &str, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.status(timeout)?["state"] == expected {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(fail(9, "service_state_unconfirmed"));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Service {
    pub fn logs(&self, args: &Args) -> Result<Value> {
        let tail = args
            .get("--tail")
            .unwrap_or("100")
            .parse::<usize>()
            .map_err(input_error)?;
        if tail == 0 || tail > 1000 {
            return Err(fail(2, "invalid_log_tail"));
        }
        #[cfg(target_os = "linux")]
        {
            let tail = tail.to_string();
            let mut query = vec![
                "--no-pager",
                "--output=json",
                "--unit",
                self.name,
                "--lines",
                &tail,
            ];
            if let Some(cursor) = args.get("--log-cursor") {
                query.extend(["--after-cursor", cursor]);
            } else if let Some(since) = args.get("--since") {
                if since.len() > 64 || since.chars().any(char::is_control) {
                    return Err(fail(2, "invalid_log_since"));
                }
                query.extend(["--since", since]);
            }
            let output = self.capture("/usr/bin/journalctl", &query, args.timeout)?;
            if !output.status.success() {
                return Err(fail(3, "logs_unavailable"));
            }
            if output.stdout.len() > 4 * 1024 * 1024 {
                return Err(fail(8, "log_budget_exceeded"));
            }
            let mut entries = Vec::new();
            for line in output
                .stdout
                .split(|b| *b == b'\n')
                .filter(|l| !l.is_empty())
            {
                let value: Value = serde_json::from_slice(line).map_err(storage_error)?;
                let message = value["MESSAGE"].as_str().unwrap_or("");
                // Suppress text log lines that contain sensitive terms.
                let lower = message.to_ascii_lowercase();
                let message = if [
                    "password",
                    "token",
                    "secret",
                    "bearer",
                    "authorization",
                    "activation",
                    "enrollment",
                ]
                .iter()
                .any(|s| lower.contains(s))
                {
                    "[sensitive log message redacted]".into()
                } else {
                    sanitize(message)
                };
                entries.push(json!({"observed_at":value["__REALTIME_TIMESTAMP"],"cursor":value["__CURSOR"],"message":message}));
            }
            Ok(json!({"entries":entries,"source":"journald"}))
        }
        #[cfg(windows)]
        {
            let since = args.get("--since").unwrap_or("1970-01-01T00:00:00Z");
            if since.len() > 40
                || !since
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b"-:TZ+. ".contains(&b))
            {
                return Err(fail(2, "invalid_log_since"));
            }
            let script = format!(
                "$ErrorActionPreference='Stop'; $name=(Get-Service -Name '{}').DisplayName; $since=[DateTimeOffset]::Parse('{}').UtcDateTime; $items=@(Get-WinEvent -FilterHashtable @{{LogName='System';ProviderName='Service Control Manager';StartTime=$since}} -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object {{$_.Properties.Count -gt 0 -and $_.Properties[0].Value -eq $name}} | Select-Object -First {} | ForEach-Object {{@{{observed_at=$_.TimeCreated.ToUniversalTime().ToString('o');cursor=[string]$_.RecordId;message=$_.Message}}}}); ConvertTo-Json -InputObject $items -Compress",
                self.name, since, tail
            );
            let output = self.capture(
                "powershell.exe",
                &["-NoProfile", "-NonInteractive", "-Command", &script],
                args.timeout,
            )?;
            if !output.status.success() {
                return Err(fail(3, "logs_unavailable"));
            }
            let mut entries: Vec<Value> =
                serde_json::from_slice(&output.stdout).map_err(storage_error)?;
            let cursor = args
                .get("--log-cursor")
                .and_then(|c| c.parse::<u64>().ok())
                .unwrap_or(0);
            entries.retain(|e| {
                e["cursor"]
                    .as_str()
                    .and_then(|c| c.parse::<u64>().ok())
                    .is_some_and(|c| c > cursor)
            });
            entries.reverse();
            for entry in &mut entries {
                entry["message"] = json!(log_message(entry["message"].as_str().unwrap_or("")));
            }
            Ok(json!({"source":"scm_lifecycle","entries":entries}))
        }
        #[cfg(target_os = "macos")]
        {
            use std::{
                io::{Read, Seek, SeekFrom},
                os::unix::fs::MetadataExt,
            };
            let path = self.log_path;
            let metadata = std::fs::symlink_metadata(path).map_err(storage_error)?;
            if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
                return Err(fail(8, "unsafe_log_file"));
            }
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
                .open(path)
                .map_err(|error| {
                    if error.raw_os_error() == Some(libc::ELOOP) {
                        fail(8, "unsafe_log_file")
                    } else {
                        storage_error(error)
                    }
                })?;
            let held = file.metadata().map_err(storage_error)?;
            if !held.is_file() || held.nlink() != 1 || held.mode() & 0o077 != 0 {
                return Err(fail(8, "unsafe_log_file"));
            }
            if held.ino() != metadata.ino() || held.dev() != metadata.dev() {
                return Err(fail(8, "log_changed_during_open"));
            }
            let length = held.len();
            let inode = held.ino();
            let resume = args
                .get("--log-cursor")
                .and_then(|c| c.split_once(':'))
                .and_then(|(i, o)| Some((i.parse::<u64>().ok()?, o.parse::<u64>().ok()?)))
                .filter(|(i, o)| *i == inode && *o <= length)
                .map(|(_, o)| o);
            let start = resume.unwrap_or(length.saturating_sub(1024 * 1024));
            file.seek(SeekFrom::Start(start)).map_err(storage_error)?;
            let mut bytes = Vec::new();
            file.take(1024 * 1024)
                .read_to_end(&mut bytes)
                .map_err(storage_error)?;
            let end = bytes
                .iter()
                .rposition(|b| *b == b'\n')
                .map(|i| i + 1)
                .unwrap_or(0);
            let cursor = format!("{inode}:{}", start + end as u64);
            let text = String::from_utf8_lossy(&bytes[..end]);
            let mut lines: Vec<_> = text.lines().collect();
            if start > 0 && resume.is_none() && !lines.is_empty() {
                lines.remove(0);
            }
            if let Some(since) = args.get("--since") {
                if since.len() > 40
                    || !since
                        .bytes()
                        .all(|b| b.is_ascii_digit() || b"-:TZ. ".contains(&b))
                {
                    return Err(fail(2, "invalid_log_since"));
                }
                lines.retain(|line| {
                    line.chars().next().is_some_and(|c| c.is_ascii_digit()) && *line >= since
                });
            }
            let skip = lines.len().saturating_sub(tail);
            let entries: Vec<_> = lines
                .into_iter()
                .skip(skip)
                .map(|line| json!({"message":log_message(line),"cursor":cursor}))
                .collect();
            Ok(json!({"source":"service_log","entries":entries}))
        }
    }
}

#[cfg(all(test, unix))]
mod tests;
