//! Versioned desktop CLI and service lifecycle. Product commands and state machines remain product-owned.
#![allow(unsafe_code)]
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Debug)]
pub struct Failure {
    pub exit: u8,
    pub code: &'static str,
    pub committed: bool,
    pub transaction_id: Option<String>,
    pub step: Option<&'static str>,
    pub detail: Option<String>,
}
pub type Result<T> = std::result::Result<T, Failure>;
pub fn fail(exit: u8, code: &'static str) -> Failure {
    Failure {
        exit,
        code,
        committed: false,
        transaction_id: None,
        step: None,
        detail: None,
    }
}
impl Failure {
    pub fn at_step(mut self, step: &'static str) -> Self {
        self.step = Some(step);
        self
    }

    pub fn with_detail(mut self, detail: impl std::fmt::Display) -> Self {
        let detail = compact_detail(&detail.to_string());
        self.detail = (!detail.is_empty()).then_some(detail);
        self
    }
}
pub fn input_error(_: impl std::fmt::Debug) -> Failure {
    fail(2, "invalid_input")
}
pub fn storage_error(_: impl std::fmt::Debug) -> Failure {
    fail(8, "unsafe_or_corrupt_state")
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for Failure {}

pub struct Args {
    pub words: Vec<String>,
    pub options: BTreeMap<String, String>,
    pub format: String,
    pub timeout: Duration,
}
impl Args {
    /// Parse common options plus the product options declared by the caller.
    ///
    /// Product option names deliberately stay out of Foundation: a product
    /// supplies only its valued and boolean option declarations.
    pub fn parse(
        raw: Vec<String>,
        valued_product_options: &[&str],
        flag_product_options: &[&str],
    ) -> Result<Self> {
        let mut words = vec![];
        let mut options = BTreeMap::new();
        let mut it = raw.into_iter();
        while let Some(arg) = it.next() {
            if arg.starts_with('-') {
                let name = match arg.as_str() {
                    "--output" => "--format",
                    "-h" => "--help",
                    "-V" => "--version",
                    _ => &arg,
                }
                .to_string();
                let value = match name.as_str() {
                    "--format" | "--timeout" | "--config" | "--state" | "--tail" | "--since" => {
                        it.next().ok_or_else(|| fail(2, "missing_option_value"))?
                    }
                    "--interactive"
                    | "--input-stdin"
                    | "--non-interactive"
                    | "--no-color"
                    | "--now"
                    | "--watch"
                    | "--check"
                    | "--follow"
                    | "--help"
                    | "--version"
                    | "--installer-session"
                    | "--elevated-setup-child" => "true".into(),
                    "--json" => {
                        if options.insert("--format".into(), "json".into()).is_some() {
                            return Err(fail(2, "duplicate_option"));
                        }
                        continue;
                    }
                    option if valued_product_options.contains(&option) => {
                        it.next().ok_or_else(|| fail(2, "missing_option_value"))?
                    }
                    option if flag_product_options.contains(&option) => "true".into(),
                    _ => return Err(fail(2, "unknown_option")),
                };
                if options.insert(name, value).is_some() {
                    return Err(fail(2, "duplicate_option"));
                }
            } else {
                words.push(arg);
            }
        }
        if options.contains_key("--interactive")
            && (options.contains_key("--non-interactive") || options.contains_key("--input-stdin"))
        {
            return Err(fail(2, "conflicting_input_modes"));
        }
        let format = options.get("--format").cloned().unwrap_or("human".into());
        if !["human", "json", "ndjson"].contains(&format.as_str()) {
            return Err(fail(2, "invalid_format"));
        }
        let timeout = duration(
            options
                .get("--timeout")
                .map(String::as_str)
                .unwrap_or("60s"),
        )?;
        for name in ["--config", "--state"].into_iter().chain(
            valued_product_options
                .iter()
                .copied()
                .filter(|name| matches!(*name, "--file" | "--bootstrap")),
        ) {
            if let Some(value) = options.get(name) {
                absolute(Path::new(value))?;
            }
        }
        Ok(Self {
            words,
            options,
            format,
            timeout,
        })
    }
    pub fn has(&self, name: &str) -> bool {
        self.options.contains_key(name)
    }
    pub fn get(&self, name: &str) -> Option<&str> {
        self.options.get(name).map(String::as_str)
    }
    pub fn require(&self, name: &str) -> Result<&str> {
        self.get(name)
            .ok_or_else(|| fail(2, "missing_required_option"))
    }
    pub fn validate_options(&self, permitted: &[&str]) -> Result<()> {
        for name in self.options.keys() {
            if ![
                "--format",
                "--timeout",
                "--config",
                "--state",
                "--non-interactive",
                "--no-color",
                "--help",
                "--version",
            ]
            .contains(&name.as_str())
                && !permitted.contains(&name.as_str())
            {
                return Err(fail(2, "option_not_valid_for_command"));
            }
        }
        Ok(())
    }
}
pub fn duration(raw: &str) -> Result<Duration> {
    let (n, m) = if let Some(s) = raw.strip_suffix("ms") {
        (s, 1)
    } else if let Some(s) = raw.strip_suffix('s') {
        (s, 1000)
    } else if let Some(s) = raw.strip_suffix('m') {
        (s, 60_000)
    } else {
        (raw, 1000)
    };
    let ms = n
        .parse::<u64>()
        .map_err(input_error)?
        .checked_mul(m)
        .ok_or_else(|| fail(2, "invalid_timeout"))?;
    if ms == 0 || ms > 3_600_000 {
        return Err(fail(2, "invalid_timeout"));
    }
    Ok(Duration::from_millis(ms))
}
pub fn absolute(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(fail(2, "absolute_path_required"));
    }
    Ok(())
}
pub fn revision(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn sanitize(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

const MAX_ERROR_DETAIL_CHARS: usize = 240;

fn compact_detail(raw: &str) -> String {
    let one_line = raw
        .split_whitespace()
        .map(sanitize)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if one_line.chars().count() <= MAX_ERROR_DETAIL_CHARS {
        return one_line;
    }
    let mut shortened: String = one_line.chars().take(MAX_ERROR_DETAIL_CHARS - 1).collect();
    shortened.push('…');
    shortened
}
pub fn redact(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, v) in map.iter_mut() {
                if [
                    "password",
                    "token",
                    "credential",
                    "secret",
                    "enrollment",
                    "certificate",
                ]
                .iter()
                .any(|k| key.contains(k))
                    && (v.is_string() || v.is_null())
                {
                    *v = json!({"configured":!v.is_null() && v.as_str().is_none_or(|s|!s.is_empty())});
                } else {
                    redact(v);
                }
            }
        }
        Value::Array(a) => {
            for v in a {
                redact(v)
            }
        }
        Value::String(s) => *s = sanitize(s),
        _ => (),
    }
}
pub fn emit(product: &str, command: &str, format: &str, result: &Result<Value>) -> u8 {
    let (exit, mut value) = match result {
        Ok(v) => (
            0,
            json!({"schema_version":1,"product":product,"command":command,"ok":true,"result":v}),
        ),
        Err(e) => (
            e.exit,
            json!({"schema_version":1,"product":product,"command":command,"ok":false,"error":{"code":e.code,"message":failure_message(e.code),"step":e.step,"detail":e.detail,"retryable":matches!(e.exit,5|6|9),"committed":e.committed,"transaction_id":e.transaction_id,"next_step":failure_next_step(product, e)}}),
        ),
    };
    if let Ok(Value::Object(fields)) = result {
        for (key, field) in fields {
            if !["schema_version", "product", "command", "ok", "result"].contains(&key.as_str()) {
                value[key] = field.clone();
            }
        }
    }
    if command == "status" && value["ok"] == false {
        value["next_steps"] = json!([
            format!("{product} setup"),
            format!("{product} status"),
            format!("{product} service status"),
            format!("{product} logs")
        ]);
    }
    redact(&mut value);
    // Every finite command emits exactly one object. Never interpolate untrusted text.
    let encoded = if format == "human"
        && let Err(error) = result
    {
        Ok(human_failure(product, error))
    } else if format == "human" {
        serde_json::to_string_pretty(&value)
    } else {
        serde_json::to_string(&value)
    };
    if writeln!(io::stdout().lock(), "{}", encoded.unwrap_or_default()).is_err() {
        return if exit == 0 { 11 } else { exit };
    }
    exit
}

pub fn requested_error_format(raw: &[String]) -> &'static str {
    if raw.iter().any(|argument| argument == "--json") {
        return "json";
    }
    raw.windows(2)
        .find_map(|pair| {
            (["--format", "--output"].contains(&pair[0].as_str())
                && ["json", "ndjson"].contains(&pair[1].as_str()))
            .then_some(if pair[1] == "ndjson" {
                "ndjson"
            } else {
                "json"
            })
        })
        .unwrap_or("human")
}

fn human_failure(product: &str, error: &Failure) -> String {
    let location = error
        .step
        .map(|step| format!(" at {step}"))
        .unwrap_or_default();
    let mut message = format!(
        "Error [{}]{}: {}",
        error.code,
        location,
        failure_message(error.code)
    );
    if let Some(detail) = error.detail.as_deref() {
        message.push_str("\nReason: ");
        message.push_str(detail);
    }
    message.push_str("\nNext: ");
    message.push_str(&failure_next_step(product, error));
    message
}

fn failure_next_step(product: &str, error: &Failure) -> String {
    match error.code {
        "administrator_privileges_required" | "elevation_cancelled" | "elevation_failed" => {
            format!("Approve Windows administrator elevation, then run `{product} setup` again.")
        }
        "protected_input_required"
        | "protected_input_timeout"
        | "interactive_terminal_required" => {
            format!(
                "Run `{product} setup` interactively, or provide the documented JSON through stdin."
            )
        }
        "unknown_command"
        | "unknown_option"
        | "option_not_valid_for_command"
        | "missing_option_value"
        | "missing_required_option"
        | "duplicate_option"
        | "invalid_format"
        | "invalid_timeout"
        | "conflicting_input_modes"
        | "conflicting_input_sources" => format!("Run `{product} --help` and correct the command."),
        "awaiting_configuration"
        | "awaiting_pairing"
        | "no_pairing_transaction"
        | "pairing_transaction_missing" => {
            format!("Run `{product} setup` to configure and pair this client.")
        }
        "credential_rejected" | "pairing_authorization_rejected" | "pairing_rejected" => {
            format!("Create a new pairing code on the server, then run `{product} setup` again.")
        }
        "pairing_postcondition_unconfirmed" | "invalid_input" | "invalid_server_origin" => {
            format!("Check the Server address and pairing code, then run `{product} setup` again.")
        }
        "server_unavailable" | "server_unavailable_or_untrusted" | "pairing_server_unavailable" => {
            format!(
                "Check the Server URL, TLS certificate, and network, then retry `{product} setup`."
            )
        }
        "service_not_installed" => {
            format!("Run `{product} setup` to install and verify the service.")
        }
        "service_action_denied" => {
            format!("Run `{product} setup` from an administrator or root terminal.")
        }
        "connection_unconfirmed" | "verification_requires_running_service" => {
            format!("Run `{product} service status`, then `{product} logs`.")
        }
        "permission_denied" => {
            format!("Run `{product} setup` from an administrator or root terminal.")
        }
        "invalid_configuration" | "unsafe_or_corrupt_state" => {
            format!("Run `{product} doctor`; repair the reported configuration or state problem.")
        }
        _ if error.exit == 9 => "Inspect pairing status and resume the same transaction.".into(),
        _ if error.exit == 5 => "Stop the service and retry the same command.".into(),
        _ => format!("Run `{product} doctor` for the focused diagnostic checks."),
    }
}

fn failure_message(code: &str) -> &'static str {
    match code {
        "absolute_path_required" => "The selected path must be absolute and normalized.",
        "awaiting_configuration" => "The client has not been configured yet.",
        "awaiting_pairing" => "The client has not completed server pairing yet.",
        "configuration_already_exists" => "A configuration already exists at the selected path.",
        "conflicting_input_modes" | "conflicting_input_sources" => {
            "More than one Setup input mode was selected."
        }
        "credential_rejected" | "pairing_authorization_rejected" | "pairing_rejected" => {
            "The server rejected the pairing credential."
        }
        "duplicate_option" => "The same command option was provided more than once.",
        "interactive_terminal_required" | "terminal_unavailable" => {
            "Interactive Setup requires an attached terminal."
        }
        "invalid_format" => "The output format must be human, json, or ndjson.",
        "invalid_input" => "The supplied input is incomplete or invalid.",
        "invalid_server_origin" => "The Server address must be a valid HTTPS origin.",
        "invalid_timeout" => "The timeout must be greater than zero and no more than one hour.",
        "missing_option_value" => "A command option is missing its value.",
        "missing_required_option" => "A required command option was not supplied.",
        "no_pairing_transaction" | "pairing_transaction_missing" => {
            "There is no saved pairing transaction to resume."
        }
        "option_not_valid_for_command" => "This option is not valid for the selected command.",
        "pairing_expired" => "The pairing request expired before authorization completed.",
        "pairing_protocol_unsupported" | "unsupported_protocol_or_platform" => {
            "The client and server do not support a compatible protocol or platform."
        }
        "pairing_server_unavailable" | "server_unavailable" | "server_unavailable_or_untrusted" => {
            "The server could not be reached or its TLS identity could not be trusted."
        }
        "protected_input_required" => {
            "Setup needs protected input from an interactive prompt or stdin."
        }
        "protected_input_timeout" => "Setup timed out while waiting for protected input.",
        "service_config_mismatch" => {
            "The selected configuration path does not match the installed service registration."
        }
        "invalid_configuration" => "The configuration failed validation.",
        "unsafe_or_corrupt_state" => {
            "The selected configuration or protected state is missing, unsafe, or corrupt."
        }
        "pairing_postcondition_unconfirmed" => {
            "Pairing returned without a durable active identity."
        }
        "service_not_installed" => "The operating-system service is not installed.",
        "service_registration_mismatch" => {
            "The installed service points to an unexpected executable or configuration path."
        }
        "unsafe_service_registration" => {
            "The installed service registration failed ownership or file-safety checks."
        }
        "service_manager_unavailable" => {
            "The operating-system service manager could not be queried."
        }
        "service_action_denied" => {
            "The operating-system service manager rejected the requested change; administrator privileges may be required."
        }
        "startup_policy_unconfirmed" => {
            "The requested service startup policy was not observed after the change."
        }
        "service_state_unconfirmed" => "The service did not reach the requested state.",
        "verification_requires_running_service" => {
            "Connection verification was requested, but the service is not running."
        }
        "connection_unconfirmed" => {
            "The client did not report a healthy connection before the timeout."
        }
        "permission_denied" => "The operation was denied by the operating system.",
        "busy" => "The client state or service is currently in use.",
        "service_timeout" => {
            "The service manager did not reach the requested state before the timeout."
        }
        "invalid_confirmation" => "The response must be yes or no.",
        "administrator_privileges_required" => {
            "Setup must run with Windows administrator privileges."
        }
        "elevation_cancelled" => "Windows administrator elevation was cancelled.",
        "elevation_failed" => "Windows could not start the elevated Setup process.",
        "unknown_command" => "The requested command is not recognized.",
        "unknown_option" => "The requested command option is not recognized.",
        _ => "The operation failed; error.code identifies the exact machine-readable reason.",
    }
}

#[cfg(windows)]
pub enum WindowsSetupElevation {
    Continue,
    ChildExited(u8),
}

#[cfg(windows)]
pub fn prepare_windows_setup_elevation(
    raw: &[String],
    interactive: bool,
    installer_session: bool,
    elevated_child: bool,
) -> Result<WindowsSetupElevation> {
    let elevated = windows_is_elevated()?;
    if !interactive {
        return if elevated {
            Ok(WindowsSetupElevation::Continue)
        } else {
            Err(fail(7, "administrator_privileges_required").at_step("configuration"))
        };
    }
    if elevated_child {
        return if elevated {
            Ok(WindowsSetupElevation::Continue)
        } else {
            Err(fail(7, "elevation_failed").at_step("configuration"))
        };
    }
    if installer_session || !elevated {
        return windows_relaunch_elevated(raw).map(WindowsSetupElevation::ChildExited);
    }
    Ok(WindowsSetupElevation::Continue)
}

#[cfg(windows)]
pub fn pause_installer_setup() {
    if io::stdin().is_terminal() {
        eprintln!("Press Enter to close Setup.");
        let mut line = String::new();
        let _ = io::stdin().read_line(&mut line);
    }
}

#[cfg(windows)]
struct OwnedWindowsHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for OwnedWindowsHandle {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
fn windows_is_elevated() -> Result<bool> {
    use std::{ffi::c_void, mem::size_of, ptr::null_mut};
    use windows_sys::Win32::{
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(fail(6, "elevation_failed").with_detail(std::io::Error::last_os_error()));
    }
    let token = OwnedWindowsHandle(token);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0;
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            &mut elevation as *mut TOKEN_ELEVATION as *mut c_void,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(fail(6, "elevation_failed").with_detail(std::io::Error::last_os_error()));
    }
    Ok(elevation.TokenIsElevated != 0)
}

#[cfg(windows)]
fn windows_relaunch_elevated(raw: &[String]) -> Result<u8> {
    use std::{ffi::OsStr, mem::size_of, os::windows::ffi::OsStrExt};
    use windows_sys::Win32::{
        Foundation::{ERROR_CANCELLED, WAIT_OBJECT_0},
        System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject},
        UI::{
            Shell::{
                SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
            },
            WindowsAndMessaging::SW_SHOWNORMAL,
        },
    };

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    let executable =
        std::env::current_exe().map_err(|error| fail(6, "elevation_failed").with_detail(error))?;
    let mut child_args = raw.to_vec();
    child_args.push("--elevated-setup-child".into());
    let parameters = child_args
        .iter()
        .map(|argument| windows_quote_argument(argument))
        .collect::<Vec<_>>()
        .join(" ");
    let verb = wide(OsStr::new("runas"));
    let executable = wide(executable.as_os_str());
    let parameters = wide(OsStr::new(&parameters));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: verb.as_ptr(),
        lpFile: executable.as_ptr(),
        lpParameters: parameters.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..SHELLEXECUTEINFOW::default()
    };
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        let failure = if code == ERROR_CANCELLED {
            fail(7, "elevation_cancelled")
        } else {
            fail(6, "elevation_failed").with_detail(std::io::Error::from_raw_os_error(code as i32))
        };
        return Err(failure.at_step("configuration"));
    }
    if info.hProcess.is_null() {
        return Err(fail(6, "elevation_failed").at_step("configuration"));
    }
    let process = OwnedWindowsHandle(info.hProcess);
    if unsafe { WaitForSingleObject(process.0, INFINITE) } != WAIT_OBJECT_0 {
        return Err(fail(6, "elevation_failed")
            .with_detail(std::io::Error::last_os_error())
            .at_step("configuration"));
    }
    let mut exit_code = 1;
    if unsafe { GetExitCodeProcess(process.0, &mut exit_code) } == 0 {
        return Err(fail(6, "elevation_failed")
            .with_detail(std::io::Error::last_os_error())
            .at_step("configuration"));
    }
    Ok(u8::try_from(exit_code).unwrap_or(1))
}

#[cfg(windows)]
fn windows_quote_argument(argument: &str) -> String {
    if !argument.is_empty()
        && !argument
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        return argument.into();
    }
    let mut quoted = String::from("\"");
    let mut backslashes = 0usize;
    for character in argument.chars() {
        if character == '\\' {
            backslashes += 1;
        } else {
            quoted.extend(std::iter::repeat_n('\\', backslashes));
            if character == '"' {
                quoted.extend(std::iter::repeat_n('\\', backslashes + 1));
            }
            backslashes = 0;
            quoted.push(character);
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

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
pub fn stdin_document<T: serde::de::DeserializeOwned + Send + 'static>(
    timeout: Duration,
) -> Result<T> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = (|| {
            let mut bytes = Vec::new();
            io::stdin()
                .lock()
                .take(65537)
                .read_to_end(&mut bytes)
                .map_err(input_error)?;
            if bytes.len() > 65536 {
                bytes.fill(0);
                return Err(fail(2, "input_too_large"));
            }
            let result = serde_json::from_slice(&bytes).map_err(input_error);
            bytes.fill(0);
            result
        })();
        let _ = tx.send(result);
    });
    rx.recv_timeout(timeout)
        .map_err(|_| fail(9, "protected_input_timeout"))?
}
pub fn prompt(label: &str, secret: bool) -> Result<String> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err(fail(2, "interactive_terminal_required"));
    }
    eprint!("{label}: ");
    io::stderr().flush().map_err(input_error)?;
    #[cfg(unix)]
    {
        struct EchoGuard(Option<String>);
        impl Drop for EchoGuard {
            fn drop(&mut self) {
                if let Some(mode) = &self.0 {
                    let _ = Command::new("/bin/stty")
                        .arg(mode)
                        .stdin(Stdio::inherit())
                        .status();
                    eprintln!();
                }
            }
        }
        let mode = if secret {
            let o = Command::new("/bin/stty")
                .arg("-g")
                .stdin(Stdio::inherit())
                .output()
                .map_err(input_error)?;
            if !o.status.success() {
                return Err(fail(2, "terminal_unavailable"));
            }
            if !Command::new("/bin/stty")
                .arg("-echo")
                .stdin(Stdio::inherit())
                .status()
                .map_err(input_error)?
                .success()
            {
                return Err(fail(2, "terminal_unavailable"));
            }
            Some(
                String::from_utf8(o.stdout)
                    .map_err(input_error)?
                    .trim()
                    .into(),
            )
        } else {
            None
        };
        let _guard = EchoGuard(mode);
        let mut value = String::new();
        io::stdin().read_line(&mut value).map_err(input_error)?;
        if value.len() > 65536 {
            return Err(fail(2, "input_too_large"));
        }
        Ok(value.trim_end_matches(['\r', '\n']).into())
    }
    #[cfg(windows)]
    {
        if secret {
            let o=Command::new("powershell.exe").args(["-NoProfile","-Command","$s=Read-Host -AsSecureString; $p=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($s); try {[Console]::Write([Runtime.InteropServices.Marshal]::PtrToStringBSTR($p))} finally {[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p)}"]).stdin(Stdio::inherit()).output().map_err(input_error)?;
            if !o.status.success() {
                return Err(fail(2, "terminal_unavailable"));
            }
            String::from_utf8(o.stdout).map_err(input_error)
        } else {
            let mut s = String::new();
            io::stdin().read_line(&mut s).map_err(input_error)?;
            Ok(s.trim_end_matches(['\r', '\n']).into())
        }
    }
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
        // Commands have fixed executables/verbs. No shell, no user-supplied service names.
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| fail(6, "service_manager_unavailable").with_detail(error))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| fail(8, "output_pipe_unavailable"))?;
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout
                .take(4 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        });
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| fail(8, "output_pipe_unavailable"))?;
        let stderr_reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        });
        let deadline = Instant::now() + timeout;
        loop {
            if child.try_wait().map_err(storage_error)?.is_some() {
                let status = child.wait().map_err(storage_error)?;
                let bytes = reader
                    .join()
                    .map_err(|_| fail(8, "output_reader_unavailable"))?
                    .map_err(storage_error)?;
                let stderr = stderr_reader
                    .join()
                    .map_err(|_| fail(8, "output_reader_unavailable"))?
                    .map_err(storage_error)?;
                if bytes.len() > 4 * 1024 * 1024 || stderr.len() > 1024 * 1024 {
                    return Err(fail(8, "output_budget_exceeded"));
                }
                return Ok(std::process::Output {
                    status,
                    stdout: bytes,
                    stderr,
                });
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(fail(9, "service_timeout"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
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
                self.capture("/bin/launchctl", &["bootout", &target], args.timeout)?
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
                // Legacy text logs may predate CLI redaction. Suppress secret-bearing lines.
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
            let mut file = std::fs::File::open(path).map_err(storage_error)?;
            let held = file.metadata().map_err(storage_error)?;
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

pub fn follow_logs(product: &str, service: &Service, mut args: Args) -> u8 {
    if let Err(error) = args.validate_options(&["--tail", "--since", "--follow"]) {
        return emit(product, "logs", "ndjson", &Err(error));
    }
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return 8,
    };
    rt.block_on(async {let deadline=tokio::time::Instant::now()+args.timeout;loop {
        let result=service.logs(&args);
        match result {
            Err(e)=>return emit(product,"logs","ndjson",&Err(e)),
            Ok(value)=>if let Some(entries)=value["entries"].as_array(){for entry in entries {
                if let Some(cursor)=entry["cursor"].as_str(){args.options.insert("--log-cursor".into(),cursor.into());}
                let code=emit(product,"logs","ndjson",&Ok(entry.clone()));if code!=0{return code;}
            }},
        }
        tokio::select!{_=tokio::signal::ctrl_c()=>return 130,_=tokio::time::sleep_until(deadline)=>return 0,_=tokio::time::sleep(Duration::from_secs(1))=>{}}
    }})
}

#[cfg(not(target_os = "linux"))]
fn log_message(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    if [
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
    }
}

#[cfg(test)]
mod concise_error_tests {
    use super::*;

    #[test]
    fn details_are_single_line_and_bounded() {
        let raw = format!("first line\nsecond\tline {}", "x".repeat(400));
        let detail = compact_detail(&raw);
        assert!(!detail.contains('\n') && !detail.contains('\t'));
        assert!(detail.chars().count() <= MAX_ERROR_DETAIL_CHARS);
        assert!(detail.ends_with('…'));
    }

    #[test]
    fn human_failures_keep_only_actionable_fields() {
        let error = fail(7, "administrator_privileges_required")
            .at_step("configuration")
            .with_detail("Access denied\nwhile opening protected state");
        let rendered = human_failure("sample-client", &error);
        assert_eq!(rendered.lines().count(), 3);
        assert!(rendered.contains("administrator_privileges_required"));
        assert!(rendered.contains("Access denied while opening protected state"));
        assert!(rendered.contains("sample-client setup"));
        assert!(!rendered.contains("schema_version") && !rendered.contains("transaction_id"));
    }

    #[test]
    fn parse_errors_default_to_human_but_honor_machine_output_requests() {
        assert_eq!(requested_error_format(&["--bad".into()]), "human");
        assert_eq!(
            requested_error_format(&["--format".into(), "json".into(), "--bad".into()]),
            "json"
        );
        assert_eq!(requested_error_format(&["--json".into()]), "json");
    }

    #[cfg(windows)]
    #[test]
    fn elevation_arguments_follow_windows_quoting_rules() {
        assert_eq!(windows_quote_argument("setup"), "setup");
        assert_eq!(windows_quote_argument(""), "\"\"");
        assert_eq!(
            windows_quote_argument(r#"C:\Program Files\Client\"#),
            r#""C:\Program Files\Client\\""#
        );
        assert_eq!(windows_quote_argument(r#"a"b"#), r#""a\"b""#);
    }
}
