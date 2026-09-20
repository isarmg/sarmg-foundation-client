//! Versioned desktop CLI and service lifecycle. Product commands and state machines remain product-owned.
#![allow(unsafe_code)]
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};
#[cfg(unix)]
use zeroize::Zeroize;
use zeroize::Zeroizing;

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

/// Default repeated Setup choices to the service's current intent. A missing
/// registration is a first installation and therefore defaults to enabled and
/// running; an existing registration is never silently re-enabled or started.
pub fn setup_service_intent(status: &Value) -> (bool, bool) {
    if !status["installed"].as_bool().unwrap_or(false) {
        return (true, true);
    }
    let enabled = matches!(
        status["startup"].as_str(),
        Some("automatic" | "enabled" | "enabled-runtime")
    );
    let running = status["state"] == "running";
    (enabled, running)
}

/// Edit a product-owned JSON configuration in the user's terminal editor.
/// The caller remains responsible for schema validation and a revision-checked
/// atomic commit, so this helper cannot bypass product concurrency controls.
pub fn edit_json(current: &Value) -> Result<Value> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(fail(2, "interactive_terminal_required"));
    }
    let editor = std::env::var_os("VISUAL")
        .or_else(|| std::env::var_os("EDITOR"))
        .ok_or_else(|| fail(2, "editor_not_configured"))?;
    let mut file = tempfile::Builder::new()
        .prefix("sarmg-config-")
        .suffix(".json")
        .tempfile()
        .map_err(storage_error)?;
    serde_json::to_writer_pretty(file.as_file_mut(), current).map_err(storage_error)?;
    file.as_file_mut().write_all(b"\n").map_err(storage_error)?;
    file.as_file_mut().sync_all().map_err(storage_error)?;
    let status = Command::new(editor)
        .arg(file.path())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| fail(8, "editor_failed").with_detail(error))?;
    if !status.success() {
        return Err(fail(2, "editor_cancelled"));
    }
    let metadata = std::fs::symlink_metadata(file.path()).map_err(storage_error)?;
    if !metadata.file_type().is_file() {
        return Err(fail(8, "unsafe_or_corrupt_state"));
    }
    if metadata.len() > 1_048_576 {
        return Err(fail(2, "edited_configuration_too_large"));
    }
    let bytes = std::fs::read(file.path()).map_err(storage_error)?;
    serde_json::from_slice(&bytes).map_err(input_error)
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
        Ok(human_success(product, command, &value["result"]))
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
    if error.committed {
        message.push_str("\nInstallation: committed; saved configuration, identity, and service state were preserved.");
    }
    message.push_str("\nNext: ");
    message.push_str(&failure_next_step(product, error));
    message
}

fn human_success(product: &str, command: &str, result: &Value) -> String {
    let mut lines = vec![format!("{product} {command}: completed")];
    render_human_fields("", result, &mut lines, 0);
    lines.truncate(17);
    lines.join("\n")
}

fn render_human_fields(prefix: &str, value: &Value, lines: &mut Vec<String>, depth: usize) {
    if lines.len() >= 17 || depth > 2 {
        return;
    }
    match value {
        Value::Object(fields) => {
            for (key, field) in fields {
                if lines.len() >= 17 {
                    break;
                }
                let name = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                render_human_fields(&name, field, lines, depth + 1);
            }
        }
        Value::Array(items) => lines.push(format!("{prefix}: {} item(s)", items.len())),
        Value::String(item) => lines.push(format!("{prefix}: {item}")),
        Value::Bool(item) => lines.push(format!("{prefix}: {item}")),
        Value::Number(item) => lines.push(format!("{prefix}: {item}")),
        Value::Null if !prefix.is_empty() => lines.push(format!("{prefix}: none")),
        Value::Null => {}
    }
}

fn failure_next_step(product: &str, error: &Failure) -> String {
    match error.code {
        "administrator_privileges_required" | "elevation_cancelled" | "elevation_failed" => {
            format!("Use an administrator or root terminal, then run `{product} setup` again.")
        }
        "protected_input_required"
        | "protected_input_timeout"
        | "interactive_terminal_required"
        | "interactive_terminal_unavailable"
        | "terminal_mode_unavailable"
        | "interactive_input_timeout" => {
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
            format!(
                "Create or rotate the authorization code on the server, then run `{product} setup --interactive`."
            )
        }
        "pairing_postcondition_unconfirmed" | "invalid_input" | "invalid_server_origin" => {
            format!("Check the Server address and pairing code, then run `{product} setup` again.")
        }
        "server_unavailable" | "server_unavailable_or_untrusted" | "pairing_server_unavailable" => {
            format!(
                "Check the Server URL, TLS certificate, and network, then retry `{product} setup`."
            )
        }
        "pairing_expired" => {
            format!("Run `{product} setup` again; a new pairing transaction will be created.")
        }
        "pairing_endpoint_not_found" | "pairing_http_method_rejected" => {
            "Check the Server address and reverse-proxy routing, then retry Setup.".into()
        }
        "pairing_server_upgrade_required" | "pairing_protocol_unsupported" => {
            "Upgrade the older Client or Server according to the compatibility manifest.".into()
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
        "active_setup_input_requires_pair_replace" => {
            "This installation is already paired; new protected pairing input requires the explicit pair replace workflow."
        }
        "configuration_already_exists" => "A configuration already exists at the selected path.",
        "conflicting_input_modes" | "conflicting_input_sources" => {
            "More than one Setup input mode was selected."
        }
        "credential_rejected" | "pairing_authorization_rejected" | "pairing_rejected" => {
            "The server rejected the pairing credential."
        }
        "duplicate_option" => "The same command option was provided more than once.",
        "editor_cancelled" => "The configuration editor exited without accepting the change.",
        "editor_failed" => "The configured terminal editor could not be started.",
        "editor_not_configured" => {
            "Set VISUAL or EDITOR to a terminal editor before editing configuration."
        }
        "edited_configuration_too_large" => {
            "The edited configuration exceeds the one-megabyte limit."
        }
        "interactive_terminal_required" | "terminal_unavailable" => {
            "Interactive Setup requires an attached terminal."
        }
        "interactive_terminal_unavailable" => "The attached terminal could not be read or written.",
        "terminal_mode_unavailable" => {
            "The attached terminal could not enter protected input mode."
        }
        "interactive_input_cancelled" => "Interactive input was cancelled.",
        "interactive_input_timeout" => "Interactive input timed out.",
        "input_too_large" => "The supplied input exceeds the permitted size.",
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
        "pairing_endpoint_not_found" => {
            "The configured Server does not expose the required pairing endpoint."
        }
        "pairing_http_method_rejected" => {
            "The Server or reverse proxy rejected the HTTP method required for pairing."
        }
        "pairing_server_upgrade_required" => {
            "The Server requires a different pairing contract or a component upgrade."
        }
        "pairing_request_rejected" => "The Server rejected the pairing request.",
        "pairing_unexpected_http_status" => {
            "The Server returned an unexpected HTTP status during pairing."
        }
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
        "server_replacement_requires_pair_replace" => {
            "The requested Server differs from the active binding; use the explicit pair replace workflow."
        }
        "sunshine_certificate_selection_required" => {
            "Choose a discovered Sunshine public certificate, enter its absolute path, or explicitly select system trust."
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
            "Setup must run with administrator or root privileges."
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
static INTERACTIVE_PROMPT: Mutex<()> = Mutex::new(());

/// Read visible text directly from the process' controlling terminal.
///
/// `deadline` is absolute so time spent in earlier command phases is not
/// silently granted again. The read stops as soon as `max_bytes` is exceeded.
pub fn prompt_text(label: &str, max_bytes: usize, deadline: Instant) -> Result<String> {
    read_terminal(label, false, max_bytes, deadline).map(|value| value.to_string())
}

/// Read a secret directly from the controlling terminal without echoing it.
/// The allocation is erased when the returned value is dropped.
pub fn prompt_secret(
    label: &str,
    max_bytes: usize,
    deadline: Instant,
) -> Result<Zeroizing<String>> {
    read_terminal(label, true, max_bytes, deadline)
}

fn read_terminal(
    label: &str,
    secret: bool,
    max_bytes: usize,
    deadline: Instant,
) -> Result<Zeroizing<String>> {
    if max_bytes == 0 {
        return Err(fail(2, "input_too_large"));
    }
    let _prompt = INTERACTIVE_PROMPT
        .lock()
        .map_err(|_| fail(8, "interactive_terminal_unavailable"))?;
    #[cfg(unix)]
    return unix_terminal_input(label, secret, max_bytes, deadline);
    #[cfg(windows)]
    return windows_terminal_input(label, secret, max_bytes, deadline);
}

#[cfg(unix)]
static TERMINAL_SIGNAL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

#[cfg(unix)]
extern "C" fn terminal_signal_handler(signal: libc::c_int) {
    TERMINAL_SIGNAL.store(signal, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(unix)]
struct TerminalSignalGuard {
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

#[cfg(unix)]
impl TerminalSignalGuard {
    fn install() -> Result<Self> {
        TERMINAL_SIGNAL.store(0, std::sync::atomic::Ordering::SeqCst);
        let mut guard = Self { previous: vec![] };
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = terminal_signal_handler as *const () as usize;
            action.sa_flags = 0;
            unsafe { libc::sigemptyset(&mut action.sa_mask) };
            let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
            if unsafe { libc::sigaction(signal, &action, &mut previous) } != 0 {
                return Err(fail(2, "terminal_mode_unavailable")
                    .with_detail(std::io::Error::last_os_error()));
            }
            guard.previous.push((signal, previous));
        }
        Ok(guard)
    }
}

#[cfg(unix)]
impl Drop for TerminalSignalGuard {
    fn drop(&mut self) {
        for (signal, previous) in self.previous.iter().rev() {
            unsafe { libc::sigaction(*signal, previous, std::ptr::null_mut()) };
        }
        TERMINAL_SIGNAL.store(0, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(unix)]
struct UnixTerminalMode {
    fd: std::os::fd::RawFd,
    original: libc::termios,
}

#[cfg(unix)]
impl Drop for UnixTerminalMode {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
    }
}

#[cfg(unix)]
fn unix_terminal_input(
    label: &str,
    secret: bool,
    max_bytes: usize,
    deadline: Instant,
) -> Result<Zeroizing<String>> {
    use std::{fs::OpenOptions, os::fd::AsRawFd};

    let mut terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|error| fail(2, "interactive_terminal_required").with_detail(error))?;
    if !terminal.is_terminal() {
        return Err(fail(2, "interactive_terminal_required"));
    }
    let fd = terminal.as_raw_fd();
    let mut original: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
        return Err(
            fail(2, "terminal_mode_unavailable").with_detail(std::io::Error::last_os_error())
        );
    }
    let mut protected = original;
    protected.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG);
    protected.c_cc[libc::VMIN] = 0;
    protected.c_cc[libc::VTIME] = 0;
    let _signals = TerminalSignalGuard::install()?;
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &protected) } != 0 {
        return Err(
            fail(2, "terminal_mode_unavailable").with_detail(std::io::Error::last_os_error())
        );
    }
    let mode = UnixTerminalMode { fd, original };
    let suffix = if secret {
        " (input hidden; type or paste, then press Enter): "
    } else {
        ": "
    };
    terminal
        .write_all(format!("{label}{suffix}").as_bytes())
        .and_then(|_| terminal.flush())
        .map_err(|error| fail(2, "interactive_terminal_unavailable").with_detail(error))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(max_bytes.min(4096)));
    let result = 'input: loop {
        if TERMINAL_SIGNAL.load(std::sync::atomic::Ordering::SeqCst) != 0 {
            break Err(fail(130, "interactive_input_cancelled"));
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break Err(fail(9, "interactive_input_timeout"));
        };
        if remaining.is_zero() {
            break Err(fail(9, "interactive_input_timeout"));
        }
        let millis = remaining.as_millis().clamp(1, libc::c_int::MAX as u128) as libc::c_int;
        let mut event = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut event, 1, millis) };
        if ready == 0 {
            break Err(fail(9, "interactive_input_timeout"));
        }
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break Err(fail(2, "interactive_terminal_unavailable").with_detail(error));
        }
        if event.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            break Err(fail(2, "interactive_terminal_unavailable"));
        }
        let mut chunk = Zeroizing::new([0_u8; 256]);
        let count = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
        if count == 0 {
            break Err(fail(2, "interactive_input_cancelled"));
        }
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted
                || error.kind() == std::io::ErrorKind::WouldBlock
            {
                continue;
            }
            break Err(fail(2, "interactive_terminal_unavailable").with_detail(error));
        }
        for byte in &chunk[..count as usize] {
            match *byte {
                b'\r' | b'\n' => {
                    let value = std::mem::take(&mut *bytes);
                    match String::from_utf8(value) {
                        Ok(value) => break 'input Ok(Zeroizing::new(value)),
                        Err(error) => {
                            let mut invalid = error.into_bytes();
                            invalid.zeroize();
                            break 'input Err(fail(2, "invalid_input"));
                        }
                    }
                }
                3 => break 'input Err(fail(130, "interactive_input_cancelled")),
                8 | 127 => {
                    if let Some(removed) = bytes.pop() {
                        if removed & 0b1100_0000 == 0b1000_0000 {
                            while bytes
                                .last()
                                .is_some_and(|byte| byte & 0b1100_0000 == 0b1000_0000)
                            {
                                bytes.pop();
                            }
                            bytes.pop();
                        }
                        if !secret {
                            let _ = terminal.write_all(b"\x08 \x08");
                            let _ = terminal.flush();
                        }
                    }
                }
                byte if byte < 0x20 => {}
                byte => {
                    bytes.push(byte);
                    if bytes.len() > max_bytes {
                        unsafe { libc::tcflush(fd, libc::TCIFLUSH) };
                        break 'input Err(fail(2, "input_too_large"));
                    }
                    if !secret {
                        let _ = terminal.write_all(&[byte]);
                        let _ = terminal.flush();
                    }
                }
            }
        }
    };
    drop(mode);
    let _ = terminal.write_all(b"\r\n");
    let _ = terminal.flush();
    result
}

#[cfg(windows)]
fn windows_terminal_input(
    label: &str,
    secret: bool,
    max_bytes: usize,
    deadline: Instant,
) -> Result<Zeroizing<String>> {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt};
    use windows_sys::Win32::{
        Foundation::{
            GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING},
        System::{
            Console::{
                ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
                FlushConsoleInputBuffer, GetConsoleMode, INPUT_RECORD, KEY_EVENT,
                ReadConsoleInputW, SetConsoleMode, WriteConsoleW,
            },
            Threading::WaitForSingleObject,
        },
    };

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().collect()
    }
    fn open_console(name: &str, access: u32) -> Result<OwnedWindowsHandle> {
        let name: Vec<u16> = OsStr::new(name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            Err(fail(2, "interactive_terminal_required")
                .with_detail(std::io::Error::last_os_error()))
        } else {
            Ok(OwnedWindowsHandle(handle))
        }
    }
    fn write_console(handle: windows_sys::Win32::Foundation::HANDLE, units: &[u16]) -> Result<()> {
        let mut written = 0;
        if unsafe {
            WriteConsoleW(
                handle,
                units.as_ptr().cast(),
                units.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        } == 0
            || written != units.len() as u32
        {
            return Err(fail(2, "interactive_terminal_unavailable")
                .with_detail(std::io::Error::last_os_error()));
        }
        Ok(())
    }
    struct WindowsConsoleMode {
        handle: windows_sys::Win32::Foundation::HANDLE,
        original: u32,
    }
    impl Drop for WindowsConsoleMode {
        fn drop(&mut self) {
            unsafe { SetConsoleMode(self.handle, self.original) };
        }
    }

    let input = open_console("CONIN$", GENERIC_READ | GENERIC_WRITE)?;
    let output = open_console("CONOUT$", GENERIC_READ | GENERIC_WRITE)?;
    let mut original = 0;
    if unsafe { GetConsoleMode(input.0, &mut original) } == 0 {
        return Err(
            fail(2, "terminal_mode_unavailable").with_detail(std::io::Error::last_os_error())
        );
    }
    let protected = original & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
    if unsafe { SetConsoleMode(input.0, protected) } == 0 {
        return Err(
            fail(2, "terminal_mode_unavailable").with_detail(std::io::Error::last_os_error())
        );
    }
    let mode = WindowsConsoleMode {
        handle: input.0,
        original,
    };
    let suffix = if secret {
        " (input hidden; type or paste, then press Enter): "
    } else {
        ": "
    };
    write_console(output.0, &wide(&format!("{label}{suffix}")))?;
    let mut units = Zeroizing::new(Vec::<u16>::with_capacity(max_bytes.min(4096)));
    let mut utf8_bytes = 0_usize;
    let result = 'input: loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break Err(fail(9, "interactive_input_timeout"));
        };
        if remaining.is_zero() {
            break Err(fail(9, "interactive_input_timeout"));
        }
        let millis = remaining.as_millis().clamp(1, u32::MAX as u128) as u32;
        match unsafe { WaitForSingleObject(input.0, millis) } {
            WAIT_TIMEOUT => break Err(fail(9, "interactive_input_timeout")),
            WAIT_OBJECT_0 => {}
            _ => {
                break Err(fail(2, "interactive_terminal_unavailable")
                    .with_detail(std::io::Error::last_os_error()));
            }
        }
        let mut record = INPUT_RECORD::default();
        let mut read = 0;
        if unsafe { ReadConsoleInputW(input.0, &mut record, 1, &mut read) } == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(995) {
                break Err(fail(130, "interactive_input_cancelled"));
            }
            break Err(fail(2, "interactive_terminal_unavailable").with_detail(error));
        }
        if read == 0 {
            break Err(fail(2, "interactive_input_cancelled"));
        }
        if record.EventType != KEY_EVENT as u16 {
            continue;
        }
        let key = unsafe { record.Event.KeyEvent };
        if key.bKeyDown == 0 {
            continue;
        }
        let unit = unsafe { key.uChar.UnicodeChar };
        if unit == 0 {
            continue;
        }
        for _ in 0..key.wRepeatCount.max(1) {
            match unit {
                10 => {}
                13 => match String::from_utf16(&units) {
                    Ok(value) => break 'input Ok(Zeroizing::new(value)),
                    Err(_) => break 'input Err(fail(2, "invalid_input")),
                },
                3 => break 'input Err(fail(130, "interactive_input_cancelled")),
                8 | 127 => {
                    if let Some(removed) = units.pop() {
                        if (0xDC00..=0xDFFF).contains(&removed)
                            && units
                                .last()
                                .is_some_and(|unit| (0xD800..=0xDBFF).contains(unit))
                        {
                            units.pop();
                            utf8_bytes = utf8_bytes.saturating_sub(4);
                        } else if !(0xD800..=0xDBFF).contains(&removed) {
                            utf8_bytes = utf8_bytes.saturating_sub(
                                char::from_u32(removed as u32)
                                    .map(char::len_utf8)
                                    .unwrap_or(0),
                            );
                        }
                        if !secret {
                            let _ = write_console(output.0, &[8, 32, 8]);
                        }
                    }
                }
                unit if unit < 0x20 => {}
                unit => {
                    let previous_high_surrogate = units
                        .last()
                        .is_some_and(|unit| (0xD800..=0xDBFF).contains(unit));
                    let encoded_bytes = if (0xD800..=0xDBFF).contains(&unit) {
                        if previous_high_surrogate {
                            break 'input Err(fail(2, "invalid_input"));
                        }
                        0
                    } else if (0xDC00..=0xDFFF).contains(&unit) {
                        if !previous_high_surrogate {
                            break 'input Err(fail(2, "invalid_input"));
                        }
                        4
                    } else {
                        if previous_high_surrogate {
                            break 'input Err(fail(2, "invalid_input"));
                        }
                        char::from_u32(unit as u32)
                            .map(char::len_utf8)
                            .ok_or_else(|| fail(2, "invalid_input"))?
                    };
                    units.push(unit);
                    utf8_bytes = utf8_bytes.saturating_add(encoded_bytes);
                    if utf8_bytes > max_bytes {
                        unsafe { FlushConsoleInputBuffer(input.0) };
                        break 'input Err(fail(2, "input_too_large"));
                    }
                    if !secret && encoded_bytes != 0 {
                        let start = if (0xDC00..=0xDFFF).contains(&unit) {
                            units.len() - 2
                        } else {
                            units.len() - 1
                        };
                        let _ = write_console(output.0, &units[start..]);
                    }
                }
            }
        }
    };
    drop(mode);
    let _ = write_console(output.0, &[13, 10]);
    result
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

    #[cfg(unix)]
    fn run_prompt_child(input: Option<&[u8]>, mode: &str) -> (String, libc::tcflag_t) {
        use std::{
            fs::File,
            os::{fd::FromRawFd, unix::process::CommandExt},
            process::Stdio,
        };

        let mut master_fd = -1;
        let mut slave_fd = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master_fd,
                    &mut slave_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let mut master = unsafe { File::from_raw_fd(master_fd) };
        let flags = unsafe { libc::fcntl(master_fd, libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(master_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        let slave = unsafe { File::from_raw_fd(slave_fd) };
        let mut initial: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(master_fd, &mut initial) }, 0);

        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .arg("--exact")
            .arg("concise_error_tests::unix_prompt_child")
            .arg("--nocapture")
            .env("SARMG_PROMPT_TEST", mode)
            .stdin(Stdio::null())
            .stdout(Stdio::from(slave.try_clone().expect("clone PTY slave")))
            .stderr(Stdio::from(slave.try_clone().expect("clone PTY slave")));
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() < 0 || libc::ioctl(slave_fd, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().expect("spawn prompt child");
        drop(slave);

        let started = Instant::now();
        let mut output = Vec::new();
        let mut sent = false;
        loop {
            let mut event = libc::pollfd {
                fd: master_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let _ = unsafe { libc::poll(&mut event, 1, 50) };
            if event.revents & libc::POLLIN != 0 {
                let mut chunk = [0_u8; 512];
                if let Ok(count) = master.read(&mut chunk) {
                    output.extend_from_slice(&chunk[..count]);
                }
            }
            if !sent
                && String::from_utf8_lossy(&output).contains("then press Enter")
                && let Some(input) = input
            {
                master.write_all(input).expect("write prompt input");
                master.flush().expect("flush prompt input");
                sent = true;
            }
            if child.try_wait().expect("poll prompt child").is_some() {
                // A child can exit after writing its result but before the
                // master side receives another POLLIN notification. Drain
                // the PTY once more so Darwin does not lose the final line.
                loop {
                    let mut chunk = [0_u8; 512];
                    match master.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(count) => output.extend_from_slice(&chunk[..count]),
                    }
                }
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(5));
        }
        let mut restored: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(master_fd, &mut restored) }, 0);
        assert_eq!(initial.c_lflag & libc::ECHO, restored.c_lflag & libc::ECHO);
        (
            String::from_utf8(output).expect("UTF-8 prompt transcript"),
            restored.c_lflag,
        )
    }

    #[cfg(unix)]
    #[test]
    fn unix_secret_prompt_is_bounded_cancellable_and_restores_echo() {
        let (success, _) = run_prompt_child(Some(b"private-value\n"), "success");
        assert!(success.contains("RESULT:13"), "transcript: {success:?}");
        assert!(!success.contains("private-value"));

        let (too_large, _) = run_prompt_child(Some(b"abcde"), "too-large");
        assert!(too_large.contains("RESULT:input_too_large"));
        assert!(!too_large.contains("abcde"));

        let (cancelled, _) = run_prompt_child(Some(&[3]), "cancelled");
        assert!(cancelled.contains("RESULT:interactive_input_cancelled"));

        let (timed_out, _) = run_prompt_child(None, "timeout");
        assert!(timed_out.contains("RESULT:interactive_input_timeout"));
    }

    #[cfg(unix)]
    #[test]
    fn unix_prompt_child() {
        let Ok(mode) = std::env::var("SARMG_PROMPT_TEST") else {
            return;
        };
        let (max_bytes, timeout) = match mode.as_str() {
            "success" => (64, Duration::from_secs(2)),
            "too-large" => (4, Duration::from_secs(2)),
            "cancelled" => (64, Duration::from_secs(2)),
            "timeout" => (64, Duration::from_millis(100)),
            _ => panic!("unknown prompt test mode"),
        };
        let result = prompt_secret("Authorization code", max_bytes, Instant::now() + timeout);
        match result {
            Ok(value) => println!("RESULT:{}", value.len()),
            Err(error) => println!("RESULT:{}", error.code),
        }
    }

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
        assert!(rendered.contains("administrator or root"));
        assert!(!rendered.contains("Windows"));
        assert!(rendered.contains("sample-client setup"));
        assert!(!rendered.contains("schema_version") && !rendered.contains("transaction_id"));
    }

    #[test]
    fn human_success_is_a_short_summary_instead_of_json() {
        let rendered = human_success(
            "sample-client",
            "status",
            &json!({"runtime":"running","queue":{"pending":2},"items":[1,2]}),
        );
        assert!(rendered.starts_with("sample-client status: completed\n"));
        assert!(rendered.contains("runtime: running"));
        assert!(rendered.contains("queue.pending: 2"));
        assert!(rendered.contains("items: 2 item(s)"));
        assert!(!rendered.contains('{'));
    }

    #[test]
    fn committed_setup_failure_explains_that_installation_was_preserved() {
        let mut error = fail(9, "connection_unconfirmed");
        error.committed = true;
        let rendered = human_failure("sample-client", &error);
        assert!(rendered.contains("Installation: committed"));
        assert!(rendered.contains("were preserved"));
    }

    #[test]
    fn repeated_setup_preserves_existing_service_intent() {
        assert_eq!(
            setup_service_intent(&json!({"installed":true,"startup":"disabled","state":"stopped"})),
            (false, false)
        );
        assert_eq!(
            setup_service_intent(
                &json!({"installed":true,"startup":"automatic","state":"running"})
            ),
            (true, true)
        );
        assert_eq!(
            setup_service_intent(&json!({"installed":false})),
            (true, true)
        );
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
