//! Versioned desktop CLI and service lifecycle. Product commands and state machines remain product-owned.
#[cfg(windows)]
#[allow(unsafe_code)]
mod elevation;
#[cfg(all(test, windows))]
use elevation::windows_quote_argument;
#[cfg(windows)]
pub use elevation::{
    WindowsSetupElevation, pause_installer_setup, prepare_windows_setup_elevation,
};
mod editor;
mod service;
pub use service::Service;
#[allow(unsafe_code)]
mod terminal;
pub use terminal::{prompt_secret, prompt_text};
mod tail;
pub use tail::{TailReadError, read_tail_lines};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{self, IsTerminal, Read, Write},
    path::Path,
    time::Duration,
};
#[cfg(all(test, unix))]
use std::{process::Command, time::Instant};
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

/// Product-owned descriptions for product error codes.
///
/// xcsc owns the output envelope and descriptions for errors raised by
/// its CLI, terminal and service primitives. Pairing protocols, remote API
/// semantics and recovery instructions remain in the product that defines
/// those contracts.
pub trait ProductErrorCatalog {
    fn message(&self, code: &'static str) -> Option<&'static str>;
    fn next_step(&self, product: &str, error: &Failure) -> Option<String>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoProductErrorCatalog;

impl ProductErrorCatalog for NoProductErrorCatalog {
    fn message(&self, _code: &'static str) -> Option<&'static str> {
        None
    }

    fn next_step(&self, _product: &str, _error: &Failure) -> Option<String> {
        None
    }
}

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
    /// Product option names deliberately stay out of xcsc: a product
    /// supplies only its valued and boolean option declarations. Product
    /// adapters validate the meaning of those values, including path policies,
    /// before dispatching commands. Common config/state paths are absolute.
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
                    "--format" | "--timeout" | "--config" | "--state" | "--tail" | "--since"
                    | "--instance-id" | "--event" | "--request-id" | "--task-id" | "--level" => {
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
        for name in ["--config", "--state"] {
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
        .map_err(|_| fail(2, "invalid_timeout"))?
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
/// VISUAL takes precedence over EDITOR. An existing literal executable path
/// is preserved; otherwise arguments use POSIX quoting on Unix and native
/// command-line quoting on Windows. No shell expansion is performed.
/// The edited path may be atomically replaced by the editor; the replacement
/// is opened without following links and read through one bounded handle.
pub fn edit_json(current: &Value) -> Result<Value> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(fail(2, "interactive_terminal_required"));
    }
    let editor = std::env::var_os("VISUAL")
        .or_else(|| std::env::var_os("EDITOR"))
        .ok_or_else(|| fail(2, "editor_not_configured"))?;
    let mut file = tempfile::Builder::new()
        .prefix("xcsc-config-")
        .suffix(".json")
        .tempfile()
        .map_err(storage_error)?;
    serde_json::to_writer_pretty(file.as_file_mut(), current).map_err(storage_error)?;
    file.as_file_mut().write_all(b"\n").map_err(storage_error)?;
    file.as_file_mut().sync_all().map_err(storage_error)?;
    let status = editor::run(&editor, file.path())?;
    if !status.success() {
        return Err(fail(2, "editor_cancelled"));
    }
    read_edited_json(file.path())
}

const MAX_EDITED_JSON_BYTES: u64 = 1_048_576;

fn read_edited_json(path: &Path) -> Result<Value> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).map_err(|error| {
        #[cfg(unix)]
        if error.raw_os_error() == Some(libc::ELOOP) {
            return fail(8, "unsafe_or_corrupt_state");
        }
        storage_error(error)
    })?;
    let metadata = file.metadata().map_err(storage_error)?;
    if !metadata.is_file() {
        return Err(fail(8, "unsafe_or_corrupt_state"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(fail(8, "unsafe_or_corrupt_state"));
        }
    }
    if metadata.len() > MAX_EDITED_JSON_BYTES {
        return Err(fail(2, "edited_configuration_too_large"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_EDITED_JSON_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(storage_error)?;
    if bytes.len() as u64 > MAX_EDITED_JSON_BYTES {
        return Err(fail(2, "edited_configuration_too_large"));
    }
    serde_json::from_slice(&bytes).map_err(input_error)
}
pub fn revision(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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
                let name: String = key
                    .chars()
                    .filter(char::is_ascii_alphanumeric)
                    .map(|character| character.to_ascii_lowercase())
                    .collect();
                if [
                    "password",
                    "token",
                    "credential",
                    "secret",
                    "enrollment",
                    "certificate",
                    "apikey",
                    "privatekey",
                ]
                .iter()
                .any(|k| name.contains(k))
                {
                    let configured = match &*v {
                        Value::Null => Some(false),
                        Value::String(value) => Some(!value.is_empty()),
                        Value::Array(value) => Some(!value.is_empty()),
                        Value::Object(value) => Some(
                            value
                                .get("configured")
                                .and_then(Value::as_bool)
                                .filter(|_| value.len() == 1)
                                .unwrap_or(!value.is_empty()),
                        ),
                        Value::Number(_) => Some(true),
                        Value::Bool(_) => None,
                    };
                    if let Some(configured) = configured {
                        *v = json!({"configured": configured});
                    }
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
pub fn emit<C: ProductErrorCatalog + ?Sized>(
    product: &str,
    command: &str,
    format: &str,
    result: &Result<Value>,
    product_errors: &C,
) -> u8 {
    let (exit, mut value) = match result {
        Ok(v) => (
            0,
            json!({"schema_version":1,"product":product,"command":command,"ok":true,"result":v}),
        ),
        Err(e) => (
            e.exit,
            json!({"schema_version":1,"product":product,"command":command,"ok":false,"error":{"code":e.code,"message":failure_message(e, product_errors),"step":e.step,"detail":e.detail,"retryable":matches!(e.exit,5|6|9),"committed":e.committed,"transaction_id":e.transaction_id,"next_step":failure_next_step(product, e, product_errors)}}),
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
        Ok(human_failure(product, error, product_errors))
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

fn human_failure<C: ProductErrorCatalog + ?Sized>(
    product: &str,
    error: &Failure,
    product_errors: &C,
) -> String {
    let location = error
        .step
        .map(|step| format!(" at {step}"))
        .unwrap_or_default();
    let mut message = format!(
        "Error [{}]{}: {}",
        error.code,
        location,
        failure_message(error, product_errors)
    );
    if let Some(detail) = error.detail.as_deref() {
        message.push_str("\nReason: ");
        message.push_str(detail);
    }
    if error.committed {
        message.push_str("\nInstallation: committed; saved configuration, identity, and service state were preserved.");
    }
    message.push_str("\nNext: ");
    message.push_str(&failure_next_step(product, error, product_errors));
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
                let key = sanitize(key);
                let name = if prefix.is_empty() {
                    key
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

fn failure_next_step<C: ProductErrorCatalog + ?Sized>(
    product: &str,
    error: &Failure,
    product_errors: &C,
) -> String {
    if let Some(next_step) = product_errors.next_step(product, error) {
        return next_step;
    }
    match error.code {
        "administrator_privileges_required" | "elevation_cancelled" | "elevation_failed" => {
            format!("Use an administrator or root terminal, then run `{product} setup` again.")
        }
        "elevated_setup_timeout" => format!(
            "Close any remaining administrator Setup window, then retry `{product} setup` with a suitable --timeout."
        ),
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
        "invalid_input" => format!("Check the supplied input, then retry `{product}`."),
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
        _ if error.exit == 9 => {
            "Check the operation status, then retry within a new deadline.".into()
        }
        _ if error.exit == 5 => "Resolve the reported conflict, then retry the command.".into(),
        _ => format!("Run `{product} doctor` for the focused diagnostic checks."),
    }
}

fn failure_message<C: ProductErrorCatalog + ?Sized>(
    error: &Failure,
    product_errors: &C,
) -> &'static str {
    product_errors
        .message(error.code)
        .unwrap_or_else(|| xcsc_failure_message(error.code))
}

fn xcsc_failure_message(code: &str) -> &'static str {
    match code {
        "absolute_path_required" => "The selected path must be absolute and normalized.",
        "configuration_already_exists" => "A configuration already exists at the selected path.",
        "conflicting_input_modes" | "conflicting_input_sources" => {
            "More than one Setup input mode was selected."
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
        "invalid_timeout" => "The timeout must be greater than zero and no more than one hour.",
        "missing_option_value" => "A command option is missing its value.",
        "missing_required_option" => "A required command option was not supplied.",
        "option_not_valid_for_command" => "This option is not valid for the selected command.",
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
        "elevated_setup_timeout" => {
            "The elevated Windows Setup process exceeded the command deadline."
        }
        "unknown_command" => "The requested command is not recognized.",
        "unknown_option" => "The requested command option is not recognized.",
        _ => "The operation failed; error.code identifies the exact machine-readable reason.",
    }
}

pub fn stdin_document<T: serde::de::DeserializeOwned + Send + 'static>(
    timeout: Duration,
) -> Result<T> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = (|| {
            let mut bytes = Zeroizing::new(Vec::new());
            io::stdin()
                .lock()
                .take(65537)
                .read_to_end(&mut bytes)
                .map_err(input_error)?;
            if bytes.len() > 65536 {
                return Err(fail(2, "input_too_large"));
            }
            serde_json::from_slice(&bytes).map_err(input_error)
        })();
        let _ = tx.send(result);
    });
    rx.recv_timeout(timeout)
        .map_err(|_| fail(9, "protected_input_timeout"))?
}
/// Query the active `.jsonl` and four unpadded `.jsonl.1` through `.jsonl.4`
/// archives emitted by the shared rotating sink, using caller-authorized reads.
/// Private storage and record schemas remain with their authoritative crates.
pub fn query_rotating_logs(
    args: &Args,
    stem: &str,
    mut read_part: impl FnMut(&str) -> Result<Option<Vec<u8>>>,
    mut decode: impl FnMut(&[u8]) -> Result<Vec<Value>>,
) -> Result<Value> {
    let tail = args
        .get("--tail")
        .unwrap_or("100")
        .parse::<usize>()
        .ok()
        .filter(|value| (1..=1000).contains(value))
        .ok_or_else(|| fail(2, "invalid_log_tail"))?;
    if stem.is_empty()
        || !stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(fail(2, "invalid_log_source"));
    }
    let mut entries = Vec::new();
    let mut available = false;
    let mut occurrences = BTreeMap::<String, usize>::new();
    for slot in (0..=4).rev() {
        let name = if slot == 0 {
            format!("{stem}.jsonl")
        } else {
            format!("{stem}.jsonl.{slot}")
        };
        let Some(bytes) = read_part(&name)? else {
            continue;
        };
        available = true;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err(fail(8, "log_budget_exceeded"));
        }
        let suffix = read_tail_lines(&mut std::io::Cursor::new(bytes), 1024 * 1024, 16 * 1024)
            .map_err(|_| fail(8, "log_integrity_or_budget_failed"))?;
        let decoded = decode(&suffix)?;
        if decoded.len() > 16384 {
            return Err(fail(8, "log_budget_exceeded"));
        }
        let mut decoded_bytes = 0usize;
        for mut entry in decoded {
            let serialized = serde_json::to_vec(&entry).map_err(storage_error)?;
            decoded_bytes = decoded_bytes
                .checked_add(serialized.len())
                .ok_or_else(|| fail(8, "log_budget_exceeded"))?;
            if serialized.len() > 16 * 1024 || decoded_bytes > 1024 * 1024 {
                return Err(fail(8, "log_budget_exceeded"));
            }
            let hash = revision(&serialized);
            let count = occurrences.entry(hash.clone()).or_default();
            *count += 1;
            let object = entry
                .as_object_mut()
                .ok_or_else(|| fail(8, "log_record_invalid"))?;
            object.insert("cursor".into(), json!(format!("{hash}:{count}")));
            entries.push(entry);
            if entries.len() > tail + 1 {
                entries.remove(0);
            }
        }
    }
    if !available {
        return Err(fail(10, "runtime_log_unavailable"));
    }
    if let Some(cursor) = args.get("--log-cursor") {
        let after = entries
            .iter()
            .position(|entry| entry["cursor"].as_str() == Some(cursor))
            .ok_or_else(|| fail(8, "log_follow_gap"))?
            + 1;
        entries.drain(..after);
        if entries.len() > tail {
            return Err(fail(8, "log_follow_gap"));
        }
    } else if entries.len() > tail {
        entries.drain(..entries.len() - tail);
    }
    Ok(json!({"entries":entries,"source":"private-runtime-log","retention_bytes":40*1024*1024}))
}

pub fn follow_logs<C: ProductErrorCatalog + ?Sized>(
    product: &str,
    service: &Service,
    args: Args,
    product_errors: &C,
) -> u8 {
    follow_log_source(product, args, product_errors, |args| service.logs(args))
}

/// Follow a product-authoritative bounded log source using common output and shutdown handling.
pub fn follow_log_source<C: ProductErrorCatalog + ?Sized>(
    product: &str,
    mut args: Args,
    product_errors: &C,
    mut source: impl FnMut(&Args) -> Result<Value>,
) -> u8 {
    if let Err(error) = args.validate_options(&[
        "--tail",
        "--since",
        "--follow",
        "--instance-id",
        "--event",
        "--request-id",
        "--task-id",
        "--level",
    ]) {
        return emit(product, "logs", "ndjson", &Err(error), product_errors);
    }
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return 8,
    };
    rt.block_on(async {let deadline=tokio::time::Instant::now()+args.timeout;loop {
        let result=source(&args);
        match result {
            Err(e)=>return emit(product,"logs","ndjson",&Err(e),product_errors),
            Ok(value)=>if let Some(entries)=value["entries"].as_array(){for entry in entries {
                if let Some(cursor)=entry["cursor"].as_str(){args.options.insert("--log-cursor".into(),cursor.into());}
                let code=emit(product,"logs","ndjson",&Ok(entry.clone()),product_errors);if code!=0{return code;}
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
#[allow(unsafe_code)]
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
            .arg("cli::concise_error_tests::unix_prompt_child")
            .arg("--nocapture")
            .env("XCSC_PROMPT_TEST", mode)
            .stdin(Stdio::null())
            .stdout(Stdio::from(slave.try_clone().expect("clone PTY slave")))
            .stderr(Stdio::from(slave.try_clone().expect("clone PTY slave")));
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() < 0
                    || libc::ioctl(slave_fd, libc::TIOCSCTTY as _, 0) < 0
                    || libc::tcsetpgrp(slave_fd, libc::getpgrp()) < 0
                {
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
        let transcript = String::from_utf8(output).expect("UTF-8 prompt transcript");
        assert!(
            transcript.contains("running 1 test") && transcript.contains("1 passed;"),
            "expected one successful prompt subprocess test: {transcript}"
        );
        (transcript, restored.c_lflag)
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
        let Ok(mode) = std::env::var("XCSC_PROMPT_TEST") else {
            return;
        };
        let (max_bytes, timeout) = match mode.as_str() {
            "success" | "high-fd" => (64, Duration::from_secs(2)),
            "too-large" => (4, Duration::from_secs(2)),
            "cancelled" => (64, Duration::from_secs(2)),
            "timeout" => (64, Duration::from_millis(100)),
            _ => panic!("unknown prompt test mode"),
        };
        let mut descriptors = Vec::new();
        if mode == "high-fd" {
            use std::os::fd::AsRawFd;
            loop {
                let file = std::fs::File::open("/dev/null").unwrap();
                let fd = file.as_raw_fd();
                descriptors.push(file);
                if fd >= libc::FD_SETSIZE as i32 {
                    break;
                }
            }
        }
        let result = prompt_secret("Authorization code", max_bytes, Instant::now() + timeout);
        match result {
            Ok(value) => println!("RESULT:{}", value.len()),
            Err(error) => println!(
                "RESULT:{}:{}",
                error.code,
                error.detail.as_deref().unwrap_or("no_detail")
            ),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unix_secret_prompt_accepts_descriptors_above_fd_setsize() {
        let (success, _) = run_prompt_child(Some(b"private-value\n"), "high-fd");
        assert!(success.contains("RESULT:13"), "transcript: {success:?}");
        assert!(!success.contains("private-value"));
    }

    #[test]
    fn product_options_keep_product_owned_value_validation() {
        for name in ["--file", "--bootstrap"] {
            let args =
                Args::parse(vec![name.into(), "product-value".into()], &[name], &[]).unwrap();
            assert_eq!(args.get(name), Some("product-value"));
            assert_eq!(
                absolute(Path::new(args.get(name).unwrap()))
                    .unwrap_err()
                    .code,
                "absolute_path_required"
            );
        }
        for name in ["--config", "--state"] {
            let error = Args::parse(vec![name.into(), "relative-path".into()], &[], &[])
                .err()
                .expect("common paths must be absolute");
            assert_eq!(error.code, "absolute_path_required");
        }
    }

    #[test]
    fn timeout_values_share_one_error_contract() {
        for value in [
            "",
            "invalid",
            "1.5s",
            "-1s",
            "0",
            "3601s",
            "18446744073709551616",
        ] {
            let error = duration(value).unwrap_err();
            assert_eq!(error.code, "invalid_timeout", "value: {value:?}");
            assert_eq!(error.exit, 2);
        }
        for (value, millis) in [("1ms", 1), ("2", 2000), ("3s", 3000), ("60m", 3_600_000)] {
            assert_eq!(duration(value).unwrap(), Duration::from_millis(millis));
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
    fn redaction_covers_nested_and_mixed_case_secret_fields() {
        let mut result = json!({
            "accessToken": "token-value",
            "ApiKey": {"value": "nested-key"},
            "api-key": "hyphenated-key",
            "pairingToken": 123456,
            "password": null,
            "passwordConfigured": false,
            "passwordStatus": {"configured": false},
            "credential": {"value": "nested-credential"},
            "certificateChain": ["certificate-bytes"],
            "status": "running",
            "state": [{"privateKey": "private-value"}]
        });
        redact(&mut result);
        let output = result.to_string();
        for secret in [
            "token-value",
            "nested-key",
            "hyphenated-key",
            "nested-credential",
            "certificate-bytes",
            "private-value",
        ] {
            assert!(!output.contains(secret));
        }
        assert_eq!(result["accessToken"], json!({"configured": true}));
        assert_eq!(result["ApiKey"], json!({"configured": true}));
        assert_eq!(result["api-key"], json!({"configured": true}));
        assert_eq!(result["pairingToken"], json!({"configured": true}));
        assert_eq!(result["password"], json!({"configured": false}));
        assert_eq!(result["passwordConfigured"], false);
        assert_eq!(result["passwordStatus"], json!({"configured": false}));
        assert_eq!(result["status"], "running");
    }

    #[test]
    fn human_failures_keep_only_actionable_fields() {
        let error = fail(7, "administrator_privileges_required")
            .at_step("configuration")
            .with_detail("Access denied\nwhile opening protected state");
        let rendered = human_failure("sample-client", &error, &NoProductErrorCatalog);
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
    fn human_success_removes_control_characters_from_dynamic_field_names() {
        let rendered = human_success(
            "sample-client",
            "status",
            &json!({"line\nname": {"field\r\u{1b}name": "ready"}}),
        );
        assert!(rendered.contains("linename.fieldname: ready"));
        assert!(!rendered.contains('\r') && !rendered.contains('\u{1b}'));
        assert_eq!(rendered.lines().count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn edited_json_reads_atomic_editor_replacement_and_rejects_special_files() {
        use std::{
            ffi::CString,
            os::unix::{ffi::OsStrExt, fs::symlink},
        };

        let directory = tempfile::tempdir().unwrap();
        let original = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        let replacement = directory.path().join("replacement.json");
        std::fs::write(&replacement, br#"{"name":"edited"}"#).unwrap();
        std::fs::rename(&replacement, original.path()).unwrap();
        assert_eq!(
            read_edited_json(original.path()).unwrap(),
            json!({"name":"edited"})
        );

        std::fs::write(
            original.path(),
            vec![b'x'; MAX_EDITED_JSON_BYTES as usize + 1],
        )
        .unwrap();
        assert_eq!(
            read_edited_json(original.path()).unwrap_err().code,
            "edited_configuration_too_large"
        );

        std::fs::remove_file(original.path()).unwrap();
        symlink("/dev/null", original.path()).unwrap();
        assert_eq!(
            read_edited_json(original.path()).unwrap_err().code,
            "unsafe_or_corrupt_state"
        );

        std::fs::remove_file(original.path()).unwrap();
        let path = CString::new(original.path().as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert_eq!(
            read_edited_json(original.path()).unwrap_err().code,
            "unsafe_or_corrupt_state"
        );
    }

    #[test]
    fn committed_setup_failure_explains_that_installation_was_preserved() {
        let mut error = fail(9, "connection_unconfirmed");
        error.committed = true;
        let rendered = human_failure("sample-client", &error, &NoProductErrorCatalog);
        assert!(rendered.contains("Installation: committed"));
        assert!(rendered.contains("were preserved"));
    }

    struct ExampleProductErrors;

    impl ProductErrorCatalog for ExampleProductErrors {
        fn message(&self, code: &'static str) -> Option<&'static str> {
            (code == "example_protocol_rejected").then_some("The example protocol rejected input.")
        }

        fn next_step(&self, product: &str, error: &Failure) -> Option<String> {
            (error.code == "example_protocol_rejected")
                .then(|| format!("Repair the example binding, then retry `{product}`."))
        }
    }

    #[test]
    fn product_error_catalog_owns_protocol_presentation() {
        let error = fail(7, "example_protocol_rejected");
        let rendered = human_failure("sample-client", &error, &ExampleProductErrors);
        assert!(rendered.contains("The example protocol rejected input."));
        assert!(rendered.contains("Repair the example binding"));

        assert_eq!(
            xcsc_failure_message("pairing_endpoint_not_found"),
            "The operation failed; error.code identifies the exact machine-readable reason."
        );
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

#[cfg(test)]
mod rotating_query_tests {
    use super::*;
    fn decode(bytes: &[u8]) -> Result<Vec<Value>> {
        bytes
            .split_inclusive(|byte| *byte == b'\n')
            .map(|line| serde_json::from_slice(line).map_err(|_| fail(8, "malformed_log")))
            .collect()
    }
    #[test]
    fn rotating_query_tails_in_order_and_detects_follow_gaps() {
        let mut args =
            Args::parse(vec!["logs".into(), "--tail".into(), "2".into()], &[], &[]).unwrap();
        let read = |name: &str| {
            Ok(match name {
                "client.jsonl.1" => Some(b"{\"event\":\"first\"}\n".to_vec()),
                "client.jsonl" => Some(b"{\"event\":\"second\"}\n{\"event\":\"third\"}\n".to_vec()),
                _ => None,
            })
        };
        let first = query_rotating_logs(&args, "client", read, decode).unwrap();
        assert_eq!(first["entries"][0]["event"], "second");
        assert_eq!(first["entries"][1]["event"], "third");
        args.options.insert(
            "--log-cursor".into(),
            first["entries"][0]["cursor"].as_str().unwrap().into(),
        );
        let next = query_rotating_logs(&args, "client", read, decode).unwrap();
        assert_eq!(next["entries"].as_array().unwrap().len(), 1);
        args.options
            .insert("--log-cursor".into(), "unavailable".into());
        assert_eq!(
            query_rotating_logs(&args, "client", read, decode)
                .unwrap_err()
                .code,
            "log_follow_gap"
        );
    }
    #[test]
    fn rotating_query_reads_all_physical_archives_and_follows_across_rotation() {
        let directory = tempfile::tempdir().unwrap();
        for (name, event) in [
            ("client.jsonl.4", "oldest"),
            ("client.jsonl.3", "older"),
            ("client.jsonl.2", "earlier"),
            ("client.jsonl.1", "previous"),
            ("client.jsonl", "current"),
            ("client.jsonl.01", "unrecognized"),
        ] {
            std::fs::write(
                directory.path().join(name),
                format!("{{\"event\":\"{event}\"}}\n"),
            )
            .unwrap();
        }
        let read = |name: &str| match std::fs::read(directory.path().join(name)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(storage_error(error)),
        };
        let mut args =
            Args::parse(vec!["logs".into(), "--tail".into(), "5".into()], &[], &[]).unwrap();
        let first = query_rotating_logs(&args, "client", read, decode).unwrap();
        let events: Vec<_> = first["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["event"].as_str().unwrap())
            .collect();
        assert_eq!(
            events,
            ["oldest", "older", "earlier", "previous", "current"]
        );
        args.options.insert(
            "--log-cursor".into(),
            first["entries"][4]["cursor"].as_str().unwrap().into(),
        );
        std::fs::remove_file(directory.path().join("client.jsonl.4")).unwrap();
        for (from, to) in [
            ("client.jsonl.3", "client.jsonl.4"),
            ("client.jsonl.2", "client.jsonl.3"),
            ("client.jsonl.1", "client.jsonl.2"),
            ("client.jsonl", "client.jsonl.1"),
        ] {
            std::fs::rename(directory.path().join(from), directory.path().join(to)).unwrap();
        }
        std::fs::write(
            directory.path().join("client.jsonl"),
            b"{\"event\":\"new\"}\n",
        )
        .unwrap();
        let next = query_rotating_logs(&args, "client", read, decode).unwrap();
        assert_eq!(next["entries"].as_array().unwrap().len(), 1);
        assert_eq!(next["entries"][0]["event"], "new");
    }

    #[test]
    fn rotating_query_rejects_invalid_tail_and_preserves_partial_line_errors() {
        let args = Args::parse(vec!["logs".into(), "--tail".into(), "0".into()], &[], &[]).unwrap();
        assert_eq!(
            query_rotating_logs(&args, "client", |_| Ok(None), decode)
                .unwrap_err()
                .code,
            "invalid_log_tail"
        );
        let args = Args::parse(vec!["logs".into()], &[], &[]).unwrap();
        let err = query_rotating_logs(
            &args,
            "client",
            |name| Ok((name == "client.jsonl").then(|| b"{\"secret\":\"private".to_vec())),
            decode,
        )
        .unwrap_err();
        assert_eq!(err.code, "malformed_log");
    }
}
