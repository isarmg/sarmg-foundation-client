//! Client-owned portable structured logging, redaction and bounded storage.
//! It has no server dependency, HTTP runtime or product logic.

#[cfg(unix)]
mod rotating;
#[cfg(unix)]
pub use rotating::RotatingLogFile;
#[cfg(windows)]
mod windows_rotating;
#[cfg(windows)]
pub use windows_rotating::{RotatingLogFile, WindowsLogAccess};

#[cfg(feature = "tracing")]
mod tracing_layer;
#[cfg(feature = "tracing")]
pub use tracing_layer::XcscStructuredLayer;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::io::{self, BufRead, Read, Write};

pub const MAX_RECORD_BYTES: usize = 16 * 1024;
pub const MAX_MESSAGE_BYTES: usize = 2048;
pub const MAX_IDENTIFIER_BYTES: usize = 128;

#[derive(Clone, Copy, Debug)]
pub struct LogRetention {
    /// Maximum bytes per active or archived file.
    pub file_bytes: u64,
    /// Between 1 and 32 archives, in addition to the active file.
    pub archives: u8,
}
impl Default for LogRetention {
    fn default() -> Self {
        Self {
            file_bytes: 8 * 1024 * 1024,
            archives: 4,
        }
    }
}

#[cfg(any(unix, windows))]
static PROCESS_SINK: std::sync::OnceLock<std::sync::Mutex<RotatingLogFile>> =
    std::sync::OnceLock::new();

/// Install one typed persistent sink after the application's state preflight.
/// A second installation is rejected, rather than silently replacing a writer.
#[cfg(any(unix, windows))]
pub fn install_rotating_file(sink: RotatingLogFile) -> Result<(), LogError> {
    PROCESS_SINK
        .set(std::sync::Mutex::new(sink))
        .map_err(|_| LogError::UnsafeStorage)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Client,
    /// Parsed when offline Clients inspect existing Server logs.
    Server,
    Instance,
}

/// Public templates are maintained here; products cannot override their
/// component, event, level or message while keeping a common event identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommonEvent {
    ConfigLoaded,
    InitializationCompleted,
    RuntimeStarted,
    ShutdownStarted,
    RuntimeStopped,
    DependencyUnavailable,
    TaskFailed,
    MaintenanceStarted,
    MaintenanceCompleted,
}
impl CommonEvent {
    #[cfg(feature = "tracing")]
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|event| event.definition().1 == name)
    }
    const ALL: [Self; 9] = [
        Self::ConfigLoaded,
        Self::InitializationCompleted,
        Self::RuntimeStarted,
        Self::ShutdownStarted,
        Self::RuntimeStopped,
        Self::DependencyUnavailable,
        Self::TaskFailed,
        Self::MaintenanceStarted,
        Self::MaintenanceCompleted,
    ];
    fn definition(self) -> (&'static str, &'static str, Level, &'static str) {
        match self {
            Self::ConfigLoaded => (
                "config",
                "common.config.loaded",
                Level::Info,
                "Current configuration loaded.",
            ),
            Self::InitializationCompleted => (
                "initialization",
                "common.initialization.completed",
                Level::Info,
                "First initialization completed.",
            ),
            Self::RuntimeStarted => (
                "runtime",
                "common.runtime.started",
                Level::Info,
                "Runtime started.",
            ),
            Self::ShutdownStarted => (
                "runtime",
                "common.runtime.shutdown_started",
                Level::Info,
                "Controlled shutdown started.",
            ),
            Self::RuntimeStopped => (
                "runtime",
                "common.runtime.stopped",
                Level::Info,
                "Runtime stopped.",
            ),
            Self::DependencyUnavailable => (
                "dependency",
                "common.dependency.unavailable",
                Level::Warn,
                "A required dependency is unavailable.",
            ),
            Self::TaskFailed => (
                "task",
                "common.task.failed",
                Level::Error,
                "A supervised task failed.",
            ),
            Self::MaintenanceStarted => (
                "maintenance",
                "common.maintenance.started",
                Level::Info,
                "Maintenance started.",
            ),
            Self::MaintenanceCompleted => (
                "maintenance",
                "common.maintenance.completed",
                Level::Info,
                "Maintenance completed.",
            ),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LogRecord {
    timestamp: String,
    level: Level,
    service: String,
    component: String,
    event: String,
    message: String,
    scope: Scope,
    #[serde(skip_serializing_if = "Option::is_none")]
    instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    instance_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<crate::error::RequestId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<crate::error::ErrorCode>,
    #[serde(skip_serializing_if = "Map::is_empty")]
    attributes: Map<String, Value>,
}

impl LogRecord {
    pub fn common_instance(
        service: &str,
        event: CommonEvent,
        instance_id: &str,
    ) -> Result<Self, LogError> {
        if !matches!(
            event,
            CommonEvent::DependencyUnavailable | CommonEvent::TaskFailed
        ) {
            return Err(LogError::InvalidRecord);
        }
        identifier(instance_id)?;
        let (component, name, level, message) = event.definition();
        Self::build(
            service,
            component,
            name,
            message,
            level,
            Some(instance_id.into()),
        )
    }
    pub fn common(service: &str, event: CommonEvent) -> Result<Self, LogError> {
        let (component, event, level, message) = event.definition();
        Self::build(service, component, event, message, level, None)
    }
    pub fn client(
        service: &str,
        component: &str,
        event: &str,
        message: &str,
        level: Level,
    ) -> Result<Self, LogError> {
        product_event(service, event)?;
        Self::build(service, component, event, message, level, None)
    }
    pub fn instance(
        service: &str,
        component: &str,
        event: &str,
        message: &str,
        level: Level,
        instance_id: &str,
    ) -> Result<Self, LogError> {
        product_event(service, event)?;
        identifier(instance_id)?;
        Self::build(
            service,
            component,
            event,
            message,
            level,
            Some(instance_id.into()),
        )
    }
    fn build(
        service: &str,
        component: &str,
        event: &str,
        message: &str,
        level: Level,
        instance_id: Option<String>,
    ) -> Result<Self, LogError> {
        identifier(service)?;
        identifier(component)?;
        identifier(event)?;
        if message.len() > MAX_MESSAGE_BYTES || message.chars().any(char::is_control) {
            return Err(LogError::InvalidRecord);
        }
        Ok(Self {
            timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            level,
            service: service.into(),
            component: component.into(),
            event: event.into(),
            message: sanitize_text(message),
            scope: if instance_id.is_some() {
                Scope::Instance
            } else {
                Scope::Client
            },
            instance_id,
            instance_type: None,
            request_id: None,
            task_id: None,
            error_code: None,
            attributes: Map::new(),
        })
    }
    pub fn with_instance_type(mut self, instance_type: &str) -> Result<Self, LogError> {
        if self.scope != Scope::Instance {
            return Err(LogError::InvalidRecord);
        }
        identifier(instance_type)?;
        self.instance_type = Some(instance_type.into());
        Ok(self)
    }
    pub fn with_request_id(mut self, request_id: &str) -> Result<Self, LogError> {
        self.request_id =
            Some(crate::error::RequestId::new(request_id).map_err(|_| LogError::InvalidRecord)?);
        Ok(self)
    }
    pub fn with_task_id(mut self, task_id: &str) -> Result<Self, LogError> {
        identifier(task_id)?;
        self.task_id = Some(task_id.into());
        Ok(self)
    }
    pub fn with_error_code(mut self, code: &str) -> Result<Self, LogError> {
        self.error_code =
            Some(crate::error::ErrorCode::new(code).map_err(|_| LogError::InvalidRecord)?);
        Ok(self)
    }
    pub fn with_attribute(mut self, key: &str, value: impl Into<Value>) -> Result<Self, LogError> {
        identifier(key)?;
        let mut attribute = json!({key: value.into()});
        redact(&mut attribute);
        self.attributes.extend(
            attribute
                .as_object_mut()
                .expect("one attribute object")
                .clone(),
        );
        self.json_line()?;
        Ok(self)
    }
    pub fn timestamp(&self) -> &str {
        &self.timestamp
    }
    pub fn level(&self) -> Level {
        self.level
    }
    pub fn scope(&self) -> Scope {
        self.scope
    }
    pub fn instance_id(&self) -> Option<&str> {
        self.instance_id.as_deref()
    }
    pub fn event(&self) -> &str {
        &self.event
    }
    pub fn json_line(&self) -> Result<Vec<u8>, LogError> {
        let mut limited = LimitedBuffer { bytes: Vec::new() };
        serde_json::to_writer(&mut limited, self).map_err(|error| {
            if error.is_io() {
                LogError::RecordTooLarge
            } else {
                LogError::InvalidRecord
            }
        })?;
        if limited.bytes.len() >= MAX_RECORD_BYTES {
            return Err(LogError::RecordTooLarge);
        }
        limited.bytes.push(b'\n');
        Ok(limited.bytes)
    }
    pub fn write_to(&self, output: &mut impl Write) -> Result<(), LogError> {
        output.write_all(&self.json_line()?)?;
        output.flush()?;
        Ok(())
    }
    /// Stderr is a stream sink. The service manager owns stream capture,
    /// retention and rotation; no application-owned file grows behind it.
    pub fn emit_stderr(&self) -> Result<(), LogError> {
        self.write_to(&mut io::stderr().lock())
    }
    /// Emit to the explicitly installed process sink, or to stderr when absent.
    /// Native background services install their persistent sink before work.
    pub fn emit(&self) -> Result<(), LogError> {
        #[cfg(any(unix, windows))]
        if let Some(sink) = PROCESS_SINK.get() {
            return sink
                .lock()
                .map_err(|_| LogError::UnsafeStorage)?
                .write(self);
        }
        self.emit_stderr()
    }
}

struct LimitedBuffer {
    bytes: Vec<u8>,
}
impl Write for LimitedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) >= MAX_RECORD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "log record exceeds its byte budget",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn identifier(value: &str) -> Result<(), LogError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
    {
        Err(LogError::InvalidRecord)
    } else {
        Ok(())
    }
}
fn product_event(service: &str, event: &str) -> Result<(), LogError> {
    if event
        .strip_prefix(service)
        .is_none_or(|suffix| !suffix.starts_with('.') || suffix.len() <= 1)
    {
        Err(LogError::InvalidRecord)
    } else {
        Ok(())
    }
}

/// Field names, including mixed case and separators, identify secrets. Never
/// put credentials in a non-secret field or an arbitrary internal error chain.
pub fn redact(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                let normalized: String = key
                    .chars()
                    .filter(char::is_ascii_alphanumeric)
                    .map(|c| c.to_ascii_lowercase())
                    .collect();
                if [
                    "password",
                    "token",
                    "secret",
                    "credential",
                    "privatekey",
                    "apikey",
                    "certificate",
                    "authorization",
                ]
                .iter()
                .any(|secret| normalized.contains(secret))
                {
                    if !value.is_boolean() {
                        let configured = match &*value {
                            Value::Null => false,
                            Value::String(value) => !value.is_empty(),
                            Value::Array(value) => !value.is_empty(),
                            Value::Object(value) => value
                                .get("configured")
                                .and_then(Value::as_bool)
                                .filter(|_| value.len() == 1)
                                .unwrap_or(!value.is_empty()),
                            _ => true,
                        };
                        *value = json!({"configured":configured});
                    }
                } else {
                    redact(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redact(value);
            }
        }
        Value::String(value) => *value = sanitize_text(value),
        _ => {}
    }
}

fn sanitize_text(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    if (value.contains("://") && value.contains('@'))
        || [
            "password=",
            "password:",
            "token=",
            "token:",
            "authorization:",
            "bearer ",
            "-----begin private key",
        ]
        .iter()
        .any(|pattern| lower.contains(pattern))
    {
        "[sensitive text redacted]".into()
    } else {
        value.chars().filter(|c| !c.is_control()).collect()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LogFilter<'a> {
    pub instance_id: Option<&'a str>,
    pub scope: Option<Scope>,
    pub since: Option<&'a str>,
    pub until: Option<&'a str>,
    pub minimum_level: Option<Level>,
    pub event: Option<&'a str>,
    pub request_id: Option<&'a str>,
    pub task_id: Option<&'a str>,
}

#[derive(Clone, Copy, Debug)]
pub struct QueryLimits {
    pub max_input_bytes: usize,
    pub max_records: usize,
}
impl Default for QueryLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024 * 1024,
            max_records: 1000,
        }
    }
}

/// Query exact structured fields with byte and result-count bounds. An
/// incomplete or malformed line is an error, never an empty success result.
pub fn query(
    mut reader: impl BufRead,
    filter: LogFilter<'_>,
    limits: QueryLimits,
) -> Result<Vec<LogRecord>, LogError> {
    if limits.max_input_bytes == 0 || limits.max_records == 0 {
        return Err(LogError::InvalidLimits);
    }
    let since = filter.since.map(parse_time).transpose()?;
    let until = filter.until.map(parse_time).transpose()?;
    if since.zip(until).is_some_and(|(since, until)| since > until) {
        return Err(LogError::InvalidLimits);
    }
    let mut result = Vec::new();
    let mut total = 0usize;
    loop {
        let mut line = Vec::new();
        (&mut reader)
            .take(MAX_RECORD_BYTES as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if line.is_empty() {
            break;
        }
        total = total
            .checked_add(line.len())
            .ok_or(LogError::QueryLimitExceeded)?;
        if total > limits.max_input_bytes {
            return Err(LogError::QueryLimitExceeded);
        }
        if line.len() > MAX_RECORD_BYTES {
            return Err(LogError::RecordTooLarge);
        }
        if line.last() != Some(&b'\n') {
            return Err(LogError::InvalidRecord);
        }
        let record = parse_record(&line)?;
        let time = parse_time(&record.timestamp)?;
        if filter
            .instance_id
            .is_none_or(|id| record.instance_id.as_deref() == Some(id))
            && filter.scope.is_none_or(|scope| record.scope == scope)
            && since.is_none_or(|since| time >= since)
            && until.is_none_or(|until| time <= until)
            && filter
                .minimum_level
                .is_none_or(|level| record.level >= level)
            && filter.event.is_none_or(|event| record.event == event)
            && filter.request_id.is_none_or(|id| {
                record
                    .request_id
                    .as_ref()
                    .map(crate::error::RequestId::as_str)
                    == Some(id)
            })
            && filter
                .task_id
                .is_none_or(|id| record.task_id.as_deref() == Some(id))
        {
            if result.len() >= limits.max_records {
                return Err(LogError::QueryLimitExceeded);
            }
            result.push(record);
        }
    }
    Ok(result)
}

fn parse_time(timestamp: &str) -> Result<DateTime<Utc>, LogError> {
    if !timestamp.ends_with('Z') {
        return Err(LogError::InvalidRecord);
    }
    DateTime::parse_from_rfc3339(timestamp)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| LogError::InvalidRecord)
}

fn parse_record(line: &[u8]) -> Result<LogRecord, LogError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Raw {
        timestamp: String,
        level: Level,
        service: String,
        component: String,
        event: String,
        message: String,
        scope: Scope,
        instance_id: Option<String>,
        instance_type: Option<String>,
        request_id: Option<crate::error::RequestId>,
        task_id: Option<String>,
        error_code: Option<crate::error::ErrorCode>,
        #[serde(default)]
        attributes: Map<String, Value>,
    }
    let raw: Raw = serde_json::from_slice(line).map_err(|_| LogError::InvalidRecord)?;
    parse_time(&raw.timestamp)?;
    if raw.event.starts_with("common.") {
        let common = CommonEvent::ALL
            .into_iter()
            .find(|event| event.definition().1 == raw.event)
            .ok_or(LogError::InvalidRecord)?;
        let definition = common.definition();
        if (raw.component.as_str(), raw.level, raw.message.as_str())
            != (definition.0, definition.2, definition.3)
            || (raw.scope == Scope::Instance
                && !matches!(
                    common,
                    CommonEvent::DependencyUnavailable | CommonEvent::TaskFailed
                ))
        {
            return Err(LogError::InvalidRecord);
        }
    } else {
        product_event(&raw.service, &raw.event)?;
    }
    if (raw.scope == Scope::Instance) != raw.instance_id.is_some()
        || (raw.scope != Scope::Instance && raw.instance_type.is_some())
    {
        return Err(LogError::InvalidRecord);
    }
    if let Some(id) = &raw.instance_id {
        identifier(id)?;
    }
    if let Some(kind) = &raw.instance_type {
        identifier(kind)?;
    }
    if let Some(id) = &raw.task_id {
        identifier(id)?;
    }
    let mut record = LogRecord::build(
        &raw.service,
        &raw.component,
        &raw.event,
        &raw.message,
        raw.level,
        raw.instance_id,
    )?;
    record.timestamp = raw.timestamp;
    record.scope = raw.scope;
    record.instance_type = raw.instance_type;
    record.request_id = raw.request_id;
    record.task_id = raw.task_id;
    record.error_code = raw.error_code;
    let mut attributes = Value::Object(raw.attributes);
    redact(&mut attributes);
    record.attributes = attributes
        .as_object_mut()
        .expect("attributes object")
        .clone();
    Ok(record)
}

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("structured log record does not satisfy the current contract")]
    InvalidRecord,
    #[error("structured log record exceeds its byte budget")]
    RecordTooLarge,
    #[error("structured log query exceeds its byte or record budget")]
    QueryLimitExceeded,
    #[error("structured log limits are invalid")]
    InvalidLimits,
    #[error("log storage must be a private directory with private regular files and one writer")]
    UnsafeStorage,
    #[error("log I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_records_keep_their_role_and_offline_queries_preserve_server_identity() {
        let record = LogRecord::client(
            "example",
            "maintenance",
            "example.phase",
            "Phase changed.",
            Level::Info,
        )
        .unwrap();
        let mut raw: Value = serde_json::from_slice(&record.json_line().unwrap()).unwrap();
        assert_eq!(raw["scope"], "client");
        raw["scope"] = Value::String("server".into());
        let bytes = serde_json::to_vec(&raw).unwrap();
        let parsed = query(&bytes[..], LogFilter::default(), QueryLimits::default()).unwrap();
        assert_eq!(parsed[0].scope(), Scope::Server);
        raw["scope"] = Value::String("client".into());
        raw["instance_type"] = Value::String("camera".into());
        let bytes = serde_json::to_vec(&raw).unwrap();
        assert!(query(&bytes[..], LogFilter::default(), QueryLimits::default()).is_err());
    }

    #[test]
    fn public_templates_and_product_records_share_one_exact_contract() {
        for event in CommonEvent::ALL {
            let record = LogRecord::common("example", event).unwrap();
            let line = record.json_line().unwrap();
            let parsed = query(&line[..], LogFilter::default(), QueryLimits::default()).unwrap();
            assert_eq!(parsed.len(), 1);
            assert_eq!(parsed[0].event(), record.event());
            assert_eq!(parsed[0].scope(), Scope::Client);
            assert!(record.timestamp().ends_with('Z'));
        }
        assert!(
            LogRecord::client(
                "example",
                "device",
                "common.config.loaded",
                "another template",
                Level::Info
            )
            .is_err()
        );
        assert!(
            LogRecord::instance(
                "example",
                "device",
                "example.device.failed",
                "Device failed.",
                Level::Warn,
                ""
            )
            .is_err()
        );
    }

    #[test]
    fn secrets_are_redacted_recursively_without_destroying_boolean_state_flags() {
        let record = LogRecord::instance("example", "device", "example.device.failed", "Device connection failed.", Level::Warn, "camera-id")
            .unwrap().with_attribute("status", json!({
                "Password":"p-sensitive", "accessTOKEN":"t-sensitive", "private-key":"k-sensitive",
                "nested":[{"api_key":17,"url":"rtsp://user:credential@camera/stream"}], "token_configured":true,
            })).unwrap();
        let bytes = record.json_line().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        for secret in [
            "p-sensitive",
            "t-sensitive",
            "k-sensitive",
            "user:credential",
        ] {
            assert!(!text.contains(secret));
        }
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["attributes"]["status"]["token_configured"], true);
        assert_eq!(
            value["attributes"]["status"]["Password"]["configured"],
            true
        );
        assert_eq!(record.instance_id(), Some("camera-id"));
    }

    #[test]
    fn query_filters_exact_instance_time_level_event_and_correlation_fields() {
        let first = LogRecord::instance(
            "example",
            "device",
            "example.device.failed",
            "Connection failed.",
            Level::Warn,
            "camera-1",
        )
        .unwrap()
        .with_request_id("request-1")
        .unwrap()
        .with_task_id("task-1")
        .unwrap();
        let second = LogRecord::instance(
            "example",
            "device",
            "example.device.failed",
            "Connection failed.",
            Level::Warn,
            "camera-10",
        )
        .unwrap();
        let mut bytes = first.json_line().unwrap();
        bytes.extend(second.json_line().unwrap());
        let filter = LogFilter {
            instance_id: Some("camera-1"),
            since: Some("2000-01-01T00:00:00Z"),
            until: Some("2100-01-01T00:00:00Z"),
            minimum_level: Some(Level::Warn),
            event: Some("example.device.failed"),
            request_id: Some("request-1"),
            task_id: Some("task-1"),
            scope: Some(Scope::Instance),
        };
        let records = query(&bytes[..], filter, QueryLimits::default()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].instance_id(), Some("camera-1"));
        assert!(matches!(
            query(
                &bytes[..],
                LogFilter::default(),
                QueryLimits {
                    max_records: 1,
                    ..QueryLimits::default()
                }
            ),
            Err(LogError::QueryLimitExceeded)
        ));
        assert!(
            query(
                &bytes[..bytes.len() - 1],
                LogFilter::default(),
                QueryLimits::default()
            )
            .is_err()
        );
    }

    #[test]
    fn record_and_query_budgets_reject_unbounded_inputs_without_partial_output() {
        let record = LogRecord::common("example", CommonEvent::RuntimeStarted).unwrap();
        assert!(matches!(
            record
                .clone()
                .with_attribute("data", "x".repeat(MAX_RECORD_BYTES)),
            Err(LogError::RecordTooLarge)
        ));
        let mut writer = Vec::new();
        let mut too_large = record;
        too_large
            .attributes
            .insert("data".into(), Value::String("x".repeat(MAX_RECORD_BYTES)));
        assert!(too_large.write_to(&mut writer).is_err());
        assert!(writer.is_empty());
        assert!(matches!(
            query(
                &vec![b'x'; MAX_RECORD_BYTES + 1][..],
                LogFilter::default(),
                QueryLimits::default()
            ),
            Err(LogError::RecordTooLarge)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn file_rotation_has_bounded_capacity_one_writer_and_safe_path_failures() {
        use std::{
            fs,
            os::unix::fs::{PermissionsExt, symlink},
        };
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let retention = LogRetention {
            file_bytes: MAX_RECORD_BYTES as u64,
            archives: 2,
        };
        let mut sink = RotatingLogFile::open(directory.path(), "events", retention).unwrap();
        assert!(RotatingLogFile::open(directory.path(), "events", retention).is_err());
        assert!(
            RotatingLogFile::open_file(directory.path().join("events.jsonl"), retention).is_err()
        );
        let record = LogRecord::common("example", CommonEvent::RuntimeStarted)
            .unwrap()
            .with_attribute("padding", "x".repeat(4096))
            .unwrap();
        for _ in 0..30 {
            sink.write(&record).unwrap();
        }
        let mut count = 0;
        for entry in fs::read_dir(directory.path()).unwrap() {
            let entry = entry.unwrap();
            if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "jsonl")
            {
                count += 1;
                assert!(entry.metadata().unwrap().len() <= retention.file_bytes);
                let parsed = query(
                    std::io::BufReader::new(fs::File::open(entry.path()).unwrap()),
                    LogFilter::default(),
                    QueryLimits::default(),
                )
                .unwrap();
                assert!(!parsed.is_empty());
            }
        }
        assert_eq!(count, 3);
        drop(sink);
        fs::remove_file(directory.path().join("events.jsonl")).unwrap();
        let other = directory.path().join("important");
        fs::write(&other, b"original").unwrap();
        symlink(&other, directory.path().join("events.jsonl")).unwrap();
        assert!(RotatingLogFile::open(directory.path(), "events", retention).is_err());
        assert_eq!(fs::read(other).unwrap(), b"original");
    }
}
