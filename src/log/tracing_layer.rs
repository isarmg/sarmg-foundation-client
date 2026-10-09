//! Tracing adapter for existing product instrumentation. Unstructured legacy
//! messages and internal error chains do not cross the ordinary-log boundary.

use crate::log::{CommonEvent, Level, LogError, LogRecord, identifier};
use serde_json::{Map, Value};
use std::{
    fmt::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};
use tracing_subscriber::{
    layer::{Context, Layer},
    registry::LookupSpan,
};

const MAX_FIELDS: usize = 32;
const MAX_FIELD_BYTES: usize = 2048;

#[derive(Clone)]
pub struct XcscStructuredLayer {
    service: Arc<str>,
    rejected: Arc<AtomicU64>,
    output: Arc<Mutex<Sink>>,
}

enum Sink {
    Process,
    Stream(Box<dyn std::io::Write + Send>),
    #[cfg(any(unix, windows))]
    File(crate::log::RotatingLogFile),
}

impl XcscStructuredLayer {
    pub fn new(service: &str) -> Result<Self, LogError> {
        identifier(service)?;
        Ok(Self {
            service: service.into(),
            rejected: Arc::default(),
            output: Arc::new(Mutex::new(Sink::Process)),
        })
    }
    pub fn with_writer(mut self, output: impl std::io::Write + Send + 'static) -> Self {
        self.output = Arc::new(Mutex::new(Sink::Stream(Box::new(output))));
        self
    }

    #[cfg(any(unix, windows))]
    pub fn with_rotating_file(mut self, output: crate::log::RotatingLogFile) -> Self {
        self.output = Arc::new(Mutex::new(Sink::File(output)));
        self
    }

    /// Switch the installed subscriber's shared sink after the run preflight.
    /// All clones observe the switch; an unavailable sink is explicit.
    #[cfg(any(unix, windows))]
    pub fn set_rotating_file(&self, output: crate::log::RotatingLogFile) -> Result<(), LogError> {
        let mut sink = self.output.lock().map_err(|_| LogError::UnsafeStorage)?;
        *sink = Sink::File(output);
        Ok(())
    }

    pub fn rejected_count(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
struct Captured {
    fields: Map<String, Value>,
    truncated: bool,
}
impl Captured {
    fn insert(&mut self, name: &str, value: Value) {
        // Legacy text can contain SQL, credentials and error chains. The event
        // identity, level and safe attributes carry its useful classification.
        if name == "message" {
            return;
        }
        if name.len() > 128 || (!self.fields.contains_key(name) && self.fields.len() >= MAX_FIELDS)
        {
            self.truncated = true;
            return;
        }
        let value = if [
            "error",
            "source",
            "error_chain",
            "backtrace",
            "stack",
            "config",
        ]
        .contains(&name)
        {
            Value::String("[internal diagnostic omitted]".into())
        } else {
            value
        };
        self.fields.insert(name.into(), value);
    }
    fn merge(&mut self, other: &Self) {
        self.truncated |= other.truncated;
        for (key, value) in &other.fields {
            self.insert(key, value.clone());
        }
    }
    fn text(&mut self, name: &str) -> Option<String> {
        self.fields
            .remove(name)
            .and_then(|value| value.as_str().map(str::to_owned))
    }
}

struct FieldBuffer {
    text: String,
    truncated: bool,
}
impl Write for FieldBuffer {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let remaining = MAX_FIELD_BYTES.saturating_sub(self.text.len());
        if value.len() <= remaining {
            self.text.push_str(value);
            return Ok(());
        }
        let mut cut = remaining;
        while !value.is_char_boundary(cut) {
            cut -= 1;
        }
        self.text.push_str(&value[..cut]);
        self.truncated = true;
        Err(fmt::Error)
    }
}

impl Visit for Captured {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            return;
        }
        let mut buffer = FieldBuffer {
            text: String::new(),
            truncated: false,
        };
        let _ = write!(&mut buffer, "{value:?}");
        self.truncated |= buffer.truncated;
        self.insert(field.name(), Value::String(buffer.text));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        let mut buffer = FieldBuffer {
            text: String::new(),
            truncated: false,
        };
        let _ = buffer.write_str(value);
        self.truncated |= buffer.truncated;
        self.insert(field.name(), Value::String(buffer.text));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field.name(), value.into());
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field.name(), value.into());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field.name(), value.into());
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.insert(field.name(), Value::from(value));
    }
}

impl<S> Layer<S> for XcscStructuredLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attributes: &Attributes<'_>, id: &Id, context: Context<'_, S>) {
        let mut captured = Captured::default();
        attributes.record(&mut captured);
        if let Some(span) = context.span(id) {
            span.extensions_mut().insert(captured);
        }
    }
    fn on_record(&self, id: &Id, values: &Record<'_>, context: Context<'_, S>) {
        if let Some(span) = context.span(id)
            && let Some(captured) = span.extensions_mut().get_mut::<Captured>()
        {
            values.record(captured);
        }
    }
    fn on_event(&self, event: &Event<'_>, context: Context<'_, S>) {
        let mut captured = Captured::default();
        if let Some(scope) = context.event_scope(event) {
            for span in scope.from_root() {
                if let Some(fields) = span.extensions().get::<Captured>() {
                    captured.merge(fields);
                }
            }
        }
        event.record(&mut captured);
        let result = build_record(&self.service, event.metadata(), captured).and_then(|record| {
            let mut output = self.output.lock().map_err(|_| LogError::UnsafeStorage)?;
            match &mut *output {
                Sink::Process => record.emit(),
                Sink::Stream(output) => record.write_to(output),
                #[cfg(any(unix, windows))]
                Sink::File(output) => output.write(&record),
            }
        });
        if result.is_err() {
            self.rejected.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn build_record(
    service: &str,
    metadata: &tracing::Metadata<'_>,
    mut captured: Captured,
) -> Result<LogRecord, LogError> {
    let level = match *metadata.level() {
        tracing::Level::TRACE => Level::Trace,
        tracing::Level::DEBUG => Level::Debug,
        tracing::Level::INFO => Level::Info,
        tracing::Level::WARN => Level::Warn,
        tracing::Level::ERROR => Level::Error,
    };
    let component = captured
        .text("component")
        .unwrap_or_else(|| metadata.target().to_owned());
    let event = captured
        .text("event")
        .unwrap_or_else(|| format!("{service}.diagnostic"));
    let instance = captured.text("instance_id");
    let instance_type = captured.text("instance_type");
    let request = captured.text("request_id");
    let task = captured.text("task_id");
    let error = captured.text("error_code");
    let mut record = if event.starts_with("common.") {
        let common = CommonEvent::from_name(&event).ok_or(LogError::InvalidRecord)?;
        if let Some(instance) = instance {
            LogRecord::common_instance(service, common, &instance)?
        } else {
            LogRecord::common(service, common)?
        }
    } else if let Some(instance) = instance {
        LogRecord::instance(
            service,
            &component,
            &event,
            "Runtime diagnostic event.",
            level,
            &instance,
        )?
    } else {
        LogRecord::client(
            service,
            &component,
            &event,
            "Runtime diagnostic event.",
            level,
        )?
    };
    if let Some(instance_type) = instance_type {
        record = record.with_instance_type(&instance_type)?;
    }
    if let Some(request) = request {
        record = record.with_request_id(&request)?;
    }
    if let Some(task) = task {
        record = record.with_task_id(&task)?;
    }
    if let Some(error) = error {
        record = record.with_error_code(&error)?;
    }
    if captured.truncated {
        record = record.with_attribute("fields_truncated", true)?;
    }
    for (key, value) in captured.fields {
        record = record.with_attribute(&key, value)?;
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;

    #[derive(Clone)]
    struct Output(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn tracing_events_inherit_scope_and_safe_fields_without_legacy_error_messages() {
        let output = Output(Arc::default());
        let layer = XcscStructuredLayer::new("example")
            .unwrap()
            .with_writer(output.clone());
        let subscriber = tracing_subscriber::registry().with(layer.clone());
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "device",
                instance_id = "camera-1",
                request_id = "req-1",
                password = "span-password"
            );
            let _entered = span.enter();
            tracing::warn!(
                event = "example.device.failed",
                error_code = "dependency_unavailable",
                error = "rtsp://user:secret@camera/stream",
                "raw internal failure includes invisible-secret"
            );
            tracing::info!(
                event = "example.device.retrying",
                attempt = 3u64,
                detail = "x".repeat(MAX_FIELD_BYTES + 100),
                "retry"
            );
        });
        assert_eq!(layer.rejected_count(), 0);
        let bytes = output.0.lock().unwrap().clone();
        let records = crate::log::query(
            &bytes[..],
            crate::log::LogFilter::default(),
            crate::log::QueryLimits::default(),
        )
        .unwrap();
        assert_eq!(records.len(), 2);
        assert!(
            records
                .iter()
                .all(|record| record.instance_id() == Some("camera-1"))
        );
        let text = String::from_utf8(bytes).unwrap();
        for secret in ["span-password", "user:secret", "invisible-secret"] {
            assert!(!text.contains(secret));
        }
        assert!(text.contains("fields_truncated"));
        assert!(text.contains("dependency_unavailable"));
    }

    #[test]
    fn common_events_keep_registered_templates_and_reject_unknown_names() {
        let output = Output(Arc::default());
        let layer = XcscStructuredLayer::new("example")
            .unwrap()
            .with_writer(output.clone());
        let subscriber = tracing_subscriber::registry().with(layer.clone());
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(
                event = "common.runtime.started",
                component = "untrusted",
                "SECRET"
            );
            tracing::info!(event = "common.invented", "SECRET");
            tracing::info!(event = "common.runtime.started", instance_id = "camera-1");
            tracing::warn!(event = "common.task.failed", instance_id = "camera-1");
        });
        assert_eq!(layer.rejected_count(), 2);
        let bytes = output.0.lock().unwrap().clone();
        let values: Vec<serde_json::Value> = std::str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0]["component"], "runtime");
        assert_eq!(values[0]["level"], "INFO");
        assert_eq!(values[0]["message"], "Runtime started.");
        assert_eq!(values[1]["scope"], "instance");
        assert!(!std::str::from_utf8(&bytes).unwrap().contains("SECRET"));
    }

    #[cfg(unix)]
    #[test]
    fn installed_layer_switches_to_a_bounded_custom_file_and_counts_sink_failure() {
        use std::{fs, os::unix::fs::PermissionsExt};
        let output = Output(Arc::default());
        let layer = XcscStructuredLayer::new("example")
            .unwrap()
            .with_writer(output.clone());
        let subscriber = tracing_subscriber::registry().with(layer.clone());
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("logs");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let retention = crate::log::LogRetention {
            file_bytes: crate::log::MAX_RECORD_BYTES as u64,
            archives: 2,
        };
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(event = "common.config.loaded");
            layer
                .set_rotating_file(
                    crate::log::RotatingLogFile::open_file(directory.join("custom.log"), retention)
                        .unwrap(),
                )
                .unwrap();
            for _ in 0..100 {
                tracing::info!(event = "common.runtime.started", padding = "x".repeat(1024));
            }
            let moved = parent.path().join("moved");
            fs::rename(&directory, &moved).unwrap();
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            tracing::info!(event = "common.runtime.stopped");
            for name in ["custom.log", "custom.log.1", "custom.log.2"] {
                assert!(fs::metadata(moved.join(name)).unwrap().len() <= retention.file_bytes);
            }
        });
        assert_eq!(layer.rejected_count(), 1);
        let bytes = output.0.lock().unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap().lines().count(), 1);
        assert!(
            !std::str::from_utf8(&bytes)
                .unwrap()
                .contains("common.runtime.started")
        );
    }
}
