//! Application-owned Unix files use a dedicated private log directory and one
//! writer lock. Other platforms can use the portable stream sink and delegate
//! rotation to their service manager.

use crate::log::{LogError, LogRecord, LogRetention, MAX_RECORD_BYTES};
use rustix::fs::{FlockOperation, OFlags, flock};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub struct RotatingLogFile {
    directory: File,
    path: PathBuf,
    stem: String,
    active_name: String,
    custom_name: bool,
    file: File,
    _writer: File,
    bytes: u64,
    retention: LogRetention,
}

impl RotatingLogFile {
    /// The caller creates the dedicated directory explicitly. Opening this
    /// sink never deletes unknown entries or repairs permissions. Existing
    /// files outside the declared retention policy are rejected.
    pub fn open(
        path: impl AsRef<Path>,
        stem: &str,
        retention: LogRetention,
    ) -> Result<Self, LogError> {
        let path = path.as_ref();
        if !path.is_absolute()
            || stem.is_empty()
            || stem.len() > 64
            || !stem
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(LogError::UnsafeStorage);
        }
        Self::open_named(path, stem, &format!("{stem}.jsonl"), false, retention)
    }

    /// Use an explicit active filename in an existing private directory.
    /// Archives are `<filename>.1` through the declared retention count.
    pub fn open_file(
        active_path: impl AsRef<Path>,
        retention: LogRetention,
    ) -> Result<Self, LogError> {
        let active_path = active_path.as_ref();
        let path = active_path.parent().ok_or(LogError::UnsafeStorage)?;
        let name = active_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(LogError::UnsafeStorage)?;
        if !active_path.is_absolute()
            || name.is_empty()
            || name.len() > 128
            || name.starts_with('.')
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            return Err(LogError::UnsafeStorage);
        }
        Self::open_named(path, name, name, true, retention)
    }

    fn open_named(
        path: &Path,
        stem: &str,
        active_name: &str,
        custom_name: bool,
        retention: LogRetention,
    ) -> Result<Self, LogError> {
        if retention.file_bytes < MAX_RECORD_BYTES as u64
            || retention.archives == 0
            || retention.archives > 32
        {
            return Err(LogError::InvalidLimits);
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags((OFlags::DIRECTORY | OFlags::NOFOLLOW).bits() as i32)
            .open(path)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(LogError::UnsafeStorage);
        }
        // The lease follows the active filename across both constructors.
        // Otherwise open("events") and open_file("events.jsonl") could each
        // hold a different lock while appending to the same active file.
        let writer_path = path.join(format!(".{active_name}.writer.lock"));
        let writer = open_private(&writer_path)?;
        flock(&writer, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| LogError::UnsafeStorage)?;
        verify_named(&writer_path, &writer)?;
        // Refuse a configuration that silently strands archives from an older
        // larger policy. Operators must change retention through an explicit
        // cleanup action, rather than normal startup deleting extra files.
        for entry in fs::read_dir(path)? {
            let name = entry?.file_name();
            let index = name
                .to_str()
                .and_then(|name| name.strip_prefix(&format!("{stem}.")))
                .and_then(|name| {
                    if custom_name {
                        Some(name)
                    } else {
                        name.strip_suffix(".jsonl")
                    }
                });
            if let Some(index) = index {
                let index: u8 = index.parse().map_err(|_| LogError::UnsafeStorage)?;
                if index == 0 || index > retention.archives {
                    return Err(LogError::UnsafeStorage);
                }
            }
        }
        let active_path = path.join(active_name);
        let file = open_private(&active_path)?;
        let bytes = file.metadata()?.len();
        if bytes > retention.file_bytes {
            return Err(LogError::InvalidLimits);
        }
        let sink = Self {
            directory,
            path: path.into(),
            stem: stem.into(),
            active_name: active_name.into(),
            custom_name,
            file,
            _writer: writer,
            bytes,
            retention,
        };
        sink.verify_directory()?;
        for index in 1..=retention.archives {
            if let Some(metadata) = sink.archive_metadata(index)?
                && metadata.len() > retention.file_bytes
            {
                return Err(LogError::InvalidLimits);
            }
        }
        Ok(sink)
    }

    pub fn write(&mut self, record: &LogRecord) -> Result<(), LogError> {
        let line = record.json_line()?;
        self.verify_directory()?;
        verify_named(&self.active_path(), &self.file)?;
        verify_named(
            &self.path.join(format!(".{}.writer.lock", self.active_name)),
            &self._writer,
        )?;
        if self.file.metadata()?.len() != self.bytes {
            return Err(LogError::UnsafeStorage);
        }
        if self
            .bytes
            .checked_add(line.len() as u64)
            .is_none_or(|bytes| bytes > self.retention.file_bytes)
        {
            self.rotate()?;
        }
        self.file.write_all(&line)?;
        self.file.flush()?;
        self.bytes += line.len() as u64;
        Ok(())
    }

    fn rotate(&mut self) -> Result<(), LogError> {
        self.file.sync_all()?;
        let last = self.archive_path(self.retention.archives);
        if self.archive_metadata(self.retention.archives)?.is_some() {
            fs::remove_file(last)?;
        }
        for index in (1..self.retention.archives).rev() {
            if self.archive_metadata(index)?.is_some() {
                fs::rename(self.archive_path(index), self.archive_path(index + 1))?;
            }
        }
        verify_named(&self.active_path(), &self.file)?;
        fs::rename(self.active_path(), self.archive_path(1))?;
        self.file = open_private(&self.active_path())?;
        if self.file.metadata()?.len() != 0 {
            return Err(LogError::UnsafeStorage);
        }
        self.bytes = 0;
        self.directory.sync_all()?;
        Ok(())
    }

    fn active_path(&self) -> PathBuf {
        self.path.join(&self.active_name)
    }
    fn archive_path(&self, index: u8) -> PathBuf {
        self.path.join(if self.custom_name {
            format!("{}.{index}", self.stem)
        } else {
            format!("{}.{index}.jsonl", self.stem)
        })
    }
    fn archive_metadata(&self, index: u8) -> Result<Option<Metadata>, LogError> {
        match fs::symlink_metadata(self.archive_path(index)) {
            Ok(metadata) => {
                require_private(&metadata)?;
                Ok(Some(metadata))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    fn verify_directory(&self) -> Result<(), LogError> {
        let held = self.directory.metadata()?;
        let named = fs::symlink_metadata(&self.path)?;
        if !named.is_dir()
            || named.dev() != held.dev()
            || named.ino() != held.ino()
            || named.mode() & 0o777 != 0o700
            || named.uid() != rustix::process::geteuid().as_raw()
        {
            Err(LogError::UnsafeStorage)
        } else {
            Ok(())
        }
    }
}

fn open_private(path: &Path) -> Result<File, LogError> {
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    verify_named(path, &file)?;
    Ok(file)
}
fn require_private(metadata: &Metadata) -> Result<(), LogError> {
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        Err(LogError::UnsafeStorage)
    } else {
        Ok(())
    }
}
fn verify_named(path: &Path, file: &File) -> Result<(), LogError> {
    let held = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    require_private(&held)?;
    require_private(&named)?;
    if held.dev() != named.dev() || held.ino() != named.ino() {
        Err(LogError::UnsafeStorage)
    } else {
        Ok(())
    }
}
