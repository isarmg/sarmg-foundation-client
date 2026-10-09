//! Linux offline-client maintenance of existing private state and lock identities.
//!
//! This is deliberately narrower than a general path-sandbox library. It owns
//! one already-resolved private directory, direct child state files, stable
//! device/inode checks, and the instance/maintenance lock protocol.

use rustix::fs::{FlockOperation, OFlags, flock};
use std::{
    ffi::OsStr,
    fs::{self, DirBuilder, File, Metadata, OpenOptions},
    io,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;

pub const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
pub const PRIVATE_FILE_MODE: u32 = 0o600;
pub const INSTANCE_LOCK_FILE: &str = ".xcss-instance.lock";
pub const MAINTENANCE_LOCK_FILE: &str = ".xcss-maintenance.lock";
/// Durable maintenance intent. Its presence prevents normal startup even
/// after a crashed maintainer has released its advisory lock.
pub const MAINTENANCE_PENDING_FILE: &str = ".xcss-maintenance-pending.json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    pub const fn device(self) -> u64 {
        self.device
    }

    pub const fn inode(self) -> u64 {
        self.inode
    }

    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PrivateStateDirectory {
    path: PathBuf,
    identity: FileIdentity,
    owner_uid: u32,
    owner_gid: u32,
    administrative_handle: Option<Arc<File>>,
}

impl PrivateStateDirectory {
    /// Create the directory when missing, then require an absolute, private,
    /// non-symlink directory owned by the effective process user.
    pub fn create(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        require_absolute(path)?;
        match fs::symlink_metadata(path) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut builder = DirBuilder::new();
                builder
                    .mode(PRIVATE_DIRECTORY_MODE)
                    .create(path)
                    .map_err(|source| Error::CreateDirectory {
                        path: path.to_path_buf(),
                        source,
                    })?;
            }
            Err(source) => {
                return Err(Error::InspectPath {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
        Self::open(path)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        require_absolute(path)?;
        let metadata = symlink_metadata(path)?;
        let owner_uid = rustix::process::geteuid().as_raw();
        require_directory(path, &metadata, owner_uid)?;
        Ok(Self {
            path: path.to_path_buf(),
            identity: FileIdentity::from_metadata(&metadata),
            owner_uid,
            owner_gid: metadata.gid(),
            administrative_handle: None,
        })
    }

    /// Open an existing service-owned private directory for offline maintenance.
    /// Only its owner or effective uid 0 is authorized. Every path component is
    /// opened without following links; newly created files retain the directory
    /// owner's uid/gid. This never creates, chmods, or chowns an existing object.
    /// Normal runtime access must continue to use [`Self::open`].
    pub fn open_for_administration(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        require_absolute(path)?;
        let directory = open_physical_directory(path)?;
        let metadata = directory.metadata().map_err(|source| Error::InspectPath {
            path: path.to_path_buf(),
            source,
        })?;
        let caller = rustix::process::geteuid().as_raw();
        if caller != 0 && caller != metadata.uid() {
            return Err(Error::UnexpectedOwner {
                path: path.to_path_buf(),
                expected: caller,
                actual: metadata.uid(),
            });
        }
        require_directory(path, &metadata, metadata.uid())?;
        let result = Self {
            path: path.to_path_buf(),
            identity: FileIdentity::from_metadata(&metadata),
            owner_uid: metadata.uid(),
            owner_gid: metadata.gid(),
            administrative_handle: Some(Arc::new(directory)),
        };
        result.verify_identity()?;
        Ok(result)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    pub const fn owner_gid(&self) -> u32 {
        self.owner_gid
    }

    pub fn verify_identity(&self) -> Result<(), Error> {
        if self.administrative_handle.is_some() {
            let caller = rustix::process::geteuid().as_raw();
            if caller != 0 && caller != self.owner_uid {
                return Err(Error::UnexpectedOwner {
                    path: self.path.clone(),
                    expected: caller,
                    actual: self.owner_uid,
                });
            }
        }
        let metadata = if self.administrative_handle.is_some() {
            open_physical_directory(&self.path)?
                .metadata()
                .map_err(|source| Error::InspectPath {
                    path: self.path.clone(),
                    source,
                })?
        } else {
            symlink_metadata(&self.path)?
        };
        require_directory(&self.path, &metadata, self.owner_uid)?;
        if self.administrative_handle.is_some()
            && metadata.mode() & 0o7777 != PRIVATE_DIRECTORY_MODE
        {
            return Err(Error::UnexpectedMode {
                path: self.path.clone(),
                expected: PRIVATE_DIRECTORY_MODE,
                actual: metadata.mode() & 0o7777,
            });
        }
        if self.administrative_handle.is_some() && metadata.gid() != self.owner_gid {
            return Err(Error::FileIdentityChanged {
                path: self.path.clone(),
                expected: self.identity,
                actual: FileIdentity::from_metadata(&metadata),
            });
        }
        require_identity(
            &self.path,
            self.identity,
            FileIdentity::from_metadata(&metadata),
        )
    }

    pub fn open_existing(&self, name: impl AsRef<OsStr>) -> Result<SecureStateFile, Error> {
        self.open_file(name.as_ref(), false)
    }

    pub fn create_file(&self, name: impl AsRef<OsStr>) -> Result<SecureStateFile, Error> {
        self.open_file(name.as_ref(), true)
    }

    pub fn try_instance_lock(&self) -> Result<InstanceLock, Error> {
        self.verify_identity()?;
        let maintenance = self.create_file(MAINTENANCE_LOCK_FILE)?;
        try_flock(
            maintenance.file(),
            FlockOperation::NonBlockingLockShared,
            LockKind::Maintenance,
        )?;
        // Check under the maintenance guard: a maintainer cannot create its
        // intent between this check and acquisition of the runtime lock.
        self.verify_no_pending_maintenance()?;
        let instance = self.create_file(INSTANCE_LOCK_FILE)?;
        try_flock(
            instance.file(),
            FlockOperation::NonBlockingLockExclusive,
            LockKind::Instance,
        )?;
        maintenance.verify_identity()?;
        instance.verify_identity()?;
        self.verify_identity()?;
        Ok(InstanceLock {
            directory: self.clone(),
            _maintenance_guard: maintenance,
            _instance: instance,
        })
    }

    pub fn try_maintenance_lock(&self) -> Result<MaintenanceLock, Error> {
        self.verify_identity()?;
        let file = self.create_file(MAINTENANCE_LOCK_FILE)?;
        try_flock(
            file.file(),
            FlockOperation::NonBlockingLockExclusive,
            LockKind::Maintenance,
        )?;
        file.verify_identity()?;
        self.verify_identity()?;
        Ok(MaintenanceLock {
            directory: self.clone(),
            _file: file,
        })
    }

    /// Coordinate an authorized online diagnostic with exclusive maintenance.
    /// This does not grant runtime ownership or bypass pending maintenance intent.
    pub fn try_shared_maintenance_lock(&self) -> Result<MaintenanceLock, Error> {
        self.verify_identity()?;
        let file = self.create_file(MAINTENANCE_LOCK_FILE)?;
        try_flock(
            file.file(),
            FlockOperation::NonBlockingLockShared,
            LockKind::Maintenance,
        )?;
        self.verify_no_pending_maintenance()?;
        file.verify_identity()?;
        self.verify_identity()?;
        Ok(MaintenanceLock {
            directory: self.clone(),
            _file: file,
        })
    }

    /// Read-only startup gate for a durable maintenance intent.
    /// An unreadable or unexpected object must never be treated as no intent.
    pub fn verify_no_pending_maintenance(&self) -> Result<(), Error> {
        self.verify_identity()?;
        let path = self.path.join(MAINTENANCE_PENDING_FILE);
        match fs::symlink_metadata(&path) {
            Ok(_) => Err(Error::MaintenancePending),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(Error::InspectPath { path, source }),
        }
    }

    fn open_file(&self, name: &OsStr, create: bool) -> Result<SecureStateFile, Error> {
        self.verify_identity()?;
        let relative = Path::new(name);
        require_direct_child(relative)?;
        let path = self.path.join(relative);
        let file = if let Some(directory) = &self.administrative_handle {
            administrative_file(directory, name, create, self.owner_uid, self.owner_gid).map_err(
                |source| Error::OpenFile {
                    path: path.clone(),
                    source,
                },
            )?
        } else {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(create)
                .mode(PRIVATE_FILE_MODE)
                .custom_flags(OFlags::NOFOLLOW.bits() as i32)
                .open(&path)
                .map_err(|source| Error::OpenFile {
                    path: path.clone(),
                    source,
                })?
        };
        let metadata = file.metadata().map_err(|source| Error::InspectPath {
            path: path.clone(),
            source,
        })?;
        require_file(&path, &metadata, self.owner_uid)?;
        let identity = FileIdentity::from_metadata(&metadata);
        let path_metadata = symlink_metadata(&path)?;
        require_file(&path, &path_metadata, self.owner_uid)?;
        require_identity(&path, identity, FileIdentity::from_metadata(&path_metadata))?;
        self.verify_identity()?;
        Ok(SecureStateFile {
            file,
            path,
            identity,
            owner_uid: self.owner_uid,
        })
    }
}

#[derive(Debug)]
pub struct SecureStateFile {
    file: File,
    path: PathBuf,
    identity: FileIdentity,
    owner_uid: u32,
}

impl SecureStateFile {
    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Re-check both the open descriptor and its path. This detects replacement
    /// between the initial check and a database driver's independent open.
    pub fn verify_identity(&self) -> Result<(), Error> {
        let descriptor = self.file.metadata().map_err(|source| Error::InspectPath {
            path: self.path.clone(),
            source,
        })?;
        require_file(&self.path, &descriptor, self.owner_uid)?;
        require_identity(
            &self.path,
            self.identity,
            FileIdentity::from_metadata(&descriptor),
        )?;
        let path_metadata = symlink_metadata(&self.path)?;
        require_file(&self.path, &path_metadata, self.owner_uid)?;
        require_identity(
            &self.path,
            self.identity,
            FileIdentity::from_metadata(&path_metadata),
        )
    }
}

#[derive(Debug)]
pub struct InstanceLock {
    directory: PrivateStateDirectory,
    _maintenance_guard: SecureStateFile,
    _instance: SecureStateFile,
}

#[derive(Debug)]
pub struct MaintenanceLock {
    directory: PrivateStateDirectory,
    _file: SecureStateFile,
}

impl InstanceLock {
    /// Call before handing a separately opened database to a storage driver.
    pub fn verify_identity(&self) -> Result<(), Error> {
        self.directory.verify_identity()?;
        self._maintenance_guard.verify_identity()?;
        self._instance.verify_identity()
    }

    /// Explicitly hand off write ownership after all business resources close.
    /// Unlocking the open file description also covers descriptors inherited
    /// briefly by concurrently spawned processes before their exec boundary.
    pub fn release(self) -> Result<(), Error> {
        self.verify_identity()?;
        try_flock(
            self._instance.file(),
            FlockOperation::Unlock,
            LockKind::Instance,
        )?;
        try_flock(
            self._maintenance_guard.file(),
            FlockOperation::Unlock,
            LockKind::Maintenance,
        )
    }
}

impl MaintenanceLock {
    /// Borrow the already-held lock description for one controlled child
    /// process. The owner retains its lifetime and must verify the directory
    /// and lock identity before spawning; this does not transfer ownership.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self._file.file().as_fd()
    }

    pub fn verify_identity(&self) -> Result<(), Error> {
        self.directory.verify_identity()?;
        self._file.verify_identity()
    }

    /// Complete the controlled maintenance handoff before starting the server.
    pub fn release(self) -> Result<(), Error> {
        self.verify_identity()?;
        try_flock(
            self._file.file(),
            FlockOperation::Unlock,
            LockKind::Maintenance,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockKind {
    Instance,
    Maintenance,
}

fn try_flock(file: &File, operation: FlockOperation, kind: LockKind) -> Result<(), Error> {
    flock(file, operation).map_err(|source| Error::LockUnavailable {
        kind,
        source: source.into(),
    })
}

fn open_physical_directory(path: &Path) -> Result<File, Error> {
    use rustix::fs::{Mode, open, openat};
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let fail = |source: rustix::io::Errno| Error::InspectPath {
        path: path.to_path_buf(),
        source: source.into(),
    };
    let mut directory = open("/", flags, Mode::empty()).map_err(fail)?;
    for component in path.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => {
                directory = openat(&directory, name, flags, Mode::empty()).map_err(fail)?
            }
            _ => {
                return Err(Error::InvalidChildName {
                    name: path.to_path_buf(),
                });
            }
        }
    }
    Ok(File::from(directory))
}

fn administrative_file(
    directory: &File,
    name: &OsStr,
    create: bool,
    uid: u32,
    gid: u32,
) -> io::Result<File> {
    use rustix::fs::{Mode, fchown, openat};
    let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    if create {
        match openat(
            directory,
            name,
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(PRIVATE_FILE_MODE),
        ) {
            Ok(fd) => {
                let file = File::from(fd);
                // This descriptor was created exclusively, so an existing
                // service file can never be repaired or taken over here.
                fchown(
                    &file,
                    Some(rustix::process::Uid::from_raw(uid)),
                    Some(rustix::process::Gid::from_raw(gid)),
                )
                .map_err(io::Error::from)?;
                file.sync_all()?;
                directory.sync_all()?;
                return Ok(file);
            }
            Err(rustix::io::Errno::EXIST) => (),
            Err(error) => return Err(error.into()),
        }
    }
    openat(directory, name, flags, Mode::empty())
        .map(File::from)
        .map_err(io::Error::from)
}

fn require_absolute(path: &Path) -> Result<(), Error> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(Error::StateDirectoryNotAbsolute {
            path: path.to_path_buf(),
        })
    }
}

fn require_direct_child(path: &Path) -> Result<(), Error> {
    let mut components = path.components();
    if matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none() {
        Ok(())
    } else {
        Err(Error::InvalidChildName {
            name: path.to_path_buf(),
        })
    }
}

fn symlink_metadata(path: &Path) -> Result<Metadata, Error> {
    fs::symlink_metadata(path).map_err(|source| Error::InspectPath {
        path: path.to_path_buf(),
        source,
    })
}

fn require_directory(path: &Path, metadata: &Metadata, owner_uid: u32) -> Result<(), Error> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::NotDirectory {
            path: path.to_path_buf(),
        });
    }
    require_owner_and_mode(path, metadata, owner_uid, PRIVATE_DIRECTORY_MODE)
}

fn require_file(path: &Path, metadata: &Metadata, owner_uid: u32) -> Result<(), Error> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    if metadata.nlink() != 1 {
        return Err(Error::UnexpectedHardLinkCount {
            path: path.to_path_buf(),
            actual: metadata.nlink(),
        });
    }
    require_owner_and_mode(path, metadata, owner_uid, PRIVATE_FILE_MODE)
}

fn require_owner_and_mode(
    path: &Path,
    metadata: &Metadata,
    owner_uid: u32,
    expected_mode: u32,
) -> Result<(), Error> {
    if metadata.uid() != owner_uid {
        return Err(Error::UnexpectedOwner {
            path: path.to_path_buf(),
            expected: owner_uid,
            actual: metadata.uid(),
        });
    }
    let actual = metadata.mode() & 0o777;
    if actual != expected_mode {
        return Err(Error::UnexpectedMode {
            path: path.to_path_buf(),
            expected: expected_mode,
            actual,
        });
    }
    Ok(())
}

fn require_identity(
    path: &Path,
    expected: FileIdentity,
    actual: FileIdentity,
) -> Result<(), Error> {
    if expected == actual {
        Ok(())
    } else {
        Err(Error::FileIdentityChanged {
            path: path.to_path_buf(),
            expected,
            actual,
        })
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("data directory has an unfinished maintenance operation")]
    MaintenancePending,
    #[error("state directory must be absolute: {path}", path = .path.display())]
    StateDirectoryNotAbsolute { path: PathBuf },
    #[error("state file name must be one normal direct child: {name}", name = .name.display())]
    InvalidChildName { name: PathBuf },
    #[error("cannot inspect state path {path}: {source}", path = .path.display())]
    InspectPath { path: PathBuf, source: io::Error },
    #[error("cannot create private state directory {path}: {source}", path = .path.display())]
    CreateDirectory { path: PathBuf, source: io::Error },
    #[error("cannot securely open state file {path}: {source}", path = .path.display())]
    OpenFile { path: PathBuf, source: io::Error },
    #[error("state path is not a real directory: {path}", path = .path.display())]
    NotDirectory { path: PathBuf },
    #[error("state path is not one regular no-follow file: {path}", path = .path.display())]
    NotRegularFile { path: PathBuf },
    #[error("state path {path} has owner {actual}, expected {expected}", path = .path.display())]
    UnexpectedOwner {
        path: PathBuf,
        expected: u32,
        actual: u32,
    },
    #[error("state path {path} has mode {actual:o}, expected {expected:o}", path = .path.display())]
    UnexpectedMode {
        path: PathBuf,
        expected: u32,
        actual: u32,
    },
    #[error("state file {path} has {actual} hard links; exactly one is required", path = .path.display())]
    UnexpectedHardLinkCount { path: PathBuf, actual: u64 },
    #[error("state file identity changed for {path}: expected {expected:?}, found {actual:?}", path = .path.display())]
    FileIdentityChanged {
        path: PathBuf,
        expected: FileIdentity,
        actual: FileIdentity,
    },
    #[error("{kind:?} lock is unavailable: {source}")]
    LockUnavailable { kind: LockKind, source: io::Error },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn private_tempdir() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        Ok(directory)
    }

    #[test]
    fn administration_preserves_service_ownership_without_relaxing_runtime()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::{fs::chown, process::CommandExt};
        use std::process::Command;
        if rustix::process::geteuid().as_raw() != 0 {
            let parent = private_tempdir()?;
            PrivateStateDirectory::open_for_administration(parent.path())?
                .try_maintenance_lock()?
                .release()?;
            return Ok(());
        }
        let parent = private_tempdir()?;
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o755))?;
        let path = parent.path().join("service-state");
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        chown(&path, Some(65534), Some(65534))?;
        assert!(matches!(
            PrivateStateDirectory::open(&path),
            Err(Error::UnexpectedOwner { .. })
        ));
        let directory = PrivateStateDirectory::open_for_administration(&path)?;
        assert_eq!(
            (directory.owner_uid(), directory.owner_gid()),
            (65534, 65534)
        );
        let lock = directory.try_maintenance_lock()?;
        let metadata = fs::metadata(path.join(MAINTENANCE_LOCK_FILE))?;
        assert_eq!(
            (
                metadata.uid(),
                metadata.gid(),
                metadata.mode() & 0o7777,
                metadata.nlink()
            ),
            (65534, 65534, 0o600, 1)
        );
        let helper = |uid, denied| -> Result<(), Box<dyn std::error::Error>> {
            let result = Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "state_file::tests::administration_uid_helper",
                    "--ignored",
                ])
                .env("XCSC_ADMIN_TEST_DATA", &path)
                .env("XCSC_ADMIN_TEST_DENIED", if denied { "yes" } else { "no" })
                .uid(uid)
                .gid(uid)
                .output()?;
            crate::assert_one_subprocess_test(&result);
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            Ok(())
        };
        helper(65534, false)?;
        helper(65533, true)?;
        lock.release()?;
        directory
            .create_file(MAINTENANCE_PENDING_FILE)?
            .file()
            .sync_all()?;
        assert_eq!(
            fs::metadata(path.join(MAINTENANCE_PENDING_FILE))?.uid(),
            65534
        );
        let alias = parent.path().join("alias");
        symlink(&path, &alias)?;
        assert!(PrivateStateDirectory::open_for_administration(&alias).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o750))?;
        assert!(PrivateStateDirectory::open_for_administration(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let existing = path.join("wrong-owner");
        fs::write(&existing, b"retain")?;
        fs::set_permissions(&existing, fs::Permissions::from_mode(0o600))?;
        assert!(directory.create_file("wrong-owner").is_err());
        assert_eq!(fs::metadata(&existing)?.uid(), 0);
        assert_eq!(fs::read(existing)?, b"retain");
        Ok(())
    }

    #[test]
    #[ignore = "real uid helper invoked by administration_preserves_service_ownership_without_relaxing_runtime"]
    fn administration_uid_helper() {
        let path = PathBuf::from(std::env::var_os("XCSC_ADMIN_TEST_DATA").unwrap());
        if std::env::var("XCSC_ADMIN_TEST_DENIED").unwrap() == "yes" {
            assert!(PrivateStateDirectory::open(&path).is_err());
            assert!(PrivateStateDirectory::open_for_administration(&path).is_err());
        } else {
            let ordinary = PrivateStateDirectory::open(&path).unwrap();
            assert!(ordinary.try_instance_lock().is_err());
            let administrative = PrivateStateDirectory::open_for_administration(&path).unwrap();
            assert!(administrative.try_maintenance_lock().is_err());
        }
    }

    #[test]
    fn creates_and_reopens_secure_files() -> Result<(), Box<dyn std::error::Error>> {
        let parent = private_tempdir()?;
        let path = parent.path().join("state");
        let state = PrivateStateDirectory::create(&path)?;
        let file = state.create_file("state.sqlite3")?;
        assert_eq!(file.file().metadata()?.mode() & 0o777, 0o600);
        assert_eq!(
            file.identity(),
            state.open_existing("state.sqlite3")?.identity()
        );
        file.verify_identity()?;
        Ok(())
    }

    #[test]
    fn rejects_relative_public_symlink_and_hardlinked_state()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            PrivateStateDirectory::open("relative"),
            Err(Error::StateDirectoryNotAbsolute { .. })
        ));
        let parent = private_tempdir()?;
        let public = parent.path().join("public");
        fs::create_dir(&public)?;
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755))?;
        assert!(matches!(
            PrivateStateDirectory::open(&public),
            Err(Error::UnexpectedMode { .. })
        ));
        let private = parent.path().join("private");
        fs::create_dir(&private)?;
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700))?;
        let link = parent.path().join("link");
        symlink(&private, &link)?;
        assert!(matches!(
            PrivateStateDirectory::open(&link),
            Err(Error::NotDirectory { .. })
        ));
        let state = PrivateStateDirectory::open(&private)?;
        state.create_file("database")?;
        fs::hard_link(private.join("database"), private.join("copy"))?;
        assert!(matches!(
            state.open_existing("database"),
            Err(Error::UnexpectedHardLinkCount { .. })
        ));
        Ok(())
    }

    #[test]
    fn detects_replacement_and_coordinates_locks() -> Result<(), Box<dyn std::error::Error>> {
        let parent = private_tempdir()?;
        let state = PrivateStateDirectory::create(parent.path().join("state"))?;
        let file = state.create_file("database")?;
        fs::rename(file.path(), state.path().join("old"))?;
        state.create_file("database")?;
        assert!(matches!(
            file.verify_identity(),
            Err(Error::FileIdentityChanged { .. })
        ));
        drop(file);

        let instance = state.try_instance_lock()?;
        assert!(matches!(
            state.try_instance_lock(),
            Err(Error::LockUnavailable {
                kind: LockKind::Instance,
                ..
            })
        ));
        assert!(matches!(
            state.try_maintenance_lock(),
            Err(Error::LockUnavailable {
                kind: LockKind::Maintenance,
                ..
            })
        ));
        drop(instance);
        let _maintenance = state.try_maintenance_lock()?;
        assert!(matches!(
            state.try_instance_lock(),
            Err(Error::LockUnavailable {
                kind: LockKind::Maintenance,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn durable_maintenance_intent_blocks_runtime_until_maintenance_handoff()
    -> Result<(), Box<dyn std::error::Error>> {
        let parent = private_tempdir()?;
        let state = PrivateStateDirectory::open(parent.path())?;
        let maintenance = state.try_maintenance_lock()?;
        let marker = state.create_file(MAINTENANCE_PENDING_FILE)?;
        marker.file().sync_all()?;
        state.verify_identity()?;
        drop(marker);
        drop(maintenance);
        assert!(matches!(
            state.try_instance_lock(),
            Err(Error::MaintenancePending)
        ));
        let maintenance = state.try_maintenance_lock()?;
        fs::remove_file(state.path().join(MAINTENANCE_PENDING_FILE))?;
        File::open(state.path())?.sync_all()?;
        drop(maintenance);
        state.try_instance_lock()?.verify_identity()?;
        Ok(())
    }

    #[test]
    fn shared_diagnostics_block_maintenance_and_explicit_release_hands_off_aliases()
    -> Result<(), Box<dyn std::error::Error>> {
        let parent = private_tempdir()?;
        let state = PrivateStateDirectory::open(parent.path())?;
        let diagnostic = state.try_shared_maintenance_lock()?;
        let runtime = state.try_instance_lock()?;
        assert!(matches!(
            state.try_maintenance_lock(),
            Err(Error::LockUnavailable { .. })
        ));
        runtime.release()?;
        assert!(matches!(
            state.try_maintenance_lock(),
            Err(Error::LockUnavailable { .. })
        ));
        diagnostic.release()?;
        let maintenance = state.try_maintenance_lock()?;
        let inherited = maintenance._file.file().try_clone()?;
        maintenance.release()?;
        let runtime = state.try_instance_lock()?;
        let inherited_runtime = runtime._instance.file().try_clone()?;
        runtime.release()?;
        state.try_instance_lock()?.release()?;
        drop(inherited_runtime);
        drop(inherited);
        state.create_file(MAINTENANCE_PENDING_FILE)?;
        assert!(matches!(
            state.try_shared_maintenance_lock(),
            Err(Error::MaintenancePending)
        ));
        Ok(())
    }

    #[test]
    fn held_lock_detects_replacement_and_symlink_intent_is_not_ignored()
    -> Result<(), Box<dyn std::error::Error>> {
        let parent = private_tempdir()?;
        let state = PrivateStateDirectory::open(parent.path())?;
        let instance = state.try_instance_lock()?;
        fs::rename(
            state.path().join(INSTANCE_LOCK_FILE),
            state.path().join("old-lock"),
        )?;
        state.create_file(INSTANCE_LOCK_FILE)?;
        assert!(matches!(
            instance.verify_identity(),
            Err(Error::FileIdentityChanged { .. })
        ));
        drop(instance);
        symlink(
            "missing-maintenance-intent",
            state.path().join(MAINTENANCE_PENDING_FILE),
        )?;
        assert!(matches!(
            state.try_instance_lock(),
            Err(Error::MaintenancePending)
        ));
        Ok(())
    }
}
