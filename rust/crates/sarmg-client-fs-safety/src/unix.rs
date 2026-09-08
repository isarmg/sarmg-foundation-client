//! Portable Unix descriptor-relative primitives; intentionally does not need openat2.
use super::{
    AdvisoryLock, ConfigurationDirectory, EntryName, Error, FileEntry, InventoryLimits,
    PrivateDirectory, RelativePath, temporary_name,
};
use rustix::{
    fd::{AsFd, OwnedFd},
    fs::{
        AtFlags, FileType, Mode, OFlags, fstat, mkdirat, open, openat, renameat, statat, unlinkat,
    },
    process::geteuid,
};
use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Read, Write},
    path::{Component, Path},
};

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

// Ancestors require search permission, not directory-listing permission. Android
// sandboxes commonly allow only search on shared ancestors such as /data.
#[cfg(any(target_os = "linux", target_os = "android"))]
const WALK_FLAGS: OFlags = OFlags::PATH
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
const WALK_FLAGS: OFlags = DIRECTORY_FLAGS;

pub(super) fn open_configuration_directory(path: &Path) -> Result<ConfigurationDirectory, Error> {
    let directory = open_directory(path)?;
    let stat = fstat(&directory).map_err(io::Error::from)?;
    let uid = geteuid().as_raw();
    if !matches!(stat.st_mode & 0o7777, 0o700 | 0o750 | 0o755)
        || (stat.st_uid != 0 && stat.st_uid != uid && uid != 0)
    {
        return Err(Error::UnsafePermissions(path.to_path_buf()));
    }
    Ok(ConfigurationDirectory { directory })
}

enum PublicationMetadata {
    Private,
    Configuration(Option<rustix::fs::Stat>),
}

pub(super) fn replace_configuration(
    directory: &ConfigurationDirectory,
    name: &EntryName,
    bytes: &[u8],
) -> Result<(), Error> {
    let original = match open_regular_at(&directory.directory, name) {
        Ok(file) => {
            let metadata = fstat(&file).map_err(io::Error::from)?;
            if !matches!(metadata.st_mode & 0o7777, 0o600 | 0o640) {
                return Err(Error::UnsafePermissions(name.as_path().to_path_buf()));
            }
            Some(file)
        }
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let metadata = original
        .as_ref()
        .map(|file| fstat(file).map_err(io::Error::from))
        .transpose()?;
    let result = atomic_write_at(
        &directory.directory,
        &name.as_relative(),
        bytes,
        original.is_none(),
        PublicationMetadata::Configuration(metadata),
    );
    // Retain the original descriptor through publication, preventing inode reuse
    // from turning a removed/replaced original into the expected identity.
    drop(original);
    result
}

pub(super) fn read_configuration(
    directory: &ConfigurationDirectory,
    name: &EntryName,
    max_bytes: usize,
) -> Result<Vec<u8>, Error> {
    let file = open_regular_at(&directory.directory, name)?;
    let metadata = fstat(&file).map_err(io::Error::from)?;
    if !matches!(metadata.st_mode & 0o7777, 0o600 | 0o640) {
        return Err(Error::UnsafePermissions(name.as_path().to_path_buf()));
    }
    read_file_bounded(file, max_bytes)
}

pub(super) fn read_configuration_input(
    directory: &ConfigurationDirectory,
    name: &EntryName,
    max_bytes: usize,
    visibility: super::InputVisibility,
) -> Result<Vec<u8>, Error> {
    let file = open_regular_at(&directory.directory, name)?;
    let metadata = fstat(&file).map_err(io::Error::from)?;
    let parent = fstat(&directory.directory).map_err(io::Error::from)?;
    let mode = metadata.st_mode & 0o7777;
    let readable = matches!(mode, 0o400 | 0o440 | 0o600 | 0o640)
        || (visibility == super::InputVisibility::Public && matches!(mode, 0o444 | 0o644));
    if !readable || ![0, geteuid().as_raw(), parent.st_uid].contains(&metadata.st_uid) {
        return Err(Error::UnsafePermissions(name.as_path().to_path_buf()));
    }
    read_file_bounded(file, max_bytes)
}

fn validate_publication(
    directory: &File,
    name: &OsStr,
    metadata: &PublicationMetadata,
) -> Result<(), Error> {
    let PublicationMetadata::Configuration(expected) = metadata else {
        return validate_destination(directory, name);
    };
    let current = match statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Some(stat),
        Err(rustix::io::Errno::NOENT) => None,
        Err(error) => return Err(io::Error::from(error).into()),
    };
    match (expected, current) {
        (None, None) => Ok(()),
        (Some(expected), Some(current))
            if (
                expected.st_dev,
                expected.st_ino,
                expected.st_uid,
                expected.st_gid,
                expected.st_mode,
                expected.st_nlink,
            ) == (
                current.st_dev,
                current.st_ino,
                current.st_uid,
                current.st_gid,
                current.st_mode,
                current.st_nlink,
            ) =>
        {
            Ok(())
        }
        _ => Err(Error::IdentityChanged(name.into())),
    }
}

// Darwin can reject all symlinks in one kernel lookup. Opening each ancestor
// separately asks an iOS sandbox for permissions outside its app container.
#[cfg(target_vendor = "apple")]
pub(super) fn open_directory(path: &Path) -> Result<File, Error> {
    use std::os::unix::fs::OpenOptionsExt;
    if !path.is_absolute() {
        return Err(Error::AbsolutePathRequired(path.to_path_buf()));
    }
    if path
        .components()
        .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(Error::UnsafeRelativePath(path.to_path_buf()));
    }
    Ok(std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW_ANY | libc::O_CLOEXEC)
        .open(path)?)
}

#[cfg(not(target_vendor = "apple"))]
pub(super) fn open_directory(path: &Path) -> Result<File, Error> {
    if !path.is_absolute() {
        return Err(Error::AbsolutePathRequired(path.to_path_buf()));
    }
    let mut fd = open("/", WALK_FLAGS, Mode::empty()).map_err(io::Error::from)?;
    for component in path.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => {
                fd = openat(&fd, name, WALK_FLAGS, Mode::empty()).map_err(io::Error::from)?;
            }
            _ => return Err(Error::UnsafeRelativePath(path.to_path_buf())),
        }
    }
    // Return a readable handle anchored to the verified final directory, so
    // fsync and inventory retain their original behavior. No pathname rewalk.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let fd = openat(&fd, ".", DIRECTORY_FLAGS, Mode::empty()).map_err(io::Error::from)?;
    Ok(File::from(fd))
}

pub(super) fn open_private_directory(path: &Path) -> Result<PrivateDirectory, Error> {
    open_private_directory_with_access(path, false)
}

pub(super) fn open_administrative_directory(path: &Path) -> Result<PrivateDirectory, Error> {
    open_private_directory_with_access(path, true)
}

fn open_private_directory_with_access(
    path: &Path,
    administrator: bool,
) -> Result<PrivateDirectory, Error> {
    let directory = open_directory(path)?;
    validate_private_directory(&directory, path, administrator)?;
    Ok(PrivateDirectory {
        path: path.to_path_buf(),
        directory,
    })
}

fn validate_private_directory(
    directory: &File,
    path: &Path,
    administrator: bool,
) -> Result<(), Error> {
    let stat = fstat(directory).map_err(io::Error::from)?;
    let uid = geteuid().as_raw();
    if (stat.st_uid != uid && !(administrator && uid == 0)) || stat.st_mode & 0o7777 != 0o700 {
        return Err(Error::UnsafePermissions(path.to_path_buf()));
    }
    Ok(())
}

pub(super) fn create_private_directory(path: &Path) -> Result<PrivateDirectory, Error> {
    create_private_directory_with_access(path, false)
}

pub(super) fn create_administrative_directory(path: &Path) -> Result<PrivateDirectory, Error> {
    create_private_directory_with_access(path, true)
}

fn create_private_directory_with_access(
    path: &Path,
    administrator: bool,
) -> Result<PrivateDirectory, Error> {
    if !path.is_absolute() {
        return Err(Error::AbsolutePathRequired(path.to_path_buf()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| Error::UnsafeRelativePath(path.to_path_buf()))?;
    let name = path
        .file_name()
        .ok_or_else(|| Error::UnsafeRelativePath(path.to_path_buf()))?;
    let parent = open_directory(parent)?;
    create_private_at(&parent, name, path, administrator, false)
}

pub(super) fn create_private_child(
    parent: &PrivateDirectory,
    name: &EntryName,
) -> Result<PrivateDirectory, Error> {
    create_private_at(
        &parent.directory,
        name.as_os_str(),
        &parent.path.join(name.as_path()),
        true,
        true,
    )
}

fn create_private_at(
    parent: &File,
    name: &OsStr,
    path: &Path,
    administrator: bool,
    inherit: bool,
) -> Result<PrivateDirectory, Error> {
    let created = match mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
        Ok(()) => true,
        Err(rustix::io::Errno::EXIST) => false,
        Err(error) => return Err(io::Error::from(error).into()),
    };
    let directory =
        File::from(openat(parent, name, DIRECTORY_FLAGS, Mode::empty()).map_err(io::Error::from)?);
    if created && inherit {
        inherit_owner(&directory, parent)?;
    }
    validate_private_directory(&directory, path, administrator)?;
    // Never chmod an existing path: even a rejected symlink must have no effect.
    if created {
        directory.sync_all()?;
        parent.sync_all()?;
    }
    Ok(PrivateDirectory {
        path: path.to_path_buf(),
        directory,
    })
}

fn entry_name(path: &RelativePath) -> Result<&OsStr, Error> {
    if path.as_path().components().count() != 1 {
        return Err(Error::UnsafeRelativePath(path.as_path().to_path_buf()));
    }
    path.as_path()
        .file_name()
        .ok_or_else(|| Error::UnsafeRelativePath(path.as_path().to_path_buf()))
}

pub(super) fn sync_file_and_parent(path: &Path) -> Result<(), Error> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::UnsafeRelativePath(path.to_path_buf()))?;
    let name = path
        .file_name()
        .ok_or_else(|| Error::UnsafeRelativePath(path.to_path_buf()))?;
    let directory = open_directory(parent)?;
    let file = File::from(
        openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    regular_single_link(&file, path)?;
    file.sync_all()?;
    directory.sync_all()?;
    Ok(())
}

pub(super) fn files(
    directory: &PrivateDirectory,
    limits: InventoryLimits,
) -> Result<Vec<FileEntry>, Error> {
    let mut entries = rustix::fs::Dir::read_from(&directory.directory).map_err(io::Error::from)?;
    let mut result = Vec::new();
    let mut total_bytes = 0u64;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(io::Error::from)?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        if result.len() >= limits.max_entries {
            return Err(Error::BudgetExceeded);
        }
        use std::os::unix::ffi::OsStrExt;
        let name = EntryName::new(OsStr::from_bytes(name.to_bytes()))?;
        let file = open_regular(directory, &name)?;
        let bytes = file.metadata()?.len();
        total_bytes = total_bytes
            .checked_add(bytes)
            .ok_or(Error::BudgetExceeded)?;
        if total_bytes > limits.max_total_bytes {
            return Err(Error::BudgetExceeded);
        }
        result.push(FileEntry { name, bytes });
    }
    Ok(result)
}

fn open_regular(directory: &PrivateDirectory, name: &EntryName) -> Result<File, Error> {
    open_regular_at(&directory.directory, name)
}

fn open_regular_at(directory: &File, name: &EntryName) -> Result<File, Error> {
    let file = File::from(
        openat(
            directory,
            name.as_os_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    let identity = regular_single_link(&file, name.as_path())?;
    let current =
        statat(directory, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
    if (identity.st_dev, identity.st_ino) != (current.st_dev, current.st_ino) {
        return Err(Error::IdentityChanged(name.as_path().to_path_buf()));
    }
    Ok(file)
}

pub(super) fn read_bounded(
    directory: &PrivateDirectory,
    name: &EntryName,
    max_bytes: usize,
) -> Result<Vec<u8>, Error> {
    let file = open_regular(directory, name)?;
    read_file_bounded(file, max_bytes)
}

pub(super) fn read_private_bounded(
    directory: &PrivateDirectory,
    name: &EntryName,
    max_bytes: usize,
) -> Result<Vec<u8>, Error> {
    let file = open_regular(directory, name)?;
    let metadata = fstat(&file).map_err(io::Error::from)?;
    let owner = fstat(&directory.directory).map_err(io::Error::from)?;
    if metadata.st_mode & 0o7777 != 0o600
        || metadata.st_uid != owner.st_uid
        || metadata.st_gid != owner.st_gid
    {
        return Err(Error::UnsafePermissions(name.as_path().to_path_buf()));
    }
    read_file_bounded(file, max_bytes)
}

fn read_file_bounded(file: File, max_bytes: usize) -> Result<Vec<u8>, Error> {
    if file.metadata()?.len() > max_bytes as u64 {
        return Err(Error::BudgetExceeded);
    }
    let mut bytes = Vec::new();
    file.take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(Error::BudgetExceeded);
    }
    Ok(bytes)
}

pub(super) fn remove_file(directory: &PrivateDirectory, name: &EntryName) -> Result<(), Error> {
    let _file = open_regular(directory, name)?;
    unlinkat(&directory.directory, name.as_os_str(), AtFlags::empty()).map_err(io::Error::from)?;
    directory.sync()
}

fn regular_single_link(fd: impl AsFd, path: &Path) -> Result<rustix::fs::Stat, Error> {
    let stat = fstat(fd).map_err(io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(Error::UnsafeFileType(path.to_path_buf()));
    }
    if stat.st_nlink != 1 {
        return Err(Error::MultipleLinks(path.to_path_buf()));
    }
    Ok(stat)
}

fn validate_destination(directory: &File, name: &OsStr) -> Result<(), Error> {
    match statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
                return Err(Error::UnsafeFileType(name.into()));
            }
            if stat.st_nlink != 1 {
                return Err(Error::MultipleLinks(name.into()));
            }
            Ok(())
        }
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(error) => Err(io::Error::from(error).into()),
    }
}

pub(super) fn atomic_replace(
    directory: &PrivateDirectory,
    destination: &RelativePath,
    bytes: &[u8],
) -> Result<(), Error> {
    atomic_write(directory, destination, bytes, false)
}

pub(super) fn atomic_create(
    directory: &PrivateDirectory,
    destination: &EntryName,
    bytes: &[u8],
) -> Result<(), Error> {
    atomic_write(directory, &destination.as_relative(), bytes, true)
}

fn atomic_write(
    directory: &PrivateDirectory,
    destination: &RelativePath,
    bytes: &[u8],
    create_only: bool,
) -> Result<(), Error> {
    atomic_write_at(
        &directory.directory,
        destination,
        bytes,
        create_only,
        PublicationMetadata::Private,
    )
}

fn atomic_write_at(
    directory: &File,
    destination: &RelativePath,
    bytes: &[u8],
    create_only: bool,
    metadata: PublicationMetadata,
) -> Result<(), Error> {
    let name = entry_name(destination)?;
    validate_publication(directory, name, &metadata)?;
    let temporary = temporary_name()?;
    let fd: OwnedFd = openat(
        directory,
        temporary.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(io::Error::from)?;
    let mut file = File::from(fd);
    let result = (|| {
        match &metadata {
            PublicationMetadata::Configuration(Some(stat)) => {
                rustix::fs::fchown(
                    &file,
                    Some(rustix::process::Uid::from_raw(stat.st_uid)),
                    Some(rustix::process::Gid::from_raw(stat.st_gid)),
                )
                .map_err(io::Error::from)?;
                rustix::fs::fchmod(&file, Mode::from_raw_mode(stat.st_mode & 0o7777))
                    .map_err(io::Error::from)?;
            }
            _ => inherit_owner(&file, directory)?,
        }
        let identity = regular_single_link(&file, Path::new(&temporary))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        validate_publication(directory, name, &metadata)?;
        if create_only {
            no_clobber_publish_at(directory, &RelativePath::new(&temporary)?, destination)?;
        } else {
            renameat(directory, temporary.as_str(), directory, name).map_err(io::Error::from)?;
        }
        let published =
            statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
        if (identity.st_dev, identity.st_ino) != (published.st_dev, published.st_ino) {
            return Err(Error::IdentityChanged(destination.as_path().to_path_buf()));
        }
        directory
            .sync_all()
            .map_err(Error::PublishedDurabilityUnknown)
    })();
    if result.is_err() {
        // Our exclusive temporary lives under the held private directory handle.
        let _ = unlinkat(directory, temporary.as_str(), AtFlags::empty());
    }
    result
}

pub(super) fn advisory_lock(
    directory: &PrivateDirectory,
    name: &RelativePath,
    wait: bool,
) -> Result<AdvisoryLock, Error> {
    let name = entry_name(name)?;
    let path = Path::new(name);
    let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let (fd, created) = match openat(
        &directory.directory,
        name,
        flags | OFlags::CREATE | OFlags::EXCL,
        Mode::from_raw_mode(0o600),
    ) {
        Ok(fd) => (fd, true),
        Err(rustix::io::Errno::EXIST) => (
            openat(&directory.directory, name, flags, Mode::empty()).map_err(io::Error::from)?,
            false,
        ),
        Err(error) => return Err(io::Error::from(error).into()),
    };
    let file = File::from(fd);
    // Never repair an existing inode: it may have been planted by another actor.
    if created {
        inherit_owner(&file, &directory.directory)?;
    }
    let identity = regular_single_link(&file, path)?;
    let parent = fstat(&directory.directory).map_err(io::Error::from)?;
    if identity.st_uid != parent.st_uid
        || identity.st_gid != parent.st_gid
        || identity.st_mode & 0o7777 != 0o600
    {
        return Err(Error::UnsafePermissions(path.to_path_buf()));
    }
    if wait {
        file.lock()?;
    } else {
        file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => Error::AlreadyLocked(path.to_path_buf()),
            std::fs::TryLockError::Error(error) => Error::Io(error),
        })?;
    }
    // Revalidate after blocking, not just before taking the lock.
    let locked = regular_single_link(&file, path)?;
    if locked.st_uid != parent.st_uid
        || locked.st_gid != parent.st_gid
        || locked.st_mode & 0o7777 != 0o600
    {
        return Err(Error::UnsafePermissions(path.to_path_buf()));
    }
    let current =
        statat(&directory.directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
    if (identity.st_dev, identity.st_ino) != (current.st_dev, current.st_ino) {
        return Err(Error::IdentityChanged(path.to_path_buf()));
    }
    file.sync_all()?;
    directory.sync()?;
    Ok(AdvisoryLock { _file: file })
}

fn inherit_owner(file: &File, parent: &File) -> Result<(), Error> {
    let parent = fstat(parent).map_err(io::Error::from)?;
    let current = fstat(file).map_err(io::Error::from)?;
    if (parent.st_uid, parent.st_gid) != (current.st_uid, current.st_gid) {
        let uid = rustix::process::Uid::from_raw(parent.st_uid);
        let gid = rustix::process::Gid::from_raw(parent.st_gid);
        rustix::fs::fchown(file, Some(uid), Some(gid)).map_err(io::Error::from)?;
    }
    Ok(())
}

pub(super) fn no_clobber_publish(
    directory: &PrivateDirectory,
    source: &RelativePath,
    destination: &RelativePath,
) -> Result<(), Error> {
    no_clobber_publish_at(&directory.directory, source, destination)
}

fn no_clobber_publish_at(
    directory: &File,
    source: &RelativePath,
    destination: &RelativePath,
) -> Result<(), Error> {
    let source = entry_name(source)?;
    let destination = entry_name(destination)?;
    let file = File::from(
        openat(
            directory,
            source,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    let identity = regular_single_link(&file, Path::new(source))?;
    file.sync_all()?;
    #[cfg(target_os = "linux")]
    rustix::fs::renameat_with(
        directory,
        source,
        directory,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            Error::DestinationExists(destination.into())
        } else {
            io::Error::from(error).into()
        }
    })?;
    #[cfg(not(target_os = "linux"))]
    {
        rustix::fs::linkat(directory, source, directory, destination, AtFlags::empty())
            .map_err(io::Error::from)?;
        directory
            .sync_all()
            .map_err(Error::PublishedDurabilityUnknown)?;
        unlinkat(directory, source, AtFlags::empty())
            .map_err(|error| Error::PublishedDurabilityUnknown(error.into()))?;
    }
    let current = statat(directory, destination, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| Error::PublishedDurabilityUnknown(error.into()))?;
    if (identity.st_dev, identity.st_ino) != (current.st_dev, current.st_ino) {
        return Err(Error::IdentityChanged(destination.into()));
    }
    directory
        .sync_all()
        .map_err(Error::PublishedDurabilityUnknown)
}

/// DFS keeps at most 128 directory handles, independent of directory width.
pub(super) fn bounded_inventory(
    path: &Path,
    limits: crate::InventoryLimits,
) -> Result<crate::DirectoryInventory, Error> {
    use rustix::fs::Dir;
    let root = open_directory(path)?;
    let mut stack = vec![Dir::new(root).map_err(io::Error::from)?];
    let mut result = crate::DirectoryInventory {
        entries: 0,
        total_bytes: 0,
    };
    while let Some(current) = stack.last_mut() {
        let Some(entry) = current.read() else {
            stack.pop();
            continue;
        };
        let entry = entry.map_err(io::Error::from)?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        result.entries = result.entries.checked_add(1).ok_or(Error::BudgetExceeded)?;
        if result.entries > limits.max_entries {
            return Err(Error::BudgetExceeded);
        }
        let parent = current.fd().map_err(io::Error::from)?;
        let stat = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
        let kind = FileType::from_raw_mode(stat.st_mode);
        if !matches!(kind, FileType::Directory | FileType::RegularFile) {
            return Err(Error::UnsafeFileType(
                name.to_string_lossy().into_owned().into(),
            ));
        }
        let fd = openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let opened = fstat(&fd).map_err(io::Error::from)?;
        if (opened.st_dev, opened.st_ino, opened.st_mode)
            != (stat.st_dev, stat.st_ino, stat.st_mode)
        {
            return Err(Error::IdentityChanged(
                name.to_string_lossy().into_owned().into(),
            ));
        }
        if kind == FileType::RegularFile && opened.st_nlink != 1 {
            return Err(Error::MultipleLinks(
                name.to_string_lossy().into_owned().into(),
            ));
        }
        result.total_bytes = result
            .total_bytes
            .checked_add(u64::try_from(opened.st_size).map_err(|_| Error::BudgetExceeded)?)
            .ok_or(Error::BudgetExceeded)?;
        if result.total_bytes > limits.max_total_bytes {
            return Err(Error::BudgetExceeded);
        }
        if kind == FileType::Directory {
            if stack.len() >= 128 {
                return Err(Error::BudgetExceeded);
            }
            stack.push(Dir::new(fd).map_err(io::Error::from)?);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_inputs_enforce_visibility_ownership_and_held_directory() {
        use super::super::InputVisibility::{Confidential, Public};
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("inputs");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o750)).unwrap();
        let file = path.join("input");
        fs::write(&file, b"secret").unwrap();
        let name = EntryName::new("input").unwrap();
        let directory = ConfigurationDirectory::open(&path).unwrap();
        for mode in [
            0o400, 0o440, 0o600, 0o640, 0o444, 0o644, 0o660, 0o666, 0o4755,
        ] {
            fs::set_permissions(&file, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                directory.read_input_bounded(&name, 6, Confidential).is_ok(),
                matches!(mode, 0o400 | 0o440 | 0o600 | 0o640)
            );
            assert_eq!(
                directory.read_input_bounded(&name, 6, Public).is_ok(),
                matches!(mode, 0o400 | 0o440 | 0o600 | 0o640 | 0o444 | 0o644)
            );
            assert_eq!(
                fs::metadata(&file).unwrap().permissions().mode() & 0o7777,
                mode
            );
        }
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            directory.read_input_bounded(&name, 5, Confidential),
            Err(Error::BudgetExceeded)
        ));
        if geteuid().as_raw() == 0 {
            rustix::fs::chown(
                &file,
                Some(rustix::process::Uid::from_raw(65534)),
                Some(rustix::process::getegid()),
            )
            .unwrap();
            assert!(
                directory
                    .read_input_bounded(&name, 6, Confidential)
                    .is_err()
            );
            rustix::fs::chown(&file, Some(geteuid()), Some(rustix::process::getegid())).unwrap();
        }
        rustix::fs::mkfifoat(
            &directory.directory,
            "fifo-input",
            Mode::from_raw_mode(0o600),
        )
        .unwrap();
        assert!(
            directory
                .read_input_bounded(&EntryName::new("fifo-input").unwrap(), 6, Confidential)
                .is_err()
        );
        fs::rename(&path, temp.path().join("held")).unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(path.join("input"), b"replacement").unwrap();
        assert_eq!(
            directory
                .read_input_bounded(&name, 6, Confidential)
                .unwrap(),
            b"secret"
        );
        assert_eq!(fs::read(path.join("input")).unwrap(), b"replacement");
    }
    use crate::AtomicFile;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    #[test]
    fn configuration_metadata_and_held_directory_survive_replacement() {
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o750)).unwrap();
        let directory = ConfigurationDirectory::open(&path).unwrap();
        let name = EntryName::new("settings.json").unwrap();
        directory.replace(&name, b"first").unwrap();
        let target = path.join(name.as_path());
        assert_eq!(fs::metadata(&target).unwrap().mode() & 0o7777, 0o600);
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        let before = fs::metadata(&target).unwrap();
        fs::rename(&path, temp.path().join("held")).unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(&target, b"do not touch").unwrap();
        directory.replace(&name, b"second").unwrap();
        let after = fs::metadata(temp.path().join("held/settings.json")).unwrap();
        assert_eq!(
            (before.uid(), before.gid(), before.mode() & 0o7777),
            (after.uid(), after.gid(), after.mode() & 0o7777)
        );
        assert_ne!(before.ino(), after.ino());
        assert_eq!(directory.read_bounded(&name, 6).unwrap(), b"second");
        assert!(matches!(
            directory.read_bounded(&name, 5),
            Err(Error::BudgetExceeded)
        ));
        assert_eq!(fs::read(&target).unwrap(), b"do not touch");
        assert_eq!(fs::read_dir(temp.path().join("held")).unwrap().count(), 1);
    }

    #[test]
    fn configuration_rejects_links_special_files_and_unsafe_modes_without_repair() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config");
        assert!(ConfigurationDirectory::open(&path).is_err());
        assert!(!path.exists());
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(ConfigurationDirectory::open(&path).is_err());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o770
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o750)).unwrap();
        symlink(&path, temp.path().join("alias")).unwrap();
        assert!(ConfigurationDirectory::open(temp.path().join("alias")).is_err());
        let directory = ConfigurationDirectory::open(&path).unwrap();
        let victim = temp.path().join("victim");
        fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, path.join("symlink")).unwrap();
        fs::hard_link(&victim, path.join("hardlink")).unwrap();
        rustix::fs::mkfifoat(&directory.directory, "fifo", Mode::from_raw_mode(0o600)).unwrap();
        fs::write(path.join("public"), b"untouched").unwrap();
        fs::set_permissions(path.join("public"), fs::Permissions::from_mode(0o644)).unwrap();
        for name in ["symlink", "hardlink", "fifo", "public"] {
            let name = EntryName::new(name).unwrap();
            assert!(directory.replace(&name, b"secret").is_err());
            assert!(directory.read_bounded(&name, 64).is_err());
        }
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
        assert_eq!(
            fs::metadata(path.join("public"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o644
        );
        assert_eq!(fs::read_dir(&path).unwrap().count(), 4);
    }

    #[test]
    fn configuration_rejects_changed_metadata_or_occupants_before_publication() {
        let temp = tempfile::tempdir().unwrap();
        let directory = ConfigurationDirectory::open(temp.path()).unwrap();
        let name = EntryName::new("settings").unwrap();
        directory.replace(&name, b"original").unwrap();
        let original = open_regular_at(&directory.directory, &name).unwrap();
        let metadata = fstat(&original).unwrap();
        fs::set_permissions(
            temp.path().join("settings"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        assert!(matches!(
            atomic_write_at(
                &directory.directory,
                &name.as_relative(),
                b"bad",
                false,
                PublicationMetadata::Configuration(Some(metadata))
            ),
            Err(Error::IdentityChanged(_))
        ));
        assert!(matches!(
            atomic_write_at(
                &directory.directory,
                &name.as_relative(),
                b"bad",
                true,
                PublicationMetadata::Configuration(None)
            ),
            Err(Error::IdentityChanged(_))
        ));
        assert_eq!(fs::read(temp.path().join("settings")).unwrap(), b"original");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn waiting_lock_serializes_transactions_without_unlinking_the_inode() {
        use std::{sync::mpsc, time::Duration};
        let temp = tempfile::tempdir().unwrap();
        let directory = PrivateDirectory::create(temp.path().join("state")).unwrap();
        let name = EntryName::new("transaction.lock").unwrap();
        let first = AdvisoryLock::acquire_waiting(&directory, &name).unwrap();
        let identity = fs::metadata(directory.path().join(name.as_path())).unwrap();
        let (tx, rx) = mpsc::channel();
        let path = directory.path().to_path_buf();
        let second = std::thread::spawn(move || {
            let directory = PrivateDirectory::open_existing(path).unwrap();
            tx.send(false).unwrap();
            let _lock = AdvisoryLock::acquire_waiting(&directory, &name).unwrap();
            tx.send(true).unwrap();
        });
        assert!(!rx.recv_timeout(Duration::from_secs(5)).unwrap());
        assert!(matches!(
            rx.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(first);
        assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap());
        second.join().unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            identity.ino(),
            fs::metadata(directory.path().join("transaction.lock"))
                .unwrap()
                .ino()
        );
    }

    #[test]
    fn private_reads_are_bounded_permission_checked_and_anchored() {
        let temp = tempfile::tempdir().unwrap();
        let directory = PrivateDirectory::create(temp.path().join("state")).unwrap();
        let name = EntryName::new("credential").unwrap();
        AtomicFile::replace(&directory, &name.as_relative(), b"secret").unwrap();
        assert_eq!(directory.read_private_bounded(&name, 6).unwrap(), b"secret");
        assert!(matches!(
            directory.read_private_bounded(&name, 5),
            Err(Error::BudgetExceeded)
        ));
        for mode in [0o644, 0o640, 0o000, 0o1600] {
            fs::set_permissions(
                directory.path().join(name.as_path()),
                fs::Permissions::from_mode(mode),
            )
            .unwrap();
            assert!(directory.read_private_bounded(&name, 6).is_err());
        }
        fs::set_permissions(
            directory.path().join(name.as_path()),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        symlink(
            directory.path().join(name.as_path()),
            directory.path().join("alias"),
        )
        .unwrap();
        assert!(
            directory
                .read_private_bounded(&EntryName::new("alias").unwrap(), 6)
                .is_err()
        );
        fs::remove_file(directory.path().join("alias")).unwrap();
        fs::hard_link(
            directory.path().join(name.as_path()),
            directory.path().join("alias"),
        )
        .unwrap();
        assert!(matches!(
            directory.read_private_bounded(&name, 6),
            Err(Error::MultipleLinks(_))
        ));
        fs::remove_file(directory.path().join("alias")).unwrap();
        rustix::fs::mkfifoat(&directory.directory, "fifo", Mode::from_raw_mode(0o600)).unwrap();
        assert!(
            directory
                .read_private_bounded(&EntryName::new("fifo").unwrap(), 6)
                .is_err()
        );
        fs::remove_file(directory.path().join("fifo")).unwrap();
        let sparse = fs::OpenOptions::new()
            .write(true)
            .open(directory.path().join(name.as_path()))
            .unwrap();
        sparse.set_len(1 << 30).unwrap();
        assert!(matches!(
            directory.read_private_bounded(&name, 6),
            Err(Error::BudgetExceeded)
        ));
        sparse.set_len(6).unwrap();
        drop(sparse);
        fs::rename(directory.path(), temp.path().join("held")).unwrap();
        let replacement = PrivateDirectory::create(directory.path()).unwrap();
        AtomicFile::replace(&replacement, &name.as_relative(), b"other!").unwrap();
        assert_eq!(directory.read_private_bounded(&name, 6).unwrap(), b"secret");
        assert_eq!(
            replacement.read_private_bounded(&name, 6).unwrap(),
            b"other!"
        );
    }

    #[test]
    fn waiting_lock_rejects_links_special_files_and_non_private_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let directory = PrivateDirectory::create(temp.path().join("state")).unwrap();
        let victim = temp.path().join("victim");
        fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, directory.path().join("symlink")).unwrap();
        fs::hard_link(&victim, directory.path().join("hardlink")).unwrap();
        fs::write(directory.path().join("public"), b"public").unwrap();
        fs::set_permissions(
            directory.path().join("public"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        rustix::fs::mkfifoat(&directory.directory, "fifo", Mode::from_raw_mode(0o600)).unwrap();
        for name in ["symlink", "hardlink", "public", "fifo"] {
            assert!(
                AdvisoryLock::acquire_waiting(&directory, &EntryName::new(name).unwrap()).is_err(),
                "{name}"
            );
        }
        assert_eq!(fs::read(victim).unwrap(), b"untouched");
        assert_eq!(
            fs::metadata(directory.path().join("public"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o644
        );
    }

    #[test]
    fn administrative_access_never_repairs_or_follows_an_unsafe_directory() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(PrivateDirectory::create_for_administration(&path).is_err());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        let link = temp.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(PrivateDirectory::open_for_administration(&link).is_err());
        assert!(PrivateDirectory::create_for_administration(link.join("nested")).is_err());
        assert!(!path.join("nested").exists());
        assert!(PrivateDirectory::open_for_administration(temp.path().join("missing")).is_err());
        assert!(!temp.path().join("missing").exists());
    }

    #[test]
    fn administrator_publishes_and_locks_as_the_service_owner() {
        use std::os::unix::{fs::MetadataExt, process::CommandExt};
        if geteuid().as_raw() != 0 {
            eprintln!(
                "service-owner subprocess requires root; covered by privileged Linux acceptance"
            );
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let path = temp.path().join("state");
        let directory = PrivateDirectory::create(&path).unwrap();
        rustix::fs::fchown(
            &directory.directory,
            Some(rustix::process::Uid::from_raw(65534)),
            Some(rustix::process::Gid::from_raw(65534)),
        )
        .unwrap();
        drop(directory);
        assert!(PrivateDirectory::open_existing(&path).is_err());
        assert!(PrivateDirectory::create(&path).is_err());
        let directory = PrivateDirectory::create_for_administration(&path).unwrap();
        let foreign = directory.path().join("foreign");
        fs::write(&foreign, b"not service owned").unwrap();
        fs::set_permissions(&foreign, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            directory.read_private_bounded(&EntryName::new("foreign").unwrap(), 64),
            Err(Error::UnsafePermissions(_))
        ));
        let file = File::open(&foreign).unwrap();
        rustix::fs::fchown(&file, Some(rustix::process::Uid::from_raw(65534)), None).unwrap();
        assert!(matches!(
            directory.read_private_bounded(&EntryName::new("foreign").unwrap(), 64),
            Err(Error::UnsafePermissions(_))
        ));
        drop(file);
        fs::remove_file(foreign).unwrap();
        AtomicFile::replace(
            &directory,
            &RelativePath::new("credential").unwrap(),
            b"secret",
        )
        .unwrap();
        drop(
            AdvisoryLock::acquire_waiting(&directory, &EntryName::new("transaction.lock").unwrap())
                .unwrap(),
        );
        let child = directory
            .create_child(&EntryName::new("queue").unwrap())
            .unwrap();
        for (path, mode) in [
            (path.clone(), 0o700),
            (path.join("credential"), 0o600),
            (path.join("transaction.lock"), 0o600),
            (child.path().to_path_buf(), 0o700),
        ] {
            let metadata = fs::metadata(path).unwrap();
            assert_eq!(
                (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777),
                (65534, 65534, mode)
            );
        }
        let config_path = temp.path().join("service-config");
        fs::create_dir(&config_path).unwrap();
        let config_dir = open_directory(&config_path).unwrap();
        rustix::fs::fchown(
            &config_dir,
            None,
            Some(rustix::process::Gid::from_raw(65534)),
        )
        .unwrap();
        rustix::fs::fchmod(&config_dir, Mode::from_raw_mode(0o750)).unwrap();
        let configuration = ConfigurationDirectory::open(&config_path).unwrap();
        let config_name = EntryName::new("settings").unwrap();
        configuration.replace(&config_name, b"first").unwrap();
        fs::set_permissions(
            config_path.join("settings"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        configuration
            .replace(&config_name, b"service-readable")
            .unwrap();
        let metadata = fs::metadata(config_path.join("settings")).unwrap();
        assert_eq!(
            (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777),
            (0, 65534, 0o640)
        );
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "unix::tests::service_owner_subprocess",
            ])
            .env("SARMG_FS_SERVICE_OWNER_TEST", &path)
            .env("SARMG_FS_SERVICE_CONFIG_TEST", &config_path)
            .uid(65534)
            .gid(65534)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            directory
                .read_private_bounded(&EntryName::new("credential").unwrap(), 32)
                .unwrap(),
            b"rotated"
        );
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn private_directory_under_search_only_ancestor() {
        use std::os::unix::process::CommandExt;
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args([
            "--ignored",
            "--exact",
            "unix::tests::search_only_ancestor_subprocess",
        ]);
        if geteuid().as_raw() == 0 {
            command.uid(65534).gid(65534);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[ignore = "invoked without root directory-read privileges by the parent test"]
    fn search_only_ancestor_subprocess() {
        assert_ne!(geteuid().as_raw(), 0);
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let ancestor = root.join("search-only");
        fs::create_dir(&ancestor).unwrap();
        let path = ancestor.join("private");
        PrivateDirectory::create(&path).unwrap();
        symlink(&path, ancestor.join("alias")).unwrap();
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o111)).unwrap();
        assert!(fs::read_dir(&ancestor).is_err());
        let result = PrivateDirectory::open_existing(&path).and_then(|directory| {
            let name = EntryName::new("retained")?;
            AtomicFile::replace(&directory, &name.as_relative(), b"private")?;
            assert_eq!(directory.read_private_bounded(&name, 7)?, b"private");
            directory.sync()
        });
        let alias_result = PrivateDirectory::open_existing(ancestor.join("alias"));
        // Restore fixture permissions even on failure so TempDir can clean it up.
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700)).unwrap();
        result.unwrap();
        assert!(alias_result.is_err());
    }

    #[test]
    #[ignore = "invoked with a service uid/gid by the administrative ownership test"]
    fn service_owner_subprocess() {
        let config_path = std::env::var_os("SARMG_FS_SERVICE_CONFIG_TEST").unwrap();
        let configuration = ConfigurationDirectory::open(config_path).unwrap();
        assert_eq!(
            configuration
                .read_input_bounded(
                    &EntryName::new("settings").unwrap(),
                    64,
                    super::super::InputVisibility::Confidential,
                )
                .unwrap(),
            b"service-readable"
        );
        assert_eq!(
            configuration
                .read_bounded(&EntryName::new("settings").unwrap(), 64)
                .unwrap(),
            b"service-readable"
        );
        let path = std::env::var_os("SARMG_FS_SERVICE_OWNER_TEST").unwrap();
        let directory = PrivateDirectory::open_existing(path).unwrap();
        let _lock =
            AdvisoryLock::acquire_waiting(&directory, &EntryName::new("transaction.lock").unwrap())
                .unwrap();
        assert_eq!(
            directory
                .read_private_bounded(&EntryName::new("credential").unwrap(), 32)
                .unwrap(),
            b"secret"
        );
        AtomicFile::replace(
            &directory,
            &RelativePath::new("credential").unwrap(),
            b"rotated",
        )
        .unwrap();
    }

    #[test]
    fn rejecting_private_directory_does_not_chmod_a_symlink_target_or_existing_directory() {
        let temp = tempfile::tempdir().unwrap();
        let victim = temp.path().join("victim");
        fs::create_dir(&victim).unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o755)).unwrap();
        let link = temp.path().join("link");
        symlink(&victim, &link).unwrap();
        assert!(PrivateDirectory::create(&link).is_err());
        assert!(PrivateDirectory::create(&victim).is_err());
        assert_eq!(
            fs::metadata(&victim).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        assert!(PrivateDirectory::create(link.join("nested")).is_err());
        assert!(!victim.join("nested").exists());
    }

    #[test]
    fn held_private_directory_survives_path_rebinding_without_touching_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("state");
        let root = PrivateDirectory::create(&original).unwrap();
        let moved = temp.path().join("moved");
        fs::rename(&original, &moved).unwrap();
        fs::create_dir(&original).unwrap();
        AtomicFile::replace(&root, &RelativePath::new("entry").unwrap(), b"private").unwrap();
        assert_eq!(fs::read(moved.join("entry")).unwrap(), b"private");
        assert!(!original.join("entry").exists());
        assert_eq!(
            fs::metadata(moved.join("entry"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        AdvisoryLock::acquire(&root, &RelativePath::new("lock").unwrap()).unwrap();
        assert!(!original.join("lock").exists());
    }

    #[test]
    fn writes_and_locks_refuse_links_and_nested_aliases() {
        let temp = tempfile::tempdir().unwrap();
        let root = PrivateDirectory::create(temp.path().join("state")).unwrap();
        let victim = temp.path().join("victim");
        fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, root.path().join("link")).unwrap();
        fs::hard_link(&victim, root.path().join("hard")).unwrap();
        symlink(temp.path(), root.path().join("escape")).unwrap();
        for name in ["link", "hard", "escape/victim"] {
            let name = RelativePath::new(name).unwrap();
            assert!(AtomicFile::replace(&root, &name, b"changed").is_err());
            assert!(AdvisoryLock::acquire(&root, &name).is_err());
            assert!(crate::sync_file_and_parent(&root.resolve(&name)).is_err());
        }
        assert_eq!(fs::read(victim).unwrap(), b"untouched");
    }

    #[test]
    fn typed_entry_io_is_bounded_and_create_never_replaces_existing_content() {
        let temp = tempfile::tempdir().unwrap();
        let directory = PrivateDirectory::create(temp.path().join("state")).unwrap();
        for invalid in ["", ".", "..", "a/b", "a/", "a\0b"] {
            assert!(EntryName::new(invalid).is_err(), "{invalid:?}");
        }
        let entry = EntryName::new("current").unwrap();
        AtomicFile::create(&directory, &entry, b"original").unwrap();
        assert!(AtomicFile::create(&directory, &entry, b"replace").is_err());
        assert_eq!(directory.read_bounded(&entry, 8).unwrap(), b"original");
        assert!(matches!(
            directory.read_bounded(&entry, 7),
            Err(Error::BudgetExceeded)
        ));
        let entries = directory
            .files(InventoryLimits {
                max_entries: 1,
                max_total_bytes: 8,
            })
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].bytes, 8);
        assert!(matches!(
            directory.files(InventoryLimits {
                max_entries: 0,
                max_total_bytes: 8
            }),
            Err(Error::BudgetExceeded)
        ));
        assert!(matches!(
            directory.files(InventoryLimits {
                max_entries: 1,
                max_total_bytes: 7
            }),
            Err(Error::BudgetExceeded)
        ));
        let path = directory.path().join(entry.as_path());
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_len(8 * 1024 * 1024 * 1024)
            .unwrap();
        assert!(matches!(
            directory.read_bounded(&entry, 1024),
            Err(Error::BudgetExceeded)
        ));
        directory.remove_file(&entry).unwrap();
        assert!(
            directory
                .files(InventoryLimits {
                    max_entries: 0,
                    max_total_bytes: 0
                })
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn no_clobber_has_one_winner_and_never_replaces_an_occupant() {
        let temp = tempfile::tempdir().unwrap();
        let root =
            std::sync::Arc::new(PrivateDirectory::create(temp.path().join("state")).unwrap());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = ["first", "second"]
            .into_iter()
            .map(|value| {
                let root = root.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let source = RelativePath::new(value).unwrap();
                    AtomicFile::replace(&root, &source, value.as_bytes()).unwrap();
                    barrier.wait();
                    crate::NoClobberPublish::publish(
                        &root,
                        &source,
                        &RelativePath::new("current").unwrap(),
                    )
                    .is_ok()
                })
            })
            .collect();
        assert_eq!(
            workers
                .into_iter()
                .map(|worker| usize::from(worker.join().unwrap()))
                .sum::<usize>(),
            1
        );
        let bytes = fs::read(root.path().join("current")).unwrap();
        assert!(bytes == b"first" || bytes == b"second");
        let victim = temp.path().join("victim");
        fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, root.path().join("occupied")).unwrap();
        let current = RelativePath::new("current").unwrap();
        assert!(
            crate::NoClobberPublish::publish(
                &root,
                &current,
                &RelativePath::new("occupied").unwrap()
            )
            .is_err()
        );
        assert_eq!(fs::read(victim).unwrap(), b"untouched");
        assert_eq!(fs::read(root.resolve(&current)).unwrap(), bytes);
    }

    #[test]
    fn inventory_rejects_linked_root_special_files_and_excessive_depth() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let alias = temp.path().join("alias");
        symlink(&root, &alias).unwrap();
        let limits = crate::InventoryLimits {
            max_entries: 1000,
            max_total_bytes: 16 * 1024 * 1024,
        };
        assert!(bounded_inventory(&alias, limits).is_err());
        let mut parent = root.clone();
        for _ in 0..128 {
            parent = parent.join("d");
            fs::create_dir(&parent).unwrap();
        }
        assert!(matches!(
            bounded_inventory(&root, limits),
            Err(Error::BudgetExceeded)
        ));
        let specials = tempfile::tempdir().unwrap();
        let _listener =
            std::os::unix::net::UnixListener::bind(specials.path().join("socket")).unwrap();
        assert!(matches!(
            bounded_inventory(specials.path(), limits),
            Err(Error::UnsafeFileType(_))
        ));
    }
}
