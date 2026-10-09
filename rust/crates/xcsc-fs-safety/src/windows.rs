//! Native private storage: descriptor ACLs, no-follow handles and atomic handle publication.
use super::{
    AdvisoryLock, DirectoryInventory, EntryName, Error, FileEntry, InventoryLimits,
    PrivateDirectory,
};
use std::{
    ffi::{OsStr, c_void},
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::windows::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, PathBuf, Prefix},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::Threading::*,
};

/// Access requested on an existing private regular file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateFileAccess {
    ReadOnly,
    ReadWrite,
}

/// A private file with owned pins for its original directory and ancestors.
/// No delete sharing, reparse points, hard links, or untrusted ACLs are accepted.
#[derive(Debug)]
pub struct WindowsPrivateFile {
    file: File,
    directory: PrivateDirectory,
    name: EntryName,
}

impl WindowsPrivateFile {
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Recheck the held objects without opening a second path or changing ACLs.
    pub fn verify(&self) -> Result<(), Error> {
        verify_directory(&self.directory)?;
        let path = self.directory.path.join(self.name.as_path());
        verify_kind(&self.file, &path, false)?;
        verify_acl(&self.file, &self.directory.access, &path, false).map(|_| ())
    }
}

pub(super) fn hold_private_file(
    directory: &PrivateDirectory,
    name: &EntryName,
    access: PrivateFileAccess,
) -> Result<WindowsPrivateFile, Error> {
    verify_directory(directory)?;
    let pinned = PrivateDirectory {
        path: directory.path.clone(),
        directory: directory.directory.try_clone()?,
        ancestors: directory
            .ancestors
            .iter()
            .map(File::try_clone)
            .collect::<Result<_, _>>()?,
        access: directory.access.clone(),
        service_anchor: directory.service_anchor,
    };
    let file = open_private(&pinned, name, access == PrivateFileAccess::ReadWrite, false)?;
    let held = WindowsPrivateFile {
        file,
        directory: pinned,
        name: name.clone(),
    };
    held.verify()?;
    Ok(held)
}

/// Derive the canonical Windows SCM service SID without requiring installation.
/// The OS uppercase mapping is used per UTF-16 unit, followed by SCM's SHA-1
/// identifier algorithm. This fixed protocol hash is not a credential hash.
pub fn service_sid(name: &str) -> Result<String, Error> {
    use sha1::{Digest, Sha1};
    let units: Vec<u16> = name.encode_utf16().collect();
    if units.is_empty() || units.len() > 256 || units.iter().any(|unit| matches!(unit, 0 | 47 | 92))
    {
        return Err(Error::UnsafeRelativePath(PathBuf::new()));
    }
    let mut hash = Sha1::new();
    for unit in units {
        // SAFETY: RtlUpcaseUnicodeChar takes and returns a UTF-16 code unit by
        // value. It borrows no storage, allocates no memory and retains no
        // pointer. Native mapping preserves SCM's invariant case semantics.
        let upper = unsafe { windows_sys::Wdk::System::SystemServices::RtlUpcaseUnicodeChar(unit) };
        hash.update(upper.to_le_bytes());
    }
    let digest = hash.finalize();
    let mut sid = String::from("S-1-5-80");
    for part in digest.as_slice().as_chunks::<4>().0 {
        sid.push('-');
        sid.push_str(&u32::from_le_bytes(*part).to_string());
    }
    Ok(sid)
}

/// Return the current process token's user SID without granting any access.
/// This reads the primary token, independent of any thread impersonation.
pub fn process_user_sid() -> Result<String, Error> {
    token_user_sid(&process_token()?)
}

fn token_user_sid(token: &File) -> Result<String, Error> {
    let user = token_information(token, TokenUser)?;
    if user.len() * std::mem::size_of::<u64>() < std::mem::size_of::<TOKEN_USER>() {
        return Err(Error::UnsafePermissions(PathBuf::new()));
    }
    // SAFETY: successful TokenUser output is held in this aligned allocation,
    // its fixed struct is in bounds, and its SID remains valid until conversion.
    unsafe { sid_text((*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid) }
}

#[derive(Clone, Debug)]
pub struct WindowsPrivateAccess {
    principals: Vec<String>,
    service_sid: Option<String>,
}
impl WindowsPrivateAccess {
    pub fn current_process() -> Result<Self, Error> {
        let token = process_token()?;
        let mut principals = vec![
            token_user_sid(&token)?,
            "S-1-5-18".into(),
            "S-1-5-32-544".into(),
        ];
        let groups = token_information(&token, TokenGroups)?;
        let count = groups
            .first()
            .ok_or_else(|| Error::UnsafePermissions(PathBuf::new()))?;
        let count = u32::from_ne_bytes(
            count.to_ne_bytes()[..4]
                .try_into()
                .expect("four count bytes"),
        ) as usize;
        let offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
        if count > 4096
            || offset + count * std::mem::size_of::<SID_AND_ATTRIBUTES>() > groups.len() * 8
        {
            return Err(Error::UnsafePermissions(PathBuf::new()));
        }
        // SAFETY: successful SDK output is aligned by u64 storage. The count
        // is read before constructing references and the complete array is in
        // bounds; embedded SID pointers remain valid in this held allocation.
        unsafe {
            let array = groups
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<SID_AND_ATTRIBUTES>();
            for group in std::slice::from_raw_parts(array, count) {
                let sid = sid_text(group.Sid)?;
                if group.Attributes & 4 != 0
                    && group.Attributes & 16 == 0
                    && specific_service_sid(&sid)
                {
                    principals.push(sid);
                }
            }
        }
        principals.sort();
        principals.dedup();
        Ok(Self {
            principals,
            service_sid: None,
        })
    }
    /// Add one product-authoritative SCM service SID and its built-in service account.
    /// No arbitrary users, group wildcards or all-services SID are accepted.
    pub fn for_service(service_sid: &str, account_sid: &str) -> Result<Self, Error> {
        if !specific_service_sid(service_sid)
            || !matches!(account_sid, "S-1-5-18" | "S-1-5-19" | "S-1-5-20")
        {
            return Err(Error::UnsafePermissions(PathBuf::new()));
        }
        let mut principals = vec![
            "S-1-5-18".into(),
            "S-1-5-32-544".into(),
            service_sid.into(),
            account_sid.into(),
        ];
        principals.sort();
        principals.dedup();
        let value = Self {
            principals,
            service_sid: Some(service_sid.into()),
        };
        Ok(value)
    }
    /// Read or create state owned by one explicit built-in service account.
    /// Products supply the account from their own SCM definition.
    pub fn for_service_account(account_sid: &str) -> Result<Self, Error> {
        if !matches!(account_sid, "S-1-5-18" | "S-1-5-19" | "S-1-5-20") {
            return Err(Error::UnsafePermissions(PathBuf::new()));
        }
        let mut principals = vec!["S-1-5-18".into(), "S-1-5-32-544".into(), account_sid.into()];
        principals.sort();
        principals.dedup();
        Ok(Self {
            principals,
            service_sid: None,
        })
    }
    /// Current user and administrators only, without enabled service group grants.
    pub fn for_current_user() -> Result<Self, Error> {
        let mut value = Self::current_process()?;
        value.principals.retain(|sid| !specific_service_sid(sid));
        Ok(value)
    }
    fn accepts(&self, sid: &str) -> bool {
        self.principals.iter().any(|p| p == sid)
    }
    fn accepts_anchor_owner(&self, sid: &str) -> bool {
        matches!(sid, "S-1-5-18" | "S-1-5-32-544") || self.service_sid.as_deref() == Some(sid)
    }
    fn accepts_ace(&self, sid: &str) -> bool {
        if let Some(service) = &self.service_sid {
            matches!(sid, "S-1-5-18" | "S-1-5-32-544") || sid == service
        } else {
            self.accepts(sid)
        }
    }
    fn descriptor(&self, inherit: bool) -> Result<Allocation, Error> {
        let flags = if inherit { "OICI" } else { "" };
        let mut sddl = String::from("D:P");
        for principal in &self.principals {
            if !self.accepts_ace(principal) {
                continue;
            }
            let rights = if self.service_sid.as_ref() == Some(principal) {
                "0x1301bf"
            } else {
                "FA"
            };
            sddl.push_str(&format!("(A;{flags};{rights};;;{principal})"));
        }
        if self.service_sid.is_some() {
            sddl.push_str(&format!("(A;{flags};RC;;;OW)"));
        }
        unsafe {
            let mut raw = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(OsStr::new(&sddl))?.as_ptr(),
                1,
                &mut raw,
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(io_error());
            }
            Ok(Allocation(raw))
        }
    }
}
fn specific_service_sid(sid: &str) -> bool {
    let Some(suffix) = sid.strip_prefix("S-1-5-80-") else {
        return false;
    };
    let mut count = 0;
    for component in suffix.split('-') {
        let Ok(number) = component.parse::<u32>() else {
            return false;
        };
        if number.to_string() != component {
            return false;
        }
        count += 1;
    }
    count == 5
}
struct Allocation(*mut c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn io_error() -> Error {
    std::io::Error::last_os_error().into()
}
fn wide(value: &OsStr) -> Result<Vec<u16>, Error> {
    let mut value: Vec<_> = value.encode_wide().collect();
    if value.contains(&0) {
        return Err(Error::UnsafeRelativePath(PathBuf::new()));
    }
    value.push(0);
    Ok(value)
}
unsafe fn sid_text(sid: PSID) -> Result<String, Error> {
    unsafe {
        if sid.is_null() || IsValidSid(sid) == 0 {
            return Err(Error::UnsafePermissions(PathBuf::new()));
        }
        let mut raw = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut raw) == 0 {
            return Err(io_error());
        }
        let _allocation = Allocation(raw.cast());
        let mut size = 0;
        while *raw.add(size) != 0 {
            size += 1;
            if size > 256 {
                return Err(Error::UnsafePermissions(PathBuf::new()));
            }
        }
        String::from_utf16(std::slice::from_raw_parts(raw, size))
            .map_err(|_| Error::UnsafePermissions(PathBuf::new()))
    }
}
fn process_token() -> Result<File, Error> {
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut token,
        ) == 0
        {
            return Err(io_error());
        }
        Ok(File::from_raw_handle(token))
    }
}
fn token_information(token: &File, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<u64>, Error> {
    unsafe {
        let mut needed = 0;
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
        if needed == 0 || needed > 65536 {
            return Err(Error::UnsafePermissions(PathBuf::new()));
        }
        let mut value = vec![0u64; (needed as usize).div_ceil(8)];
        if GetTokenInformation(
            token.as_raw_handle(),
            class,
            value.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ) == 0
        {
            return Err(io_error());
        }
        Ok(value)
    }
}

fn creation_owner_sid() -> Result<String, Error> {
    let mut raw = std::ptr::null_mut();
    // SAFETY: query the actual impersonation token when present. OpenAsSelf
    // only authorizes obtaining its handle, not changing the effective token.
    let token = if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } != 0 {
        // SAFETY: successful token open transfers one unique owned handle.
        unsafe { File::from_raw_handle(raw) }
    } else if unsafe { GetLastError() } == ERROR_NO_TOKEN {
        // SAFETY: no impersonation token exists. Query only the real primary
        // token; successful output transfers one uniquely owned handle.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
            return Err(io_error());
        }
        // SAFETY: successful process token open transfers handle ownership.
        unsafe { File::from_raw_handle(raw) }
    } else {
        return Err(io_error());
    };
    let owner = token_information(&token, TokenOwner)?;
    if owner.len() * std::mem::size_of::<u64>() < std::mem::size_of::<TOKEN_OWNER>() {
        return Err(Error::UnsafePermissions(PathBuf::new()));
    }
    // SAFETY: successful TokenOwner SDK output is held in aligned storage;
    // the fixed struct and its embedded owner SID remain live for conversion.
    unsafe { sid_text((*owner.as_ptr().cast::<TOKEN_OWNER>()).Owner) }
}
struct VerifiedAcl {
    protected: bool,
    anchor_owner: bool,
}

fn verify_acl(
    file: &File,
    access: &WindowsPrivateAccess,
    path: &Path,
    directory: bool,
) -> Result<VerifiedAcl, Error> {
    unsafe {
        let mut owner = std::ptr::null_mut();
        let mut acl = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        let code = GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut acl,
            std::ptr::null_mut(),
            &mut descriptor,
        );
        if code != 0 {
            return Err(std::io::Error::from_raw_os_error(code as i32).into());
        }
        let _allocation = Allocation(descriptor);
        let mut control = 0;
        let mut revision = 0;
        if owner.is_null() || acl.is_null() {
            return Err(Error::UnsafePermissions(path.into()));
        }
        let owner = sid_text(owner)?;
        if !access.accepts(&owner)
            || GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0
            || (access.service_sid.is_none() && control & SE_DACL_PROTECTED == 0)
            || (*acl).AceCount == 0
            || (access.service_sid.is_some() && (*acl).AceCount != 4)
        {
            return Err(Error::UnsafePermissions(path.into()));
        }
        let mut service_trustees = 0u8;
        for index in 0..(*acl).AceCount {
            let mut ace = std::ptr::null_mut();
            if GetAce(acl, index.into(), &mut ace) == 0 {
                return Err(io_error());
            }
            let header = &*ace.cast::<ACE_HEADER>();
            if header.AceType != 0
                || usize::from(header.AceSize)
                    < std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart) + 8
            {
                return Err(Error::UnsafePermissions(path.into()));
            }
            let allowed = &*ace.cast::<ACCESS_ALLOWED_ACE>();
            let sid_ptr = std::ptr::addr_of!(allowed.SidStart).cast::<u8>();
            // The accepted ACE covers the fixed SID prefix. Validate its
            // variable length before any native routine reads the SID.
            let revision = *sid_ptr;
            let count = *sid_ptr.add(1);
            if revision != 1
                || count > 15
                || std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart) + 8 + usize::from(count) * 4
                    > usize::from(header.AceSize)
            {
                return Err(Error::UnsafePermissions(path.into()));
            }
            let sid = sid_text(sid_ptr.cast_mut().cast())?;
            if let Some(service) = &access.service_sid {
                // Every role is required exactly once. In particular, omitting
                // OWNER RIGHTS would restore the account owner's implicit
                // WRITE_DAC and let another service using that account widen
                // this DACL. Subset masks and inheritance-only ACEs are not the
                // declared effective service policy.
                let (trustee, rights) = match sid.as_str() {
                    "S-1-5-18" => (1, FILE_ALL_ACCESS),
                    "S-1-5-32-544" => (2, FILE_ALL_ACCESS),
                    "S-1-3-4" => (4, READ_CONTROL),
                    value if value == service => (8, 0x1301bf),
                    _ => return Err(Error::UnsafePermissions(path.into())),
                };
                let flags = if directory {
                    OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
                } else {
                    0
                };
                if allowed.Mask != rights
                    || u32::from(header.AceFlags) & !INHERITED_ACE != flags
                    || service_trustees & trustee != 0
                {
                    return Err(Error::UnsafePermissions(path.into()));
                }
                service_trustees |= trustee;
                continue;
            }
            if sid == "S-1-3-4" && allowed.Mask == READ_CONTROL {
                continue;
            }
            if !access.accepts_ace(&sid) {
                return Err(Error::UnsafePermissions(path.into()));
            }
        }
        if access.service_sid.is_some() && service_trustees != 15 {
            return Err(Error::UnsafePermissions(path.into()));
        }
        Ok(VerifiedAcl {
            protected: control & SE_DACL_PROTECTED != 0,
            // A shared service account can precreate an object and retain a
            // WRITE_DAC handle before installing an exact-looking DACL. Only
            // a privileged or this unique service owner can anchor inherited
            // state; the built-in account remains valid for descendants.
            anchor_owner: access.accepts_anchor_owner(&owner),
        })
    }
}
fn verify_kind(file: &File, path: &Path, directory: bool) -> Result<(), Error> {
    unsafe {
        let mut info: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
        if GetFileInformationByHandle(file.as_raw_handle(), &mut info) == 0 {
            return Err(io_error());
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        {
            return Err(Error::UnsafeFileType(path.into()));
        }
        if !directory && info.nNumberOfLinks != 1 {
            return Err(Error::MultipleLinks(path.into()));
        }
        Ok(())
    }
}
fn checked_path(path: &Path) -> Result<(), Error> {
    let mut parts = path.components();
    if !matches!(parts.next(),Some(Component::Prefix(p)) if matches!(p.kind(),Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        || !matches!(parts.next(), Some(Component::RootDir))
    {
        return Err(Error::AbsolutePathRequired(path.into()));
    }
    let remaining: Vec<_> = parts.collect();
    if remaining.is_empty()
        || remaining.iter().any(|part| match part {
            Component::Normal(value) => EntryName::new(value).is_err(),
            _ => true,
        })
    {
        return Err(Error::UnsafeRelativePath(path.into()));
    }
    let normalized: PathBuf = path.components().collect();
    if normalized.as_os_str() != path.as_os_str() {
        return Err(Error::UnsafeRelativePath(path.into()));
    }
    Ok(())
}
fn directory_handle(path: &Path, write: bool) -> Result<File, Error> {
    let file = OpenOptions::new()
        .access_mode(
            READ_CONTROL
                | FILE_READ_ATTRIBUTES
                | if write {
                    GENERIC_READ | GENERIC_WRITE
                } else {
                    0
                },
        )
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    verify_kind(&file, path, true)?;
    Ok(file)
}
fn pin_ancestors(path: &Path) -> Result<Vec<File>, Error> {
    checked_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| Error::UnsafeRelativePath(path.into()))?;
    let mut cursor = PathBuf::new();
    let mut handles = Vec::new();
    for component in parent.components() {
        cursor.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        handles.push(directory_handle(&cursor, false)?);
    }
    Ok(handles)
}

fn service_anchor(
    ancestors: &[File],
    directory: &File,
    access: &WindowsPrivateAccess,
    path: &Path,
) -> Result<Option<usize>, Error> {
    if access.service_sid.is_none() {
        verify_acl(directory, access, path, true)?;
        return Ok(None);
    }
    // Never skip an ambient or foreign segment looking for a more distant
    // trusted ancestor. Every directory up to the protected anchor must have
    // the same exact effective policy and an accepted owner.
    for index in (0..=ancestors.len()).rev() {
        let file = ancestors.get(index).unwrap_or(directory);
        let acl = verify_acl(file, access, path, true)?;
        if acl.protected && acl.anchor_owner {
            return Ok(Some(index));
        }
    }
    Err(Error::UnsafePermissions(path.into()))
}

pub(super) fn open_directory(
    path: &Path,
    create: bool,
    access: WindowsPrivateAccess,
) -> Result<PrivateDirectory, Error> {
    let ancestors = pin_ancestors(path)?;
    let directory = match directory_handle(path, true) {
        Ok(directory) => directory,
        Err(Error::Io(error)) if create && error.kind() == std::io::ErrorKind::NotFound => {
            // This public entry initializes a protected root. It never
            // inherits an ambient parent's ACL or changes policy on failure.
            if access.service_sid.is_some() && !access.accepts_anchor_owner(&creation_owner_sid()?)
            {
                return Err(Error::UnsafePermissions(path.into()));
            }
            let descriptor = access.descriptor(true)?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: 0,
            };
            // SAFETY: terminated checked path and owned native descriptor
            // remain live through this synchronous call; handles aren't inherited.
            unsafe {
                if CreateDirectoryW(wide(path.as_os_str())?.as_ptr(), &attributes) == 0
                    && GetLastError() != ERROR_ALREADY_EXISTS
                {
                    return Err(io_error());
                }
            }
            let directory = directory_handle(path, true)?;
            let acl = verify_acl(&directory, &access, path, true)?;
            if access.service_sid.is_some() && (!acl.protected || !acl.anchor_owner) {
                return Err(Error::UnsafePermissions(path.into()));
            }
            directory
        }
        Err(error) => return Err(error),
    };
    let anchor = service_anchor(&ancestors, &directory, &access, path)?;
    let directory = PrivateDirectory {
        path: path.into(),
        directory,
        ancestors,
        access,
        service_anchor: anchor,
    };
    verify_directory(&directory)?;
    Ok(directory)
}

pub(super) fn create_private_child(
    parent: &PrivateDirectory,
    name: &EntryName,
) -> Result<PrivateDirectory, Error> {
    verify_directory(parent)?;
    let path = parent.path.join(name.as_path());
    if parent.access.service_sid.is_none() {
        return open_directory(&path, true, parent.access.clone());
    }
    let mut ancestors = parent
        .ancestors
        .iter()
        .map(File::try_clone)
        .collect::<Result<Vec<_>, _>>()?;
    ancestors.push(parent.directory.try_clone()?);
    let directory = match directory_handle(&path, true) {
        Ok(directory) => directory,
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            // NULL is permitted only below this held, fully verified private
            // parent. The inherited object is checked before returning it.
            // SAFETY: the checked single child path is terminated and parent
            // namespace pins remain live through the synchronous call.
            unsafe {
                if CreateDirectoryW(wide(path.as_os_str())?.as_ptr(), std::ptr::null()) == 0
                    && GetLastError() != ERROR_ALREADY_EXISTS
                {
                    return Err(io_error());
                }
            }
            directory_handle(&path, true)?
        }
        Err(error) => return Err(error),
    };
    let child = PrivateDirectory {
        path,
        directory,
        ancestors,
        access: parent.access.clone(),
        service_anchor: parent.service_anchor,
    };
    verify_directory(&child)?;
    Ok(child)
}

pub(super) fn verify_directory(directory: &PrivateDirectory) -> Result<(), Error> {
    for ancestor in &directory.ancestors {
        verify_kind(ancestor, directory.path(), true)?;
    }
    verify_kind(&directory.directory, directory.path(), true)?;
    if directory.access.service_sid.is_some() {
        let anchor = directory
            .service_anchor
            .filter(|index| *index <= directory.ancestors.len())
            .ok_or_else(|| Error::UnsafePermissions(directory.path.clone()))?;
        for (index, file) in directory
            .ancestors
            .iter()
            .chain(std::iter::once(&directory.directory))
            .enumerate()
            .skip(anchor)
        {
            let acl = verify_acl(file, &directory.access, directory.path(), true)?;
            if index == anchor && (!acl.protected || !acl.anchor_owner) {
                return Err(Error::UnsafePermissions(directory.path.clone()));
            }
        }
        Ok(())
    } else {
        verify_acl(
            &directory.directory,
            &directory.access,
            directory.path(),
            true,
        )
        .map(|_| ())
    }
}
fn open_private(
    directory: &PrivateDirectory,
    name: &EntryName,
    write: bool,
    delete: bool,
) -> Result<File, Error> {
    verify_directory(directory)?;
    let path = directory.path.join(name.as_path());
    let file = OpenOptions::new()
        .access_mode(
            READ_CONTROL
                | GENERIC_READ
                | if write { GENERIC_WRITE } else { 0 }
                | if delete { DELETE } else { 0 },
        )
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&path)?;
    verify_kind(&file, &path, false)?;
    verify_acl(&file, &directory.access, &path, false)?;
    Ok(file)
}
fn create_file(
    directory: &PrivateDirectory,
    name: &EntryName,
    delete: bool,
) -> Result<File, Error> {
    verify_directory(directory)?;
    let descriptor = if directory.access.service_sid.is_none() {
        Some(directory.access.descriptor(false)?)
    } else {
        None
    };
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor
            .as_ref()
            .map_or(std::ptr::null_mut(), |value| value.0),
        bInheritHandle: 0,
    };
    let path = directory.path.join(name.as_path());
    // SAFETY: held directory/ancestor pins remain live. A descriptor is
    // supplied for ordinary profiles and owned through the call; NULL is used
    // only inside the verified service private chain. The returned unique
    // handle is checked before any business bytes are written.
    unsafe {
        let raw = CreateFileW(
            wide(path.as_os_str())?.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL | if delete { DELETE } else { 0 },
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            if descriptor.is_some() {
                &attributes
            } else {
                std::ptr::null()
            },
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        );
        if raw == INVALID_HANDLE_VALUE {
            return Err(io_error());
        }
        let file = File::from_raw_handle(raw);
        verify_kind(&file, &path, false)?;
        verify_acl(&file, &directory.access, &path, false)?;
        Ok(file)
    }
}
pub(super) fn read_private(
    directory: &PrivateDirectory,
    name: &EntryName,
    max: usize,
) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    open_private(directory, name, false, false)?
        .take((max as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(Error::BudgetExceeded);
    }
    verify_directory(directory)?;
    Ok(bytes)
}
fn mark_deleted(file: &File) -> Result<(), Error> {
    unsafe {
        let info = FILE_DISPOSITION_INFO { DeleteFile: true };
        if SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            std::ptr::addr_of!(info).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        ) == 0
        {
            return Err(io_error());
        }
        Ok(())
    }
}
pub(super) fn remove_file(directory: &PrivateDirectory, name: &EntryName) -> Result<(), Error> {
    let file = open_private(directory, name, false, true)?;
    mark_deleted(&file)?;
    drop(file);
    directory.sync()
}
fn rename(file: &File, destination: &Path, replace: bool) -> Result<(), Error> {
    let name = wide(destination.as_os_str())?;
    // FILE_RENAME_INFO stores a NUL-terminated name, while FileNameLength
    // excludes that terminator. Retain it even when the allocation is exactly
    // u64-aligned; alignment padding is not a substitute for string storage.
    let name_bytes = (name.len() - 1) * 2;
    let offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let size = offset + name.len() * 2;
    let mut buffer = vec![0u64; size.div_ceil(8)];
    unsafe {
        let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        (*info).Anonymous.ReplaceIfExists = replace;
        (*info).RootDirectory = std::ptr::null_mut();
        (*info).FileNameLength = name_bytes as u32;
        std::ptr::copy_nonoverlapping(name.as_ptr(), (*info).FileName.as_mut_ptr(), name.len());
        if SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfo,
            buffer.as_ptr().cast(),
            size as u32,
        ) == 0
        {
            return Err(io_error());
        }
    }
    Ok(())
}
fn destination_checked(
    directory: &PrivateDirectory,
    name: &EntryName,
    replace: bool,
) -> Result<(), Error> {
    match open_private(directory, name, false, false) {
        Ok(_) => {
            if replace {
                Ok(())
            } else {
                Err(Error::DestinationExists(
                    directory.path.join(name.as_path()),
                ))
            }
        }
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}
pub(super) fn atomic_write(
    directory: &PrivateDirectory,
    name: &EntryName,
    bytes: &[u8],
    replace: bool,
) -> Result<(), Error> {
    destination_checked(directory, name, replace)?;
    let temporary = EntryName::new(super::temporary_name()?)?;
    let mut file = create_file(directory, &temporary, true)?;
    let mut published = false;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        verify_directory(directory)?;
        destination_checked(directory, name, replace)?;
        rename(&file, &directory.path.join(name.as_path()), replace)?;
        published = true;
        directory.sync().map_err(|error| {
            Error::PublishedDurabilityUnknown(std::io::Error::other(error.to_string()))
        })
    })();
    if result.is_err() && !published {
        let _ = mark_deleted(&file);
    }
    result
}
pub(super) fn publish(
    directory: &PrivateDirectory,
    source: &EntryName,
    destination: &EntryName,
) -> Result<(), Error> {
    let file = open_private(directory, source, true, true)?;
    destination_checked(directory, destination, false)?;
    file.sync_all()?;
    verify_directory(directory)?;
    destination_checked(directory, destination, false)?;
    rename(&file, &directory.path.join(destination.as_path()), false)?;
    directory.sync()
}
pub(super) fn advisory_lock(
    directory: &PrivateDirectory,
    name: &EntryName,
    wait: bool,
) -> Result<AdvisoryLock, Error> {
    let file = match create_file(directory, name, false) {
        Ok(file) => file,
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            open_private(directory, name, true, false)?
        }
        Err(error) => return Err(error),
    };
    if wait {
        file.lock()?;
    } else {
        file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => {
                Error::AlreadyLocked(directory.path.join(name.as_path()))
            }
            std::fs::TryLockError::Error(error) => Error::Io(error),
        })?;
    }
    file.sync_all()?;
    directory.sync()?;
    Ok(AdvisoryLock { _file: file })
}
pub(super) fn files(
    directory: &PrivateDirectory,
    limits: InventoryLimits,
) -> Result<Vec<FileEntry>, Error> {
    verify_directory(directory)?;
    let mut result = Vec::new();
    let mut total = 0u64;
    for entry in std::fs::read_dir(directory.path())? {
        let entry = entry?;
        if result.len() >= limits.max_entries {
            return Err(Error::BudgetExceeded);
        }
        let name = EntryName::new(entry.file_name())?;
        let metadata = open_private(directory, &name, false, false)?.metadata()?;
        total = total
            .checked_add(metadata.len())
            .ok_or(Error::BudgetExceeded)?;
        if total > limits.max_total_bytes {
            return Err(Error::BudgetExceeded);
        }
        result.push(FileEntry {
            name,
            bytes: metadata.len(),
        });
    }
    Ok(result)
}
pub(super) fn inventory(path: &Path, limits: InventoryLimits) -> Result<DirectoryInventory, Error> {
    let _ancestors = pin_ancestors(path)?;
    let root = directory_handle(path, false)?;
    let mut held_directories = vec![root];
    let mut pending = vec![path.to_owned()];
    let mut total = DirectoryInventory {
        entries: 0,
        total_bytes: 0,
    };
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            let file = OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
                .open(entry.path())?;
            verify_kind(&file, &entry.path(), metadata.is_dir())?;
            total.entries = total.entries.checked_add(1).ok_or(Error::BudgetExceeded)?;
            total.total_bytes = total
                .total_bytes
                .checked_add(metadata.len())
                .ok_or(Error::BudgetExceeded)?;
            if total.entries > limits.max_entries || total.total_bytes > limits.max_total_bytes {
                return Err(Error::BudgetExceeded);
            }
            if metadata.is_dir() {
                held_directories.push(file);
                pending.push(entry.path());
            }
        }
    }
    Ok(total)
}
pub(super) fn sync_directory(path: &Path) -> Result<(), Error> {
    let _ancestors = pin_ancestors(path)?;
    directory_handle(path, true)?.sync_all()?;
    Ok(())
}
pub(super) fn sync_file_and_parent(path: &Path) -> Result<(), Error> {
    let _ancestors = pin_ancestors(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    verify_kind(&file, path, false)?;
    file.sync_all()?;
    sync_directory(
        path.parent()
            .ok_or_else(|| Error::UnsafeRelativePath(path.into()))?,
    )
}

#[cfg(test)]
mod tests;
