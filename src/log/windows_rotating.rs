//! Native Windows log storage. Every live directory name is pinned by a handle
//! without FILE_SHARE_DELETE. Current-user storage has an exact protected DACL.
//! Service storage inherits its exact policy only below a held, authenticated
//! protected anchor; every private segment is rechecked before use. Existing
//! metadata is validated, never repaired.

use crate::log::{LogError, LogRecord, LogRetention, MAX_RECORD_BYTES};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, c_void},
    fs::{self, File},
    io::{self, Write},
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Component, Path, PathBuf, Prefix},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
        ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree,
    },
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION, AclSizeInformation,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
        },
        CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, GetAce, GetAclInformation,
        GetSecurityDescriptorControl, GetTokenInformation, INHERITED_ACE, OBJECT_INHERIT_ACE,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ALL_ACCESS,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle, OPEN_EXISTING, READ_CONTROL,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

/// Exact private-log access policy. Service logs remain owned by LocalService;
/// only the selected SCM service SID can mutate them, alongside administrators
/// and SYSTEM. OWNER RIGHTS grants only READ_CONTROL, suppressing the owner's
/// implicit permission to rewrite the DACL.
#[derive(Clone, Debug)]
pub struct WindowsLogAccess {
    owner_sid: String,
    service_sid: Option<String>,
}

impl WindowsLogAccess {
    /// Select one canonical product SCM service SID. No account-wide
    /// LocalService data access or all-services SID is accepted.
    pub fn for_service(service_sid: &str) -> Result<Self, LogError> {
        if service_sid.len() > 64 {
            return Err(LogError::UnsafeStorage);
        }
        let Some(parts) = service_sid.strip_prefix("S-1-5-80-") else {
            return Err(LogError::UnsafeStorage);
        };
        let parts: Vec<_> = parts.split('-').collect();
        if parts.len() != 5
            || parts.iter().any(|part| {
                part.parse::<u32>()
                    .ok()
                    .is_none_or(|value| value.to_string() != *part)
            })
        {
            return Err(LogError::UnsafeStorage);
        }
        Ok(Self {
            owner_sid: "S-1-5-19".into(),
            service_sid: Some(service_sid.into()),
        })
    }

    fn current_process() -> Result<Self, LogError> {
        Ok(Self {
            owner_sid: current_sid()?,
            service_sid: None,
        })
    }

    fn accepts_anchor_owner(&self, owner: &str) -> bool {
        matches!(owner, "S-1-5-18" | "S-1-5-32-544") || self.service_sid.as_deref() == Some(owner)
    }

    fn trustees(&self) -> BTreeMap<String, u32> {
        let mut result = BTreeMap::from([
            ("S-1-5-18".into(), FILE_ALL_ACCESS),
            ("S-1-5-32-544".into(), FILE_ALL_ACCESS),
        ]);
        if let Some(service) = &self.service_sid {
            // File read/write/execute/delete + READ_CONTROL + SYNCHRONIZE;
            // excludes WRITE_DAC and WRITE_OWNER.
            result.insert(service.clone(), 0x0013_01bf);
            result.insert("S-1-3-4".into(), READ_CONTROL);
        } else {
            result.insert(self.owner_sid.clone(), FILE_ALL_ACCESS);
        }
        result
    }
}

struct Allocation(PSECURITY_DESCRIPTOR);
impl Drop for Allocation {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: each allocation comes from an API documented to use LocalFree.
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn wide(value: &OsStr) -> Result<Vec<u16>, LogError> {
    let mut result: Vec<u16> = value.encode_wide().collect();
    if result.contains(&0) {
        return Err(LogError::UnsafeStorage);
    }
    result.push(0);
    Ok(result)
}

#[allow(unsafe_code)]
fn sid_text(sid: *mut c_void) -> Result<String, LogError> {
    let mut value = ptr::null_mut();
    // SAFETY: SID is within a live token/security descriptor, output is valid.
    if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let _allocation = Allocation(value.cast());
    let mut length = 0;
    // SAFETY: ConvertSidToStringSidW returned a live, NUL-terminated UTF-16
    // allocation. Its SID representation is bounded independently of input.
    while unsafe { *value.add(length) } != 0 {
        length += 1;
        if length > 256 {
            return Err(LogError::UnsafeStorage);
        }
    }
    // SAFETY: the successful API supplied this terminated allocation.
    String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) })
        .map_err(|_| LogError::UnsafeStorage)
}

#[allow(unsafe_code)]
fn current_sid() -> Result<String, LogError> {
    let mut raw = ptr::null_mut();
    // SAFETY: pseudo-process handle and valid output; token is owned below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: successful OpenProcessToken transferred a new owned handle;
    // this is its sole owner and closes it after all token reads.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut needed = 0;
    // SAFETY: the token is live, the null buffer has zero length, and `needed`
    // is writable for the documented size-query operation.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed < size_of::<TOKEN_USER>() as u32 || needed > 16 * 1024 {
        return Err(LogError::UnsafeStorage);
    }
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: aligned buffer has capacity at least needed bytes, API length is bounded.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: the successful TokenUser query initialized a complete TOKEN_USER
    // in this u64-aligned buffer. Its SID remains live through sid_text.
    sid_text(unsafe { (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid })
}

#[allow(unsafe_code)]
fn descriptor(access: &WindowsLogAccess, directory: bool) -> Result<Allocation, LogError> {
    let flags = if directory { "OICI" } else { "" };
    let mut text = format!("O:{}D:P", access.owner_sid);
    for (trustee, rights) in access.trustees() {
        text.push_str(&format!("(A;{flags};0x{rights:x};;;{trustee})"));
    }
    let text = wide(OsStr::new(&text))?;
    let mut value = ptr::null_mut();
    // SAFETY: generated SDDL contains only OS-derived SID and fixed syntax.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &mut value,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(Allocation(value))
}

#[allow(unsafe_code)]
fn information(file: &File, directory: bool) -> Result<BY_HANDLE_FILE_INFORMATION, LogError> {
    let mut value = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: owned file handle and writable struct.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut value) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    if value.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (value.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && value.nNumberOfLinks != 1)
    {
        return Err(LogError::UnsafeStorage);
    }
    Ok(value)
}

struct VerifiedAcl {
    owner_matches: bool,
    protected: bool,
    anchor_owner: bool,
}

#[allow(unsafe_code)]
fn inspect_acl(
    file: &File,
    access: &WindowsLogAccess,
    directory: bool,
) -> Result<VerifiedAcl, LogError> {
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut sd = ptr::null_mut();
    // SAFETY: file handle is valid; descriptor allocation owns returned SID/ACL.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut sd,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32).into());
    }
    let _allocation = Allocation(sd);
    if owner.is_null() || dacl.is_null() {
        return Err(LogError::UnsafeStorage);
    }
    let owner = sid_text(owner)?;
    let anchor_owner = access.service_sid.is_some() && access.accepts_anchor_owner(&owner);
    if owner != access.owner_sid && !(directory && anchor_owner) {
        return Err(LogError::UnsafeStorage);
    }
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: GetSecurityInfo returned the live security descriptor; both
    // outputs point to initialized writable storage of the required types.
    if unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) } == 0
        || (access.service_sid.is_none() && control & SE_DACL_PROTECTED == 0)
    {
        return Err(LogError::UnsafeStorage);
    }
    let mut size = ACL_SIZE_INFORMATION::default();
    // SAFETY: the non-null DACL belongs to the live descriptor and the output
    // buffer and exact byte length match ACL_SIZE_INFORMATION.
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let expected = access.trustees();
    if size.AceCount as usize != expected.len() {
        return Err(LogError::UnsafeStorage);
    }
    let mut observed = BTreeSet::new();
    for index in 0..size.AceCount {
        let mut raw = ptr::null_mut();
        // SAFETY: index is within the OS-reported ACL count; the live ACL and
        // writable output remain valid. Returned ACEs borrow the descriptor.
        if unsafe { GetAce(dacl, index, &mut raw) } == 0 || raw.is_null() {
            return Err(LogError::UnsafeStorage);
        }
        // SAFETY: GetAce returns a header within the live OS descriptor. Check
        // its type and full fixed fields before forming the larger ACE reference.
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        if header.AceType != 0 || usize::from(header.AceSize) < sid_offset + 8 {
            return Err(LogError::UnsafeStorage);
        }
        // SAFETY: the accepted native ACE has its fixed mask and SID prefix.
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        let flags = if directory {
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        } else {
            0
        };
        if ace.Header.AceType != 0
            || u32::from(ace.Header.AceFlags)
                & if access.service_sid.is_some() {
                    !INHERITED_ACE
                } else {
                    u32::MAX
                }
                != flags
            || (ace.Header.AceSize as usize) < size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(LogError::UnsafeStorage);
        }
        let sid = (&ace.SidStart as *const u32).cast::<u8>();
        // SAFETY: the previous size check covers the SID revision and count.
        // Check the variable extent before passing it to any SID conversion API.
        let (revision, count) = unsafe { (*sid, *sid.add(1)) };
        if revision != 1
            || count > 15
            || sid_offset + 8 + usize::from(count) * 4 > usize::from(header.AceSize)
        {
            return Err(LogError::UnsafeStorage);
        }
        let trustee = sid_text(sid.cast_mut().cast())?;
        if expected.get(&trustee) != Some(&ace.Mask) || !observed.insert(trustee) {
            return Err(LogError::UnsafeStorage);
        }
    }
    if observed != expected.keys().cloned().collect() {
        return Err(LogError::UnsafeStorage);
    }
    Ok(VerifiedAcl {
        owner_matches: owner == access.owner_sid,
        protected: control & SE_DACL_PROTECTED != 0,
        anchor_owner,
    })
}

fn verify_acl(file: &File, access: &WindowsLogAccess, directory: bool) -> Result<(), LogError> {
    inspect_acl(file, access, directory).map(|_| ())
}

// Opening an existing leaf and creating an inherited leaf both use a NULL
// descriptor, but must never share their creation disposition.
#[derive(Clone, Copy)]
enum LeafOpen<'a> {
    Existing,
    Protected(&'a Allocation),
    Inherited,
}

#[allow(unsafe_code)]
fn open_handle(
    path: &Path,
    directory: bool,
    access: u32,
    mode: LeafOpen<'_>,
    share: u32,
) -> Result<File, LogError> {
    let path = wide(path.as_os_str())?;
    let attributes = match mode {
        LeafOpen::Protected(sd) => Some(SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        }),
        LeafOpen::Existing | LeafOpen::Inherited => None,
    };
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            FILE_ATTRIBUTE_NORMAL
        };
    // SAFETY: path is terminated, attributes borrow a live descriptor, handle is owned on success.
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            access | FILE_READ_ATTRIBUTES | READ_CONTROL,
            share,
            attributes.as_ref().map_or(ptr::null(), |a| a),
            match mode {
                LeafOpen::Existing => OPEN_EXISTING,
                LeafOpen::Protected(_) | LeafOpen::Inherited => CREATE_NEW,
            },
            flags,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: successful CreateFileW returned a new handle with no other owner.
    // File now closes it exactly once, including on validation errors.
    let file = unsafe { File::from_raw_handle(raw) };
    information(&file, directory)?;
    Ok(file)
}

fn create_file(path: &Path, access: &WindowsLogAccess) -> Result<File, LogError> {
    // The caller has verified and pinned the private parent chain. A service
    // never installs its own explicit CreatorDACL: inherit only that exact
    // authenticated policy, then validate the actual new leaf before use.
    let sd = if access.service_sid.is_none() {
        Some(descriptor(access, false)?)
    } else {
        None
    };
    let mode = sd.as_ref().map_or(LeafOpen::Inherited, LeafOpen::Protected);
    let file = open_handle(
        path,
        false,
        GENERIC_READ | GENERIC_WRITE,
        mode,
        FILE_SHARE_READ,
    )?;
    verify_acl(&file, access, false)?;
    Ok(file)
}

fn private_file(path: &Path, access: &WindowsLogAccess) -> Result<File, LogError> {
    let existing = open_handle(
        path,
        false,
        GENERIC_READ | GENERIC_WRITE,
        LeafOpen::Existing,
        FILE_SHARE_READ,
    );
    let file = match existing {
        Ok(file) => file,
        Err(LogError::Io(error)) if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => {
            match create_file(path, access) {
                Ok(file) => file,
                Err(LogError::Io(error)) if matches!(error.raw_os_error(), Some(code) if code == ERROR_FILE_EXISTS as i32 || code == ERROR_ALREADY_EXISTS as i32) => {
                    open_handle(
                        path,
                        false,
                        GENERIC_READ | GENERIC_WRITE,
                        LeafOpen::Existing,
                        FILE_SHARE_READ,
                    )?
                }
                Err(error) => return Err(error),
            }
        }
        Err(error) => return Err(error),
    };
    verify_acl(&file, access, false)?;
    Ok(file)
}

fn validate_component(value: &OsStr) -> Result<(), LogError> {
    let units: Vec<_> = value.encode_wide().collect();
    if units.is_empty()
        || units.len() > 255
        || units
            .iter()
            .any(|unit| *unit < 32 || matches!(*unit, 34 | 42 | 47 | 58 | 60 | 62 | 63 | 92 | 124))
        || matches!(units.last(), Some(32 | 46))
    {
        return Err(LogError::UnsafeStorage);
    }
    let name = value.to_string_lossy();
    let base = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    if matches!(
        base.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        base.strip_prefix(prefix).is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    }) {
        return Err(LogError::UnsafeStorage);
    }
    Ok(())
}

fn find_anchor(directories: &[File], access: &WindowsLogAccess) -> Result<Option<usize>, LogError> {
    if access.service_sid.is_none() {
        verify_acl(
            directories.last().ok_or(LogError::UnsafeStorage)?,
            access,
            true,
        )?;
        return Ok(None);
    }
    // Work upwards without skipping a foreign or ambient segment. The first
    // protected, privileged/unique-service-owned exact policy authenticates
    // every private descendant. Store this position; never rediscover a new
    // anchor after the namespace has been opened.
    for (index, directory) in directories.iter().enumerate().rev() {
        let acl = inspect_acl(directory, access, true)?;
        if acl.protected && acl.anchor_owner {
            return Ok(Some(index));
        }
    }
    Err(LogError::UnsafeStorage)
}

fn verify_chain(
    directories: &[File],
    anchor: Option<usize>,
    access: &WindowsLogAccess,
) -> Result<(), LogError> {
    for directory in directories {
        information(directory, true)?;
    }
    if access.service_sid.is_some() {
        let anchor = anchor
            .filter(|index| *index < directories.len())
            .ok_or(LogError::UnsafeStorage)?;
        for (index, directory) in directories.iter().enumerate().skip(anchor) {
            let acl = inspect_acl(directory, access, true)?;
            if index == anchor && (!acl.protected || !acl.anchor_owner) {
                return Err(LogError::UnsafeStorage);
            }
        }
        Ok(())
    } else {
        if anchor.is_some() {
            return Err(LogError::UnsafeStorage);
        }
        verify_acl(
            directories.last().ok_or(LogError::UnsafeStorage)?,
            access,
            true,
        )
    }
}

fn pin_directories(path: &Path) -> Result<Vec<File>, LogError> {
    if !path.is_absolute() {
        return Err(LogError::UnsafeStorage);
    }
    let mut current = PathBuf::new();
    let mut held = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix)
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) =>
            {
                current.push(component)
            }
            Component::RootDir => {
                current.push(component);
                held.push(open_handle(
                    &current,
                    true,
                    FILE_READ_ATTRIBUTES,
                    LeafOpen::Existing,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                )?);
            }
            Component::Normal(value) => {
                validate_component(value)?;
                current.push(value);
                held.push(open_handle(
                    &current,
                    true,
                    FILE_READ_ATTRIBUTES,
                    LeafOpen::Existing,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                )?);
            }
            _ => return Err(LogError::UnsafeStorage),
        }
        if held.len() > 128 {
            return Err(LogError::UnsafeStorage);
        }
    }
    if held.is_empty() {
        return Err(LogError::UnsafeStorage);
    }
    Ok(held)
}

pub struct RotatingLogFile {
    _directories: Vec<File>,
    private_anchor: Option<usize>,
    _writer: File,
    path: PathBuf,
    access: WindowsLogAccess,
    active: String,
    file: Option<File>,
    bytes: u64,
    retention: LogRetention,
    failed: bool,
}

impl RotatingLogFile {
    /// Create only the final private log directory below already-existing
    /// application state. Existing metadata is never changed or repaired.
    #[allow(unsafe_code)]
    pub fn create_private(
        path: impl AsRef<Path>,
        stem: &str,
        retention: LogRetention,
    ) -> Result<Self, LogError> {
        Self::create_private_with_access(
            path,
            stem,
            retention,
            WindowsLogAccess::current_process()?,
        )
    }

    /// Create only the final directory using the declared exact policy. Service
    /// callers run as LocalService with their SCM SID and inherit only below
    /// an authenticated, held private parent. Existing ACLs are never repaired.
    #[allow(unsafe_code)]
    pub fn create_private_with_access(
        path: impl AsRef<Path>,
        stem: &str,
        retention: LogRetention,
        access: WindowsLogAccess,
    ) -> Result<Self, LogError> {
        if current_sid()? != access.owner_sid {
            return Err(LogError::UnsafeStorage);
        }
        let path = path.as_ref();
        validate(stem, retention)?;
        validate_component(path.file_name().ok_or(LogError::UnsafeStorage)?)?;
        let parent = path.parent().ok_or(LogError::UnsafeStorage)?;
        let parents = pin_directories(parent)?;
        let anchor = if access.service_sid.is_some() {
            let anchor = find_anchor(&parents, &access)?;
            verify_chain(&parents, anchor, &access)?;
            anchor
        } else {
            None
        };
        let sd = if access.service_sid.is_none() {
            Some(descriptor(&access, true)?)
        } else {
            None
        };
        let attributes = sd.as_ref().map(|sd| SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        });
        let name = wide(path.as_os_str())?;
        // SAFETY: the terminated path and optional descriptor remain live.
        // NULL attributes are used only below the held, verified service chain.
        if unsafe {
            CreateDirectoryW(
                name.as_ptr(),
                attributes.as_ref().map_or(ptr::null(), |a| a),
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
                return Err(error.into());
            }
        }
        if access.service_sid.is_some() {
            verify_chain(&parents, anchor, &access)?;
        }
        Self::open_with_access(path, stem, retention, access)
    }

    pub fn open(
        path: impl AsRef<Path>,
        stem: &str,
        retention: LogRetention,
    ) -> Result<Self, LogError> {
        Self::open_with_access(path, stem, retention, WindowsLogAccess::current_process()?)
    }

    /// Open only exact private policy. Service logs require a fixed protected
    /// authenticated ancestor and LocalService-owned final directory/leaf;
    /// unknown entries, unsafe objects and ambient inheritance are refused.
    pub fn open_with_access(
        path: impl AsRef<Path>,
        stem: &str,
        retention: LogRetention,
        access: WindowsLogAccess,
    ) -> Result<Self, LogError> {
        validate(stem, retention)?;
        let path = path.as_ref();
        let directories = pin_directories(path)?;
        let private_anchor = find_anchor(&directories, &access)?;
        verify_chain(&directories, private_anchor, &access)?;
        let last = inspect_acl(
            directories.last().ok_or(LogError::UnsafeStorage)?,
            &access,
            true,
        )?;
        if access.service_sid.is_some() && !last.owner_matches {
            // Log payload never lives directly in the privileged state anchor.
            return Err(LogError::UnsafeStorage);
        }
        let active = format!("{stem}.jsonl");
        verify_chain(&directories, private_anchor, &access)?;
        let writer = private_file(&path.join(format!(".{active}.writer.lock")), &access)?;
        writer.try_lock().map_err(|_| LogError::UnsafeStorage)?;
        let mut entries = 0;
        for entry in fs::read_dir(path)? {
            entries += 1;
            if entries > 128 {
                return Err(LogError::UnsafeStorage);
            }
            let name = entry?.file_name();
            let name = name.to_str().ok_or(LogError::UnsafeStorage)?;
            if name == active || name == format!(".{active}.writer.lock") {
                continue;
            }
            let index = name
                .strip_prefix(&format!("{active}."))
                .and_then(|n| n.parse::<u8>().ok())
                .ok_or(LogError::UnsafeStorage)?;
            if index == 0 || index > retention.archives || name != format!("{active}.{index}") {
                return Err(LogError::UnsafeStorage);
            }
            verify_chain(&directories, private_anchor, &access)?;
            let file = open_handle(
                &path.join(name),
                false,
                GENERIC_READ,
                LeafOpen::Existing,
                FILE_SHARE_READ,
            )?;
            verify_acl(&file, &access, false)?;
            if file.metadata()?.len() > retention.file_bytes {
                return Err(LogError::InvalidLimits);
            }
        }
        verify_chain(&directories, private_anchor, &access)?;
        let mut file = private_file(&path.join(&active), &access)?;
        use std::io::{Seek, SeekFrom};
        let bytes = file.seek(SeekFrom::End(0))?;
        if bytes > retention.file_bytes {
            return Err(LogError::InvalidLimits);
        }
        Ok(Self {
            _directories: directories,
            private_anchor,
            _writer: writer,
            path: path.into(),
            access,
            active,
            file: Some(file),
            bytes,
            retention,
            failed: false,
        })
    }

    pub fn write(&mut self, record: &LogRecord) -> Result<(), LogError> {
        if self.failed {
            return Err(LogError::UnsafeStorage);
        }
        let line = record.json_line()?;
        let result = self.write_line(&line);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn write_line(&mut self, line: &[u8]) -> Result<(), LogError> {
        self.verify_namespace()?;
        let file = self.file.as_ref().ok_or(LogError::UnsafeStorage)?;
        information(file, false)?;
        verify_acl(file, &self.access, false)?;
        if file.metadata()?.len() != self.bytes {
            return Err(LogError::UnsafeStorage);
        }
        if self
            .bytes
            .checked_add(line.len() as u64)
            .is_none_or(|n| n > self.retention.file_bytes)
        {
            self.rotate()?;
        }
        let file = self.file.as_mut().ok_or(LogError::UnsafeStorage)?;
        file.write_all(line)?;
        file.sync_all()?;
        self.bytes += line.len() as u64;
        Ok(())
    }

    fn verify_namespace(&self) -> Result<(), LogError> {
        verify_chain(&self._directories, self.private_anchor, &self.access)?;
        let last = inspect_acl(
            self._directories.last().ok_or(LogError::UnsafeStorage)?,
            &self.access,
            true,
        )?;
        if !last.owner_matches {
            return Err(LogError::UnsafeStorage);
        }
        information(&self._writer, false)?;
        verify_acl(&self._writer, &self.access, false)
    }

    fn archive(&self, index: u8) -> PathBuf {
        self.path.join(format!("{}.{index}", self.active))
    }
    fn checked_archive(&self, index: u8) -> Result<bool, LogError> {
        self.verify_namespace()?;
        match open_handle(
            &self.archive(index),
            false,
            GENERIC_READ,
            LeafOpen::Existing,
            FILE_SHARE_READ,
        ) {
            Ok(file) => {
                verify_acl(&file, &self.access, false)?;
                if file.metadata()?.len() > self.retention.file_bytes {
                    return Err(LogError::InvalidLimits);
                }
                Ok(true)
            }
            Err(LogError::Io(error)) if matches!(error.raw_os_error(), Some(code) if code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PATH_NOT_FOUND as i32) => {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }
    fn rotate(&mut self) -> Result<(), LogError> {
        // The private namespace and exclusive writer lease remain pinned while
        // Windows requires closing active/archive handles for rename.
        self.verify_namespace()?;
        let active = self.file.as_ref().ok_or(LogError::UnsafeStorage)?;
        information(active, false)?;
        verify_acl(active, &self.access, false)?;
        if active.metadata()?.len() != self.bytes {
            return Err(LogError::UnsafeStorage);
        }
        // Reject any malformed retained evidence before closing active or
        // deleting an unrelated older slot. All checks repeat before mutation.
        for index in 1..=self.retention.archives {
            self.checked_archive(index)?;
        }
        active.sync_all()?;
        self.verify_namespace()?;
        self.file.take();
        if self.checked_archive(self.retention.archives)? {
            self.verify_namespace()?;
            fs::remove_file(self.archive(self.retention.archives))?;
        }
        for index in (1..self.retention.archives).rev() {
            if self.checked_archive(index)? {
                self.verify_namespace()?;
                fs::rename(self.archive(index), self.archive(index + 1))?;
            }
        }
        self.verify_namespace()?;
        let active = open_handle(
            &self.path.join(&self.active),
            false,
            GENERIC_READ,
            LeafOpen::Existing,
            FILE_SHARE_READ,
        )?;
        verify_acl(&active, &self.access, false)?;
        if active.metadata()?.len() != self.bytes {
            return Err(LogError::UnsafeStorage);
        }
        drop(active);
        self.verify_namespace()?;
        fs::rename(self.path.join(&self.active), self.archive(1))?;
        self.verify_namespace()?;
        // Rotation must create a fresh active leaf, never append to an object
        // that unexpectedly appeared after the rename.
        self.file = Some(create_file(&self.path.join(&self.active), &self.access)?);
        self.bytes = 0;
        Ok(())
    }
}

fn validate(stem: &str, retention: LogRetention) -> Result<(), LogError> {
    if stem.is_empty()
        || stem.len() > 64
        || !stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(LogError::UnsafeStorage);
    }
    if retention.file_bytes < MAX_RECORD_BYTES as u64
        || retention.archives == 0
        || retention.archives > 32
    {
        return Err(LogError::InvalidLimits);
    }
    Ok(())
}

#[cfg(test)]
#[path = "windows_rotating_tests.rs"]
mod tests;
