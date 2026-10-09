use super::*;
use crate::log::{Level, LogFilter, QueryLimits, query};
use windows_sys::Win32::Security::{
    Authorization::ConvertStringSidToSidW, CreateRestrictedToken, DISABLE_MAX_PRIVILEGE,
    ImpersonateLoggedOnUser, RevertToSelf, SID_AND_ATTRIBUTES, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
};

fn record(instance: &str) -> LogRecord {
    LogRecord::instance(
        "test-service",
        "worker",
        "test-service.worker.completed",
        "The worker completed its operation.",
        Level::Info,
        instance,
    )
    .unwrap()
}

fn limits() -> LogRetention {
    LogRetention {
        file_bytes: MAX_RECORD_BYTES as u64,
        archives: 2,
    }
}

#[test]
fn native_rotation_persists_bounded_exact_instance_records_and_reopens() {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("logs");
    let mut sink = RotatingLogFile::create_private(&path, "service", limits()).unwrap();
    for index in 0..200 {
        sink.write(&record(if index % 2 == 0 {
            "camera-1"
        } else {
            "camera-10"
        }))
        .unwrap();
    }
    assert!(RotatingLogFile::open(&path, "service", limits()).is_err());
    assert!(fs::rename(&path, parent.path().join("moved")).is_err());
    drop(sink);
    let mut retained = 0;
    let mut total = 0;
    for entry in fs::read_dir(&path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        retained += 1;
        let bytes = fs::read(entry.path()).unwrap();
        assert!(bytes.len() as u64 <= limits().file_bytes);
        total += bytes.len();
        let filtered = query(
            &bytes[..],
            LogFilter {
                instance_id: Some("camera-1"),
                ..LogFilter::default()
            },
            QueryLimits::default(),
        )
        .unwrap();
        assert!(!filtered.is_empty());
        for item in filtered {
            assert_eq!(item.instance_id.as_deref(), Some("camera-1"));
            assert!(item.timestamp.ends_with('Z'));
            assert_eq!(item.event, "test-service.worker.completed");
        }
    }
    assert_eq!(retained, 3);
    assert!(total as u64 <= limits().file_bytes * 3);
    RotatingLogFile::open(&path, "service", limits())
        .unwrap()
        .write(&record("camera-1"))
        .unwrap();
    assert_eq!(
        LogRetention::default().file_bytes * (u64::from(LogRetention::default().archives) + 1),
        40 * 1024 * 1024
    );
}

#[test]
fn unsafe_existing_acl_is_refused_without_repair_or_writes() {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("logs");
    fs::create_dir(&path).unwrap();
    fs::write(path.join("sentinel"), b"unchanged").unwrap();
    let before = fs::metadata(&path).unwrap().modified().unwrap();
    assert!(matches!(
        RotatingLogFile::create_private(&path, "service", limits()),
        Err(LogError::UnsafeStorage)
    ));
    assert_eq!(fs::read(path.join("sentinel")).unwrap(), b"unchanged");
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), before);
    assert_eq!(fs::read_dir(path).unwrap().count(), 1);
}

#[test]
fn hardlinks_unknown_files_and_archive_aliases_are_refused() {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("logs");
    let mut sink = RotatingLogFile::create_private(&path, "service", limits()).unwrap();
    sink.write(&record("instance")).unwrap();
    drop(sink);
    let active = path.join("service.jsonl");
    let before = fs::read(&active).unwrap();
    fs::hard_link(&active, parent.path().join("hardlink")).unwrap();
    assert!(matches!(
        RotatingLogFile::open(&path, "service", limits()),
        Err(LogError::UnsafeStorage)
    ));
    assert_eq!(fs::read(&active).unwrap(), before);
    fs::remove_file(parent.path().join("hardlink")).unwrap();
    fs::write(path.join("service.jsonl.01"), b"").unwrap();
    assert!(matches!(
        RotatingLogFile::open(&path, "service", limits()),
        Err(LogError::UnsafeStorage)
    ));
    fs::remove_file(path.join("service.jsonl.01")).unwrap();
    fs::write(path.join("unexpected"), b"").unwrap();
    assert!(matches!(
        RotatingLogFile::open(&path, "service", limits()),
        Err(LogError::UnsafeStorage)
    ));
    assert_eq!(fs::read(&active).unwrap(), before);
}

#[test]
fn native_directory_junction_is_refused_without_target_writes() {
    let parent = tempfile::tempdir().unwrap();
    let target = parent.path().join("target");
    let junction = parent.path().join("logs");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("sentinel"), b"unchanged").unwrap();
    let result = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&target)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(matches!(
        RotatingLogFile::create_private(&junction, "service", limits()),
        Err(LogError::UnsafeStorage)
    ));
    assert_eq!(fs::read(target.join("sentinel")).unwrap(), b"unchanged");
    assert_eq!(fs::read_dir(&target).unwrap().count(), 1);
    fs::remove_dir(junction).unwrap();
}

#[test]
#[allow(unsafe_code)]
fn changed_acl_poisoning_refuses_append_and_exposes_layer_failure() {
    use windows_sys::Win32::Security::{
        Authorization::SetNamedSecurityInfoW, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("logs");
    let mut sink = RotatingLogFile::create_private(&path, "service", limits()).unwrap();
    sink.write(&record("instance")).unwrap();
    let active = path.join("service.jsonl");
    let before = fs::read(&active).unwrap();
    let name = wide(active.as_os_str()).unwrap();
    // SAFETY: the fixture is owned by this token; setting a NULL DACL deliberately
    // makes it unsafe, so the writer must refuse rather than silently repair it.
    let result = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert_eq!(result, ERROR_SUCCESS);
    assert!(matches!(
        sink.write(&record("instance")),
        Err(LogError::UnsafeStorage)
    ));
    assert!(matches!(
        sink.write(&record("instance")),
        Err(LogError::UnsafeStorage)
    ));
    assert_eq!(fs::read(&active).unwrap(), before);
    #[cfg(feature = "tracing")]
    {
        use tracing_subscriber::prelude::*;
        let layer = crate::log::XcscStructuredLayer::new("test-service")
            .unwrap()
            .with_rotating_file(sink);
        let counter = layer.clone();
        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), || {
            tracing::info!(
                event = "test-service.worker.completed",
                message = "The worker completed its operation."
            );
        });
        assert_eq!(counter.rejected_count(), 1);
        assert_eq!(fs::read(&active).unwrap(), before);
    }
}

struct Impersonation;
impl Drop for Impersonation {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: restore the test thread's original token before cleanup.
        assert_ne!(unsafe { RevertToSelf() }, 0);
    }
}

#[test]
#[allow(unsafe_code)]
fn actual_restricted_standard_token_cannot_read_or_write_private_logs() {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("logs");
    let mut sink = RotatingLogFile::create_private(&path, "service", limits()).unwrap();
    sink.write(&record("instance")).unwrap();
    drop(sink);
    let before = fs::read(path.join("service.jsonl")).unwrap();
    let mut process_token = ptr::null_mut();
    assert_ne!(
        // SAFETY: live process and owned output token.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                &mut process_token,
            )
        },
        0
    );
    // SAFETY: the successful API transferred a unique, live token handle.
    let process_token = unsafe { OwnedHandle::from_raw_handle(process_token) };
    let everyone = wide(OsStr::new("S-1-1-0")).unwrap();
    let admins = wide(OsStr::new("S-1-5-32-544")).unwrap();
    let mut everyone_sid = ptr::null_mut();
    let mut admins_sid = ptr::null_mut();
    assert_ne!(
        // SAFETY: fixed valid SID strings, LocalFree owns both successful outputs.
        unsafe { ConvertStringSidToSidW(everyone.as_ptr(), &mut everyone_sid) },
        0
    );
    let _everyone = Allocation(everyone_sid);
    assert_ne!(
        // SAFETY: the fixed terminated SID string is valid and the successful
        // allocation is immediately owned by _admins for LocalFree cleanup.
        unsafe { ConvertStringSidToSidW(admins.as_ptr(), &mut admins_sid) },
        0
    );
    let _admins = Allocation(admins_sid);
    let restricted = SID_AND_ATTRIBUTES {
        Sid: everyone_sid,
        Attributes: 0,
    };
    let disabled = SID_AND_ATTRIBUTES {
        Sid: admins_sid,
        Attributes: 0,
    };
    let mut raw = ptr::null_mut();
    assert_ne!(
        // SAFETY: all buffers/token handles remain live; privileges and administrator
        // allow ACEs are disabled, and the restricting SID requires an Everyone ACE.
        unsafe {
            CreateRestrictedToken(
                process_token.as_raw_handle(),
                DISABLE_MAX_PRIVILEGE,
                1,
                &disabled,
                0,
                ptr::null(),
                1,
                &restricted,
                &mut raw,
            )
        },
        0
    );
    // SAFETY: CreateRestrictedToken succeeded and transferred this unique handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    // SAFETY: this live token grants impersonation access; the test restores the
    // thread's original token with the following Impersonation guard.
    assert_ne!(unsafe { ImpersonateLoggedOnUser(token.as_raw_handle()) }, 0);
    let impersonation = Impersonation;
    assert_eq!(
        fs::read(path.join("service.jsonl")).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        File::create(path.join("forbidden")).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    drop(impersonation);
    assert_eq!(fs::read(path.join("service.jsonl")).unwrap(), before);
    assert!(!path.join("forbidden").exists());
}

#[cfg(feature = "tracing")]
#[test]
fn process_sink_routes_typed_and_tracing_events_to_one_persistent_file() {
    let parent = tempfile::tempdir().unwrap();
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "log::windows_rotating::tests::process_sink_helper",
        ])
        .env("XCSS_LOG_TEST_DIRECTORY", parent.path().join("logs"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let bytes = fs::read(parent.path().join("logs/service.jsonl")).unwrap();
    let records = query(&bytes[..], LogFilter::default(), QueryLimits::default()).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].instance_id.as_deref(), Some("instance"));
    assert_eq!(records[1].event, "test-service.worker.completed");
}

#[cfg(feature = "tracing")]
#[test]
#[ignore = "invoked in a subprocess by process_sink_routes_typed_and_tracing_events_to_one_persistent_file"]
fn process_sink_helper() {
    use tracing_subscriber::prelude::*;
    let path = PathBuf::from(std::env::var_os("XCSS_LOG_TEST_DIRECTORY").unwrap());
    let sink = RotatingLogFile::create_private(&path, "service", limits()).unwrap();
    crate::log::install_rotating_file(sink).unwrap();
    record("instance").emit().unwrap();
    let layer = crate::log::XcscStructuredLayer::new("test-service").unwrap();
    let counter = layer.clone();
    tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), || {
        tracing::info!(
            event = "test-service.worker.completed",
            message = "The worker completed its operation."
        );
    });
    assert_eq!(counter.rejected_count(), 0);
    let other = tempfile::tempdir().unwrap();
    assert!(
        crate::log::install_rotating_file(
            RotatingLogFile::create_private(other.path().join("logs"), "service", limits())
                .unwrap()
        )
        .is_err()
    );
}

const SERVICE_SID: &str = "S-1-5-80-1-2-3-4-5";

#[test]
fn service_policy_rejects_noncanonical_and_account_wide_principals_before_creation() {
    for sid in [
        "S-1-5-19",
        "S-1-5-80-0",
        "S-1-5-80-1-2-3-4",
        "S-1-5-80-1-2-3-4-5-6",
        "S-1-5-80-01-2-3-4-5",
        "S-1-5-80-4294967296-2-3-4-5",
        "S-1-5-80-1-2-3-4-5)(A;;FA;;;WD)",
    ] {
        assert!(matches!(
            WindowsLogAccess::for_service(sid),
            Err(LogError::UnsafeStorage)
        ));
    }
    assert!(WindowsLogAccess::for_service(&"x".repeat(65)).is_err());
    let policy = WindowsLogAccess::for_service(SERVICE_SID).unwrap();
    assert_eq!(policy.owner_sid, "S-1-5-19");
    if current_sid().unwrap() != "S-1-5-19" {
        let parent = tempfile::tempdir().unwrap();
        let path = parent.path().join("logs");
        assert!(matches!(
            RotatingLogFile::create_private_with_access(&path, "service", limits(), policy),
            Err(LogError::UnsafeStorage)
        ));
        assert!(!path.exists());
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }
}

// These native fixtures retain the real CI identity/groups. A duplicate token
// selects its actual user as default owner before NULL-SA creation; no later
// ownership rewrite can change inherited OWNER RIGHTS behavior. The root is
// administrator-owned. This is not a LocalService/SCM execution claim.
struct FixtureOwnerToken {
    _token: OwnedHandle,
}

impl FixtureOwnerToken {
    #[allow(unsafe_code)]
    fn impersonate(owner: &str) -> Self {
        use windows_sys::Win32::Security::{
            DuplicateTokenEx, SecurityImpersonation, SetTokenInformation, TOKEN_ADJUST_DEFAULT,
            TOKEN_OWNER, TokenImpersonation, TokenOwner,
        };
        let mut raw = ptr::null_mut();
        assert_ne!(
            // SAFETY: real primary token, fixed query/duplicate rights and writable output.
            unsafe {
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw)
            },
            0
        );
        // SAFETY: successful API transfers sole ownership of this token.
        let process = unsafe { OwnedHandle::from_raw_handle(raw) };
        let owner_text = wide(OsStr::new(owner)).unwrap();
        let mut owner_sid = ptr::null_mut();
        assert_ne!(
            // SAFETY: OS-derived terminated SID; Allocation holds the successful output.
            unsafe { ConvertStringSidToSidW(owner_text.as_ptr(), &mut owner_sid) },
            0
        );
        let _owner = Allocation(owner_sid);
        let mut raw = ptr::null_mut();
        assert_ne!(
            // SAFETY: duplicate retains real identity/groups; only this fixture token changes.
            unsafe {
                DuplicateTokenEx(
                    process.as_raw_handle(),
                    TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_ADJUST_DEFAULT,
                    ptr::null(),
                    SecurityImpersonation,
                    TokenImpersonation,
                    &mut raw,
                )
            },
            0
        );
        // SAFETY: successful duplication transfers sole owned handle.
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let owner = TOKEN_OWNER { Owner: owner_sid };
        assert_ne!(
            // SAFETY: fixed native struct and its held SID outlive the synchronous setter.
            unsafe {
                SetTokenInformation(
                    token.as_raw_handle(),
                    TokenOwner,
                    (&owner as *const TOKEN_OWNER).cast(),
                    size_of::<TOKEN_OWNER>() as u32,
                )
            },
            0
        );
        // SAFETY: guard holds this token and reverts before closing it.
        assert_ne!(unsafe { ImpersonateLoggedOnUser(token.as_raw_handle()) }, 0);
        Self { _token: token }
    }
}
impl Drop for FixtureOwnerToken {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: paired with this guard's successful thread impersonation.
        assert_ne!(unsafe { RevertToSelf() }, 0);
    }
}

#[allow(unsafe_code)]
fn service_acl_fixture() -> (
    tempfile::TempDir,
    PathBuf,
    WindowsLogAccess,
    RotatingLogFile,
    FixtureOwnerToken,
) {
    let parent = tempfile::tempdir().unwrap();
    let anchor = parent.path().join("state");
    let mut policy = WindowsLogAccess::for_service(SERVICE_SID).unwrap();
    policy.owner_sid = "S-1-5-32-544".into();
    let sd = descriptor(&policy, true).unwrap();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let name = wide(anchor.as_os_str()).unwrap();
    // SAFETY: controlled test root and exact administrator-owned descriptor stay live.
    assert_ne!(unsafe { CreateDirectoryW(name.as_ptr(), &attributes) }, 0);
    policy.owner_sid = current_sid().unwrap();
    let owner = FixtureOwnerToken::impersonate(&policy.owner_sid);
    let path = anchor.join("logs");
    let sink =
        RotatingLogFile::create_private_with_access(&path, "service", limits(), policy.clone())
            .unwrap();
    assert_inherited_policy(&path, &policy, true);
    (parent, path, policy, sink, owner)
}

#[allow(unsafe_code)]
fn assert_inherited_policy(path: &Path, policy: &WindowsLogAccess, directory: bool) {
    let held = open_handle(
        path,
        directory,
        FILE_READ_ATTRIBUTES,
        LeafOpen::Existing,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )
    .unwrap();
    let observed = inspect_acl(&held, policy, directory).unwrap();
    assert!(observed.owner_matches);
    assert!(!observed.protected);
    let mut dacl = ptr::null_mut();
    let mut sd = ptr::null_mut();
    assert_eq!(
        // SAFETY: the live metadata handle yields one LocalFree descriptor owning its DACL.
        unsafe {
            GetSecurityInfo(
                held.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut sd,
            )
        },
        ERROR_SUCCESS
    );
    let _allocation = Allocation(sd);
    // SAFETY: successful SDK descriptor supplies a complete live ACL header.
    for index in 0..unsafe { (*dacl).AceCount } {
        let mut raw = ptr::null_mut();
        // SAFETY: index is within the live SDK ACL; returned ACE header is held by allocation.
        assert_ne!(unsafe { GetAce(dacl, index.into(), &mut raw) }, 0);
        assert_eq!(
            // SAFETY: successful GetAce returned a valid native header.
            u32::from(unsafe { (*raw.cast::<ACE_HEADER>()).AceFlags }),
            INHERITED_ACE
                | if directory {
                    OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
                } else {
                    0
                }
        );
    }
}

#[test]
#[allow(unsafe_code)]
fn service_acl_rotates_reopens_and_rejects_account_wide_grants_without_repair() {
    use windows_sys::Win32::Security::{
        Authorization::SetNamedSecurityInfoW, GetSecurityDescriptorDacl,
        PROTECTED_DACL_SECURITY_INFORMATION,
    };
    let (_parent, path, policy, mut sink, _owner_token) = service_acl_fixture();
    for _ in 0..200 {
        sink.write(&record("instance")).unwrap();
    }
    drop(sink);
    for entry in fs::read_dir(&path).unwrap() {
        assert_inherited_policy(&entry.unwrap().path(), &policy, false);
    }
    let mut sink =
        RotatingLogFile::open_with_access(&path, "service", limits(), policy.clone()).unwrap();
    let active = path.join("service.jsonl");
    let before = fs::read(&active).unwrap();
    let broad = WindowsLogAccess {
        owner_sid: policy.owner_sid.clone(),
        service_sid: None,
    };
    let sd = descriptor(&broad, false).unwrap();
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = ptr::null_mut();
    assert_ne!(
        // SAFETY: the owned native descriptor remains live while extracting its DACL.
        unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) },
        0
    );
    assert_ne!(present, 0);
    let name = wide(active.as_os_str()).unwrap();
    assert_eq!(
        // SAFETY: this controlled fixture is administered by the test token; the
        // descriptor and path remain live. Deliberately replace only this test ACL.
        unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null_mut(),
            )
        },
        ERROR_SUCCESS
    );
    assert!(matches!(
        sink.write(&record("instance")),
        Err(LogError::UnsafeStorage)
    ));
    drop(sink);
    assert_eq!(fs::read(&active).unwrap(), before);
    assert!(matches!(
        RotatingLogFile::open_with_access(&path, "service", limits(), policy),
        Err(LogError::UnsafeStorage)
    ));
    let held = open_handle(
        &active,
        false,
        GENERIC_READ,
        LeafOpen::Existing,
        FILE_SHARE_READ,
    )
    .unwrap();
    // Rejection did not silently restore the restricted service ACL.
    verify_acl(&held, &broad, false).unwrap();
}

#[test]
#[allow(unsafe_code)]
fn service_owner_rights_prevent_data_access_and_implicit_dacl_rewrite() {
    use windows_sys::Win32::{
        Security::{AccessCheck, GENERIC_MAPPING, GROUP_SECURITY_INFORMATION, PRIVILEGE_SET},
        Storage::FileSystem::{
            FILE_FLAG_OVERLAPPED, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
            FILE_READ_DATA, WRITE_DAC,
        },
        System::Threading::{GetCurrentThread, OpenThreadToken},
    };
    fn requested_rights(path: &Path, rights: u32) -> io::Result<File> {
        let name = wide(path.as_os_str()).unwrap();
        // SAFETY: controlled fixture path is terminated and live. Request
        // exactly these rights. OVERLAPPED avoids the implicit SYNCHRONIZE right
        // required by a synchronous handle; adding it or READ_ATTRIBUTES would
        // mask the distinct OWNER RIGHTS behavior that this test must prove.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                rights,
                FILE_SHARE_READ,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OVERLAPPED,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful creation returned a unique owned handle.
        Ok(unsafe { File::from_raw_handle(handle) })
    }
    for inherited in [false, true] {
        let (_parent, active, policy, _owner_token) = if inherited {
            let (parent, path, policy, mut sink, owner_token) = service_acl_fixture();
            sink.write(&record("instance")).unwrap();
            drop(sink);
            let active = path.join("service.jsonl");
            assert_inherited_policy(&active, &policy, false);
            (parent, active, policy, Some(owner_token))
        } else {
            let parent = tempfile::tempdir().unwrap();
            let active = parent.path().join("owner-rights.jsonl");
            let mut policy = WindowsLogAccess::for_service(SERVICE_SID).unwrap();
            policy.owner_sid = current_sid().unwrap();
            let sd = descriptor(&policy, false).unwrap();
            let mut file = open_handle(
                &active,
                false,
                GENERIC_READ | GENERIC_WRITE,
                LeafOpen::Protected(&sd),
                FILE_SHARE_READ,
            )
            .unwrap();
            file.write_all(b"private-marker").unwrap();
            file.sync_all().unwrap();
            drop(file);
            (parent, active, policy, None)
        };
        let before = fs::read(&active).unwrap();
        let held = requested_rights(&active, READ_CONTROL).unwrap();
        verify_acl(&held, &policy, false).unwrap();
        let mut owner = ptr::null_mut();
        let mut group = ptr::null_mut();
        let mut dacl = ptr::null_mut();
        let mut sd = ptr::null_mut();
        assert_eq!(
            // SAFETY: the live fixture handle grants READ_CONTROL. This returns one
            // LocalFree-owned descriptor containing all SID/ACL pointers below.
            unsafe {
                GetSecurityInfo(
                    held.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION
                        | GROUP_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION,
                    &mut owner,
                    &mut group,
                    &mut dacl,
                    ptr::null_mut(),
                    &mut sd,
                )
            },
            ERROR_SUCCESS
        );
        let descriptor = Allocation(sd);
        assert!(!owner.is_null() && !group.is_null() && !dacl.is_null());
        assert_eq!(sid_text(owner).unwrap(), policy.owner_sid);
        let mut raw = ptr::null_mut();
        assert_ne!(
            // SAFETY: writable output receives one owned current-process token.
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                    &mut raw,
                )
            },
            0
        );
        // SAFETY: the successful API transferred sole ownership of this token.
        let process = unsafe { OwnedHandle::from_raw_handle(raw) };
        let admins = wide(OsStr::new("S-1-5-32-544")).unwrap();
        let mut admins_sid = ptr::null_mut();
        assert_ne!(
            // SAFETY: fixed NUL-terminated SID and writable output; Allocation frees it.
            unsafe { ConvertStringSidToSidW(admins.as_ptr(), &mut admins_sid) },
            0
        );
        let _admins = Allocation(admins_sid);
        let disabled = SID_AND_ATTRIBUTES {
            Sid: admins_sid,
            Attributes: 0,
        };
        let mut raw = ptr::null_mut();
        assert_ne!(
            // SAFETY: disable privileges and administrator allow grants, retaining the
            // actual owner SID and no extra restricting SID that could mask owner rights.
            unsafe {
                CreateRestrictedToken(
                    process.as_raw_handle(),
                    DISABLE_MAX_PRIVILEGE,
                    1,
                    &disabled,
                    0,
                    ptr::null(),
                    0,
                    ptr::null(),
                    &mut raw,
                )
            },
            0
        );
        // SAFETY: successful token creation transferred this unique live handle.
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        // SAFETY: token has impersonation access; the following guard restores it.
        assert_ne!(unsafe { ImpersonateLoggedOnUser(token.as_raw_handle()) }, 0);
        let impersonation = Impersonation;
        let mut raw = ptr::null_mut();
        assert_ne!(
            // SAFETY: OpenAsSelf only authorizes opening the current thread's token;
            // the returned token is the actual restricted impersonation identity.
            unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) },
            0
        );
        // SAFETY: successful OpenThreadToken transferred one owned live handle.
        let thread_token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut needed = 0;
        // SAFETY: the live token and writable length support the documented size query.
        unsafe {
            GetTokenInformation(
                thread_token.as_raw_handle(),
                TokenUser,
                ptr::null_mut(),
                0,
                &mut needed,
            );
        }
        assert!((size_of::<TOKEN_USER>() as u32..=16 * 1024).contains(&needed));
        let mut user = vec![0u64; (needed as usize).div_ceil(8)];
        assert_ne!(
            // SAFETY: the bounded u64-aligned buffer holds at least needed bytes.
            unsafe {
                GetTokenInformation(
                    thread_token.as_raw_handle(),
                    TokenUser,
                    user.as_mut_ptr().cast(),
                    needed,
                    &mut needed,
                )
            },
            0
        );
        // SAFETY: successful query initialized TOKEN_USER and its SID in this live buffer.
        let user_sid = unsafe { (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
        assert_eq!(sid_text(user_sid).unwrap(), sid_text(owner).unwrap());
        let mapping = GENERIC_MAPPING {
            GenericRead: FILE_GENERIC_READ,
            GenericWrite: FILE_GENERIC_WRITE,
            GenericExecute: FILE_GENERIC_EXECUTE,
            GenericAll: FILE_ALL_ACCESS,
        };
        for (rights, expected) in [
            (READ_CONTROL, true),
            (WRITE_DAC, false),
            (FILE_READ_DATA, false),
        ] {
            let mut privileges = PRIVILEGE_SET::default();
            let mut privilege_bytes = size_of::<PRIVILEGE_SET>() as u32;
            let mut granted = 0;
            let mut allowed = 0;
            // Test the actual file's DACL and actual owner token directly. A path
            // open also checks directory traversal and Win32 file-open semantics,
            // which must not mask this OWNER RIGHTS positive/negative control.
            assert_ne!(
                // SAFETY: owned descriptor/token are live; exact non-generic rights,
                // file mapping and correctly sized writable outputs satisfy AccessCheck.
                unsafe {
                    AccessCheck(
                        descriptor.0,
                        thread_token.as_raw_handle(),
                        rights,
                        &mapping,
                        &mut privileges,
                        &mut privilege_bytes,
                        &mut granted,
                        &mut allowed,
                    )
                },
                0,
                "AccessCheck API failed for {rights:#x}: {}",
                io::Error::last_os_error()
            );
            assert_eq!(
                allowed != 0,
                expected,
                "rights {rights:#x}; inherited={inherited}"
            );
            assert_eq!(granted, if expected { rights } else { 0 });
        }
        assert_eq!(
            fs::read(&active).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(matches!(requested_rights(&active, WRITE_DAC),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied));
        drop(impersonation);
        assert_eq!(fs::read(active).unwrap(), before);
    }
}

#[test]
fn service_storage_refuses_ambient_inheritance_and_shared_account_owned_roots() {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("untrusted-root");
    let mut policy = WindowsLogAccess::for_service(SERVICE_SID).unwrap();
    // Isolate this CI-account fixture from the public LocalService identity.
    policy.owner_sid = current_sid().unwrap();
    let sd = descriptor(&policy, true).unwrap();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let name = wide(path.as_os_str()).unwrap();
    // SAFETY: controlled fixture name and held exact descriptor outlive this call.
    #[allow(unsafe_code)]
    let created = unsafe { CreateDirectoryW(name.as_ptr(), &attributes) };
    assert_ne!(created, 0);
    assert!(matches!(
        RotatingLogFile::open_with_access(&path, "service", limits(), policy.clone()),
        Err(LogError::UnsafeStorage)
    ));
    assert!(matches!(
        RotatingLogFile::create_private_with_access(
            path.join("logs"),
            "service",
            limits(),
            policy.clone()
        ),
        Err(LogError::UnsafeStorage)
    ));
    assert!(!path.join("logs").exists());
    assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
    // Missing protected policy, even below an otherwise genuine private root,
    // must never be skipped while searching upward for an anchor.
    let (_parent, logs, policy, sink, _owner_token) = service_acl_fixture();
    drop(sink);
    let foreign = WindowsLogAccess::for_service("S-1-5-80-6-7-8-9-10").unwrap();
    let foreign = WindowsLogAccess {
        owner_sid: policy.owner_sid,
        ..foreign
    };
    assert!(matches!(
        RotatingLogFile::open_with_access(&logs, "service", limits(), foreign),
        Err(LogError::UnsafeStorage)
    ));
}

#[allow(unsafe_code)]
fn replace_fixture_dacl(path: &Path, policy: &WindowsLogAccess, directory: bool) {
    use windows_sys::Win32::Security::{
        Authorization::SetNamedSecurityInfoW, GetSecurityDescriptorDacl,
        PROTECTED_DACL_SECURITY_INFORMATION,
    };
    let descriptor = descriptor(policy, directory).unwrap();
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = ptr::null_mut();
    assert_ne!(
        // SAFETY: controlled SDK descriptor owns the DACL throughout this call.
        unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) },
        0
    );
    assert_ne!(present, 0);
    let name = wide(path.as_os_str()).unwrap();
    assert_eq!(
        // SAFETY: change only this administered fixture; live path and descriptor.
        unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null_mut(),
            )
        },
        ERROR_SUCCESS
    );
}

#[allow(unsafe_code)]
fn fixture_sddl(file: &File) -> String {
    use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
    let information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut sd = ptr::null_mut();
    // SAFETY: live metadata handle and writable output; the returned allocation
    // owns the complete descriptor until string conversion has finished.
    let error = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            information,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut sd,
        )
    };
    if error != ERROR_SUCCESS {
        return format!("GetSecurityInfo error {error}");
    }
    let _descriptor = Allocation(sd);
    let mut text = ptr::null_mut();
    let mut length = 0;
    // SAFETY: the successful SDK query owns a live descriptor; SDDL revision 1
    // and writable outputs are valid. The resulting string has separate ownership.
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            information,
            &mut text,
            &mut length,
        )
    } == 0
    {
        return format!("SDDL conversion error {}", io::Error::last_os_error());
    }
    let _text = Allocation(text.cast());
    if text.is_null() || !(1..=16 * 1024).contains(&length) {
        return format!("invalid SDDL output length {length}");
    }
    // SAFETY: the successful SDK conversion reports its allocated WCHAR buffer
    // length; the allocation stays live and the bounded slice is only read.
    let text = unsafe { std::slice::from_raw_parts(text, length as usize) };
    let end = text
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(text.len());
    String::from_utf16_lossy(&text[..end])
}

fn require_fixture_acl(
    file: &File,
    policy: &WindowsLogAccess,
    directory: bool,
    stage: &str,
) -> VerifiedAcl {
    inspect_acl(file, policy, directory).unwrap_or_else(|error| {
        panic!(
            "{stage}: {error:?}; physical owner/DACL: {}",
            fixture_sddl(file)
        )
    })
}

fn protect_fixture_log_objects(path: &Path, policy: &WindowsLogAccess, sink: &RotatingLogFile) {
    // This owner-mutation fixture must not modify inherited descendant ACLs.
    // Protect leaves before their parent, retaining the same exact trustees,
    // rights and actual owner. Other tests exercise real inherited storage.
    replace_fixture_dacl(
        &path.join(format!(".{}.writer.lock", sink.active)),
        policy,
        false,
    );
    replace_fixture_dacl(&path.join(&sink.active), policy, false);
    replace_fixture_dacl(path, policy, true);
    for (file, directory, stage) in [
        (
            sink._directories.last().unwrap(),
            true,
            "protected log directory",
        ),
        (&sink._writer, false, "protected writer"),
        (sink.file.as_ref().unwrap(), false, "protected active"),
    ] {
        let acl = require_fixture_acl(file, policy, directory, stage);
        assert!(
            acl.protected && acl.owner_matches,
            "{stage}: {}",
            fixture_sddl(file)
        );
    }
    sink.verify_namespace().unwrap();
}

#[test]
fn service_namespace_rechecks_fixed_anchor_before_append_without_repair() {
    let (_parent, path, policy, mut sink, _owner_token) = service_acl_fixture();
    sink.write(&record("instance")).unwrap();
    let active = path.join("service.jsonl");
    let before = fs::read(&active).unwrap();
    let anchor = path.parent().unwrap();
    protect_fixture_log_objects(&path, &policy, &sink);
    // Change only the trusted owner's identity, then reinstate the exact
    // fixture DACL. Both leaf policies remain valid, so rejection must inspect
    // the stored protected anchor rather than merely notice propagation.
    replace_fixture_owner(anchor, &policy.owner_sid);
    replace_fixture_dacl(anchor, &policy, true);
    require_fixture_acl(
        sink._directories.last().unwrap(),
        &policy,
        true,
        "unchanged log directory",
    );
    require_fixture_acl(&sink._writer, &policy, false, "unchanged writer");
    require_fixture_acl(
        sink.file.as_ref().unwrap(),
        &policy,
        false,
        "unchanged active",
    );
    assert!(matches!(
        sink.write(&record("instance")),
        Err(LogError::UnsafeStorage)
    ));
    assert_eq!(fs::read(&active).unwrap(), before);
    drop(sink);
    assert!(matches!(
        RotatingLogFile::open_with_access(&path, "service", limits(), policy.clone()),
        Err(LogError::UnsafeStorage)
    ));
    let held = open_handle(
        anchor,
        true,
        FILE_READ_ATTRIBUTES,
        LeafOpen::Existing,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )
    .unwrap();
    let acl = inspect_acl(&held, &policy, true).unwrap();
    assert!(
        acl.protected && acl.owner_matches && !acl.anchor_owner,
        "{}",
        fixture_sddl(&held)
    );
}

#[test]
fn rotation_rejects_bad_archive_before_deleting_other_retained_evidence() {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("logs");
    let mut sink = RotatingLogFile::create_private(&path, "service", limits()).unwrap();
    for _ in 0..200 {
        sink.write(&record("instance")).unwrap();
    }
    let slots = [
        path.join("service.jsonl"),
        path.join("service.jsonl.1"),
        path.join("service.jsonl.2"),
    ];
    let before: Vec<_> = slots.iter().map(|path| fs::read(path).unwrap()).collect();
    fs::hard_link(&slots[1], parent.path().join("unexpected-hardlink")).unwrap();
    assert!(matches!(sink.rotate(), Err(LogError::UnsafeStorage)));
    assert!(sink.file.is_some());
    for (path, before) in slots.iter().zip(before) {
        assert_eq!(fs::read(path).unwrap(), before);
    }
}

#[test]
fn windows_namespace_names_reject_trimmed_device_and_stream_aliases() {
    for name in [
        "logs.",
        "logs ",
        "logs:stream",
        "NUL",
        "con.txt",
        "COM1",
        "LPT³.log",
        "CONIN$",
        "child\\name",
        "bad?name",
    ] {
        assert!(
            matches!(
                validate_component(OsStr::new(name)),
                Err(LogError::UnsafeStorage)
            ),
            "{name}"
        );
    }
    assert!(validate_component(OsStr::new(&"x".repeat(256))).is_err());
    for name in ["logs", "状态", "COM10", "LPT0", "console.log"] {
        validate_component(OsStr::new(name)).unwrap();
    }
}

#[allow(unsafe_code)]
fn replace_fixture_owner(path: &Path, owner: &str) {
    use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
    let text = wide(OsStr::new(owner)).unwrap();
    let mut owner_sid = ptr::null_mut();
    assert_ne!(
        // SAFETY: fixed or actual CI SID; unique Allocation holds SDK output.
        unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut owner_sid) },
        0
    );
    let _owner = Allocation(owner_sid);
    let path = wide(path.as_os_str()).unwrap();
    assert_eq!(
        // SAFETY: controlled isolated fixture; only ownership is changed here.
        unsafe {
            SetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                owner_sid,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        },
        ERROR_SUCCESS
    );
}

#[test]
fn service_final_directory_owner_is_rechecked_after_open() {
    let (_parent, path, policy, mut sink, _owner_token) = service_acl_fixture();
    sink.write(&record("instance")).unwrap();
    let active = path.join("service.jsonl");
    let before = fs::read(&active).unwrap();
    protect_fixture_log_objects(&path, &policy, &sink);
    replace_fixture_owner(&path, "S-1-5-32-544");
    replace_fixture_dacl(&path, &policy, true);
    // Exact trustees and protected policy do not make a privileged-owned
    // payload directory the declared service-account-owned log directory.
    require_fixture_acl(&sink._writer, &policy, false, "unchanged writer");
    require_fixture_acl(
        sink.file.as_ref().unwrap(),
        &policy,
        false,
        "unchanged active",
    );
    let terminal = require_fixture_acl(
        sink._directories.last().unwrap(),
        &policy,
        true,
        "changed terminal owner",
    );
    assert!(
        terminal.protected && terminal.anchor_owner && !terminal.owner_matches,
        "{}",
        fixture_sddl(sink._directories.last().unwrap())
    );
    assert!(matches!(
        sink.write(&record("instance")),
        Err(LogError::UnsafeStorage)
    ));
    assert_eq!(fs::read(active).unwrap(), before);
}
