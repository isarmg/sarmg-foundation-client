use super::*;

#[test]
fn process_user_sid_matches_the_native_primary_token_identity() {
    let actual = process_user_sid().unwrap();
    let output = std::process::Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains(&format!("\"{actual}\"")));
    assert!(
        WindowsPrivateAccess::for_current_user()
            .unwrap()
            .accepts(&actual)
    );
}
#[test]
fn derived_service_sid_matches_native_sc_without_installation() {
    for name in [
        "XcscFoundationFixture",
        "xcscfoundationfixture",
        "XcscStraßeİFixture",
        "Xcsc测试Fixture",
    ] {
        let sid = service_sid(name).unwrap();
        let output = std::process::Command::new("sc.exe")
            .args(["showsid", name])
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains(&sid), "Derived SID differs from SCM");
        assert!(specific_service_sid(&sid));
    }
    assert_eq!(
        service_sid("XcscFoundationFixture").unwrap(),
        service_sid("xcscfoundationfixture").unwrap()
    );
    for invalid in ["", "a/b", "a\\b", "a\0b", &"x".repeat(257)] {
        assert!(service_sid(invalid).is_err());
    }
    assert!(service_sid(&"x".repeat(256)).is_ok());
}

#[test]
fn held_private_file_keeps_original_pins_after_directory_owner_drops() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("private-held");
    let name = EntryName::new("database.sqlite3").unwrap();
    let directory = PrivateDirectory::create(&path).unwrap();
    super::super::AtomicFile::create(&directory, &name, b"private").unwrap();
    let mut held = directory
        .open_private_file(&name, PrivateFileAccess::ReadWrite)
        .unwrap();
    drop(directory);
    held.verify().unwrap();
    assert!(std::fs::rename(&path, temp.path().join("moved")).is_err());
    assert!(std::fs::remove_file(path.join(name.as_path())).is_err());
    held.file.write_all(b"updated").unwrap();
    held.file.sync_all().unwrap();
    held.verify().unwrap();
    drop(held);
    std::fs::rename(&path, temp.path().join("moved")).unwrap();
}

#[test]
fn held_private_file_refuses_links_and_acl_poison_without_repair() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("private-held");
    let directory = PrivateDirectory::create(&path).unwrap();
    let name = EntryName::new("database.sqlite3").unwrap();
    assert!(
        directory
            .open_private_file(&name, PrivateFileAccess::ReadWrite)
            .is_err()
    );
    assert!(!path.join(name.as_path()).exists());
    super::super::AtomicFile::create(&directory, &name, b"private").unwrap();
    std::fs::hard_link(path.join(name.as_path()), path.join("alias")).unwrap();
    assert!(
        directory
            .open_private_file(&name, PrivateFileAccess::ReadOnly)
            .is_err()
    );
    std::fs::remove_file(path.join("alias")).unwrap();
    let held = directory
        .open_private_file(&name, PrivateFileAccess::ReadOnly)
        .unwrap();
    assert!(
        held.file()
            .try_clone()
            .unwrap()
            .write_all(b"write")
            .is_err()
    );
    let poisoned = OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC | GENERIC_READ)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(path.join(name.as_path()))
        .unwrap();
    unsafe_acl(&poisoned);
    assert!(matches!(held.verify(), Err(Error::UnsafePermissions(_))));
    assert!(matches!(
        directory.open_private_file(&name, PrivateFileAccess::ReadWrite),
        Err(Error::UnsafePermissions(_))
    ));
    assert_eq!(
        std::fs::read(path.join(name.as_path())).unwrap(),
        b"private"
    );
    drop(poisoned);
    drop(held);
}
#[test]
fn service_access_rejects_all_services_and_noncanonical_sid_components() {
    for sid in [
        "S-1-5-80-0",
        "S-1-5-80-01-2-3-4-5",
        "S-1-5-80-1-2-3-4",
        "S-1-5-80-1-2-3-4-4294967296",
    ] {
        assert!(!specific_service_sid(sid));
        assert!(WindowsPrivateAccess::for_service(sid, "S-1-5-19").is_err());
    }
    assert!(specific_service_sid("S-1-5-80-1-2-3-4-5"));
    assert!(
        !WindowsPrivateAccess::current_process()
            .unwrap()
            .accepts("S-1-5-80-0")
    );
}
#[test]
fn canonical_local_drive_paths_preserve_private_checks_and_reject_namespaces() {
    for path in [
        r"\\server\share\state",
        r"\\?\UNC\server\share\state",
        r"\\.\C:\state",
        r"C:\state\..\other",
        r"C:\state\file:stream",
    ] {
        assert!(checked_path(Path::new(path)).is_err());
    }
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state");
    let directory = PrivateDirectory::create(&path).unwrap();
    let canonical = path.canonicalize().unwrap();
    checked_path(&canonical).unwrap();
    super::super::AtomicFile::create(
        &directory,
        &EntryName::new("state.json").unwrap(),
        b"private",
    )
    .unwrap();
    let reopened = PrivateDirectory::open_existing(canonical).unwrap();
    assert_eq!(
        reopened
            .read_private_bounded(&EntryName::new("state.json").unwrap(), 7)
            .unwrap(),
        b"private"
    );
}
#[test]
fn canonical_verbatim_atomic_replacements_preserve_exact_names_for_all_alignments() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("private-state");
    let directory = PrivateDirectory::create(&path).unwrap();
    let canonical = path.canonicalize().unwrap();
    assert!(canonical.as_os_str().to_string_lossy().starts_with(r"\\?\"));
    drop(directory);
    let directory = PrivateDirectory::open_existing(&canonical).unwrap();
    let mut expected = Vec::new();
    for length in 1..=16 {
        // Vary the destination's UTF-16 length through every u64 alignment.
        let file_name = format!("{}-é.json", "a".repeat(length));
        let name = EntryName::new(&file_name).unwrap();
        super::super::AtomicFile::create(&directory, &name, b"first").unwrap();
        for replacement in [b"second".as_slice(), b"third".as_slice()] {
            super::super::AtomicFile::replace(&directory, &name.as_relative(), replacement)
                .unwrap();
            assert_eq!(
                directory.read_private_bounded(&name, 16).unwrap(),
                replacement
            );
            let reopened = PrivateDirectory::open_existing(&canonical).unwrap();
            assert_eq!(
                reopened.read_private_bounded(&name, 16).unwrap(),
                replacement
            );
        }
        expected.push(file_name);
    }
    let mut actual = std::fs::read_dir(&canonical)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    actual.sort();
    expected.sort();
    assert_eq!(
        actual, expected,
        "no truncated, suffixed or leftover temporary name is accepted"
    );
}
#[test]
fn specific_service_creation_preserves_modify_and_owner_rights_boundaries() {
    let service = "S-1-5-80-1-2-3-4-5";
    let access = WindowsPrivateAccess::for_service(service, "S-1-5-19").unwrap();
    assert!(access.accepts("S-1-5-19"));
    assert!(!access.accepts_ace("S-1-5-19"));
    assert!(access.accepts_ace(service));
    assert!(WindowsPrivateAccess::for_service_account("S-1-5-32-545").is_err());
    let descriptor = access.descriptor(false).unwrap();
    unsafe {
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = std::ptr::null_mut();
        assert_ne!(
            GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted),
            0
        );
        assert_eq!((*acl).AceCount, 4);
        for index in 0..(*acl).AceCount {
            let mut raw = std::ptr::null_mut();
            assert_ne!(GetAce(acl, index.into(), &mut raw), 0);
            let ace = &*raw.cast::<ACCESS_ALLOWED_ACE>();
            let sid = sid_text(std::ptr::addr_of!(ace.SidStart).cast_mut().cast()).unwrap();
            match sid.as_str() {
                "S-1-5-18" | "S-1-5-32-544" => assert_eq!(ace.Mask, FILE_ALL_ACCESS),
                "S-1-3-4" => assert_eq!(ace.Mask, READ_CONTROL),
                value if value == service => assert_eq!(ace.Mask, 0x1301bf),
                _ => panic!("Unexpected service ACL principal"),
            }
        }
    }
}

const SERVICE_FIXTURE_SID: &str = "S-1-5-80-1-2-3-4-5";

struct FixtureOwnerToken {
    _token: File,
}

impl FixtureOwnerToken {
    fn impersonate(owner: &str) -> Self {
        let process = process_token().unwrap();
        let descriptor = native_descriptor(&format!("O:{owner}"));
        let mut owner_sid = std::ptr::null_mut();
        let mut defaulted = 0;
        let mut raw = std::ptr::null_mut();
        // SAFETY: live SDK owner descriptor and real process token. The
        // duplicate retains actual identity/groups and exists only in this
        // fixture; the setter captures its valid user/group default owner.
        unsafe {
            assert_ne!(
                GetSecurityDescriptorOwner(descriptor.0, &mut owner_sid, &mut defaulted),
                0
            );
            assert_ne!(
                DuplicateTokenEx(
                    process.as_raw_handle(),
                    TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_ADJUST_DEFAULT,
                    std::ptr::null(),
                    SecurityImpersonation,
                    TokenImpersonation,
                    &mut raw
                ),
                0
            );
        }
        // SAFETY: successful duplication transfers one uniquely owned handle.
        let token = unsafe { File::from_raw_handle(raw) };
        let default_owner = TOKEN_OWNER { Owner: owner_sid };
        // SAFETY: fixed TOKEN_OWNER and its SDK SID remain live through the
        // synchronous setter; no process token or privilege is changed.
        assert_ne!(
            unsafe {
                SetTokenInformation(
                    token.as_raw_handle(),
                    TokenOwner,
                    (&default_owner as *const TOKEN_OWNER).cast(),
                    std::mem::size_of::<TOKEN_OWNER>() as u32,
                )
            },
            0
        );
        // SAFETY: select the actual duplicate only on this test thread. The
        // guard keeps its handle and restores identity before closing it.
        assert_ne!(unsafe { ImpersonateLoggedOnUser(token.as_raw_handle()) }, 0);
        Self { _token: token }
    }
}

impl Drop for FixtureOwnerToken {
    fn drop(&mut self) {
        // SAFETY: paired with successful thread impersonation above; revert
        // happens before this guard's owned token handle is dropped.
        assert_ne!(unsafe { RevertToSelf() }, 0);
    }
}

// The isolated root is explicitly administrator-owned, as trusted provisioning
// would make it. Only the later file owner uses the real CI account; no
// LocalService token or trusted shared-account root is fabricated.
fn service_fixture() -> (tempfile::TempDir, PrivateDirectory, EntryName) {
    let temp = tempfile::tempdir().unwrap();
    let mut access = WindowsPrivateAccess::for_service(SERVICE_FIXTURE_SID, "S-1-5-19").unwrap();
    access.principals.push(process_user_sid().unwrap());
    let path = temp.path().join("service-state");
    let root = native_descriptor(&format!(
        "O:BA{}",
        service_directory_acl(SERVICE_FIXTURE_SID)
    ));
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: root.0,
        bInheritHandle: 0,
    };
    // SAFETY: controlled isolated fixture path and live SDK security descriptor.
    assert_ne!(
        unsafe { CreateDirectoryW(wide(path.as_os_str()).unwrap().as_ptr(), &attributes) },
        0
    );
    let directory = PrivateDirectory::open_with_windows_access(path, access).unwrap();
    let name = EntryName::new("credential.json").unwrap();
    let owner = process_user_sid().unwrap();
    {
        // Determine the real file's owner at creation, instead of an
        // administrator changing ownership after inherited ACL assignment.
        let _owner_token = FixtureOwnerToken::impersonate(&owner);
        assert_eq!(creation_owner_sid().unwrap(), owner);
        let created = super::super::AtomicFile::create(&directory, &name, b"private-marker");
        if created.is_err() {
            // Bound failure diagnostics to this isolated fixture's physical
            // ACLs; never read payload bytes or dump arbitrary token state.
            for entry in std::fs::read_dir(directory.path()).unwrap().take(4) {
                let file = OpenOptions::new()
                    .access_mode(READ_CONTROL)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(entry.unwrap().path())
                    .unwrap();
                println!(
                    "isolated failed owner-at-creation security: {}",
                    physical_acl_text(&file)
                );
            }
        }
        created.unwrap();
    }
    let held = directory
        .open_private_file(&name, PrivateFileAccess::ReadOnly)
        .unwrap();
    assert_fixture_owner(held.file(), &owner);
    assert_native_inherited_acl(held.file(), false);
    held.verify().unwrap(); // Requires all four effective trustees, including OW RC.
    println!(
        "isolated service fixture security: {}",
        physical_acl_text(held.file())
    );
    (temp, directory, name)
}

fn service_directory_acl(service: &str) -> String {
    format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;{service})(A;OICI;RC;;;OW)")
}

fn fixture_administrator_directory(path: &Path) -> File {
    OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC | WRITE_OWNER)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .unwrap()
}

fn replace_fixture_owner(file: &File, sid: &str, access: &WindowsPrivateAccess, path: &Path) {
    let descriptor = native_descriptor(&format!("O:{sid}"));
    let mut owner = std::ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: live controlled fixture descriptor and WRITE_OWNER handle.
    unsafe {
        assert_ne!(
            GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut defaulted),
            0
        );
        assert_eq!(
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ),
            ERROR_SUCCESS
        );
    }
    // Isolate the owner-authentication negative control from any ACL effects
    // of the privileged owner reassignment. Only this fixture reinstalls its
    // controlled exact DACL; production never repairs existing permissions.
    replace_fixture_acl(file, &service_directory_acl(SERVICE_FIXTURE_SID));
    assert_fixture_owner(file, sid);
    assert!(
        access.accepts(sid),
        "negative control must retain an accepted descendant owner"
    );
    let text = physical_acl_text(file);
    let acl = verify_acl(file, access, path, true).unwrap_or_else(|error| {
        panic!("owner fixture lost exact effective policy: {error}; {text}")
    });
    assert!(acl.protected, "owner fixture protection: {text}");
    assert!(
        !acl.anchor_owner,
        "negative control unexpectedly has a trusted root owner: {text}"
    );
    println!("isolated untrusted root-owner security: {text}");
}

fn assert_fixture_owner(file: &File, expected: &str) {
    let descriptor = physical_descriptor(file);
    let mut owner = std::ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: actual SDK descriptor remains live through owner conversion.
    unsafe {
        assert_ne!(
            GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut defaulted),
            0
        );
        assert_eq!(sid_text(owner).unwrap(), expected);
    }
}

fn assert_native_inherited_acl(file: &File, directory: bool) {
    let descriptor = physical_descriptor(file);
    let mut control = 0;
    let mut revision = 0;
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = std::ptr::null_mut();
    // SAFETY: actual held native descriptor and initialized SDK outputs.
    unsafe {
        assert_ne!(
            GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision),
            0
        );
        assert_eq!(control & SE_DACL_PROTECTED, 0);
        assert_ne!(
            GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted),
            0
        );
        assert_ne!(present, 0);
        assert!(!acl.is_null());
        assert_eq!((*acl).AceCount, 4);
        for index in 0..4 {
            let mut raw = std::ptr::null_mut();
            assert_ne!(GetAce(acl, index, &mut raw), 0);
            assert_eq!(
                u32::from((*raw.cast::<ACE_HEADER>()).AceFlags),
                INHERITED_ACE
                    | if directory {
                        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
                    } else {
                        0
                    }
            );
        }
    }
}

#[test]
fn spool_inspection_borrows_the_verified_service_policy_without_reopening_as_user() {
    use crate::runtime::{BoundedBytes, ContractId, QuarantineReason, Spool, SpoolLimits};
    let (_temp, root, _name) = service_fixture();
    let directory = root
        .create_child(&EntryName::new("spool").unwrap())
        .unwrap();
    let path = directory.path().to_path_buf();
    let limits = SpoolLimits {
        max_record_bytes: 1024,
        max_entries: 8,
        max_bytes: 16 * 1024,
    };
    let writer = Spool::from_directory(directory, limits).unwrap();
    let id = writer
        .enqueue(
            ContractId::new("example.current").unwrap(),
            1,
            BoundedBytes::new(b"pending".to_vec(), 1024).unwrap(),
        )
        .unwrap();
    writer
        .quarantine(&id, QuarantineReason::IdentityMismatch)
        .unwrap();
    // The interactive-user policy must continue rejecting the service ACL.
    assert!(Spool::inspect_existing(&path, limits).is_err());
    let inspector = PrivateDirectory::open_with_windows_access(&path, root.access.clone()).unwrap();
    let before_acl = physical_acl_text(&inspector.directory);
    let before = inspector
        .files(InventoryLimits {
            max_entries: 9,
            max_total_bytes: limits.max_bytes,
        })
        .unwrap()
        .into_iter()
        .map(|entry| (entry.name, entry.bytes))
        .collect::<std::collections::BTreeMap<_, _>>();
    let health = Spool::inspect_directory(&inspector, limits).unwrap();
    assert_eq!(health, writer.doctor().unwrap());
    assert_eq!(health.identity_mismatch_entries, 1);
    assert_eq!(physical_acl_text(&inspector.directory), before_acl);
    let after = inspector
        .files(InventoryLimits {
            max_entries: 9,
            max_total_bytes: limits.max_bytes,
        })
        .unwrap()
        .into_iter()
        .map(|entry| (entry.name, entry.bytes))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(after, before);
    assert!(matches!(
        AdvisoryLock::acquire(
            &inspector,
            &EntryName::new("spool.instance.lock").unwrap().as_relative()
        ),
        Err(Error::AlreadyLocked(_))
    ));
}

#[test]
fn service_children_and_state_inherit_from_the_held_provisioned_anchor() {
    let (_temp, root, _name) = service_fixture();
    let first = root
        .create_child(&EntryName::new("queue").unwrap())
        .unwrap();
    let second = first
        .create_child(&EntryName::new("pending").unwrap())
        .unwrap();
    assert_native_inherited_acl(&first.directory, true);
    assert_native_inherited_acl(&second.directory, true);
    let name = EntryName::new("state.json").unwrap();
    super::super::AtomicFile::create(&second, &name, b"first").unwrap();
    super::super::AtomicFile::replace(&second, &name.as_relative(), b"second").unwrap();
    let held = second
        .open_private_file(&name, PrivateFileAccess::ReadOnly)
        .unwrap();
    assert_native_inherited_acl(held.file(), false);
    let staged = EntryName::new("staged.json").unwrap();
    let published = EntryName::new("published.json").unwrap();
    super::super::AtomicFile::create(&second, &staged, b"published").unwrap();
    publish(&second, &staged, &published).unwrap();
    assert!(!second.path.join(staged.as_path()).exists());
    assert_eq!(
        second.read_private_bounded(&published, 16).unwrap(),
        b"published"
    );
    let lock = advisory_lock(&second, &EntryName::new("runtime.lock").unwrap(), false).unwrap();
    assert_native_inherited_acl(&lock._file, false);
    let before = physical_acl_text(&second.directory);
    let reopened =
        PrivateDirectory::create_with_windows_access(second.path(), root.access.clone()).unwrap();
    assert_eq!(reopened.read_private_bounded(&name, 16).unwrap(), b"second");
    assert_eq!(physical_acl_text(&second.directory), before);
    assert_eq!(reopened.service_anchor, root.service_anchor);
    drop(reopened);
    drop(lock);
    drop(second);
    drop(first);
    drop(root);
    held.verify().unwrap();
}

#[test]
fn service_held_chain_refuses_foreign_parent_and_never_reselects_a_poisoned_anchor() {
    let (_temp, root, _name) = service_fixture();
    let child = root
        .create_child(&EntryName::new("queue").unwrap())
        .unwrap();
    let leaf = child
        .create_child(&EntryName::new("pending").unwrap())
        .unwrap();
    let name = EntryName::new("state.json").unwrap();
    super::super::AtomicFile::create(&leaf, &name, b"marker").unwrap();
    // A privileged test actor isolates an exact protected leaf so parent ACL
    // poisoning cannot alter these bytes or be detected merely at the leaf.
    let leaf_admin = fixture_administrator_directory(leaf.path());
    replace_fixture_acl(&leaf_admin, &service_directory_acl(SERVICE_FIXTURE_SID));
    let child_admin = fixture_administrator_directory(child.path());
    replace_fixture_acl(&child_admin, &service_directory_acl("S-1-5-80-9-8-7-6-5"));
    let before_parent = physical_acl_text(&child_admin);
    let before_leaf = physical_acl_text(&leaf_admin);
    for operation in [
        leaf.read_private_bounded(&name, 16).map(|_| ()),
        super::super::AtomicFile::replace(&leaf, &name.as_relative(), b"changed"),
        publish(&leaf, &name, &EntryName::new("published.json").unwrap()),
        leaf.create_child(&EntryName::new("new-child").unwrap())
            .map(|_| ()),
        advisory_lock(&leaf, &EntryName::new("new.lock").unwrap(), false).map(|_| ()),
    ] {
        assert!(matches!(operation, Err(Error::UnsafePermissions(_))));
    }
    assert_eq!(physical_acl_text(&child_admin), before_parent);
    assert_eq!(physical_acl_text(&leaf_admin), before_leaf);
    assert_eq!(
        std::fs::read(leaf.path.join(name.as_path())).unwrap(),
        b"marker"
    );
    assert_eq!(std::fs::read_dir(leaf.path()).unwrap().count(), 1);

    replace_fixture_acl(&child_admin, &service_directory_acl(SERVICE_FIXTURE_SID));
    let root_admin = fixture_administrator_directory(root.path());
    // The file/directory owners remain accepted. Losing the original root's
    // trusted provisioning owner must not cause a held guard to choose leaf.
    replace_fixture_owner(
        &root_admin,
        &process_user_sid().unwrap(),
        &root.access,
        root.path(),
    );
    let before_root = physical_acl_text(&root_admin);
    assert!(matches!(
        verify_directory(&leaf),
        Err(Error::UnsafePermissions(_))
    ));
    assert_eq!(physical_acl_text(&root_admin), before_root);
    assert_eq!(
        std::fs::read(leaf.path.join(name.as_path())).unwrap(),
        b"marker"
    );
}

#[test]
fn service_exact_dacl_on_an_account_owned_ambient_root_is_not_a_trusted_anchor() {
    let (_temp, root, name) = service_fixture();
    let administrator = fixture_administrator_directory(root.path());
    replace_fixture_owner(
        &administrator,
        &process_user_sid().unwrap(),
        &root.access,
        root.path(),
    );
    let before = physical_acl_text(&administrator);
    for operation in [
        PrivateDirectory::open_with_windows_access(root.path(), root.access.clone()).map(|_| ()),
        PrivateDirectory::create_with_windows_access(root.path(), root.access.clone()).map(|_| ()),
        root.create_child(&EntryName::new("child").unwrap())
            .map(|_| ()),
        super::super::AtomicFile::replace(&root, &name.as_relative(), b"changed"),
    ] {
        assert!(matches!(operation, Err(Error::UnsafePermissions(_))));
    }
    assert_eq!(physical_acl_text(&administrator), before);
    assert_eq!(
        std::fs::read(root.path.join(name.as_path())).unwrap(),
        b"private-marker"
    );
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn service_root_creation_checks_the_effective_default_owner_before_creating() {
    let (temp, root, _name) = service_fixture();
    let process = process_token().unwrap();
    let owner = process_user_sid().unwrap();
    let owner_text = wide(OsStr::new(&owner)).unwrap();
    let mut owner_sid = std::ptr::null_mut();
    // SAFETY: canonical actual account SID and writable SDK allocation output.
    assert_ne!(
        unsafe { ConvertStringSidToSidW(owner_text.as_ptr(), &mut owner_sid) },
        0
    );
    let _owner_sid = Allocation(owner_sid);
    let mut raw = std::ptr::null_mut();
    // SAFETY: duplicate the real token for this test thread only. Existing
    // identity/groups remain real; only the new object's default owner changes.
    assert_ne!(
        unsafe {
            DuplicateTokenEx(
                process.as_raw_handle(),
                TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_ADJUST_DEFAULT,
                std::ptr::null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut raw,
            )
        },
        0
    );
    // SAFETY: successful duplication transfers a unique owned token handle.
    let token = unsafe { File::from_raw_handle(raw) };
    let default_owner = TOKEN_OWNER { Owner: owner_sid };
    // SAFETY: actual TokenUser is an assignable owner within this token; fixed
    // TOKEN_OWNER and its SDK SID allocation remain live through the call.
    assert_ne!(
        unsafe {
            SetTokenInformation(
                token.as_raw_handle(),
                TokenOwner,
                (&default_owner as *const TOKEN_OWNER).cast(),
                std::mem::size_of::<TOKEN_OWNER>() as u32,
            )
        },
        0
    );
    // SAFETY: impersonate the real duplicate on this test thread; the guard
    // always restores it before the owned token and SID storage are released.
    assert_ne!(unsafe { ImpersonateLoggedOnUser(token.as_raw_handle()) }, 0);
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            // SAFETY: paired with successful thread impersonation above.
            assert_ne!(unsafe { RevertToSelf() }, 0);
        }
    }
    let revert = Revert;
    assert_eq!(creation_owner_sid().unwrap(), owner);
    let missing = temp.path().join("unprovisioned-root");
    assert!(matches!(
        PrivateDirectory::create_with_windows_access(&missing, root.access.clone()),
        Err(Error::UnsafePermissions(_))
    ));
    assert!(!missing.exists());
    // Existing protected roots use their physical owner and never require the
    // caller's default owner to match. This token retains its real admin group.
    PrivateDirectory::create_with_windows_access(root.path(), root.access.clone()).unwrap();
    drop(revert);
    // A trusted default owner on that same real token permits protected root
    // initialization. This mutates only the duplicate, never the process token.
    let admins = native_descriptor("O:BA");
    let mut admin_sid = std::ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: the SDK descriptor stays live through changing the duplicate's
    // default owner; BA is an assignable owner group on this real admin token.
    unsafe {
        assert_ne!(
            GetSecurityDescriptorOwner(admins.0, &mut admin_sid, &mut defaulted),
            0
        );
        let default_owner = TOKEN_OWNER { Owner: admin_sid };
        assert_ne!(
            SetTokenInformation(
                token.as_raw_handle(),
                TokenOwner,
                (&default_owner as *const TOKEN_OWNER).cast(),
                std::mem::size_of::<TOKEN_OWNER>() as u32
            ),
            0
        );
    }
    // SAFETY: reselect the actual duplicate after its default owner changed;
    // do not assume a previously selected thread token observes that mutation.
    assert_ne!(unsafe { ImpersonateLoggedOnUser(token.as_raw_handle()) }, 0);
    let revert = Revert;
    assert_eq!(creation_owner_sid().unwrap(), "S-1-5-32-544");
    let created =
        PrivateDirectory::create_with_windows_access(&missing, root.access.clone()).unwrap();
    let actual = physical_acl_text(&created.directory);
    assert!(actual.starts_with("O:BA"), "physical root owner: {actual}");
    assert!(actual.contains("D:P"), "physical root protection: {actual}");
    drop(revert);
}

fn native_descriptor(sddl: &str) -> Allocation {
    let text = wide(OsStr::new(sddl)).unwrap();
    let mut raw = std::ptr::null_mut();
    // SAFETY: controlled, terminated fixture SDDL and writable output.
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut raw,
                std::ptr::null_mut(),
            )
        },
        0
    );
    Allocation(raw)
}

fn replace_fixture_acl(file: &File, sddl: &str) {
    let descriptor = native_descriptor(sddl);
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = std::ptr::null_mut();
    // SAFETY: the owned SDK descriptor remains live through the ACL update.
    assert_ne!(
        unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) },
        0
    );
    assert_ne!(present, 0);
    // SAFETY: the administrator fixture handle has WRITE_DAC; only this
    // test's DACL is changed, with the descriptor held through completion.
    assert_eq!(
        unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        },
        ERROR_SUCCESS
    );
}

fn physical_descriptor(file: &File) -> Allocation {
    let mut raw = std::ptr::null_mut();
    // SAFETY: held READ_CONTROL handle; SDK returns one LocalFree-owned SD.
    assert_eq!(
        unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut raw,
            )
        },
        ERROR_SUCCESS
    );
    Allocation(raw)
}

fn physical_acl_text(file: &File) -> String {
    let descriptor = physical_descriptor(file);
    let mut text = std::ptr::null_mut();
    let mut length = 0;
    // SAFETY: the live SDK SD includes owner/group/DACL; output is SDK owned.
    assert_ne!(
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.0,
                1,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut text,
                &mut length,
            )
        },
        0
    );
    let _allocation = Allocation(text.cast());
    assert!(!text.is_null() && (1..=64 * 1024).contains(&length));
    // SAFETY: successful SDK output has the bounded reported storage and NUL.
    // Alias formatting can leave spare NULs in that storage; stop at the first.
    let units = unsafe { std::slice::from_raw_parts(text, length as usize) };
    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .expect("terminated native SDDL");
    String::from_utf16(&units[..end]).unwrap()
}

#[test]
fn service_effective_acl_rejects_missing_roles_masks_and_inheritance_without_repair() {
    let (_temp, directory, name) = service_fixture();
    let path = directory.path.join(name.as_path());
    let administrator = OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC)
        // This fixture controls ACLs, not namespace pinning. Allow delete
        // opens so public remove reaches its real ACL check after guard close.
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(&path)
        .unwrap();
    let fixed = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";
    let service = format!("(A;;0x1301bf;;;{SERVICE_FIXTURE_SID})");
    let complete = format!("{fixed}{service}(A;;RC;;;OW)");
    for rejected in [
        format!("{fixed}{service}"), // Missing OWNER RIGHTS restores implicit WRITE_DAC.
        format!("{fixed}(A;;0x1201bf;;;{SERVICE_FIXTURE_SID})(A;;RC;;;OW)"),
        format!("{fixed}{service}{service}"),
        format!("D:P(A;;FA;;;BA){service}(A;;RC;;;OW)"),
        format!("{fixed}{service}(A;;RC;;;OW)(A;;RC;;;LS)"),
        format!("{fixed}(A;IO;0x1301bf;;;{SERVICE_FIXTURE_SID})(A;;RC;;;OW)"),
        format!("{fixed}{service}(A;;0x60000;;;OW)"),
    ] {
        // Reinitialize only the isolated fixture between variants, then hold
        // the valid file before installing the next controlled bad policy.
        replace_fixture_acl(&administrator, &complete);
        let held = directory
            .open_private_file(&name, PrivateFileAccess::ReadOnly)
            .unwrap();
        replace_fixture_acl(&administrator, &rejected);
        let before_acl = physical_acl_text(&administrator);
        let verified = held.verify();
        assert!(
            matches!(&verified, Err(Error::UnsafePermissions(_))),
            "held.verify: {verified:?}; requested={rejected}; physical={before_acl}"
        );
        // A production guard intentionally denies DELETE sharing. Closing it
        // isolates the ACL refusal from a prior sharing violation.
        drop(held);
        for (operation, result) in [
            (
                "open_private_file",
                directory
                    .open_private_file(&name, PrivateFileAccess::ReadOnly)
                    .map(|_| ()),
            ),
            (
                "read_private_bounded",
                directory.read_private_bounded(&name, 64).map(|_| ()),
            ),
            (
                "atomic_replace",
                super::super::AtomicFile::replace(&directory, &name.as_relative(), b"replacement"),
            ),
            (
                "advisory_lock",
                advisory_lock(&directory, &name, false).map(|_| ()),
            ),
            ("remove_file", directory.remove_file(&name)),
        ] {
            assert!(
                matches!(&result, Err(Error::UnsafePermissions(_))),
                "{operation}: {result:?}; requested={rejected}; physical={before_acl}"
            );
        }
        assert_eq!(physical_acl_text(&administrator), before_acl);
        assert_eq!(std::fs::read(&path).unwrap(), b"private-marker");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
    let parent = OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(directory.path())
        .unwrap();
    replace_fixture_acl(
        &parent,
        &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;{SERVICE_FIXTURE_SID})"),
    );
    let before_acl = physical_acl_text(&parent);
    assert!(matches!(
        directory.create_child(&EntryName::new("child").unwrap()),
        Err(Error::UnsafePermissions(_))
    ));
    assert!(!directory.path().join("child").exists());
    assert_eq!(physical_acl_text(&parent), before_acl);
}

#[test]
fn actual_owner_token_proves_missing_owner_rights_allows_dacl_rewrite() {
    let (_temp, directory, name) = service_fixture();
    let path = directory.path.join(name.as_path());
    let administrator = OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&path)
        .unwrap();
    let process = process_token().unwrap();
    let admins = native_descriptor("D:P(A;;FA;;;BA)");
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = std::ptr::null_mut();
    let mut ace = std::ptr::null_mut();
    // SAFETY: fixed SDK descriptor/ACL/ACE are held for the token creation.
    unsafe {
        assert_ne!(
            GetSecurityDescriptorDacl(admins.0, &mut present, &mut acl, &mut defaulted),
            0
        );
        assert_ne!(GetAce(acl, 0, &mut ace), 0);
    }
    // SAFETY: the SDK initialized a standard allow ACE containing the BA SID.
    let admins_sid = unsafe {
        std::ptr::addr_of!((*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart)
            .cast_mut()
            .cast()
    };
    let disabled = SID_AND_ATTRIBUTES {
        Sid: admins_sid,
        Attributes: 0,
    };
    let mut raw = std::ptr::null_mut();
    // SAFETY: remove administrator grants and privileges, retaining the real
    // owner. No extra restricting SID is added that could mask owner rights.
    assert_ne!(
        unsafe {
            CreateRestrictedToken(
                process.as_raw_handle(),
                DISABLE_MAX_PRIVILEGE,
                1,
                &disabled,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                &mut raw,
            )
        },
        0
    );
    // SAFETY: successful creation transfers one unique owned token handle.
    let token = unsafe { File::from_raw_handle(raw) };
    let service_text = wide(OsStr::new(SERVICE_FIXTURE_SID)).unwrap();
    let mut service_sid = std::ptr::null_mut();
    // SAFETY: fixed canonical fixture SID and writable LocalAlloc output.
    assert_ne!(
        unsafe { ConvertStringSidToSidW(service_text.as_ptr(), &mut service_sid) },
        0
    );
    let _service_sid = Allocation(service_sid);
    let owner = process_user_sid().unwrap();
    let proposed = native_descriptor(&format!("D:P(A;;FA;;;{owner})"));
    let mut proposed_acl = std::ptr::null_mut();
    // SAFETY: held SDK descriptor and writable ACL outputs.
    assert_ne!(
        unsafe {
            GetSecurityDescriptorDacl(proposed.0, &mut present, &mut proposed_acl, &mut defaulted)
        },
        0
    );
    let name = wide(path.as_os_str()).unwrap();
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };
    for owner_rights_present in [true, false] {
        if !owner_rights_present {
            replace_fixture_acl(
                &administrator,
                &format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;{SERVICE_FIXTURE_SID})"),
            );
        }
        let actual = physical_descriptor(&administrator);
        let mut actual_owner = std::ptr::null_mut();
        // SAFETY: SDK descriptor stays live while its actual owner is checked.
        assert_ne!(
            unsafe { GetSecurityDescriptorOwner(actual.0, &mut actual_owner, &mut defaulted) },
            0
        );
        // SAFETY: this actual owner SID belongs to the held SDK descriptor.
        assert_eq!(unsafe { sid_text(actual_owner) }.unwrap(), owner);
        let before = physical_acl_text(&administrator);
        // SAFETY: real derived token; guard always restores this test thread.
        assert_ne!(unsafe { ImpersonateLoggedOnUser(token.as_raw_handle()) }, 0);
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                // SAFETY: paired with successful impersonation on this thread.
                assert_ne!(unsafe { RevertToSelf() }, 0);
            }
        }
        let revert = Revert;
        let mut thread_raw = std::ptr::null_mut();
        // SAFETY: OpenAsSelf authorizes opening the actual thread token only.
        assert_ne!(
            unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread_raw) },
            0
        );
        // SAFETY: successful token open transfers one owned real handle.
        let effective = unsafe { File::from_raw_handle(thread_raw) };
        assert_eq!(token_user_sid(&effective).unwrap(), owner);
        for sid in [admins_sid, service_sid] {
            let mut enabled = 0;
            // SAFETY: actual query token and held SDK SID allocations.
            assert_ne!(
                unsafe { CheckTokenMembership(effective.as_raw_handle(), sid, &mut enabled) },
                0
            );
            assert_eq!(
                enabled, 0,
                "owner control must not gain an administrator or service grant"
            );
        }
        let mut privileges = [0u64; 512];
        let mut privilege_bytes = std::mem::size_of_val(&privileges) as u32;
        let mut granted = 0;
        let mut allowed = 0;
        // SAFETY: physical owner/group/DACL and real effective token are held;
        // exact specific right, native mapping and aligned outputs are valid.
        assert_ne!(
            unsafe {
                AccessCheck(
                    actual.0,
                    effective.as_raw_handle(),
                    WRITE_DAC,
                    &mapping,
                    privileges.as_mut_ptr().cast(),
                    &mut privilege_bytes,
                    &mut granted,
                    &mut allowed,
                )
            },
            0
        );
        assert_eq!(
            allowed != 0,
            !owner_rights_present,
            "physical isolated ACL: {before}; OWNER RIGHTS present={owner_rights_present}; granted={granted:#x}"
        );
        assert_eq!(
            granted,
            if owner_rights_present { 0 } else { WRITE_DAC },
            "physical isolated ACL: {before}; OWNER RIGHTS present={owner_rights_present}"
        );
        // SAFETY: controlled terminated physical path and held proposed DACL;
        // this is an actual OS ACL rewrite, not a validator implementation test.
        let result = unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                proposed_acl,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(
            result,
            if owner_rights_present {
                ERROR_ACCESS_DENIED
            } else {
                ERROR_SUCCESS
            },
            "physical isolated ACL: {before}; OWNER RIGHTS present={owner_rights_present}; granted={granted:#x}"
        );
        drop(effective);
        drop(revert);
        if owner_rights_present {
            assert_eq!(physical_acl_text(&administrator), before);
        } else {
            assert_ne!(physical_acl_text(&administrator), before);
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"private-marker");
    }
}

fn unsafe_acl(file: &File) {
    unsafe {
        let mut raw = std::ptr::null_mut();
        let sddl = wide(OsStr::new("D:P(A;;FA;;;WD)(A;;FA;;;BA)(A;;FA;;;SY)")).unwrap();
        assert_ne!(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut raw,
                std::ptr::null_mut()
            ),
            0
        );
        let _allocation = Allocation(raw);
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = std::ptr::null_mut();
        assert_ne!(
            GetSecurityDescriptorDacl(raw, &mut present, &mut acl, &mut defaulted),
            0
        );
        assert_eq!(
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut()
            ),
            0
        );
    }
}
#[test]
fn private_files_reject_public_acl_without_repair_and_reject_hard_links() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state");
    let directory = PrivateDirectory::create(&path).unwrap();
    let name = EntryName::new("credential.json").unwrap();
    super::super::AtomicFile::create(&directory, &name, b"private-marker").unwrap();
    let file = OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC | GENERIC_READ | GENERIC_WRITE)
        .open(path.join(name.as_path()))
        .unwrap();
    unsafe_acl(&file);
    drop(file);
    for operation in [
        directory.read_private_bounded(&name, 64).map(|_| ()),
        super::super::AtomicFile::replace(&directory, &name.as_relative(), b"replacement"),
        advisory_lock(&directory, &name, false).map(|_| ()),
        directory.remove_file(&name),
    ] {
        assert!(matches!(operation, Err(Error::UnsafePermissions(_))));
    }
    assert_eq!(
        std::fs::read(path.join(name.as_path())).unwrap(),
        b"private-marker"
    );
    let safe = EntryName::new("master.key").unwrap();
    super::super::AtomicFile::create(&directory, &safe, b"master-marker").unwrap();
    std::fs::hard_link(path.join(safe.as_path()), path.join("alias.key")).unwrap();
    assert!(matches!(
        directory.read_private_bounded(&safe, 64),
        Err(Error::MultipleLinks(_))
    ));
    assert!(matches!(
        super::super::AtomicFile::replace(&directory, &safe.as_relative(), b"replacement"),
        Err(Error::MultipleLinks(_))
    ));
}
#[test]
fn unsafe_existing_directory_is_not_repaired_and_held_names_cannot_move() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state");
    let root = PrivateDirectory::create(&path).unwrap();
    assert!(std::fs::rename(&path, temp.path().join("moved")).is_err());
    let handle = OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(&path)
        .unwrap();
    unsafe_acl(&handle);
    drop(handle);
    drop(root);
    assert!(matches!(
        PrivateDirectory::create(&path),
        Err(Error::UnsafePermissions(_))
    ));
    assert!(matches!(
        PrivateDirectory::open_existing(&path),
        Err(Error::UnsafePermissions(_))
    ));
}
#[test]
fn native_unprivileged_token_cannot_read_or_change_credentials_master_key_or_state() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state");
    let directory = PrivateDirectory::create(&path).unwrap();
    for name in ["credential.json", "master.key", "state.json"] {
        super::super::AtomicFile::create(
            &directory,
            &EntryName::new(name).unwrap(),
            b"private-marker",
        )
        .unwrap();
    }
    let paths: Vec<_> = ["credential.json", "master.key", "state.json"]
        .iter()
        .map(|n| path.join(n))
        .collect();
    std::thread::spawn(move || unsafe {
        let token = process_token().unwrap();
        let mut sid = std::ptr::null_mut();
        assert_ne!(
            ConvertStringSidToSidW(wide(OsStr::new("S-1-1-0")).unwrap().as_ptr(), &mut sid),
            0
        );
        let _allocation = Allocation(sid);
        let restriction = SID_AND_ATTRIBUTES {
            Sid: sid,
            Attributes: 0,
        };
        let mut restricted = std::ptr::null_mut();
        assert_ne!(
            CreateRestrictedToken(
                token.as_raw_handle(),
                DISABLE_MAX_PRIVILEGE,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                1,
                &restriction,
                &mut restricted
            ),
            0
        );
        let restricted = File::from_raw_handle(restricted);
        assert_ne!(ImpersonateLoggedOnUser(restricted.as_raw_handle()), 0);
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                unsafe {
                    assert_ne!(RevertToSelf(), 0);
                }
            }
        }
        let _revert = Revert;
        for path in paths {
            assert_eq!(
                File::open(&path).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::PermissionDenied
            );
        }
    })
    .join()
    .unwrap();
    for name in ["credential.json", "master.key", "state.json"] {
        assert_eq!(
            directory
                .read_private_bounded(&EntryName::new(name).unwrap(), 64)
                .unwrap(),
            b"private-marker"
        );
    }
}
