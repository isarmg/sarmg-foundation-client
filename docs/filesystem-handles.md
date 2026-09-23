# Filesystem handles and publication boundaries

`sarmg-client-fs-safety` supplies generic file, directory, publication and locking
mechanisms. Products own filenames, payload formats, budgets and recovery policy.
Unix operations use held directory descriptors. Non-Unix implementations use
portable path operations and do not provide equivalent Windows handle,
reparse-point or ACL guarantees.

## Private state and administration

`PrivateDirectory::create` requires an absolute path, walks existing ancestors
without following symlinks, and creates only the final directory as 0700. The
final directory must belong to the effective user with exact 0700 permissions.
Existing metadata is validated without repair. Parent and new-directory sync
complete creation.

`open_existing` checks the same owner and permissions without creating or syncing
state. `open_for_administration` and `create_for_administration` also allow Unix
root to access service-owned 0700 state. The product must select a trusted state
path and authorize the operation. No entry point creates missing ancestors.

`EntryName` represents one canonical filename. `create_child`, `files`,
`read_bounded`, `read_private_bounded` and `remove_file` operate relative to the
held Unix descriptor. Replacing the external pathname cannot redirect them.
`path` and `resolve` provide diagnostic paths, not capabilities for mutations.

`read_private_bounded` requires a regular, single-linked 0600 file with the held
directory's uid/gid. It checks length before allocation and caps streaming reads
at the budget plus one sentinel byte. Links, special files, unsafe metadata and
oversized files are errors. Reads do not create files or acquire writer locks.

## Atomic publication and locking

`AtomicFile::replace` writes and syncs a private temporary, publishes it within
the held directory, checks the published inode and syncs the parent.
`AtomicFile::create` uses no-clobber publication. A collision preserves the
occupant. Newly created files, locks and private children inherit the parent's
uid/gid. Private files and locks use mode 0600.

A failure after publication does not prove rollback. In particular,
`PublishedDurabilityUnknown` reports a publication whose parent sync failed.
Callers apply their recovery policy before retrying. Temporary names use the
exact namespace recognized by `AtomicFile::is_temporary_name`; cleanup requires
exclusive application ownership.

`NoClobberPublish::publish` accepts a private directory and two typed names.
It requires a regular, single-linked source. Linux uses `RENAME_NOREPLACE` and
fails when the filesystem does not support it. Other Unix targets use link,
parent sync, unlink and parent sync. A failure can retain both source and
published evidence.

`AdvisoryLock::acquire` is nonblocking; `acquire_waiting` serializes short
synchronous transactions. Existing lock files must be regular, single-linked,
0600 and owned by the directory's uid/gid. Waiting acquisition rechecks metadata
and directory-entry identity before returning. Release closes the handle and
retains the stable lock inode. Keep network I/O outside the lock lifetime.

These APIs require an application-owned namespace. Advisory locks coordinate
cooperating processes; they do not protect against a malicious process running
as the same OS user.

## Configuration and protected inputs

`ConfigurationDirectory` accepts existing Unix directories with mode 0700, 0750
or 0755, owned by root or the effective user. Root may administer a service-owned
directory. All ancestors are opened without following links. This API does not
create parents or repair permissions.

Configuration reads require a regular, single-linked 0600 or 0640 file and enforce
the supplied byte limit before allocation and while reading. Replacement holds
the opened file through publication, preserves uid/gid/mode, and rechecks its
identity and metadata. Missing files are created with mode 0600 and the directory's
uid/gid using no-clobber publication. Callers serialize configuration updates.

`read_input_bounded` accepts an explicit `InputVisibility`. It rejects links,
special files, group/other writes and special mode bits. The owner must be root,
the effective user or the protected directory's owner.

| Visibility | Accepted Unix file modes |
|---|---|
| `Confidential` | 0400, 0440, 0600, 0640 |
| `Public` | 0400, 0440, 0444, 0600, 0640, 0644 |

Products select visibility and size limits, validate certificate or key contents,
and handle secret storage. `SecretBytes`, `SecretString` and `SecretWriter` provide
zeroizing owned buffers, redacted formatting and bounded serialization.
`SecretWriter` reserves its byte budget before accepting data and rejects overflow
without reallocating populated storage. These types do not erase external parser,
HTTP-library, kernel or persistent copies. Product serializers explicitly opt in
to exposing secret values.

## Inventory and Linux rooted filesystems

Inventory uses descriptor-relative Unix traversal, validates pre/post-open
identity and rejects symlinks, special files and multiply-linked files. Entry,
byte and 128-directory-depth budgets bound traversal. Depth-first traversal
bounds simultaneous directory handles independently of directory width.
File/parent sync also rejects unsafe file types and multiple links.

Linux `OpenAt2Root` validates its initial directory and probes `openat2`.
`MountPolicy` explicitly controls cross-mount access. `open_file` accepts only
single-linked regular files and rejects symlinks in all components; nonblocking
opens prevent FIFO probes from hanging. `FileIdentity` and
`SingleLinkRequirement` describe opened objects. The Linux directory
`AdvisoryLock` locks the held root descriptor. Missing required kernel primitives
produce an error.

## Verification

Foundation tests cover unsafe metadata, budget overflow, links, special files,
publication collisions, lock contention and directory rebinding. Privileged Linux
tests also verify root-created state/configuration remains accessible to its
service uid/gid. Non-root runs cannot exercise that privilege case.

Native macOS execution, Windows filesystem guarantees and each product's staging,
publication and recovery paths require platform-specific acceptance evidence.
Passing Foundation Linux tests establishes only their exercised boundaries.
