# Filesystem handles and publication boundaries

The current filesystem primitives are being hardened and adopted in P8. This document describes the implemented Unix/Linux boundary, not completion of the Windows/macOS or all-consumer acceptance gates.

## Unix private state

`PrivateDirectory::open_existing` walks the same no-follow descriptors and checks
the same owner and permissions without creating directories, changing modes or
syncing files. Read-only Agent diagnostics use this entry point.

`create_child` creates or validates a typed direct child relative to the held
parent descriptor on Unix. Host hands that capability to `Spool::from_directory`,
so replacing the original state pathname cannot redirect spool initialization.

`PrivateDirectory::create` requires an absolute path. It walks existing ancestors through no-follow directory descriptors and creates only the final directory with mode 0700. The final directory must be owned by the effective user with exact 0700 permissions. An existing directory is validated, never chmodded; rejection cannot change a symlink target's permissions. Parent and new-directory sync complete creation.

`AtomicFile::replace` and `AdvisoryLock::acquire` accept a validated, single-component relative name under the held private-directory descriptor. They do not resolve mutations through the original absolute pathname. A renamed or replaced external pathname therefore cannot redirect the operation. Atomic files and lock files are created as 0600; special files, symlinks, and hardlinked targets are rejected. The stable lock inode remains after release.

Atomic replacement writes and syncs the temporary file, renames within the held directory, checks the published inode, and syncs the directory. Failure after publication is not proof of rollback; parent-sync failure is explicitly `PublishedDurabilityUnknown`.

### Administrative access to service-owned state

`open_for_administration` and `create_for_administration` explicitly allow the
effective owner or Unix root to open service-owned 0700 state. Ordinary
`open_existing`/`create` remain effective-owner-only. None of these entry points
repairs existing ownership, permissions or symlinks, or creates missing ancestors.
The caller must select a trusted deployment state path; root access is not a
replacement for the product's deployment authorization checks.

Atomic publication, newly created locks and newly created private children inherit
the held parent's uid/gid before use. An administrator therefore cannot accidentally
publish a root-owned 0600 credential that the service account cannot read. A real
Linux test publishes as root, then runs a subprocess as uid/gid 65534 to lock, read
and rotate the credential. Non-root test runs cannot exercise that privilege case.

`AdvisoryLock::acquire_waiting` accepts an `EntryName` and serializes short synchronous
transactions. Existing lock files are never chowned or chmodded. Lock files must
be regular, single-linked, 0600, and owned by the held directory's uid/gid. Type,
link count, permissions and directory-entry identity are checked again after
waiting; release closes the handle without unlinking the persistent inode. Keep
network I/O outside the transaction. Nonblocking `acquire` retains its existing
already-locked error for process/spool ownership.

Host's Unix pairing transaction lock and private state publications now use these
APIs (token, identity, pairing journal, authorization state and active binding).
Host still owns filenames, contents and pairing compare-and-swap semantics.
Its `StateTransaction` owns one Foundation directory and its advisory lock:
identity, credential, journal, authorization and binding reads/writes all use
that same handle for the entire transaction. Internal state writers require the
transaction capability; a `StateReader` alone cannot write. No transaction is
held across network I/O. Read-only pairing status holds one reader across its
multi-file retry snapshot and never acquires a write lock. Unix configuration
read/write also uses the shared configuration boundary below. The Windows native
implementation remains outstanding; no historical reader or permission-repair
fallback was introduced.

### Private read budgets

`read_private_bounded(EntryName, max_bytes)` opens a regular single-linked file
under the held Unix directory, checks exact 0600 and the directory's uid/gid on
that file descriptor, then checks length before allocation and limits streaming
reads to the budget plus one sentinel byte. It never creates a directory, lock,
or file and never changes permissions. A symlink (including a dangling one),
hardlink, FIFO, public file, wrong owner/group, or oversized sparse file is an
error, not absent state. Tests also replace the external directory pathname and
confirm reads stay under the original held handle.

Host uses this boundary for collection identity, identity diagnostics, its token,
pairing journal, authorization state, and active endpoint binding. Product budgets
apply to the complete file, including whitespace; the same typed `StateFile`
defines each read/write budget. A rejected write creates no temporary or data
file and preserves existing bytes (opening a transaction can create the private
directory and persistent lock):

| Current Host state | Maximum bytes |
|---|---:|
| host-id | 128 |
| agent-token | 4096 |
| pairing-state.json | 65536 |
| auth-state.json | 16384 |
| active-binding.json | 16384 |

Token reads wrap the successfully read buffer in `SecretBytes` before UTF-8
validation and retain the token as `SecretString`. Host Reporter snapshots share
`Arc<SecretString>` for Host and OTLP credentials; formatting is redacted and the
last owner releases zeroizing storage. Creating/Pending/Activating pairing
journals also retain `Arc<SecretString>` values, so state snapshots share secret
ownership rather than cloning plaintext strings. Only the product's explicitly
opted-in private-journal serde adapter serializes these values; shared secrets
remain non-serializable by default. `SecretWriter` reserves the full byte budget
before accepting data and rejects overflow without reallocating populated
storage. Successful and partial output use zeroizing storage. Host serializes
directly into that bounded sink, so a failed serialization never publishes or
leaves an ordinary output String behind. Successfully read journal bytes are
wrapped before parsing; malformed JSON diagnostics never quote raw values.

This does not guarantee erasure of serde parser scratch, HTTP-library copies,
kernel buffers or persistent plaintext. Host configuration OTLP tokens and TLS
identity passwords now also use `Arc<SecretString>` with explicit product serde
fields. Successful configuration reads enter `SecretBytes` before parsing;
serialization writes directly into a 64 KiB `SecretWriter`, including the final
newline, before publishing. Config/Reporter clones share the same token storage.
Malformed configuration diagnostics retain line/column but no raw values/keys.
Environment copies are wrapped on entry, not erased from the process environment.
Host TLS identity/CA inputs now use the protected input reader below on Unix;
these guarantees do not cover every parser/library scratch buffer or failed-read
partial buffer. Host now adopts the [credential transaction interface](credential-transactions.md)
for snapshots, rotation and invalidation. The polling
Authorization header explicitly exposes its value for transport and is marked
sensitive, preventing ordinary HeaderValue Debug output from printing it.

Windows Host state reads are now byte-bounded, but still await the native
handle/reparse-point/ACL backend; Unix tests do not prove Windows safety.

Host's directory-rebinding regression replaces the external state pathname
between writing the Activating journal and publishing its files. The real
activation commit, active binding validation, identity load and Reporter
credential snapshot all stay in the locked original directory; all five
replacement-directory sentinel files remain untouched. The product path-based
`persist_private_value` helper and Unix per-file directory reopen implementation
were deleted. Windows-specific helpers remain pending, not as historical
compatibility paths.

## Protected TLS inputs

`ConfigurationDirectory::read_input_bounded` uses the held directory descriptor
and a typed `EntryName`, rejecting symlinks (including ancestors), hardlinks,
special files, group/other writes and special mode bits. The file owner must be
root, the effective user or the protected directory's owner. The existing
configuration write/read modes are unchanged; read-only TLS inputs have a
separate closed visibility policy:

| Input visibility | Accepted Unix modes |
|---|---|
| Confidential | 0400, 0440, 0600, 0640 |
| Public | 0400, 0440, 0444, 0600, 0640, 0644 |

Host identities are Confidential; CA certificates are Public. Both share
`sarmg-agent-secure-http::MAX_TLS_INPUT_BYTES` (1 MiB). Empty inputs fail and
successful read buffers enter `SecretBytes` before parsing. CA parsing must
produce at least one certificate: reqwest's rustls `from_pem` path can otherwise
silently accept text with no certificates. Host now parses a nonempty bundle and
adds each certificate. Parse errors do not echo input/password contents.

Tests cover mode/owner rejection without repair, exact/overflow budgets, links,
FIFO, held-directory rebinding and actual root-to-service group reads. Host Linux
tests generate ephemeral PEM material with OpenSSL and construct a real client;
no test private key is committed. This is construction evidence, not a TLS or
mTLS handshake test. Windows has only bounded reads until native handles/ACLs
are adopted; macOS/Windows PKCS#12 execution remains unverified.

### Service-readable Unix configuration

`ConfigurationDirectory` is distinct from `PrivateDirectory`: its existing
directory may be 0700, 0750 or 0755, with root/current-user ownership (root may
explicitly administer a service-owned directory). All ancestors are walked
without following links. It does not create missing parents or repair modes.
This permits an unprivileged service to read root-owned configuration through
its service group without weakening the 0700 private-state contract.

Typed `EntryName` configuration reads require a regular, single-linked 0600 or
0640 file and are bounded before allocation and during reading. Replacement
preserves that opened file's uid/gid/mode, holds its descriptor through
publication, and rechecks its identity and metadata before publishing. Missing
files are created 0600 with the held directory's uid/gid and no-clobber
publication. The same internal atomic engine owns temporary creation, flushing,
rename/no-clobber and parent sync for private state and configuration; no second
path-based publication implementation was added. Cooperating callers must still
serialize configuration updates; this is not protection against a malicious
same-UID process modifying the namespace.

Host uses this interface for both config loading and saving, with a 65536-byte
limit including the saved newline. Status reports rejected configuration without
altering it. Tests cover changed occupants/metadata, unsafe file/directory modes,
symlinks, hardlinks, FIFOs, directory rebinding, complete replacement and limits.
The privileged Linux subprocess test also verifies that root:service-group 0640
configuration remains readable through this API as uid/gid 65534 after a root
replacement. Host's local Unix `fchown`, rename and directory-sync helpers were
removed; product code retains JSON serialization and business path selection.

`EntryName` represents exactly one canonical filename. `PrivateDirectory::files`, `read_bounded` and `remove_file` use these typed names and the held descriptor on Unix, not reconstructed absolute paths. `AtomicFile::create` provides no-clobber creation; failed collision preserves the occupant. Platform temporaries have one exact random namespace, exposed through `AtomicFile::is_temporary_name` for cleanup under exclusive process ownership. The Agent spool consumes these APIs for all of its file operations.

`NoClobberPublish::publish` accepts a private directory and two typed single-component names, not arbitrary source/destination strings. It only publishes a single-linked regular file within that directory. Linux uses `RENAME_NOREPLACE`, with no fallback on unsupported filesystems. The Unix implementation for other operating systems uses link, parent sync, unlink, parent sync. Publication or sync failures must not be interpreted as permission to blindly replay a mutation.

Inventory opens directories descriptor-relatively and refuses symlinks, special files and multiply-linked files. It checks pre/post-open identity and enforces entry, byte and 128-directory-depth budgets; depth-first traversal bounds simultaneous directory handles independent of directory width. File/parent synchronization on Unix also opens through no-follow descriptors and refuses non-regular or multiply-linked files.

These private-state primitives require exclusive application ownership of the directory. They do not claim to defend against a malicious process running as the same user and concurrently modifying the private namespace. Advisory locks only coordinate cooperating participants.

## Linux rooted filesystems

`OpenAt2Root` verifies the initial directory and probes openat2 before serving work. `MountPolicy` makes cross-mount access an explicit technical capability. There is no openat fallback when the required Linux primitive is unavailable.

`open_file` only returns single-linked regular files and refuses symlinks in all components; NONBLOCK prevents FIFO type probes from hanging. `FileIdentity` and `SingleLinkRequirement` describe opened objects. The Linux directory `AdvisoryLock` holds the anchored root itself instead of a replaceable separate lock pathname.

Products may retain business-specific symlink, upload metadata, tree mutation and crash-recovery semantics while their generic helpers are progressively replaced. Server filesystem consumers are outside this repository. Agent consumers must not use the diagnostic `PrivateDirectory::path`/`resolve` values as a substitute for held-handle mutations.

## Remaining acceptance

Windows handle/reparse-point semantics and native macOS acceptance remain unverified. Product-side raw-path staging/Spool operations, cross-directory publication, bounded inventories at every consumer, and Upgrade adoption still require implementation and acceptance. Passing the Linux library tests is not P8 completion.
