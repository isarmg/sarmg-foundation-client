# Current Client spool

Foundation owns the opaque spool container, atomic publication, ordering, capacity,
locking, acknowledgement, corruption isolation and delivery cancellation. Products
own only payload codecs, collection timing and their transport protocol.

## Current storage contract

There is exactly one reader. Each record contains the `SARMGSPOOL` magic and current
format marker, 16-byte record ID, priority, creation time, bounded contract ID,
32-bit payload length, opaque payload bytes and a SHA-256 checksum. No product DTO
or JSON byte array is serialized by the spool. The checksum detects corruption;
it is not a MAC and does not defend against a malicious writer with the same OS
identity. Container identity, priority and timestamp must exactly match the
canonical filename. Unknown formats and invalid bodies are not converted.

The lower numeric priority is read first, then creation time and record ID provide
a stable order. Negative creation times and noncanonical identifiers are rejected.
An acknowledgement removes only the selected current record and syncs its parent.
Duplicate acknowledgement returns `RecordNotFound`; a product may explicitly treat
an already-acknowledged report as complete.

The process-exclusive spool lock is acquired before cleanup. A process-local mutex
serializes the complete capacity-check/publication and read/ack/quarantine
sequences. Only the exact current `.sarmg-atomic-<32 lowercase hex>.tmp` namespace
can be cleaned after acquiring the lock; arbitrary `.tmp` files are preserved and
cause failure. Quarantine uses no-clobber publication and retains the original
container bytes without replacing existing evidence. The finite
`QuarantineReason` selects `.bad` for corruption/invalid payload and `.identity`
for a local delivery identity mismatch. Both are current quarantine categories,
not alternate readers or historical container formats. Neither rewrites the
container or exposes a quarantined ID to ordinary ACK.

## Limits and I/O

`desktop-client` declares hard ceilings of 1 MiB payload, 256 MiB spool and 4096
records. Components declaring `bounded-spool` must declare all three limits;
conformance rejects omissions, unknown keys, booleans, nonintegers, zero and values
above the Profile. Rust runtime validation uses the same ceilings, with a test
binding them to the checked Profile.

`max_bytes` counts physical container bytes, including metadata and quarantines,
not just payload bytes. Quarantines also consume the entry budget. The stable
zero-length lock file does not consume a record slot. All records are read through
a bounded reader before decoding; oversized but structurally named records are
quarantined, not loaded unboundedly. Directory scans are bounded and errors are
propagated, never discarded by `filter_map(Result::ok)`.

On Unix, enumeration, reads, publication and removal are relative to a held private
directory descriptor. Renaming or replacing the original path cannot redirect
those operations. Symlink, hardlink and special-file entries fail closed without
being read or removed. The directory is exclusive application state, not an
untrusted shared namespace. Windows/macOS native safety and execution acceptance
remain pending; a cross-compilation check alone does not prove those semantics.

`Spool::inspect_existing` uses the same bounded current-namespace inventory for
read-only status and doctor commands. It never creates a directory or lock file,
acquires the writer's lock, removes a temporary, or quarantines a record. Known
quarantines make the inventory unhealthy; `identity_mismatch_entries` reports
the identity subset of `quarantined_entries`. Unknown names, nonempty lock files and
unsafe entries fail closed. A writer's active temporary or concurrent removal can
cause a transient inspection error; the result is not a transactional snapshot.
This inventory does not verify payload checksums and must not be presented as a
full data-integrity check. Host status and read-only doctor consume this API.

## Delivery and shutdown

`DeliveryWorker<ClientDeliveryDriver>` owns the delivery/recovery loop, coalescing
capacity-one notifications, deadlines, retry state, authorization pause, local
queue failure tracking and shutdown. It does not know any product DTO, API route,
pairing phase or credential file format. Host now uses this worker; its driver
only interprets pairing progress, installs Reporter snapshots and classifies
validated protocol failures.

Recovery and delivery futures are owned directly, not detached tasks. Sampling
wake edges and recovery timer events never discard an in-flight request. Only an
explicitly renewed credential snapshot cancels the superseded request and
restarts delivery; a stable report ID makes an unknown remote outcome retryable.
An authorization failure preserves queued reports and pauses delivery until
renewal. Ordinary wakes cannot bypass authorization or active backoff. Shutdown,
a lost shutdown controller or closed sampling notifications cancel both owned
futures. Host's optional OTLP worker is aborted by its driver's Drop.

`deliver_batch` is shared by the daemon and the explicit one-shot path. It handles
at most 32 records, including permanently rejected and isolated records, then yields the batch
boundary to its caller. Protocol adapters distinguish a definitive content
rejection from transient failure and credential rejection. Only definitive
content rejection authorizes discarding that record; a transient/authorization
error retains it. The adapter returns the finite `FailureDisposition`, with
Retain, Discard or Quarantine(reason); the old boolean-only disposition is removed.
A typed local identity mismatch must be isolated, not discarded. The queue's
required `quarantine` operation must preserve original bytes, and its failure
stops the batch without a callback, fallback ACK or next send. The isolation
callback runs only after durable mutation and is never the success/OTLP callback.
Success is durably acknowledged before a bounded secondary
output callback such as OTLP. A failed ack never invokes a secondary output or a
discard callback. There is no await between a completed send, ack and callback.

`RetryBackoff` owns consecutive retry state, doubling, jitter and reset. It rejects
zero base, maximum below base, maximum above 300 seconds and jitter above 50%.
The final randomized delay cannot exceed the chosen maximum. Products may use a
stricter maximum, such as 60 seconds for interactive pairing; they do not own
another doubling loop. Sampling retains its separate business cadence and uses
`sampling_jitter`.

`QueueFailureStreak` owns the fixed 100-consecutive-local-failure threshold.
Read, write and delivery operations have separate trackers; successes do not mask
failures of a different operation. Network errors are not local disk failures.
The desktop Profile records the batch, retry, jitter and failure bounds, and
Rust tests bind the runtime constants to that Profile.

Conformance rejects product-defined delivery workers, retry state, failure
trackers, batch outcome enums, container/lock namespaces and named jitter/backoff
implementations. Product pairing wire, report codecs, optional output adapters
and business sampling remain product-owned.

## Verification and remaining work

Worker tests cover retry deadlines, repeated wake edges, recovery events during
an in-flight send, authorization pause/renewal, snapshot cancellation, shutdown,
closed controllers, invalid polling delays and persistent/reset local failures.
Batch tests cover ack-before-export, failed ack, permanent rejection, the batch
budget and cancellation retaining the head. Host has a real loopback HTTP test
that withholds the response while issuing ten sampling notifications and then
requires the durable queue to drain through the shared worker.

Host now uses shared Unix configuration/state handles and the
[credential transaction interface](credential-transactions.md). Remaining identity,
complete TLS/HTTP integration and native-platform verification work is still outstanding.
These tests are not a declaration that P8/P11 or immutable publication is complete.

## Delivery session lifetime

`ClientSession` owns an anchored private state directory and `SingleInstanceLock`
on `client.instance.lock`. Acquire it before delivery bootstrap or collection and
retain it until shutdown. It neither loads credentials nor contacts a Server.
Pairing uses its own short transaction lock; read-only diagnostics do not take
the delivery session lock. Existing unsafe directory/lock metadata is rejected,
not repaired. The lock inode remains after close and must not be deleted to
force a second running instance.

Host Run, Once and Doctor-with-delivery now acquire the session before identity
loading and sampler initialization. Its Spool borrows the session's held
directory when creating the child queue and retains an `Arc<ClientSession>`;
clones keep the delivery exclusion alive. Standalone Host Spool opening acquires the
same session, and invalid Spool limits are rejected before creating state.
Status, read-only Doctor, Probe and Pair do not acquire this delivery lock.

The Spool's own lock still protects the queue namespace, including standalone
Foundation Spool callers. It has a different scope from the state-root delivery
session; neither is an old-version compatibility path. Tests cover real process
contention/release, unsafe lock rejection, clone lifetime, pairing concurrency,
held-directory rebinding and the actual Host command boundary. These are Linux
tests, not Windows/macOS native filesystem validation.
