# Credential transactions

`sarmg-client-runtime` owns `CredentialStore`, `CredentialSnapshot`,
`CredentialAuthorization` and `CredentialMutation`. Products implement the
storage adapter and own their revision identities, prepared rotation journals,
pairing wire, identity/endpoint binding and crash recovery. No Host pairing wire
contract has been promoted into Foundation.

The interface is synchronous and operates within an already-held, short exclusive
storage transaction. It never holds a lock across network I/O. Load returns an
authorized secret snapshot with its durable revision. Snapshot clones share
`Arc<SecretString>`, never separate plaintext strings. Invalidated/missing
credentials are unavailable; unsafe storage, malformed authorization and
inconsistent identity/binding are errors, not repair opportunities.

Replace revalidates the prepared journal under the same lock before publishing.
Invalidate compares the expected in-flight revision with the currently bound
credential and returns Applied or Superseded. Superseded means no writes. Only
`authorized` and `reauth_required` are accepted durable authorization spellings.

## Host adoption

Host's adapter borrows its `StateTransaction`; it cannot reopen a directory or
take a second lock. Loading a Reporter, committing/recovering Activating, and
processing unauthorized delivery now use this interface. Host removed the
unconditional authorize/invalidate production functions. The previous unused
asynchronous interface was replaced, not retained as a compatibility API.

The Reporter carries the credential's `(generation, request_id)`. The durable
active binding identifies the still-active credential while another pairing is
Creating/Pending/Denied/Expired. A delayed rejection from credential A cannot
invalidate credential B simply because a third pairing is Pending. An Activating
journal owns its files until Active is committed last; invalidation does not
touch an incomplete rotation. Replace reloads and commits the durable journal,
rejects a superseded one and validates identity before replacing token bytes.

Host tests cover real transaction load/rotation/invalidation, repeated
invalidation, snapshot revision retention while Pending, old rejection across
two rotations, superseded journal no-write, incomplete rotation, corrupt binding,
unknown authorization and nil-identity rejection before writes. Existing
multi-file recovery and directory-rebinding regressions remain in place.

Host also bundles Reporter, Host identity and report endpoint in one product
`ReporterSnapshot` captured under the same transaction lock. Startup during an
incomplete replacement applies this complete bundle. Failed construction cannot
partly update the caller's config or Host identity. A captured bundle keeps its
own identity/endpoint even if another process rotates credentials afterward.

Delivery recovery checks for a locally committed credential before waiting for
the next pairing's network endpoint. If the process missed B's Active state and
C is now Pending, it loads B immediately and continues C's polling schedule.
After a network probe it also checks the durable binding, rather than using the
probe's Active generation as authority. The Reporter is the sole in-memory
credential revision source; the separate optional active-pairing marker is gone.
Installing a renewed bundle updates the sampler's identity watch and replaces
the optional OTLP worker, aborting the worker that retained the old Reporter.

Real loopback recovery tests poll C and send/ack a report to B, verifying the
wire authorization header and Host ID, durable queue removal, no rollback from
an old Active probe, and old OTLP worker termination. Startup and partial-failure
regressions cover the same bundle boundary. These are not real Collector tests.

This is Linux execution evidence. Windows/macOS native filesystem guarantees,
remaining native TLS/HTTP integration, full Client identity adoption and
other P11 acceptance requirements are not completed by these tests.
