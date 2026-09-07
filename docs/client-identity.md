# Client identity and credential ownership

`sarmg-client-runtime::ClientIdentity` is the immutable runtime identity of an
Client delivery context: product ID, instance ID and current payload contract.
All three participate in equality. Construction checks nonempty ASCII
alphanumeric/dot/dash/underscore identifiers, with 128 bytes for product and
256 for instance; `ContractId` supplies the existing 128-byte contract policy.
Fields are private, with read-only accessors. No unchecked constructor,
normalizing parser, raw-field mutation or old struct-construction API remains.
`ensure_matches` rejects any differing dimension without echoing identifiers.

An authorized `CredentialSnapshot` must carry the identity together with its
revision and shared secret, captured under the same short storage transaction.
Cloning a snapshot preserves these values; a sender must not reread a mutable
identity file to relabel an already captured credential. Rotation constructs a
complete new snapshot and replaces it atomically at the consumer boundary.

Foundation does not choose business UUIDs, create a product identity file or
define Host Report fields. Products adapt their wire constraints and protected
storage to this type. Runtime identity is not authentication by itself; it does
not replace TLS, remote authorization or credential revision fencing.

## Host adoption

Host's `client_identity` adapter keeps the canonical lowercase hyphenated UUID
wire constraint, current report contract and fixed product ID. Its state reader
uses the held private directory and 128-byte `host-id` budget. Trailing newline
in current text state is allowed; it never creates, generates, locks or repairs
an identity during a read. Invalid contents and unsafe/unreadable state have
distinct typed failures; parse errors do not echo file contents. Collection,
credential loading and read-only status/doctor use the same adapter.

`HostIdentity` remains the product telemetry DTO (OS, architecture and version);
it is not a second implementation of Foundation runtime identity. The Spool's
opaque bytes and Host wire format do not change as a consequence of this type.

Reporter stores the identity in the credential snapshot, checks product and
contract at construction, and verifies the report's identity before sending
Report or configured OTLP requests. A different *valid* identity is not remote
authorization failure or permanent content rejection: no network request,
credential invalidation, ACK, record deletion or OTLP export is performed. The
delivery loop classifies this typed local failure as `Quarantine(IdentityMismatch)`.
The queue moves the unchanged container into the `.identity` quarantine category
with no-clobber publication, then continues the bounded batch. It never silently
relabels a report or treats isolation as successful delivery. If isolation fails,
the batch stops, retaining the source and any conflicting evidence; no callback,
ACK or subsequent send is permitted for that failed mutation.

Quarantined bytes and entries still consume capacity and survive restart. Status
and read-only doctor expose `spool_identity_mismatch` and its count; status JSON
adds `spool_identity_mismatch_batches` and status text
also distinguishes identity mismatches within the total quarantine count. These
are bounded inventory observations, not proof that all payloads are valid.
Diagnostics neither acquire the writer lock nor read/disclose payload bytes.
No automatic deletion, replay under another identity, old-format reader or
credential repair is supplied. Evidence retention can eventually exhaust the
configured capacity; operators must review it through their state-management
workflow rather than expecting a hidden purge.

Tests cover all identity dimensions and budgets, immutable snapshot clones,
Host-specific UUID rejection, bounded read-only state failures, cross-product
credential rejection and a real credential rotation with durable Spool delivery
that preserves a mismatched item's original bytes, exercises a publication
collision, and then delivers the current instance's report with a real ACK.
CLI tests verify diagnostics leave the state tree unchanged and never connect
to a loopback HTTP trap or disclose quarantined payload contents.
Native filesystem acceptance remains separate from Linux tests.
