# Client identity and credential ownership

`sarmg-client-runtime::ClientIdentity` identifies a Client delivery context by
product ID, instance ID and payload contract. All three participate in equality.
Construction requires nonempty ASCII letters, digits, dots, dashes or underscores:
product IDs are bounded to 128 bytes and instance IDs to 256 bytes. `ContractId`
applies the same character policy with a 128-byte limit. Private fields and
read-only accessors preserve validation after construction. `ensure_matches`
rejects any differing dimension without echoing identifiers.

An authorized `CredentialSnapshot` carries this identity, its durable revision
and an `Arc<SecretString>`, captured under one short storage transaction. Cloning
a snapshot preserves its identity and revision and shares secret ownership.
A sender uses the captured identity throughout the request. Rotation constructs
a complete replacement snapshot; the product adapter installs it atomically.

Products own UUID constraints, identity filenames, payload fields, endpoint
bindings and state recovery. Foundation runtime identity does not authenticate
requests: TLS, remote authorization and credential revision checks remain
separate requirements.

## Identity mismatch during delivery

A product adapter compares each payload's identity with its authorized snapshot
before sending. A local mismatch maps to
`FailureDisposition::Quarantine(QuarantineReason::IdentityMismatch)`. The shared
batch loop invokes the queue's durable quarantine operation before its callback.
The Spool preserves the original container bytes in the `.identity` category.
A failed quarantine stops the batch without acknowledgement or a callback.

Quarantined entries consume capacity and survive restart.
`Spool::inspect_existing` reports `identity_mismatch_entries` as a subset of
`quarantined_entries`. Inspection does not acquire the writer lock, read payloads
or validate payload checksums. Products decide how to present these observations
and how operators review retained evidence. Foundation does not relabel,
automatically replay or purge an isolated record.

## Verification

Foundation tests cover identifier dimensions, byte budgets, exact equality,
secret-sharing snapshot clones, durable quarantine, publication collisions and
batch ordering. Product repositories validate their wire identities, storage
adapters and command behavior. Native filesystem acceptance is recorded for each
target platform.
