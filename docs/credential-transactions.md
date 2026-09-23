# Credential transactions

`sarmg-client-runtime` owns `CredentialStore`, `CredentialSnapshot`,
`CredentialAuthorization` and `CredentialMutation`. Products implement storage
adapters and own revision identities, rotation journals, pairing protocols,
endpoint bindings and crash recovery.

The interface is synchronous. The adapter retains an exclusive storage lock for
each complete operation and serializes against every writer of the same state.
Network I/O belongs outside this transaction.

| Operation | Contract |
|---|---|
| `load` | Return an authorized identity, durable revision and shared secret captured consistently. Missing or invalidated credentials return `None`; unsafe storage, malformed state and inconsistent bindings return an error. |
| `replace` | Revalidate the prepared replacement against the durable journal under the transaction lock. Publish authorization as part of the complete recoverable commit. A superseded journal fails without modifying credentials. |
| `invalidate` | Compare the rejected in-flight revision with the current durable revision. Return `Applied` for the current revision or `Superseded` without writes when it differs. Preserve any incomplete rotation. |

Only `authorized` and `reauth_required` are valid serialized authorization
values. Unknown spellings fail deserialization. Snapshot clones preserve their
identity and revision and share `Arc<SecretString>`; formatting redacts secrets.
The last shared owner releases zeroizing storage.

## Product adapter responsibilities

A pending replacement does not change the revision of the active credential.
A delayed rejection for credential A cannot invalidate credential B. Products
must compare against the durable active revision, retain complete snapshot
identity/endpoint associations, and expose renewed snapshots only after the
replacement is committed. Recovery and journal ordering follow the product's
storage protocol.

`DeliveryWorker` installs renewed recovery results through the product driver's
`apply_recovery` method. Returning `RecoveryUpdate::Renewed` cancels delivery
using the superseded snapshot and schedules a batch with the replacement.
Adapters own any auxiliary workers and must terminate workers whose snapshot is
superseded or whose driver is dropped.

Foundation tests validate exact authorization spellings and snapshot clone
semantics. Each product tests transaction locking, rotation, delayed rejection,
superseded replacements, incomplete commits, unsafe state and recovery against
its concrete storage adapter. Linux execution alone does not establish
Windows/macOS filesystem or native HTTP behavior.
