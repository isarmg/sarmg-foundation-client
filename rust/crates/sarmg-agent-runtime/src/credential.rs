//! Credential transactions, independent of pairing wire and product journals.

use std::sync::Arc;

use sarmg_agent_secret::SecretString;
use serde::{Deserialize, Serialize};

/// The only current durable authorization states. Unknown spellings are errors,
/// never an implicit authorization or a historical compatibility state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CredentialAuthorization {
    #[serde(rename = "authorized")]
    Authorized,
    #[serde(rename = "reauth_required")]
    ReauthorizationRequired,
}

/// An authorized, consistently loaded identity, credential and durable revision.
/// Load all three under the same transaction. A cloned in-flight snapshot keeps
/// the same identity and revision and shares secret ownership, never rereads an ID.
#[derive(Clone, Debug)]
pub struct CredentialSnapshot<R> {
    pub identity: crate::AgentIdentity,
    pub revision: R,
    pub secret: Arc<SecretString>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialMutation {
    Applied,
    Superseded,
}

/// A short, synchronous credential transaction, not an asynchronous network
/// operation. Implementors must retain their exclusive storage lock throughout
/// each call and serialize against every writer of the same credential state.
/// No operation may silently repair invalid storage or accept historical data.
///
/// Products own revision identities, prepared rotation journals, pairing wire,
/// and crash recovery. The interface does not freeze any one product's protocol.
pub trait CredentialStore {
    type Revision: Clone + Eq;
    type Replacement;
    type Error;

    /// Load only an authorized credential with matching durable identity and
    /// endpoint binding. Missing/invalidated is None; unsafe/corrupt is an error.
    fn load(&self) -> Result<Option<CredentialSnapshot<Self::Revision>>, Self::Error>;

    /// Revalidate the prepared replacement against the current durable journal,
    /// publish it under the transaction lock, and make authorization visible
    /// only as part of the complete recoverable commit. A superseded journal
    /// must fail without modifying current credentials.
    fn replace(&mut self, replacement: Self::Replacement) -> Result<(), Self::Error>;

    /// Durably block delivery only for the exact revision of the rejected
    /// in-flight snapshot. A newer pending pairing does not change the revision
    /// of a still-active credential; an incomplete rotation must not be touched.
    /// Return Superseded without writing if the expected revision is not current.
    /// Repeating invalidation must never authorize or erase a newer credential.
    fn invalidate(
        &mut self,
        expected: &Self::Revision,
        reason: &str,
    ) -> Result<CredentialMutation, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_accepts_only_the_current_exact_states() {
        for (state, wire) in [
            (CredentialAuthorization::Authorized, "authorized"),
            (
                CredentialAuthorization::ReauthorizationRequired,
                "reauth_required",
            ),
        ] {
            let json = serde_json::to_string(&state).unwrap();
            assert_eq!(json, format!("\"{wire}\""));
            assert_eq!(
                serde_json::from_str::<CredentialAuthorization>(&json).unwrap(),
                state
            );
        }
        for json in [
            "null",
            "0",
            "{}",
            "\"Authorized\"",
            "\"unknown\"",
            "\" authorized\"",
        ] {
            assert!(serde_json::from_str::<CredentialAuthorization>(json).is_err());
        }
    }

    #[test]
    fn snapshot_clones_keep_revision_and_share_redacted_secret() {
        let snapshot = CredentialSnapshot {
            identity: crate::AgentIdentity::new(
                "product",
                "instance",
                crate::ContractId::new("current").unwrap(),
            )
            .unwrap(),
            revision: 42_u64,
            secret: Arc::new(SecretString::new("private-token".into())),
        };
        let copy = snapshot.clone();
        assert_eq!(copy.identity, snapshot.identity);
        assert_eq!(copy.revision, 42);
        assert!(Arc::ptr_eq(&snapshot.secret, &copy.secret));
        assert!(!format!("{copy:?}").contains("private-token"));
        drop(snapshot);
        assert_eq!(copy.secret.expose(), "private-token");
    }
}
