//! The spool stores bounded opaque bytes and never depends on a product DTO.

use rand::Rng;
use sarmg_agent_fs_safety::{AdvisoryLock, PrivateDirectory, RelativePath};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::watch;

mod identity;
pub use identity::AgentIdentity;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct RecordId(String);
impl TryFrom<String> for RecordId {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Error> {
        Self::parse(value)
    }
}
impl From<RecordId> for String {
    fn from(value: RecordId) -> Self {
        value.0
    }
}
impl RecordId {
    pub fn new() -> Result<Self, Error> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| Error::Randomness)?;
        Ok(Self(bytes.iter().map(|b| format!("{b:02x}")).collect()))
    }
    pub fn parse(value: String) -> Result<Self, Error> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::InvalidRecord);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct ContractId(String);
impl TryFrom<String> for ContractId {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Error> {
        Self::new(value)
    }
}
impl From<ContractId> for String {
    fn from(value: ContractId) -> Self {
        value.0
    }
}
impl ContractId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            return Err(Error::InvalidContract);
        }
        Ok(Self(value))
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedBytes(Vec<u8>);
impl BoundedBytes {
    pub fn new(value: Vec<u8>, max: usize) -> Result<Self, Error> {
        if value.len() > max {
            return Err(Error::RecordTooLarge);
        }
        Ok(Self(value))
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpoolRecord {
    pub record_id: RecordId,
    pub contract_id: ContractId,
    pub created_at_micros: i64,
    pub payload: BoundedBytes,
}
pub trait AgentPayloadCodec {
    type Value;
    fn contract_id(&self) -> ContractId;
    fn encode(&self, value: &Self::Value) -> Result<BoundedBytes, Error>;
    fn validate(&self, bytes: &[u8]) -> Result<(), Error>;
}
mod session;
mod spool;
pub use session::AgentSession;
pub use spool::{
    MAX_RECORD_BYTES, MAX_SPOOL_BYTES, MAX_SPOOL_ENTRIES, QuarantineReason, Spool, SpoolLimits,
};
mod delivery;
mod worker;
pub use delivery::{
    BatchOutcome, DELIVERY_BATCH_RECORDS, DeliveryAdapter, DeliveryQueue, FailureDisposition,
    MAX_RETRY_BACKOFF, MAX_RETRY_JITTER_PERCENT, RetryBackoff, deliver_batch,
};
pub use worker::{
    AgentDeliveryDriver, DeliveryFuture, DeliveryNotifications, DeliveryResponse, DeliveryWake,
    DeliveryWorker, MAX_QUEUE_FAILURES, QueueFailureStreak, RecoveryUpdate,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AgentHealth {
    pub healthy: bool,
    pub spool_entries: usize,
    pub spool_bytes: u64,
    pub quarantined_entries: usize,
    pub identity_mismatch_entries: usize,
    pub capacity_remaining: bool,
}

pub struct SingleInstanceLock {
    _lock: AdvisoryLock,
}

impl SingleInstanceLock {
    pub fn acquire(state_directory: &PrivateDirectory) -> Result<Self, Error> {
        let name = RelativePath::new("agent.instance.lock")?;
        let lock = AdvisoryLock::acquire(state_directory, &name).map_err(|error| {
            if matches!(error, sarmg_agent_fs_safety::Error::AlreadyLocked(_)) {
                Error::AlreadyRunning
            } else {
                Error::Filesystem(error)
            }
        })?;
        Ok(Self { _lock: lock })
    }
}

mod credential;
pub use credential::{
    CredentialAuthorization, CredentialMutation, CredentialSnapshot, CredentialStore,
};

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow_and_update() || shutdown.changed().await.is_err() {
            return;
        }
    }
}
/// Jitter for a validated Agent sampling interval. Network retries must use
/// exponential_backoff so their final, jittered delay respects the retry cap.
pub fn sampling_jitter(base: Duration, percent: u8) -> Result<Duration, Error> {
    if base.is_zero() || base > Duration::from_secs(3600) || percent > 50 {
        return Err(Error::InvalidLimits);
    }
    if percent == 0 {
        return Ok(base);
    }
    randomize_delay(base, f64::from(percent) / 100.0)
}

fn randomize_delay(base: Duration, fraction: f64) -> Result<Duration, Error> {
    let multiplier = rand::rng().random_range((1.0 - fraction)..=(1.0 + fraction));
    Duration::try_from_secs_f64(base.as_secs_f64() * multiplier).map_err(|_| Error::InvalidLimits)
}

fn exponential_backoff(
    attempt: u32,
    base: Duration,
    maximum: Duration,
    jitter_fraction: f64,
) -> Result<Duration, Error> {
    if base.is_zero()
        || maximum < base
        || maximum > Duration::from_secs(300)
        || !jitter_fraction.is_finite()
        || !(0.0..=1.0).contains(&jitter_fraction)
    {
        return Err(Error::InvalidLimits);
    }
    let factor = 1u32.checked_shl(attempt.min(30)).unwrap_or(u32::MAX);
    let bounded = base.saturating_mul(factor).min(maximum);
    Ok(randomize_delay(bounded, jitter_fraction)?.min(maximum))
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("spool serialization gate is poisoned")]
    SpoolUnavailable,
    #[error("invalid spool limits")]
    InvalidLimits,
    #[error("record exceeds its byte budget")]
    RecordTooLarge,
    #[error("spool capacity exhausted")]
    SpoolFull,
    #[error("invalid spool record")]
    InvalidRecord,
    #[error("invalid contract identifier")]
    InvalidContract,
    #[error("spool record not found")]
    RecordNotFound,
    #[error("secure randomness unavailable")]
    Randomness,
    #[error("invalid agent identity")]
    InvalidIdentity,
    #[error("Agent identity does not match the active delivery identity")]
    IdentityMismatch,
    #[error("another agent instance already owns the state directory")]
    AlreadyRunning,
    #[error("persistent local queue failure requires service intervention")]
    PersistentQueueFailure,
    #[error(transparent)]
    Filesystem(#[from] sarmg_agent_fs_safety::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn jitter_validates_inputs_and_caps_the_final_network_delay() {
        assert_eq!(
            sampling_jitter(Duration::from_secs(3600), 0).unwrap(),
            Duration::from_secs(3600)
        );
        assert!(sampling_jitter(Duration::ZERO, 0).is_err());
        assert!(sampling_jitter(Duration::MAX, 1).is_err());
        assert!(sampling_jitter(Duration::from_secs(1), 51).is_err());
        assert!(RetryBackoff::new(Duration::from_secs(301), MAX_RETRY_BACKOFF, 0).is_err());
        assert!(RetryBackoff::new(Duration::from_secs(1), MAX_RETRY_BACKOFF, 255).is_err());
        for _ in 0..512 {
            let delay = RetryBackoff::new(Duration::from_secs(300), MAX_RETRY_BACKOFF, 50)
                .unwrap()
                .next_delay()
                .unwrap();
            assert!((Duration::from_secs(150)..=Duration::from_secs(300)).contains(&delay));
            let sample = sampling_jitter(Duration::from_secs(10), 50).unwrap();
            assert!((Duration::from_secs(5)..=Duration::from_secs(15)).contains(&sample));
        }
    }

    #[test]
    fn spool_is_fifo_bounded_and_acknowledged() {
        let temp = tempfile::tempdir().unwrap();
        let spool = Spool::open(
            temp.path().join("spool"),
            SpoolLimits {
                max_record_bytes: 10,
                max_entries: 2,
                max_bytes: 10000,
            },
        )
        .unwrap();
        let contract = ContractId::new("host.report").unwrap();
        let first = spool
            .enqueue(contract.clone(), 2, BoundedBytes::new(vec![2], 10).unwrap())
            .unwrap();
        spool
            .enqueue(contract, 1, BoundedBytes::new(vec![1], 10).unwrap())
            .unwrap();
        assert_eq!(spool.next().unwrap().unwrap().payload.as_slice(), &[1]);
        spool.ack(&first).unwrap();
        assert_eq!(spool.usage().unwrap().0, 1);
    }
    #[test]
    fn backoff_is_bounded() {
        for _ in 0..100 {
            assert!(
                exponential_backoff(30, Duration::from_secs(1), Duration::from_secs(60), 0.2)
                    .unwrap()
                    <= Duration::from_secs(60)
            );
        }
    }

    #[test]
    fn invalid_backoff_and_deserialized_identifiers_are_rejected() {
        for jitter in [f64::NAN, f64::INFINITY, -0.1, 1.1] {
            assert!(
                exponential_backoff(1, Duration::from_secs(1), Duration::from_secs(60), jitter)
                    .is_err()
            );
        }
        assert!(exponential_backoff(1, Duration::ZERO, Duration::from_secs(60), 0.2).is_err());
        assert!(
            exponential_backoff(1, Duration::from_secs(1), Duration::from_secs(301), 0.2).is_err()
        );
        assert!(serde_json::from_str::<RecordId>(&format!("\"{}\"", "A".repeat(32))).is_err());
        assert!(serde_json::from_str::<ContractId>("\"\"").is_err());
    }
}
