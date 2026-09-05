//! Queue draining and retry mechanics shared by daemon and one-shot consumers.
//! The adapter owns protocol interpretation, never the ack/retry ordering.

use std::{future::Future, time::Duration};

use crate::{Error, QuarantineReason, Spool, SpoolRecord, exponential_backoff};

pub const DELIVERY_BATCH_RECORDS: usize = 32;
pub const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(300);
pub const MAX_RETRY_JITTER_PERCENT: u8 = 50;

/// Validated policy plus the consecutive failure count. Products may reset on
/// success and choose a stricter cap, but must not implement their own doubling.
#[derive(Clone, Debug)]
pub struct RetryBackoff {
    base: Duration,
    maximum: Duration,
    jitter_percent: u8,
    attempt: u32,
}

impl RetryBackoff {
    pub fn new(base: Duration, maximum: Duration, jitter_percent: u8) -> Result<Self, Error> {
        if base.is_zero()
            || base > maximum
            || maximum > MAX_RETRY_BACKOFF
            || jitter_percent > MAX_RETRY_JITTER_PERCENT
        {
            return Err(Error::InvalidLimits);
        }
        Ok(Self {
            base,
            maximum,
            jitter_percent,
            attempt: 0,
        })
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    pub fn next_delay(&mut self) -> Result<Duration, Error> {
        let delay = exponential_backoff(
            self.attempt,
            self.base,
            self.maximum,
            f64::from(self.jitter_percent) / 100.0,
        )?;
        self.attempt = self.attempt.saturating_add(1);
        Ok(delay)
    }
}

/// A durable queue or a product codec around one. `acknowledge` must finish
/// its durable mutation before returning; an error must not be treated as ack.
pub trait DeliveryQueue: Sync {
    type Item: Send + Sync;
    type Error: Send;

    fn next(&self) -> Result<Option<Self::Item>, Self::Error>;
    fn acknowledge(&self, item: &Self::Item) -> Result<(), Self::Error>;
    /// Preserve the original durable bytes outside the delivery queue. Failure
    /// must retain evidence, never silently fall back to acknowledgement.
    fn quarantine(&self, item: &Self::Item, reason: QuarantineReason) -> Result<(), Self::Error>;
}

impl DeliveryQueue for Spool {
    type Item = SpoolRecord;
    type Error = Error;

    fn next(&self) -> Result<Option<SpoolRecord>, Error> {
        Spool::next(self)
    }

    fn acknowledge(&self, item: &SpoolRecord) -> Result<(), Error> {
        self.ack(&item.record_id)
    }
    fn quarantine(&self, item: &SpoolRecord, reason: QuarantineReason) -> Result<(), Error> {
        Spool::quarantine(self, &item.record_id, reason)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureDisposition {
    Retain,
    Discard,
    Quarantine(QuarantineReason),
}

pub trait DeliveryAdapter<Item: Sync>: Sync {
    type Error: Send;

    fn send(&self, item: &Item) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Only a protocol-level definitive rejection may authorize discarding a
    /// record. Timeout, unknown outcome and credential rejection must Retain.
    /// A local identity mismatch must Quarantine, never Discard.
    fn disposition(&self, error: &Self::Error) -> FailureDisposition;

    /// Bounded, non-blocking secondary output, called only after durable ack.
    fn acknowledged(&self, _item: &Item) {}

    /// A permanent rejection has been durably removed. Never a success callback.
    fn discarded(&self, _item: &Item, _error: &Self::Error) {}
    /// Called only after durable isolation; never a successful delivery/export.
    fn quarantined(&self, _item: &Item, _reason: QuarantineReason) {}
}

#[derive(Debug, Eq, PartialEq)]
pub enum BatchOutcome<E> {
    Drained,
    BatchComplete,
    Failed(E),
}

/// Cancellation before a send completes retains the current record. There is
/// no await between a completed send, durable ack and its secondary callback.
/// At most 32 records are processed per poll batch, including discarded/isolated records.
pub async fn deliver_batch<Q, T>(queue: &Q, adapter: &T) -> Result<BatchOutcome<T::Error>, Q::Error>
where
    Q: DeliveryQueue,
    T: DeliveryAdapter<Q::Item>,
{
    for _ in 0..DELIVERY_BATCH_RECORDS {
        let Some(item) = queue.next()? else {
            return Ok(BatchOutcome::Drained);
        };
        match adapter.send(&item).await {
            Ok(()) => {
                queue.acknowledge(&item)?;
                adapter.acknowledged(&item);
            }
            Err(error) => match adapter.disposition(&error) {
                FailureDisposition::Discard => {
                    queue.acknowledge(&item)?;
                    adapter.discarded(&item, &error);
                }
                FailureDisposition::Quarantine(reason) => {
                    queue.quarantine(&item, reason)?;
                    adapter.quarantined(&item, reason);
                }
                FailureDisposition::Retain => return Ok(BatchOutcome::Failed(error)),
            },
        }
    }
    Ok(BatchOutcome::BatchComplete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Failure {
        Retry,
        Unauthorized,
        Permanent,
        IdentityMismatch,
    }

    struct Queue {
        records: Mutex<VecDeque<u32>>,
        events: Arc<Mutex<Vec<String>>>,
        fail_ack: bool,
        fail_quarantine: bool,
        isolated: Mutex<Vec<u32>>,
    }

    impl DeliveryQueue for Queue {
        type Item = u32;
        type Error = &'static str;
        fn next(&self) -> Result<Option<u32>, Self::Error> {
            Ok(self.records.lock().unwrap().front().copied())
        }
        fn acknowledge(&self, value: &u32) -> Result<(), Self::Error> {
            if self.fail_ack {
                return Err("ack failed");
            }
            assert_eq!(self.records.lock().unwrap().pop_front(), Some(*value));
            self.events.lock().unwrap().push(format!("ack:{value}"));
            Ok(())
        }
        fn quarantine(&self, value: &u32, reason: QuarantineReason) -> Result<(), Self::Error> {
            if self.fail_quarantine {
                return Err("quarantine failed");
            }
            assert_eq!(self.records.lock().unwrap().pop_front(), Some(*value));
            self.isolated.lock().unwrap().push(*value);
            self.events
                .lock()
                .unwrap()
                .push(format!("isolate:{value}:{reason:?}"));
            Ok(())
        }
    }

    struct Adapter {
        outcome: Mutex<VecDeque<Result<(), Failure>>>,
        events: Arc<Mutex<Vec<String>>>,
    }
    impl DeliveryAdapter<u32> for Adapter {
        type Error = Failure;
        async fn send(&self, value: &u32) -> Result<(), Failure> {
            self.events.lock().unwrap().push(format!("send:{value}"));
            self.outcome.lock().unwrap().pop_front().unwrap_or(Ok(()))
        }
        fn disposition(&self, error: &Failure) -> FailureDisposition {
            match error {
                Failure::Permanent => FailureDisposition::Discard,
                Failure::IdentityMismatch => {
                    FailureDisposition::Quarantine(QuarantineReason::IdentityMismatch)
                }
                _ => FailureDisposition::Retain,
            }
        }
        fn acknowledged(&self, value: &u32) {
            self.events.lock().unwrap().push(format!("export:{value}"));
        }
        fn discarded(&self, value: &u32, _: &Failure) {
            self.events.lock().unwrap().push(format!("discard:{value}"));
        }
        fn quarantined(&self, value: &u32, _: QuarantineReason) {
            self.events
                .lock()
                .unwrap()
                .push(format!("isolated:{value}"));
        }
    }

    fn fixture(count: u32, fail_ack: bool, outcomes: Vec<Result<(), Failure>>) -> (Queue, Adapter) {
        let events = Arc::new(Mutex::new(Vec::new()));
        (
            Queue {
                records: Mutex::new((0..count).collect()),
                events: events.clone(),
                fail_ack,
                fail_quarantine: false,
                isolated: Mutex::new(Vec::new()),
            },
            Adapter {
                outcome: Mutex::new(outcomes.into()),
                events,
            },
        )
    }

    #[tokio::test]
    async fn secondary_output_is_after_durable_ack_and_permanent_rejection_does_not_block() {
        let (queue, adapter) = fixture(2, false, vec![Err(Failure::Permanent), Ok(())]);
        assert_eq!(
            deliver_batch(&queue, &adapter).await.unwrap(),
            BatchOutcome::Drained
        );
        assert_eq!(
            *queue.events.lock().unwrap(),
            [
                "send:0",
                "ack:0",
                "discard:0",
                "send:1",
                "ack:1",
                "export:1"
            ]
        );
    }

    #[tokio::test]
    async fn failures_and_unauthorized_responses_keep_the_head_and_prevent_secondary_output() {
        for failure in [Failure::Retry, Failure::Unauthorized] {
            let (queue, adapter) = fixture(2, false, vec![Err(failure)]);
            assert_eq!(
                deliver_batch(&queue, &adapter).await.unwrap(),
                BatchOutcome::Failed(failure)
            );
            assert_eq!(queue.next().unwrap(), Some(0));
            assert_eq!(*queue.events.lock().unwrap(), ["send:0"]);
        }
        for outcome in [Ok(()), Err(Failure::Permanent)] {
            let (queue, adapter) = fixture(2, true, vec![outcome]);
            assert_eq!(deliver_batch(&queue, &adapter).await, Err("ack failed"));
            assert_eq!(queue.next().unwrap(), Some(0));
            assert_eq!(*queue.events.lock().unwrap(), ["send:0"]);
        }
    }

    #[tokio::test]
    async fn a_batch_is_bounded_even_when_every_record_is_rejected() {
        for outcome in [Ok(()), Err(Failure::Permanent)] {
            let (queue, adapter) = fixture(33, false, vec![outcome; 33]);
            assert_eq!(
                deliver_batch(&queue, &adapter).await.unwrap(),
                BatchOutcome::BatchComplete
            );
            assert_eq!(queue.next().unwrap(), Some(32));
            assert_eq!(
                deliver_batch(&queue, &adapter).await.unwrap(),
                BatchOutcome::Drained
            );
        }
    }

    #[tokio::test]
    async fn isolation_is_durable_before_callback_and_never_exports_or_discards() {
        let (queue, adapter) = fixture(2, false, vec![Err(Failure::IdentityMismatch), Ok(())]);
        assert_eq!(
            deliver_batch(&queue, &adapter).await.unwrap(),
            BatchOutcome::Drained
        );
        assert_eq!(*queue.isolated.lock().unwrap(), vec![0]);
        assert_eq!(
            *queue.events.lock().unwrap(),
            vec![
                "send:0",
                "isolate:0:IdentityMismatch",
                "isolated:0",
                "send:1",
                "ack:1",
                "export:1"
            ]
        );
    }

    #[tokio::test]
    async fn isolation_failure_stops_without_ack_callback_or_processing_next_item() {
        let (mut queue, adapter) = fixture(2, false, vec![Err(Failure::IdentityMismatch)]);
        queue.fail_quarantine = true;
        assert_eq!(
            deliver_batch(&queue, &adapter).await,
            Err("quarantine failed")
        );
        assert_eq!(*queue.records.lock().unwrap(), VecDeque::from([0, 1]));
        assert!(queue.isolated.lock().unwrap().is_empty());
        assert_eq!(*queue.events.lock().unwrap(), vec!["send:0"]);
    }

    #[tokio::test]
    async fn isolated_records_count_toward_the_fixed_batch_limit() {
        let (queue, adapter) = fixture(33, false, vec![Err(Failure::IdentityMismatch); 33]);
        assert_eq!(
            deliver_batch(&queue, &adapter).await.unwrap(),
            BatchOutcome::BatchComplete
        );
        assert_eq!(queue.next().unwrap(), Some(32));
        assert_eq!(queue.isolated.lock().unwrap().len(), 32);
        assert_eq!(
            deliver_batch(&queue, &adapter).await.unwrap(),
            BatchOutcome::Drained
        );
        assert_eq!(queue.isolated.lock().unwrap().len(), 33);
    }

    struct Hanging;
    impl DeliveryAdapter<u32> for Hanging {
        type Error = Failure;
        async fn send(&self, _: &u32) -> Result<(), Failure> {
            std::future::pending().await
        }
        fn disposition(&self, _: &Failure) -> FailureDisposition {
            FailureDisposition::Retain
        }
    }

    #[tokio::test]
    async fn cancelling_a_pending_send_never_acknowledges_it() {
        let (queue, _) = fixture(2, false, vec![]);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), deliver_batch(&queue, &Hanging))
                .await
                .is_err()
        );
        assert_eq!(queue.next().unwrap(), Some(0));
        assert!(queue.events.lock().unwrap().is_empty());
    }

    #[test]
    fn delivery_limits_match_the_desktop_profile() {
        let profile = include_str!("../../../../profiles/desktop-agent.toml");
        for (key, value) in [
            ("batch_records", DELIVERY_BATCH_RECORDS as u64),
            ("max_backoff_seconds", MAX_RETRY_BACKOFF.as_secs()),
            ("max_jitter_percent", u64::from(MAX_RETRY_JITTER_PERCENT)),
            ("max_queue_failures", u64::from(crate::MAX_QUEUE_FAILURES)),
        ] {
            assert!(
                profile
                    .lines()
                    .any(|line| line == format!("{key} = {value}"))
            );
        }
    }

    #[test]
    fn retry_state_resets_caps_and_rejects_invalid_policy() {
        let mut retry =
            RetryBackoff::new(Duration::from_secs(1), Duration::from_secs(3), 0).unwrap();
        for expected in [1, 2, 3, 3, 3] {
            assert_eq!(retry.next_delay().unwrap(), Duration::from_secs(expected));
        }
        retry.reset();
        assert_eq!(retry.next_delay().unwrap(), Duration::from_secs(1));
        retry.attempt = u32::MAX;
        assert_eq!(retry.next_delay().unwrap(), Duration::from_secs(3));
        assert_eq!(retry.attempt, u32::MAX);
        for (base, maximum, jitter) in [(0, 1, 0), (2, 1, 0), (1, 301, 0), (1, 2, 51)] {
            assert!(
                RetryBackoff::new(
                    Duration::from_secs(base),
                    Duration::from_secs(maximum),
                    jitter
                )
                .is_err()
            );
        }
    }
}
