//! One owner for queue delivery, recovery polling, notifications and cancellation.

use crate::{BatchOutcome, Error, MAX_RETRY_BACKOFF, RetryBackoff};
#[cfg(test)]
mod tests;
use std::{future::Future, pin::Pin, time::Duration};
use tokio::{
    sync::{mpsc, watch},
    time::Instant,
};

pub const MAX_QUEUE_FAILURES: u32 = 100;

#[derive(Default)]
pub struct QueueFailureStreak(u32);

impl QueueFailureStreak {
    pub fn record_success(&mut self) {
        self.0 = 0;
    }
    pub fn consecutive_failures(&self) -> u32 {
        self.0
    }
    pub fn record_failure(&mut self) -> Result<(), Error> {
        self.0 = self.0.saturating_add(1);
        if self.0 >= MAX_QUEUE_FAILURES {
            return Err(Error::PersistentQueueFailure);
        }
        Ok(())
    }
}
pub type DeliveryFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

#[derive(Clone)]
pub struct DeliveryWake(mpsc::Sender<()>);
pub struct DeliveryNotifications(mpsc::Receiver<()>);

impl DeliveryWake {
    pub fn channel() -> (Self, DeliveryNotifications) {
        let (sender, receiver) = mpsc::channel(1);
        (Self(sender), DeliveryNotifications(receiver))
    }

    /// A coalescing edge; durable queue contents remain the source of truth.
    pub fn notify(&self) -> bool {
        match self.0.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(())) => true,
            Err(mpsc::error::TrySendError::Closed(())) => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryUpdate {
    Unchanged {
        poll_after: Duration,
    },
    /// The adapter has atomically installed a new credential/endpoint snapshot.
    Renewed {
        poll_after: Duration,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryResponse {
    Retry,
    RetryAfterRecovery,
    /// Preserve the queue and wait for an explicitly renewed credential.
    AuthorizationRequired,
}

/// Product wire/state adapter. Returned futures own immutable snapshots and
/// must not spawn detached work. Recovery may replace a snapshot only via Renewed.
pub trait AgentDeliveryDriver: Send + 'static {
    type Probe: Send + 'static;
    type Failure: Send + 'static;
    type Error: From<Error> + Send + 'static;

    fn recover(&self) -> DeliveryFuture<Result<Self::Probe, Self::Error>>;
    fn apply_recovery(&mut self, probe: Self::Probe) -> Result<RecoveryUpdate, Self::Error>;
    fn batch(&self) -> DeliveryFuture<Result<BatchOutcome<Self::Failure>, Self::Error>>;
    fn classify_failure(&mut self, error: &Self::Failure) -> DeliveryResponse;

    fn recovery_failed(&self, _error: &Self::Error, _retry_in: Duration) {}
    fn local_queue_failed(&self, _error: &Self::Error, _consecutive: u32) {}
    fn delivery_failed(&self, _error: &Self::Failure, _retry_in: Option<Duration>) {}
}

pub struct DeliveryWorker<D: AgentDeliveryDriver> {
    driver: D,
    retry: RetryBackoff,
}

impl<D: AgentDeliveryDriver> DeliveryWorker<D> {
    pub fn new(driver: D, jitter_percent: u8) -> Result<Self, Error> {
        Ok(Self {
            driver,
            retry: RetryBackoff::new(Duration::from_secs(1), MAX_RETRY_BACKOFF, jitter_percent)?,
        })
    }

    pub async fn run(
        self,
        mut notifications: DeliveryNotifications,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), D::Error> {
        let Self {
            mut driver,
            mut retry,
        } = self;
        let mut recovery_retry = retry.clone();
        let mut retry_at = Some(Instant::now());
        let mut recovery_at = Instant::now();
        let mut authorization_blocked = false;
        let mut queue_failures = QueueFailureStreak::default();
        let mut pending_recovery = None;
        let mut pending_batch = None;

        loop {
            if *shutdown.borrow() || shutdown.has_changed().is_err() || notifications.0.is_closed()
            {
                return Ok(());
            }
            let now = Instant::now();
            if pending_recovery.is_none() && now >= recovery_at {
                pending_recovery = Some(driver.recover());
            }
            if !authorization_blocked
                && pending_batch.is_none()
                && retry_at.is_some_and(|at| now >= at)
            {
                pending_batch = Some(driver.batch());
            }
            // A ready deadline must never race the request it has just started.
            let next_delivery = (!authorization_blocked && pending_batch.is_none())
                .then_some(retry_at)
                .flatten();
            let next_recovery = pending_recovery.is_none().then_some(recovery_at);
            let deadline = match (next_delivery, next_recovery) {
                (Some(left), Some(right)) => left.min(right),
                (Some(value), None) | (None, Some(value)) => value,
                (None, None) => now + Duration::from_secs(3600),
            };

            tokio::select! {
                biased;
                _ = crate::wait_for_shutdown(&mut shutdown) => return Ok(()),
                result = async { pending_recovery.as_mut().expect("recovery branch requires a future").await }, if pending_recovery.is_some() => {
                    pending_recovery = None;
                    match result.and_then(|probe| driver.apply_recovery(probe)) {
                        Ok(update) => {
                            let poll_after = match update {
                                RecoveryUpdate::Unchanged { poll_after } | RecoveryUpdate::Renewed { poll_after } => poll_after,
                            };
                            if poll_after.is_zero() || poll_after > Duration::from_secs(3600) {
                                return Err(Error::InvalidLimits.into());
                            }
                            recovery_retry.reset();
                            recovery_at = Instant::now() + poll_after;
                            if matches!(update, RecoveryUpdate::Renewed { .. }) {
                                // Unknown outcomes retain their record ID; no stale response
                                // can invalidate the newly installed credential snapshot.
                                pending_batch = None;
                                authorization_blocked = false;
                                retry_at = Some(Instant::now());
                                retry.reset();
                            }
                        }
                        Err(error) => {
                            let delay = recovery_retry.next_delay()?;
                            recovery_at = Instant::now() + delay;
                            driver.recovery_failed(&error, delay);
                        }
                    }
                }
                result = async { pending_batch.as_mut().expect("batch branch requires a future").await }, if pending_batch.is_some() => {
                    pending_batch = None;
                    match result {
                        Ok(BatchOutcome::Drained) => {
                            queue_failures.record_success();
                            retry.reset();
                            retry_at = None;
                        }
                        Ok(BatchOutcome::BatchComplete) => {
                            queue_failures.record_success();
                            retry.reset();
                            retry_at = Some(Instant::now());
                            tokio::task::yield_now().await;
                        }
                        Err(error) => {
                            let status = queue_failures.record_failure();
                            driver.local_queue_failed(&error, queue_failures.consecutive_failures());
                            status?;
                            retry_at = Some(Instant::now() + retry.next_delay()?);
                        }
                        Ok(BatchOutcome::Failed(error)) => {
                            queue_failures.record_success();
                            match driver.classify_failure(&error) {
                                DeliveryResponse::AuthorizationRequired => {
                                    authorization_blocked = true;
                                    retry_at = None;
                                    recovery_at = Instant::now();
                                    driver.delivery_failed(&error, None);
                                }
                                response @ (DeliveryResponse::Retry | DeliveryResponse::RetryAfterRecovery) => {
                                    if response == DeliveryResponse::RetryAfterRecovery {
                                        recovery_at = Instant::now();
                                    }
                                    let delay = retry.next_delay()?;
                                    retry_at = Some(Instant::now() + delay);
                                    driver.delivery_failed(&error, Some(delay));
                                }
                            }
                        }
                    }
                }
                notification = notifications.0.recv() => {
                    if notification.is_none() {
                        return Ok(());
                    }
                    // Samples neither cancel an in-flight future nor collapse backoff.
                    if !authorization_blocked && retry_at.is_none() {
                        retry_at = Some(Instant::now());
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {},
            }
        }
    }
}
