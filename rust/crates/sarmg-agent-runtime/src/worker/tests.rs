use super::*;
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

#[derive(Clone, Copy, Debug)]
enum Failure {
    Transient,
    Unauthorized,
}
#[derive(Clone, Copy)]
enum SendAction {
    Drain,
    Retry,
    Unauthorized,
    QueueError,
    Hang,
}

#[derive(Default)]
struct State {
    sends: AtomicUsize,
    cancelled_sends: AtomicUsize,
    cancelled_probes: AtomicUsize,
    replies: Mutex<VecDeque<SendAction>>,
    recovery: Mutex<VecDeque<RecoveryUpdate>>,
    local_failures: Mutex<Vec<u32>>,
    drained: tokio::sync::Notify,
}

struct CancellationGuard {
    state: Arc<State>,
    probe: bool,
    complete: bool,
}
impl Drop for CancellationGuard {
    fn drop(&mut self) {
        if !self.complete {
            if self.probe {
                &self.state.cancelled_probes
            } else {
                &self.state.cancelled_sends
            }
            .fetch_add(1, Ordering::SeqCst);
        }
    }
}

struct Driver {
    state: Arc<State>,
    probe_hangs: bool,
    poll_interval: Duration,
}
impl AgentDeliveryDriver for Driver {
    type Probe = RecoveryUpdate;
    type Failure = Failure;
    type Error = Error;

    fn recover(&self) -> DeliveryFuture<Result<Self::Probe, Error>> {
        let state = self.state.clone();
        let hangs = self.probe_hangs;
        let interval = self.poll_interval;
        Box::pin(async move {
            let mut guard = CancellationGuard {
                state: state.clone(),
                probe: true,
                complete: false,
            };
            if hangs {
                std::future::pending::<()>().await;
            }
            guard.complete = true;
            let next =
                state
                    .recovery
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(RecoveryUpdate::Unchanged {
                        poll_after: interval,
                    });
            Ok(next)
        })
    }
    fn apply_recovery(&mut self, probe: Self::Probe) -> Result<RecoveryUpdate, Error> {
        Ok(probe)
    }
    fn batch(&self) -> DeliveryFuture<Result<BatchOutcome<Failure>, Error>> {
        let state = self.state.clone();
        Box::pin(async move {
            state.sends.fetch_add(1, Ordering::SeqCst);
            let mut guard = CancellationGuard {
                state: state.clone(),
                probe: false,
                complete: false,
            };
            let action = state
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(SendAction::Drain);
            let result = match action {
                SendAction::Drain => {
                    state.drained.notify_one();
                    Ok(BatchOutcome::Drained)
                }
                SendAction::Retry => Ok(BatchOutcome::Failed(Failure::Transient)),
                SendAction::Unauthorized => Ok(BatchOutcome::Failed(Failure::Unauthorized)),
                SendAction::QueueError => Err(Error::InvalidRecord),
                SendAction::Hang => std::future::pending().await,
            };
            guard.complete = true;
            result
        })
    }
    fn classify_failure(&mut self, error: &Failure) -> DeliveryResponse {
        match error {
            Failure::Transient => DeliveryResponse::Retry,
            Failure::Unauthorized => DeliveryResponse::AuthorizationRequired,
        }
    }
    fn local_queue_failed(&self, _: &Error, count: u32) {
        self.state.local_failures.lock().unwrap().push(count);
    }
}

fn fixture(actions: Vec<SendAction>, probe_hangs: bool) -> (Arc<State>, Driver) {
    let state = Arc::new(State::default());
    *state.replies.lock().unwrap() = actions.into();
    let driver = Driver {
        state: state.clone(),
        probe_hangs,
        poll_interval: Duration::from_secs(1),
    };
    (state, driver)
}

async fn settle() {
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn wake_edges_do_not_collapse_backoff_or_cancel_a_pending_send() {
    let (state, driver) = fixture(
        vec![SendAction::Retry, SendAction::Retry, SendAction::Hang],
        false,
    );
    let (wake, notifications) = DeliveryWake::channel();
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(
        DeliveryWorker::new(driver, 0)
            .unwrap()
            .run(notifications, shutdown),
    );
    settle().await;
    assert_eq!(state.sends.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_millis(500)).await;
    for _ in 0..10 {
        assert!(wake.notify());
        settle().await;
    }
    assert_eq!(state.sends.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_millis(500)).await;
    settle().await;
    assert_eq!(state.sends.load(Ordering::SeqCst), 2);
    tokio::time::advance(Duration::from_secs(2)).await;
    settle().await;
    assert_eq!(state.sends.load(Ordering::SeqCst), 3);
    for _ in 0..10 {
        assert!(wake.notify());
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
    }
    assert_eq!(state.sends.load(Ordering::SeqCst), 3);
    assert_eq!(state.cancelled_sends.load(Ordering::SeqCst), 0);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(state.cancelled_sends.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn authorization_requires_explicit_renewal_and_renewal_cancels_the_old_snapshot() {
    for first in [SendAction::Unauthorized, SendAction::Hang] {
        let (state, driver) = fixture(vec![first, SendAction::Drain], false);
        let (wake, notifications) = DeliveryWake::channel();
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(
            DeliveryWorker::new(driver, 0)
                .unwrap()
                .run(notifications, shutdown),
        );
        settle().await;
        for _ in 0..4 {
            assert!(wake.notify());
            tokio::time::advance(Duration::from_secs(1)).await;
            settle().await;
        }
        assert_eq!(state.sends.load(Ordering::SeqCst), 1);
        state
            .recovery
            .lock()
            .unwrap()
            .push_back(RecoveryUpdate::Renewed {
                poll_after: Duration::from_secs(60),
            });
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
        assert_eq!(state.sends.load(Ordering::SeqCst), 2);
        assert_eq!(
            state.cancelled_sends.load(Ordering::SeqCst),
            usize::from(matches!(first, SendAction::Hang))
        );
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn shutdown_and_lost_controllers_cancel_both_owned_futures() {
    for mode in 0..3 {
        let (state, driver) = fixture(vec![SendAction::Hang], true);
        let (wake, notifications) = DeliveryWake::channel();
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(
            DeliveryWorker::new(driver, 0)
                .unwrap()
                .run(notifications, shutdown),
        );
        settle().await;
        match mode {
            0 => {
                stop.send(true).unwrap();
            }
            1 => drop(stop),
            _ => drop(wake),
        }
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(state.cancelled_sends.load(Ordering::SeqCst), 1);
        assert_eq!(state.cancelled_probes.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn preclosed_controls_and_invalid_poll_intervals_never_start_a_delivery() {
    for close_notifications in [false, true] {
        let (state, driver) = fixture(vec![SendAction::Drain], false);
        let (wake, notifications) = DeliveryWake::channel();
        let (stop, shutdown) = watch::channel(false);
        if close_notifications {
            drop(wake);
        } else {
            drop(stop);
        }
        DeliveryWorker::new(driver, 0)
            .unwrap()
            .run(notifications, shutdown)
            .await
            .unwrap();
        assert_eq!(state.sends.load(Ordering::SeqCst), 0);
    }
    for poll_after in [Duration::ZERO, Duration::from_secs(3601)] {
        let (state, driver) = fixture(vec![SendAction::Drain], false);
        state
            .recovery
            .lock()
            .unwrap()
            .push_back(RecoveryUpdate::Renewed { poll_after });
        let (_wake, notifications) = DeliveryWake::channel();
        let (_stop, shutdown) = watch::channel(false);
        assert!(matches!(
            DeliveryWorker::new(driver, 0)
                .unwrap()
                .run(notifications, shutdown)
                .await,
            Err(Error::InvalidLimits)
        ));
        assert_eq!(state.sends.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn persistent_queue_failure_stops_but_network_failure_resets_the_local_streak() {
    let (state, mut driver) = fixture(
        vec![SendAction::QueueError; MAX_QUEUE_FAILURES as usize],
        false,
    );
    driver.poll_interval = Duration::from_secs(3600);
    let (_wake, notifications) = DeliveryWake::channel();
    let (_stop, shutdown) = watch::channel(false);
    let result = tokio::time::timeout(
        Duration::from_secs(36000),
        DeliveryWorker::new(driver, 0)
            .unwrap()
            .run(notifications, shutdown),
    )
    .await
    .unwrap();
    assert!(matches!(result, Err(Error::PersistentQueueFailure)));
    assert_eq!(
        state.local_failures.lock().unwrap().last(),
        Some(&MAX_QUEUE_FAILURES)
    );

    let mut actions = vec![SendAction::QueueError; (MAX_QUEUE_FAILURES - 1) as usize];
    actions.push(SendAction::Retry);
    actions.extend(vec![
        SendAction::QueueError;
        (MAX_QUEUE_FAILURES - 1) as usize
    ]);
    actions.push(SendAction::Drain);
    let (state, mut driver) = fixture(actions, false);
    driver.poll_interval = Duration::from_secs(3600);
    let (_wake, notifications) = DeliveryWake::channel();
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(
        DeliveryWorker::new(driver, 0)
            .unwrap()
            .run(notifications, shutdown),
    );
    tokio::time::timeout(Duration::from_secs(72000), state.drained.notified())
        .await
        .unwrap();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(
        state
            .local_failures
            .lock()
            .unwrap()
            .iter()
            .filter(|&&value| value == 1)
            .count(),
        2
    );
}
