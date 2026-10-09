use std::future::Future;

/// Synchronously finish a trusted future backed by a native worker/channel.
///
/// This entry point does not start or nest a Tokio runtime. The caller must
/// ensure that the future needs no Tokio reactor, timers or task spawning, and
/// must explicitly close its worker resources before completion. It is not a
/// blocking adapter for arbitrary async application code. Recursively entering
/// this executor from its own future is outside the contract.
pub fn block_on_worker_future<F: Future>(future: F) -> F::Output {
    futures_executor::block_on(future)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn worker_channel_round_trip() {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let worker = std::thread::spawn(move || sender.send(7).unwrap());
        assert_eq!(block_on_worker_future(receiver).unwrap(), 7);
        worker.join().unwrap();
    }
    #[test]
    fn worker_channel_without_a_runtime() {
        worker_channel_round_trip();
    }
    #[test]
    fn worker_channel_inside_existing_current_thread_runtime() {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                worker_channel_round_trip();
            });
    }
    #[test]
    fn worker_channel_inside_existing_multithread_runtime() {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .build()
            .unwrap()
            .block_on(async {
                worker_channel_round_trip();
            });
    }
}
