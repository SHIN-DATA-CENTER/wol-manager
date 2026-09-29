//! Worker pools (plan §7.3): 8 threads for probes, 2 for I/O (sending, ARP, adapter
//! enumeration, PATH). Jobs receive and return only `Send` data; results are posted to the
//! UI thread with [`post_ui`].

use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};

type Job = Box<dyn FnOnce() + Send + 'static>;

/// A fixed-size thread pool. Dropping it lets the threads finish their current job and exit
/// (they are not joined: a probe may block for seconds and the process is exiting anyway).
pub struct Pool {
    tx: Option<Sender<Job>>,
}

impl Pool {
    /// Starts `threads` workers named `<name>-<n>`.
    pub fn new(name: &str, threads: usize) -> Pool {
        let (tx, rx) = mpsc::channel::<Job>();
        let rx = Arc::new(Mutex::new(rx));
        for n in 0..threads.max(1) {
            let rx = rx.clone();
            let spawned = std::thread::Builder::new()
                .name(format!("{name}-{n}"))
                .spawn(move || {
                    loop {
                        let job = {
                            let guard = rx.lock().unwrap_or_else(|p| p.into_inner());
                            guard.recv()
                        };
                        match job {
                            Ok(job) => job(),
                            Err(_) => break,
                        }
                    }
                });
            if let Err(e) = spawned {
                log::error!("cannot start worker thread {name}-{n}: {e}");
            }
        }
        Pool { tx: Some(tx) }
    }

    /// Runs `f` on a worker.
    pub fn spawn(&self, f: impl FnOnce() + Send + 'static) {
        if let Some(tx) = &self.tx
            && tx.send(Box::new(f)).is_err()
        {
            log::warn!("worker pool is gone; job dropped");
        }
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.tx.take();
    }
}

/// Runs `f` with the app on the UI thread (dropped silently when the event loop is gone or
/// the app was already torn down).
pub fn post_ui(f: impl FnOnce(&crate::app::App) + Send + 'static) {
    if let Err(e) = slint::invoke_from_event_loop(move || {
        crate::app::with(|app| f(app));
    }) {
        log::debug!("post_ui: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn pool_runs_jobs_in_parallel() {
        let pool = Pool::new("test", 4);
        let (tx, rx) = mpsc::channel();
        let barrier = Arc::new(std::sync::Barrier::new(4));
        for i in 0..4 {
            let tx = tx.clone();
            let b = barrier.clone();
            pool.spawn(move || {
                b.wait();
                tx.send(i).unwrap();
            });
        }
        let mut got: Vec<i32> = (0..4)
            .map(|_| rx.recv_timeout(Duration::from_secs(5)).unwrap())
            .collect();
        got.sort();
        assert_eq!(got, vec![0, 1, 2, 3]);
    }
}
