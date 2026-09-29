//! Worker pools (plan §7.3): 8 threads for probes, 2 for I/O (sending, ARP, adapter
//! enumeration, PATH). Jobs receive and return only `Send` data; results are posted to the
//! UI thread with [`post_ui`].
//!
//! Remote management (v0.2.0, cross review m1) has these lanes: the `remote` pool for
//! operations the user started (power, boot time, editor test / MAC), a thread of its own for
//! each "Cancel shutdown" (time-critical; review C5), a smaller `remote-auto` pool for automatic
//! boot-time fetches, and one [`SerialQueue`] for Credential Manager changes, which a later
//! remote operation waits for ([`SerialQueue::barrier`]), the store thread fills for written
//! saves / deletes (review C2) and the app flushes on exit.

use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

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

/// Jobs queued / finished so far.
#[derive(Debug, Default)]
struct Progress {
    queued: u64,
    done: u64,
}

type Shared = Arc<(Mutex<Progress>, Condvar)>;

fn lock(s: &Shared) -> std::sync::MutexGuard<'_, Progress> {
    s.0.lock().unwrap_or_else(|p| p.into_inner())
}

/// One worker thread that runs its jobs in order (Credential Manager writes and deletions):
/// a save and a later delete of the same host happen in that order, and other threads can wait
/// until everything queued so far ran ([`SerialQueue::barrier`]).
pub struct SerialQueue {
    pool: Pool,
    progress: Shared,
}

impl SerialQueue {
    /// Starts the thread `<name>-0`.
    pub fn new(name: &str) -> SerialQueue {
        SerialQueue {
            pool: Pool::new(name, 1),
            progress: Arc::new((Mutex::new(Progress::default()), Condvar::new())),
        }
    }

    /// Runs `f` after every job queued before (a panicking job still counts as done).
    pub fn spawn(&self, f: impl FnOnce() + Send + 'static) {
        lock(&self.progress).queued += 1;
        let progress = self.progress.clone();
        self.pool.spawn(move || {
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err() {
                log::error!("a secret-store job panicked");
            }
            lock(&progress).done += 1;
            progress.1.notify_all();
        });
    }

    /// Everything queued up to now: [`Barrier::wait`] returns once it all ran.
    pub fn barrier(&self) -> Barrier {
        Barrier {
            target: lock(&self.progress).queued,
            progress: self.progress.clone(),
        }
    }

    /// Waits (at most `timeout`) until every queued job ran; `false` on timeout. App exit:
    /// deletions of removed hosts' passwords are not lost.
    pub fn flush(&self, timeout: Duration) -> bool {
        self.barrier().wait(timeout)
    }

    /// Nothing queued is still waiting or running (session end: block the logoff while
    /// something is; review C2).
    pub fn is_idle(&self) -> bool {
        let p = lock(&self.progress);
        p.done >= p.queued
    }
}

/// A point in a [`SerialQueue`] (see [`SerialQueue::barrier`]). `Send`: taken on the UI thread,
/// waited for on a worker.
#[derive(Clone)]
pub struct Barrier {
    target: u64,
    progress: Shared,
}

impl Barrier {
    /// Blocks (at most `timeout`) until the jobs queued before this barrier ran; `false` on
    /// timeout (the caller goes on: a Credential Manager call never takes that long).
    pub fn wait(&self, timeout: Duration) -> bool {
        let guard = lock(&self.progress);
        let (g, _) = self
            .progress
            .1
            .wait_timeout_while(guard, timeout, |p| p.done < self.target)
            .unwrap_or_else(|p| p.into_inner());
        g.done >= self.target
    }
}

/// How long a remote operation waits for earlier Credential Manager changes.
pub const SECRET_WAIT: Duration = Duration::from_secs(10);

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

    /// Cross review m1: Credential Manager jobs run in order, a remote operation can wait for
    /// the ones queued before it, and the app can flush them on exit.
    #[test]
    fn serial_queue_orders_waits_and_flushes() {
        let q = SerialQueue::new("secrets-test");
        assert!(q.barrier().wait(Duration::ZERO), "nothing queued");
        let order = Arc::new(Mutex::new(Vec::new()));
        let (go_tx, go_rx) = mpsc::channel::<()>();
        {
            let order = order.clone();
            q.spawn(move || {
                go_rx.recv().unwrap();
                order.lock().unwrap().push("save");
            });
        }
        {
            let order = order.clone();
            q.spawn(move || order.lock().unwrap().push("delete"));
        }
        let barrier = q.barrier();
        // A later job is not waited for.
        q.spawn(|| std::thread::sleep(Duration::from_millis(200)));
        assert!(
            !barrier.wait(Duration::from_millis(50)),
            "the first job still waits"
        );
        let waiter = {
            let b = barrier.clone();
            std::thread::spawn(move || b.wait(Duration::from_secs(5)))
        };
        go_tx.send(()).unwrap();
        assert!(waiter.join().unwrap());
        assert_eq!(*order.lock().unwrap(), vec!["save", "delete"]);
        // A panicking job does not block the queue.
        q.spawn(|| panic!("boom"));
        let (tx, rx) = mpsc::channel();
        q.spawn(move || tx.send(()).unwrap());
        assert!(q.flush(Duration::from_secs(5)));
        rx.try_recv().expect("ran after the panic");
    }
}
