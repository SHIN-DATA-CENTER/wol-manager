//! The store thread (plan §7.3): owns the one `wol_core::store::Store` and handles, in
//! order, updates, a poll for external changes every 2 s, portable-mode migrations, reloads
//! and the final flush. Results go back to the UI thread through a sink (in the app:
//! `slint::invoke_from_event_loop`).
//!
//! A parse error is reported, never "fixed": `Store::update` refuses to write over a file it
//! cannot parse, and polls report the error once per file content.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use wol_core::store::portable::{self, CopySettings, EnableReport};
use wol_core::store::{ConfigLocation, Loaded, Store, Updated};
use wol_core::{Config, EditBase, Error, Host, HostDraft, HostId};

/// Poll interval for external changes.
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// How long shutdown waits for pending writes.
pub const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// How a host from the editor is saved.
// Short-lived message moved once to the store thread; boxing would only add noise.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum SaveKind {
    /// New host with this id.
    New {
        /// Id chosen by the UI (kept for the row and its status).
        id: HostId,
    },
    /// Edit with a three-way merge against the snapshot taken when the editor opened.
    Edit(EditBase),
    /// Duplicate of `template` (hidden fields and `extra` are copied) with this id.
    Copy {
        /// The duplicated host as it was when the editor opened.
        template: Box<Host>,
        /// New id.
        id: HostId,
    },
}

/// A change to `config.toml`.
// Short-lived message (already boxed in the channel).
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Op {
    /// Editor save.
    SaveHost {
        /// Text of the editor.
        draft: HostDraft,
        /// New / edit / duplicate.
        kind: SaveKind,
    },
    /// Delete a host.
    DeleteHost {
        /// Host.
        id: HostId,
    },
    /// `Settings::set_key` for each pair.
    SetSettings(Vec<(String, String)>),
}

/// What an [`Op`] did.
#[derive(Debug, Clone, PartialEq)]
pub enum OpOutput {
    /// Saved host id.
    Saved(HostId),
    /// Removed host.
    Deleted(Box<Host>),
    /// Settings applied.
    Settings,
}

/// Applies an op to a config (pure; runs inside `Store::update` under the lock).
pub fn apply_op(cfg: &mut Config, op: &Op) -> wol_core::Result<OpOutput> {
    match op {
        Op::SaveHost { draft, kind } => match kind {
            SaveKind::New { id } => {
                let mut host = draft.build(cfg, None).map_err(Error::from)?;
                host.id = *id;
                cfg.insert_host(host).map(OpOutput::Saved)
            }
            SaveKind::Edit(base) => cfg.save_draft(draft, Some(base)).map(OpOutput::Saved),
            SaveKind::Copy { template, id } => {
                let mut host = draft.build_copy(cfg, template).map_err(Error::from)?;
                host.id = *id;
                cfg.insert_host(host).map(OpOutput::Saved)
            }
        },
        Op::DeleteHost { id } => cfg.remove_host(*id).map(|h| OpOutput::Deleted(Box::new(h))),
        Op::SetSettings(pairs) => {
            for (k, v) in pairs {
                cfg.settings.set_key(k, v)?;
            }
            Ok(OpOutput::Settings)
        }
    }
}

/// Portable-mode request.
#[derive(Debug, Clone)]
pub enum PortableCmd {
    /// `portable::enable(exe, copy)`.
    Enable(CopySettings),
    /// `portable::disable(exe)`.
    Disable,
}

/// Result of a portable switch.
#[derive(Debug)]
pub enum PortableDone {
    /// Enabled.
    Enabled(EnableReport),
    /// Disabled (`true` if a marker was removed).
    Disabled(bool),
}

/// Messages from the store thread.
#[derive(Debug)]
pub enum StoreEvent {
    /// Result of an update (`tag` from [`StoreHandle::update`]).
    Updated {
        /// Request tag.
        tag: u64,
        /// Result.
        result: wol_core::Result<Updated<OpOutput>>,
    },
    /// The file changed on disk (another process, e.g. `wolm`).
    Changed(Box<Loaded>),
    /// Result of an explicit reload.
    Reloaded(wol_core::Result<Box<Loaded>>),
    /// A poll could not read / parse the file (reported once per content).
    PollFailed(Error),
    /// The settings location changed outside the app (the portable marker was created or
    /// removed, e.g. by `wolm portable enable|disable` or by hand): the store now uses
    /// `location` and `loaded` is its content.
    Relocated {
        /// The new location.
        location: Box<ConfigLocation>,
        /// Content of the new location.
        loaded: wol_core::Result<Box<Loaded>>,
    },
    /// Portable mode switched (or failed). On success the store now uses `location` and
    /// `loaded` is its content.
    Portable {
        /// Switch result.
        result: wol_core::Result<PortableDone>,
        /// The (new) location.
        location: Box<ConfigLocation>,
        /// Content of the new location.
        loaded: Option<wol_core::Result<Box<Loaded>>>,
    },
}

enum Cmd {
    Update { tag: u64, op: Box<Op> },
    Reload,
    Portable { exe: PathBuf, cmd: PortableCmd },
    Flush(Sender<()>),
    Shutdown,
}

/// Handle of the store thread (owned by the UI thread).
pub struct StoreHandle {
    tx: Sender<Cmd>,
    done: Receiver<()>,
    join: Option<JoinHandle<()>>,
}

impl StoreHandle {
    /// Starts the thread with a store whose baseline was set by the startup `load()`.
    /// `flag` is the `--config-dir` value (used when the location is resolved again after a
    /// portable switch).
    pub fn start(
        store: Store,
        flag: Option<PathBuf>,
        sink: impl Fn(StoreEvent) + Send + 'static,
    ) -> StoreHandle {
        let (tx, rx) = mpsc::channel();
        let (done_tx, done) = mpsc::channel();
        let join = std::thread::Builder::new()
            .name("store".into())
            .spawn(move || {
                run(store, flag, rx, &sink);
                let _ = done_tx.send(());
            })
            .expect("spawn store thread");
        StoreHandle {
            tx,
            done,
            join: Some(join),
        }
    }

    /// Queues an update.
    pub fn update(&self, tag: u64, op: Op) {
        let _ = self.tx.send(Cmd::Update {
            tag,
            op: Box::new(op),
        });
    }

    /// Queues a reload (`Store::load`).
    pub fn reload(&self) {
        let _ = self.tx.send(Cmd::Reload);
    }

    /// Queues a portable switch (after the pending writes).
    pub fn portable(&self, exe: &Path, cmd: PortableCmd) {
        let _ = self.tx.send(Cmd::Portable {
            exe: exe.to_path_buf(),
            cmd,
        });
    }

    /// Waits until every queued command ran (at most `timeout`).
    pub fn flush(&self, timeout: Duration) -> bool {
        let (tx, rx) = mpsc::channel();
        if self.tx.send(Cmd::Flush(tx)).is_err() {
            return false;
        }
        rx.recv_timeout(timeout).is_ok()
    }

    /// Flushes, stops and joins the thread; gives up after `timeout` in total.
    pub fn shutdown(mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        if !self.flush(timeout) {
            return false;
        }
        let _ = self.tx.send(Cmd::Shutdown);
        let ok = self
            .done
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .is_ok();
        if ok && let Some(j) = self.join.take() {
            let _ = j.join();
        }
        ok
    }
}

fn run(mut store: Store, flag: Option<PathBuf>, rx: Receiver<Cmd>, sink: &dyn Fn(StoreEvent)) {
    let mut next_poll = Instant::now() + POLL_INTERVAL;
    // What resolving the location gave last time. A change means that the portable marker
    // was created or removed outside the app (`wolm portable enable|disable`, by hand).
    let mut resolved = wol_core::store::resolve(flag.as_deref()).ok();
    loop {
        let wait = next_poll.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(Cmd::Update { tag, op }) => {
                let result = store.update(|c| apply_op(c, &op));
                if let Err(e) = &result {
                    log::warn!("saving failed: {e}");
                }
                sink(StoreEvent::Updated { tag, result });
            }
            Ok(Cmd::Reload) => {
                sink(StoreEvent::Reloaded(store.load().map(Box::new)));
            }
            Ok(Cmd::Portable { exe, cmd }) => {
                let result = match cmd {
                    PortableCmd::Enable(copy) => {
                        portable::enable(&exe, copy).map(PortableDone::Enabled)
                    }
                    PortableCmd::Disable => portable::disable(&exe).map(PortableDone::Disabled),
                };
                let loaded = if result.is_ok() {
                    match Store::open(flag.as_deref()) {
                        Ok(s) => {
                            store = s;
                            resolved = Some(store.location().clone());
                            Some(store.load().map(Box::new))
                        }
                        Err(e) => Some(Err(e)),
                    }
                } else {
                    None
                };
                sink(StoreEvent::Portable {
                    result,
                    location: Box::new(store.location().clone()),
                    loaded,
                });
            }
            Ok(Cmd::Flush(reply)) => {
                let _ = reply.send(());
            }
            Ok(Cmd::Shutdown) | Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {}
        }
        if Instant::now() >= next_poll {
            // The CLI (`wolm portable enable|disable`) or the user (marker file) may switch
            // the location while the app runs: follow it, like the app's own switch does,
            // instead of splitting the host list over two folders until a restart.
            let now = wol_core::store::resolve(flag.as_deref()).ok();
            if let Some(moved) = relocated(&mut resolved, now) {
                log::info!(
                    "settings location changed outside the app: {} -> {}",
                    store.location().dir.display(),
                    moved.dir.display()
                );
                store = Store::new(moved);
                sink(StoreEvent::Relocated {
                    location: Box::new(store.location().clone()),
                    loaded: store.load().map(Box::new),
                });
            } else {
                poll(&store, sink);
            }
            next_poll = Instant::now() + POLL_INTERVAL;
        }
    }
}

/// `now` (the location resolved again), when it names another folder than `last` (the
/// previous resolution); remembers `now` in `last`.
fn relocated(
    last: &mut Option<ConfigLocation>,
    now: Option<ConfigLocation>,
) -> Option<ConfigLocation> {
    let now = now?;
    let changed = last
        .as_ref()
        .is_some_and(|l| l.dir != now.dir || l.source != now.source);
    *last = Some(now.clone());
    changed.then_some(now)
}

fn poll(store: &Store, sink: &dyn Fn(StoreEvent)) {
    match store.poll_changed() {
        Ok(Some(loaded)) => sink(StoreEvent::Changed(Box::new(loaded))),
        Ok(None) => {}
        Err(e @ Error::ConfigParse { .. }) => sink(StoreEvent::PollFailed(e)),
        Err(e) => log::debug!("poll: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wol_core::MacAddr;

    fn collect() -> (impl Fn(StoreEvent) + Send + 'static, Receiver<StoreEvent>) {
        let (tx, rx) = mpsc::channel();
        (
            move |e| {
                let _ = tx.send(e);
            },
            rx,
        )
    }

    #[test]
    fn updates_run_in_order_and_flush_waits() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(ConfigLocation::custom(dir.path()));
        store.load().unwrap();
        let (sink, rx) = collect();
        let h = StoreHandle::start(store, None, sink);
        let d = HostDraft {
            name: "PC".into(),
            mac: "00:11:22:33:44:55".into(),
            ..HostDraft::default()
        };
        let id = HostId::new_v4();
        h.update(
            1,
            Op::SaveHost {
                draft: d,
                kind: SaveKind::New { id },
            },
        );
        h.update(
            2,
            Op::SetSettings(vec![("gui.theme".into(), "dark".into())]),
        );
        h.update(
            3,
            Op::SetSettings(vec![("wake.repeat".into(), "99".into())]),
        );
        assert!(h.flush(Duration::from_secs(10)));
        let mut tags = Vec::new();
        for _ in 0..3 {
            match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
                StoreEvent::Updated { tag, result } => {
                    if tag == 3 {
                        assert!(result.is_err(), "out of range is rejected");
                    } else {
                        let u = result.unwrap();
                        assert!(u.written);
                        if tag == 1 {
                            assert_eq!(u.value, OpOutput::Saved(id));
                        }
                    }
                    tags.push(tag);
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(tags, vec![1, 2, 3]);
        assert!(h.shutdown(Duration::from_secs(5)));
        let text = std::fs::read_to_string(dir.path().join("config.toml")).unwrap();
        assert!(text.contains("theme = \"dark\""));
        assert!(text.contains(&id.to_string()));
    }

    #[test]
    fn external_changes_and_parse_errors_are_polled() {
        let dir = tempfile::tempdir().unwrap();
        let loc = ConfigLocation::custom(dir.path());
        let store = Store::new(loc.clone());
        store.load().unwrap();
        let (sink, rx) = collect();
        let h = StoreHandle::start(store, None, sink);
        // Another process adds a host.
        let other = Store::new(loc);
        other
            .update(|c| {
                c.insert_host(Host::new(
                    "ext",
                    MacAddr::parse("00:11:22:33:44:66").unwrap(),
                ))
            })
            .unwrap();
        match rx.recv_timeout(Duration::from_secs(10)).unwrap() {
            StoreEvent::Changed(l) => assert_eq!(l.config.hosts.len(), 1),
            e => panic!("unexpected {e:?}"),
        }
        std::fs::write(dir.path().join("config.toml"), "[[hosts]\nbroken").unwrap();
        match rx.recv_timeout(Duration::from_secs(10)).unwrap() {
            StoreEvent::PollFailed(Error::ConfigParse { .. }) => {}
            e => panic!("unexpected {e:?}"),
        }
        // Reported once per content.
        assert!(rx.recv_timeout(Duration::from_millis(2500)).is_err());
        // An update never overwrites the broken file.
        h.update(
            9,
            Op::SetSettings(vec![("gui.theme".into(), "dark".into())]),
        );
        match rx.recv_timeout(Duration::from_secs(10)).unwrap() {
            StoreEvent::Updated { tag: 9, result } => assert!(result.is_err()),
            e => panic!("unexpected {e:?}"),
        }
        assert_eq!(
            std::fs::read_to_string(dir.path().join("config.toml")).unwrap(),
            "[[hosts]\nbroken"
        );
        h.reload();
        match rx.recv_timeout(Duration::from_secs(10)).unwrap() {
            StoreEvent::Reloaded(Err(Error::ConfigParse { .. })) => {}
            e => panic!("unexpected {e:?}"),
        }
        assert!(h.shutdown(Duration::from_secs(5)));
    }

    #[test]
    fn delete_op() {
        let mut cfg = Config::default();
        let h = Host::new("PC", MacAddr::parse("00:11:22:33:44:55").unwrap());
        let id = h.id;
        cfg.hosts.push(h);
        match apply_op(&mut cfg, &Op::DeleteHost { id }).unwrap() {
            OpOutput::Deleted(h) => assert_eq!(h.name, "PC"),
            o => panic!("{o:?}"),
        }
        assert!(matches!(
            apply_op(&mut cfg, &Op::DeleteHost { id }),
            Err(Error::HostIdNotFound(_))
        ));
    }

    /// The store thread follows the location when resolving it again gives another folder
    /// (a portable marker created or removed outside the app), and only then.
    #[test]
    fn relocation_is_detected() {
        let a = ConfigLocation::custom(r"C:\cfg\a");
        let mut b = ConfigLocation::custom(r"C:\cfg\b");
        b.source = wol_core::store::ConfigSource::Portable;
        let mut last = None;
        assert!(
            relocated(&mut last, Some(a.clone())).is_none(),
            "first resolution"
        );
        assert!(relocated(&mut last, Some(a.clone())).is_none());
        assert!(relocated(&mut last, None).is_none(), "resolution failed");
        assert_eq!(relocated(&mut last, Some(b.clone())), Some(b.clone()));
        assert!(relocated(&mut last, Some(b)).is_none(), "reported once");
        assert_eq!(relocated(&mut last, Some(a.clone())), Some(a));
    }
}
