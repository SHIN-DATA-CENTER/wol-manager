//! Host list model: `Host` → `HostRow` mapping, natural sort, search / group filter
//! (`FilterModel` over `Rc<VecModel<HostRow>>`), reconcile by id and selection sync.
//!
//! Rows are always addressed by host id; indices are only used right after they were looked
//! up (plan §7.3, contract §9.2).

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::rc::Rc;

use slint::{FilterModel, Model, ModelRc, SharedString, VecModel};
use wol_core::normalize;
use wol_core::{Config, Host};

use crate::{HostRow, HostStatus, ProbeVia, RemoteKind, TrayHost};

/// Status part of a row (owned by the scheduler).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RowState {
    /// Status shown in the row.
    pub status: HostStatus,
    /// How the last successful probe answered.
    pub via: ProbeVia,
    /// Round-trip time of the last successful probe, -1 = unknown.
    pub rtt_ms: i32,
}

impl Default for RowState {
    fn default() -> Self {
        RowState {
            status: HostStatus::Unknown,
            via: ProbeVia::None,
            rtt_ms: -1,
        }
    }
}

/// Remote-management part of a row (owned by `crate::remote::RemoteState`, contract §10.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemoteRow {
    /// Localized boot line, "" = unknown / hidden.
    pub boot_text: String,
    /// The boot time is approximate (the UI adds its own marker).
    pub boot_approx: bool,
    /// A user-started remote operation runs on a worker.
    pub busy: bool,
}

/// `HostRow.remote-kind` of a host.
pub fn remote_kind(h: &Host) -> RemoteKind {
    match h.remote_kind() {
        None => RemoteKind::None,
        Some(wol_core::RemoteKind::Windows) => RemoteKind::Windows,
        Some(wol_core::RemoteKind::Ssh) => RemoteKind::Ssh,
    }
}

/// First line of a multi-line text (the row shows a single elided line).
pub fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or("").trim_end()
}

/// The row for a host.
pub fn host_row(h: &Host, st: RowState, rx: &RemoteRow) -> HostRow {
    let kind = remote_kind(h);
    let managed = kind != RemoteKind::None;
    HostRow {
        id: h.id.to_string().into(),
        name: h.name.as_str().into(),
        mac: h.mac.to_string().into(),
        address: h
            .address
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default()
            .into(),
        group: h.group.as_deref().unwrap_or("").into(),
        notes: first_line(h.notes.as_deref().unwrap_or("")).into(),
        status: st.status,
        via: st.via,
        rtt_ms: st.rtt_ms,
        managed,
        remote_kind: kind,
        // Only managed hosts show remote data (a removed table hides stale values at once).
        boot_text: if managed {
            rx.boot_text.as_str().into()
        } else {
            SharedString::default()
        },
        boot_approx: managed && rx.boot_approx && !rx.boot_text.is_empty(),
        busy_remote: managed && rx.busy,
    }
}

fn apply_remote(r: &mut HostRow, rx: &RemoteRow) -> bool {
    let (text, approx, busy) = if r.managed {
        (
            SharedString::from(rx.boot_text.as_str()),
            rx.boot_approx && !rx.boot_text.is_empty(),
            rx.busy,
        )
    } else {
        (SharedString::default(), false, false)
    };
    if r.boot_text == text && r.boot_approx == approx && r.busy_remote == busy {
        return false;
    }
    r.boot_text = text;
    r.boot_approx = approx;
    r.busy_remote = busy;
    true
}

/// "Natural" order of names: width-folded, case-insensitive, digit runs compared by value
/// ("PC2" < "PC10").
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    let ka = normalize::name_key(a);
    let kb = normalize::name_key(b);
    let mut ia = ka.chars().peekable();
    let mut ib = kb.chars().peekable();
    loop {
        match (ia.peek().copied(), ib.peek().copied()) {
            (None, None) => return a.cmp(b),
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(ca), Some(cb)) if ca.is_ascii_digit() && cb.is_ascii_digit() => {
                let da = take_digits(&mut ia);
                let db = take_digits(&mut ib);
                let ta = da.trim_start_matches('0');
                let tb = db.trim_start_matches('0');
                let ord = ta.len().cmp(&tb.len()).then_with(|| ta.cmp(tb));
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            (Some(ca), Some(cb)) => {
                if ca != cb {
                    return ca.cmp(&cb);
                }
                ia.next();
                ib.next();
            }
        }
    }
}

fn take_digits(it: &mut std::iter::Peekable<std::str::Chars<'_>>) -> String {
    let mut s = String::new();
    while let Some(c) = it.peek().copied() {
        if !c.is_ascii_digit() {
            break;
        }
        s.push(c);
        it.next();
    }
    s
}

/// Hosts in display order.
pub fn sorted_hosts(cfg: &Config) -> Vec<&Host> {
    let mut v: Vec<&Host> = cfg.hosts.iter().collect();
    v.sort_by(|a, b| natural_cmp(&a.name, &b.name).then_with(|| a.id.cmp(&b.id)));
    v
}

/// Tray submenu entries (display order, at most `max`).
pub fn tray_hosts(cfg: &Config, max: usize, state: impl Fn(&Host) -> RowState) -> Vec<TrayHost> {
    sorted_hosts(cfg)
        .into_iter()
        .take(max)
        .map(|h| TrayHost {
            id: h.id.to_string().into(),
            name: h.name.as_str().into(),
            status: state(h).status,
        })
        .collect()
}

/// Search / group criteria plus the hosts they are evaluated on.
#[derive(Default)]
struct FilterState {
    query: String,
    group_key: String,
    hosts: HashMap<SharedString, Host>,
}

impl FilterState {
    fn matches(&self, row: &HostRow) -> bool {
        let Some(h) = self.hosts.get(&row.id) else {
            return true;
        };
        if !self.group_key.is_empty()
            && normalize::name_key(h.group.as_deref().unwrap_or("")) != self.group_key
        {
            return false;
        }
        h.matches_search(&self.query)
    }
}

type Predicate = Box<dyn Fn(&HostRow) -> bool>;
/// The filtered view handed to `AppState.hosts`.
pub type View = FilterModel<Rc<VecModel<HostRow>>, Predicate>;

/// The host list: all rows (source) and the filtered view.
pub struct HostList {
    source: Rc<VecModel<HostRow>>,
    view: Rc<View>,
    filter: Rc<RefCell<FilterState>>,
}

impl Default for HostList {
    fn default() -> Self {
        Self::new()
    }
}

impl HostList {
    /// An empty list.
    pub fn new() -> HostList {
        let source = Rc::new(VecModel::<HostRow>::default());
        let filter = Rc::new(RefCell::new(FilterState::default()));
        let f = filter.clone();
        let pred: Predicate = Box::new(move |row: &HostRow| match f.try_borrow() {
            Ok(st) => st.matches(row),
            Err(_) => true,
        });
        let view = Rc::new(FilterModel::new(source.clone(), pred));
        HostList {
            source,
            view,
            filter,
        }
    }

    /// Model for `AppState.hosts`.
    pub fn model(&self) -> ModelRc<HostRow> {
        ModelRc::from(self.view.clone())
    }

    /// Number of rows before filtering.
    pub fn total(&self) -> usize {
        self.source.row_count()
    }

    /// Number of visible rows.
    pub fn visible_count(&self) -> usize {
        self.view.row_count()
    }

    /// Ids of the visible rows, in display order.
    pub fn visible_ids(&self) -> Vec<SharedString> {
        self.view.iter().map(|r| r.id).collect()
    }

    /// Index of `id` in the visible rows.
    #[cfg(test)]
    pub fn index_in_view(&self, id: &str) -> Option<usize> {
        self.view.iter().position(|r| r.id == id)
    }

    /// Row of `id` (visible or not).
    pub fn row(&self, id: &str) -> Option<HostRow> {
        self.source.iter().find(|r| r.id == id)
    }

    /// Sets the search text and re-filters.
    pub fn set_query(&self, query: &str) {
        self.filter.borrow_mut().query = query.to_owned();
        self.view.reset();
    }

    /// Sets the group filter ("" = all) and re-filters.
    pub fn set_group(&self, group: &str) {
        self.filter.borrow_mut().group_key = normalize::name_key(group);
        self.view.reset();
    }

    /// Replaces the rows with `cfg`'s hosts (display order), keeping rows whose content did
    /// not change. `state` supplies the status part (kept by the scheduler across reloads),
    /// `remote` the remote-management part (boot text, busy).
    pub fn reconcile(
        &self,
        cfg: &Config,
        state: impl Fn(&Host) -> RowState,
        remote: impl Fn(&Host) -> RemoteRow,
    ) {
        let hosts = sorted_hosts(cfg);
        {
            let mut f = self.filter.borrow_mut();
            f.hosts = hosts
                .iter()
                .map(|h| (SharedString::from(h.id.to_string()), (*h).clone()))
                .collect();
        }
        let rows: Vec<HostRow> = hosts
            .iter()
            .map(|h| host_row(h, state(h), &remote(h)))
            .collect();
        let same_order = self.source.row_count() == rows.len()
            && self
                .source
                .iter()
                .zip(rows.iter())
                .all(|(a, b)| a.id == b.id);
        if !same_order {
            self.source.set_vec(rows);
            return;
        }
        let expected: Vec<SharedString> = {
            let f = self.filter.borrow();
            rows.iter()
                .filter(|r| f.matches(r))
                .map(|r| r.id.clone())
                .collect()
        };
        for (i, r) in rows.into_iter().enumerate() {
            if self.source.row_data(i).as_ref() != Some(&r) {
                self.source.set_row_data(i, r);
            }
        }
        // A change in a field that is not part of the row (e.g. the second line of the notes)
        // can change the search result without changing the row.
        if self.visible_ids() != expected {
            self.view.reset();
        }
    }

    /// Updates the status part of one row. Returns `false` if the row does not exist.
    pub fn set_state(&self, id: &str, st: RowState) -> bool {
        let Some(i) = self.source.iter().position(|r| r.id == id) else {
            return false;
        };
        if let Some(mut r) = self.source.row_data(i) {
            if r.status == st.status && r.via == st.via && r.rtt_ms == st.rtt_ms {
                return true;
            }
            r.status = st.status;
            r.via = st.via;
            r.rtt_ms = st.rtt_ms;
            self.source.set_row_data(i, r);
        }
        true
    }

    /// Updates the remote-management part of one row (boot text, busy). Returns `false` if
    /// the row does not exist.
    pub fn set_remote(&self, id: &str, rx: &RemoteRow) -> bool {
        let Some(i) = self.source.iter().position(|r| r.id == id) else {
            return false;
        };
        if let Some(mut r) = self.source.row_data(i)
            && apply_remote(&mut r, rx)
        {
            self.source.set_row_data(i, r);
        }
        true
    }

    /// Ids of all rows (visible or not).
    pub fn all_ids(&self) -> Vec<SharedString> {
        self.source.iter().map(|r| r.id).collect()
    }

    /// Removes one row.
    #[cfg(test)]
    pub fn remove(&self, id: &str) {
        if let Some(i) = self.source.iter().position(|r| r.id == id) {
            self.source.remove(i);
        }
        self.filter.borrow_mut().hosts.remove(id);
    }
}

/// `(selected-row, selected-id)` after the visible rows changed: the index of `selected_id`
/// in the view, or `(-1, "")` when it is no longer visible (contract §9.2).
pub fn sync_selection(visible_ids: &[SharedString], selected_id: &str) -> (i32, SharedString) {
    if selected_id.is_empty() {
        return (-1, SharedString::default());
    }
    match visible_ids.iter().position(|id| id == selected_id) {
        Some(i) => (i as i32, selected_id.into()),
        None => (-1, SharedString::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wol_core::{HostAddr, MacAddr};

    fn host(name: &str, mac: &str) -> Host {
        Host::new(name, MacAddr::parse(mac).unwrap())
    }

    fn cfg_with(hosts: Vec<Host>) -> Config {
        Config {
            hosts,
            ..Config::default()
        }
    }

    fn names(list: &HostList) -> Vec<String> {
        list.view.iter().map(|r| r.name.to_string()).collect()
    }

    #[test]
    fn mapping_uses_display_forms() {
        let mut h = host("NAS", "00-11-22-33-44-55");
        h.address = Some(HostAddr::parse("192.168.1.10").unwrap());
        h.group = Some("Home".into());
        h.notes = Some("書斎の NAS\r\nsecond line".into());
        let r = host_row(&h, RowState::default(), &RemoteRow::default());
        assert_eq!(r.id, h.id.to_string());
        assert_eq!(r.mac, "00:11:22:33:44:55");
        assert_eq!(r.address, "192.168.1.10");
        assert_eq!(r.group, "Home");
        assert_eq!(r.notes, "書斎の NAS");
        assert_eq!(r.status, HostStatus::Unknown);
        assert_eq!(r.rtt_ms, -1);

        let bare = host_row(
            &host("x", "00:11:22:33:44:56"),
            RowState::default(),
            &RemoteRow::default(),
        );
        assert_eq!(bare.address, "");
        assert_eq!(bare.group, "");
        assert_eq!(bare.notes, "");
    }

    #[test]
    fn remote_fields_of_rows() {
        let mut h = host("PC", "00:11:22:33:44:55");
        let rx = RemoteRow {
            boot_text: "起動 9/29 08:12（稼働 3時間12分）".into(),
            boot_approx: true,
            busy: true,
        };
        // Unmanaged: no badge, and stale remote data is never shown.
        let r = host_row(&h, RowState::default(), &rx);
        assert!(!r.managed);
        assert_eq!(r.remote_kind, RemoteKind::None);
        assert_eq!(r.boot_text, "");
        assert!(!r.boot_approx && !r.busy_remote);

        h.remote = Some(wol_core::RemoteConfig::new(wol_core::RemoteKind::Windows));
        let r = host_row(&h, RowState::default(), &rx);
        assert!(r.managed);
        assert_eq!(r.remote_kind, RemoteKind::Windows);
        assert_eq!(r.boot_text, rx.boot_text.as_str());
        assert!(r.boot_approx && r.busy_remote);

        h.remote = Some(wol_core::RemoteConfig::new(wol_core::RemoteKind::Ssh));
        let r = host_row(&h, RowState::default(), &RemoteRow::default());
        assert_eq!(r.remote_kind, RemoteKind::Ssh);
        assert_eq!(r.boot_text, "");
        assert!(!r.boot_approx, "approx without a text is hidden");

        // set_remote updates only the remote part, by id.
        let id = h.id.to_string();
        let list = HostList::new();
        list.reconcile(
            &cfg_with(vec![h.clone()]),
            |_| RowState {
                status: HostStatus::Online,
                ..RowState::default()
            },
            |_| RemoteRow::default(),
        );
        assert!(list.set_remote(&id, &rx));
        let r = list.row(&id).unwrap();
        assert_eq!(r.boot_text, rx.boot_text.as_str());
        assert!(r.busy_remote);
        assert_eq!(r.status, HostStatus::Online);
        assert!(list.set_remote(&id, &RemoteRow::default()));
        assert_eq!(list.row(&id).unwrap().boot_text, "");
        assert!(!list.set_remote("nope", &rx));
        assert_eq!(list.all_ids(), vec![SharedString::from(id)]);
    }

    #[test]
    fn natural_sort() {
        let mut v = vec!["PC10", "pc2", "ＰＣ１", "Alpha", "PC02b", "beta"];
        v.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(v, vec!["Alpha", "beta", "ＰＣ１", "pc2", "PC02b", "PC10"]);
    }

    #[test]
    fn reconcile_keeps_status_and_order() {
        let a = host("B-host", "00:11:22:33:44:01");
        let b = host("A-host", "00:11:22:33:44:02");
        let (ida, idb) = (a.id, b.id);
        let mut cfg = cfg_with(vec![a, b]);
        let list = HostList::new();
        let online = RowState {
            status: HostStatus::Online,
            via: ProbeVia::Icmp,
            rtt_ms: 3,
        };
        let state = |h: &Host| {
            if h.id == ida {
                online
            } else {
                RowState::default()
            }
        };
        list.reconcile(&cfg, state, |_| RemoteRow::default());
        assert_eq!(names(&list), vec!["A-host", "B-host"]);
        assert_eq!(
            list.row(&ida.to_string()).unwrap().status,
            HostStatus::Online
        );

        // Rename B-host (same order) keeps the status supplied by the scheduler.
        cfg.get_mut(ida).unwrap().notes = Some("n".into());
        list.reconcile(&cfg, state, |_| RemoteRow::default());
        let r = list.row(&ida.to_string()).unwrap();
        assert_eq!(r.status, HostStatus::Online);
        assert_eq!(r.rtt_ms, 3);
        assert_eq!(r.notes, "n");

        // Reorder by renaming: rows are rebuilt, status still comes from `state`.
        cfg.get_mut(ida).unwrap().name = "0-first".into();
        list.reconcile(&cfg, state, |_| RemoteRow::default());
        assert_eq!(names(&list), vec!["0-first", "A-host"]);
        assert_eq!(
            list.row(&ida.to_string()).unwrap().status,
            HostStatus::Online
        );

        // Removal.
        cfg.remove_host(idb).unwrap();
        list.reconcile(&cfg, state, |_| RemoteRow::default());
        assert_eq!(names(&list), vec!["0-first"]);
        assert!(list.row(&idb.to_string()).is_none());

        // set_state updates by id.
        assert!(list.set_state(
            &ida.to_string(),
            RowState {
                status: HostStatus::Offline,
                via: ProbeVia::None,
                rtt_ms: -1
            }
        ));
        assert_eq!(
            list.row(&ida.to_string()).unwrap().status,
            HostStatus::Offline
        );
        assert!(!list.set_state("nope", RowState::default()));
    }

    #[test]
    fn search_full_width_japanese_and_mac() {
        let mut a = host("書斎の NAS", "00:11:22:AA:BB:CC");
        a.address = Some(HostAddr::parse("192.168.1.10").unwrap());
        a.notes = Some("first\nバックアップ用".into());
        let mut b = host("Office-PC", "00:11:22:33:44:55");
        b.group = Some("Lab".into());
        let cfg = cfg_with(vec![a, b]);
        let list = HostList::new();
        list.reconcile(&cfg, |_| RowState::default(), |_| RemoteRow::default());
        assert_eq!(list.visible_count(), 2);

        list.set_query("ｏｆｆｉｃｅ");
        assert_eq!(names(&list), vec!["Office-PC"]);
        list.set_query("書斎");
        assert_eq!(names(&list), vec!["書斎の NAS"]);
        // Second line of the notes is searchable although the row shows only the first line.
        list.set_query("バックアップ");
        assert_eq!(names(&list), vec!["書斎の NAS"]);
        list.set_query("aabbcc");
        assert_eq!(names(&list), vec!["書斎の NAS"]);
        list.set_query("00-11-22-33");
        assert_eq!(names(&list), vec!["Office-PC"]);
        list.set_query("１９２．１６８");
        assert_eq!(names(&list), vec!["書斎の NAS"]);
        list.set_query("LAB");
        assert_eq!(names(&list), vec!["Office-PC"]);
        list.set_query("zzz");
        assert_eq!(list.visible_count(), 0);
        list.set_query("  ");
        assert_eq!(list.visible_count(), 2);
    }

    #[test]
    fn group_filter_combines_with_search() {
        let mut a = host("PC1", "00:11:22:33:44:01");
        a.group = Some("Lab".into());
        let mut b = host("PC2", "00:11:22:33:44:02");
        b.group = Some("ｌａｂ".into());
        let mut c = host("NAS", "00:11:22:33:44:03");
        c.group = Some("Home".into());
        let d = host("Loose", "00:11:22:33:44:04");
        let cfg = cfg_with(vec![a, b, c, d]);
        let list = HostList::new();
        list.reconcile(&cfg, |_| RowState::default(), |_| RemoteRow::default());
        list.set_group("Lab");
        assert_eq!(names(&list), vec!["PC1", "PC2"]);
        list.set_query("pc2");
        assert_eq!(names(&list), vec!["PC2"]);
        list.set_query("");
        list.set_group("");
        assert_eq!(list.visible_count(), 4);
        list.set_group("Home");
        assert_eq!(names(&list), vec!["NAS"]);
    }

    #[test]
    fn reconcile_refilters_when_hidden_fields_change() {
        let mut a = host("PC", "00:11:22:33:44:01");
        a.notes = Some("one\ntwo".into());
        let id = a.id;
        let mut cfg = cfg_with(vec![a]);
        let list = HostList::new();
        list.reconcile(&cfg, |_| RowState::default(), |_| RemoteRow::default());
        list.set_query("two");
        assert_eq!(list.visible_count(), 1);
        cfg.get_mut(id).unwrap().notes = Some("one\nthree".into());
        list.reconcile(&cfg, |_| RowState::default(), |_| RemoteRow::default());
        assert_eq!(list.visible_count(), 0);
    }

    #[test]
    fn selected_row_sync() {
        let a = host("A", "00:11:22:33:44:01");
        let b = host("B", "00:11:22:33:44:02");
        let c = host("C", "00:11:22:33:44:03");
        let (idb, idc) = (b.id.to_string(), c.id.to_string());
        let cfg = cfg_with(vec![a, b, c]);
        let list = HostList::new();
        list.reconcile(&cfg, |_| RowState::default(), |_| RemoteRow::default());
        let (row, id) = sync_selection(&list.visible_ids(), &idc);
        assert_eq!((row, id.as_str()), (2, idc.as_str()));

        list.set_query("B");
        let (row, id) = sync_selection(&list.visible_ids(), &idb);
        assert_eq!((row, id.as_str()), (0, idb.as_str()));
        // Selection no longer visible -> cleared.
        let (row, id) = sync_selection(&list.visible_ids(), &idc);
        assert_eq!((row, id.as_str()), (-1, ""));
        let (row, id) = sync_selection(&list.visible_ids(), "");
        assert_eq!((row, id.as_str()), (-1, ""));
        assert_eq!(list.index_in_view(&idb), Some(0));
        list.remove(&idb);
        assert_eq!(list.visible_count(), 0);
        assert_eq!(list.total(), 2);
    }

    #[test]
    fn tray_entries_follow_display_order() {
        let cfg = cfg_with(vec![
            host("b", "00:11:22:33:44:01"),
            host("a", "00:11:22:33:44:02"),
            host("c", "00:11:22:33:44:03"),
        ]);
        let t = tray_hosts(&cfg, 2, |_| RowState {
            status: HostStatus::Online,
            ..RowState::default()
        });
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].name, "a");
        assert_eq!(t[1].name, "b");
        assert_eq!(t[0].status, HostStatus::Online);
    }
}
