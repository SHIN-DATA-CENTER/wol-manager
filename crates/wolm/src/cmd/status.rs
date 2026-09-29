//! `status`: probe hosts (ICMP / TCP) in parallel.

use std::time::Duration;

use serde::Serialize;
use wol_core::i18n::{Header, Msg, StatusLabel};
use wol_core::model::limits;
use wol_core::probe::{self, HostState, ProbeSpec};
use wol_core::{Error, Field, HostAddr, HostId};

use crate::cli::StatusArgs;
use crate::ctx::Ctx;
use crate::exit::{self, CmdResult};
use crate::output::table::Cell;
use crate::output::{self, Table};
use crate::util;

/// Parallel probes (plan §5.4: at most 32).
const MAX_PARALLEL: usize = 32;

/// `--timeout`: the range of `probe.timeout_ms`.
const PROBE_TIMEOUT_MS_RANGE: std::ops::RangeInclusive<Duration> =
    Duration::from_millis(*limits::PROBE_TIMEOUT_MS.start() as u64)
        ..=Duration::from_millis(*limits::PROBE_TIMEOUT_MS.end() as u64);

#[derive(Serialize)]
struct StatusView<'a> {
    label: &'a str,
    host_id: Option<HostId>,
    address: Option<String>,
    status: StatusLabel,
    #[serde(flatten)]
    state: &'a HostState,
}

fn label_of(st: &HostState) -> StatusLabel {
    match st {
        HostState::Up { .. } => StatusLabel::Online,
        HostState::Unknown => StatusLabel::NotMonitored,
        HostState::Down { .. } | HostState::Unresolved { .. } | HostState::Error { .. } => {
            StatusLabel::Offline
        }
    }
}

pub fn run(ctx: &mut Ctx, a: &StatusArgs) -> CmdResult {
    let method = a
        .probe
        .as_deref()
        .map(|v| util::parse_probe("--probe", v))
        .transpose()?;
    let ports = if a.tcp_port.is_empty() {
        None
    } else {
        Some(util::parse_ports(&a.tcp_port)?)
    };
    // The range of probe.timeout_ms: 0 would make every TCP check fail at once and report a
    // live host as offline.
    let timeout = a
        .timeout
        .as_deref()
        .map(|v| util::parse_duration_in("--timeout", v, PROBE_TIMEOUT_MS_RANGE, "100ms..=30s"))
        .transpose()?;

    let (_store, loaded) = ctx.load()?;
    let cfg = &loaded.config;
    let s = &cfg.settings;
    let mut specs: Vec<ProbeSpec> = Vec::new();
    let mut add = |spec: ProbeSpec| {
        let dup = spec.host_id.is_some() && specs.iter().any(|x| x.host_id == spec.host_id);
        if !dup {
            specs.push(spec);
        }
    };
    for q in &a.hosts {
        match cfg.find(q) {
            Ok(h) => add(ProbeSpec::for_host(h, s)),
            Err(Error::HostNotFound(_)) if wol_core::addr::parse_ipv4(q).is_ok() => {
                let ip = util::parse_ipv4(Field::Address, q)?;
                add(ProbeSpec::adhoc(HostAddr::V4(ip), s));
            }
            Err(e) => return Err(e.into()),
        }
    }
    for g in &a.group {
        let hosts = cfg.hosts_in_group(g);
        if hosts.is_empty() {
            return Err(Error::GroupNotFound(g.clone()).into());
        }
        for h in hosts {
            add(ProbeSpec::for_host(h, s));
        }
    }
    if a.all || (a.hosts.is_empty() && a.group.is_empty()) {
        for h in &cfg.hosts {
            add(ProbeSpec::for_host(h, s));
        }
    }
    for spec in &mut specs {
        if let Some(m) = method {
            spec.method = m;
        }
        if let Some(p) = &ports {
            spec.tcp_ports = p.clone();
        }
        if let Some(t) = timeout {
            spec.timeout = t;
        }
    }

    if specs.is_empty() {
        if ctx.json() {
            ctx.print_json(&Vec::<()>::new());
        } else {
            ctx.info(&ctx.t(Msg::NoHosts));
        }
        return Ok(exit::OK);
    }

    let states = probe::probe_all(&specs, MAX_PARALLEL);
    let monitored = states
        .iter()
        .filter(|s| !matches!(s, HostState::Unknown))
        .count();
    let up = states.iter().filter(|s| s.is_up()).count();
    let code = if up < monitored {
        exit::NEGATIVE
    } else {
        exit::OK
    };

    if ctx.json() {
        let v: Vec<StatusView> = specs
            .iter()
            .zip(&states)
            .map(|(sp, st)| StatusView {
                label: &sp.label,
                host_id: sp.host_id,
                address: sp.address.as_ref().map(ToString::to_string),
                status: label_of(st),
                state: st,
            })
            .collect();
        ctx.print_json(&v);
        return Ok(code);
    }

    let h = |x| ctx.t(Msg::Header(x));
    let mut t = Table::new(vec![
        h(Header::Status),
        h(Header::Name),
        h(Header::Address),
        h(Header::Result),
    ]);
    for (sp, st) in specs.iter().zip(&states) {
        let label = label_of(st);
        let style = match label {
            StatusLabel::Online => output::GREEN,
            StatusLabel::Offline => output::RED,
            _ => output::DIM,
        };
        let addr = match (st.ip(), &sp.address) {
            (Some(ip), Some(HostAddr::Name(n))) => format!("{n} ({ip})"),
            (_, Some(a)) => a.to_string(),
            (_, None) => "-".to_owned(),
        };
        t.row(vec![
            Cell::styled(ctx.t(Msg::Status(label)), style),
            Cell::styled(sp.label.clone(), output::BOLD),
            Cell::plain(addr),
            Cell::plain(ctx.t(Msg::HostState(st.clone()))),
        ]);
    }
    for l in t.lines() {
        ctx.out(&l);
    }
    ctx.info(&ctx.t(Msg::SummaryUp {
        up,
        total: monitored,
    }));
    Ok(code)
}
