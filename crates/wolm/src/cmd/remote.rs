//! `boot-time`, `remote set|clear|show|test`, and helpers shared by the remote-management
//! commands (`restart`, `shutdown`, `abort`, `mac`, `cred`, `ssh`).

use serde::Serialize;
use wol_core::i18n::{self, Header, Msg};
use wol_core::model::{RemoteDraft, SudoMode};
use wol_core::remote::{
    self, AdminCheck, BootInfo, ConnInfo, KeyFileIssue, RemoteClient, RemoteOp,
};
use wol_core::secret::{self, SecretKind, SecretState, SecretStore};
use wol_core::{Config, EditBase, Error, Field, Host, HostId, HostKeyProblem, RemoteKind};

use crate::backend::{self, Remote};
use crate::cli::{BootTimeArgs, RemoteClearArgs, RemoteCmd, RemoteHostArg, RemoteSetArgs};
use crate::ctx::Ctx;
use crate::exit::{self, CmdResult, Failure, shell_arg};
use crate::output::table::{Cell, key_values};
use crate::output::{self, Table};
use crate::text::Text;
use crate::{prompt, timefmt};

// ------------------------------------------------------------------ shared helpers

/// Looks up every query (in order, duplicates removed). The first unknown / ambiguous query
/// fails the command before anything runs.
pub fn find_hosts<'c>(cfg: &'c Config, queries: &[String]) -> Result<Vec<&'c Host>, Error> {
    let mut v: Vec<&Host> = Vec::new();
    for q in queries {
        let h = cfg.find(q)?;
        if !v.iter().any(|x| x.id == h.id) {
            v.push(h);
        }
    }
    Ok(v)
}

/// What wol-core's remote client checks before it connects: remote management set up, an
/// address, and an operation this kind supports. Run it for every host before the first
/// request, so a batch never stops halfway for a configuration problem.
pub fn precheck(ctx: &Ctx, h: &Host, op: RemoteOp) -> Result<RemoteKind, Failure> {
    let Some(r) = h.remote.as_ref() else {
        if h.unsupported_remote().is_some() {
            return Err(Failure::Usage(
                ctx.tx(Text::RemoteFromNewerVersion { label: &h.name }),
            ));
        }
        return Err(Error::RemoteNotConfigured {
            host: h.name.clone(),
        }
        .into());
    };
    if h.management_address().is_none() {
        return Err(Error::RemoteNoAddress {
            host: h.name.clone(),
        }
        .into());
    }
    let unsupported = match r.kind {
        RemoteKind::Ssh => op == RemoteOp::AbortShutdown,
        RemoteKind::Windows => matches!(op, RemoteOp::ScanHostKey | RemoteOp::HostKey),
    };
    if unsupported {
        return Err(Error::RemoteUnsupported {
            host: h.name.clone(),
            kind: r.kind,
            op,
        }
        .into());
    }
    Ok(r.kind)
}

/// Runs `f` for every item on its own thread (remote calls block for seconds); results in
/// input order.
pub fn parallel<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    if items.len() <= 1 {
        return items.iter().map(&f).collect();
    }
    std::thread::scope(|s| {
        let f = &f;
        let handles: Vec<_> = items.iter().map(|it| s.spawn(move || f(it))).collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)))
            .collect()
    })
}

/// An explicit user action for these hosts (named on the command line, or configured with
/// `remote set`): records that Windows hosts without a saved password may use the current
/// Windows sign-in at their management address, and says so once per host (cross review X2;
/// the GUI's automatic boot time only uses the sign-in for confirmed hosts). A store that
/// cannot be written only matters for those automatic fetches: noted with `-v`.
pub fn confirm_sign_in(ctx: &Ctx, client: &RemoteClient, hosts: &[&Host]) {
    for h in hosts {
        match client.confirm_sign_in(h) {
            Ok(Some(account)) => ctx.note(&ctx.tx(Text::SignInConfirmed {
                label: &h.name,
                account: &account,
            })),
            Ok(None) => {}
            Err(e) if ctx.verbose() > 0 => ctx.warn(&i18n::describe_error(&e, ctx.lang)),
            Err(_) => {}
        }
    }
}

/// Exit code of a batch: the first failure in input order, else 0.
pub fn first_code<T>(results: &[Result<T, Failure>]) -> u8 {
    results
        .iter()
        .find_map(|r| r.as_ref().err().map(Failure::exit_code))
        .unwrap_or(exit::OK)
}

/// JSON view of a failure inside a document (batches report per-host failures there).
#[derive(Debug, Serialize)]
pub struct ErrorView {
    kind: &'static str,
    message: String,
    exit_code: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_key: Option<HostKeyProblem>,
}

impl ErrorView {
    /// The view of `f` in the output language.
    pub fn of(ctx: &Ctx, f: &Failure) -> ErrorView {
        ErrorView {
            kind: f.kind(),
            message: f.message(ctx.lang),
            exit_code: f.exit_code(),
            hint: f.hint(ctx.lang),
            host_key: f.host_key().cloned(),
        }
    }
}

/// JSON view of a boot time: ISO-8601 with seconds (local with offset, and UTC).
#[derive(Debug, Serialize)]
pub struct BootView<'a> {
    /// Boot time in this PC's time zone, e.g. `2026-09-29T08:12:34+09:00`.
    boot_time: String,
    /// The same in UTC.
    boot_time_utc: String,
    boot_time_unix_ms: i64,
    uptime_secs: u64,
    source: &'a str,
    approximate: bool,
    boot_id: Option<&'a str>,
}

impl<'a> BootView<'a> {
    /// View of `b`.
    pub fn new(b: &'a BootInfo) -> BootView<'a> {
        BootView {
            boot_time: timefmt::iso_local(b.boot_time),
            boot_time_utc: timefmt::iso_utc(b.boot_time),
            boot_time_unix_ms: timefmt::unix_ms(b.boot_time),
            uptime_secs: b.uptime.as_secs(),
            source: &b.source,
            approximate: b.approximate,
            boot_id: b.boot_id.as_deref(),
        }
    }
}

/// `2026-09-29 08:12:34` (+ "approx." marker).
pub fn boot_text(ctx: &Ctx, b: &BootInfo) -> String {
    let mut s = timefmt::local_display(b.boot_time);
    if b.approximate {
        s.push_str(&ctx.tx(Text::Approximate));
    }
    s
}

/// A pinned SSH host key (public data).
#[derive(Debug, Serialize)]
pub struct HostKeyView {
    algorithm: String,
    fingerprint: String,
}

/// JSON view of `[hosts.remote]` (never a secret; the host key as algorithm + fingerprint).
#[derive(Debug, Serialize)]
pub struct RemoteView<'a> {
    kind: RemoteKind,
    user: Option<&'a str>,
    address: Option<String>,
    effective_address: Option<String>,
    port: Option<u16>,
    key_file: Option<String>,
    sudo: Option<SudoMode>,
    host_key: Option<HostKeyView>,
    reboot_command: Option<&'a str>,
    shutdown_command: Option<&'a str>,
}

impl<'a> RemoteView<'a> {
    /// View of the host's remote management (`None` when not managed).
    pub fn of(h: &'a Host) -> Option<RemoteView<'a>> {
        let r = h.remote.as_ref()?;
        let ssh = r.kind == RemoteKind::Ssh;
        Some(RemoteView {
            kind: r.kind,
            user: r.user(),
            address: r.address.as_ref().map(ToString::to_string),
            effective_address: h.management_address().map(ToString::to_string),
            port: ssh.then(|| r.ssh_port()),
            key_file: r
                .key_file
                .as_ref()
                .filter(|p| !p.as_os_str().is_empty())
                .map(|p| p.display().to_string()),
            sudo: ssh.then_some(r.sudo),
            host_key: r
                .host_key()
                .and_then(|k| remote::parse_host_key(k).ok())
                .map(|k| HostKeyView {
                    algorithm: k.algorithm,
                    fingerprint: k.fingerprint,
                }),
            reboot_command: r.reboot_command.as_deref(),
            shutdown_command: r.shutdown_command.as_deref(),
        })
    }
}

/// Asks for confirmation. `Ok(true)`: go ahead (`--yes`, or "y" on the console);
/// `Ok(false)`: declined (the caller exits 1); stdin not a console without `--yes`: exit 2.
/// `lines` are shown before the question (stderr, also with `-q` / `--json`).
pub fn confirm(ctx: &Ctx, yes: bool, lines: &[String]) -> Result<bool, Failure> {
    if yes {
        return Ok(true);
    }
    if !ctx.interactive() {
        return Err(Failure::Usage(ctx.tx(Text::ConfirmNeedsYes)));
    }
    for l in lines {
        ctx.ask_line(l);
    }
    if prompt::confirm(&ctx.tx(Text::ContinuePrompt)) {
        Ok(true)
    } else {
        ctx.warn(&ctx.tx(Text::Declined));
        Ok(false)
    }
}

// ------------------------------------------------------------------ boot-time

#[derive(Serialize)]
struct BootEntry<'a> {
    host: &'a str,
    id: HostId,
    kind: Option<RemoteKind>,
    ok: bool,
    boot: Option<BootView<'a>>,
    error: Option<ErrorView>,
}

pub fn boot_time(ctx: &mut Ctx, a: &BootTimeArgs) -> CmdResult {
    let (_store, loaded) = ctx.load()?;
    let cfg = &loaded.config;
    let s = &cfg.settings;
    let all = a.hosts.is_empty();
    let hosts: Vec<&Host> = if all {
        let v: Vec<&Host> = cfg.hosts.iter().filter(|h| h.remote.is_some()).collect();
        if v.is_empty() {
            return Err(Failure::NotFound(ctx.tx(Text::NoManagedHosts)));
        }
        v
    } else {
        find_hosts(cfg, &a.hosts)?
    };
    for h in &hosts {
        precheck(ctx, h, RemoteOp::BootTime)?;
    }
    let remote = Remote::new()?;
    // Named hosts: the user asked for them. Without names (every managed host, maybe from a
    // scheduled task), a Windows host that would use this user's sign-in is only contacted
    // when that was confirmed for its address, like the app's automatic boot time (X2).
    if !all {
        confirm_sign_in(ctx, remote.client(), &hosts);
    }
    let results: Vec<Result<BootInfo, Failure>> = parallel(&hosts, |h| {
        if all {
            remote.client().check_sign_in(h, RemoteOp::BootTime)?;
        }
        remote.boot_time(h, s).map_err(Failure::from)
    });
    let code = first_code(&results);
    if ctx.json() {
        let v: Vec<BootEntry> = hosts
            .iter()
            .zip(&results)
            .map(|(h, r)| BootEntry {
                host: &h.name,
                id: h.id,
                kind: h.remote_kind(),
                ok: r.is_ok(),
                boot: r.as_ref().ok().map(BootView::new),
                error: r.as_ref().err().map(|f| ErrorView::of(ctx, f)),
            })
            .collect();
        ctx.print_json(&v);
        return Ok(code);
    }
    let hd = |x| ctx.t(Msg::Header(x));
    let verbose = ctx.verbose() > 0;
    let mut headers = vec![hd(Header::Name), hd(Header::Boot), hd(Header::Uptime)];
    if verbose {
        headers.push(hd(Header::Source));
    }
    let mut t = Table::new(headers);
    let mut any = false;
    for (h, r) in hosts.iter().zip(&results) {
        if let Ok(b) = r {
            any = true;
            let mut row = vec![
                Cell::styled(h.name.clone(), output::BOLD),
                Cell::plain(boot_text(ctx, b)),
                Cell::plain(i18n::format_uptime(ctx.lang, b.uptime)),
            ];
            if verbose {
                row.push(Cell::styled(b.source.clone(), output::DIM));
            }
            t.row(row);
        }
    }
    if any {
        for l in t.lines() {
            ctx.out(&l);
        }
    }
    for r in &results {
        if let Err(f) = r {
            ctx.report(f);
        }
    }
    Ok(code)
}

// ------------------------------------------------------------------ remote set / clear / show / test

pub fn run(ctx: &mut Ctx, c: &RemoteCmd) -> CmdResult {
    match c {
        RemoteCmd::Set(a) => set(ctx, a),
        RemoteCmd::Clear(a) => clear(ctx, a),
        RemoteCmd::Show(a) => show(ctx, a),
        RemoteCmd::Test(a) => test(ctx, a),
    }
}

fn parse_kind(v: &str) -> Result<RemoteKind, Error> {
    v.parse::<RemoteKind>().map_err(|_| Error::InvalidSetting {
        key: "--kind".to_owned(),
        value: v.to_owned(),
        expected: "windows | ssh".to_owned(),
    })
}

fn parse_sudo(v: &str) -> Result<SudoMode, Error> {
    v.parse::<SudoMode>().map_err(|_| Error::InvalidSetting {
        key: "--sudo".to_owned(),
        value: v.to_owned(),
        expected: "auto | root | nopasswd | password | separate".to_owned(),
    })
}

/// A key file as stored: quotes removed, made absolute (the app runs in another folder).
/// A network (UNC) path is refused here (wol-core never reads one; cross review m4), a `.pub`
/// or missing file is a warning.
fn key_file_text(ctx: &Ctx, input: &str) -> Result<String, Failure> {
    let cleaned = wol_core::model::clean_key_file(input);
    if cleaned.is_empty() {
        return Ok(cleaned);
    }
    let raw = std::path::Path::new(&cleaned);
    if remote::key_file_issue(raw) == Some(KeyFileIssue::NetworkPath) {
        return Err(Failure::Usage(
            ctx.tx(Text::KeyFileOnNetwork { path: &cleaned }),
        ));
    }
    let p = std::path::absolute(&cleaned).unwrap_or_else(|_| cleaned.clone().into());
    let shown = p.display().to_string();
    match remote::key_file_issue(&p) {
        Some(KeyFileIssue::NetworkPath) => {
            return Err(Failure::Usage(
                ctx.tx(Text::KeyFileOnNetwork { path: &shown }),
            ));
        }
        Some(KeyFileIssue::PublicKey) => ctx.warn(&ctx.tx(Text::KeyFileIsPublic { path: &shown })),
        Some(KeyFileIssue::Missing) => ctx.warn(&ctx.tx(Text::KeyFileMissing { path: &shown })),
        None => {}
    }
    Ok(shown)
}

#[derive(Serialize)]
struct HostRemoteDoc<'a> {
    changed: bool,
    host: &'a str,
    id: HostId,
    remote: Option<RemoteView<'a>>,
}

fn set(ctx: &mut Ctx, a: &RemoteSetArgs) -> CmdResult {
    let kind = a.kind.as_deref().map(parse_kind).transpose()?;
    let sudo = a.sudo.as_deref().map(parse_sudo).transpose()?;
    let (store, loaded) = ctx.load()?;
    let cfg = &loaded.config;
    let host = cfg.find(&a.host)?;
    let base = EditBase::of(host);
    let mut d = base.draft.clone();
    let Some(kind) = kind.or(d.remote.kind) else {
        return Err(Failure::Usage(
            ctx.tx(Text::RemoteSetNeedsKind { label: &host.name }),
        ));
    };
    let ssh_only = a.port.is_some()
        || a.key_file.is_some()
        || a.sudo.is_some()
        || a.reboot_command.is_some()
        || a.shutdown_command.is_some();
    if kind == RemoteKind::Windows && ssh_only {
        return Err(Failure::Usage(ctx.tx(Text::SshOnlyFlags)));
    }
    let r = &mut d.remote;
    r.kind = Some(kind);
    if let Some(v) = &a.user {
        r.user = v.clone();
    }
    if let Some(v) = &a.address {
        r.address = v.clone();
    }
    if let Some(v) = &a.port {
        r.port = v.clone();
    }
    if let Some(v) = &a.key_file {
        r.key_file = key_file_text(ctx, v)?;
    }
    if let Some(m) = sudo {
        r.sudo = m;
    }
    if let Some(v) = &a.reboot_command {
        r.reboot_command = v.clone();
    }
    if let Some(v) = &a.shutdown_command {
        r.shutdown_command = v.clone();
    }
    let clears: [(bool, &mut String); 6] = [
        (a.clear_user, &mut r.user),
        (a.clear_address, &mut r.address),
        (a.clear_port, &mut r.port),
        (a.clear_key_file, &mut r.key_file),
        (a.clear_reboot_command, &mut r.reboot_command),
        (a.clear_shutdown_command, &mut r.shutdown_command),
    ];
    for (clear, field) in clears {
        if clear {
            field.clear();
        }
    }
    let unchanged = |ctx: &Ctx, cfg: &Config| -> CmdResult {
        if let Some(h) = cfg.get(base.id) {
            // Still an explicit "this host is set up like this" (e.g. after the hint of an
            // unconfirmed sign-in).
            confirm_sign_in(ctx, &backend::client(), &[h]);
        }
        if ctx.json() {
            if let Some(h) = cfg.get(base.id) {
                ctx.print_json(&HostRemoteDoc {
                    changed: false,
                    host: &h.name,
                    id: h.id,
                    remote: RemoteView::of(h),
                });
            }
        } else {
            ctx.info(&ctx.t(Msg::NoChanges));
        }
        Ok(exit::NEGATIVE)
    };
    if d == base.draft {
        return unchanged(ctx, cfg);
    }
    // A newer version's remote table (kept in the file) is replaced as a whole: ask first
    // (cross review m12).
    if host.unsupported_remote().is_some() {
        let lines = [ctx.tx(Text::RemoteSetReplacesNewer { label: &host.name })];
        if !confirm(ctx, a.yes, &lines)? {
            return Ok(exit::NEGATIVE);
        }
    }
    let up = store.update(|c| c.save_draft(&d, Some(&base)))?;
    if !up.written {
        return unchanged(ctx, &up.config);
    }
    let h = up
        .config
        .get(up.value)
        .ok_or(Error::HostIdNotFound(up.value))?;
    after_connection_edit(ctx, host, h, true);
    if ctx.json() {
        ctx.print_json(&HostRemoteDoc {
            changed: true,
            host: &h.name,
            id: h.id,
            remote: RemoteView::of(h),
        });
    } else {
        ctx.info(&ctx.t(Msg::HostUpdated {
            name: h.name.clone(),
        }));
        for l in describe(ctx, h, None) {
            ctx.out(&l);
        }
        next_steps(ctx, h);
    }
    Ok(exit::OK)
}

/// After the USER changed a managed host (`remote set`, `edit`; never after an import): stored
/// passwords are bound to the connection. When only the address or SSH port changed they follow
/// the host (same kind and account); anything else leaves them unused, which is reported.
/// With `confirm` (`remote set`, or an edit that moved the management address), a Windows host
/// without a saved password is confirmed for the current Windows sign-in at its (new) address.
pub fn after_connection_edit(ctx: &Ctx, before: &Host, after: &Host, confirm: bool) {
    if after.remote.is_none() {
        return;
    }
    let secrets = backend::secret_store();
    if let Err(e) = secrets.rebind(before, after) {
        ctx.warn(&i18n::describe_error(&e, ctx.lang));
    }
    if confirm {
        confirm_sign_in(ctx, &backend::client(), &[after]);
    }
    for (kind, st) in secret_states(&secrets, after) {
        if let Ok(SecretState::Stale { stored_for }) = st {
            ctx.warn(&ctx.tx(Text::SecretStale {
                label: &after.name,
                kind,
                stored_for: &stored_for,
            }));
        }
    }
}

/// Notes after `remote set`: what is still missing before the first operation.
fn next_steps(ctx: &Ctx, h: &Host) {
    let Some(r) = &h.remote else { return };
    let arg = shell_arg(&h.name);
    let has_login = matches!(
        backend::secret_store().state(h, SecretKind::Login),
        Ok(SecretState::Usable)
    );
    match r.kind {
        RemoteKind::Ssh => {
            if r.host_key().is_none() {
                ctx.note(&ctx.tx(Text::NextTrust { host: &arg }));
            }
            if r.key_file.is_none() && !has_login {
                ctx.note(&ctx.tx(Text::NextCredSet { host: &arg }));
            }
        }
        RemoteKind::Windows => match r.user() {
            // Another account than this sign-in: nothing works until its password is stored.
            Some(u) if !has_login && !remote::is_current_windows_account(u) => {
                ctx.note(&ctx.tx(Text::NextCredSetAccount {
                    account: u,
                    host: &arg,
                }));
            }
            None if !has_login => {
                let account = remote::current_windows_account().unwrap_or_default();
                ctx.note(&ctx.tx(Text::NextCredSetWindows {
                    host: &arg,
                    account: &account,
                }));
            }
            _ => {}
        },
    }
    ctx.note(&ctx.tx(Text::NextTest { host: &arg }));
}

/// `login password` → `Login password` (labels; Japanese is unchanged).
fn capitalized(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// `label  value` lines of a host's remote management (and the stored secrets when known).
/// Whether each stored password of `h` is usable (bound to its current connection).
fn secret_states(secrets: &SecretStore, h: &Host) -> Vec<(SecretKind, Result<SecretState, Error>)> {
    SecretKind::ALL
        .iter()
        .map(|k| (*k, secrets.state(h, *k)))
        .collect()
}

/// The Windows account used when `remote.user` is empty (review R4): the one stored with
/// the login password, else this PC's sign-in.
fn windows_user_line(ctx: &Ctx, h: &Host) -> String {
    let stored = backend::secret_store().list().ok().and_then(|l| {
        l.into_iter()
            .find(|e| e.host_id == h.id && e.kind == SecretKind::Login)
            .map(|e| e.user)
    });
    match stored.filter(|a| !a.is_empty()) {
        Some(account) => ctx.tx(Text::WindowsUserStored { account: &account }),
        None => match remote::current_windows_account() {
            Some(account) => ctx.tx(Text::WindowsUserSignIn { account: &account }),
            None => ctx.tx(Text::DefaultWindowsUser),
        },
    }
}

fn describe(
    ctx: &Ctx,
    h: &Host,
    secrets: Option<&[(SecretKind, Result<SecretState, Error>)]>,
) -> Vec<String> {
    let Some(r) = &h.remote else {
        return vec![ctx.t(Msg::RemoteNotSetUp)];
    };
    let f = |x| ctx.t(Msg::Field(x));
    let mut pairs = vec![(f(Field::RemoteKind), ctx.t(Msg::RemoteKindName(r.kind)))];
    let user = match (r.user(), r.kind) {
        (Some(u), _) => u.to_owned(),
        (None, RemoteKind::Windows) => windows_user_line(ctx, h),
        (None, RemoteKind::Ssh) => format!("{}{}", r.ssh_user(), ctx.tx(Text::Default)),
    };
    pairs.push((f(Field::RemoteUser), user));
    let address = match (&r.address, h.management_address()) {
        (Some(a), _) => a.to_string(),
        (None, Some(a)) => ctx.tx(Text::SameAsAddress {
            address: &a.to_string(),
        }),
        (None, None) => "-".to_owned(),
    };
    pairs.push((f(Field::RemoteAddress), address));
    if r.kind == RemoteKind::Ssh {
        pairs.push((
            f(Field::SshPort),
            if r.port.is_some_and(|p| p != 0) {
                r.ssh_port().to_string()
            } else {
                format!("{}{}", r.ssh_port(), ctx.tx(Text::Default))
            },
        ));
        pairs.push((
            f(Field::SshKeyFile),
            r.key_file
                .as_ref()
                .filter(|p| !p.as_os_str().is_empty())
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| ctx.tx(Text::PasswordLogin)),
        ));
        pairs.push((f(Field::SshSudo), ctx.t(Msg::SudoModeName(r.sudo))));
        let key = match r.host_key().map(remote::parse_host_key) {
            Some(Ok(k)) => format!("{} {}", k.algorithm, k.fingerprint),
            Some(Err(_)) => ctx.t(Msg::FieldIssue(wol_core::FieldIssue::InvalidHostKey)),
            None => ctx.tx(Text::NotTrustedYet),
        };
        pairs.push((f(Field::SshHostKey), key));
        for (field, cmd) in [
            (Field::RebootCommand, &r.reboot_command),
            (Field::ShutdownCommand, &r.shutdown_command),
        ] {
            if let Some(c) = cmd.as_deref().filter(|c| !c.trim().is_empty()) {
                pairs.push((f(field), c.to_owned()));
            }
        }
    }
    for (k, st) in secrets.unwrap_or_default() {
        // Windows hosts only use the login password; show the others only when stored.
        let shown = r.kind == RemoteKind::Ssh
            || *k == SecretKind::Login
            || !matches!(st, Ok(SecretState::Missing));
        if !shown {
            continue;
        }
        let v = match st {
            Ok(SecretState::Usable) => ctx.tx(Text::Stored),
            Ok(SecretState::Stale { stored_for }) => ctx.tx(Text::StoredForOther { stored_for }),
            Ok(_) => ctx.tx(Text::NotStored),
            Err(e) => ctx.tx(Text::Unknown {
                reason: &i18n::describe_error(e, ctx.lang),
            }),
        };
        pairs.push((capitalized(&ctx.t(Msg::SecretKindName(*k))), v));
    }
    key_values(&pairs, 0)
}

/// `remote show --json`: per secret `{"state": "usable" | "stale" | "missing"}` (stale with
/// `stored_for`); `null` when Credential Manager could not be read.
#[derive(Serialize)]
struct SecretsView {
    login: Option<SecretState>,
    key_passphrase: Option<SecretState>,
    sudo: Option<SecretState>,
}

impl SecretsView {
    fn of(states: &[(SecretKind, Result<SecretState, Error>)]) -> SecretsView {
        let get = |kind: SecretKind| {
            states
                .iter()
                .find(|(k, _)| *k == kind)
                .and_then(|(_, s)| s.as_ref().ok().cloned())
        };
        SecretsView {
            login: get(SecretKind::Login),
            key_passphrase: get(SecretKind::KeyPassphrase),
            sudo: get(SecretKind::Sudo),
        }
    }
}

fn show(ctx: &mut Ctx, a: &RemoteHostArg) -> CmdResult {
    let (_store, loaded) = ctx.load()?;
    let h = loaded.config.find(&a.host)?;
    let states = secret_states(&backend::secret_store(), h);
    let code = if h.remote.is_some() {
        exit::OK
    } else {
        exit::NEGATIVE
    };
    if ctx.json() {
        #[derive(Serialize)]
        struct Doc<'a> {
            host: &'a str,
            id: HostId,
            remote: Option<RemoteView<'a>>,
            secrets: SecretsView,
        }
        ctx.print_json(&Doc {
            host: &h.name,
            id: h.id,
            remote: RemoteView::of(h),
            secrets: SecretsView::of(&states),
        });
        return Ok(code);
    }
    if h.remote.is_none() {
        if h.unsupported_remote().is_some() {
            ctx.info(&ctx.tx(Text::RemoteFromNewerVersion { label: &h.name }));
        } else {
            ctx.info(&ctx.t(Msg::RemoteNotSetUp));
        }
        return Ok(code);
    }
    for l in describe(ctx, h, Some(&states)) {
        ctx.out(&l);
    }
    Ok(code)
}

fn clear(ctx: &mut Ctx, a: &RemoteClearArgs) -> CmdResult {
    let (store, loaded) = ctx.load()?;
    let h = loaded.config.find(&a.host)?;
    let secrets = backend::secret_store();
    let stored = secrets
        .status(h.id)
        .map(|s| s.login || s.key_passphrase || s.sudo)
        .unwrap_or(false);
    let managed = h.remote.is_some();
    let doc = |ctx: &Ctx, changed: bool, deleted: usize| {
        if ctx.json() {
            #[derive(Serialize)]
            struct Doc<'a> {
                host: &'a str,
                id: HostId,
                changed: bool,
                secrets_deleted: usize,
            }
            ctx.print_json(&Doc {
                host: &h.name,
                id: h.id,
                changed,
                secrets_deleted: deleted,
            });
        }
    };
    if !managed && !stored {
        if h.unsupported_remote().is_some() {
            ctx.info(&ctx.tx(Text::RemoteFromNewerVersion { label: &h.name }));
        } else {
            ctx.info(&ctx.tx(Text::NothingToClear { label: &h.name }));
        }
        doc(ctx, false, 0);
        return Ok(exit::NEGATIVE);
    }
    // A newer version's table stays as it is (this version cannot edit it); only the
    // passwords go (cross review m11).
    let lines = if !managed && h.unsupported_remote().is_some() {
        [ctx.tx(Text::RemoteClearSecretsOnly { label: &h.name })]
    } else {
        [ctx.tx(Text::RemoteClearConfirm { label: &h.name })]
    };
    if !confirm(ctx, a.yes, &lines)? {
        return Ok(exit::NEGATIVE);
    }
    let mut changed = false;
    if managed {
        let base = EditBase::of(h);
        let mut d = base.draft.clone();
        d.remote = RemoteDraft::default();
        let up = store.update(|c| c.save_draft(&d, Some(&base)))?;
        changed = up.written;
    }
    // After the config change (a failure there must not lose the passwords).
    let deleted = secret::forget_host(&secrets, h.id);
    if !ctx.json() {
        if changed {
            ctx.info(&ctx.tx(Text::RemoteCleared { label: &h.name }));
        }
        if deleted > 0 {
            ctx.info(&ctx.tx(Text::SecretsDeleted { count: deleted }));
        }
    }
    doc(ctx, changed, deleted);
    Ok(exit::OK)
}

#[derive(Serialize)]
struct TestDoc<'a> {
    host: &'a str,
    id: HostId,
    kind: RemoteKind,
    address: Option<String>,
    os: Option<&'a str>,
    kernel: Option<&'a str>,
    user: Option<&'a str>,
    admin_hint: Option<bool>,
    admin_check: AdminCheck,
    boot: BootView<'a>,
}

fn test(ctx: &mut Ctx, a: &RemoteHostArg) -> CmdResult {
    let (_store, loaded) = ctx.load()?;
    let cfg = &loaded.config;
    let h = cfg.find(&a.host)?;
    let kind = precheck(ctx, h, RemoteOp::TestConnection)?;
    let remote = Remote::new()?;
    confirm_sign_in(ctx, remote.client(), &[h]);
    let info: ConnInfo = remote.test_connection(h, &cfg.settings)?;
    if ctx.json() {
        ctx.print_json(&TestDoc {
            host: &h.name,
            id: h.id,
            kind,
            address: h.management_address().map(ToString::to_string),
            os: info.os.as_deref(),
            kernel: info.kernel.as_deref(),
            user: info.user.as_deref(),
            admin_hint: info.admin_hint,
            admin_check: info.admin_check,
            boot: BootView::new(&info.boot),
        });
        return Ok(exit::OK);
    }
    ctx.out(&output::paint(
        output::GREEN,
        &ctx.t(Msg::RemoteTestOk {
            label: h.name.clone(),
            os: info.os.clone(),
        }),
    ));
    let mut pairs: Vec<(String, String)> = Vec::new();
    if let Some(os) = &info.os {
        pairs.push(("OS".to_owned(), os.clone()));
    }
    if let Some(k) = &info.kernel {
        pairs.push((ctx.tx(Text::Kernel), k.clone()));
    }
    if let Some(u) = &info.user {
        pairs.push((ctx.tx(Text::UserLabel), u.clone()));
    }
    pairs.push((ctx.tx(Text::BootedLabel), boot_text(ctx, &info.boot)));
    pairs.push((
        ctx.tx(Text::UptimeLabel),
        i18n::format_uptime(ctx.lang, info.boot.uptime),
    ));
    if ctx.verbose() > 0 {
        pairs.push((ctx.tx(Text::SourceLabel), info.boot.source.clone()));
    }
    for l in key_values(&pairs, 2) {
        ctx.out(&l);
    }
    // Review R3: UAC-filtered token, firewall or unknown, each with its own advice.
    match info.admin_check.note() {
        Some((true, msg)) => ctx.warn(&ctx.t(msg)),
        Some((false, msg)) => ctx.note(&ctx.t(msg)),
        None => {}
    }
    Ok(exit::OK)
}
