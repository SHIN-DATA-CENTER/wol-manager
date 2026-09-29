//! `cred set|delete|list|prune`: passwords for remote management in Windows Credential
//! Manager. Passwords are never taken as arguments and never printed.

use serde::Serialize;
use wol_core::i18n::{Header, Msg};
use wol_core::model::{SCHEMA_VERSION, SudoMode, check_remote_user};
use wol_core::remote;
use wol_core::secret::{self, SecretEntry, SecretKind, SecretState};
use wol_core::{Error, Field, HostId, RemoteKind};
use zeroize::Zeroizing;

use super::remote::confirm;
use crate::backend;
use crate::cli::{CredCmd, CredDeleteArgs, CredPruneArgs, CredSetArgs};
use crate::ctx::Ctx;
use crate::exit::{self, CmdResult, Failure};
use crate::output::table::Cell;
use crate::output::{self, Table};
use crate::prompt;
use crate::text::Text;

pub fn run(ctx: &mut Ctx, c: &CredCmd) -> CmdResult {
    match c {
        CredCmd::Set(a) => set(ctx, a),
        CredCmd::Delete(a) => delete(ctx, a),
        CredCmd::List => list(ctx),
        CredCmd::Prune(a) => prune(ctx, a),
    }
}

fn parse_kind(v: &str) -> Result<SecretKind, Error> {
    v.parse::<SecretKind>().map_err(|_| Error::InvalidSetting {
        key: "--kind".to_owned(),
        value: v.to_owned(),
        expected: "login | key-passphrase | sudo".to_owned(),
    })
}

/// The password: `--password-stdin`, else asked twice on the console (hidden).
fn read_secret(
    ctx: &Ctx,
    a: &CredSetArgs,
    label: &str,
    kind: SecretKind,
    account: &str,
) -> Result<Zeroizing<String>, Failure> {
    if a.password_stdin {
        return prompt::read_secret_stdin()
            .map_err(|error| Failure::Usage(ctx.tx(Text::StdinSecret { error })));
    }
    if !ctx.interactive() {
        return Err(Failure::Usage(ctx.tx(Text::PasswordNeedsConsole)));
    }
    let io = |e: std::io::Error| Failure::from(Error::io("read password", None, e));
    let prompt_text = ctx.tx(Text::PasswordPrompt {
        label,
        kind,
        account,
    });
    let first = prompt::password(&prompt_text).map_err(io)?;
    if first.is_empty() {
        return Err(Failure::Usage(ctx.tx(Text::StdinSecret {
            error: prompt::StdinSecretError::Empty,
        })));
    }
    let second = prompt::password(&ctx.tx(Text::PasswordAgain)).map_err(io)?;
    if *first != *second {
        return Err(Failure::Usage(ctx.tx(Text::PasswordMismatch)));
    }
    Ok(first)
}

fn set(ctx: &mut Ctx, a: &CredSetArgs) -> CmdResult {
    let kind = parse_kind(&a.kind)?;
    let (store, loaded) = ctx.load()?;
    let h = loaded.config.find(&a.host)?;
    let r = h
        .remote
        .as_ref()
        .ok_or_else(|| Error::RemoteNotConfigured {
            host: h.name.clone(),
        })?;
    if r.kind == RemoteKind::Windows && kind != SecretKind::Login {
        return Err(Failure::Usage(ctx.tx(Text::CredKindNeedsSsh {
            label: &h.name,
            kind,
        })));
    }
    // The password is stored under the host id: an id that config.toml does not have yet (a
    // hand-edited file) would change when hosts are reordered, orphaning the password. Write
    // such ids first; refuse only when the file cannot be written (read-only, newer version).
    let ids = store.persist_assigned_ids()?;
    if !ids.value.is_saved(h.id) {
        return Err(Failure::Usage(
            ctx.tx(Text::HostIdNotSaved { label: &h.name }),
        ));
    }
    let cfg = ids.config;
    let h = cfg.get(h.id).ok_or(Error::HostIdNotFound(h.id))?;
    let r = h
        .remote
        .as_ref()
        .ok_or_else(|| Error::RemoteNotConfigured {
            host: h.name.clone(),
        })?;
    // The account the password is stored for (what `SecretStore::set_for_host` stores): SSH
    // the login user; Windows the host's remote user, else --user, else the current sign-in.
    let given = a
        .user
        .as_deref()
        .map(|u| check_remote_user(u, r.kind).map_err(|i| Error::invalid(Field::RemoteUser, i, u)))
        .transpose()?
        .filter(|u| !u.is_empty());
    let account = match r.kind {
        RemoteKind::Ssh => r.ssh_user().to_owned(),
        RemoteKind::Windows => r
            .user()
            .map(str::to_owned)
            .or_else(|| given.clone())
            .or_else(remote::current_windows_account)
            .unwrap_or_default(),
    };
    if let Some(u) = &given
        && !secret::same_account(r.kind, u, &account)
    {
        ctx.warn(&ctx.tx(Text::CredUserIgnored { user: &account }));
    }
    match kind {
        SecretKind::Sudo if !matches!(r.sudo, SudoMode::Auto | SudoMode::Separate) => {
            ctx.warn(&ctx.tx(Text::SudoSecretUnused {
                mode: &ctx.t(Msg::SudoModeName(r.sudo)),
            }));
        }
        SecretKind::KeyPassphrase if r.key_file.is_none() => {
            ctx.warn(&ctx.tx(Text::PassphraseUnused));
        }
        _ => {}
    }
    // Review R4: a Windows host without a user name stores the password for this PC's own
    // sign-in account; say so before asking (the target's admin often has another name).
    if r.kind == RemoteKind::Windows && r.user().is_none() && given.is_none() && !account.is_empty()
    {
        ctx.note(&ctx.tx(Text::CredDefaultAccount {
            account: &account,
            host: &crate::exit::shell_arg(&h.name),
        }));
    }
    // The key passphrase is not bound to an account.
    let shown_account = if kind.is_bound() {
        account.as_str()
    } else {
        ""
    };
    let secret = read_secret(ctx, a, &h.name, kind, shown_account)?;
    let secrets = backend::secret_store();
    // Bound to the host's kind, management address, SSH port and account: remote operations
    // never send it anywhere else.
    let user = secrets.set_for_host(h, kind, given.as_deref().unwrap_or(""), &secret)?;
    drop(secret);
    if ctx.json() {
        #[derive(Serialize)]
        struct Doc<'a> {
            host: &'a str,
            id: HostId,
            kind: SecretKind,
            user: &'a str,
            stored: bool,
        }
        ctx.print_json(&Doc {
            host: &h.name,
            id: h.id,
            kind,
            user: &user,
            stored: true,
        });
    } else {
        ctx.info(&ctx.tx(Text::CredSaved {
            label: &h.name,
            kind,
            account: if kind.is_bound() { &user } else { "" },
        }));
        if ctx.verbose() > 0 {
            ctx.note(&ctx.t(Msg::SecretsStorageNote));
        }
    }
    Ok(exit::OK)
}

fn delete(ctx: &mut Ctx, a: &CredDeleteArgs) -> CmdResult {
    let kind = a.kind.as_deref().map(parse_kind).transpose()?;
    let (_store, loaded) = ctx.load()?;
    // A removed host's secrets can still be deleted by its full id.
    let (id, label) = match loaded.config.find(&a.host) {
        Ok(h) => (h.id, h.name.clone()),
        Err(Error::HostNotFound(q)) => match HostId::parse_str(a.host.trim()) {
            Ok(id) => (id, id.to_string()),
            Err(_) => return Err(Error::HostNotFound(q).into()),
        },
        Err(e) => return Err(e.into()),
    };
    let secrets = backend::secret_store();
    let kinds: Vec<SecretKind> = match kind {
        Some(k) => vec![k],
        None => SecretKind::ALL.to_vec(),
    };
    let mut deleted: Vec<SecretKind> = Vec::new();
    for k in kinds {
        if secrets.delete(id, k)? {
            deleted.push(k);
        }
    }
    if ctx.json() {
        #[derive(Serialize)]
        struct Doc<'a> {
            host: &'a str,
            id: HostId,
            deleted: &'a [SecretKind],
        }
        ctx.print_json(&Doc {
            host: &label,
            id,
            deleted: &deleted,
        });
    } else if deleted.is_empty() {
        ctx.info(&match kind {
            Some(k) => ctx.t(Msg::SecretNotStored {
                label: label.clone(),
                kind: k,
            }),
            None => ctx.tx(Text::NoSecretsFor { label: &label }),
        });
    } else {
        for k in &deleted {
            ctx.info(&ctx.t(Msg::SecretDeleted {
                label: label.clone(),
                kind: *k,
            }));
        }
    }
    Ok(if deleted.is_empty() {
        exit::NEGATIVE
    } else {
        exit::OK
    })
}

/// One stored secret with its host (never the secret itself).
#[derive(Serialize)]
struct EntryView<'a> {
    host_id: HostId,
    /// `null` for a host that is not in these settings.
    host: Option<&'a str>,
    kind: SecretKind,
    user: &'a str,
    /// The host is not in these settings (a removed host, or one of another settings
    /// folder): a `cred prune` candidate.
    orphan: bool,
    /// `usable`, or `stale` (saved for another kind / address / port / account: not used);
    /// `null` for orphans and when it could not be read.
    state: Option<SecretState>,
    /// The host exists but has no remote management (the secret is not used; review R9).
    #[serde(skip)]
    unmanaged: bool,
}

fn entry_views<'a>(
    cfg: &'a wol_core::Config,
    entries: &'a [SecretEntry],
    secrets: Option<&secret::SecretStore>,
) -> Vec<EntryView<'a>> {
    entries
        .iter()
        .map(|e| {
            let h = cfg.get(e.host_id);
            EntryView {
                host_id: e.host_id,
                host: h.map(|h| h.name.as_str()),
                kind: e.kind,
                user: &e.user,
                orphan: h.is_none(),
                state: h.zip(secrets).and_then(|(h, s)| s.state(h, e.kind).ok()),
                unmanaged: h.is_some_and(|h| h.remote.is_none()),
            }
        })
        .collect()
}

fn print_entries(ctx: &Ctx, views: &[EntryView<'_>]) {
    let hd = |x| ctx.t(Msg::Header(x));
    let verbose = ctx.verbose() > 0;
    let mut headers = vec![
        hd(Header::Name),
        hd(Header::Kind),
        hd(Header::User),
        String::new(),
    ];
    if verbose {
        headers.push(hd(Header::Id));
    }
    let mut t = Table::new(headers);
    for v in views {
        let name = match v.host {
            Some(n) => Cell::styled(n, output::BOLD),
            None => Cell::styled(ctx.tx(Text::RemovedHost), output::DIM),
        };
        let host_arg = v.host.map(crate::exit::shell_arg).unwrap_or_default();
        let note = match &v.state {
            // Review R9: `cred set` cannot fix this one (no remote management).
            _ if v.unmanaged => Cell::styled(
                ctx.tx(Text::StoredUnmanaged { host: &host_arg }),
                output::YELLOW,
            ),
            Some(SecretState::Stale { stored_for }) => {
                Cell::styled(ctx.tx(Text::StoredForOther { stored_for }), output::YELLOW)
            }
            _ => Cell::plain(""),
        };
        let mut row = vec![
            name,
            Cell::plain(ctx.t(Msg::SecretKindName(v.kind))),
            Cell::plain(if v.user.is_empty() { "-" } else { v.user }),
            note,
        ];
        if verbose {
            row.push(Cell::styled(v.host_id.to_string(), output::DIM));
        }
        t.row(row);
    }
    for l in t.lines() {
        ctx.out(&l);
    }
}

fn list(ctx: &mut Ctx) -> CmdResult {
    let (_store, loaded) = ctx.load()?;
    let secrets = backend::secret_store();
    let entries = secrets.list()?;
    let views = entry_views(&loaded.config, &entries, Some(&secrets));
    if ctx.json() {
        ctx.print_json(&views);
    } else if views.is_empty() {
        ctx.info(&ctx.tx(Text::NoSecretsStored));
    } else {
        print_entries(ctx, &views);
    }
    Ok(exit::OK)
}

fn prune(ctx: &mut Ctx, a: &CredPruneArgs) -> CmdResult {
    let (store, loaded) = ctx.load()?;
    let cfg = &loaded.config;
    // A newer file may have dropped remote tables this build cannot read, and a missing file
    // (another settings folder) has no hosts: either would delete passwords still in use.
    if cfg.is_newer_schema() {
        return Err(Error::NewerSchema {
            found: cfg.schema_version,
            supported: SCHEMA_VERSION,
        }
        .into());
    }
    if !loaded.exists {
        return Err(Failure::Usage(ctx.tx(Text::PruneNoSettings {
            path: &store.config_path().display().to_string(),
        })));
    }
    let secrets = backend::secret_store();
    let orphans = secrets.orphans(cfg)?;
    let views = entry_views(cfg, &orphans, None);
    let doc = |ctx: &Ctx, deleted: bool| {
        if ctx.json() {
            #[derive(Serialize)]
            struct Doc<'a, 'b> {
                dry_run: bool,
                deleted: bool,
                entries: &'a [EntryView<'b>],
            }
            ctx.print_json(&Doc {
                dry_run: a.dry_run,
                deleted,
                entries: &views,
            });
        }
    };
    if orphans.is_empty() {
        ctx.info(&ctx.tx(Text::NothingToPrune));
        doc(ctx, false);
        return Ok(exit::NEGATIVE);
    }
    if !ctx.json() {
        print_entries(ctx, &views);
    }
    if a.dry_run {
        doc(ctx, false);
        return Ok(exit::OK);
    }
    let lines = [
        ctx.tx(Text::PruneConfirm {
            count: orphans.len(),
        }),
        ctx.tx(Text::PruneSharedNote),
    ];
    if !confirm(ctx, a.yes, &lines)? {
        return Ok(exit::NEGATIVE);
    }
    // Exactly what was shown (not a new scan).
    for e in &orphans {
        secrets.delete(e.host_id, e.kind)?;
    }
    if !ctx.json() {
        ctx.info(&ctx.t(Msg::SecretsPruned {
            count: orphans.len(),
        }));
    }
    doc(ctx, true);
    Ok(exit::OK)
}
