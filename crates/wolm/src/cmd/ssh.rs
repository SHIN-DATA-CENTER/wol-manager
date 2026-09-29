//! `ssh trust|forget`: pinning the SSH host key of a host (trust on first use, never
//! automatic).

use serde::Serialize;
use wol_core::i18n::Msg;
use wol_core::remote::{self, HostKeyInfo, RemoteOp};
use wol_core::{Error, HostId, HostKeyProblem};

use super::remote::precheck;
use crate::backend::Remote;
use crate::cli::{RemoteHostArg, SshCmd, SshTrustArgs};
use crate::ctx::Ctx;
use crate::exit::{self, CmdResult, Failure};
use crate::output;
use crate::prompt;
use crate::text::Text;

pub fn run(ctx: &mut Ctx, c: &SshCmd) -> CmdResult {
    match c {
        SshCmd::Trust(a) => trust(ctx, a),
        SshCmd::Forget(a) => forget(ctx, a),
    }
}

#[derive(Serialize)]
struct TrustDoc<'a> {
    host: &'a str,
    id: HostId,
    algorithm: &'a str,
    fingerprint: &'a str,
    openssh_line: &'a str,
    in_known_hosts: bool,
    trusted: bool,
    changed: bool,
}

fn trust(ctx: &mut Ctx, a: &SshTrustArgs) -> CmdResult {
    let (store, loaded) = ctx.load()?;
    let cfg = &loaded.config;
    let h = cfg.find(&a.host)?;
    precheck(ctx, h, RemoteOp::ScanHostKey)?;
    let remote = Remote::new()?;
    let key: HostKeyInfo = remote.scan_host_key(h, &cfg.settings)?;
    // Where the key came from and what was pinned: the pin is written only if the host still
    // matches after the question (review S4).
    let basis = remote::TrustBasis::of(h).ok_or_else(|| Error::RemoteNotConfigured {
        host: h.name.clone(),
    })?;
    let doc = |ctx: &Ctx, known: bool, trusted: bool, changed: bool| {
        if ctx.json() {
            ctx.print_json(&TrustDoc {
                host: &h.name,
                id: h.id,
                algorithm: &key.algorithm,
                fingerprint: &key.fingerprint,
                openssh_line: &key.openssh_line,
                in_known_hosts: known,
                trusted,
                changed,
            });
        }
    };

    // A key is pinned already: the same one → nothing to do; another one → never replaced
    // here (forget it first, after checking why it changed).
    if let Some(pinned) = h.remote.as_ref().and_then(|r| r.host_key()) {
        let pinned = remote::parse_host_key(pinned).ok();
        if pinned
            .as_ref()
            .is_some_and(|p| p.openssh_line == key.openssh_line)
        {
            ctx.info(&ctx.tx(Text::HostKeyAlreadyTrusted { label: &h.name }));
            doc(ctx, false, true, false);
            return Ok(exit::NEGATIVE);
        }
        return Err(Error::HostKeyMismatch(Box::new(HostKeyProblem {
            host: h.name.clone(),
            address: h
                .management_address()
                .map(ToString::to_string)
                .unwrap_or_default(),
            port: h.remote.as_ref().map_or(22, |r| r.ssh_port()),
            algorithm: key.algorithm.clone(),
            fingerprint: key.fingerprint.clone(),
            openssh_line: String::new(),
            expected_fingerprint: pinned.map(|p| p.fingerprint),
            in_known_hosts: false,
        }))
        .into());
    }

    let known = remote.in_known_hosts(h, &key.openssh_line);
    let key_line = ctx.tx(Text::HostKeyShow {
        label: &h.name,
        algorithm: &key.algorithm,
        fingerprint: &key.fingerprint,
    });
    let check_hint = ctx.t(Msg::HostKeyCheckHint {
        algorithm: key.algorithm.clone(),
    });
    let asking = a.fingerprint.is_none() && !a.accept_new;
    if asking {
        if !ctx.interactive() {
            ctx.out(&key_line);
            return Err(Failure::Usage(ctx.tx(Text::TrustNeedsFlag)));
        }
        ctx.ask_line(&output::paint(output::BOLD, &key_line));
        ctx.ask_line(&check_hint);
        if known {
            ctx.ask_line(&ctx.tx(Text::HostKeyInKnownHosts));
        }
        if !prompt::confirm(&ctx.tx(Text::TrustPrompt)) {
            ctx.warn(&ctx.tx(Text::Declined));
            doc(ctx, known, false, false);
            return Ok(exit::NEGATIVE);
        }
    } else {
        ctx.out(&key_line);
        if let Some(fp) = &a.fingerprint
            && !remote::fingerprints_match(fp, &key.fingerprint)
        {
            return Err(Failure::Permission(ctx.t(
                Msg::HostKeyFingerprintMismatch {
                    expected: fp.trim().to_owned(),
                    actual: key.fingerprint.clone(),
                },
            )));
        }
    }
    let up = store.update(|c| remote::trust_host_key(c, h.id, &key.openssh_line, &basis))?;
    if !ctx.json() {
        ctx.info(&output::paint(
            output::GREEN,
            &ctx.t(Msg::HostKeyTrusted {
                label: h.name.clone(),
                fingerprint: key.fingerprint.clone(),
            }),
        ));
    }
    doc(ctx, known, true, up.written);
    Ok(exit::OK)
}

fn forget(ctx: &mut Ctx, a: &RemoteHostArg) -> CmdResult {
    let (store, loaded) = ctx.load()?;
    let h = loaded.config.find(&a.host)?;
    if h.remote.is_none() {
        return Err(Error::RemoteNotConfigured {
            host: h.name.clone(),
        }
        .into());
    }
    let up = store.update(|c| remote::forget_host_key(c, h.id))?;
    let forgotten = up.value;
    if ctx.json() {
        #[derive(Serialize)]
        struct Doc<'a> {
            host: &'a str,
            id: HostId,
            forgotten: bool,
        }
        ctx.print_json(&Doc {
            host: &h.name,
            id: h.id,
            forgotten,
        });
    } else if forgotten {
        ctx.info(&ctx.t(Msg::HostKeyForgotten {
            label: h.name.clone(),
        }));
    } else {
        ctx.info(&ctx.t(Msg::HostKeyNotPinned {
            label: h.name.clone(),
        }));
    }
    Ok(if forgotten { exit::OK } else { exit::NEGATIVE })
}
