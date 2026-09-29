//! Command implementations.

mod completions;
mod config;
mod cred;
mod gui;
mod hosts;
mod mac;
mod net;
mod path;
mod portable;
mod power;
mod remote;
mod ssh;
mod status;
mod transfer;
mod wake;

use wol_core::remote::PowerAction;

use crate::cli::Command;
use crate::ctx::Ctx;
use crate::exit::CmdResult;

/// Runs one command and returns its exit code.
pub fn dispatch(ctx: &mut Ctx, command: Command) -> CmdResult {
    match command {
        Command::Wake(a) => wake::run(ctx, &a),
        Command::Status(a) => status::run(ctx, &a),
        Command::List(a) => hosts::list(ctx, &a),
        Command::Show(a) => hosts::show(ctx, &a),
        Command::Add(a) => hosts::add(ctx, &a),
        Command::Edit(a) => hosts::edit(ctx, &a),
        Command::Remove(a) => hosts::remove(ctx, &a),
        Command::Arp(a) => net::arp(ctx, &a),
        Command::Interfaces(a) => net::interfaces(ctx, &a),
        Command::Listen(a) => net::listen(ctx, &a),
        Command::Export(a) => transfer::export(ctx, &a),
        Command::Import(a) => transfer::import(ctx, &a),
        Command::Config(c) => config::run(ctx, &c),
        Command::Portable(c) => portable::run(ctx, &c),
        Command::Path(c) => path::run(ctx, &c),
        Command::Completions(a) => completions::run(ctx, &a),
        Command::Gui => gui::run(ctx),
        Command::Restart(a) => power::run(ctx, &a, PowerAction::Restart),
        Command::Shutdown(a) => power::run(ctx, &a, PowerAction::Shutdown),
        Command::Abort(a) => power::abort(ctx, &a),
        Command::BootTime(a) => remote::boot_time(ctx, &a),
        Command::Mac(a) => mac::run(ctx, &a),
        Command::Remote(c) => remote::run(ctx, &c),
        Command::Cred(c) => cred::run(ctx, &c),
        Command::Ssh(c) => ssh::run(ctx, &c),
    }
}
