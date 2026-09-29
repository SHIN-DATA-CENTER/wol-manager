//! Command implementations.

mod completions;
mod config;
mod gui;
mod hosts;
mod net;
mod path;
mod portable;
mod status;
mod transfer;
mod wake;

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
    }
}
