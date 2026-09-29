//! `completions [SHELL]` (default PowerShell).

use clap::CommandFactory;
use clap_complete::Shell;

use crate::cli::{Cli, CompletionsArgs};
use crate::ctx::Ctx;
use crate::exit::{self, CmdResult};
use crate::output;

/// Generated script; the PowerShell one registers both `wolm` and `wolm.exe`.
pub fn script(shell: Shell) -> String {
    let mut cmd = Cli::command();
    let mut buf: Vec<u8> = Vec::new();
    clap_complete::generate(shell, &mut cmd, "wolm", &mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    match shell {
        Shell::PowerShell => text.replace("-CommandName 'wolm'", "-CommandName 'wolm', 'wolm.exe'"),
        _ => text,
    }
}

pub fn run(ctx: &mut Ctx, a: &CompletionsArgs) -> CmdResult {
    let shell = a.shell.unwrap_or(Shell::PowerShell);
    let text = script(shell);
    if ctx.json() {
        ctx.print_json(&serde_json::json!({ "shell": shell.to_string(), "script": text }));
    } else {
        output::stdout_bytes(text.as_bytes());
    }
    Ok(exit::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powershell_registers_both_names() {
        let s = script(Shell::PowerShell);
        assert!(s.contains("-CommandName 'wolm', 'wolm.exe'"), "{s}");
        assert!(s.contains("'wolm;wake'"));
    }
}
