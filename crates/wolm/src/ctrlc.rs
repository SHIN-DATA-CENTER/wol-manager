//! Ctrl+C / Ctrl+Break / closing the console window.
//!
//! * Always ([`init`], called by `main`): before the process ends, the Windows `\\host\IPC$`
//!   connections that remote operations of this process opened with a stored password are
//!   closed. They belong to the logon session and would otherwise stay until logoff, and later
//!   operations would silently reuse their credentials (review C3). Then the default handler
//!   ends the process, as before.
//! * While a command waits (`wake --wait`, `listen`, `restart|shutdown --wait`: [`install`]):
//!   the first Ctrl+C only sets a flag, so the command can finish cleanly (print its result,
//!   exit 130), and prints what happens; a second Ctrl+C quits at once (review C7: a boot-time
//!   read can take up to about a minute before the command sees the flag).

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, Once};

use windows_sys::Win32::System::Console::{
    CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, SetConsoleCtrlHandler,
};
use windows_sys::core::BOOL;

static CANCELLED: AtomicBool = AtomicBool::new(false);
static WAITING: AtomicBool = AtomicBool::new(false);
static NOTICE: Mutex<Option<String>> = Mutex::new(None);
static REGISTERED: Once = Once::new();

/// What a Ctrl+C / Ctrl+Break / close event does (pure; the handler acts on it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    /// A waiting command's first Ctrl+C: set the flag, print the notice, keep running.
    Cancel,
    /// Close the connections this process opened, then let the default handler end it.
    Quit,
    /// Not ours to handle.
    Pass,
}

fn action(ctrl_type: u32, waiting: bool, already_cancelled: bool) -> Action {
    match ctrl_type {
        CTRL_C_EVENT | CTRL_BREAK_EVENT if waiting && !already_cancelled => Action::Cancel,
        CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT => Action::Quit,
        _ => Action::Pass,
    }
}

unsafe extern "system" fn handler(ctrl_type: u32) -> BOOL {
    let waiting = WAITING.load(Ordering::SeqCst);
    // Only a Ctrl+C that is handled here marks the command as cancelled.
    let cancelled = match action(ctrl_type, waiting, CANCELLED.load(Ordering::SeqCst)) {
        Action::Cancel => CANCELLED.swap(true, Ordering::SeqCst),
        other => return quit_or_pass(other),
    };
    if cancelled {
        // Another Ctrl+C won the race: this one quits.
        return quit_or_pass(Action::Quit);
    }
    let notice = NOTICE.lock().ok().and_then(|n| n.clone());
    if let Some(n) = notice {
        let _ = writeln!(std::io::stderr(), "{n}");
    }
    1
}

fn quit_or_pass(a: Action) -> BOOL {
    if a == Action::Quit {
        wol_core::remote::cancel_owned_connections();
    }
    // FALSE: the next handler (the system default) ends the process.
    0
}

/// Registers the handler once (every command: the exit cleanup above).
pub fn init() {
    REGISTERED.call_once(|| {
        // SAFETY: `handler` is a valid `extern "system"` function for the whole process
        // lifetime; it only touches atomics, a mutex, stderr and the connection cleanup.
        unsafe {
            SetConsoleCtrlHandler(Some(handler), 1);
        }
    });
}

/// The command starts waiting: the first Ctrl+C sets the returned flag instead of ending the
/// process (a second one quits at once).
pub fn install() -> &'static AtomicBool {
    install_with(None)
}

/// [`install`], printing `notice` on stderr when the first Ctrl+C arrives.
pub fn install_with(notice: Option<String>) -> &'static AtomicBool {
    init();
    if let Some(n) = notice
        && let Ok(mut slot) = NOTICE.lock()
    {
        *slot = Some(n);
    }
    WAITING.store(true, Ordering::SeqCst);
    &CANCELLED
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review C7 / C3: the first Ctrl+C of a waiting command cancels, a second one (and any
    /// Ctrl+C of a command that does not wait, and closing the window) quits after the cleanup.
    #[test]
    fn first_ctrl_c_cancels_second_quits() {
        assert_eq!(action(CTRL_C_EVENT, true, false), Action::Cancel);
        assert_eq!(action(CTRL_BREAK_EVENT, true, false), Action::Cancel);
        assert_eq!(action(CTRL_C_EVENT, true, true), Action::Quit);
        assert_eq!(action(CTRL_C_EVENT, false, false), Action::Quit);
        assert_eq!(action(CTRL_CLOSE_EVENT, true, false), Action::Quit);
        assert_eq!(
            action(5 /* CTRL_LOGOFF_EVENT */, false, false),
            Action::Pass
        );
    }
}
