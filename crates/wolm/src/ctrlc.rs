//! Ctrl+C / Ctrl+Break handling for long-running commands (`wake --wait`, `listen`): the
//! handler only sets a flag, so the command can finish cleanly (print its result, exit 130).

use std::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler};
use windows_sys::core::BOOL;

static CANCELLED: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn handler(ctrl_type: u32) -> BOOL {
    match ctrl_type {
        CTRL_C_EVENT | CTRL_BREAK_EVENT => {
            CANCELLED.store(true, Ordering::SeqCst);
            1
        }
        _ => 0,
    }
}

/// Installs the handler (idempotent enough: a second registration only adds a duplicate
/// entry) and returns the flag it sets.
pub fn install() -> &'static AtomicBool {
    // SAFETY: `handler` is a valid `extern "system"` function for the whole process
    // lifetime and only touches an atomic.
    unsafe {
        SetConsoleCtrlHandler(Some(handler), 1);
    }
    &CANCELLED
}
