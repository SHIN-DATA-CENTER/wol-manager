//! Remote restart / shutdown / abort, behind a mockable [`ShutdownBackend`] seam.
//!
//! # Safety
//! The real OS calls (`InitiateSystemShutdownExW`, `AbortSystemShutdownW`) live **only** in the
//! crate-private `RealShutdown` backend, which only [`crate::power()`] / [`crate::abort_shutdown`]
//! construct, after refusing a local target. All logic is written against the [`ShutdownBackend`]
//! trait, so tests drive it with an in-memory mock and never send a shutdown to any machine. As
//! defense in depth, `RealShutdown` itself
//! - **panics in `cfg(test)` builds** before touching the OS, so no unit test can ever reach a real
//!   shutdown, even through the top-level API;
//! - refuses an empty / non-UNC machine name (an empty name means *this PC* to the OS) and any
//!   name that [`crate::is_local_target`] recognizes, returning `ERROR_INVALID_PARAMETER`.
//!
//! # Blocking
//! [`power_with`] and [`abort_with`] make one RPC call over the remote-shutdown endpoint. On a
//! reachable host they return promptly; if the endpoint is filtered the call can block until the
//! RPC connect times out (tens of seconds).

use crate::error::{Error, Op, Result};

/// What to do to the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerAction {
    /// Restart (reboot) the target.
    Restart,
    /// Shut the target down (full S5 shutdown; not a Fast-Startup hybrid shutdown).
    Shutdown,
}

impl PowerAction {
    fn is_reboot(self) -> bool {
        matches!(self, PowerAction::Restart)
    }
}

/// Options for a power request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PowerOptions {
    /// Countdown before the action, in seconds (`0` = immediate, no dialog, not abortable).
    /// Clamped to [`MAX_TIMEOUT_SECS`].
    pub delay_secs: u32,
    /// Force applications closed (`bForceAppsClosed`). `false` can leave the target stuck with a
    /// pending, unabortable shutdown if the console user has unsaved work.
    pub force: bool,
    /// A message shown to any logged-on user during the countdown.
    pub message: Option<String>,
}

impl Default for PowerOptions {
    fn default() -> Self {
        PowerOptions {
            delay_secs: 30,
            force: true,
            message: None,
        }
    }
}

/// The result of a successfully accepted power request. A shutdown is asynchronous, so this only
/// means the target accepted the request; confirm by polling boot time / reachability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerOutcome {
    /// Accepted for immediate action (no countdown).
    Accepted,
    /// Scheduled after the countdown; abortable with [`abort_with`] until it fires.
    Scheduled,
}

/// `shutdown.exe`'s documented maximum timeout (10 years, in seconds). Not exported by windows-sys.
pub const MAX_TIMEOUT_SECS: u32 = 315_360_000;

/// `SHTDN_REASON_FLAG_PLANNED | SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER`.
/// Reason `0` (unplanned) can trigger system-state capture, so a planned reason is always used.
pub const REASON_PLANNED_OTHER: u32 = 0x8000_0000;

/// Clamps a requested delay to the OS maximum.
pub(crate) fn clamp_timeout(secs: u32) -> u32 {
    secs.min(MAX_TIMEOUT_SECS)
}

fn outcome_for(timeout: u32) -> PowerOutcome {
    if timeout > 0 {
        PowerOutcome::Scheduled
    } else {
        PowerOutcome::Accepted
    }
}

/// The seam over the OS shutdown APIs. `machine` is the `\\host` string that the IPC$ session was
/// established with; every method returns `Ok(())` on acceptance or the raw Win32 error code.
pub trait ShutdownBackend {
    /// Requests a restart or shutdown (`InitiateSystemShutdownExW`).
    fn initiate(
        &self,
        machine: &str,
        message: Option<&str>,
        timeout_secs: u32,
        force: bool,
        reboot: bool,
        reason: u32,
    ) -> std::result::Result<(), u32>;

    /// Cancels a pending shutdown (`AbortSystemShutdownW`).
    fn abort(&self, machine: &str) -> std::result::Result<(), u32>;
}

/// Requests a power action through `backend`.
///
/// `reachable` must be `true` once an IPC$ session or `NetRemoteTOD` has succeeded, so that error
/// codes 5 / 53 are classified as *insufficient rights* rather than *unreachable* (see
/// [`Error::from_win32_reachable`]).
pub fn power_with<B: ShutdownBackend>(
    backend: &B,
    machine: &str,
    reachable: bool,
    action: PowerAction,
    opts: &PowerOptions,
) -> Result<PowerOutcome> {
    let timeout = clamp_timeout(opts.delay_secs);
    match backend.initiate(
        machine,
        opts.message.as_deref(),
        timeout,
        opts.force,
        action.is_reboot(),
        REASON_PLANNED_OTHER,
    ) {
        Ok(()) => Ok(outcome_for(timeout)),
        Err(code) => Err(Error::from_win32_reachable(
            Op::Power,
            code,
            reachable,
            format!("InitiateSystemShutdownExW({machine})"),
        )),
    }
}

/// Cancels a pending shutdown through `backend`. See [`power_with`] for `reachable`.
pub fn abort_with<B: ShutdownBackend>(backend: &B, machine: &str, reachable: bool) -> Result<()> {
    match backend.abort(machine) {
        Ok(()) => Ok(()),
        Err(code) => Err(Error::from_win32_reachable(
            Op::Abort,
            code,
            reachable,
            format!("AbortSystemShutdownW({machine})"),
        )),
    }
}

/// `ERROR_INVALID_PARAMETER`, returned by [`RealShutdown`] when it refuses a machine name.
#[cfg(windows)]
const REFUSED_MACHINE: u32 = 87;

/// Defense in depth for [`RealShutdown`]: the machine must be a non-empty `\\host` that is not this
/// PC. The OS treats a NULL / empty machine name as the local computer.
#[cfg(windows)]
fn refuse_local_machine(machine: &str) -> std::result::Result<(), u32> {
    let host = machine.strip_prefix(r"\\").unwrap_or("");
    if host.is_empty() || host.contains('\\') || crate::local::is_local_target(host) {
        log::error!("refusing a shutdown/abort RPC to {machine:?}: empty, malformed or this PC");
        return Err(REFUSED_MACHINE);
    }
    Ok(())
}

/// The real backend, calling the advapi32 shutdown APIs. Crate-private: constructed only by the
/// top-level [`crate::power()`] / [`crate::abort_shutdown`] entry points after their own
/// local-target guard. Panics in `cfg(test)` builds so tests can never reach the OS shutdown calls.
#[cfg(windows)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct RealShutdown;

#[cfg(windows)]
impl ShutdownBackend for RealShutdown {
    fn initiate(
        &self,
        machine: &str,
        message: Option<&str>,
        timeout_secs: u32,
        force: bool,
        reboot: bool,
        reason: u32,
    ) -> std::result::Result<(), u32> {
        use windows_sys::Win32::Foundation::GetLastError;
        use windows_sys::Win32::System::Shutdown::InitiateSystemShutdownExW;

        if cfg!(test) {
            panic!("RealShutdown::initiate reached in a test build; tests must use a mock backend");
        }
        refuse_local_machine(machine)?;
        let m = crate::wide::wz(machine);
        let msg = message.map(crate::wide::wz);
        let msg_ptr = msg.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
        // SAFETY: `m` and `msg` (if any) are NUL-terminated wide strings that outlive the call.
        let ok = unsafe {
            InitiateSystemShutdownExW(
                m.as_ptr(),
                msg_ptr,
                timeout_secs,
                force as i32,
                reboot as i32,
                reason,
            )
        } != 0;
        if ok {
            Ok(())
        } else {
            // SAFETY: reads thread-local error state.
            Err(unsafe { GetLastError() })
        }
    }

    fn abort(&self, machine: &str) -> std::result::Result<(), u32> {
        use windows_sys::Win32::Foundation::GetLastError;
        use windows_sys::Win32::System::Shutdown::AbortSystemShutdownW;

        if cfg!(test) {
            panic!("RealShutdown::abort reached in a test build; tests must use a mock backend");
        }
        refuse_local_machine(machine)?;
        let m = crate::wide::wz(machine);
        // SAFETY: `m` is a NUL-terminated wide string.
        let ok = unsafe { AbortSystemShutdownW(m.as_ptr()) } != 0;
        if ok {
            Ok(())
        } else {
            // SAFETY: reads thread-local error state.
            Err(unsafe { GetLastError() })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ErrorKind, Hint};
    use std::cell::RefCell;

    /// Records calls and returns a configured result. Never touches the OS.
    #[derive(Default)]
    struct MockShutdown {
        initiate_result: Option<u32>, // Some(code) => error, None => Ok
        abort_result: Option<u32>,
        calls: RefCell<Vec<String>>,
    }

    impl ShutdownBackend for MockShutdown {
        fn initiate(
            &self,
            machine: &str,
            message: Option<&str>,
            timeout_secs: u32,
            force: bool,
            reboot: bool,
            reason: u32,
        ) -> std::result::Result<(), u32> {
            self.calls.borrow_mut().push(format!(
                "initiate {machine} msg={message:?} t={timeout_secs} force={force} reboot={reboot} reason={reason:#x}"
            ));
            match self.initiate_result {
                Some(code) => Err(code),
                None => Ok(()),
            }
        }

        fn abort(&self, machine: &str) -> std::result::Result<(), u32> {
            self.calls.borrow_mut().push(format!("abort {machine}"));
            match self.abort_result {
                Some(code) => Err(code),
                None => Ok(()),
            }
        }
    }

    #[test]
    fn clamp_and_outcome() {
        assert_eq!(clamp_timeout(30), 30);
        assert_eq!(clamp_timeout(u32::MAX), MAX_TIMEOUT_SECS);
        assert_eq!(outcome_for(0), PowerOutcome::Accepted);
        assert_eq!(outcome_for(30), PowerOutcome::Scheduled);
    }

    #[test]
    fn restart_passes_reboot_and_planned_reason() {
        let mock = MockShutdown::default();
        let opts = PowerOptions {
            delay_secs: 30,
            force: true,
            message: Some("bye".into()),
        };
        let out = power_with(&mock, r"\\host", true, PowerAction::Restart, &opts).unwrap();
        assert_eq!(out, PowerOutcome::Scheduled);
        let calls = mock.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].contains("reboot=true"), "{}", calls[0]);
        assert!(calls[0].contains(&format!("reason={REASON_PLANNED_OTHER:#x}")));
        assert!(calls[0].contains("msg=Some(\"bye\")"));
    }

    #[test]
    fn shutdown_immediate_is_accepted() {
        let mock = MockShutdown::default();
        let opts = PowerOptions {
            delay_secs: 0,
            force: true,
            message: None,
        };
        let out = power_with(&mock, r"\\host", true, PowerAction::Shutdown, &opts).unwrap();
        assert_eq!(out, PowerOutcome::Accepted);
        assert!(mock.calls.borrow()[0].contains("reboot=false"));
    }

    #[test]
    fn reachable_error_53_is_access_denied() {
        let mock = MockShutdown {
            initiate_result: Some(53),
            ..Default::default()
        };
        let e = power_with(
            &mock,
            r"\\host",
            true,
            PowerAction::Restart,
            &PowerOptions::default(),
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::AccessDenied);
        assert_eq!(e.hint(), Some(Hint::UacRemoteRestriction));
    }

    #[test]
    fn unknown_reachability_error_53_is_unreachable() {
        let mock = MockShutdown {
            initiate_result: Some(53),
            ..Default::default()
        };
        let e = power_with(
            &mock,
            r"\\host",
            false,
            PowerAction::Restart,
            &PowerOptions::default(),
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unreachable);
    }

    #[test]
    fn abort_maps_no_pending() {
        let mock = MockShutdown {
            abort_result: Some(1116),
            ..Default::default()
        };
        let e = abort_with(&mock, r"\\host", true).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NoShutdownInProgress);
        assert_eq!(mock.calls.borrow()[0], r"abort \\host");

        let ok = MockShutdown::default();
        assert!(abort_with(&ok, r"\\host", true).is_ok());
    }

    /// The real backend refuses every spelling of "this PC" / a malformed machine before any OS
    /// call (an empty machine name means the local computer to `InitiateSystemShutdownExW`).
    #[cfg(windows)]
    #[test]
    fn real_backend_guard_refuses_local_and_malformed_machines() {
        for m in [
            "",
            r"\\",
            "host-without-unc",
            r"\\host\share",
            r"\\127.0.0.1",
            r"\\127.1",
            r"\\localhost",
            r"\\.",
            r"\\::1",
        ] {
            assert_eq!(refuse_local_machine(m), Err(REFUSED_MACHINE), "{m:?}");
        }
        for n in crate::local::local_computer_names() {
            assert_eq!(
                refuse_local_machine(&format!(r"\\{n}")),
                Err(REFUSED_MACHINE),
                "{n}"
            );
        }
    }

    /// Backstop: in a test build the real backend panics before touching the OS. The machine is
    /// empty, so even without the panic the local-machine guard would refuse it.
    #[cfg(windows)]
    #[test]
    #[should_panic(expected = "reached in a test build")]
    fn real_backend_panics_in_test_builds() {
        let _ = RealShutdown.initiate("", None, 30, true, true, REASON_PLANNED_OTHER);
    }

    #[cfg(windows)]
    #[test]
    #[should_panic(expected = "reached in a test build")]
    fn real_abort_panics_in_test_builds() {
        let _ = RealShutdown.abort("");
    }
}
