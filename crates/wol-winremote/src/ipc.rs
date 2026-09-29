//! The `\\host\IPC$` session used to authenticate SMB/RPC calls with stored credentials.
//!
//! A connection created with [`WNetAddConnection2W`] belongs to the whole **logon session**, not
//! one thread, and there may be only one credential per server name. This guard therefore:
//! - reuses an existing `\\host\IPC$` connection instead of adding a second one, and records that
//!   it does **not** own it, so [`Drop`] leaves the user's own connection alone (cancelling by
//!   remote name would remove *every* deviceless connection to that resource);
//! - cancels only connections it created (`owned = true`), never with `fForce` (except
//!   [`cancel_owned_connections`] at process exit);
//! - never touches any other resource (e.g. `\\TSCLIENT\C` of an RDP session): the only name it
//!   ever cancels is the exact `\\host\IPC$` it added;
//! - resolves `ERROR_EXTENDED_ERROR` (1208) through `WNetGetLastErrorW` for a real error code.
//!
//! Callers must serialize operations per host (the crate's top-level API does this with a per-host
//! lock). The guard is panic-safe: `Drop` runs during unwinding.
//!
//! A connection that is never cancelled outlives the process (until logoff), and later operations
//! would silently reuse its credentials. Every connection this process added is therefore also
//! recorded in a process-wide list: [`cancel_owned_connections`] removes the ones still open when
//! the process is about to exit (GUI exit, Ctrl+C in `wolm`), where the threads that own them are
//! not unwound.
//!
//! # Blocking
//! [`IpcSession::open`] performs an SMB logon; against an unreachable host the redirector can block
//! for **tens of seconds**. Pre-probe TCP 445 and run on a worker thread.
//!
//! [`WNetAddConnection2W`]: https://learn.microsoft.com/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection2w

/// Case-insensitive comparison of two UNC-ish strings (ASCII case only, which is all UNC paths use
/// for the separators and `IPC$`; host names are compared case-insensitively too).
pub(crate) fn unc_eq_ci(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.eq_ignore_ascii_case(b)
}

#[cfg(windows)]
pub use windows_impl::{IpcSession, cancel_owned_connections};

#[cfg(all(windows, test))]
pub(crate) use windows_impl::connected_remote_names;

#[cfg(windows)]
mod windows_impl {
    use super::unc_eq_ci;
    use crate::error::{Error, Op, Result};
    use crate::wide::{from_pwstr, wz, wz_secret};
    use std::sync::Mutex;
    use windows_sys::Win32::Foundation::{
        ERROR_EXTENDED_ERROR, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, FALSE, NO_ERROR, TRUE,
    };
    use windows_sys::Win32::NetworkManagement::WNet::{
        CONNECT_TEMPORARY, NETRESOURCEW, RESOURCE_CONNECTED, RESOURCETYPE_ANY, WNetAddConnection2W,
        WNetCancelConnection2W, WNetCloseEnum, WNetEnumResourceW, WNetGetLastErrorW, WNetOpenEnumW,
    };

    /// An `\\host\IPC$` session. Dropping it cancels the connection **only if this guard created it**.
    pub struct IpcSession {
        ipc_name: Vec<u16>,
        owned: bool,
    }

    /// The connections this process added and has not cancelled yet (`\\host\IPC$` names),
    /// and whether the process is exiting (no new connections then).
    struct Owned {
        names: Vec<Vec<u16>>,
        closed: bool,
    }

    static OWNED: Mutex<Owned> = Mutex::new(Owned {
        names: Vec::new(),
        closed: false,
    });

    fn owned() -> std::sync::MutexGuard<'static, Owned> {
        OWNED.lock().unwrap_or_else(|p| p.into_inner())
    }

    #[cfg(test)]
    pub(super) fn unregister_for_test(name: &[u16]) -> bool {
        unregister(name)
    }

    /// Removes `name` from the list; `false` when it is not there (cancelled at exit already).
    fn unregister(name: &[u16]) -> bool {
        let mut o = owned();
        match o.names.iter().position(|n| n.as_slice() == name) {
            Some(i) => {
                o.names.swap_remove(i);
                true
            }
            None => false,
        }
    }

    /// Process exit: cancels every `\\host\IPC$` connection this process added that is still
    /// open (a thread that owns one may be ended without unwinding, and the connection would
    /// otherwise stay until logoff), and refuses to add new ones from now on. Only the exact
    /// names this process added are cancelled (the user's own connections are never touched);
    /// `fForce` is used because a call that is still running may hold them and the process is
    /// ending anyway. Returns how many were cancelled. Call it only right before the process
    /// exits.
    pub fn cancel_owned_connections() -> usize {
        let names = {
            let mut o = owned();
            o.closed = true;
            std::mem::take(&mut o.names)
        };
        for name in &names {
            // SAFETY: `name` is the NUL-terminated wide string this process passed to
            // WNetAddConnection2W.
            let rc = unsafe { WNetCancelConnection2W(name.as_ptr(), 0, TRUE) };
            if rc != NO_ERROR {
                log::debug!("WNetCancelConnection2W at exit failed with {rc}");
            }
        }
        if !names.is_empty() {
            log::info!("{} remote connection(s) closed at exit", names.len());
        }
        names.len()
    }

    impl IpcSession {
        /// Opens (or reuses) an `\\host\IPC$` session.
        ///
        /// `unc` is the `\\host` string (IP literal or name) that every later call MUST reuse
        /// verbatim. When `creds` is `None`, no connection is made and Windows uses the current
        /// logon; the returned guard is a no-op.
        pub fn open(unc: &str, creds: Option<(&str, &str)>) -> Result<Self> {
            let ipc = format!(r"{unc}\IPC$");
            let mut ipc_name = wz(&ipc);

            let Some((user, pass)) = creds else {
                // No stored credential: rely on the current logon; nothing to own or cancel.
                return Ok(IpcSession {
                    ipc_name,
                    owned: false,
                });
            };

            // Reuse an existing connection to the same resource rather than adding a second one
            // (cancelling by remote name would remove the user's own deviceless connection too).
            match connected_remote_names() {
                Some(names) if names.iter().any(|n| unc_eq_ci(n, &ipc)) => {
                    // Windows keeps one credential per server and logon session: the one of
                    // that connection is used, not the account given here.
                    log::info!(
                        "{ipc} is already connected in this Windows session (Explorer, net use, \
                         another program): its credentials are used, not the given account"
                    );
                    return Ok(IpcSession {
                        ipc_name,
                        owned: false,
                    });
                }
                Some(_) => {}
                None => log::warn!("cannot enumerate connections; assuming {ipc} is not connected"),
            }

            let exiting = || {
                Error::new(
                    crate::error::ErrorKind::Other,
                    Op::Connect,
                    format!("not connecting to {ipc}: the program is exiting"),
                )
            };
            if owned().closed {
                return Err(exiting());
            }
            let u = wz(user);
            let p = wz_secret(pass);
            let nr = NETRESOURCEW {
                dwType: RESOURCETYPE_ANY,
                lpRemoteName: ipc_name.as_mut_ptr(),
                ..Default::default()
            };
            // SAFETY: `nr` borrows `ipc_name`; `u`/`p` are NUL-terminated wide strings; all outlive
            // the call.
            let rc = unsafe { WNetAddConnection2W(&nr, p.as_ptr(), u.as_ptr(), CONNECT_TEMPORARY) };
            if rc == NO_ERROR {
                let mut o = owned();
                if o.closed {
                    // `cancel_owned_connections` ran while this logon was in progress.
                    drop(o);
                    // SAFETY: as above; the connection was just added by this call.
                    unsafe { WNetCancelConnection2W(ipc_name.as_ptr(), 0, TRUE) };
                    return Err(exiting());
                }
                o.names.push(ipc_name.clone());
                return Ok(IpcSession {
                    ipc_name,
                    owned: true,
                });
            }
            // 1208 is a wrapper; the real code comes from WNetGetLastErrorW.
            let real = if rc == ERROR_EXTENDED_ERROR {
                wnet_last_error().unwrap_or(rc)
            } else {
                rc
            };
            Err(Error::from_win32(
                Op::Connect,
                real,
                format!("WNetAddConnection2W({ipc})"),
            ))
        }

        /// `true` when this guard itself established the connection with the given credentials,
        /// which proves them. `false` for the no-credential no-op guard and for a reused
        /// connection (whose credentials are unknown).
        pub fn authenticated(&self) -> bool {
            self.owned
        }
    }

    impl Drop for IpcSession {
        fn drop(&mut self) {
            // Not ours, or already cancelled by `cancel_owned_connections` (a connection that
            // someone else added under the same name since then is left alone).
            if !self.owned || !unregister(&self.ipc_name) {
                return;
            }
            // SAFETY: `ipc_name` is a NUL-terminated wide string. fForce=FALSE: never force-cancel.
            let rc = unsafe { WNetCancelConnection2W(self.ipc_name.as_ptr(), 0, FALSE) };
            if rc != NO_ERROR {
                log::debug!("WNetCancelConnection2W failed with {rc} (handles may still be open)");
            }
        }
    }

    /// Retrieves the real error behind `ERROR_EXTENDED_ERROR`.
    fn wnet_last_error() -> Option<u32> {
        let mut code = 0u32;
        let mut err_buf = [0u16; 512];
        let mut name_buf = [0u16; 512];
        // SAFETY: both buffers are valid for the given lengths.
        let rc = unsafe {
            WNetGetLastErrorW(
                &mut code,
                err_buf.as_mut_ptr(),
                err_buf.len() as u32,
                name_buf.as_mut_ptr(),
                name_buf.len() as u32,
            )
        };
        if rc == NO_ERROR { Some(code) } else { None }
    }

    /// The remote names of every connected resource of this logon session (all network providers,
    /// deviceless connections included), or `None` when they cannot be enumerated. Read-only.
    pub(crate) fn connected_remote_names() -> Option<Vec<String>> {
        let mut henum = std::ptr::null_mut();
        // SAFETY: a RESOURCE_CONNECTED enumeration with no root resource.
        let rc = unsafe {
            WNetOpenEnumW(
                RESOURCE_CONNECTED,
                RESOURCETYPE_ANY,
                0,
                std::ptr::null(),
                &mut henum,
            )
        };
        if rc != NO_ERROR {
            return None;
        }
        let mut names = Vec::new();
        // u64-backed so the NETRESOURCEW array (pointer-aligned) is properly aligned.
        let mut buf: Vec<u64> = vec![0; 16 * 1024 / 8];
        // `true` for the normal end of the enumeration (ERROR_NO_MORE_ITEMS).
        let ok = loop {
            let mut count = u32::MAX; // as many as fit
            let mut size = (buf.len() * 8) as u32;
            // SAFETY: `henum` is a live enum handle; `buf` is `size` writable, aligned bytes.
            let rc =
                unsafe { WNetEnumResourceW(henum, &mut count, buf.as_mut_ptr().cast(), &mut size) };
            if rc == ERROR_MORE_DATA {
                // Not even one entry fits; `size` holds the needed byte count.
                let needed = (size as usize).div_ceil(8).max(buf.len() * 2);
                buf.resize(needed, 0);
                continue;
            }
            if rc != NO_ERROR {
                // ERROR_NO_MORE_ITEMS is the normal end; anything else is a failure.
                break rc == ERROR_NO_MORE_ITEMS;
            }
            // SAFETY: on success `buf` holds `count` NETRESOURCEW structs, whose string pointers
            // refer into the same buffer.
            let entries = unsafe {
                std::slice::from_raw_parts(buf.as_ptr() as *const NETRESOURCEW, count as usize)
            };
            for e in entries {
                if !e.lpRemoteName.is_null() {
                    // SAFETY: lpRemoteName is a NUL-terminated wide string inside `buf`.
                    names.push(unsafe { from_pwstr(e.lpRemoteName) });
                }
            }
        };
        // SAFETY: `henum` came from WNetOpenEnumW and is closed exactly once.
        unsafe {
            WNetCloseEnum(henum);
        }
        ok.then_some(names)
    }
}

#[cfg(test)]
mod tests {
    use super::unc_eq_ci;

    #[test]
    fn unc_compare_is_case_insensitive() {
        assert!(unc_eq_ci(r"\\HOST\IPC$", r"\\host\ipc$"));
        assert!(unc_eq_ci(r"\\100.105.1.2\IPC$", r"\\100.105.1.2\ipc$"));
        assert!(!unc_eq_ci(r"\\host\IPC$", r"\\other\IPC$"));
        assert!(!unc_eq_ci(r"\\host\IPC$", r"\\host\IPC$ "));
        // A different resource on the same server is never "the same connection".
        assert!(!unc_eq_ci(r"\\TSCLIENT\C", r"\\TSCLIENT\IPC$"));
    }

    /// Read-only: enumerates this logon session's connections (as `net use` shows them). No
    /// connection is added or cancelled.
    #[cfg(windows)]
    #[test]
    fn enumerating_connections_is_read_only_and_works() {
        // Tolerant: a service session on a CI runner may have no network providers.
        match super::connected_remote_names() {
            Some(names) => names.iter().for_each(|n| println!("connected: {n}")),
            None => println!("connection enumeration unavailable in this session"),
        }
    }

    /// With no credentials the guard is a no-op: it neither adds nor cancels anything.
    #[cfg(windows)]
    #[test]
    fn no_credential_guard_is_a_no_op() {
        // Returns before any WNet call (no network I/O); nothing to own, so Drop cancels nothing.
        let s = super::IpcSession::open(r"\\192.0.2.1", None).unwrap();
        assert!(!s.authenticated());
    }

    /// Review C3: at process exit the connections this process added are cancelled, and no new
    /// one is added afterwards (refused before `WNetAddConnection2W`: no network I/O, the
    /// TEST-NET address is never contacted).
    #[cfg(windows)]
    #[test]
    fn exit_cleanup_cancels_and_refuses_new_connections() {
        assert_eq!(super::cancel_owned_connections(), 0, "nothing was added");
        let e = super::IpcSession::open(r"\\192.0.2.1", Some(("user", "not-a-password")))
            .err()
            .expect("refused while exiting");
        assert_eq!(e.kind(), crate::ErrorKind::Other);
        assert_eq!(e.op(), crate::Op::Connect);
        // Dropping a guard that is not in the list never cancels anything.
        assert!(!super::windows_impl::unregister_for_test(&[0]));
    }
}
