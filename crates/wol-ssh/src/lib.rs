//! Blocking SSH facade used by WoL Manager's remote management (Linux / BSD / NAS hosts).
//!
//! Built on [russh](https://docs.rs/russh) 0.63 (ring backend). Every operation is
//! **blocking**: it runs a private current-thread tokio runtime, so callers (the GUI's worker
//! threads, the CLI) stay synchronous. Never call from the UI thread. Calls also work inside a
//! tokio runtime (an async task or a `spawn_blocking` thread; they then run on a short-lived
//! helper thread instead of panicking), but from an async task they still block its worker
//! thread, so use `spawn_blocking` there.
//!
//! # Operations
//! | Function | Remote side | Privileges |
//! |---|---|---|
//! | [`test_connection`] → [`ConnInfo`] | OS name, user, uid, groups, boot time | none |
//! | [`boot_time`] → [`BootInfo`] | `/proc/stat` btime, FreeBSD `kern.boottime`, boot id | none |
//! | [`mac_candidates`] → `Vec<`[`MacCandidate`]`>` | sysfs / `ifconfig`: NICs below the default route | none (WoL state needs root) |
//! | [`power`] → [`PowerScheduled`] | detached `systemctl reboot` / `poweroff` / FreeBSD / TrueNAS / Synology command | root or sudo |
//! | [`scan_host_key`] → [`HostKeyInfo`] | the server's host key, without authenticating | none |
//!
//! For several operations on one connection use [`Session`] directly
//! (e.g. [`Session::boot_time`] before [`Session::power`]).
//!
//! # Host keys (TOFU)
//! [`Target::host_key`] pins the server's key (an OpenSSH public-key line). Without a pin,
//! connecting fails with [`SshError::UnknownHostKey`] carrying the key and its `SHA256:`
//! fingerprint; after the user trusts it, store `openssh_line` and retry. A different key fails
//! with [`SshError::HostKeyMismatch`] (never replace the pin automatically). While a key is
//! pinned only its type is negotiated. [`known_hosts_keys`] reads `~/.ssh/known_hosts`
//! read-only as an optional seed.
//!
//! # Remote protocol
//! Read-only scripts run as `sh -s` with the script on stdin (safe with csh / fish login
//! shells); privileged work is a one-line `/bin/sh -c '...'`, prefixed with
//! `env LC_ALL=C sudo -n --` or `env LC_ALL=C sudo -k -S -p 'WOLM_SUDO_PROMPT:' --` as needed
//! (see [`SudoMode`]); the sudo password only travels on stdin. Output lines are prefixed with
//! `WOLM1 `; everything else is ignored.
//!
//! # Secrets
//! Passwords and passphrases are [`zeroize::Zeroizing`] strings supplied by the caller (from
//! Credential Manager, just in time). They are never logged, never put on a command line, and
//! redacted from `Debug` output. wol-ssh's own copies are zeroized, but russh 0.63's API
//! takes secrets as plain `String` / `Bytes` and its packet buffers are plain `Vec<u8>`s, so
//! non-zeroized copies are unavoidable for: the login password (`password` authentication),
//! the keyboard-interactive answer (the same password), and the sudo password sent on stdin
//! (one owned `Bytes` copy handed to the channel, plus russh's plaintext packet buffers).
//! They live in this process's heap until the memory is reused.
//!
//! # Errors
//! [`SshError`] variants are precise; [`SshError::class`] groups them into
//! [`ErrorClass::Network`], [`ErrorClass::Permission`], [`ErrorClass::HostKey`],
//! [`ErrorClass::Config`], [`ErrorClass::Remote`] and [`ErrorClass::Internal`].
//!
//! # Example
//! ```no_run
//! use wol_ssh::{SshError, Target};
//! use wol_ssh::Zeroizing;
//!
//! let mut t = Target::new("100.105.128.10", "root");
//! t.auth.password = Some(Zeroizing::new("secret".to_string()));
//! t.host_key = None; // first contact
//! match wol_ssh::boot_time(&t) {
//!     Ok(b) => println!("booted {:?} ago", b.uptime),
//!     Err(SshError::UnknownHostKey { openssh_line, fingerprint_sha256 }) => {
//!         // show fingerprint_sha256; if trusted: store openssh_line in the host config, retry
//!         # let _ = (openssh_line, fingerprint_sha256);
//!     }
//!     Err(e) => eprintln!("{e}"),
//! }
//! ```
#![warn(missing_docs)]

mod boot;
mod error;
mod hostkey;
mod info;
mod net;
mod power;
mod scripts;
mod session;
mod target;

pub use boot::BootInfo;
pub use error::{ErrorClass, Result, SshError, TimeoutStage};
pub use hostkey::{
    HostKeyInfo, fingerprints_match, known_hosts_keys, known_hosts_keys_in, parse_host_key,
};
pub use info::ConnInfo;
pub use net::{Mac, MacCandidate, NicKind, WolInfo, format_mac};
pub use power::{Elevation, PowerAction, PowerOverrides, PowerScheduled};
pub use session::{ExecOutput, OUTPUT_CAP, Session, scan_host_key};
pub use target::{Auth, SudoMode, Target, Timeouts};
/// Re-export of [`zeroize::Zeroizing`], the wrapper used for every secret in this API.
pub use zeroize::Zeroizing;

/// Connect, then read OS / user / root status / boot time (read-only).
///
/// **Blocking**: at most [`Timeouts::connect_worst_case`] + [`Timeouts::command`] + 1 s
/// (61 s with the defaults; typically well under a second on a LAN / VPN).
///
/// # Errors
/// See [`Session::connect`] and [`Session::conn_info`].
pub fn test_connection(target: &Target) -> Result<ConnInfo> {
    let mut s = Session::connect(target)?;
    let r = s.conn_info();
    s.close();
    r
}

/// Connect, then read the boot time (read-only).
///
/// **Blocking**: at most [`Timeouts::connect_worst_case`] + [`Timeouts::command`] + 1 s.
///
/// # Errors
/// See [`Session::connect`] and [`Session::boot_time`].
pub fn boot_time(target: &Target) -> Result<BootInfo> {
    let mut s = Session::connect(target)?;
    let r = s.boot_time();
    s.close();
    r
}

/// Connect, then rank the host's physical NICs for Wake-on-LAN (read-only).
///
/// **Blocking**: at most [`Timeouts::connect_worst_case`] + [`Timeouts::command`] + 1 s.
///
/// # Errors
/// See [`Session::connect`] and [`Session::mac_candidates`].
pub fn mac_candidates(target: &Target) -> Result<Vec<MacCandidate>> {
    let mut s = Session::connect(target)?;
    let r = s.mac_candidates();
    s.close();
    r
}

/// Connect, then schedule a restart / shutdown (see [`Session::power`]).
///
/// Success means the host confirmed that the command was scheduled (~2 s later); verify the
/// outcome by polling (restart: [`BootInfo::rebooted_since`]; shutdown: the host stops
/// answering).
///
/// **Blocking**: at most [`Timeouts::connect_worst_case`] + 3 × [`Timeouts::command`] + 1 s.
///
/// # Errors
/// See [`Session::connect`] and [`Session::power`].
pub fn power(
    target: &Target,
    action: PowerAction,
    overrides: &PowerOverrides,
) -> Result<PowerScheduled> {
    let mut s = Session::connect(target)?;
    let r = s.power(action, overrides);
    s.close();
    r
}
