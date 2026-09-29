//! Core library of WoL Manager.
//!
//! Shared by the GUI (`wol-manager.exe`) and the CLI (`wolm.exe`). Contains no UI code and
//! no Slint dependency.
//!
//! # Map of the crate
//! | Module | Purpose |
//! |---|---|
//! | [`consts`] | Identifiers shared with the installer (file names, mutex names, env vars) |
//! | [`error`] | [`Error`] / [`ErrorKind`], and the field-validation types [`FieldError`] / [`FieldIssue`] |
//! | [`normalize`] | Full-width → half-width folding for IME input, kana detection, comparison keys |
//! | [`mac`] / [`addr`] | [`MacAddr`], [`SecureOn`], IPv4 / port / host / `host[:port]` parsers |
//! | [`magic`] | Magic packet build / parse |
//! | [`model`] | `config.toml` schema: [`Config`], [`Host`], [`Settings`], [`HostDraft`] |
//! | [`netif`] | Network interface enumeration and selection (pure `select` / `explain`) |
//! | [`send`] | Wake planning (pure `plan`) and sending (`execute`, `wake`, `wake_many`) |
//! | [`probe`] | Online checks: ICMP (IcmpSendEcho) and TCP connect |
//! | [`arp`] | MAC lookup from an IPv4 address (SendARP) |
//! | [`store`] | Settings location, locked read-modify-write of `config.toml`, portable mode |
//! | [`pathenv`] | Adding / removing the CLI folder to / from the user or machine `PATH` |
//! | [`i18n`] | Japanese / English runtime messages ([`i18n::Msg`]) |
//! | [`transfer`] | TOML / JSON / CSV export and import |
//! | [`sys`] | Small Windows helpers (elevation, exe folder, wide strings, folder ACLs) |
//! | [`instance`] | The running GUI's settings folder (single-instance checks) |
//!
//! # Threading
//! Everything here is synchronous. Calls that may block for a noticeable time are marked
//! **Blocking** in their docs (network sends, probes, ARP, DNS, registry broadcast, file
//! locks). GUI code must run them on worker threads.
//!
//! The crate targets Windows only (it uses the registry, IP Helper and user32).
#![warn(missing_docs)]

pub mod addr;
pub mod arp;
pub mod consts;
pub mod error;
pub mod i18n;
pub mod instance;
pub mod mac;
pub mod magic;
pub mod model;
pub mod netif;
pub mod normalize;
pub mod pathenv;
pub mod probe;
pub mod send;
pub mod store;
pub mod sys;
pub mod transfer;

pub use addr::{HostAddr, Target};
pub use error::{Error, ErrorKind, Field, FieldError, FieldIssue, Result};
pub use mac::{MacAddr, SecureOn};
pub use model::{Config, EditBase, Host, HostDraft, HostId, Settings};

#[cfg(test)]
mod thread_safety {
    //! Types handed to worker threads by the GUI must be `Send` (and the store `Sync`).
    fn send<T: Send>() {}
    fn sync<T: Sync>() {}

    #[test]
    fn public_types_cross_threads() {
        send::<crate::Error>();
        sync::<crate::Error>();
        send::<crate::Config>();
        send::<crate::store::Store>();
        sync::<crate::store::Store>();
        send::<crate::store::Loaded>();
        send::<crate::send::WakeRequest>();
        send::<crate::send::WakeReport>();
        send::<crate::probe::ProbeSpec>();
        send::<crate::probe::HostState>();
        send::<crate::netif::NetInterface>();
        send::<Box<dyn crate::pathenv::EnvBackend>>();
        sync::<crate::pathenv::RegistryBackend>();
        send::<crate::i18n::Msg>();
    }
}
