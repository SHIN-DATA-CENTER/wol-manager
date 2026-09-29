//! Read-only check of the Windows remote backend against THIS PC, through `wol_core::remote`
//! (dispatch, error mapping, result conversion). Ignored by default; run it explicitly:
//!
//! ```text
//! cargo test -p wol-core --locked --test remote_local -- --ignored --nocapture
//! ```
//!
//! It only READS: the boot time (SMB / NetRemoteTOD to `localhost` with the current Windows
//! sign-in) and the physical NIC candidates (local WMI). No credentials are read or written
//! (in-memory secret store), nothing is restarted or shut down, no other machine is contacted.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use wol_core::i18n::{Lang, describe_error};
use wol_core::remote::{RemoteClient, SystemSsh, SystemWindows};
use wol_core::secret::SecretStore;
use wol_core::{Host, RemoteConfig, RemoteKind, Settings};

fn this_pc() -> Host {
    let mut h = Host::new("this-pc", "02:00:00:00:00:01".parse().unwrap());
    h.address = Some("localhost".parse().unwrap());
    h.remote = Some(RemoteConfig::new(RemoteKind::Windows));
    h
}

fn client() -> RemoteClient {
    RemoteClient::new(
        SecretStore::in_memory(),
        Arc::new(SystemWindows),
        Arc::new(SystemSsh),
    )
}

#[test]
#[ignore = "reads this PC's boot time and NICs; run explicitly"]
fn this_pc_boot_time_and_mac_candidates() {
    let host = this_pc();
    let settings = Settings::default();
    let c = client();

    match c.boot_time(&host, &settings) {
        Ok(b) => {
            println!(
                "boot_time: {} | uptime {:?} | source {} | approximate {}",
                b.boot_line(Lang::Ja),
                b.uptime,
                b.source,
                b.approximate
            );
            println!("           {}", b.boot_line(Lang::En));
            assert!(b.uptime > Duration::ZERO);
            assert!(b.boot_time < SystemTime::now());
            assert!(b.source.starts_with("windows/"));
        }
        Err(e) => panic!("boot_time failed: {e}\n{}", describe_error(&e, Lang::Ja)),
    }

    match c.mac_candidates(&host, &settings) {
        Ok(v) => {
            for m in &v {
                println!(
                    "mac: {} {} kind {:?} default_route {} link_up {} lan {:?}",
                    m.iface,
                    m.mac,
                    m.kind,
                    m.on_default_route,
                    m.link_up,
                    m.lan_ipv4.map(|s| s.to_string())
                );
            }
            assert!(!v.is_empty());
            assert!(v.iter().all(|m| m.mac.is_usable()));
        }
        Err(e) => panic!(
            "mac_candidates failed: {e}\n{}",
            describe_error(&e, Lang::Ja)
        ),
    }
}
