//! Read-only verification against **this** PC. These tests are `#[ignore]`d so the normal gate
//! never touches machine state or the network; run them with:
//!
//! ```text
//! cargo test -p wol-winremote --locked -- --ignored --nocapture
//! ```
//!
//! They only READ: boot time (local NetAPI and the loopback SMB path), the local WMI adapter and
//! OS queries. No shutdown, abort, IPC$ connection with credentials, or credential write happens
//! here, and no other machine is contacted (only this PC: `""`, `"."`, `127.0.0.1`).

#![cfg(windows)]

use std::time::{Duration, UNIX_EPOCH};
use wol_winremote::{RemoteHost, boot, wmi};

/// `Win32_OperatingSystem.LastBootUpTime` in Unix milliseconds, via PowerShell (read-only).
fn wmi_last_boot_unix_ms() -> Option<i64> {
    let out = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[DateTimeOffset]::new((Get-CimInstance Win32_OperatingSystem).LastBootUpTime)\
             .ToUnixTimeMilliseconds()",
        ])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

fn unix_ms(t: std::time::SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

fn assert_matches_last_boot(bi: &wol_winremote::BootInfo) {
    let ours = unix_ms(bi.boot_time_utc);
    let theirs = wmi_last_boot_unix_ms().expect("LastBootUpTime via PowerShell");
    let diff = (ours - theirs).abs();
    println!(
        "boot_time_utc={ours} ms, LastBootUpTime={theirs} ms, diff={diff} ms, uptime={:?}, \
         source={}, approximate={}",
        bi.uptime, bi.source, bi.approximate
    );
    assert!(
        diff < 60_000,
        "boot time differs from LastBootUpTime by {diff} ms"
    );
}

#[test]
#[ignore = "reads the local machine; run explicitly"]
fn local_boot_time_matches_last_boot_up_time() {
    // Empty server = the local machine (NetRemoteTOD/NetStatisticsGet).
    let bi = boot::boot_time("").expect("local boot_time should succeed");
    assert_eq!(bi.source, "NetRemoteTOD+NetStatisticsGet");
    assert!(!bi.approximate);
    assert!(bi.uptime > Duration::ZERO);
    assert_matches_last_boot(&bi);
}

#[test]
#[ignore = "reads this PC over loopback SMB (current logon, no credentials); run explicitly"]
fn public_boot_time_over_loopback_smb() {
    let bi = wol_winremote::boot_time(&RemoteHost::new("127.0.0.1"))
        .expect("loopback boot_time should succeed");
    assert_matches_last_boot(&bi);
}

#[test]
#[ignore = "reads the local machine over WMI; run explicitly"]
fn local_mac_candidates_finds_a_physical_nic() {
    // "." + no credentials = local WMI.
    let cands = wmi::mac_candidates(".", None, false).expect("local WMI query should succeed");
    for c in &cands {
        println!(
            "iface={} mac={} perm={:?} kind={:?} default_route={} link_up={} score={} ip={:?}",
            c.iface,
            c.mac,
            c.permanent_mac,
            c.kind,
            c.on_default_route,
            c.link_up,
            c.score,
            c.lan_ipv4
        );
    }
    assert!(!cands.is_empty(), "expected at least one physical NIC");
    assert!(
        cands[0].on_default_route,
        "the best candidate carries the default route"
    );
}

#[test]
#[ignore = "reads this PC over WMI through the public API (135 on loopback); run explicitly"]
fn public_mac_candidates_and_test_connection_on_loopback() {
    let host = RemoteHost::new("127.0.0.1");
    let local = wmi::mac_candidates(".", None, false).unwrap();
    let cands = wol_winremote::mac_candidates(&host).expect("public mac_candidates on loopback");
    assert_eq!(
        cands.iter().map(|c| &c.mac).collect::<Vec<_>>(),
        local.iter().map(|c| &c.mac).collect::<Vec<_>>()
    );
    let info = wol_winremote::test_connection(&host).expect("test_connection on loopback");
    println!(
        "os={:?} admin={:?} check={:?} boot={:?}",
        info.os, info.user_is_admin_or_root, info.admin_check, info.boot.boot_time_utc
    );
    assert!(info.os.as_deref().unwrap_or("").contains("Windows"));
    // This PC: nothing to warn about (review R3).
    assert_eq!(info.admin_check, wol_winremote::AdminCheck::Local);
    assert_matches_last_boot(&info.boot);
}

#[test]
#[ignore = "reads the local machine over WMI; run explicitly"]
fn wmi_with_credentials_on_this_pc_retries_without_them() {
    // WMI refuses explicit credentials for "." / "localhost" / the computer name
    // (WBEM_E_LOCAL_CREDENTIALS); the crate retries with the process identity. The account is
    // deliberately nonexistent, so a real logon attempt would fail.
    const CREDS: Option<(&str, &str)> = Some(("wol-manager-test-nonexistent", "not-a-password"));
    let name = std::env::var("COMPUTERNAME").expect("COMPUTERNAME");
    for h in [".", "localhost", name.as_str()] {
        let cands = wmi::mac_candidates(h, CREDS, false)
            .unwrap_or_else(|e| panic!("{h}: local WMI with credentials should fall back: {e}"));
        assert!(!cands.is_empty(), "{h}");
        let os = wmi::os_caption(h, CREDS, false).unwrap_or_else(|e| panic!("{h}: {e}"));
        println!("{h}: {} candidate(s), os caption {os}", cands.len());
    }
    // This PC's own IP literals are NOT local to WMI (it attempts a loopback DCOM logon); the
    // public API recognizes them first and queries locally without credentials or any logon.
    let host = RemoteHost::new("127.0.0.1")
        .with_credentials("wol-manager-test-nonexistent", "not-a-password");
    let cands = wol_winremote::mac_candidates(&host).expect("public API on this PC's own IP");
    assert!(!cands.is_empty());
}
