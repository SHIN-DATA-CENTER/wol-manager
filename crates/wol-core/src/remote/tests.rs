//! Dispatch, credential resolution, error classification and verification, all with mock
//! backends: nothing here touches the network or any power API.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::*;
use crate::ErrorKind;
use crate::i18n::describe_error;
use crate::probe::{HostState, ProbeVia};

const ED25519: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

pub(crate) fn t0() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_790_669_520)
}

// ---- mocks ------------------------------------------------------------------------------------

/// What a backend was called with (secrets included so the tests can check resolution).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Seen {
    pub(crate) op: &'static str,
    pub(crate) host: String,
    pub(crate) user: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) connect_ms: u128,
    // SSH only
    pub(crate) port: u16,
    pub(crate) key_file: Option<PathBuf>,
    pub(crate) passphrase: Option<String>,
    pub(crate) host_key: Option<String>,
    pub(crate) sudo: Option<wol_ssh::SudoMode>,
    pub(crate) sudo_password: Option<String>,
    // power
    pub(crate) action: Option<&'static str>,
    pub(crate) delay: Option<u32>,
    pub(crate) force: Option<bool>,
    pub(crate) message: Option<String>,
    pub(crate) reboot_command: Option<String>,
}

type WinResult<T> = wol_winremote::Result<T>;

#[derive(Default)]
pub(crate) struct MockWin {
    pub(crate) seen: Mutex<Vec<Seen>>,
    pub(crate) fail: Mutex<Option<wol_winremote::Error>>,
    pub(crate) boots: Mutex<VecDeque<WinResult<wol_winremote::BootInfo>>>,
    pub(crate) macs: Mutex<Vec<wol_winremote::MacCandidate>>,
    pub(crate) outcome: Mutex<Option<wol_winremote::PowerOutcome>>,
}

impl MockWin {
    fn record(&self, op: &'static str, h: &wol_winremote::RemoteHost) -> Seen {
        let s = Seen {
            op,
            host: h.host.clone(),
            user: h.user.clone(),
            password: h.password.as_ref().map(|p| p.to_string()),
            connect_ms: h.connect_timeout.as_millis(),
            ..Seen::default()
        };
        self.seen.lock().unwrap().push(s.clone());
        s
    }
    fn fail(&self) -> WinResult<()> {
        match self.fail.lock().unwrap().clone() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
    pub(crate) fn last(&self) -> Seen {
        self.seen.lock().unwrap().last().cloned().expect("a call")
    }
}

pub(crate) fn win_boot(uptime_s: u64) -> wol_winremote::BootInfo {
    wol_winremote::BootInfo {
        boot_time_utc: t0() - Duration::from_secs(uptime_s),
        uptime: Duration::from_secs(uptime_s),
        source: "NetRemoteTOD+NetStatisticsGet".into(),
        approximate: false,
        boot_id: None,
    }
}

impl WindowsBackend for MockWin {
    fn boot_time(&self, h: &wol_winremote::RemoteHost) -> WinResult<wol_winremote::BootInfo> {
        self.record("boot_time", h);
        self.fail()?;
        self.boots
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Ok(win_boot(3600)))
    }
    fn power(
        &self,
        h: &wol_winremote::RemoteHost,
        action: wol_winremote::PowerAction,
        opts: &wol_winremote::PowerOptions,
    ) -> WinResult<wol_winremote::PowerOutcome> {
        let mut s = self.record("power", h);
        s.action = Some(match action {
            wol_winremote::PowerAction::Restart => "restart",
            wol_winremote::PowerAction::Shutdown => "shutdown",
        });
        s.delay = Some(opts.delay_secs);
        s.force = Some(opts.force);
        s.message = opts.message.clone();
        *self.seen.lock().unwrap().last_mut().unwrap() = s;
        self.fail()?;
        Ok(self
            .outcome
            .lock()
            .unwrap()
            .unwrap_or(wol_winremote::PowerOutcome::Scheduled))
    }
    fn abort_shutdown(&self, h: &wol_winremote::RemoteHost) -> WinResult<()> {
        self.record("abort", h);
        self.fail()
    }
    fn mac_candidates(
        &self,
        h: &wol_winremote::RemoteHost,
    ) -> WinResult<Vec<wol_winremote::MacCandidate>> {
        self.record("mac", h);
        self.fail()?;
        Ok(self.macs.lock().unwrap().clone())
    }
    fn test_connection(&self, h: &wol_winremote::RemoteHost) -> WinResult<wol_winremote::ConnInfo> {
        self.record("test", h);
        self.fail()?;
        Ok(wol_winremote::ConnInfo {
            os: Some("Microsoft Windows 11 Pro".into()),
            boot: win_boot(600),
            user_is_admin_or_root: Some(true),
            admin_check: wol_winremote::AdminCheck::Admin,
        })
    }
}

type SshErrFn = Box<dyn Fn() -> wol_ssh::SshError + Send + Sync>;

#[derive(Default)]
pub(crate) struct MockSsh {
    pub(crate) seen: Mutex<Vec<Seen>>,
    pub(crate) fail: Mutex<Option<SshErrFn>>,
    pub(crate) boots: Mutex<VecDeque<wol_ssh::BootInfo>>,
    pub(crate) macs: Mutex<Vec<wol_ssh::MacCandidate>>,
    pub(crate) known_hosts: Mutex<Vec<wol_ssh::HostKeyInfo>>,
}

impl MockSsh {
    fn record(&self, op: &'static str, t: &wol_ssh::Target) -> Seen {
        let s = Seen {
            op,
            host: t.host.clone(),
            user: Some(t.user.clone()),
            password: t.auth.password.as_ref().map(|p| p.to_string()),
            connect_ms: t.timeouts.connect.as_millis(),
            port: t.port,
            key_file: t.auth.key_file.clone(),
            passphrase: t.auth.key_passphrase.as_ref().map(|p| p.to_string()),
            host_key: t.host_key.clone(),
            sudo: Some(t.sudo),
            sudo_password: t.sudo_password.as_ref().map(|p| p.to_string()),
            ..Seen::default()
        };
        self.seen.lock().unwrap().push(s.clone());
        s
    }
    fn fail(&self) -> wol_ssh::Result<()> {
        match &*self.fail.lock().unwrap() {
            Some(f) => Err(f()),
            None => Ok(()),
        }
    }
    pub(crate) fn set_fail(&self, f: impl Fn() -> wol_ssh::SshError + Send + Sync + 'static) {
        *self.fail.lock().unwrap() = Some(Box::new(f));
    }
    pub(crate) fn last(&self) -> Seen {
        self.seen.lock().unwrap().last().cloned().expect("a call")
    }
    pub(crate) fn calls(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

pub(crate) fn ssh_boot(uptime_s: u64, id: &str) -> wol_ssh::BootInfo {
    wol_ssh::BootInfo {
        btime: 1_790_669_520 - uptime_s as i64,
        remote_now: Some(1_790_669_520),
        uptime: Duration::from_secs(uptime_s),
        boot_time_local: t0() - Duration::from_secs(uptime_s),
        approximate: false,
        source: "proc_stat".into(),
        boot_id: Some(id.into()),
        kernel: "Linux".into(),
    }
}

impl SshBackend for MockSsh {
    fn boot_time(&self, t: &wol_ssh::Target) -> wol_ssh::Result<wol_ssh::BootInfo> {
        self.record("boot_time", t);
        self.fail()?;
        Ok(self
            .boots
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| ssh_boot(3600, "boot-a")))
    }
    fn power(
        &self,
        t: &wol_ssh::Target,
        action: wol_ssh::PowerAction,
        o: &wol_ssh::PowerOverrides,
    ) -> wol_ssh::Result<wol_ssh::PowerScheduled> {
        let mut s = self.record("power", t);
        s.action = Some(match action {
            wol_ssh::PowerAction::Restart => "restart",
            wol_ssh::PowerAction::Shutdown => "shutdown",
        });
        s.reboot_command = o.reboot_command.clone();
        *self.seen.lock().unwrap().last_mut().unwrap() = s;
        self.fail()?;
        Ok(wol_ssh::PowerScheduled {
            method: "systemd-run".into(),
            unit: Some("wolm-power-0123abcd".into()),
            command: "systemctl reboot".into(),
            wol_armed: None,
            elevation: wol_ssh::Elevation::SudoPassword,
        })
    }
    fn mac_candidates(&self, t: &wol_ssh::Target) -> wol_ssh::Result<Vec<wol_ssh::MacCandidate>> {
        self.record("mac", t);
        self.fail()?;
        Ok(self.macs.lock().unwrap().clone())
    }
    fn test_connection(&self, t: &wol_ssh::Target) -> wol_ssh::Result<wol_ssh::ConnInfo> {
        self.record("test", t);
        self.fail()?;
        Ok(wol_ssh::ConnInfo {
            os: "Debian GNU/Linux 12 (bookworm)".into(),
            kernel: "Linux 6.1.0-18-amd64".into(),
            user: "pi".into(),
            uid: Some(1000),
            is_root: false,
            groups: vec!["pi".into(), "sudo".into()],
            boot: ssh_boot(120, "boot-b"),
        })
    }
    fn scan_host_key(
        &self,
        host: &str,
        port: u16,
        _timeouts: wol_ssh::Timeouts,
    ) -> wol_ssh::Result<wol_ssh::HostKeyInfo> {
        self.seen.lock().unwrap().push(Seen {
            op: "scan",
            host: host.into(),
            port,
            ..Seen::default()
        });
        self.fail()?;
        wol_ssh::parse_host_key(ED25519)
    }
    fn known_hosts_keys(&self, _host: &str, _port: u16) -> Vec<wol_ssh::HostKeyInfo> {
        self.known_hosts.lock().unwrap().clone()
    }
}

/// Fake clock + scripted probes. `sleep_until` jumps the clock.
pub(crate) struct FakeEnv {
    now: Mutex<Instant>,
    start_wall: SystemTime,
    start: Instant,
    probes: Mutex<VecDeque<HostState>>,
    fallback: HostState,
    probed: Mutex<Vec<Option<crate::HostAddr>>>,
    cancel_after: Option<usize>,
}

impl FakeEnv {
    pub(crate) fn new(probes: Vec<HostState>, fallback: HostState) -> FakeEnv {
        let start = Instant::now();
        FakeEnv {
            now: Mutex::new(start),
            start_wall: t0(),
            start,
            probes: Mutex::new(probes.into()),
            fallback,
            probed: Mutex::new(Vec::new()),
            cancel_after: None,
        }
    }
    fn probe_count(&self) -> usize {
        self.probed.lock().unwrap().len()
    }
}

impl VerifyEnv for FakeEnv {
    fn probe(&self, spec: &crate::probe::ProbeSpec) -> HostState {
        self.probed.lock().unwrap().push(spec.address.clone());
        self.probes
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| self.fallback.clone())
    }
    fn now(&self) -> Instant {
        *self.now.lock().unwrap()
    }
    fn wall_clock(&self) -> SystemTime {
        self.start_wall + self.now().duration_since(self.start)
    }
    fn sleep_until(&self, until: Instant, cancel: &AtomicBool) -> bool {
        if let Some(n) = self.cancel_after
            && self.probe_count() >= n
        {
            cancel.store(true, Ordering::Relaxed);
        }
        if cancel.load(Ordering::Relaxed) {
            return false;
        }
        let mut now = self.now.lock().unwrap();
        if until > *now {
            *now = until;
        }
        true
    }
}

pub(crate) fn up() -> HostState {
    HostState::Up {
        via: ProbeVia::Tcp { port: 445 },
        rtt: Duration::from_millis(3),
        ip: Ipv4Addr::new(100, 105, 1, 2),
    }
}

pub(crate) fn down() -> HostState {
    HostState::Down {
        ip: Ipv4Addr::new(100, 105, 1, 2),
    }
}

pub(crate) struct Rig {
    pub(crate) win: Arc<MockWin>,
    pub(crate) ssh: Arc<MockSsh>,
    pub(crate) secrets: SecretStore,
    pub(crate) settings: Settings,
}

impl Rig {
    pub(crate) fn new() -> Rig {
        let mut settings = Settings::default();
        settings.remote.connect_timeout_ms = 7000;
        Rig {
            win: Arc::new(MockWin::default()),
            ssh: Arc::new(MockSsh::default()),
            secrets: SecretStore::in_memory(),
            settings,
        }
    }
    pub(crate) fn client(&self) -> RemoteClient {
        RemoteClient::new(self.secrets.clone(), self.win.clone(), self.ssh.clone())
    }
    pub(crate) fn client_env(&self, env: Arc<FakeEnv>) -> RemoteClient {
        self.client().with_verify_env(env)
    }
}

pub(crate) fn host(kind: Option<RemoteKind>) -> Host {
    let mut h = Host::new("nas", "02:00:00:00:00:01".parse().unwrap());
    h.address = Some("192.168.1.20".parse().unwrap());
    h.remote = kind.map(RemoteConfig::new);
    h
}

pub(crate) fn remote(h: &mut Host) -> &mut RemoteConfig {
    h.remote.as_mut().unwrap()
}

// ---- dispatch & credentials -------------------------------------------------------------------

#[test]
fn not_configured_and_no_address() {
    let rig = Rig::new();
    let c = rig.client();
    let e = c.boot_time(&host(None), &rig.settings).unwrap_err();
    assert!(matches!(e, Error::RemoteNotConfigured { ref host } if host == "nas"));
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
    let mut h = host(Some(RemoteKind::Ssh));
    h.address = None;
    let e = c.mac_candidates(&h, &rig.settings).unwrap_err();
    assert!(matches!(e, Error::RemoteNoAddress { .. }));
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
    // The management address alone is enough.
    remote(&mut h).address = Some("100.105.1.2".parse().unwrap());
    c.boot_time(&h, &rig.settings).unwrap();
    assert_eq!(rig.ssh.last().host, "100.105.1.2");
    assert_eq!(rig.win.seen.lock().unwrap().len(), 0);
    for e in [
        Error::RemoteNotConfigured { host: "x".into() },
        Error::RemoteNoAddress { host: "x".into() },
    ] {
        assert!(!describe_error(&e, Lang::Ja).is_empty());
        assert!(describe_error(&e, Lang::En).is_ascii());
    }
}

#[test]
fn windows_uses_management_address_stored_login_and_timeout() {
    let rig = Rig::new();
    let mut h = host(Some(RemoteKind::Windows));
    remote(&mut h).address = Some("100.105.1.2".parse().unwrap());
    remote(&mut h).user = Some(r"DESKTOP-6FDOQLK\admin".into());
    assert_eq!(
        rig.secrets
            .set_for_host(&h, SecretKind::Login, "ignored-account", "pw")
            .unwrap(),
        r"DESKTOP-6FDOQLK\admin"
    );
    let b = rig.client().boot_time(&h, &rig.settings).unwrap();
    let seen = rig.win.last();
    assert_eq!(seen.host, "100.105.1.2");
    assert_eq!(seen.user.as_deref(), Some(r"DESKTOP-6FDOQLK\admin"));
    assert_eq!(seen.password.as_deref(), Some("pw"));
    assert_eq!(seen.connect_ms, 7000);
    assert_eq!(b.source, "windows/NetRemoteTOD+NetStatisticsGet");
    assert_eq!(b.boot_time, t0() - Duration::from_secs(3600));
    assert_eq!(b.uptime, Duration::from_secs(3600));
    assert!(!b.approximate);
    assert!(rig.ssh.seen.lock().unwrap().is_empty());
}

#[test]
fn windows_account_resolution() {
    let rig = Rig::new();
    let c = rig.client();
    let mut h = host(Some(RemoteKind::Windows));
    // Nothing stored, no configured user: the current Windows sign-in.
    c.boot_time(&h, &rig.settings).unwrap();
    assert_eq!((rig.win.last().user, rig.win.last().password), (None, None));
    // Nothing stored and the configured user is the current sign-in: single sign-on.
    if let Some(me) = current_windows_account() {
        remote(&mut h).user = Some(me);
        c.boot_time(&h, &rig.settings).unwrap();
        assert_eq!((rig.win.last().user, rig.win.last().password), (None, None));
    }
    // No configured user: the account stored with the password.
    remote(&mut h).user = None;
    rig.secrets
        .set_for_host(&h, SecretKind::Login, r"NAS\backup", "pw")
        .unwrap();
    c.boot_time(&h, &rig.settings).unwrap();
    assert_eq!(rig.win.last().user.as_deref(), Some(r"NAS\backup"));
    // A password without any account: the current Windows account name with that password.
    rig.secrets
        .set_for_host(&h, SecretKind::Login, "  ", "pw")
        .unwrap();
    c.boot_time(&h, &rig.settings).unwrap();
    assert_eq!(rig.win.last().user, current_windows_account());
    assert_eq!(rig.win.last().password.as_deref(), Some("pw"));
    // `.\user` is sent as the bare user name.
    remote(&mut h).user = Some(r".\Administrator".into());
    rig.secrets
        .set_for_host(&h, SecretKind::Login, "", "admin-pw")
        .unwrap();
    c.boot_time(&h, &rig.settings).unwrap();
    assert_eq!(rig.win.last().user.as_deref(), Some("Administrator"));
    assert_eq!(rig.win.last().password.as_deref(), Some("admin-pw"));
    assert_eq!(windows_account(r" PC\u "), r"PC\u");
}

/// Review m6 / n3: the current sign-in never sends this PC's name as the domain, and the
/// checks do not depend on the environment the tests run in.
#[test]
fn current_account_forms() {
    let s = |v: &str| Some(v.to_owned());
    // Local account (USERDOMAIN = COMPUTERNAME) or Microsoft account: bare user name.
    assert_eq!(
        account_from_env(s("comug"), s("MYPC"), s("mypc")).as_deref(),
        Some("comug")
    );
    // Domain account.
    assert_eq!(
        account_from_env(s("taro"), s("CORP"), s("MYPC")).as_deref(),
        Some(r"CORP\taro")
    );
    assert_eq!(
        account_from_env(s("taro"), None, s("MYPC")).as_deref(),
        Some("taro")
    );
    assert_eq!(account_from_env(None, s("CORP"), s("MYPC")), None);
    // Single sign-on only for the sign-in itself.
    let local = |u: &str| is_current_account_in(u, Some("comug"), Some("MYPC"), Some("MYPC"));
    assert!(local("comug") && local(r".\Comug") && local(r"mypc\comug"));
    assert!(!local("admin") && !local(r"OTHER\comug") && !local("comug@example.com"));
    let domain = |u: &str| is_current_account_in(u, Some("taro"), Some("CORP"), Some("MYPC"));
    assert!(domain(r"corp\taro"));
    // A bare name on a domain PC is the TARGET's local account, not this sign-in.
    assert!(!domain("taro") && !domain(r"MYPC\taro"));
    assert!(!is_current_account_in("x", None, None, None));
    if let Some(me) = current_windows_account() {
        assert!(is_current_windows_account(&me), "{me}");
    }
}

#[test]
fn windows_power_options_outcomes_and_abort() {
    let rig = Rig::new();
    let c = rig.client();
    let h = host(Some(RemoteKind::Windows));
    let opts = PowerOptions {
        delay_secs: 45,
        force: false,
        message: Some("  ".into()),
    };
    let out = c
        .power(&h, &rig.settings, PowerAction::Shutdown, &opts)
        .unwrap();
    assert_eq!(out, PowerOutcome::Scheduled { delay_secs: 45 });
    let s = rig.win.last();
    assert_eq!(
        (s.op, s.action, s.delay, s.force, s.message),
        ("power", Some("shutdown"), Some(45), Some(false), None)
    );
    *rig.win.outcome.lock().unwrap() = Some(wol_winremote::PowerOutcome::Accepted);
    let opts = PowerOptions {
        message: Some(" Backup done ".into()),
        ..PowerOptions::from_settings(&rig.settings.remote)
    };
    assert_eq!(opts.delay_secs, 30);
    assert!(opts.force);
    let out = c
        .power(&h, &rig.settings, PowerAction::Restart, &opts)
        .unwrap();
    assert_eq!(out, PowerOutcome::Accepted);
    assert_eq!(out.delay_secs(), 0);
    assert_eq!(rig.win.last().message.as_deref(), Some("Backup done"));
    assert_eq!(rig.win.last().action, Some("restart"));
    c.abort_shutdown(&h, &rig.settings).unwrap();
    assert_eq!(rig.win.last().op, "abort");
    // Cancelling is Windows only.
    let e = c
        .abort_shutdown(&host(Some(RemoteKind::Ssh)), &rig.settings)
        .unwrap_err();
    assert!(matches!(
        e,
        Error::RemoteUnsupported {
            kind: RemoteKind::Ssh,
            op: RemoteOp::AbortShutdown,
            ..
        }
    ));
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
    assert_eq!(rig.ssh.calls(), 0);
    assert!(describe_error(&e, Lang::Ja).contains("Windows"));
    // Verification time includes the countdown.
    assert_eq!(
        verify_timeout(
            PowerAction::Restart,
            &rig.settings,
            &PowerOutcome::Scheduled { delay_secs: 45 }
        ),
        Duration::from_secs(645)
    );
    assert_eq!(
        verify_timeout(
            PowerAction::Shutdown,
            &rig.settings,
            &PowerOutcome::Accepted
        ),
        Duration::from_secs(300)
    );
}

#[test]
fn ssh_target_defaults_keys_and_passphrase() {
    let rig = Rig::new();
    let c = rig.client();
    let mut h = host(Some(RemoteKind::Ssh));
    c.boot_time(&h, &rig.settings).unwrap();
    let s = rig.ssh.last();
    assert_eq!(s.host, "192.168.1.20");
    assert_eq!(s.user.as_deref(), Some("root"));
    assert_eq!(s.port, 22);
    assert_eq!(s.connect_ms, 7000);
    assert_eq!((s.key_file, s.password, s.host_key), (None, None, None));
    // Key file + passphrase (read only with a key file), login password, pinned key, port.
    rig.secrets
        .set_for_host(&h, SecretKind::KeyPassphrase, "", "pp")
        .unwrap();
    rig.secrets
        .set_for_host(&h, SecretKind::Login, "", "root-pw")
        .unwrap();
    c.boot_time(&h, &rig.settings).unwrap();
    assert_eq!(rig.ssh.last().passphrase, None);
    assert_eq!(rig.ssh.last().password.as_deref(), Some("root-pw"));
    let r = remote(&mut h);
    r.user = Some("pi".into());
    r.port = Some(2222);
    r.key_file = Some(PathBuf::from(r"C:\Users\me\.ssh\id_ed25519"));
    r.host_key = Some(format!(" {ED25519} "));
    // Review M3: root's password is never sent for pi (with a key file it is just left out).
    c.boot_time(&h, &rig.settings).unwrap();
    assert_eq!(rig.ssh.last().password, None);
    assert_eq!(rig.ssh.last().user.as_deref(), Some("pi"));
    rig.secrets
        .set_for_host(&h, SecretKind::Login, "", "pw")
        .unwrap();
    c.boot_time(&h, &rig.settings).unwrap();
    let s = rig.ssh.last();
    assert_eq!(s.user.as_deref(), Some("pi"));
    assert_eq!(s.port, 2222);
    assert_eq!(
        s.key_file.as_deref(),
        Some(std::path::Path::new(r"C:\Users\me\.ssh\id_ed25519"))
    );
    assert_eq!(s.passphrase.as_deref(), Some("pp"));
    assert_eq!(s.password.as_deref(), Some("pw"));
    assert_eq!(s.host_key.as_deref(), Some(ED25519));
    // Boot info mapping.
    let b = c.boot_time(&h, &rig.settings).unwrap();
    assert_eq!(b.source, "ssh/proc_stat");
    assert_eq!(b.boot_id.as_deref(), Some("boot-a"));
    assert_eq!(b.boot_time, t0() - Duration::from_secs(3600));
}

#[test]
fn ssh_sudo_modes() {
    let rig = Rig::new();
    let c = rig.client();
    let mut h = host(Some(RemoteKind::Ssh));
    remote(&mut h).user = Some("pi".into());
    remote(&mut h).reboot_command = Some("/sbin/reboot".into());
    rig.secrets
        .set_for_host(&h, SecretKind::Login, "", "login")
        .unwrap();
    let power = |h: &Host| {
        c.power(
            h,
            &rig.settings,
            PowerAction::Restart,
            &PowerOptions::default(),
        )
    };

    // auto without a sudo secret: wol-ssh falls back to the login password itself.
    assert_eq!(power(&h).unwrap(), PowerOutcome::Accepted);
    let s = rig.ssh.last();
    assert_eq!(s.sudo, Some(wol_ssh::SudoMode::Auto));
    assert_eq!(s.sudo_password, None);
    assert_eq!(s.password.as_deref(), Some("login"));
    assert_eq!(s.reboot_command.as_deref(), Some("/sbin/reboot"));
    assert_eq!(s.action, Some("restart"));
    // auto with a stored sudo secret uses it for power, and never reads it otherwise.
    rig.secrets
        .set_for_host(&h, SecretKind::Sudo, "", "sudo")
        .unwrap();
    power(&h).unwrap();
    assert_eq!(rig.ssh.last().sudo_password.as_deref(), Some("sudo"));
    c.boot_time(&h, &rig.settings).unwrap();
    assert_eq!(rig.ssh.last().sudo_password, None);
    // password = the login password (the separate secret is ignored).
    remote(&mut h).sudo = SudoMode::Password;
    power(&h).unwrap();
    let s = rig.ssh.last();
    assert_eq!(s.sudo, Some(wol_ssh::SudoMode::Password));
    assert_eq!(s.sudo_password, None);
    // separate = the sudo secret.
    remote(&mut h).sudo = SudoMode::Separate;
    power(&h).unwrap();
    let s = rig.ssh.last();
    assert_eq!(s.sudo, Some(wol_ssh::SudoMode::Password));
    assert_eq!(s.sudo_password.as_deref(), Some("sudo"));
    // separate without the secret fails before connecting.
    rig.secrets.delete(h.id, SecretKind::Sudo).unwrap();
    let calls = rig.ssh.calls();
    let e = power(&h).unwrap_err();
    assert_eq!(rig.ssh.calls(), calls);
    assert_eq!(
        e.remote().map(|r| &r.failure),
        Some(&RemoteFailure::SudoPasswordRequired)
    );
    assert_eq!(e.kind(), ErrorKind::Permission);
    c.boot_time(&h, &rig.settings).unwrap();
    // root / nopasswd map 1:1.
    for (m, w) in [
        (SudoMode::Root, wol_ssh::SudoMode::Root),
        (SudoMode::NoPasswd, wol_ssh::SudoMode::NoPasswd),
    ] {
        remote(&mut h).sudo = m;
        power(&h).unwrap();
        assert_eq!(rig.ssh.last().sudo, Some(w));
    }
}

#[test]
fn secret_overrides_replace_or_hide_stored_secrets() {
    let rig = Rig::new();
    let mut h = host(Some(RemoteKind::Ssh));
    remote(&mut h).key_file = Some("id".into());
    rig.secrets
        .set_for_host(&h, SecretKind::Login, "", "stored")
        .unwrap();
    rig.secrets
        .set_for_host(&h, SecretKind::KeyPassphrase, "", "stored-pp")
        .unwrap();
    let c = rig.client().with_overrides(SecretOverrides {
        login: SecretOverride::Value(Zeroizing::new("typed".into())),
        key_passphrase: SecretOverride::Absent,
        sudo: SecretOverride::Stored,
    });
    assert!(!format!("{c:?}").contains("typed"));
    c.test_connection(&h, &rig.settings).unwrap();
    let s = rig.ssh.last();
    assert_eq!(s.password.as_deref(), Some("typed"));
    assert_eq!(s.passphrase, None);
    // Windows: a typed password with the configured user.
    let mut w = host(Some(RemoteKind::Windows));
    remote(&mut w).user = Some(r"PC\admin".into());
    c.test_connection(&w, &rig.settings).unwrap();
    assert_eq!(rig.win.last().password.as_deref(), Some("typed"));
    assert_eq!(rig.win.last().user.as_deref(), Some(r"PC\admin"));
    // Typed password, empty user (editor): the current Windows account, like a saved one.
    remote(&mut w).user = None;
    c.test_connection(&w, &rig.settings).unwrap();
    assert_eq!(rig.win.last().user, current_windows_account());
    assert_eq!(rig.win.last().password.as_deref(), Some("typed"));
}

#[test]
fn conn_info_mapping() {
    let rig = Rig::new();
    let c = rig.client();
    let i = c
        .test_connection(&host(Some(RemoteKind::Windows)), &rig.settings)
        .unwrap();
    assert_eq!(i.os.as_deref(), Some("Microsoft Windows 11 Pro"));
    assert_eq!(i.admin_hint, Some(true));
    assert_eq!(i.boot.uptime, Duration::from_secs(600));
    assert_eq!(i.user, None);
    let i = c
        .test_connection(&host(Some(RemoteKind::Ssh)), &rig.settings)
        .unwrap();
    assert_eq!(i.os.as_deref(), Some("Debian GNU/Linux 12 (bookworm)"));
    assert_eq!(i.admin_hint, Some(true)); // member of sudo
    assert_eq!(i.user.as_deref(), Some("pi"));
    assert_eq!(i.kernel.as_deref(), Some("Linux 6.1.0-18-amd64"));
    assert_eq!(i.boot.boot_id.as_deref(), Some("boot-b"));
}

#[test]
fn mac_candidates_are_mapped_and_sorted() {
    let rig = Rig::new();
    let c = rig.client();
    let wc = |iface: &str, mac: &str, score: i32| wol_winremote::MacCandidate {
        iface: iface.into(),
        mac: mac.into(),
        permanent_mac: Some(mac.into()),
        kind: wol_winremote::NicKind::Physical,
        on_default_route: score > 100,
        link_up: true,
        score,
        lan_ipv4: Some((Ipv4Addr::new(192, 168, 1, 199), 24)),
    };
    *rig.win.macs.lock().unwrap() = vec![
        wc("Wi-Fi", "F4:B5:20:42:72:5D", 11),
        wc("Broken", "not-a-mac", 500),
        wc("Ethernet", "F4:B5:20:42:72:5C", 199_921),
    ];
    let v = c
        .mac_candidates(&host(Some(RemoteKind::Windows)), &rig.settings)
        .unwrap();
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].iface, "Ethernet");
    assert_eq!(v[0].mac.to_string(), "F4:B5:20:42:72:5C");
    assert_eq!(v[0].lan_ipv4.unwrap().to_string(), "192.168.1.199/24");
    assert_eq!(unique_best(&v).map(|c| c.iface.as_str()), Some("Ethernet"));
    // Ties: let the user choose.
    let mut tie = v.clone();
    tie[1].score = tie[0].score;
    assert!(unique_best(&tie).is_none());
    assert!(unique_best(&[]).is_none());
    assert!(unique_best(&v[..1]).is_some());

    let perm = [0x02, 0, 0, 0, 0, 0x10];
    *rig.ssh.macs.lock().unwrap() = vec![wol_ssh::MacCandidate {
        iface: "eno1".into(),
        mac: perm,
        current_mac: [0x02, 0, 0, 0, 0, 0x20],
        permanent_mac: Some(perm),
        kind: wol_ssh::NicKind::Physical,
        on_default_route: true,
        via: Some("vmbr0".into()),
        link_up: true,
        wol: Some(wol_ssh::WolInfo {
            supported: "pumbg".into(),
            enabled: "d".into(),
        }),
        lan_ipv4: Some((Ipv4Addr::new(10, 0, 0, 5), 24)),
        score: 132,
    }];
    let v = c
        .mac_candidates(&host(Some(RemoteKind::Ssh)), &rig.settings)
        .unwrap();
    assert_eq!(v[0].mac, MacAddr(perm));
    assert_eq!(v[0].current_mac, Some(MacAddr([0x02, 0, 0, 0, 0, 0x20])));
    assert_eq!(v[0].via.as_deref(), Some("vmbr0"));
    assert_eq!(v[0].wol_enabled, Some(false));
    // Nothing found.
    rig.ssh.macs.lock().unwrap().clear();
    let e = c
        .mac_candidates(&host(Some(RemoteKind::Ssh)), &rig.settings)
        .unwrap_err();
    assert_eq!(
        e.remote().map(|r| &r.failure),
        Some(&RemoteFailure::NoCandidates)
    );
    assert_eq!(e.kind(), ErrorKind::NotFound);
}

// ---- errors -----------------------------------------------------------------------------------

#[test]
fn windows_error_classification() {
    use wol_winremote::{Error as WE, ErrorKind as K, Hint as H, Op};
    let rig = Rig::new();
    let c = rig.client();
    let h = host(Some(RemoteKind::Windows));
    let cases = [
        (K::Unreachable, Some(H::SmbFirewall), ErrorKind::Network),
        (
            K::AuthFailed,
            Some(H::CheckCredentials),
            ErrorKind::Permission,
        ),
        (
            K::AccessDenied,
            Some(H::UacRemoteRestriction),
            ErrorKind::Permission,
        ),
        (
            K::CredentialConflict,
            Some(H::CloseOtherConnections),
            ErrorKind::Permission,
        ),
        (K::LocalTarget, None, ErrorKind::InvalidInput),
        (K::InvalidInput, None, ErrorKind::InvalidInput),
        (K::Unsupported, None, ErrorKind::InvalidInput),
        (K::SecretStoreUnavailable, None, ErrorKind::Permission),
        (
            K::ShutdownInProgress,
            Some(H::RetryLater),
            ErrorKind::Remote,
        ),
        (K::NoShutdownInProgress, None, ErrorKind::Remote),
        (K::UsersLoggedOn, None, ErrorKind::Remote),
        (K::NotReady, Some(H::RetryLater), ErrorKind::Remote),
        (K::Other, None, ErrorKind::Remote),
    ];
    for (kind, hint, want) in cases {
        let mut e = WE::new(kind, Op::Power, "detail").with_code(wol_winremote::Code::Win32(1219));
        if let Some(hint) = hint {
            e = e.with_hint(hint);
        }
        *rig.win.fail.lock().unwrap() = Some(e);
        let err = c
            .power(
                &h,
                &rig.settings,
                PowerAction::Restart,
                &PowerOptions::default(),
            )
            .unwrap_err();
        assert_eq!(err.kind(), want, "{kind:?}");
        let r = err.remote().expect("Error::Remote");
        assert_eq!(r.op, RemoteOp::Restart);
        assert_eq!(r.backend, RemoteKind::Windows);
        assert_eq!(r.address, "192.168.1.20");
        assert_eq!(r.code.as_deref(), Some("error 1219"));
        assert_eq!(r.hint.is_some(), hint.is_some(), "{kind:?}");
        let ja = describe_error(&err, Lang::Ja);
        let en = describe_error(&err, Lang::En);
        assert!(ja.starts_with("nas（192.168.1.20）: "), "{ja}");
        assert!(en.starts_with("nas (192.168.1.20): "), "{en}");
        assert!(en.is_ascii(), "{en}");
        assert!(!err.is_remote_transient() || want == ErrorKind::Network);
    }
    // Specific texts: UAC remote restrictions, 1219.
    *rig.win.fail.lock().unwrap() =
        Some(WE::new(K::AccessDenied, Op::Power, "5").with_hint(H::UacRemoteRestriction));
    let e = c.abort_shutdown(&h, &rig.settings).unwrap_err();
    for lang in [Lang::Ja, Lang::En] {
        let t = describe_error(&e, lang);
        assert!(
            t.contains("KB951016") && t.contains("LocalAccountTokenFilterPolicy"),
            "{t}"
        );
    }
    assert!(describe_error(&e, Lang::Ja).contains("シャットダウンを取り消せませんでした"));
    *rig.win.fail.lock().unwrap() = Some(WE::new(K::CredentialConflict, Op::Connect, "1219"));
    let e = c.boot_time(&h, &rig.settings).unwrap_err();
    assert!(describe_error(&e, Lang::Ja).contains("1219"));
    assert!(describe_error(&e, Lang::En).contains("1219"));
    *rig.win.fail.lock().unwrap() =
        Some(WE::new(K::Unreachable, Op::Wmi, "135").with_hint(H::WmiFirewall));
    let e = c.mac_candidates(&h, &rig.settings).unwrap_err();
    assert!(e.is_remote_transient());
    assert!(describe_error(&e, Lang::Ja).contains("Windows Management Instrumentation"));
}

#[test]
fn ssh_error_classification() {
    use wol_ssh::SshError as S;
    let rig = Rig::new();
    let c = rig.client();
    let h = host(Some(RemoteKind::Ssh));
    type Case = (fn() -> S, ErrorKind, RemoteFailure);
    let cases: Vec<Case> = vec![
        (
            || S::Connect {
                addr: "192.168.1.20:22".into(),
                message: "refused".into(),
            },
            ErrorKind::Network,
            RemoteFailure::Unreachable,
        ),
        (
            || S::Timeout(wol_ssh::TimeoutStage::Handshake),
            ErrorKind::Network,
            RemoteFailure::Timeout {
                stage: RemoteStage::Handshake,
            },
        ),
        (
            || S::Disconnected("eof".into()),
            ErrorKind::Network,
            RemoteFailure::Disconnected,
        ),
        (
            || S::NoCredentials,
            ErrorKind::Permission,
            RemoteFailure::NoCredentials,
        ),
        (|| S::NotRoot, ErrorKind::Permission, RemoteFailure::NotRoot),
        (
            || S::SudoPasswordRequired,
            ErrorKind::Permission,
            RemoteFailure::SudoPasswordRequired,
        ),
        (
            || S::SudoWrongPassword,
            ErrorKind::Permission,
            RemoteFailure::SudoWrongPassword,
        ),
        (
            || S::SudoNotAllowed,
            ErrorKind::Permission,
            RemoteFailure::SudoNotAllowed,
        ),
        (
            || S::SudoNeedsTty,
            ErrorKind::Permission,
            RemoteFailure::SudoNeedsTty,
        ),
        (
            || S::SudoMissing,
            ErrorKind::Permission,
            RemoteFailure::SudoMissing,
        ),
        (
            || S::KeyFile {
                path: "id.pub".into(),
                message: "public key".into(),
            },
            ErrorKind::InvalidInput,
            RemoteFailure::KeyFile {
                path: "id.pub".into(),
            },
        ),
        (
            || S::KeyPassphraseWrong { path: "id".into() },
            ErrorKind::Permission,
            RemoteFailure::KeyPassphraseWrong { path: "id".into() },
        ),
        (
            || S::CommandFailed {
                exit_status: Some(1),
                exit_signal: None,
                stderr: "Failed to reboot".into(),
            },
            ErrorKind::Remote,
            RemoteFailure::CommandFailed {
                exit_status: Some(1),
                stderr: "Failed to reboot".into(),
            },
        ),
        (
            || S::PowerUnconfirmed,
            ErrorKind::Remote,
            RemoteFailure::PowerUnconfirmed,
        ),
        (
            || S::UnexpectedOutput("x".into()),
            ErrorKind::Remote,
            RemoteFailure::UnexpectedOutput,
        ),
        (
            || S::InvalidInput("bad override".into()),
            ErrorKind::InvalidInput,
            RemoteFailure::InvalidInput,
        ),
    ];
    for (make, kind, failure) in cases {
        rig.ssh.set_fail(make);
        let e = c
            .power(
                &h,
                &rig.settings,
                PowerAction::Shutdown,
                &PowerOptions::default(),
            )
            .unwrap_err();
        assert_eq!(e.kind(), kind, "{failure:?}");
        let r = e.remote().unwrap();
        assert_eq!(r.failure, failure);
        assert_eq!(r.op, RemoteOp::Shutdown);
        assert_eq!(r.failure.is_sudo(), failure.is_sudo());
        let ja = describe_error(&e, Lang::Ja);
        let en = describe_error(&e, Lang::En);
        assert!(!ja.is_empty() && en.is_ascii(), "{en}");
    }
    // Password logins disabled on the server: hint only without a key file.
    rig.ssh.set_fail(|| S::AuthFailed {
        server_methods: vec!["publickey".into()],
    });
    let e = c.boot_time(&h, &rig.settings).unwrap_err();
    assert_eq!(
        e.remote().unwrap().hint,
        Some(RemoteHint::PasswordAuthDisabled)
    );
    assert!(describe_error(&e, Lang::En).contains("public keys only"));
    let mut hk = host(Some(RemoteKind::Ssh));
    remote(&mut hk).key_file = Some("id".into());
    let e = c.boot_time(&hk, &rig.settings).unwrap_err();
    assert_eq!(e.remote().unwrap().hint, None);
    assert_eq!(e.kind(), ErrorKind::Permission);
    // PowerUnconfirmed has no "failed" prefix.
    rig.ssh.set_fail(|| S::PowerUnconfirmed);
    let e = c
        .power(
            &h,
            &rig.settings,
            PowerAction::Restart,
            &PowerOptions::default(),
        )
        .unwrap_err();
    assert!(!describe_error(&e, Lang::Ja).contains("要求できませんでした"));
}

#[test]
fn ssh_host_key_errors_carry_trust_data() {
    use wol_ssh::SshError as S;
    let rig = Rig::new();
    let c = rig.client();
    let mut h = host(Some(RemoteKind::Ssh));
    remote(&mut h).port = Some(2222);
    let fp = wol_ssh::parse_host_key(ED25519).unwrap().fingerprint_sha256;
    let fp2 = fp.clone();
    rig.ssh.set_fail(move || S::UnknownHostKey {
        openssh_line: ED25519.into(),
        fingerprint_sha256: fp2.clone(),
    });
    let e = c.boot_time(&h, &rig.settings).unwrap_err();
    let Error::UnknownHostKey(p) = &e else {
        panic!("{e:?}")
    };
    assert_eq!(
        (p.host.as_str(), p.address.as_str(), p.port),
        ("nas", "192.168.1.20", 2222)
    );
    assert_eq!(p.algorithm, "ssh-ed25519");
    assert_eq!(p.openssh_line, ED25519);
    assert_eq!(p.fingerprint, fp);
    assert!(!p.in_known_hosts);
    assert_eq!(e.kind(), ErrorKind::Permission);
    assert!(e.host_key_problem().is_some());
    let ja = describe_error(&e, Lang::Ja);
    assert!(
        ja.contains(&fp) && ja.contains("ssh_host_ed25519_key.pub"),
        "{ja}"
    );
    // Same key already in ~/.ssh/known_hosts.
    rig.ssh
        .known_hosts
        .lock()
        .unwrap()
        .push(wol_ssh::parse_host_key(ED25519).unwrap());
    let e = c.boot_time(&h, &rig.settings).unwrap_err();
    assert!(e.host_key_problem().unwrap().in_known_hosts);
    assert!(describe_error(&e, Lang::En).contains("known_hosts"));
    assert!(c.in_known_hosts(&h, &format!("{ED25519} comment")));
    assert!(!c.in_known_hosts(&h, "junk"));
    // Mismatch and "type no longer offered" are both mismatches (offer "forget").
    rig.ssh.set_fail(|| S::HostKeyMismatch {
        expected_fp: "SHA256:old".into(),
        actual_fp: "SHA256:new".into(),
    });
    let e = c.boot_time(&h, &rig.settings).unwrap_err();
    let Error::HostKeyMismatch(p) = &e else {
        panic!("{e:?}")
    };
    assert_eq!(p.expected_fingerprint.as_deref(), Some("SHA256:old"));
    assert_eq!(p.fingerprint, "SHA256:new");
    assert!(p.openssh_line.is_empty());
    assert_eq!(e.kind(), ErrorKind::Permission);
    assert!(describe_error(&e, Lang::Ja).contains("SHA256:new"));
    rig.ssh.set_fail(|| S::HostKeyTypeUnavailable {
        expected_fp: "SHA256:old".into(),
        key_type: "ssh-ed25519".into(),
    });
    let e = c.boot_time(&h, &rig.settings).unwrap_err();
    assert!(
        matches!(&e, Error::HostKeyMismatch(p) if p.fingerprint.is_empty() && p.algorithm == "ssh-ed25519")
    );
    assert!(describe_error(&e, Lang::En).is_ascii());
    // scan_host_key: SSH only.
    *rig.ssh.fail.lock().unwrap() = None;
    let k = c.scan_host_key(&h, &rig.settings).unwrap();
    assert_eq!(k.openssh_line, ED25519);
    assert_eq!(rig.ssh.last().port, 2222);
    assert!(matches!(
        c.scan_host_key(&host(Some(RemoteKind::Windows)), &rig.settings),
        Err(Error::RemoteUnsupported { .. })
    ));
}

#[test]
fn trust_and_forget_host_key_in_config() {
    let mut cfg = Config::default();
    let ssh = host(Some(RemoteKind::Ssh));
    let win = host(Some(RemoteKind::Windows));
    let mut plain = host(None);
    plain.name = "plain".into();
    let mut win2 = win.clone();
    win2.name = "win".into();
    cfg.hosts = vec![ssh.clone(), win2.clone(), plain.clone()];
    let basis = TrustBasis::of(&ssh).unwrap();
    assert_eq!(basis.pinned, None);
    assert!(TrustBasis::of(&win2).is_none() && TrustBasis::of(&plain).is_none());
    let k = trust_host_key(&mut cfg, ssh.id, &format!("{ED25519} root@pve"), &basis).unwrap();
    assert_eq!(k.algorithm, "ssh-ed25519");
    assert!(k.fingerprint.starts_with("SHA256:"));
    assert_eq!(
        cfg.get(ssh.id)
            .unwrap()
            .remote
            .as_ref()
            .unwrap()
            .host_key
            .as_deref(),
        Some(ED25519)
    );
    assert!(matches!(
        trust_host_key(&mut cfg, ssh.id, "garbage", &basis),
        Err(Error::InvalidValue {
            field: Field::SshHostKey,
            issue: FieldIssue::InvalidHostKey,
            ..
        })
    ));
    assert!(matches!(
        trust_host_key(&mut cfg, win2.id, ED25519, &basis),
        Err(Error::RemoteUnsupported { .. })
    ));
    assert!(matches!(
        trust_host_key(&mut cfg, plain.id, ED25519, &basis),
        Err(Error::RemoteNotConfigured { .. })
    ));
    assert!(matches!(
        trust_host_key(&mut cfg, HostId::new_v4(), ED25519, &basis),
        Err(Error::HostIdNotFound(_))
    ));
    // Trusting the same key again (the first basis) changes nothing and succeeds.
    trust_host_key(&mut cfg, ssh.id, ED25519, &basis).unwrap();
    assert!(forget_host_key(&mut cfg, ssh.id).unwrap());
    assert!(!forget_host_key(&mut cfg, ssh.id).unwrap());
    assert!(!forget_host_key(&mut cfg, plain.id).unwrap());
    assert!(cfg.validate().is_empty());
    assert!(parse_host_key("ssh-ed25519").is_err());
    assert!(fingerprints_match(
        &k.fingerprint,
        k.fingerprint.trim_start_matches("SHA256:")
    ));
    assert!(!fingerprints_match(&k.fingerprint, "SHA256:other"));
}

/// Review S4: a key is pinned only for the endpoint it was read from, and never over a key
/// that was pinned meanwhile.
#[test]
fn review_s4_trust_checks_the_endpoint_and_the_pin() {
    let mut cfg = Config::default();
    let mut ssh = host(Some(RemoteKind::Ssh));
    remote(&mut ssh).address = Some("192.0.2.7".parse().unwrap());
    cfg.hosts = vec![ssh.clone()];
    let pin = |cfg: &Config| {
        cfg.get(ssh.id)
            .and_then(|h| h.remote.as_ref())
            .and_then(|r| r.host_key.clone())
    };
    // What the dialog showed: the unknown key of 192.0.2.7:22.
    let problem = HostKeyProblem {
        host: ssh.name.clone(),
        address: "192.0.2.7".into(),
        port: 22,
        algorithm: "ssh-ed25519".into(),
        fingerprint: "SHA256:x".into(),
        openssh_line: ED25519.into(),
        expected_fingerprint: None,
        in_known_hosts: false,
    };
    let basis = TrustBasis::unknown_key(&problem);
    assert_eq!(Some(&basis), TrustBasis::of(&ssh).as_ref());
    // Re-pointed meanwhile (import, other program): refused, nothing pinned.
    let mut moved = cfg.clone();
    remote(moved.get_mut(ssh.id).unwrap()).address = Some("192.0.2.8".parse().unwrap());
    let e = trust_host_key(&mut moved, ssh.id, ED25519, &basis).unwrap_err();
    assert!(matches!(e, Error::RemoteChanged { .. }), "{e}");
    assert_eq!(e.kind(), ErrorKind::Permission);
    assert!(describe_error(&e, Lang::En).is_ascii());
    assert_eq!(pin(&moved), None);
    let mut port = cfg.clone();
    remote(port.get_mut(ssh.id).unwrap()).port = Some(2222);
    assert!(matches!(
        trust_host_key(&mut port, ssh.id, ED25519, &basis),
        Err(Error::RemoteChanged { .. })
    ));
    // Another key pinned meanwhile: never replaced.
    let mut pinned = cfg.clone();
    remote(pinned.get_mut(ssh.id).unwrap()).host_key = Some(OTHER_ED25519.into());
    assert!(matches!(
        trust_host_key(&mut pinned, ssh.id, ED25519, &basis),
        Err(Error::RemoteChanged { .. })
    ));
    assert_eq!(pin(&pinned).as_deref(), Some(OTHER_ED25519));
    // The same key pinned meanwhile: fine. Address spelling does not matter.
    let mut same = cfg.clone();
    remote(same.get_mut(ssh.id).unwrap()).host_key = Some(ED25519.into());
    trust_host_key(&mut same, ssh.id, ED25519, &basis).unwrap();
    let upper = TrustBasis {
        address: "192.0.2.7.".into(),
        ..basis.clone()
    };
    trust_host_key(&mut cfg, ssh.id, ED25519, &upper).unwrap();
    assert_eq!(pin(&cfg).as_deref(), Some(ED25519));
}

/// Review R3: the note under a successful test follows the WMI outcome (UAC-filtered token vs
/// firewall vs this PC).
#[test]
fn review_r3_admin_check_notes() {
    use wol_winremote::AdminCheck as W;
    assert_eq!(AdminCheck::of_windows(W::Admin), AdminCheck::Admin);
    assert_eq!(AdminCheck::of_windows(W::Denied), AdminCheck::WmiDenied);
    assert_eq!(
        AdminCheck::of_windows(W::Unreachable),
        AdminCheck::WmiUnreachable
    );
    assert_eq!(AdminCheck::of_windows(W::Failed), AdminCheck::Unknown);
    assert_eq!(AdminCheck::of_windows(W::Local), AdminCheck::NotChecked);
    assert_eq!(AdminCheck::Admin.note(), None);
    assert_eq!(AdminCheck::NotChecked.note(), None);
    assert_eq!(
        AdminCheck::WmiDenied.note(),
        Some((true, crate::i18n::Msg::RemoteWmiDenied))
    );
    assert_eq!(
        AdminCheck::WmiUnreachable.note(),
        Some((false, crate::i18n::Msg::RemoteWmiUnreachable))
    );
    assert_eq!(
        AdminCheck::NotAdmin.note(),
        Some((true, crate::i18n::Msg::RemoteNotAdmin))
    );
    let ja = crate::i18n::Msg::RemoteWmiDenied.text(Lang::Ja);
    assert!(ja.contains("KB951016") && ja.contains("LocalAccountTokenFilterPolicy"));
    // The generic note no longer claims that WMI is unreachable.
    assert!(
        !crate::i18n::Msg::RemoteAdminUnknown
            .text(Lang::Ja)
            .contains("WMI")
    );
    // Through the client: a Windows test reports the check.
    let rig = Rig::new();
    let info = rig
        .client()
        .test_connection(&host(Some(RemoteKind::Windows)), &rig.settings)
        .unwrap();
    assert_eq!(info.admin_check, AdminCheck::Admin);
    assert_eq!(info.admin_hint, Some(true));
}

#[test]
fn boot_info_lines_and_json() {
    let b = BootInfo {
        boot_time: t0(),
        uptime: Duration::from_secs(3 * 3600 + 12 * 60),
        source: "ssh/proc_stat".into(),
        approximate: false,
        boot_id: None,
    };
    let ja = b.boot_line(Lang::Ja);
    assert!(
        ja.starts_with("起動 ") && ja.ends_with("（稼働 3時間12分）"),
        "{ja}"
    );
    let en = b.boot_line(Lang::En);
    assert!(
        en.starts_with("Up since ") && en.ends_with(" (3h 12m)"),
        "{en}"
    );
    let v = serde_json::to_value(&b).unwrap();
    assert_eq!(v["boot_time_unix_ms"], 1_790_669_520_000i64);
    assert_eq!(v["uptime_ms"], 11_520_000u64);
    let json = serde_json::to_string(&PowerOutcome::Scheduled { delay_secs: 30 }).unwrap();
    assert_eq!(json, r#"{"result":"scheduled","delay_secs":30}"#);
}

// ---- verification -----------------------------------------------------------------------------

fn settings_short(rig: &Rig) -> Settings {
    let mut s = rig.settings.clone();
    s.remote.restart_verify_timeout_secs = 60;
    s
}

#[test]
fn restart_verified_after_down_and_new_boot() {
    let rig = Rig::new();
    let env = Arc::new(FakeEnv::new(vec![up(), down(), down(), up(), up()], up()));
    let c = rig.client_env(env.clone());
    let h = host(Some(RemoteKind::Windows));
    let before = c.boot_time(&h, &rig.settings).unwrap();
    {
        let mut q = rig.win.boots.lock().unwrap();
        q.push_back(Ok(win_boot(3605))); // still the old boot (countdown running)
        q.push_back(Err(wol_winremote::Error::new(
            wol_winremote::ErrorKind::Unreachable,
            wol_winremote::Op::Connect,
            "SMB not ready",
        )));
        let mut new = win_boot(20);
        new.boot_time_utc = t0() + Duration::from_secs(40);
        q.push_back(Ok(new));
    }
    let mut ticks = Vec::new();
    let r = c.verify_restart(
        &h,
        &rig.settings,
        Some(&before),
        env.now() + Duration::from_secs(600),
        &AtomicBool::new(false),
        |t| ticks.push(t.phase),
    );
    let RestartVerify::Restarted { boot } = r else {
        panic!("{r:?}")
    };
    assert_eq!(boot.boot_time, t0() + Duration::from_secs(40));
    assert_eq!(
        ticks,
        vec![
            VerifyPhase::Up,
            VerifyPhase::Down { failures: 1 },
            VerifyPhase::Down { failures: 2 },
            VerifyPhase::Up,
            VerifyPhase::Up
        ]
    );
    assert_eq!(env.probe_count(), 5);
    // Probed the host address.
    assert_eq!(
        env.probed.lock().unwrap()[0]
            .as_ref()
            .map(ToString::to_string),
        Some("192.168.1.20".into())
    );
}

#[test]
fn restart_times_out_when_the_boot_never_changes() {
    let rig = Rig::new();
    let env = Arc::new(FakeEnv::new(vec![], up()));
    let c = rig.client_env(env.clone());
    let h = host(Some(RemoteKind::Ssh));
    let before = c.boot_time(&h, &rig.settings).unwrap();
    let s = settings_short(&rig);
    let start = env.now();
    let r = c.verify_restart(
        &h,
        &s,
        Some(&before),
        start + s.remote.effective_restart_verify_timeout(),
        &AtomicBool::new(false),
        |_| {},
    );
    match r {
        RestartVerify::TimedOut {
            went_down,
            online,
            last_error,
        } => {
            assert!(!went_down);
            assert!(online);
            assert!(last_error.is_none());
        }
        other => panic!("{other:?}"),
    }
    // One probe every 5 s for 60 s, plus the one at the deadline.
    assert_eq!(env.probe_count(), 13);
    assert_eq!(env.now() - start, Duration::from_secs(60));
}

#[test]
fn restart_boot_id_decides_and_without_before_uses_start_time() {
    let rig = Rig::new();
    let env = Arc::new(FakeEnv::new(vec![], up()));
    let c = rig.client_env(env.clone());
    let h = host(Some(RemoteKind::Ssh));
    // Same boot id but "later" btime (clock step): not a restart; new id: restart.
    rig.ssh.boots.lock().unwrap().extend([
        {
            let mut b = ssh_boot(10, "boot-a");
            b.boot_time_local = t0() + Duration::from_secs(3600);
            b
        },
        ssh_boot(5, "boot-b"),
    ]);
    let before = BootInfo::from_ssh(ssh_boot(3600, "boot-a"));
    let r = c.verify_restart(
        &h,
        &rig.settings,
        Some(&before),
        env.now() + Duration::from_secs(600),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(
        matches!(&r, RestartVerify::Restarted { boot } if boot.boot_id.as_deref() == Some("boot-b")),
        "{r:?}"
    );
    assert_eq!(env.probe_count(), 2);

    // Without "before": a boot after the start (minus slack) counts.
    let env = Arc::new(FakeEnv::new(vec![down()], up()));
    let c = rig.client_env(env.clone());
    rig.ssh.boots.lock().unwrap().clear();
    rig.ssh
        .boots
        .lock()
        .unwrap()
        .extend([ssh_boot(7200, "old")]);
    let mut fresh = ssh_boot(1, "fresh");
    fresh.boot_time_local = t0() + Duration::from_secs(8);
    rig.ssh.boots.lock().unwrap().push_back(fresh);
    let r = c.verify_restart(
        &h,
        &rig.settings,
        None,
        env.now() + Duration::from_secs(600),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(
        matches!(&r, RestartVerify::Restarted { boot } if boot.boot_id.as_deref() == Some("fresh")),
        "{r:?}"
    );
}

#[test]
fn restart_stops_on_fatal_errors_and_cancel() {
    let rig = Rig::new();
    let env = Arc::new(FakeEnv::new(vec![], up()));
    let c = rig.client_env(env.clone());
    let h = host(Some(RemoteKind::Ssh));
    rig.ssh.set_fail(|| wol_ssh::SshError::HostKeyMismatch {
        expected_fp: "SHA256:a".into(),
        actual_fp: "SHA256:b".into(),
    });
    let r = c.verify_restart(
        &h,
        &rig.settings,
        None,
        env.now() + Duration::from_secs(600),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(
        matches!(r, RestartVerify::Failed(Error::HostKeyMismatch(_))),
        "{r:?}"
    );
    assert_eq!(env.probe_count(), 1);
    // Network errors keep polling (and are reported at the deadline).
    rig.ssh.set_fail(|| wol_ssh::SshError::Connect {
        addr: "x".into(),
        message: "refused".into(),
    });
    let env = Arc::new(FakeEnv::new(vec![], up()));
    let c = rig.client_env(env.clone());
    let r = c.verify_restart(
        &h,
        &rig.settings,
        None,
        env.now() + Duration::from_secs(20),
        &AtomicBool::new(false),
        |_| {},
    );
    match r {
        RestartVerify::TimedOut { last_error, .. } => {
            assert!(last_error.unwrap().is_remote_transient())
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(env.probe_count(), 5);
    // Cancel before the first probe, and during the wait.
    let r = c.verify_restart(
        &h,
        &rig.settings,
        None,
        env.now() + Duration::from_secs(20),
        &AtomicBool::new(true),
        |_| {},
    );
    assert!(matches!(r, RestartVerify::Cancelled));
    let mut env2 = FakeEnv::new(vec![], down());
    env2.cancel_after = Some(2);
    let env2 = Arc::new(env2);
    let c = rig.client_env(env2.clone());
    let r = c.verify_restart(
        &h,
        &rig.settings,
        None,
        env2.now() + Duration::from_secs(600),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(matches!(r, RestartVerify::Cancelled));
    assert_eq!(env2.probe_count(), 2);
}

#[test]
fn restart_without_probing_reads_the_boot_time_every_round() {
    let rig = Rig::new();
    let env = Arc::new(FakeEnv::new(vec![], down()));
    let c = rig.client_env(env.clone());
    let mut h = host(Some(RemoteKind::Windows));
    h.probe = Some(crate::model::ProbeMethod::None);
    let before = BootInfo::from_windows(win_boot(3600));
    {
        let mut q = rig.win.boots.lock().unwrap();
        q.push_back(Ok(win_boot(3610)));
        let mut new = win_boot(5);
        new.boot_time_utc = t0() + Duration::from_secs(60);
        q.push_back(Ok(new));
    }
    let mut states = Vec::new();
    let r = c.verify_restart(
        &h,
        &rig.settings,
        Some(&before),
        env.now() + Duration::from_secs(600),
        &AtomicBool::new(false),
        |t| states.push(t.state.clone()),
    );
    assert!(matches!(r, RestartVerify::Restarted { .. }), "{r:?}");
    assert_eq!(env.probe_count(), 0);
    assert_eq!(states, vec![HostState::Unknown, HostState::Unknown]);
}

#[test]
fn shutdown_needs_three_failed_probes_in_a_row() {
    let rig = Rig::new();
    let env = Arc::new(FakeEnv::new(
        vec![up(), down(), up(), down(), down(), down()],
        up(),
    ));
    let c = rig.client_env(env.clone());
    let mut h = host(Some(RemoteKind::Windows));
    // No host address: the management address is probed.
    h.address = None;
    remote(&mut h).address = Some("100.105.1.2".parse().unwrap());
    let mut phases = Vec::new();
    let start = env.now();
    let r = c.verify_shutdown(
        &h,
        &rig.settings,
        start + Duration::from_secs(300),
        &AtomicBool::new(false),
        |t| phases.push(t.phase),
    );
    assert_eq!(r, ShutdownVerify::ShutDown);
    assert_eq!(
        phases,
        vec![
            VerifyPhase::Up,
            VerifyPhase::Down { failures: 1 },
            VerifyPhase::Up,
            VerifyPhase::Down { failures: 1 },
            VerifyPhase::Down { failures: 2 },
            VerifyPhase::Down { failures: 3 },
        ]
    );
    assert_eq!(env.now() - start, SHUTDOWN_POLL * 5);
    assert_eq!(
        env.probed.lock().unwrap()[0]
            .as_ref()
            .map(ToString::to_string),
        Some("100.105.1.2".into())
    );
    // Never goes down: timeout with the last state.
    let env = Arc::new(FakeEnv::new(vec![], up()));
    let c = rig.client_env(env.clone());
    let r = c.verify_shutdown(
        &h,
        &rig.settings,
        env.now() + Duration::from_secs(30),
        &AtomicBool::new(false),
        |_| {},
    );
    assert_eq!(r, ShutdownVerify::TimedOut { last: up() });
    assert_eq!(env.probe_count(), 11);
    // Not monitored.
    let mut nm = h.clone();
    nm.probe = Some(crate::model::ProbeMethod::None);
    assert_eq!(
        c.verify_shutdown(
            &nm,
            &rig.settings,
            env.now(),
            &AtomicBool::new(false),
            |_| {}
        ),
        ShutdownVerify::NotMonitored
    );
    // Cancelled.
    assert_eq!(
        c.verify_shutdown(
            &h,
            &rig.settings,
            env.now() + Duration::from_secs(30),
            &AtomicBool::new(true),
            |_| {}
        ),
        ShutdownVerify::Cancelled
    );
}

// ---- review fixes (review-wol-core-v020.md) -----------------------------------------------------

/// A second SSH host key (for imports that bring another pin).
const OTHER_ED25519: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGKrOJm1dz5vWoZxZWq6YEoJmD2d2zSJ8VeyUdTqWRqf";

/// LAN address (for WoL on that LAN, not reachable from here) + VPN management address.
fn vpn_host(kind: RemoteKind) -> Host {
    let mut h = host(Some(kind));
    h.address = Some("192.168.50.20".parse().unwrap());
    remote(&mut h).address = Some("100.105.128.173".parse().unwrap());
    h
}

/// Answers only on VPN (100.x) addresses; fake clock.
struct VpnEnv {
    now: Mutex<Instant>,
    probed: Mutex<Vec<String>>,
}

impl VpnEnv {
    fn new() -> VpnEnv {
        VpnEnv {
            now: Mutex::new(Instant::now()),
            probed: Mutex::new(Vec::new()),
        }
    }
}

impl VerifyEnv for VpnEnv {
    fn probe(&self, spec: &crate::probe::ProbeSpec) -> HostState {
        let a = spec.address.as_ref().unwrap().to_string();
        self.probed.lock().unwrap().push(a.clone());
        let ip: Ipv4Addr = a.parse().unwrap();
        if a.starts_with("100.") {
            HostState::Up {
                via: ProbeVia::Icmp,
                rtt: Duration::from_millis(5),
                ip,
            }
        } else {
            HostState::Down { ip }
        }
    }
    fn now(&self) -> Instant {
        *self.now.lock().unwrap()
    }
    fn sleep_until(&self, until: Instant, _cancel: &AtomicBool) -> bool {
        let mut n = self.now.lock().unwrap();
        if until > *n {
            *n = until;
        }
        true
    }
}

/// Review M1 (repro r1): verification probes the management address, the path that carried
/// the request, so a VPN host is neither reported shut down while it runs nor left unverified.
#[test]
fn review_m1_verification_uses_the_management_address() {
    let rig = Rig::new();
    let env = Arc::new(VpnEnv::new());
    let c = rig.client().with_verify_env(env.clone());
    let h = vpn_host(RemoteKind::Windows);
    assert_eq!(
        verify_probe_spec(&h, &rig.settings)
            .address
            .map(|a| a.to_string())
            .as_deref(),
        Some("100.105.128.173")
    );
    // Still up (e.g. the countdown was aborted): never "shut down".
    let r = c.verify_shutdown(
        &h,
        &rig.settings,
        env.now() + Duration::from_secs(30),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(
        matches!(r, ShutdownVerify::TimedOut { ref last } if last.is_up()),
        "{r:?}"
    );
    assert!(
        env.probed
            .lock()
            .unwrap()
            .iter()
            .all(|a| a == "100.105.128.173")
    );
    // Restart: the boot time is read (over the management address) and the new boot seen.
    let before = c.boot_time(&h, &rig.settings).unwrap();
    {
        let mut q = rig.win.boots.lock().unwrap();
        q.push_back(Ok(win_boot(3605)));
        q.push_back(Ok(win_boot(4)));
    }
    let r = c.verify_restart(
        &h,
        &rig.settings,
        Some(&before),
        env.now() + Duration::from_secs(600),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(
        matches!(r, RestartVerify::Restarted { ref boot } if boot.uptime == Duration::from_secs(4)),
        "{r:?}"
    );
    assert_eq!(rig.win.last().host, "100.105.128.173");
    // Unmanaged hosts keep probing their address.
    let plain = host(None);
    assert_eq!(
        verify_probe_spec(&plain, &rig.settings)
            .address
            .map(|a| a.to_string())
            .as_deref(),
        Some("192.168.1.20")
    );
}

/// Review M1: a probe that never answers (ICMP filtered on the VPN) does not hide a restart:
/// the boot time is still read every third round.
#[test]
fn review_m1_restart_reads_the_boot_time_while_the_probe_says_down() {
    let rig = Rig::new();
    let env = Arc::new(FakeEnv::new(vec![], down()));
    let c = rig.client_env(env.clone());
    let h = host(Some(RemoteKind::Windows));
    let before = BootInfo::from_windows(win_boot(3600));
    rig.win.boots.lock().unwrap().push_back(Ok(win_boot(4)));
    let mut phases = Vec::new();
    let r = c.verify_restart(
        &h,
        &rig.settings,
        Some(&before),
        env.now() + Duration::from_secs(600),
        &AtomicBool::new(false),
        |t| phases.push(t.phase),
    );
    assert!(matches!(r, RestartVerify::Restarted { .. }), "{r:?}");
    assert_eq!(
        phases,
        vec![
            VerifyPhase::Down { failures: 1 },
            VerifyPhase::Down { failures: 2 },
            VerifyPhase::Up
        ]
    );
    assert_eq!(rig.win.seen.lock().unwrap().len(), 1);
}

/// Review m1 (repro r2): without `before`, a host that booted 40 s before the verification
/// started is the old boot, not a restart; a stale cached `before` does not fool it either.
#[test]
fn review_m1_restart_needs_a_boot_after_the_start() {
    let rig = Rig::new();
    let s = settings_short(&rig);
    let h = host(Some(RemoteKind::Windows));
    // Uptime growing with the clock (a real host), and stuck at 40 s (repro r2's mock).
    let cases = [
        (None, 5u64),
        (Some(BootInfo::from_windows(win_boot(90_000))), 5),
        (None, 0),
    ];
    for (before, step) in cases {
        let env = Arc::new(FakeEnv::new(vec![], up()));
        let c = rig.client_env(env.clone());
        {
            let mut q = rig.win.boots.lock().unwrap();
            q.clear();
            for round in 0..20u64 {
                q.push_back(Ok(win_boot(40 + step * round)));
            }
        }
        let r = c.verify_restart(
            &h,
            &s,
            before.as_ref(),
            env.now() + s.remote.effective_restart_verify_timeout(),
            &AtomicBool::new(false),
            |_| {},
        );
        assert!(
            matches!(
                r,
                RestartVerify::TimedOut {
                    went_down: false,
                    online: true,
                    last_error: None
                }
            ),
            "{before:?}: {r:?}"
        );
    }
}

/// Review m2: a step of this PC's clock and the Windows 49.7-day counter wrap (approximate
/// readings) are not restarts.
#[test]
fn review_m2_clock_steps_and_counter_wraps_are_not_restarts() {
    let rig = Rig::new();
    let h = host(Some(RemoteKind::Windows));
    let before = BootInfo::from_windows(win_boot(3600));
    let env = Arc::new(FakeEnv::new(vec![], up()));
    let c = rig.client_env(env.clone());
    {
        let mut q = rig.win.boots.lock().unwrap();
        let mut stepped = win_boot(3605);
        stepped.boot_time_utc = t0() + Duration::from_secs(45);
        q.push_back(Ok(stepped));
        let mut wrapped = win_boot(3);
        wrapped.approximate = true;
        q.push_back(Ok(wrapped.clone()));
        q.push_back(Ok(wrapped));
    }
    let r = c.verify_restart(
        &h,
        &rig.settings,
        Some(&before),
        env.now() + Duration::from_secs(12),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(
        matches!(
            r,
            RestartVerify::TimedOut {
                went_down: false,
                online: true,
                ..
            }
        ),
        "{r:?}"
    );
    // The same kind of approximate reading after the host was seen down is a restart.
    let env = Arc::new(FakeEnv::new(vec![down()], up()));
    let c = rig.client_env(env.clone());
    {
        let mut q = rig.win.boots.lock().unwrap();
        q.clear();
        let mut w = win_boot(8);
        w.approximate = true;
        q.push_back(Ok(w));
    }
    let r = c.verify_restart(
        &h,
        &rig.settings,
        Some(&before),
        env.now() + Duration::from_secs(600),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(matches!(r, RestartVerify::Restarted { .. }), "{r:?}");
}

/// Review m3: wrong credentials end the restart verification after two attempts (no lockout
/// from an hour of polling); stored-password problems at once.
#[test]
fn review_m3_permission_errors_end_the_restart_verification() {
    let rig = Rig::new();
    let h = host(Some(RemoteKind::Ssh));
    rig.ssh.set_fail(|| wol_ssh::SshError::AuthFailed {
        server_methods: vec!["password".into()],
    });
    let env = Arc::new(FakeEnv::new(vec![], up()));
    let c = rig.client_env(env.clone());
    let r = c.verify_restart(
        &h,
        &rig.settings,
        None,
        env.now() + Duration::from_secs(3600),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(
        matches!(&r, RestartVerify::Failed(e) if e.kind() == ErrorKind::Permission),
        "{r:?}"
    );
    assert_eq!(rig.ssh.calls(), 2);
    // A configured Windows account without a stored password: at once, nothing sent.
    let mut w = host(Some(RemoteKind::Windows));
    remote(&mut w).user = Some(r"DESK\admin".into());
    let env = Arc::new(FakeEnv::new(vec![], up()));
    let c = rig.client_env(env.clone());
    let r = c.verify_restart(
        &w,
        &rig.settings,
        None,
        env.now() + Duration::from_secs(3600),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(
        matches!(&r, RestartVerify::Failed(e) if matches!(e.remote().map(|r| &r.failure), Some(RemoteFailure::PasswordRequired { .. }))),
        "{r:?}"
    );
    assert!(rig.win.seen.lock().unwrap().is_empty());
}

/// Review m4: a failing local probe is inconclusive; `Unresolved` counts as no answer.
#[test]
fn review_m4_local_probe_errors_are_not_down() {
    let rig = Rig::new();
    let err = || HostState::Error {
        message: "IcmpSendEcho2 failed".into(),
    };
    let unresolved = || HostState::Unresolved {
        name: "nas.local".into(),
        error: "not found".into(),
    };
    let env = Arc::new(FakeEnv::new(
        vec![
            up(),
            down(),
            err(),
            err(),
            err(),
            unresolved(),
            err(),
            up(),
            down(),
            down(),
            down(),
        ],
        up(),
    ));
    let c = rig.client_env(env.clone());
    let h = host(Some(RemoteKind::Windows));
    let mut phases = Vec::new();
    let r = c.verify_shutdown(
        &h,
        &rig.settings,
        env.now() + Duration::from_secs(300),
        &AtomicBool::new(false),
        |t| phases.push(t.phase),
    );
    assert_eq!(r, ShutdownVerify::ShutDown);
    let d = |failures| VerifyPhase::Down { failures };
    assert_eq!(
        phases,
        vec![
            VerifyPhase::Up,
            d(1),
            d(1),
            d(1),
            d(1),
            d(2),
            d(2),
            VerifyPhase::Up,
            d(1),
            d(2),
            d(3)
        ]
    );
}

/// Review R5: the shutdown verification never reports "shut down" for a host its probe never
/// saw answering, and it also probes the port remote management just used.
#[test]
fn review_r5_shutdown_needs_the_host_seen_answering_first() {
    let rig = Rig::new();
    // An SSH host on a non-default port behind a firewall that drops ICMP and the probe ports:
    // the probe includes the SSH port (an ICMP-only probe becomes ICMP, then that port).
    let mut ssh = host(Some(RemoteKind::Ssh));
    remote(&mut ssh).address = Some("192.0.2.7".parse().unwrap());
    remote(&mut ssh).port = Some(2222);
    let spec = verify_probe_spec(&ssh, &rig.settings);
    assert_eq!(
        spec.address.map(|a| a.to_string()).as_deref(),
        Some("192.0.2.7")
    );
    assert!(spec.tcp_ports.contains(&2222), "{:?}", spec.tcp_ports);
    ssh.probe = Some(crate::model::ProbeMethod::Icmp);
    let spec = verify_probe_spec(&ssh, &rig.settings);
    assert_eq!(spec.method, crate::model::ProbeMethod::Auto);
    assert_eq!(spec.tcp_ports, vec![2222]);
    ssh.probe = Some(crate::model::ProbeMethod::None);
    assert!(!verify_probe_spec(&ssh, &rig.settings).is_monitored());
    // Windows: SMB (445), once.
    let win = host(Some(RemoteKind::Windows));
    let ports = verify_probe_spec(&win, &rig.settings).tcp_ports;
    assert_eq!(ports.iter().filter(|p| **p == 445).count(), 1, "{ports:?}");
    ssh.probe = None;

    // Never seen answering: not "shut down" but "cannot verify", after three rounds.
    let env = Arc::new(FakeEnv::new(vec![], down()));
    let c = rig.client_env(env.clone());
    let mut phases = Vec::new();
    let start = env.now();
    let r = c.verify_shutdown(
        &ssh,
        &rig.settings,
        start + Duration::from_secs(300),
        &AtomicBool::new(false),
        |t| phases.push(t.phase),
    );
    assert_eq!(r, ShutdownVerify::NotMonitored);
    assert_eq!(phases, vec![VerifyPhase::Down { failures: 0 }; 3]);
    assert_eq!(env.now() - start, SHUTDOWN_POLL * 2);
    // Seen once, then gone: shut down.
    let env = Arc::new(FakeEnv::new(vec![down(), up()], down()));
    let c = rig.client_env(env.clone());
    let r = c.verify_shutdown(
        &ssh,
        &rig.settings,
        env.now() + Duration::from_secs(300),
        &AtomicBool::new(false),
        |_| {},
    );
    assert_eq!(r, ShutdownVerify::ShutDown);
    assert_eq!(env.probe_count(), 5);
}

/// Review m5: without probing, `online` / `went_down` come from the boot-time reads, so "did
/// not restart" and "did not come back" can be told apart.
#[test]
fn review_m5_unmonitored_restart_reports_what_it_saw() {
    let rig = Rig::new();
    let mut h = host(Some(RemoteKind::Windows));
    h.probe = Some(crate::model::ProbeMethod::None);
    let before = BootInfo::from_windows(win_boot(3600));
    // Never restarted: the old boot every round.
    let env = Arc::new(FakeEnv::new(vec![], up()));
    let c = rig.client_env(env.clone());
    let r = c.verify_restart(
        &h,
        &rig.settings,
        Some(&before),
        env.now() + Duration::from_secs(20),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(
        matches!(
            r,
            RestartVerify::TimedOut {
                went_down: false,
                online: true,
                last_error: None
            }
        ),
        "{r:?}"
    );
    // Went down and never came back.
    *rig.win.fail.lock().unwrap() = Some(wol_winremote::Error::new(
        wol_winremote::ErrorKind::Unreachable,
        wol_winremote::Op::Connect,
        "445",
    ));
    let env = Arc::new(FakeEnv::new(vec![], up()));
    let c = rig.client_env(env.clone());
    let r = c.verify_restart(
        &h,
        &rig.settings,
        Some(&before),
        env.now() + Duration::from_secs(20),
        &AtomicBool::new(false),
        |_| {},
    );
    match r {
        RestartVerify::TimedOut {
            went_down,
            online,
            last_error,
        } => {
            assert!(went_down && !online);
            assert!(last_error.unwrap().is_remote_transient());
        }
        other => panic!("{other:?}"),
    }
}

/// Review M3 (repro r3): a stored password is only sent for the kind, account, address and
/// port it was saved for; otherwise the operation fails before connecting.
#[test]
fn review_m3_passwords_stay_with_their_kind_and_account() {
    let rig = Rig::new();
    let c = rig.client();
    let mut h = vpn_host(RemoteKind::Windows);
    remote(&mut h).user = Some(r"DESK\admin".into());
    rig.secrets
        .set_for_host(&h, SecretKind::Login, "", "WinAdminPw!")
        .unwrap();
    c.boot_time(&h, &rig.settings).unwrap();
    assert_eq!(rig.win.last().password.as_deref(), Some("WinAdminPw!"));

    // Kind switched to SSH: the Windows password is not sent to root.
    remote(&mut h).kind = RemoteKind::Ssh;
    remote(&mut h).user = None;
    let e = c.boot_time(&h, &rig.settings).unwrap_err();
    assert_eq!(rig.ssh.calls(), 0);
    assert_eq!(e.kind(), ErrorKind::Permission);
    let r = e.remote().unwrap();
    assert_eq!(
        r.failure,
        RemoteFailure::SecretMismatch {
            secret: SecretKind::Login,
            stored_for: r"DESK\admin @ 100.105.128.173 (Windows)".into(),
            expected_for: "root@100.105.128.173:22 (SSH)".into(),
        }
    );
    let ja = describe_error(&e, Lang::Ja);
    let en = describe_error(&e, Lang::En);
    assert!(
        ja.contains("もう一度入力") && ja.contains(r"DESK\admin"),
        "{ja}"
    );
    assert!(en.is_ascii() && en.contains("again"), "{en}");

    // Windows with another configured account: not sent either.
    remote(&mut h).kind = RemoteKind::Windows;
    remote(&mut h).user = Some(r"DESK\other".into());
    let e = c.boot_time(&h, &rig.settings).unwrap_err();
    assert!(matches!(
        e.remote().map(|r| &r.failure),
        Some(RemoteFailure::SecretMismatch { .. })
    ));
    assert_eq!(rig.win.seen.lock().unwrap().len(), 1);

    // SSH user renamed pi -> root: pi's password is not sent for root.
    let mut s = vpn_host(RemoteKind::Ssh);
    remote(&mut s).user = Some("pi".into());
    rig.secrets
        .set_for_host(&s, SecretKind::Login, "", "pi-pw")
        .unwrap();
    rig.secrets
        .set_for_host(&s, SecretKind::Sudo, "", "pi-sudo")
        .unwrap();
    c.boot_time(&s, &rig.settings).unwrap();
    assert_eq!(rig.ssh.last().password.as_deref(), Some("pi-pw"));
    remote(&mut s).user = Some("root".into());
    let calls = rig.ssh.calls();
    assert!(c.boot_time(&s, &rig.settings).is_err());
    assert_eq!(rig.ssh.calls(), calls);
    // Separate sudo password for another port: refused before connecting.
    remote(&mut s).user = Some("pi".into());
    remote(&mut s).sudo = SudoMode::Separate;
    remote(&mut s).port = Some(2222);
    rig.secrets
        .set_for_host(&s, SecretKind::Login, "", "pi-pw")
        .unwrap();
    let e = c
        .power(
            &s,
            &rig.settings,
            PowerAction::Restart,
            &PowerOptions::default(),
        )
        .unwrap_err();
    assert!(matches!(
        e.remote().map(|r| &r.failure),
        Some(RemoteFailure::SecretMismatch {
            secret: SecretKind::Sudo,
            ..
        })
    ));
    assert_eq!(rig.ssh.calls(), calls);
    // Auto sudo with a stale sudo secret: not used (wol-ssh falls back to the login password).
    remote(&mut s).sudo = SudoMode::Auto;
    c.power(
        &s,
        &rig.settings,
        PowerAction::Restart,
        &PowerOptions::default(),
    )
    .unwrap();
    assert_eq!(rig.ssh.last().sudo_password, None);
    assert_eq!(rig.ssh.last().password.as_deref(), Some("pi-pw"));

    // Windows: a configured account without a password is not replaced by the sign-in.
    let mut w = host(Some(RemoteKind::Windows));
    remote(&mut w).user = Some(r"DESK\admin".into());
    let e = c.boot_time(&w, &rig.settings).unwrap_err();
    assert_eq!(
        e.remote().map(|r| &r.failure),
        Some(&RemoteFailure::PasswordRequired {
            account: r"DESK\admin".into()
        })
    );
    assert_eq!(e.kind(), ErrorKind::Permission);
    assert!(describe_error(&e, Lang::Ja).contains(r"DESK\admin"));
    assert!(describe_error(&e, Lang::En).is_ascii());
    assert_eq!(rig.win.seen.lock().unwrap().len(), 1);
}

/// Review M2 (repro r8): an import that re-points a host (address, pin) cannot make the
/// stored password travel to the new machine.
#[test]
fn review_m2_import_cannot_repoint_a_stored_password() {
    use crate::transfer::{ImportMode, ImportOptions, import};
    let rig = Rig::new();
    let c = rig.client();
    let mut cfg = Config::default();
    let mut h = host(Some(RemoteKind::Ssh));
    remote(&mut h).user = Some("admin".into());
    remote(&mut h).host_key = Some(ED25519.into());
    cfg.hosts.push(h.clone());
    rig.secrets
        .set_for_host(&h, SecretKind::Login, "", "MyNasPw")
        .unwrap();
    c.boot_time(&h, &rig.settings).unwrap();
    assert_eq!(rig.ssh.last().password.as_deref(), Some("MyNasPw"));
    let json = format!(
        r#"[{{"name":"NAS","mac":"02:00:00:00:00:01","remote":{{"kind":"ssh","user":"admin","address":"203.0.113.66","host_key":"{OTHER_ED25519}"}}}}]"#
    );
    for mode in [ImportMode::Merge, ImportMode::Replace] {
        let mut after = cfg.clone();
        let summary = import(
            &mut after,
            json.as_bytes(),
            None,
            &ImportOptions {
                mode,
                ..ImportOptions::default()
            },
        )
        .unwrap();
        assert_eq!(summary.remote_changed, vec!["NAS".to_owned()], "{mode:?}");
        assert!(summary.host_keys_kept.is_empty());
        // Review R6: the file's key is not pinned for the new address (nor the old key).
        assert_eq!(
            summary.host_keys_cleared,
            vec!["NAS".to_owned()],
            "{mode:?}"
        );
        assert_eq!(
            crate::secret::forget_removed_hosts(&rig.secrets, &cfg, &after),
            0
        );
        let h2 = after.get(h.id).unwrap();
        assert_eq!(h2.remote.as_ref().unwrap().host_key(), None);
        let calls = rig.ssh.calls();
        let e = c.boot_time(h2, &rig.settings).unwrap_err();
        assert_eq!(
            rig.ssh.calls(),
            calls,
            "nothing may be sent to the new address"
        );
        assert!(matches!(
            e.remote().map(|r| &r.failure),
            Some(RemoteFailure::SecretMismatch { stored_for, .. }) if stored_for == "admin@192.168.1.20:22 (SSH)"
        ));
        assert_eq!(
            rig.secrets.state(h2, SecretKind::Login).unwrap(),
            crate::secret::SecretState::Stale {
                stored_for: "admin@192.168.1.20:22 (SSH)".into()
            }
        );
    }
}

struct UnavailableStore;

impl crate::secret::SecretBackend for UnavailableStore {
    fn read(&self, _t: &str) -> Result<Option<Secret>> {
        Err(unavailable())
    }
    fn write(&self, _t: &str, _u: &str, _s: &str) -> Result<()> {
        Err(unavailable())
    }
    fn delete(&self, _t: &str) -> Result<bool> {
        Err(unavailable())
    }
    fn list(&self, _p: &str) -> Result<Vec<(String, String)>> {
        Err(unavailable())
    }
}

fn unavailable() -> Error {
    Error::SecretStore {
        failure: SecretStoreFailure::Unavailable,
        detail: "1312".into(),
    }
}

/// Review M6 (repro r4): an unavailable Credential Manager is reported (exit 7) when the
/// operation needs a stored password, and Windows never silently switches to the sign-in.
#[test]
fn review_m6_unavailable_credential_manager_is_reported() {
    use wol_winremote::{Error as WE, ErrorKind as K, Hint as H, Op};
    let rig = Rig::new();
    let store = SecretStore::with_backend(Arc::new(UnavailableStore), crate::secret::TARGET_PREFIX);
    let c = RemoteClient::new(store, rig.win.clone(), rig.ssh.clone());
    // SSH password login.
    let mut s = vpn_host(RemoteKind::Ssh);
    remote(&mut s).user = Some("pi".into());
    let e = c.boot_time(&s, &rig.settings).unwrap_err();
    assert_eq!(
        e.remote().map(|r| &r.failure),
        Some(&RemoteFailure::SecretStoreUnavailable)
    );
    assert_eq!(e.kind(), ErrorKind::Permission);
    assert_eq!(rig.ssh.calls(), 0);
    let ja = describe_error(&e, Lang::Ja);
    assert!(ja.contains("資格情報マネージャー"), "{ja}");
    assert!(!ja.contains("鍵ファイルもパスワードも"), "{ja}");
    // With a key file it goes on; a permission error then says why no secret was used.
    remote(&mut s).key_file = Some("id".into());
    rig.ssh
        .set_fail(|| wol_ssh::SshError::KeyPassphraseRequired { path: "id".into() });
    let e = c.boot_time(&s, &rig.settings).unwrap_err();
    assert_eq!(
        e.remote().unwrap().hint,
        Some(RemoteHint::SecretStoreUnavailable)
    );
    assert!(describe_error(&e, Lang::En).is_ascii());
    // Windows with a configured account: refused, nothing sent.
    let mut w = vpn_host(RemoteKind::Windows);
    remote(&mut w).user = Some(r"DESK\admin".into());
    let e = c.boot_time(&w, &rig.settings).unwrap_err();
    assert_eq!(
        e.remote().map(|r| &r.failure),
        Some(&RemoteFailure::SecretStoreUnavailable)
    );
    assert!(rig.win.seen.lock().unwrap().is_empty());
    // Without an account: the current sign-in (as with nothing stored), and an auth failure
    // explains that saved passwords could not be read.
    remote(&mut w).user = None;
    c.boot_time(&w, &rig.settings).unwrap();
    assert_eq!((rig.win.last().user, rig.win.last().password), (None, None));
    *rig.win.fail.lock().unwrap() =
        Some(WE::new(K::AuthFailed, Op::Connect, "1326").with_hint(H::StoreCredentials));
    let e = c.boot_time(&w, &rig.settings).unwrap_err();
    assert_eq!(
        e.remote().unwrap().hint,
        Some(RemoteHint::SecretStoreUnavailable)
    );
    assert!(describe_error(&e, Lang::Ja).contains("資格情報マネージャー"));
}

/// Review m7 / m8 / n6, and key files on network paths.
#[test]
fn review_m7_m8_n6_ssh_error_details() {
    use wol_ssh::SshError as S;
    let rig = Rig::new();
    let c = rig.client();
    let mut h = host(Some(RemoteKind::Ssh));
    // m7: a local failure is Io (exit 6), not "the host reported".
    rig.ssh.set_fail(|| S::Internal("runtime".into()));
    let e = c.boot_time(&h, &rig.settings).unwrap_err();
    assert_eq!(e.remote().unwrap().failure, RemoteFailure::Local);
    assert_eq!(e.kind(), ErrorKind::Io);
    assert!(describe_error(&e, Lang::En).is_ascii());
    // Protocol errors hint at the port.
    rig.ssh.set_fail(|| S::Protocol("not ssh".into()));
    let e = c.boot_time(&h, &rig.settings).unwrap_err();
    assert_eq!(e.remote().unwrap().hint, Some(RemoteHint::CheckPort));
    assert!(describe_error(&e, Lang::Ja).contains("ポート"));
    // m8: a changed key names the pinned type (the ssh-keygen hint file).
    remote(&mut h).host_key = Some(format!("{ED25519} root@pve"));
    rig.ssh.set_fail(|| S::HostKeyMismatch {
        expected_fp: "SHA256:old".into(),
        actual_fp: "SHA256:new".into(),
    });
    let e = c.boot_time(&h, &rig.settings).unwrap_err();
    let p = e.host_key_problem().unwrap();
    assert_eq!(p.algorithm, "ssh-ed25519");
    assert!(
        crate::i18n::Msg::HostKeyCheckHint {
            algorithm: p.algorithm.clone()
        }
        .text(Lang::Ja)
        .contains("ssh_host_ed25519_key.pub")
    );
    assert!(e.to_string().contains("presented SHA256:new"), "{e}");
    rig.ssh.set_fail(|| S::HostKeyTypeUnavailable {
        expected_fp: "SHA256:old".into(),
        key_type: "ssh-ed25519".into(),
    });
    let e = c.boot_time(&h, &rig.settings).unwrap_err();
    assert!(
        e.to_string()
            .contains("no longer offers a ssh-ed25519 host key"),
        "{e}"
    );
    // n6: a blank key path is no key file (the "public keys only" hint still shows).
    remote(&mut h).host_key = None;
    remote(&mut h).key_file = Some(PathBuf::from("  "));
    rig.ssh.set_fail(|| S::AuthFailed {
        server_methods: vec!["publickey".into()],
    });
    let e = c.boot_time(&h, &rig.settings).unwrap_err();
    assert_eq!(rig.ssh.last().key_file, None);
    assert_eq!(
        e.remote().unwrap().hint,
        Some(RemoteHint::PasswordAuthDisabled)
    );
    // Key files on network paths are refused (reading one would log on to that server).
    *rig.ssh.fail.lock().unwrap() = None;
    for p in [
        r"\\attacker\share\id",
        "//attacker/share/id",
        r"\\?\UNC\srv\s\id",
    ] {
        remote(&mut h).key_file = Some(PathBuf::from(p));
        let calls = rig.ssh.calls();
        let e = c.boot_time(&h, &rig.settings).unwrap_err();
        assert!(
            matches!(
                e.remote().map(|r| &r.failure),
                Some(RemoteFailure::KeyFile { .. })
            ),
            "{p}"
        );
        assert_eq!(rig.ssh.calls(), calls, "{p}");
    }
    for p in [r"\\?\C:\keys\id", r"C:\Users\me\.ssh\id_ed25519", "id"] {
        remote(&mut h).key_file = Some(PathBuf::from(p));
        c.boot_time(&h, &rig.settings).unwrap();
    }
}

/// Review m11: the best candidate is only taken without asking when it is a good WoL target.
#[test]
fn review_m11_unique_best_only_picks_wired_linked_wol_capable_nics() {
    let base = MacCandidate {
        iface: "eno1".into(),
        mac: MacAddr([0x02, 0, 0, 0, 0, 1]),
        permanent_mac: None,
        current_mac: None,
        kind: NicKind::Physical,
        on_default_route: true,
        via: None,
        link_up: true,
        wol_enabled: None,
        lan_ipv4: None,
        score: 100,
    };
    assert!(unique_best(std::slice::from_ref(&base)).is_some());
    for bad in [
        MacCandidate {
            kind: NicKind::Wifi,
            ..base.clone()
        },
        MacCandidate {
            kind: NicKind::Other,
            ..base.clone()
        },
        MacCandidate {
            link_up: false,
            ..base.clone()
        },
        MacCandidate {
            wol_enabled: Some(false),
            ..base.clone()
        },
    ] {
        assert!(!auto_pickable(&bad));
        assert!(unique_best(std::slice::from_ref(&bad)).is_none(), "{bad:?}");
        let second = MacCandidate {
            score: 1,
            ..base.clone()
        };
        assert!(unique_best(&[bad, second]).is_none());
    }
    assert!(auto_pickable(&MacCandidate {
        wol_enabled: Some(true),
        ..base
    }));
}

/// A stale `before` with another boot id and a probe that never answers (ICMP filtered) do
/// not fake a restart: the current boot becomes the baseline, a real restart is still seen.
#[test]
fn review_m1_stale_boot_id_with_a_blind_probe_is_not_a_restart() {
    let rig = Rig::new();
    let h = host(Some(RemoteKind::Ssh));
    let stale = BootInfo::from_ssh(ssh_boot(90_000, "boot-from-last-week"));
    let env = Arc::new(FakeEnv::new(vec![], down()));
    let c = rig.client_env(env.clone());
    let r = c.verify_restart(
        &h,
        &rig.settings,
        Some(&stale),
        env.now() + Duration::from_secs(60),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(
        matches!(r, RestartVerify::TimedOut { online: false, .. }),
        "{r:?}"
    );
    // The same situation with a real restart after the old boot was read.
    let env = Arc::new(FakeEnv::new(vec![], down()));
    let c = rig.client_env(env.clone());
    {
        let mut q = rig.ssh.boots.lock().unwrap();
        q.push_back(ssh_boot(3600, "current"));
        q.push_back(ssh_boot(3615, "current"));
        let mut skewed = ssh_boot(7200, "after-restart");
        skewed.approximate = true;
        q.push_back(skewed);
    }
    let r = c.verify_restart(
        &h,
        &rig.settings,
        Some(&stale),
        env.now() + Duration::from_secs(600),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(
        matches!(&r, RestartVerify::Restarted { boot } if boot.boot_id.as_deref() == Some("after-restart")),
        "{r:?}"
    );
}

/// Cross review X2: a Windows host without a saved password connects with the current
/// Windows sign-in. An unattended client (the GUI's automatic boot time) does that only for a
/// host the user confirmed at its current management address; an import can neither create
/// nor move the confirmation.
#[test]
fn x2_unattended_operations_need_a_confirmed_sign_in() {
    let rig = Rig::new();
    let user = rig.client();
    let auto = rig.client().unattended();
    let mut h = host(Some(RemoteKind::Windows));
    assert!(user.uses_sign_in(&h));
    // Not confirmed: the automatic fetch sends nothing.
    let e = auto.boot_time(&h, &rig.settings).unwrap_err();
    assert_eq!(
        e.remote().map(|r| &r.failure),
        Some(&RemoteFailure::SignInNotConfirmed)
    );
    assert_eq!(e.kind(), ErrorKind::Permission);
    assert!(rig.win.seen.lock().unwrap().is_empty(), "nothing was sent");
    assert!(describe_error(&e, Lang::En).is_ascii());
    assert!(describe_error(&e, Lang::Ja).contains("Windows サインイン"));
    assert!(auto.check_sign_in(&h, RemoteOp::BootTime).is_err());
    // A user-started operation works as before (and says nothing about confirmations).
    user.boot_time(&h, &rig.settings).unwrap();
    assert_eq!((rig.win.last().user, rig.win.last().password), (None, None));
    // The user's confirmation: recorded once, then automatic operations may use it.
    assert_eq!(
        user.confirm_sign_in(&h).unwrap(),
        Some(current_windows_account().unwrap_or_default())
    );
    assert_eq!(user.confirm_sign_in(&h).unwrap(), None, "already confirmed");
    auto.boot_time(&h, &rig.settings).unwrap();
    auto.check_sign_in(&h, RemoteOp::BootTime).unwrap();
    // Re-pointed (e.g. by an import): another address is not confirmed.
    let mut moved = h.clone();
    remote(&mut moved).address = Some("203.0.113.9".parse().unwrap());
    let before = rig.win.seen.lock().unwrap().len();
    assert!(auto.boot_time(&moved, &rig.settings).is_err());
    assert_eq!(rig.win.seen.lock().unwrap().len(), before);
    // Every operation of an unattended client is covered.
    assert!(auto.mac_candidates(&moved, &rig.settings).is_err());
    assert!(auto.test_connection(&moved, &rig.settings).is_err());
    assert!(auto.abort_shutdown(&moved, &rig.settings).is_err());
    assert!(
        auto.power(
            &moved,
            &rig.settings,
            PowerAction::Restart,
            &PowerOptions::default()
        )
        .is_err()
    );
    assert_eq!(rig.win.seen.lock().unwrap().len(), before);
    // A saved password (sent only to its own address) needs no confirmation.
    rig.secrets
        .set_for_host(&moved, SecretKind::Login, r"PC\admin", "pw")
        .unwrap();
    assert!(!user.uses_sign_in(&moved));
    assert_eq!(user.confirm_sign_in(&moved).unwrap(), None);
    auto.boot_time(&moved, &rig.settings).unwrap();
    assert_eq!(rig.win.last().password.as_deref(), Some("pw"));
    // Typed passwords (editor overrides) are not the sign-in either.
    let typed = rig.client().with_overrides(SecretOverrides {
        login: SecretOverride::Value("typed".to_owned().into()),
        ..SecretOverrides::default()
    });
    assert!(!typed.uses_sign_in(&h));
    // Another configured account without a password fails before connecting anyway.
    remote(&mut h).user = Some(r"OTHER-PC\someone".into());
    if !is_current_windows_account(r"OTHER-PC\someone") {
        assert!(!user.uses_sign_in(&h));
        assert!(auto.check_sign_in(&h, RemoteOp::BootTime).is_ok());
    }
    // SSH never uses the Windows sign-in.
    let ssh = host(Some(RemoteKind::Ssh));
    assert!(!user.uses_sign_in(&ssh));
    assert_eq!(user.confirm_sign_in(&ssh).unwrap(), None);
    assert!(auto.check_sign_in(&ssh, RemoteOp::BootTime).is_ok());
    // A store that cannot be read counts as "not confirmed".
    let unavailable =
        SecretStore::with_backend(Arc::new(UnavailableStore), crate::secret::TARGET_PREFIX);
    let c = RemoteClient::new(unavailable, rig.win.clone(), rig.ssh.clone()).unattended();
    let fresh = host(Some(RemoteKind::Windows));
    let e = c.boot_time(&fresh, &rig.settings).unwrap_err();
    assert_eq!(
        e.remote().map(|r| &r.failure),
        Some(&RemoteFailure::SignInNotConfirmed)
    );
}

/// Cross review X1 / m3 / m4: the custom power command of a host (for the confirmations) and
/// key file checks at set time.
#[test]
fn x1_custom_commands_and_key_file_issues() {
    let mut h = host(Some(RemoteKind::Ssh));
    assert_eq!(custom_power_command(&h, PowerAction::Restart), None);
    remote(&mut h).reboot_command = Some("  /sbin/reboot -f ".into());
    remote(&mut h).shutdown_command = Some("   ".into());
    assert_eq!(
        custom_power_command(&h, PowerAction::Restart),
        Some("/sbin/reboot -f")
    );
    assert_eq!(custom_power_command(&h, PowerAction::Shutdown), None);
    // Windows hosts never run one.
    remote(&mut h).kind = RemoteKind::Windows;
    assert_eq!(custom_power_command(&h, PowerAction::Restart), None);

    use std::path::Path;
    assert_eq!(key_file_issue(Path::new("")), None);
    for unc in [
        r"\\server\share\id",
        "//server/share/id",
        r"\\?\UNC\server\share\id",
    ] {
        assert_eq!(
            key_file_issue(Path::new(unc)),
            Some(KeyFileIssue::NetworkPath),
            "{unc}"
        );
    }
    assert_eq!(
        key_file_issue(Path::new(r"C:\no\such\id_ed25519.PUB")),
        Some(KeyFileIssue::PublicKey)
    );
    assert_eq!(
        key_file_issue(Path::new(r"C:\no\such\id_ed25519")),
        Some(KeyFileIssue::Missing)
    );
    let dir = std::env::temp_dir().join(format!("wolm-key-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("id_ed25519");
    std::fs::write(&key, "test").unwrap();
    assert_eq!(key_file_issue(&key), None);
    assert_eq!(
        key_file_issue(&dir),
        Some(KeyFileIssue::Missing),
        "a folder"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
