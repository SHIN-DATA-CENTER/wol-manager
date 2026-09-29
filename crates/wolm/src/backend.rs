//! Remote management and the secret store as the commands use them.
//!
//! Release builds always use Windows Credential Manager and the real Windows / SSH backends
//! of wol-core. Debug builds (the test suite) have two seams, like
//! `WOL_MANAGER_PATH_BACKEND_FILE` for PATH:
//! * [`ENV_SECRET_FILE`]: a JSON file instead of Credential Manager, so tests never create,
//!   read or delete real credentials.
//! * [`ENV_REMOTE_FAKE`]: a JSON script that answers every remote operation (and logs the
//!   calls as JSON lines), so tests never contact a host and never run a real power request.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use wol_core::macfind::{self, MacFound, MacQuery, SystemMacEnv};
use wol_core::remote::{
    BootInfo, ConnInfo, HostKeyInfo, PowerAction, PowerOptions, PowerOutcome, RemoteClient,
    RestartVerify, ShutdownVerify, SystemSsh, SystemWindows, VerifyTick,
};
use wol_core::secret::SecretStore;
use wol_core::{Host, Result, Settings};

/// Debug builds: JSON file used instead of Windows Credential Manager.
#[cfg(debug_assertions)]
pub const ENV_SECRET_FILE: &str = "WOL_MANAGER_SECRET_BACKEND_FILE";

/// Debug builds: JSON script that replaces every remote operation.
#[cfg(debug_assertions)]
pub const ENV_REMOTE_FAKE: &str = "WOL_MANAGER_REMOTE_FAKE";

#[cfg(debug_assertions)]
fn env_path(name: &str) -> Option<std::path::PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
}

/// The secret store: Windows Credential Manager (debug builds: the test file when
/// [`ENV_SECRET_FILE`] is set).
pub fn secret_store() -> SecretStore {
    #[cfg(debug_assertions)]
    if let Some(p) = env_path(ENV_SECRET_FILE) {
        return SecretStore::with_backend(
            Arc::new(file_secrets::FileSecrets::new(p)),
            wol_core::secret::TARGET_PREFIX,
        );
    }
    SecretStore::system()
}

/// A remote client with [`secret_store`] for the checks that need no connection (whether a
/// host uses the current Windows sign-in, and its confirmation).
pub fn client() -> RemoteClient {
    RemoteClient::new(secret_store(), Arc::new(SystemWindows), Arc::new(SystemSsh))
}

/// Remote operations of one `wolm` run. Everything here blocks (network I/O).
pub struct Remote {
    client: RemoteClient,
    #[cfg(debug_assertions)]
    fake: Option<fake::Fake>,
}

impl Remote {
    /// Real backends with [`secret_store`] (debug builds: the fake when [`ENV_REMOTE_FAKE`]
    /// is set).
    pub fn new() -> Result<Remote> {
        let client = client();
        #[cfg(debug_assertions)]
        {
            let fake = match env_path(ENV_REMOTE_FAKE) {
                Some(p) => Some(fake::Fake::load(&p)?),
                None => None,
            };
            Ok(Remote { client, fake })
        }
        #[cfg(not(debug_assertions))]
        Ok(Remote { client })
    }

    /// The secret store the operations use (the fake logs whether a password is stored).
    #[cfg(debug_assertions)]
    fn secrets(&self) -> &SecretStore {
        self.client.secrets()
    }

    /// The client (sign-in checks and confirmations; the fake does not replace them, they
    /// only use the secret store).
    pub fn client(&self) -> &RemoteClient {
        &self.client
    }

    /// Boot time.
    pub fn boot_time(&self, h: &Host, s: &Settings) -> Result<BootInfo> {
        #[cfg(debug_assertions)]
        if let Some(f) = &self.fake {
            return f.boot_time(h, self.secrets());
        }
        self.client.boot_time(h, s)
    }

    /// Restart / shutdown request.
    pub fn power(
        &self,
        h: &Host,
        s: &Settings,
        action: PowerAction,
        opts: &PowerOptions,
    ) -> Result<PowerOutcome> {
        #[cfg(debug_assertions)]
        if let Some(f) = &self.fake {
            return f.power(h, self.secrets(), action, opts);
        }
        self.client.power(h, s, action, opts)
    }

    /// Cancels a pending Windows shutdown.
    pub fn abort_shutdown(&self, h: &Host, s: &Settings) -> Result<()> {
        #[cfg(debug_assertions)]
        if let Some(f) = &self.fake {
            return f.abort(h, self.secrets());
        }
        self.client.abort_shutdown(h, s)
    }

    /// Smart MAC lookup (ARP on the LAN, else the host's remote management).
    pub fn find_mac(&self, q: &MacQuery<'_>, s: &Settings) -> Result<MacFound> {
        #[cfg(debug_assertions)]
        if let Some(f) = &self.fake
            && let Some(h) = q.host.filter(|h| h.remote.is_some())
        {
            return f.mac(h, self.secrets());
        }
        macfind::find_mac_with(q, s, &self.client, &SystemMacEnv)
    }

    /// Connection test.
    pub fn test_connection(&self, h: &Host, s: &Settings) -> Result<ConnInfo> {
        #[cfg(debug_assertions)]
        if let Some(f) = &self.fake {
            return f.test(h, self.secrets());
        }
        self.client.test_connection(h, s)
    }

    /// Reads an SSH host key without logging in.
    pub fn scan_host_key(&self, h: &Host, s: &Settings) -> Result<HostKeyInfo> {
        #[cfg(debug_assertions)]
        if let Some(f) = &self.fake {
            return f.scan_host_key(h, self.secrets());
        }
        self.client.scan_host_key(h, s)
    }

    /// `~/.ssh/known_hosts` has this key for the host.
    pub fn in_known_hosts(&self, h: &Host, openssh_line: &str) -> bool {
        #[cfg(debug_assertions)]
        if let Some(f) = &self.fake {
            return f.in_known_hosts();
        }
        self.client.in_known_hosts(h, openssh_line)
    }

    /// Waits for a restart (see `wol_core::remote::verify_restart`).
    pub fn verify_restart(
        &self,
        h: &Host,
        s: &Settings,
        before: Option<&BootInfo>,
        deadline: Instant,
        cancel: &AtomicBool,
        on_tick: impl FnMut(&VerifyTick),
    ) -> RestartVerify {
        #[cfg(debug_assertions)]
        if let Some(f) = &self.fake {
            return f.verify_restart(h, deadline, cancel, on_tick);
        }
        self.client
            .verify_restart(h, s, before, deadline, cancel, on_tick)
    }

    /// Waits for a shutdown (see `wol_core::remote::verify_shutdown`).
    pub fn verify_shutdown(
        &self,
        h: &Host,
        s: &Settings,
        deadline: Instant,
        cancel: &AtomicBool,
        on_tick: impl FnMut(&VerifyTick),
    ) -> ShutdownVerify {
        #[cfg(debug_assertions)]
        if let Some(f) = &self.fake {
            return f.verify_shutdown(h, deadline, cancel, on_tick);
        }
        self.client.verify_shutdown(h, s, deadline, cancel, on_tick)
    }
}

/// Test secret store: `{"<target>": {"user": "...", "secret": "..."}}`. `"__unavailable":
/// true` makes every call fail like Credential Manager in a network logon session.
#[cfg(debug_assertions)]
mod file_secrets {
    use std::path::PathBuf;

    use serde_json::{Map, Value, json};
    use wol_core::error::SecretStoreFailure;
    use wol_core::secret::{MAX_STORED_UNITS, MAX_USER_UNITS, Secret, SecretBackend};
    use wol_core::{Error, Result};
    use zeroize::Zeroizing;

    pub struct FileSecrets {
        path: PathBuf,
    }

    impl FileSecrets {
        pub fn new(path: PathBuf) -> FileSecrets {
            FileSecrets { path }
        }

        fn load(&self) -> Result<Map<String, Value>> {
            let map = match std::fs::read_to_string(&self.path) {
                Ok(t) if !t.trim().is_empty() => serde_json::from_str::<Map<String, Value>>(&t)
                    .map_err(|e| Error::Serialize(e.to_string()))?,
                Ok(_) => Map::new(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Map::new(),
                Err(e) => return Err(Error::io("read", self.path.clone(), e)),
            };
            if map.get("__unavailable").and_then(Value::as_bool) == Some(true) {
                return Err(Error::SecretStore {
                    failure: SecretStoreFailure::Unavailable,
                    detail: "test backend: unavailable".to_owned(),
                });
            }
            Ok(map)
        }

        fn save(&self, map: &Map<String, Value>) -> Result<()> {
            let text =
                serde_json::to_string_pretty(map).map_err(|e| Error::Serialize(e.to_string()))?;
            std::fs::write(&self.path, text).map_err(|e| Error::io("write", self.path.clone(), e))
        }
    }

    impl SecretBackend for FileSecrets {
        fn read(&self, target: &str) -> Result<Option<Secret>> {
            Ok(self.load()?.get(target).map(|v| Secret {
                user: v["user"].as_str().unwrap_or_default().to_owned(),
                secret: Zeroizing::new(v["secret"].as_str().unwrap_or_default().to_owned()),
            }))
        }

        /// The limits of Windows Credential Manager for the stored (sealed) value; wol-core
        /// refuses a secret above `MAX_SECRET_UNITS` before it adds the binding, exactly as
        /// with the real store (cross review n10).
        fn write(&self, target: &str, user: &str, secret: &str) -> Result<()> {
            if secret.encode_utf16().count() > MAX_STORED_UNITS
                || user.encode_utf16().count() > MAX_USER_UNITS
            {
                return Err(Error::SecretStore {
                    failure: SecretStoreFailure::TooLong,
                    detail: "secret or user name too long".to_owned(),
                });
            }
            let mut map = self.load()?;
            map.insert(target.to_owned(), json!({ "user": user, "secret": secret }));
            self.save(&map)
        }

        fn delete(&self, target: &str) -> Result<bool> {
            let mut map = self.load()?;
            let existed = map.remove(target).is_some();
            if existed {
                self.save(&map)?;
            }
            Ok(existed)
        }

        fn list(&self, prefix: &str) -> Result<Vec<(String, String)>> {
            Ok(self
                .load()?
                .iter()
                .filter(|(t, _)| t.starts_with(prefix))
                .map(|(t, v)| (t.clone(), v["user"].as_str().unwrap_or_default().to_owned()))
                .collect())
        }
    }
}

/// Scripted remote operations for the tests. The script is a JSON object; every key is
/// optional:
///
/// ```json
/// { "log": "calls.jsonl",                       // default: <script>.log
///   "boot_time": {"uptime_secs": 3600, "source": "fake", "approximate": false},
///   "power": {"result": "accepted" | "scheduled"},  // default: Windows with a delay → scheduled
///   "abort": {},  "test": {"os": "...", "admin_hint": true, "user": "root", "kernel": "...",
///            "admin_check": "admin" | "not_admin" | "wmi_denied" | "wmi_unreachable" |
///                           "not_checked" | "unknown"},  // default: from admin_hint
///   "mac": {"candidates": [{"iface": "eth0", "mac": "..", "kind": "physical", "score": 10,
///            "on_default_route": true, "link_up": true, "lan_ipv4": "192.0.2.5/24"}]},
///   "scan_host_key": {"host_key": "ssh-ed25519 AAAA..."}, "known_hosts": false,
///   "verify_restart": "restarted" | "timed_out" | "cancelled" | "failed:<error>",
///   "verify_shutdown": "shut_down" | "timed_out" | "not_monitored" | "cancelled" }
/// ```
///
/// Any operation object may be `{"error": "<code>"}` instead: `unreachable`, `timeout`,
/// `auth_failed`, `access_denied`, `sudo_password_required`, `no_shutdown_in_progress`,
/// `power_unconfirmed`, `no_candidates`, `local_target`, `unknown_host_key`,
/// `host_key_mismatch`, `secret_mismatch`, `password_required`, anything else = `other`. Every
/// call appends one JSON line to the log.
#[cfg(debug_assertions)]
mod fake {
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant, SystemTime};

    use serde_json::{Value, json};
    use wol_core::macfind::MacFound;
    use wol_core::netif::Ipv4Subnet;
    use wol_core::probe::HostState;
    use wol_core::remote::{
        self, AdminCheck, BootInfo, ConnInfo, HostKeyInfo, MacCandidate, NicKind, PowerAction,
        PowerOptions, PowerOutcome, RemoteError, RemoteFailure, RemoteOp, RemoteStage,
        RestartVerify, ShutdownVerify, VerifyPhase, VerifyTick,
    };
    use wol_core::secret::{SecretKind, SecretStore};
    use wol_core::{Error, Host, HostKeyProblem, MacAddr, RemoteKind, Result};

    /// Host key used for scripted host-key errors (any valid key works).
    const FAKE_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    pub struct Fake {
        script: Value,
        log: PathBuf,
    }

    struct Call<'a> {
        host: &'a Host,
        kind: RemoteKind,
        address: String,
    }

    impl Fake {
        pub fn load(path: &Path) -> Result<Fake> {
            let text = std::fs::read_to_string(path)
                .map_err(|e| Error::io("read", path.to_path_buf(), e))?;
            let script: Value =
                serde_json::from_str(&text).map_err(|e| Error::Serialize(e.to_string()))?;
            let log = script
                .get("log")
                .and_then(Value::as_str)
                .map(PathBuf::from)
                .unwrap_or_else(|| path.with_extension("log"));
            Ok(Fake { script, log })
        }

        fn record(&self, entry: &Value) {
            // Batches call from several threads: one write per line, one writer at a time.
            static LOG: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let _guard = LOG.lock().unwrap_or_else(|p| p.into_inner());
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log)
            {
                let _ = f.write_all(format!("{entry}\n").as_bytes());
            }
        }

        /// The checks of wol-core's `RemoteClient`, then logs the call and returns the
        /// scripted answer (or its error).
        fn call<'h>(
            &self,
            op: &str,
            h: &'h Host,
            secrets: &SecretStore,
            extra: Value,
        ) -> Result<(Call<'h>, Value)> {
            let r = h
                .remote
                .as_ref()
                .ok_or_else(|| Error::RemoteNotConfigured {
                    host: h.name.clone(),
                })?;
            let address = h
                .management_address()
                .ok_or_else(|| Error::RemoteNoAddress {
                    host: h.name.clone(),
                })?
                .to_string();
            let call = Call {
                host: h,
                kind: r.kind,
                address,
            };
            let mut entry = json!({
                "op": op,
                "host": h.name,
                "kind": r.kind.as_str(),
                "address": call.address,
                "login_secret": secrets.has(h.id, SecretKind::Login).unwrap_or(false),
                "sign_in_confirmed": secrets.sign_in_confirmed(h).unwrap_or(false),
            });
            if let (Some(e), Value::Object(x)) = (entry.as_object_mut(), extra) {
                e.extend(x);
            }
            self.record(&entry);
            let answer = self.script.get(op).cloned().unwrap_or(Value::Null);
            if let Some(code) = answer.get("error").and_then(Value::as_str) {
                return Err(error(code, &call, op_of(op)));
            }
            Ok((call, answer))
        }

        pub fn boot_time(&self, h: &Host, secrets: &SecretStore) -> Result<BootInfo> {
            let (_, v) = self.call("boot_time", h, secrets, json!({}))?;
            Ok(boot(&v))
        }

        pub fn power(
            &self,
            h: &Host,
            secrets: &SecretStore,
            action: PowerAction,
            opts: &PowerOptions,
        ) -> Result<PowerOutcome> {
            let extra = json!({
                "action": action.as_str(),
                "delay_secs": opts.delay_secs,
                "force": opts.force,
                "message": opts.message,
            });
            let op = match action {
                PowerAction::Restart => RemoteOp::Restart,
                PowerAction::Shutdown => RemoteOp::Shutdown,
            };
            let (c, v) = self
                .call("power", h, secrets, extra)
                .map_err(|e| retag(e, op))?;
            Ok(match v.get("result").and_then(Value::as_str) {
                Some("accepted") => PowerOutcome::Accepted,
                Some("scheduled") => PowerOutcome::Scheduled {
                    delay_secs: opts.delay_secs,
                },
                _ if c.kind == RemoteKind::Windows && opts.delay_secs > 0 => {
                    PowerOutcome::Scheduled {
                        delay_secs: opts.delay_secs,
                    }
                }
                _ => PowerOutcome::Accepted,
            })
        }

        pub fn abort(&self, h: &Host, secrets: &SecretStore) -> Result<()> {
            if let Some(r) = &h.remote
                && r.kind == RemoteKind::Ssh
            {
                return Err(Error::RemoteUnsupported {
                    host: h.name.clone(),
                    kind: r.kind,
                    op: RemoteOp::AbortShutdown,
                });
            }
            self.call("abort", h, secrets, json!({}))?;
            Ok(())
        }

        pub fn mac(&self, h: &Host, secrets: &SecretStore) -> Result<MacFound> {
            let (c, v) = self.call("mac", h, secrets, json!({}))?;
            let mut candidates: Vec<MacCandidate> = v
                .get("candidates")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(candidate).collect())
                .unwrap_or_default();
            candidates.sort_by_key(|c| std::cmp::Reverse(c.score));
            if candidates.is_empty() {
                return Err(error("no_candidates", &c, RemoteOp::MacCandidates));
            }
            Ok(MacFound::Remote { candidates })
        }

        pub fn test(&self, h: &Host, secrets: &SecretStore) -> Result<ConnInfo> {
            let (c, v) = self.call("test", h, secrets, json!({}))?;
            let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
            let admin_hint = v.get("admin_hint").and_then(Value::as_bool);
            let admin_check = match (s("admin_check").as_deref(), admin_hint, c.kind) {
                (Some("admin"), ..) | (None, Some(true), _) => AdminCheck::Admin,
                (Some("not_admin"), ..) | (None, Some(false), RemoteKind::Ssh) => {
                    AdminCheck::NotAdmin
                }
                (Some("wmi_denied"), ..) | (None, Some(false), RemoteKind::Windows) => {
                    AdminCheck::WmiDenied
                }
                (Some("wmi_unreachable"), ..) => AdminCheck::WmiUnreachable,
                (Some("not_checked"), ..) => AdminCheck::NotChecked,
                _ => AdminCheck::Unknown,
            };
            Ok(ConnInfo {
                os: s("os"),
                boot: boot(v.get("boot").unwrap_or(&Value::Null)),
                admin_hint,
                admin_check,
                user: s("user").or_else(|| (c.kind == RemoteKind::Ssh).then(|| "root".into())),
                kernel: s("kernel"),
            })
        }

        pub fn scan_host_key(&self, h: &Host, secrets: &SecretStore) -> Result<HostKeyInfo> {
            if let Some(r) = &h.remote
                && r.kind == RemoteKind::Windows
            {
                return Err(Error::RemoteUnsupported {
                    host: h.name.clone(),
                    kind: r.kind,
                    op: RemoteOp::ScanHostKey,
                });
            }
            let (_, v) = self.call("scan_host_key", h, secrets, json!({}))?;
            remote::parse_host_key(
                v.get("host_key")
                    .and_then(Value::as_str)
                    .unwrap_or(FAKE_KEY),
            )
        }

        pub fn in_known_hosts(&self) -> bool {
            self.script.get("known_hosts").and_then(Value::as_bool) == Some(true)
        }

        fn ticks(&self, h: &Host, verb: &str, on_tick: &mut impl FnMut(&VerifyTick)) {
            self.record(&json!({ "op": verb, "host": h.name }));
            on_tick(&VerifyTick {
                phase: VerifyPhase::Down { failures: 1 },
                state: HostState::Unknown,
                elapsed: Duration::from_millis(10),
            });
        }

        pub fn verify_restart(
            &self,
            h: &Host,
            _deadline: Instant,
            _cancel: &AtomicBool,
            mut on_tick: impl FnMut(&VerifyTick),
        ) -> RestartVerify {
            self.ticks(h, "verify_restart", &mut on_tick);
            let v = self
                .script
                .get("verify_restart")
                .and_then(Value::as_str)
                .unwrap_or("restarted");
            match v {
                "timed_out" => RestartVerify::TimedOut {
                    went_down: true,
                    online: false,
                    last_error: None,
                },
                "cancelled" => RestartVerify::Cancelled,
                other => match other.strip_prefix("failed:") {
                    Some(code) => {
                        let call = Call {
                            host: h,
                            kind: h.remote_kind().unwrap_or(RemoteKind::Ssh),
                            address: h
                                .management_address()
                                .map(ToString::to_string)
                                .unwrap_or_default(),
                        };
                        RestartVerify::Failed(error(code, &call, RemoteOp::BootTime))
                    }
                    None => RestartVerify::Restarted {
                        boot: boot(&json!({ "uptime_secs": 20 })),
                    },
                },
            }
        }

        pub fn verify_shutdown(
            &self,
            h: &Host,
            _deadline: Instant,
            _cancel: &AtomicBool,
            mut on_tick: impl FnMut(&VerifyTick),
        ) -> ShutdownVerify {
            self.ticks(h, "verify_shutdown", &mut on_tick);
            match self
                .script
                .get("verify_shutdown")
                .and_then(Value::as_str)
                .unwrap_or("shut_down")
            {
                "timed_out" => ShutdownVerify::TimedOut {
                    last: HostState::Unknown,
                },
                "not_monitored" => ShutdownVerify::NotMonitored,
                "cancelled" => ShutdownVerify::Cancelled,
                _ => ShutdownVerify::ShutDown,
            }
        }
    }

    fn op_of(op: &str) -> RemoteOp {
        match op {
            "boot_time" => RemoteOp::BootTime,
            "abort" => RemoteOp::AbortShutdown,
            "mac" => RemoteOp::MacCandidates,
            "test" => RemoteOp::TestConnection,
            "scan_host_key" => RemoteOp::ScanHostKey,
            _ => RemoteOp::Restart,
        }
    }

    fn retag(e: Error, op: RemoteOp) -> Error {
        match e {
            Error::Remote(mut r) => {
                r.op = op;
                Error::Remote(r)
            }
            other => other,
        }
    }

    fn boot(v: &Value) -> BootInfo {
        let uptime =
            Duration::from_secs(v.get("uptime_secs").and_then(Value::as_u64).unwrap_or(3600));
        BootInfo {
            boot_time: SystemTime::now() - uptime,
            uptime,
            source: v
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or("fake")
                .to_owned(),
            approximate: v.get("approximate").and_then(Value::as_bool) == Some(true),
            boot_id: v.get("boot_id").and_then(Value::as_str).map(str::to_owned),
        }
    }

    fn candidate(v: &Value) -> Option<MacCandidate> {
        let s = |k: &str| v.get(k).and_then(Value::as_str);
        let b = |k: &str| v.get(k).and_then(Value::as_bool);
        Some(MacCandidate {
            iface: s("iface")?.to_owned(),
            mac: MacAddr::parse(s("mac")?).ok()?,
            permanent_mac: None,
            current_mac: None,
            kind: match s("kind") {
                Some("wifi") => NicKind::Wifi,
                Some("other") => NicKind::Other,
                _ => NicKind::Physical,
            },
            on_default_route: b("on_default_route").unwrap_or(false),
            via: s("via").map(str::to_owned),
            link_up: b("link_up").unwrap_or(true),
            wol_enabled: b("wol_enabled"),
            lan_ipv4: s("lan_ipv4").and_then(|t| t.parse::<Ipv4Subnet>().ok()),
            score: v.get("score").and_then(Value::as_i64).unwrap_or(0) as i32,
        })
    }

    fn error(code: &str, c: &Call<'_>, op: RemoteOp) -> Error {
        let problem = |mismatch: bool| {
            let k = remote::parse_host_key(FAKE_KEY).expect("valid test key");
            Box::new(HostKeyProblem {
                host: c.host.name.clone(),
                address: c.address.clone(),
                port: c.host.remote.as_ref().map_or(22, |r| r.ssh_port()),
                algorithm: k.algorithm,
                fingerprint: k.fingerprint,
                openssh_line: if mismatch {
                    String::new()
                } else {
                    k.openssh_line
                },
                expected_fingerprint: mismatch
                    .then(|| "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned()),
                in_known_hosts: false,
            })
        };
        let failure = match code {
            "unknown_host_key" => return Error::UnknownHostKey(problem(false)),
            "host_key_mismatch" => return Error::HostKeyMismatch(problem(true)),
            "unreachable" => RemoteFailure::Unreachable,
            "timeout" => RemoteFailure::Timeout {
                stage: RemoteStage::Connect,
            },
            "auth_failed" => RemoteFailure::AuthFailed {
                server_methods: Vec::new(),
            },
            "access_denied" => RemoteFailure::AccessDenied,
            "sudo_password_required" => RemoteFailure::SudoPasswordRequired,
            "no_shutdown_in_progress" => RemoteFailure::NoShutdownInProgress,
            "power_unconfirmed" => RemoteFailure::PowerUnconfirmed,
            "no_candidates" => RemoteFailure::NoCandidates,
            "local_target" => RemoteFailure::LocalTarget,
            "secret_mismatch" => RemoteFailure::SecretMismatch {
                secret: SecretKind::Login,
                stored_for: "root@192.0.2.99:22 (SSH)".to_owned(),
                expected_for: format!("root@{}:22 (SSH)", c.address),
            },
            "password_required" => RemoteFailure::PasswordRequired {
                account: r"PC\admin".to_owned(),
            },
            _ => RemoteFailure::Other,
        };
        Error::Remote(Box::new(RemoteError {
            host: c.host.name.clone(),
            address: c.address.clone(),
            backend: c.kind,
            op,
            failure,
            hint: None,
            code: None,
            detail: format!("fake {code}"),
        }))
    }
}
