//! The blocking SSH [`Session`] over russh: connect with timeouts, host-key pinning,
//! authentication, `exec` with capped output, clean disconnect.

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use russh::client::{self, AuthResult, KeyboardInteractiveAuthResponse};
use russh::keys::{
    self, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate,
};
use russh::{
    AlgorithmKind, Channel, ChannelMsg, Disconnect, MethodKind, MethodSet, Preferred, Sig,
};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::time::{Instant, timeout, timeout_at};
use zeroize::Zeroizing;

use crate::boot::{self, BootInfo, no_marker_hint};
use crate::error::{Result, SshError, TimeoutStage, from_russh, sanitize};
use crate::hostkey::{self, HostKeyInfo};
use crate::info::{self, ConnInfo};
use crate::net::{self, MacCandidate};
use crate::power::{self, PowerAction, PowerOverrides, PowerScheduled};
use crate::scripts::{self, MARKER, READONLY_COMMAND, marker_lines};
use crate::target::{SudoMode, Target, Timeouts};

/// Cap for each of stdout and stderr collected by [`Session::exec`] (1 MiB).
pub const OUTPUT_CAP: usize = 1 << 20;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const KEEPALIVE_MAX: usize = 3;
const DISCONNECT_FLUSH: Duration = Duration::from_secs(1);
const CHANNEL_CLOSE_WAIT: Duration = Duration::from_millis(500);
const MAX_TCP_ATTEMPTS: usize = 2;
const KBD_INT_ROUNDS: usize = 6;
/// Private key files are a few KiB; refuse to read anything much larger.
const MAX_KEY_FILE: u64 = 1 << 20;
/// Stand-in deadline distance when `now + limit` overflows (`Duration::MAX` = "no limit");
/// the same 30 years tokio uses for its own far-future timers.
const FAR_FUTURE: Duration = Duration::from_secs(86_400 * 365 * 30);

/// Result of one remote command ([`Session::exec`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecOutput {
    /// Standard output, at most [`OUTPUT_CAP`] bytes.
    pub stdout: Vec<u8>,
    /// Standard error, at most [`OUTPUT_CAP`] bytes.
    pub stderr: Vec<u8>,
    /// More stdout arrived than [`OUTPUT_CAP`]; the rest was discarded.
    pub stdout_truncated: bool,
    /// More stderr arrived than [`OUTPUT_CAP`]; the rest was discarded.
    pub stderr_truncated: bool,
    /// Exit status, when the server sent one (optional in RFC 4254).
    pub exit_status: Option<u32>,
    /// Signal name (e.g. `"KILL"`) when the command was killed by a signal.
    pub exit_signal: Option<String>,
    /// The server confirmed the exec request (CHANNEL_SUCCESS).
    pub exec_accepted: bool,
    /// The channel closed (or the connection dropped) without exit status or signal. For a
    /// power command this proves nothing; see [`SshError::PowerUnconfirmed`].
    pub closed_early: bool,
}

impl ExecOutput {
    /// `exit_status == Some(0)`.
    pub fn success(&self) -> bool {
        self.exit_status == Some(0)
    }

    /// stdout as lossy UTF-8.
    pub fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// stderr as lossy UTF-8.
    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// How [`exec_async`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecEnd {
    /// The channel closed (or the connection dropped while the command ran).
    Closed,
    /// The time limit expired; the [`ExecOutput`] holds what had arrived until then.
    /// `exec_sent`: the exec request had been handed to the connection, so the command may be
    /// running (or have run) on the host.
    TimedOut {
        /// The exec request may have reached the host.
        exec_sent: bool,
    },
}

/// An authenticated SSH connection to one host.
///
/// Owns a private current-thread tokio runtime; every method blocks the calling thread and
/// nothing async leaks out. Keep sessions short-lived (one user action): keepalives and other
/// background protocol work only run while a method is executing. Dropping the session sends
/// SSH_MSG_DISCONNECT (waiting at most 1 s for it to be flushed).
///
/// Meant for plain worker threads. It also works inside a tokio runtime (an async task or a
/// `spawn_blocking` thread): there each call runs on a short-lived helper thread, because one
/// runtime cannot be driven from inside another. From an async task the call still blocks
/// that task's worker thread for its whole duration, so prefer `spawn_blocking` there.
/// `Session` is `Send`, so it may be created on one worker thread and used on another.
pub struct Session {
    rt: Option<Runtime>,
    handle: Option<client::Handle<Client>>,
    server_key: HostKeyInfo,
    sudo: SudoMode,
    sudo_password: Option<Zeroizing<String>>,
    command_timeout: Duration,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("server_key", &self.server_key.fingerprint_sha256)
            .field("sudo", &self.sudo)
            .field("open", &self.handle.is_some())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Resolve, connect, verify the host key against [`Target::host_key`] and authenticate.
    ///
    /// The key file (if any) is read and decrypted before any network activity.
    ///
    /// **Blocking**: at most [`Timeouts::connect_worst_case`] (`3 × connect + handshake`,
    /// 30 s with the defaults), plus the local key decryption (well under a second).
    ///
    /// # Errors
    /// [`SshError::InvalidInput`] (empty host/user, port 0, unparsable or unsupported pin),
    /// key-file errors, [`SshError::Resolve`] / [`SshError::Connect`] / [`SshError::Timeout`],
    /// [`SshError::Protocol`], host-key errors ([`SshError::UnknownHostKey`],
    /// [`SshError::HostKeyMismatch`], [`SshError::HostKeyTypeUnavailable`]) and authentication
    /// errors ([`SshError::NoCredentials`], [`SshError::AuthFailed`], [`SshError::AuthPartial`],
    /// [`SshError::AuthPromptUnsupported`]). The host key is verified before any credential
    /// is sent.
    pub fn connect(target: &Target) -> Result<Session> {
        off_runtime(|| Self::connect_here(target))?
    }

    /// [`Session::connect`] on the current thread (never inside a tokio runtime).
    fn connect_here(target: &Target) -> Result<Session> {
        let host = hostkey::strip_brackets(target.host.trim()).to_string();
        if host.is_empty() || host.contains(char::is_whitespace) {
            return Err(SshError::InvalidInput(format!(
                "invalid host {:?}",
                target.host
            )));
        }
        if target.user.trim().is_empty() {
            return Err(SshError::InvalidInput("the SSH user name is empty".into()));
        }
        if target.port == 0 {
            return Err(SshError::InvalidInput("the SSH port is 0".into()));
        }
        let pinned = match target
            .host_key
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(line) => {
                let p = hostkey::parse_pin(line)?;
                if !hostkey::is_supported_host_key_type(&p.algorithm()) {
                    return Err(SshError::InvalidInput(format!(
                        "the pinned host key type {} is not supported",
                        p.algorithm().as_str()
                    )));
                }
                Some(p)
            }
            None => None,
        };
        let key = match &target.auth.key_file {
            Some(path) => Some(load_key(path, target.auth.key_passphrase.as_ref())?),
            None => None,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| SshError::Internal(format!("cannot start the async runtime: {e}")))?;
        log::debug!(
            "ssh: connecting to {host}:{} as {}",
            target.port,
            target.user
        );
        match rt.block_on(connect_async(&host, target, pinned, key)) {
            Ok((handle, server_key)) => {
                log::debug!("ssh: connected to {host}:{}", target.port);
                Ok(Session {
                    rt: Some(rt),
                    handle: Some(handle),
                    server_key: hostkey::info_of(&server_key),
                    sudo: target.sudo,
                    sudo_password: target.effective_sudo_password().cloned(),
                    command_timeout: target.timeouts.command,
                })
            }
            Err(e) => {
                log::debug!("ssh: connecting to {host}:{} failed: {e}", target.port);
                rt.shutdown_background();
                Err(e)
            }
        }
    }

    /// The (verified) host key the server presented.
    pub fn server_host_key(&self) -> &HostKeyInfo {
        &self.server_key
    }

    /// Run `command` (parsed by the account's login shell; no PTY), write `stdin` (if any)
    /// followed by EOF, and collect stdout / stderr (each capped at [`OUTPUT_CAP`]) until the
    /// channel closes.
    ///
    /// A non-zero exit status is NOT an error here; inspect [`ExecOutput`].
    ///
    /// **Blocking**: at most `timeout` (+0.5 s to close the channel on timeout).
    /// [`Duration::MAX`] means no limit.
    ///
    /// # Errors
    /// [`SshError::Timeout`]`(Command)` (the channel is closed; output received until then is
    /// discarded), [`SshError::ExecRefused`], [`SshError::Disconnected`] (connection already
    /// lost or lost before the command could run). A connection lost *while* the command runs
    /// yields `Ok` with [`ExecOutput::closed_early`].
    pub fn exec(
        &mut self,
        command: &str,
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<ExecOutput> {
        match self.exec_collect(command, stdin, timeout)? {
            (out, ExecEnd::Closed) => Ok(out),
            (_, ExecEnd::TimedOut { .. }) => Err(SshError::Timeout(TimeoutStage::Command)),
        }
    }

    /// Like [`Session::exec`], but a timeout is not an error: the output received until then
    /// is returned with [`ExecEnd::TimedOut`] (the channel is closed).
    pub(crate) fn exec_collect(
        &mut self,
        command: &str,
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<(ExecOutput, ExecEnd)> {
        let (rt, handle) = self.parts()?;
        if handle.is_closed() {
            return Err(SshError::Disconnected("the connection is closed".into()));
        }
        off_runtime(|| rt.block_on(exec_async(handle, command, stdin, timeout)))?
    }

    /// Boot time of the host (read-only script; no privileges).
    ///
    /// **Blocking**: at most the command timeout ([`Timeouts::command`]).
    ///
    /// # Errors
    /// [`Session::exec`] errors; [`SshError::UnexpectedOutput`] when the login shell cannot run
    /// the script (nologin / appliance shell), no boot time is available, or the values are
    /// implausible (beyond 2^36 s, about the year 4147, or a boot time more than a day after
    /// the host's own clock).
    pub fn boot_time(&mut self) -> Result<BootInfo> {
        let out = self.run_readonly(&scripts::boot_script())?;
        boot::parse_boot(&out, SystemTime::now())
    }

    /// OS, user, root status and boot time (read-only script; no privileges). May take about a
    /// second longer on Proxmox VE (`pveversion`).
    ///
    /// **Blocking**: at most the command timeout ([`Timeouts::command`]).
    ///
    /// # Errors
    /// As [`Session::boot_time`].
    pub fn conn_info(&mut self) -> Result<ConnInfo> {
        let out = self.run_readonly(&scripts::info_script())?;
        info::parse_conn_info(&out, SystemTime::now())
    }

    /// Ranked physical NICs behind the default route (read-only script; no privileges; the WoL
    /// state is only available when the login user is root on Linux). May be empty.
    ///
    /// **Blocking**: at most the command timeout ([`Timeouts::command`]).
    ///
    /// # Errors
    /// As [`Session::boot_time`].
    pub fn mac_candidates(&mut self) -> Result<Vec<MacCandidate>> {
        let out = self.run_readonly(&scripts::net_script())?;
        Ok(net::select(&net::parse_net(&out)?))
    }

    /// Schedule a restart / shutdown as root, about 2 s later and detached from the SSH session
    /// (`systemd-run` transient timer, else `nohup [setsid|daemon -f] sh -c 'sleep 2; ...'`).
    /// Succeeds only when the host printed the `WOLM1 power ok` marker.
    ///
    /// Root is obtained per [`Target::sudo`]: a uid-0 login runs the script directly;
    /// otherwise `sudo -n`, and in [`SudoMode::Auto`] one `sudo -S` attempt with the password on
    /// stdin when sudo asks for one. A wrong password is never retried.
    ///
    /// **Blocking**: up to 3 commands (identity probe, `sudo -n`, `sudo -S`), each bounded by
    /// the command timeout ([`Timeouts::command`]).
    ///
    /// # Errors
    /// [`SshError::InvalidInput`] (overrides / interface name: checked before anything runs;
    /// a sudo password with a line break: checked before it would be sent),
    /// [`SshError::NotRoot`], [`SshError::SudoPasswordRequired`],
    /// [`SshError::SudoWrongPassword`], [`SshError::SudoNotAllowed`], [`SshError::SudoNeedsTty`],
    /// [`SshError::SudoMissing`], [`SshError::PowerUnconfirmed`] (no marker and no exit status,
    /// or the command timeout expired after the request was sent: verify by polling, do not
    /// retry blindly), [`SshError::CommandFailed`], and [`Session::exec`] errors. When the
    /// command timeout expires, the output received until then is still classified (a marker
    /// that arrived means success); [`SshError::Timeout`]`(Command)` only when the power
    /// request itself was never sent (nothing can have run).
    pub fn power(
        &mut self,
        action: PowerAction,
        overrides: &PowerOverrides,
    ) -> Result<PowerScheduled> {
        power::run_power(self, action, overrides)
    }

    /// Disconnect now (same as dropping the session).
    ///
    /// **Blocking**: at most 1 s.
    pub fn close(mut self) {
        self.shutdown();
    }

    pub(crate) fn sudo_mode(&self) -> SudoMode {
        self.sudo
    }

    pub(crate) fn sudo_password(&self) -> Option<&Zeroizing<String>> {
        self.sudo_password.as_ref()
    }

    pub(crate) fn command_timeout(&self) -> Duration {
        self.command_timeout
    }

    /// uid of the login user (`None` when `id -u` printed nothing usable).
    pub(crate) fn remote_uid(&mut self) -> Result<Option<u32>> {
        let out = self.run_readonly(&scripts::id_script())?;
        let mut saw = false;
        let mut uid = None;
        for l in marker_lines(&out) {
            if let Some(v) = l.strip_prefix("uid") {
                saw = true;
                uid = v.trim().parse().ok();
            }
        }
        if !saw {
            return Err(SshError::UnexpectedOutput(no_marker_hint("identity", &out)));
        }
        Ok(uid)
    }

    /// Run a read-only script via `sh -s`; returns stdout (lossy UTF-8).
    fn run_readonly(&mut self, script: &str) -> Result<String> {
        let timeout = self.command_timeout;
        let out = self.exec(READONLY_COMMAND, Some(script.as_bytes()), timeout)?;
        let stdout = out.stdout_lossy();
        if !stdout.lines().any(|l| l.starts_with(MARKER)) {
            let stderr = sanitize(&out.stderr_lossy(), 160);
            let shown = if stderr.is_empty() {
                sanitize(&stdout, 160)
            } else {
                stderr
            };
            return Err(SshError::UnexpectedOutput(format!(
                "the remote shell did not run the script (exit status {:?}{}); the account's login \
                 shell must be able to run `sh -s` (not nologin or an appliance CLI){}",
                out.exit_status,
                if out.closed_early {
                    ", closed early"
                } else {
                    ""
                },
                if shown.is_empty() {
                    String::new()
                } else {
                    format!(": {shown:?}")
                }
            )));
        }
        Ok(stdout)
    }

    fn parts(&self) -> Result<(&Runtime, &client::Handle<Client>)> {
        match (&self.rt, &self.handle) {
            (Some(rt), Some(h)) => Ok((rt, h)),
            _ => Err(SshError::Disconnected("the session is closed".into())),
        }
    }

    fn shutdown(&mut self) {
        if let (Some(rt), Some(h)) = (self.rt.as_ref(), self.handle.take()) {
            // Only fails when no helper thread can be started; then DISCONNECT is skipped
            // (the TCP connection still closes below).
            if let Err(e) = off_runtime(|| rt.block_on(disconnect(h))) {
                log::debug!("ssh: could not send DISCONNECT: {e}");
            }
        }
        if let Some(rt) = self.rt.take() {
            // Allowed inside an async context too (unlike dropping the runtime).
            rt.shutdown_background();
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Connect without credentials to read the server's host key (like `ssh-keyscan`); nothing is
/// authenticated and no credential is sent. Uses russh's default host-key preference
/// (ed25519 first).
///
/// **Blocking**: at most [`Timeouts::connect_worst_case`].
///
/// # Errors
/// Network / protocol errors as [`Session::connect`].
pub fn scan_host_key(host: &str, port: u16, timeouts: Timeouts) -> Result<HostKeyInfo> {
    let mut t = Target::new(host, "wol-manager-keyscan");
    t.port = port;
    t.timeouts = timeouts;
    match Session::connect(&t) {
        Err(SshError::UnknownHostKey {
            openssh_line,
            fingerprint_sha256,
        }) => Ok(HostKeyInfo {
            algorithm: openssh_line
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string(),
            fingerprint_sha256,
            openssh_line,
        }),
        Err(e) => Err(e),
        Ok(s) => Ok(s.server_host_key().clone()),
    }
}

/// Run `f`, which drives a private runtime with `block_on`, on a thread where that is allowed:
/// the current thread normally; a short-lived scoped helper thread when the current thread is
/// inside a tokio runtime (an async task, where `block_on` would panic, or a `spawn_blocking`
/// thread, where tokio does not tell the two apart). A panic in `f` propagates unchanged.
///
/// # Errors
/// [`SshError::Internal`] when the helper thread cannot be started.
fn off_runtime<T: Send>(f: impl FnOnce() -> T + Send) -> Result<T> {
    if tokio::runtime::Handle::try_current().is_err() {
        return Ok(f());
    }
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("wol-ssh".into())
            .spawn_scoped(scope, f)
            .map_err(|e| SshError::Internal(format!("cannot start a helper thread: {e}")))?;
        match worker.join() {
            Ok(v) => Ok(v),
            Err(panic) => std::panic::resume_unwind(panic),
        }
    })
}

/// `now + limit`; about 30 years from now when that overflows ([`Duration::MAX`] = no limit).
fn deadline_after(limit: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(limit).unwrap_or_else(|| now + FAR_FUTURE)
}

// ---------------------------------------------------------------- russh handler

pub(crate) struct Client {
    pinned: Option<PublicKey>,
    seen: Arc<Mutex<Option<PublicKey>>>,
}

#[derive(Debug)]
pub(crate) enum ClientError {
    Russh(russh::Error),
    Verdict(SshError),
}

impl From<russh::Error> for ClientError {
    fn from(e: russh::Error) -> Self {
        ClientError::Russh(e)
    }
}

impl client::Handler for Client {
    type Error = ClientError;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, ClientError> {
        let key = match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key,
            _ => {
                return Err(ClientError::Verdict(SshError::Protocol(
                    "the server presented a host certificate, which this client does not request"
                        .into(),
                )));
            }
        };
        if let Ok(mut seen) = self.seen.lock() {
            *seen = Some(key.clone());
        }
        hostkey::verify(self.pinned.as_ref(), key).map_err(ClientError::Verdict)?;
        Ok(true)
    }
}

fn map_client_error(e: ClientError, pinned: Option<&PublicKey>) -> SshError {
    match e {
        ClientError::Verdict(v) => v,
        ClientError::Russh(russh::Error::NoCommonAlgo {
            kind: AlgorithmKind::Key,
            ours,
            theirs,
        }) => match pinned {
            Some(p) => SshError::HostKeyTypeUnavailable {
                expected_fp: hostkey::fingerprint(p),
                key_type: p.algorithm().as_str().to_string(),
            },
            None => SshError::Protocol(format!(
                "no common host key algorithm (ours: {}, theirs: {})",
                ours.join(","),
                theirs.join(",")
            )),
        },
        ClientError::Russh(e) => from_russh(e),
    }
}

fn client_config(pinned: Option<&PublicKey>) -> client::Config {
    let mut preferred = Preferred::default();
    if let Some(p) = pinned {
        // Negotiate only the pinned key type, so a server that also has RSA / ECDSA keys never
        // looks "changed".
        let alg = p.algorithm();
        preferred.key = Cow::Owned(
            Preferred::DEFAULT
                .key
                .iter()
                .filter(|a| hostkey::same_key_type(a, &alg))
                .cloned()
                .collect(),
        );
    }
    client::Config {
        preferred,
        keepalive_interval: Some(KEEPALIVE_INTERVAL),
        keepalive_max: KEEPALIVE_MAX,
        inactivity_timeout: None,
        nodelay: true,
        ..Default::default()
    }
}

// ---------------------------------------------------------------- connect

async fn connect_async(
    host: &str,
    t: &Target,
    pinned: Option<PublicKey>,
    key: Option<PrivateKey>,
) -> Result<(client::Handle<Client>, PublicKey)> {
    let tcp = tcp_connect(host, t.port, t.timeouts.connect).await?;
    let config = Arc::new(client_config(pinned.as_ref()));
    let seen = Arc::new(Mutex::new(None));
    let handler = Client {
        pinned: pinned.clone(),
        seen: Arc::clone(&seen),
    };
    let deadline = deadline_after(t.timeouts.handshake);
    let mut handle = match timeout_at(deadline, client::connect_stream(config, tcp, handler)).await
    {
        Err(_) => return Err(SshError::Timeout(TimeoutStage::Handshake)),
        Ok(Err(e)) => return Err(map_client_error(e, pinned.as_ref())),
        Ok(Ok(h)) => h,
    };
    let server_key = seen
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .ok_or_else(|| SshError::Internal("the host key was not verified".into()));
    let result = match server_key {
        Ok(server_key) => match timeout_at(deadline, authenticate(&mut handle, t, key)).await {
            Err(_) => Err(SshError::Timeout(TimeoutStage::Authentication)),
            Ok(Err(e)) => Err(e),
            Ok(Ok(())) => Ok(server_key),
        },
        Err(e) => Err(e),
    };
    match result {
        Ok(k) => Ok((handle, k)),
        Err(e) => {
            disconnect(handle).await;
            Err(e)
        }
    }
}

/// IPv4 addresses first (the app is IPv4-centric; an unreachable AAAA must not eat the
/// budget); at most [`MAX_TCP_ATTEMPTS`] attempts of `limit` each.
async fn tcp_connect(host: &str, port: u16, limit: Duration) -> Result<TcpStream> {
    let mut addrs: Vec<SocketAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => match timeout(limit, tokio::net::lookup_host((host, port))).await {
            Err(_) => return Err(SshError::Timeout(TimeoutStage::Resolve)),
            Ok(Err(e)) => {
                return Err(SshError::Resolve {
                    host: host.to_string(),
                    message: e.to_string(),
                });
            }
            Ok(Ok(it)) => it.collect(),
        },
    };
    addrs.sort_by_key(SocketAddr::is_ipv6);
    addrs.dedup();
    let mut last = SshError::Resolve {
        host: host.to_string(),
        message: "no addresses".into(),
    };
    for addr in addrs.iter().take(MAX_TCP_ATTEMPTS) {
        match timeout(limit, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Ok(Err(e)) => {
                last = SshError::Connect {
                    addr: addr.to_string(),
                    message: e.to_string(),
                }
            }
            Err(_) => last = SshError::Timeout(TimeoutStage::Connect),
        }
    }
    Err(last)
}

async fn disconnect(h: client::Handle<Client>) {
    let _ = h.disconnect(Disconnect::ByApplication, "", "en").await;
    // Awaiting the handle lets the DISCONNECT message be flushed before the runtime goes away.
    let _ = timeout(DISCONNECT_FLUSH, h).await;
}

// ---------------------------------------------------------------- authentication

fn load_key(path: &Path, passphrase: Option<&Zeroizing<String>>) -> Result<PrivateKey> {
    let file_err = |message: String| SshError::KeyFile {
        path: path.to_path_buf(),
        message,
    };
    let len = std::fs::metadata(path)
        .map_err(|e| file_err(e.to_string()))?
        .len();
    if len > MAX_KEY_FILE {
        return Err(file_err(format!(
            "the file is too large for a private key ({len} bytes)"
        )));
    }
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|e| file_err(e.to_string()))?);
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| file_err("not a text (OpenSSH / PEM / PuTTY) key file".into()))?;
    let passphrase = passphrase.map(|p| p.as_str()).filter(|p| !p.is_empty());
    match keys::decode_secret_key(text, passphrase) {
        Ok(k) => Ok(k),
        Err(keys::Error::KeyIsEncrypted) => Err(SshError::KeyPassphraseRequired {
            path: path.to_path_buf(),
        }),
        Err(_) if passphrase.is_some() => Err(SshError::KeyPassphraseWrong {
            path: path.to_path_buf(),
        }),
        Err(e) => {
            let looks_public = text.trim_start().starts_with("ssh-")
                || text.trim_start().starts_with("ecdsa-")
                || path
                    .extension()
                    .is_some_and(|x| x.eq_ignore_ascii_case("pub"));
            Err(file_err(if looks_public {
                "this is a public key; select the private key file (without .pub)".into()
            } else {
                format!(
                    "unsupported or invalid private key ({e}); if it is passphrase-protected, set the \
                     passphrase, or convert it with `ssh-keygen -p -f <key>`"
                )
            }))
        }
    }
}

fn method_names(m: &[MethodKind]) -> Vec<String> {
    m.iter().map(|k| <&str>::from(k).to_string()).collect()
}

async fn authenticate(
    h: &mut client::Handle<Client>,
    t: &Target,
    key: Option<PrivateKey>,
) -> Result<()> {
    let user = t.user.trim();
    let password = t.auth.password.as_ref();
    if key.is_none() && password.is_none() {
        return Err(SshError::NoCredentials);
    }
    // Learn the method list with "none", like OpenSSH does.
    let mut methods: Vec<MethodKind> = match h.authenticate_none(user).await.map_err(from_russh)? {
        AuthResult::Success => return Ok(()),
        AuthResult::Failure {
            remaining_methods, ..
        } => remaining_methods.to_vec(),
    };
    let offers = |m: &[MethodKind], k: MethodKind| m.is_empty() || m.contains(&k);
    let mut partial = false;

    if let Some(key) = key
        && offers(&methods, MethodKind::PublicKey)
    {
        // Ask for an RSA signature hash only for RSA keys; a server without server-sig-algs
        // must not fall back to SHA-1 (refused by OpenSSH >= 8.8).
        let hash = if key.algorithm().is_rsa() {
            h.best_supported_rsa_hash()
                .await
                .map_err(from_russh)?
                .unwrap_or(Some(HashAlg::Sha256))
        } else {
            None
        };
        match h
            .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
            .await
            .map_err(from_russh)?
        {
            AuthResult::Success => return Ok(()),
            AuthResult::Failure {
                remaining_methods,
                partial_success,
            } => {
                partial |= partial_success;
                methods = remaining_methods.to_vec();
            }
        }
    }

    if let Some(pw) = password {
        if offers(&methods, MethodKind::Password) {
            match h
                .authenticate_password(user, pw.as_str())
                .await
                .map_err(from_russh)?
            {
                AuthResult::Success => return Ok(()),
                AuthResult::Failure {
                    remaining_methods,
                    partial_success,
                } => {
                    // Do not repeat the same (wrong) password via keyboard-interactive: every
                    // attempt counts towards pam_faillock / MaxAuthTries.
                    return Err(auth_failure(partial || partial_success, &remaining_methods));
                }
            }
        } else if methods.contains(&MethodKind::KeyboardInteractive) {
            return keyboard_interactive(h, user, pw, partial).await;
        }
    }
    Err(if partial {
        SshError::AuthPartial {
            remaining_methods: method_names(&methods),
        }
    } else {
        SshError::AuthFailed {
            server_methods: method_names(&methods),
        }
    })
}

fn auth_failure(partial: bool, remaining: &MethodSet) -> SshError {
    if partial {
        SshError::AuthPartial {
            remaining_methods: method_names(remaining),
        }
    } else {
        SshError::AuthFailed {
            server_methods: method_names(remaining),
        }
    }
}

/// Whole words (ASCII case-insensitive) that mark a keyboard-interactive prompt as a second
/// factor rather than the account password; "one time" / "one-time" is matched as a pair.
const SECOND_FACTOR_WORDS: &[&str] = &[
    "code",
    "otp",
    "totp",
    "token",
    "verification",
    "authenticator",
    "passcode",
    "duo",
    "yubikey",
];

/// Lower-case ASCII-alphanumeric words of `s`.
fn words(s: &str) -> impl Iterator<Item = String> + '_ {
    s.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_ascii_lowercase)
}

/// `true` when a keyboard-interactive prompt asks for a one-time code (never answered with the
/// password). User and host names are not part of the question: `user@host` tokens (OpenPAM's
/// remote prompt `Password for %u@%h:` on FreeBSD / TrueNAS CORE, `(user@host)` prefixes) and
/// the login user's name are skipped, and only whole words count, so
/// `Password for root@vscode-nas:` or a user called `token` is still a password prompt.
fn looks_like_second_factor(prompt: &str, user: &str) -> bool {
    let user_words: Vec<String> = words(user).collect();
    let w: Vec<String> = prompt
        .split_whitespace()
        .filter(|t| !t.contains('@'))
        .flat_map(words)
        .filter(|w| !user_words.contains(w))
        .collect();
    w.iter().any(|w| SECOND_FACTOR_WORDS.contains(&w.as_str()))
        || w.windows(2).any(|p| p[0] == "one" && p[1] == "time")
}

/// Answer exactly one hidden, password-like prompt with the password; anything else (OTP,
/// several prompts, a second password round) is reported, not guessed.
async fn keyboard_interactive(
    h: &mut client::Handle<Client>,
    user: &str,
    pw: &Zeroizing<String>,
    partial: bool,
) -> Result<()> {
    let mut reply = h
        .authenticate_keyboard_interactive_start(user, None)
        .await
        .map_err(from_russh)?;
    let mut answered = false;
    for _ in 0..KBD_INT_ROUNDS {
        match reply {
            KeyboardInteractiveAuthResponse::Success => return Ok(()),
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            } => {
                return Err(auth_failure(partial || partial_success, &remaining_methods));
            }
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let answers = if prompts.is_empty() {
                    Vec::new()
                } else if !answered
                    && prompts.len() == 1
                    && !prompts[0].echo
                    && !looks_like_second_factor(&prompts[0].prompt, user)
                {
                    answered = true;
                    // russh takes the answers as plain `String`s (not zeroized); see the
                    // crate docs, "Secrets".
                    vec![pw.to_string()]
                } else {
                    let prompt = prompts
                        .iter()
                        .map(|p| p.prompt.as_str())
                        .collect::<Vec<_>>()
                        .join(" / ");
                    return Err(SshError::AuthPromptUnsupported {
                        prompt: sanitize(&prompt, 120),
                    });
                };
                reply = h
                    .authenticate_keyboard_interactive_respond(answers)
                    .await
                    .map_err(from_russh)?;
            }
        }
    }
    Err(SshError::AuthPromptUnsupported {
        prompt: "(too many keyboard-interactive rounds)".into(),
    })
}

// ---------------------------------------------------------------- exec

/// Open a session channel, run `command`, collect its output until CHANNEL_CLOSE or the
/// deadline. On timeout the partial output is returned with [`ExecEnd::TimedOut`].
async fn exec_async(
    h: &client::Handle<Client>,
    command: &str,
    stdin: Option<&[u8]>,
    limit: Duration,
) -> Result<(ExecOutput, ExecEnd)> {
    let deadline = deadline_after(limit);
    let mut ch = match timeout_at(deadline, h.channel_open_session()).await {
        Err(_) => {
            return Ok((
                ExecOutput::default(),
                ExecEnd::TimedOut { exec_sent: false },
            ));
        }
        Ok(Err(e)) => return Err(from_russh(e)),
        Ok(Ok(ch)) => ch,
    };
    let mut out = ExecOutput::default();
    let mut exec_sent = false;
    let result = timeout_at(
        deadline,
        drive(&mut ch, &mut out, &mut exec_sent, command, stdin),
    )
    .await;
    match result {
        Ok(Ok(())) => {
            out.closed_early = out.exit_status.is_none() && out.exit_signal.is_none();
            Ok((out, ExecEnd::Closed))
        }
        Ok(Err(e)) => {
            let _ = timeout(CHANNEL_CLOSE_WAIT, ch.close()).await;
            Err(e)
        }
        Err(_) => {
            let _ = timeout(CHANNEL_CLOSE_WAIT, ch.close()).await;
            Ok((out, ExecEnd::TimedOut { exec_sent }))
        }
    }
}

async fn drive(
    ch: &mut Channel<client::Msg>,
    out: &mut ExecOutput,
    exec_sent: &mut bool,
    command: &str,
    stdin: Option<&[u8]>,
) -> Result<()> {
    // Set before sending: if the deadline cancels the send half-way, the request may still
    // have reached the host.
    *exec_sent = true;
    // No PTY on purpose: separate stdout/stderr, no echo, sudo reads stdin (-S).
    ch.exec(true, command).await.map_err(from_russh)?;
    // From here on the command may already be running: a failure to deliver stdin / EOF (the
    // command exited early, the link died) is not an error of its own; the outcome is decided
    // by what arrives below (or by `closed_early`).
    //
    // `data_bytes` hands one owned copy to russh; `data` would also pass it through tokio's
    // 8 KiB copy buffer. Neither copy (nor russh's packet buffers) is zeroized: see the crate
    // docs, "Secrets" (stdin may carry the sudo password).
    if let Some(input) = stdin.filter(|s| !s.is_empty())
        && let Err(e) = ch.data_bytes(input.to_vec()).await
    {
        log::debug!("ssh: could not deliver stdin: {e}");
    }
    if let Err(e) = ch.eof().await {
        log::debug!("ssh: could not send EOF: {e}");
    }
    // Wait for CLOSE, not EOF: exit-status may arrive after EOF.
    while let Some(msg) = ch.wait().await {
        match msg {
            ChannelMsg::Data { data } => {
                push_capped(&mut out.stdout, &mut out.stdout_truncated, &data)
            }
            ChannelMsg::ExtendedData { data, ext: 1 } => {
                push_capped(&mut out.stderr, &mut out.stderr_truncated, &data)
            }
            ChannelMsg::ExitStatus { exit_status } => out.exit_status = Some(exit_status),
            ChannelMsg::ExitSignal { signal_name, .. } => {
                out.exit_signal = Some(signal_text(&signal_name))
            }
            ChannelMsg::Success => out.exec_accepted = true,
            ChannelMsg::Failure => return Err(SshError::ExecRefused),
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    Ok(())
}

fn push_capped(buf: &mut Vec<u8>, truncated: &mut bool, data: &[u8]) {
    let room = OUTPUT_CAP.saturating_sub(buf.len());
    if data.len() > room {
        *truncated = true;
    }
    buf.extend_from_slice(&data[..data.len().min(room)]);
}

fn signal_text(sig: &Sig) -> String {
    match sig {
        Sig::Custom(s) => sanitize(s, 32),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_is_send() {
        fn send<T: Send>() {}
        send::<Session>();
        send::<Target>();
    }

    #[test]
    fn capped_output() {
        let mut buf = Vec::new();
        let mut t = false;
        push_capped(&mut buf, &mut t, &vec![1u8; OUTPUT_CAP - 1]);
        assert!(!t);
        push_capped(&mut buf, &mut t, &[2, 3]);
        assert!(t);
        assert_eq!(buf.len(), OUTPUT_CAP);
        assert_eq!(buf[OUTPUT_CAP - 1], 2);
    }

    #[test]
    fn signal_names() {
        assert_eq!(signal_text(&Sig::KILL), "KILL");
        assert_eq!(signal_text(&Sig::Custom("XCPU".into())), "XCPU");
    }

    #[test]
    fn second_factor_prompts() {
        for (prompt, user) in [
            ("Password: ", "alice"),
            ("alice@nas's password:", "alice"),
            // OpenPAM's remote prompt (FreeBSD / TrueNAS CORE): user and host are not words
            // of the question (review probe r6).
            ("Password for root@vscode-nas:", "root"),
            ("Password for admin@barcode-server.lan:", "admin"),
            ("Password for token@nas:", "token"),
            ("Password for root@duo:", "root"),
            ("Password for root@codebox:", "root"),
            ("(alice@otp-gw) Password:", "alice"),
            // The login user's own name, even without a host.
            ("Password for token:", "token"),
            ("token's password: ", "token"),
            // Substrings of words do not count.
            ("Passwort für codeberg:", "alice"),
        ] {
            assert!(
                !looks_like_second_factor(prompt, user),
                "{prompt:?} as {user}"
            );
        }
        for prompt in [
            "Verification code: ",
            "Enter OTP:",
            "Enter your one-time password:",
            "One-time password (OATH) for `alice': ",
            "one time code",
            "Duo two-factor login for alice\n\nEnter a passcode or select one of the following options:",
            "Enter PASSCODE: ",
            "YubiKey for `alice': ",
            "Token code:",
            "TOTP: ",
            "Password for root@nas (authenticator app):",
        ] {
            assert!(looks_like_second_factor(prompt, "alice"), "{prompt:?}");
        }
    }

    #[test]
    fn deadlines_never_overflow() {
        let far = deadline_after(Duration::MAX);
        assert!(far > Instant::now() + Duration::from_secs(86_400 * 365));
        let near = deadline_after(Duration::from_secs(1));
        assert!(near <= Instant::now() + Duration::from_secs(1));
    }

    #[test]
    fn pinned_type_restricts_negotiation() {
        use russh::keys::ssh_key::private::Ed25519Keypair;
        let k = PrivateKey::from(Ed25519Keypair::from_seed(&[9; 32]))
            .public_key()
            .clone();
        let c = client_config(Some(&k));
        assert_eq!(c.preferred.key.as_ref(), &[russh::keys::Algorithm::Ed25519]);
        let c = client_config(None);
        assert!(c.preferred.key.len() > 1);
        assert_eq!(c.keepalive_interval, Some(KEEPALIVE_INTERVAL));
    }

    #[test]
    fn key_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        assert!(matches!(
            load_key(&missing, None),
            Err(SshError::KeyFile { .. })
        ));
        let public = dir.path().join("id_ed25519.pub");
        std::fs::write(
            &public,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ x\n",
        )
        .unwrap();
        match load_key(&public, None) {
            Err(SshError::KeyFile { message, .. }) => {
                assert!(message.contains("public key"), "{message}")
            }
            other => panic!("{other:?}"),
        }
        let huge = dir.path().join("huge");
        std::fs::write(&huge, vec![b'a'; (MAX_KEY_FILE + 1) as usize]).unwrap();
        match load_key(&huge, None) {
            Err(SshError::KeyFile { message, .. }) => {
                assert!(message.contains("too large"), "{message}")
            }
            other => panic!("{other:?}"),
        }
        let garbage = dir.path().join("garbage");
        std::fs::write(&garbage, "hello").unwrap();
        assert!(matches!(
            load_key(&garbage, None),
            Err(SshError::KeyFile { .. })
        ));
        assert!(matches!(
            load_key(&garbage, Some(&Zeroizing::new("pw".into()))),
            Err(SshError::KeyPassphraseWrong { .. })
        ));
    }

    #[test]
    fn off_runtime_works_everywhere() {
        // Plain thread: runs in place.
        let here = std::thread::current().id();
        assert_eq!(off_runtime(|| std::thread::current().id()).unwrap(), here);
        // Inside an async task: a helper thread, no panic, no refusal.
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let (id, v) = rt.block_on(async {
            off_runtime(|| {
                let inner = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap();
                (std::thread::current().id(), inner.block_on(async { 42 }))
            })
            .unwrap()
        });
        assert_ne!(id, here);
        assert_eq!(v, 42);
        // Validation errors come back as such inside a runtime (not `Internal`).
        let mut t = Target::new("127.0.0.1", "u");
        t.port = 0;
        let r = rt.block_on(async { Session::connect(&t).map(|_| ()) });
        assert!(matches!(r, Err(SshError::InvalidInput(_))), "{r:?}");
    }

    #[test]
    fn off_runtime_propagates_panics() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.block_on(async { off_runtime::<()>(|| panic!("boom")) })
        }));
        assert!(r.is_err());
    }
}
