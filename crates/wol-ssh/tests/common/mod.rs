//! In-process russh SSH server on 127.0.0.1 for the wol-ssh integration tests.
//!
//! No network access beyond loopback. The host key is generated at runtime. Users can
//! authenticate by password, public key or keyboard-interactive; `exec` requests are answered by
//! a test-supplied [`Behavior`] (see [`FakeHost`] for an emulation of the WoL Manager scripts and
//! of sudo).
#![allow(dead_code)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::hash::{BuildHasher, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::ssh_key::LineEnding;
use russh::keys::ssh_key::private::{EcdsaKeypair, Ed25519Keypair, RsaKeypair};
use russh::keys::ssh_key::rand_core::{TryCryptoRng, TryRng};
use russh::keys::{EcdsaCurve, PrivateKey, PublicKey};
use russh::server::{self, Auth, Msg, Response, Server as _, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Sig};
use wol_ssh::{Target, Timeouts};

// ---------------------------------------------------------------- keys

/// Non-cryptographic RNG (splitmix64 seeded from the OS-randomized std hasher) — test keys only.
pub struct TestRng(u64);

impl TestRng {
    pub fn new() -> Self {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        );
        TestRng(h.finish())
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl TryRng for TestRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.next() as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self.next())
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}

pub fn random_ed25519() -> PrivateKey {
    let mut seed = [0u8; 32];
    TestRng::new().try_fill_bytes(&mut seed).unwrap();
    PrivateKey::from(Ed25519Keypair::from_seed(&seed))
}

pub fn random_ecdsa_p256() -> PrivateKey {
    PrivateKey::from(EcdsaKeypair::random(&mut TestRng::new(), EcdsaCurve::NistP256).unwrap())
}

pub fn random_rsa_2048() -> PrivateKey {
    PrivateKey::from(RsaKeypair::random(&mut TestRng::new(), 2048).unwrap())
}

/// Write `key` as an OpenSSH private key file (optionally encrypted) into `dir`.
pub fn write_key(dir: &Path, name: &str, key: &PrivateKey, passphrase: Option<&str>) -> PathBuf {
    let key = match passphrase {
        Some(p) => key.encrypt(&mut TestRng::new(), p).unwrap(),
        None => key.clone(),
    };
    let path = dir.join(name);
    std::fs::write(&path, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
    path
}

pub fn openssh_line(key: &PublicKey) -> String {
    key.to_openssh().unwrap()
}

// ---------------------------------------------------------------- server

#[derive(Clone, Default)]
pub struct User {
    pub name: String,
    pub password: Option<String>,
    pub key: Option<PublicKey>,
    /// keyboard-interactive: (prompt, expected answer)
    pub kbd: Option<(String, String)>,
    /// The correct keyboard-interactive answer is accepted with partial success; a public key is
    /// still required. (russh's server drops `partial_success` on the `password` path, so the
    /// emulation uses keyboard-interactive.)
    pub partial: bool,
}

impl User {
    pub fn password(name: &str, pw: &str) -> Self {
        User {
            name: name.into(),
            password: Some(pw.into()),
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug)]
pub struct Exec {
    pub user: String,
    pub command: String,
    pub stdin: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// Output, exit status / signal, EOF, CLOSE.
    #[default]
    Normal,
    /// Output, then CLOSE without exit status (sshd killed by reboot).
    CloseEarly,
    /// Drop the whole connection.
    DropConnection,
    /// Never answer.
    Hang,
    /// Output, exit status / signal, EOF, but no CLOSE (a VPN tunnel that went down before
    /// sshd while the host shuts down).
    NoClose,
}

#[derive(Clone, Debug, Default)]
pub struct Reply {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit: Option<u32>,
    pub signal: Option<Sig>,
    pub mode: Mode,
}

impl Reply {
    pub fn ok(stdout: impl Into<String>) -> Self {
        Reply {
            stdout: stdout.into().into_bytes(),
            exit: Some(0),
            ..Default::default()
        }
    }
    pub fn fail(stderr: impl Into<String>, exit: u32) -> Self {
        Reply {
            stderr: stderr.into().into_bytes(),
            exit: Some(exit),
            ..Default::default()
        }
    }
}

pub type Behavior = Arc<dyn Fn(&Exec) -> Reply + Send + Sync>;

pub struct ServerSpec {
    pub users: Vec<User>,
    pub methods: Vec<MethodKind>,
    pub behavior: Behavior,
    pub host_key: Option<PrivateKey>,
}

impl ServerSpec {
    pub fn new(users: Vec<User>, behavior: Behavior) -> Self {
        ServerSpec {
            users,
            methods: vec![
                MethodKind::PublicKey,
                MethodKind::Password,
                MethodKind::KeyboardInteractive,
            ],
            behavior,
            host_key: None,
        }
    }
}

struct Inner {
    users: Vec<User>,
    methods: MethodSet,
    behavior: Behavior,
    log: Arc<Mutex<Vec<Exec>>>,
    auth_attempts: Arc<AtomicUsize>,
    password_attempts: Arc<AtomicUsize>,
}

#[derive(Clone)]
struct Srv {
    inner: Arc<Inner>,
    user: String,
    cmds: HashMap<ChannelId, String>,
    stdin: HashMap<ChannelId, Vec<u8>>,
}

impl Srv {
    fn find(&self, name: &str) -> Option<&User> {
        self.inner.users.iter().find(|u| u.name == name)
    }
    fn reject(&self) -> Auth {
        Auth::Reject {
            proceed_with_methods: Some(self.inner.methods.clone()),
            partial_success: false,
        }
    }
    fn offers(&self, m: MethodKind) -> bool {
        self.inner.methods.contains(&m)
    }
}

impl server::Server for Srv {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        self.clone()
    }
}

impl server::Handler for Srv {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.inner.auth_attempts.fetch_add(1, Ordering::SeqCst);
        self.inner.password_attempts.fetch_add(1, Ordering::SeqCst);
        if !self.offers(MethodKind::Password) {
            return Ok(self.reject());
        }
        let found = self.find(user).cloned();
        if let Some(u) = found
            && u.password.as_deref() == Some(password)
        {
            self.user = user.to_string();
            return Ok(Auth::Accept);
        }
        Ok(self.reject())
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        self.inner.auth_attempts.fetch_add(1, Ordering::SeqCst);
        let ok = self.offers(MethodKind::PublicKey)
            && self
                .find(user)
                .and_then(|u| u.key.as_ref())
                .is_some_and(|k| k.key_data() == key.key_data());
        if ok {
            self.user = user.to_string();
            Ok(Auth::Accept)
        } else {
            Ok(self.reject())
        }
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        self.inner.auth_attempts.fetch_add(1, Ordering::SeqCst);
        let Some((prompt, answer)) = self.find(user).and_then(|u| u.kbd.clone()) else {
            return Ok(self.reject());
        };
        if !self.offers(MethodKind::KeyboardInteractive) {
            return Ok(self.reject());
        }
        match response {
            None => Ok(Auth::Partial {
                name: "".into(),
                instructions: "".into(),
                prompts: vec![(prompt.into(), false)].into(),
            }),
            Some(mut r) => {
                let ok = r.next().is_some_and(|b| &b[..] == answer.as_bytes());
                if ok {
                    if self.find(user).is_some_and(|u| u.partial) {
                        return Ok(Auth::Reject {
                            proceed_with_methods: Some(MethodSet::from(
                                &[MethodKind::PublicKey][..],
                            )),
                            partial_success: true,
                        });
                    }
                    self.user = user.to_string();
                    Ok(Auth::Accept)
                } else {
                    Ok(self.reject())
                }
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        ch: ChannelId,
        data: &[u8],
        s: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data).to_string();
        match cmd.as_str() {
            "REFUSE" => {
                s.channel_failure(ch)?;
                return Ok(());
            }
            "DROP" => return Err(russh::Error::Disconnect),
            _ => {}
        }
        s.channel_success(ch)?;
        self.cmds.insert(ch, cmd);
        Ok(())
    }

    async fn data(
        &mut self,
        ch: ChannelId,
        data: &[u8],
        _s: &mut Session,
    ) -> Result<(), Self::Error> {
        self.stdin.entry(ch).or_default().extend_from_slice(data);
        Ok(())
    }

    async fn channel_eof(&mut self, ch: ChannelId, s: &mut Session) -> Result<(), Self::Error> {
        let Some(command) = self.cmds.remove(&ch) else {
            return Ok(());
        };
        let exec = Exec {
            user: self.user.clone(),
            command,
            stdin: self.stdin.remove(&ch).unwrap_or_default(),
        };
        self.inner.log.lock().unwrap().push(exec.clone());
        let reply = (self.inner.behavior)(&exec);
        match reply.mode {
            Mode::Hang => {}
            Mode::DropConnection => return Err(russh::Error::Disconnect),
            Mode::CloseEarly => {
                if !reply.stdout.is_empty() {
                    s.data(ch, reply.stdout)?;
                }
                if !reply.stderr.is_empty() {
                    s.extended_data(ch, 1, reply.stderr)?;
                }
                s.close(ch)?;
            }
            Mode::Normal | Mode::NoClose => {
                if !reply.stdout.is_empty() {
                    s.data(ch, reply.stdout)?;
                }
                if !reply.stderr.is_empty() {
                    s.extended_data(ch, 1, reply.stderr)?;
                }
                if let Some(sig) = reply.signal {
                    s.exit_signal_request(ch, sig, false, "killed", "en")?;
                }
                if let Some(code) = reply.exit {
                    s.exit_status_request(ch, code)?;
                }
                s.eof(ch)?;
                if reply.mode == Mode::Normal {
                    s.close(ch)?;
                }
            }
        }
        Ok(())
    }
}

pub struct TestServer {
    pub port: u16,
    pub host_key: PublicKey,
    log: Arc<Mutex<Vec<Exec>>>,
    auth_attempts: Arc<AtomicUsize>,
    password_attempts: Arc<AtomicUsize>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    pub fn start(spec: ServerSpec) -> TestServer {
        let host_key = spec.host_key.unwrap_or_else(random_ed25519);
        let public = host_key.public_key().clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let log = Arc::new(Mutex::new(Vec::new()));
        let auth_attempts = Arc::new(AtomicUsize::new(0));
        let password_attempts = Arc::new(AtomicUsize::new(0));
        let inner = Arc::new(Inner {
            users: spec.users,
            methods: MethodSet::from(&spec.methods[..]),
            behavior: spec.behavior,
            log: Arc::clone(&log),
            auth_attempts: Arc::clone(&auth_attempts),
            password_attempts: Arc::clone(&password_attempts),
        });
        let config = Arc::new(server::Config {
            keys: vec![host_key],
            methods: MethodSet::from(&spec.methods[..]),
            auth_rejection_time: Duration::from_millis(1),
            auth_rejection_time_initial: Some(Duration::ZERO),
            inactivity_timeout: Some(Duration::from_secs(60)),
            ..Default::default()
        });
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let mut srv = Srv {
                    inner,
                    user: String::new(),
                    cmds: HashMap::new(),
                    stdin: HashMap::new(),
                };
                tokio::select! {
                    _ = srv.run_on_socket(config, &listener) => {}
                    _ = rx => {}
                }
            });
            rt.shutdown_background();
        });
        TestServer {
            port,
            host_key: public,
            log,
            auth_attempts,
            password_attempts,
            shutdown: Some(tx),
            thread: Some(thread),
        }
    }

    /// The server's key as an OpenSSH line (for pinning).
    pub fn host_key_line(&self) -> String {
        openssh_line(&self.host_key)
    }

    pub fn fingerprint(&self) -> String {
        wol_ssh::parse_host_key(&self.host_key_line())
            .unwrap()
            .fingerprint_sha256
    }

    pub fn execs(&self) -> Vec<Exec> {
        self.log.lock().unwrap().clone()
    }

    pub fn auth_attempts(&self) -> usize {
        self.auth_attempts.load(Ordering::SeqCst)
    }

    pub fn password_attempts(&self) -> usize {
        self.password_attempts.load(Ordering::SeqCst)
    }

    /// Target on 127.0.0.1 with the server key pinned and short timeouts.
    pub fn target(&self, user: &str) -> Target {
        let mut t = Target::new("127.0.0.1", user);
        t.port = self.port;
        t.host_key = Some(self.host_key_line());
        t.timeouts = Timeouts {
            connect: Duration::from_secs(5),
            handshake: Duration::from_secs(10),
            command: Duration::from_secs(10),
        };
        t
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

// ---------------------------------------------------------------- fake remote host

/// How the fake host's sudo behaves.
#[derive(Clone, Debug)]
pub enum FakeSudo {
    NoPasswd,
    Password(String),
    NotInSudoers(String),
    Missing,
    RequireTty,
    /// sudo-rs (default `sudo` on Ubuntu 25.10 / 26.04 LTS) with a password rule; messages
    /// verbatim from sudo-rs 0.2.13. PAM's own prompt is shown instead of `-p`, so only the
    /// message strings identify a failure.
    RsPassword(String),
    /// sudo-rs, user without any sudoers rule: refused before authentication.
    RsNotAllowed,
}

/// Emulates a Linux host running WoL Manager's scripts (by their `# wolm:<tag> v1` header) and
/// sudo (by the exact command prefixes).
#[derive(Clone, Debug)]
pub struct FakeHost {
    pub uid: u32,
    pub user: String,
    pub sudo: FakeSudo,
    pub boot_line: String,
    pub os_lines: String,
    pub net: String,
    pub power_stdout: String,
    pub power_mode: Mode,
    pub power_exit: Option<u32>,
    /// Printed before every script output (like a chatty .bashrc).
    pub noise: String,
    /// Login shell cannot run scripts (nologin).
    pub nologin: bool,
}

pub const SUDO_PROMPT: &str = "WOLM_SUDO_PROMPT:";
pub const PREFIX_NOPASSWD: &str = "env LC_ALL=C sudo -n -- ";
pub const PREFIX_PASSWORD: &str = "env LC_ALL=C sudo -k -S -p 'WOLM_SUDO_PROMPT:' -- ";

impl FakeHost {
    pub fn linux(uid: u32, user: &str, sudo: FakeSudo) -> Self {
        FakeHost {
            uid,
            user: user.into(),
            sudo,
            boot_line: "WOLM1 boot os=Linux btime=1727600000 now=1727610000 src=proc_stat boot_id=6f9619ff-8b86-d011-b42d-00c04fc964ff\n"
                .into(),
            os_lines: "WOLM1 osrel \"Debian GNU/Linux 12 (bookworm)\"\nWOLM1 uname Linux 6.1.0-25-amd64\n".into(),
            net: include_str!("../fixtures/net_proxmox.txt").into(),
            power_stdout: "WOLM1 power ok=systemd-run unit=wolm-power-0badf00d cmd=systemctl reboot\n".into(),
            power_mode: Mode::Normal,
            power_exit: Some(0),
            noise: "Welcome to the test host (noise from .bashrc)\n".into(),
            nologin: false,
        }
    }

    pub fn behavior(self) -> Behavior {
        Arc::new(move |e: &Exec| self.respond(e))
    }

    fn id_lines(&self) -> String {
        format!(
            "WOLM1 uid {}\nWOLM1 user {}\nWOLM1 groups {} sudo\n",
            self.uid, self.user, self.user
        )
    }

    fn power_reply(&self, stderr_prefix: &str) -> Reply {
        Reply {
            stdout: self.power_stdout.clone().into_bytes(),
            stderr: stderr_prefix.as_bytes().to_vec(),
            exit: self.power_exit,
            signal: None,
            mode: self.power_mode,
        }
    }

    fn respond(&self, e: &Exec) -> Reply {
        if self.nologin {
            return Reply {
                stdout: b"This account is currently not available.\n".to_vec(),
                exit: Some(1),
                ..Default::default()
            };
        }
        let cmd = e.command.as_str();
        if cmd == "sh -s" {
            let script = String::from_utf8_lossy(&e.stdin);
            assert!(
                script.starts_with("{\n# wolm:") && script.ends_with("}\n"),
                "scripts are braced: {script}"
            );
            let body = if script.contains("# wolm:boot v1") {
                self.boot_line.clone()
            } else if script.contains("# wolm:info v1") {
                format!("{}{}{}", self.boot_line, self.id_lines(), self.os_lines)
            } else if script.contains("# wolm:id v1") {
                self.id_lines()
            } else if script.contains("# wolm:net v1") {
                self.net.clone()
            } else {
                return Reply::fail("sh: unknown script", 2);
            };
            return Reply::ok(format!("{}{}", self.noise, body));
        }
        // Privileged one-liners.
        let (mode, rest) = if let Some(r) = cmd.strip_prefix(PREFIX_NOPASSWD) {
            ("nopasswd", r)
        } else if let Some(r) = cmd.strip_prefix(PREFIX_PASSWORD) {
            ("password", r)
        } else {
            ("direct", cmd)
        };
        let script = rest
            .strip_prefix("/bin/sh -c '")
            .and_then(|s| s.strip_suffix('\''))
            .unwrap_or_else(|| panic!("unexpected command {cmd:?}"));
        assert!(!script.contains('\''), "one-liner must not contain quotes");
        assert!(
            script.starts_with("a=reboot;") || script.starts_with("a=poweroff;"),
            "{script}"
        );
        let wrong_pw = || {
            Reply::fail(
                format!(
                    "{SUDO_PROMPT}Sorry, try again.\n{SUDO_PROMPT}sudo: no password was provided\nsudo: 1 incorrect password attempt\n"
                ),
                1,
            )
        };
        let first_line = || {
            let s = String::from_utf8_lossy(&e.stdin).to_string();
            s.split('\n').next().unwrap_or("").to_string()
        };
        let rs_wrong_pw = || {
            // The password line was wrong, then stdin hit EOF: two more failed PAM rounds.
            Reply::fail(
                "Password: \nsudo: Authentication failed, try again.\nPassword: \nsudo: Authentication failed, try again.\nPassword: \nsudo: maximum 3 incorrect authentication attempts\n",
                1,
            )
        };
        let rs_not_allowed = || {
            Reply::fail(
                format!(
                    "sudo: I'm sorry {}. I'm afraid I can't do that\n",
                    self.user
                ),
                1,
            )
        };
        match mode {
            "direct" => {
                if self.uid == 0 {
                    self.power_reply("")
                } else {
                    Reply {
                        stdout: b"WOLM1 power err=notroot\n".to_vec(),
                        exit: Some(3),
                        ..Default::default()
                    }
                }
            }
            "nopasswd" => match &self.sudo {
                FakeSudo::NoPasswd => self.power_reply(""),
                FakeSudo::Password(_) | FakeSudo::NotInSudoers(_) => {
                    Reply::fail("sudo: a password is required\n", 1)
                }
                FakeSudo::Missing => Reply::fail("env: 'sudo': No such file or directory\n", 127),
                FakeSudo::RequireTty => {
                    Reply::fail("sudo: sorry, you must have a tty to run sudo\n", 1)
                }
                FakeSudo::RsPassword(_) => {
                    Reply::fail("sudo: interactive authentication is required\n", 1)
                }
                FakeSudo::RsNotAllowed => rs_not_allowed(),
            },
            _ => match &self.sudo {
                FakeSudo::NoPasswd => self.power_reply(""),
                FakeSudo::RsPassword(pw) if first_line() == *pw => self.power_reply("Password: "),
                FakeSudo::RsPassword(_) => rs_wrong_pw(),
                FakeSudo::RsNotAllowed => rs_not_allowed(),
                FakeSudo::Password(pw) if first_line() == *pw => self.power_reply(SUDO_PROMPT),
                FakeSudo::NotInSudoers(pw) if first_line() == *pw => Reply::fail(
                    format!(
                        "{SUDO_PROMPT}{} is not in the sudoers file.  This incident will be reported.\n",
                        self.user
                    ),
                    1,
                ),
                FakeSudo::Password(_) | FakeSudo::NotInSudoers(_) => wrong_pw(),
                FakeSudo::Missing => Reply::fail("env: 'sudo': No such file or directory\n", 127),
                FakeSudo::RequireTty => {
                    Reply::fail("sudo: sorry, you must have a tty to run sudo\n", 1)
                }
            },
        }
    }
}

/// A behavior for raw exec tests: `cat` echoes stdin, `big` prints `n` bytes, `sig` is killed,
/// `close-early` closes without status, `no-close` sends everything but CLOSE, `hang` never
/// answers, `drop` drops the connection.
pub fn raw_behavior() -> Behavior {
    Arc::new(|e: &Exec| match e.command.as_str() {
        "cat" => Reply {
            stdout: e.stdin.clone(),
            stderr: b"to stderr\n".to_vec(),
            exit: Some(3),
            ..Default::default()
        },
        "big" => Reply {
            stdout: vec![b'x'; 1_500_000],
            stderr: vec![b'e'; 1_100_000],
            exit: Some(0),
            ..Default::default()
        },
        "sig" => Reply {
            signal: Some(Sig::KILL),
            ..Default::default()
        },
        "close-early" => Reply {
            stdout: b"partial\n".to_vec(),
            mode: Mode::CloseEarly,
            ..Default::default()
        },
        "no-close" => Reply {
            stdout: b"all output\n".to_vec(),
            exit: Some(0),
            mode: Mode::NoClose,
            ..Default::default()
        },
        "hang" => Reply {
            mode: Mode::Hang,
            ..Default::default()
        },
        "drop" => Reply {
            mode: Mode::DropConnection,
            ..Default::default()
        },
        "whoami" => Reply::ok(format!("{}\n", e.user)),
        other => Reply::fail(format!("sh: {other}: not found\n"), 127),
    })
}
