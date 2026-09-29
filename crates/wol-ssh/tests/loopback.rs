//! End-to-end tests against an in-process russh server on 127.0.0.1 (no other network access).
//! No power command is ever executed anywhere: the server only emulates the scripts' output.

mod common;

use std::time::{Duration, Instant};

use common::*;
use russh::MethodKind;
use wol_ssh::{
    Elevation, ErrorClass, PowerAction, PowerOverrides, Session, SshError, SudoMode, Target,
    TimeoutStage, Timeouts, Zeroizing,
};

const PW: &str = "correct horse";

fn zs(s: &str) -> Option<Zeroizing<String>> {
    Some(Zeroizing::new(s.to_string()))
}

fn pw_server(behavior: Behavior) -> TestServer {
    TestServer::start(ServerSpec::new(vec![User::password("alice", PW)], behavior))
}

fn pw_target(srv: &TestServer, user: &str) -> Target {
    let mut t = srv.target(user);
    t.auth.password = zs(PW);
    t
}

// ---------------------------------------------------------------- host keys

#[test]
fn unknown_host_key_is_reported_before_any_credential_is_sent() {
    let srv = pw_server(raw_behavior());
    let mut t = pw_target(&srv, "alice");
    t.host_key = None;
    match Session::connect(&t) {
        Err(SshError::UnknownHostKey {
            openssh_line,
            fingerprint_sha256,
        }) => {
            assert_eq!(fingerprint_sha256, srv.fingerprint());
            assert!(fingerprint_sha256.starts_with("SHA256:"));
            let info = wol_ssh::parse_host_key(&openssh_line).unwrap();
            assert_eq!(info.openssh_line, srv.host_key_line());
            assert_eq!(info.algorithm, "ssh-ed25519");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        srv.auth_attempts(),
        0,
        "no credential may be sent to an unverified host"
    );
}

#[test]
fn pinned_key_connects_and_comment_or_crlf_is_ignored() {
    let srv = pw_server(raw_behavior());
    let mut t = pw_target(&srv, "alice");
    t.host_key = Some(format!("  {} root@pve\r\n", srv.host_key_line()));
    let mut s = Session::connect(&t).unwrap();
    assert_eq!(s.server_host_key().fingerprint_sha256, srv.fingerprint());
    let out = s.exec("whoami", None, Duration::from_secs(5)).unwrap();
    assert_eq!(out.stdout, b"alice\n");
    assert!(out.success() && out.exec_accepted && !out.closed_early);
    s.close();
}

#[test]
fn host_key_mismatch_is_a_hard_error() {
    let srv = pw_server(raw_behavior());
    let other = random_ed25519();
    let mut t = pw_target(&srv, "alice");
    t.host_key = Some(openssh_line(other.public_key()));
    match Session::connect(&t) {
        Err(e @ SshError::HostKeyMismatch { .. }) => {
            assert!(e.is_host_key());
            let SshError::HostKeyMismatch {
                expected_fp,
                actual_fp,
            } = e
            else {
                unreachable!()
            };
            assert_eq!(
                expected_fp,
                wol_ssh::parse_host_key(&openssh_line(other.public_key()))
                    .unwrap()
                    .fingerprint_sha256
            );
            assert_eq!(actual_fp, srv.fingerprint());
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(srv.auth_attempts(), 0);
}

#[test]
fn pinned_key_type_no_longer_offered() {
    let srv = pw_server(raw_behavior()); // ed25519 only
    let ecdsa = random_ecdsa_p256();
    let mut t = pw_target(&srv, "alice");
    t.host_key = Some(openssh_line(ecdsa.public_key()));
    match Session::connect(&t) {
        Err(SshError::HostKeyTypeUnavailable {
            key_type,
            expected_fp,
        }) => {
            assert_eq!(key_type, "ecdsa-sha2-nistp256");
            assert!(expected_fp.starts_with("SHA256:"));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(srv.auth_attempts(), 0);
}

#[test]
fn invalid_pin_is_a_config_error() {
    let srv = pw_server(raw_behavior());
    let mut t = pw_target(&srv, "alice");
    t.host_key = Some("ssh-ed25519 not-base64".into());
    let e = Session::connect(&t).unwrap_err();
    assert_eq!(e.class(), ErrorClass::Config, "{e:?}");
}

#[test]
fn scan_host_key_reads_the_key_without_authenticating() {
    let srv = pw_server(raw_behavior());
    let info = wol_ssh::scan_host_key("127.0.0.1", srv.port, Timeouts::default()).unwrap();
    assert_eq!(info.fingerprint_sha256, srv.fingerprint());
    assert_eq!(info.openssh_line, srv.host_key_line());
    assert_eq!(info.algorithm, "ssh-ed25519");
    assert_eq!(srv.auth_attempts(), 0);
}

// ---------------------------------------------------------------- authentication

#[test]
fn password_auth() {
    let srv = pw_server(raw_behavior());
    let mut s = Session::connect(&pw_target(&srv, "alice")).unwrap();
    assert_eq!(
        s.exec("whoami", None, Duration::from_secs(5))
            .unwrap()
            .stdout,
        b"alice\n"
    );
}

#[test]
fn wrong_password_fails_once_without_keyboard_interactive_retry() {
    let srv = pw_server(raw_behavior());
    let mut t = srv.target("alice");
    t.auth.password = zs("wrong");
    match Session::connect(&t) {
        Err(e @ SshError::AuthFailed { .. }) => {
            assert!(e.is_permission());
            let SshError::AuthFailed { server_methods } = e else {
                unreachable!()
            };
            assert!(
                server_methods.contains(&"password".to_string()),
                "{server_methods:?}"
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(srv.password_attempts(), 1);
    assert_eq!(
        srv.auth_attempts(),
        1,
        "no keyboard-interactive attempt with the same password"
    );
}

#[test]
fn keyboard_interactive_answers_the_password_prompt() {
    // Stock FreeBSD: no "password" method, PAM keyboard-interactive only.
    let user = User {
        name: "bsd".into(),
        kbd: Some(("Password for bsd@host:".into(), PW.into())),
        ..Default::default()
    };
    let mut spec = ServerSpec::new(vec![user], raw_behavior());
    spec.methods = vec![MethodKind::PublicKey, MethodKind::KeyboardInteractive];
    let srv = TestServer::start(spec);
    let mut s = Session::connect(&pw_target(&srv, "bsd")).unwrap();
    assert_eq!(
        s.exec("whoami", None, Duration::from_secs(5))
            .unwrap()
            .stdout,
        b"bsd\n"
    );
    assert_eq!(srv.password_attempts(), 0);
}

#[test]
fn openpam_prompt_with_code_like_names_is_a_password_prompt() {
    // FreeBSD / TrueNAS CORE: "Password for %u@%h:" (review probe r6: refused before).
    for (name, prompt) in [
        ("token", "Password for token@vscode-nas:"),
        ("root", "Password for root@barcode-server.lan:"),
        ("admin", "Password for admin@duo:"),
    ] {
        let user = User {
            name: name.into(),
            kbd: Some((prompt.into(), PW.into())),
            ..Default::default()
        };
        let mut spec = ServerSpec::new(vec![user], raw_behavior());
        spec.methods = vec![MethodKind::PublicKey, MethodKind::KeyboardInteractive];
        let srv = TestServer::start(spec);
        let mut s = Session::connect(&pw_target(&srv, name))
            .unwrap_or_else(|e| panic!("{prompt:?}: {e:?}"));
        assert_eq!(
            s.exec("whoami", None, Duration::from_secs(5))
                .unwrap()
                .stdout,
            format!("{name}\n").as_bytes()
        );
    }
}

#[test]
fn one_time_code_prompt_is_not_answered() {
    let user = User {
        name: "otp".into(),
        kbd: Some(("Verification code: ".into(), "123456".into())),
        ..Default::default()
    };
    let mut spec = ServerSpec::new(vec![user], raw_behavior());
    spec.methods = vec![MethodKind::KeyboardInteractive];
    let srv = TestServer::start(spec);
    match Session::connect(&pw_target(&srv, "otp")) {
        Err(SshError::AuthPromptUnsupported { prompt }) => {
            assert!(prompt.contains("Verification code"))
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn partial_success_is_reported() {
    // e.g. `AuthenticationMethods keyboard-interactive,publickey` with no key configured.
    let user = User {
        name: "twofa".into(),
        kbd: Some(("Password: ".into(), PW.into())),
        partial: true,
        ..Default::default()
    };
    let mut spec = ServerSpec::new(vec![user], raw_behavior());
    spec.methods = vec![MethodKind::PublicKey, MethodKind::KeyboardInteractive];
    let srv = TestServer::start(spec);
    match Session::connect(&pw_target(&srv, "twofa")) {
        Err(SshError::AuthPartial { remaining_methods }) => {
            assert_eq!(remaining_methods, ["publickey"])
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn no_credentials() {
    let srv = pw_server(raw_behavior());
    let e = Session::connect(&srv.target("alice")).unwrap_err();
    assert!(matches!(e, SshError::NoCredentials), "{e:?}");
    assert!(e.is_permission());
}

#[test]
fn key_auth_ed25519_plain_and_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let key = random_ed25519();
    let user = User {
        name: "k".into(),
        key: Some(key.public_key().clone()),
        ..Default::default()
    };
    let srv = TestServer::start(ServerSpec::new(vec![user], raw_behavior()));

    let plain = write_key(dir.path(), "id_plain", &key, None);
    let mut t = srv.target("k");
    t.auth.key_file = Some(plain);
    let mut s = Session::connect(&t).unwrap();
    assert_eq!(
        s.exec("whoami", None, Duration::from_secs(5))
            .unwrap()
            .stdout,
        b"k\n"
    );
    s.close();

    let enc = write_key(dir.path(), "id_enc", &key, Some("pass phrase"));
    t.auth.key_file = Some(enc.clone());
    t.auth.key_passphrase = zs("pass phrase");
    Session::connect(&t).unwrap().close();

    t.auth.key_passphrase = None;
    assert!(
        matches!(Session::connect(&t), Err(SshError::KeyPassphraseRequired { path }) if path == enc)
    );
    t.auth.key_passphrase = zs("wrong");
    assert!(matches!(
        Session::connect(&t),
        Err(SshError::KeyPassphraseWrong { .. })
    ));
}

#[test]
fn key_auth_ecdsa_and_rsa() {
    let dir = tempfile::tempdir().unwrap();
    let ecdsa = random_ecdsa_p256();
    let rsa = random_rsa_2048();
    let users = vec![
        User {
            name: "ec".into(),
            key: Some(ecdsa.public_key().clone()),
            ..Default::default()
        },
        User {
            name: "rsa".into(),
            key: Some(rsa.public_key().clone()),
            ..Default::default()
        },
    ];
    let srv = TestServer::start(ServerSpec::new(users, raw_behavior()));
    for (user, key) in [("ec", &ecdsa), ("rsa", &rsa)] {
        let mut t = srv.target(user);
        t.auth.key_file = Some(write_key(dir.path(), user, key, None));
        let mut s = Session::connect(&t).unwrap_or_else(|e| panic!("{user}: {e:?}"));
        assert_eq!(
            s.exec("whoami", None, Duration::from_secs(5))
                .unwrap()
                .stdout,
            format!("{user}\n").as_bytes()
        );
    }
}

#[test]
fn rejected_key_falls_back_to_password() {
    let dir = tempfile::tempdir().unwrap();
    let srv = pw_server(raw_behavior());
    let mut t = pw_target(&srv, "alice");
    t.auth.key_file = Some(write_key(dir.path(), "id_other", &random_ed25519(), None));
    Session::connect(&t).unwrap().close();

    t.auth.password = None;
    assert!(matches!(
        Session::connect(&t),
        Err(SshError::AuthFailed { .. })
    ));
}

// ---------------------------------------------------------------- exec

#[test]
fn exec_delivers_stdin_and_separates_streams() {
    let srv = pw_server(raw_behavior());
    let mut s = Session::connect(&pw_target(&srv, "alice")).unwrap();
    let input = b"line1\nbinary\0\xff\n";
    let out = s.exec("cat", Some(input), Duration::from_secs(5)).unwrap();
    assert_eq!(out.stdout, input);
    assert_eq!(out.stderr, b"to stderr\n");
    assert_eq!(out.exit_status, Some(3));
    assert!(!out.success() && !out.closed_early);
    assert_eq!(srv.execs().last().unwrap().stdin, input);
    // Without stdin the server sees an immediate EOF and empty input.
    let out = s.exec("cat", None, Duration::from_secs(5)).unwrap();
    assert!(out.stdout.is_empty());
}

#[test]
fn exec_output_is_capped() {
    let srv = pw_server(raw_behavior());
    let mut s = Session::connect(&pw_target(&srv, "alice")).unwrap();
    let out = s.exec("big", None, Duration::from_secs(20)).unwrap();
    assert_eq!(out.stdout.len(), wol_ssh::OUTPUT_CAP);
    assert_eq!(out.stderr.len(), wol_ssh::OUTPUT_CAP);
    assert!(out.stdout_truncated && out.stderr_truncated);
    assert_eq!(
        out.exit_status,
        Some(0),
        "the stream was drained to the end"
    );
}

#[test]
fn exec_signal_close_early_refused() {
    let srv = pw_server(raw_behavior());
    let mut s = Session::connect(&pw_target(&srv, "alice")).unwrap();
    let out = s.exec("sig", None, Duration::from_secs(5)).unwrap();
    assert_eq!(out.exit_signal.as_deref(), Some("KILL"));
    assert!(!out.closed_early);

    let out = s.exec("close-early", None, Duration::from_secs(5)).unwrap();
    assert!(out.closed_early && out.exec_accepted);
    assert_eq!(out.stdout, b"partial\n");

    assert!(matches!(
        s.exec("REFUSE", None, Duration::from_secs(5)),
        Err(SshError::ExecRefused)
    ));
    // The session is still usable afterwards.
    assert!(
        s.exec("whoami", None, Duration::from_secs(5))
            .unwrap()
            .success()
    );
}

#[test]
fn command_timeout_closes_the_channel_and_keeps_the_session() {
    let srv = pw_server(raw_behavior());
    let mut s = Session::connect(&pw_target(&srv, "alice")).unwrap();
    let t0 = Instant::now();
    let e = s
        .exec("hang", None, Duration::from_millis(400))
        .unwrap_err();
    assert!(
        matches!(e, SshError::Timeout(TimeoutStage::Command)),
        "{e:?}"
    );
    assert!(e.is_network() && e.is_timeout());
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
    assert!(
        s.exec("whoami", None, Duration::from_secs(5))
            .unwrap()
            .success()
    );
}

#[test]
fn exec_timeout_without_close_is_still_a_timeout() {
    // The public contract is unchanged; only `power` looks at partial output.
    let srv = pw_server(raw_behavior());
    let mut s = Session::connect(&pw_target(&srv, "alice")).unwrap();
    let e = s
        .exec("no-close", None, Duration::from_millis(500))
        .unwrap_err();
    assert!(
        matches!(e, SshError::Timeout(TimeoutStage::Command)),
        "{e:?}"
    );
    assert!(
        s.exec("whoami", None, Duration::from_secs(5))
            .unwrap()
            .success()
    );
}

#[test]
fn unlimited_timeouts_do_not_panic() {
    // Duration::MAX is a natural "no limit" (review probe r5: three overflow panics).
    let max = Timeouts {
        connect: Duration::MAX,
        handshake: Duration::MAX,
        command: Duration::MAX,
    };
    assert_eq!(max.connect_worst_case(), Duration::MAX);
    let srv = pw_server(raw_behavior());
    for host in ["127.0.0.1", "localhost"] {
        let mut t = pw_target(&srv, "alice");
        t.host = host.into();
        t.timeouts = max;
        let mut s = Session::connect(&t).unwrap();
        let out = s.exec("whoami", None, Duration::MAX).unwrap();
        assert_eq!(out.stdout, b"alice\n");
    }

    let host = FakeHost::linux(0, "root", FakeSudo::Missing);
    let srv = TestServer::start(ServerSpec::new(
        vec![User::password("root", PW)],
        host.behavior(),
    ));
    let mut t = pw_target(&srv, "root");
    t.timeouts = max;
    assert_eq!(wol_ssh::boot_time(&t).unwrap().btime, 1727600000);
    wol_ssh::power(&t, PowerAction::Restart, &PowerOverrides::default()).unwrap();
}

#[test]
fn works_inside_an_async_runtime() {
    // Review probes r2 (exec / boot_time panicked inside `block_on`) and r3 (`connect` was
    // refused on a `spawn_blocking` thread).
    let host = FakeHost::linux(0, "root", FakeSudo::Missing);
    let srv = TestServer::start(ServerSpec::new(
        vec![User::password("root", PW)],
        host.behavior(),
    ));
    let t = pw_target(&srv, "root");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // Directly in an async task.
    rt.block_on(async {
        let mut s = Session::connect(&t).unwrap();
        assert_eq!(s.boot_time().unwrap().btime, 1727600000);
        assert_eq!(s.conn_info().unwrap().user, "root");
        assert_eq!(s.mac_candidates().unwrap().len(), 1);
        let p = s
            .power(PowerAction::Restart, &PowerOverrides::default())
            .unwrap();
        assert_eq!(p.elevation, Elevation::Direct);
        drop(s); // DISCONNECT from inside the runtime
        wol_ssh::test_connection(&t).unwrap();
    });

    // On a spawn_blocking thread.
    let t2 = t.clone();
    let b = rt
        .block_on(async move {
            tokio::task::spawn_blocking(move || {
                let mut s = Session::connect(&t2)?;
                let b = s.boot_time()?;
                s.close();
                Ok::<_, SshError>(b)
            })
            .await
            .unwrap()
        })
        .unwrap();
    assert_eq!(b.btime, 1727600000);

    // Connected on a plain thread, used and dropped inside the runtime.
    let mut s = Session::connect(&t).unwrap();
    rt.block_on(async move {
        assert_eq!(s.boot_time().unwrap().btime, 1727600000);
        s.close();
    });
}

#[test]
fn dropped_connection() {
    let srv = pw_server(raw_behavior());
    let mut s = Session::connect(&pw_target(&srv, "alice")).unwrap();
    // Dropped while the command runs: Ok with closed_early (like sshd dying on reboot).
    let out = s.exec("drop", None, Duration::from_secs(5)).unwrap();
    assert!(out.closed_early);
    assert_eq!(out.exit_status, None);
    // Afterwards the session is dead.
    let e = s.exec("whoami", None, Duration::from_secs(5)).unwrap_err();
    assert!(e.is_network(), "{e:?}");
}

// ---------------------------------------------------------------- network errors / timeouts

#[test]
fn connection_refused() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut t = Target::new("127.0.0.1", "alice");
    t.port = port;
    t.auth.password = zs(PW);
    t.timeouts.connect = Duration::from_secs(4);
    let e = Session::connect(&t).unwrap_err();
    assert!(
        matches!(
            e,
            SshError::Connect { .. } | SshError::Timeout(TimeoutStage::Connect)
        ),
        "{e:?}"
    );
    assert!(e.is_network());
}

#[test]
fn handshake_timeout_on_a_silent_server() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut t = Target::new("127.0.0.1", "alice");
    t.port = port;
    t.auth.password = zs(PW);
    t.timeouts.handshake = Duration::from_millis(500);
    let t0 = Instant::now();
    let e = Session::connect(&t).unwrap_err();
    assert!(
        matches!(e, SshError::Timeout(TimeoutStage::Handshake)),
        "{e:?}"
    );
    assert!(t0.elapsed() < Duration::from_secs(5));
    drop(listener);
}

#[test]
fn not_an_ssh_server_is_a_protocol_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let th = std::thread::spawn(move || {
        use std::io::Write;
        if let Ok((mut c, _)) = listener.accept() {
            let _ = c.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        }
    });
    let mut t = Target::new("127.0.0.1", "alice");
    t.port = port;
    t.auth.password = zs(PW);
    t.timeouts.handshake = Duration::from_secs(5);
    let e = Session::connect(&t).unwrap_err();
    assert!(
        matches!(e, SshError::Protocol(_) | SshError::Disconnected(_)),
        "{e:?}"
    );
    th.join().unwrap();
}

#[test]
fn localhost_name_resolves_and_prefers_ipv4() {
    let srv = pw_server(raw_behavior());
    let mut t = pw_target(&srv, "alice");
    t.host = "localhost".into(); // resolved locally (hosts file), may yield ::1 first
    Session::connect(&t).unwrap().close();
}

#[test]
fn invalid_targets() {
    let mut t = Target::new("  ", "alice");
    assert!(matches!(
        Session::connect(&t),
        Err(SshError::InvalidInput(_))
    ));
    t.host = "127.0.0.1".into();
    t.user = String::new();
    assert!(matches!(
        Session::connect(&t),
        Err(SshError::InvalidInput(_))
    ));
    t.user = "alice".into();
    t.port = 0;
    assert!(matches!(
        Session::connect(&t),
        Err(SshError::InvalidInput(_))
    ));
}

// ---------------------------------------------------------------- read-only operations

#[test]
fn boot_time_and_test_connection() {
    let host = FakeHost::linux(1000, "alice", FakeSudo::Password(PW.into()));
    let srv = pw_server(host.behavior());
    let t = pw_target(&srv, "alice");
    let b = wol_ssh::boot_time(&t).unwrap();
    assert_eq!(b.btime, 1727600000);
    assert_eq!(b.uptime, Duration::from_secs(10000));
    assert_eq!(
        b.boot_id.as_deref(),
        Some("6f9619ff-8b86-d011-b42d-00c04fc964ff")
    );
    assert!(!b.approximate);
    let age = std::time::SystemTime::now()
        .duration_since(b.boot_time_local)
        .unwrap();
    assert!(
        age >= Duration::from_secs(10000) && age < Duration::from_secs(10060),
        "{age:?}"
    );

    let c = wol_ssh::test_connection(&t).unwrap();
    assert_eq!(c.os, "Debian GNU/Linux 12 (bookworm)");
    assert_eq!(c.user, "alice");
    assert_eq!(c.uid, Some(1000));
    assert!(!c.is_root && c.likely_admin());
    assert_eq!(c.boot.btime, 1727600000);
    // Read-only operations never use sudo or a privileged command.
    assert!(srv.execs().iter().all(|e| e.command == "sh -s"));
}

#[test]
fn mac_candidates_over_ssh() {
    let host = FakeHost::linux(0, "root", FakeSudo::Missing);
    let user = User::password("root", PW);
    let srv = TestServer::start(ServerSpec::new(vec![user], host.behavior()));
    let c = wol_ssh::mac_candidates(&pw_target(&srv, "root")).unwrap();
    assert_eq!(c.len(), 1, "{c:#?}");
    assert_eq!(wol_ssh::format_mac(&c[0].mac), "AA:BB:CC:00:00:01");
    assert_eq!(c[0].iface, "eno1");
    assert_eq!(c[0].via.as_deref(), Some("vmbr0"));
    assert!(c[0].on_default_route);
}

#[test]
fn nologin_shell_is_explained() {
    let mut host = FakeHost::linux(1000, "alice", FakeSudo::NoPasswd);
    host.nologin = true;
    let srv = pw_server(host.behavior());
    match wol_ssh::boot_time(&pw_target(&srv, "alice")) {
        Err(SshError::UnexpectedOutput(m)) => {
            assert!(m.contains("sh -s") && m.contains("not available"), "{m}")
        }
        other => panic!("{other:?}"),
    }
}

// ---------------------------------------------------------------- power (emulated; nothing is executed)

fn privileged(srv: &TestServer) -> Vec<Exec> {
    srv.execs()
        .into_iter()
        .filter(|e| e.command != "sh -s")
        .collect()
}

#[test]
fn sudo_password_with_line_break_is_never_sent() {
    let host = FakeHost::linux(1000, "alice", FakeSudo::Password(PW.into()));
    let srv = pw_server(host.behavior());
    let mut t = pw_target(&srv, "alice");
    t.sudo_password = zs("line1\nline2");
    let e = wol_ssh::power(&t, PowerAction::Restart, &PowerOverrides::default()).unwrap_err();
    assert!(matches!(e, SshError::InvalidInput(_)), "{e:?}");
    assert!(privileged(&srv).iter().all(|e| e.stdin.is_empty()));
}

#[test]
fn power_as_root_runs_directly() {
    let host = FakeHost::linux(0, "root", FakeSudo::Missing);
    let srv = TestServer::start(ServerSpec::new(
        vec![User::password("root", PW)],
        host.behavior(),
    ));
    let p = wol_ssh::power(
        &pw_target(&srv, "root"),
        PowerAction::Restart,
        &PowerOverrides::default(),
    )
    .unwrap();
    assert_eq!(p.elevation, Elevation::Direct);
    assert_eq!(p.method, "systemd-run");
    assert_eq!(p.unit.as_deref(), Some("wolm-power-0badf00d"));
    assert_eq!(p.command, "systemctl reboot");
    let cmds = privileged(&srv);
    assert_eq!(cmds.len(), 1);
    assert!(
        cmds[0]
            .command
            .starts_with("/bin/sh -c 'a=reboot; w=; o=\"\"; n="),
        "{}",
        cmds[0].command
    );
    assert!(
        cmds[0].stdin.is_empty(),
        "no password is sent to a root login"
    );
}

#[test]
fn power_auto_uses_nopasswd_sudo() {
    let host = FakeHost::linux(1000, "alice", FakeSudo::NoPasswd);
    let srv = pw_server(host.behavior());
    let p = wol_ssh::power(
        &pw_target(&srv, "alice"),
        PowerAction::Shutdown,
        &PowerOverrides::default(),
    )
    .unwrap();
    assert_eq!(p.elevation, Elevation::SudoNoPasswd);
    let cmds = privileged(&srv);
    assert_eq!(cmds.len(), 1);
    assert!(
        cmds[0]
            .command
            .starts_with(&format!("{PREFIX_NOPASSWD}/bin/sh -c 'a=poweroff;"))
    );
    assert!(cmds[0].stdin.is_empty());
}

#[test]
fn power_auto_falls_back_to_password_once() {
    let host = FakeHost::linux(1000, "alice", FakeSudo::Password(PW.into()));
    let srv = pw_server(host.behavior());
    let p = wol_ssh::power(
        &pw_target(&srv, "alice"),
        PowerAction::Restart,
        &PowerOverrides::default(),
    )
    .unwrap();
    assert_eq!(p.elevation, Elevation::SudoPassword);
    let cmds = privileged(&srv);
    assert_eq!(cmds.len(), 2);
    assert!(cmds[0].command.starts_with(PREFIX_NOPASSWD) && cmds[0].stdin.is_empty());
    assert!(cmds[1].command.starts_with(PREFIX_PASSWORD));
    assert_eq!(
        cmds[1].stdin,
        format!("{PW}\n").as_bytes(),
        "password only on stdin, one line"
    );
    assert!(!cmds[1].command.contains(PW), "never on the command line");
}

#[test]
fn separate_sudo_password_is_preferred() {
    let host = FakeHost::linux(1000, "alice", FakeSudo::Password("sudo-secret".into()));
    let srv = pw_server(host.behavior());
    let mut t = pw_target(&srv, "alice");
    t.sudo_password = zs("sudo-secret");
    let p = wol_ssh::power(&t, PowerAction::Restart, &PowerOverrides::default()).unwrap();
    assert_eq!(p.elevation, Elevation::SudoPassword);
    assert_eq!(privileged(&srv).last().unwrap().stdin, b"sudo-secret\n");
}

#[test]
fn wrong_sudo_password_is_not_retried() {
    let host = FakeHost::linux(1000, "alice", FakeSudo::Password("other".into()));
    let srv = pw_server(host.behavior());
    let e = wol_ssh::power(
        &pw_target(&srv, "alice"),
        PowerAction::Restart,
        &PowerOverrides::default(),
    )
    .unwrap_err();
    assert!(matches!(e, SshError::SudoWrongPassword), "{e:?}");
    assert!(e.is_permission() && e.is_sudo());
    let attempts = privileged(&srv)
        .iter()
        .filter(|e| e.command.starts_with(PREFIX_PASSWORD))
        .count();
    assert_eq!(attempts, 1);
}

#[test]
fn not_in_sudoers() {
    let host = FakeHost::linux(1000, "alice", FakeSudo::NotInSudoers(PW.into()));
    let srv = pw_server(host.behavior());
    let e = wol_ssh::power(
        &pw_target(&srv, "alice"),
        PowerAction::Restart,
        &PowerOverrides::default(),
    )
    .unwrap_err();
    assert!(matches!(e, SshError::SudoNotAllowed), "{e:?}");
}

#[test]
fn sudo_password_required_without_a_password() {
    let dir = tempfile::tempdir().unwrap();
    let key = random_ed25519();
    let host = FakeHost::linux(1000, "k", FakeSudo::Password(PW.into()));
    let user = User {
        name: "k".into(),
        key: Some(key.public_key().clone()),
        ..Default::default()
    };
    let srv = TestServer::start(ServerSpec::new(vec![user], host.behavior()));
    let mut t = srv.target("k");
    t.auth.key_file = Some(write_key(dir.path(), "id", &key, None));
    let e = wol_ssh::power(&t, PowerAction::Restart, &PowerOverrides::default()).unwrap_err();
    assert!(matches!(e, SshError::SudoPasswordRequired), "{e:?}");
    assert!(
        privileged(&srv)
            .iter()
            .all(|e| !e.command.starts_with(PREFIX_PASSWORD))
    );
}

#[test]
fn sudo_modes_nopasswd_password_root() {
    // NoPasswd: never falls back to a password.
    let host = FakeHost::linux(1000, "alice", FakeSudo::Password(PW.into()));
    let srv = pw_server(host.behavior());
    let mut t = pw_target(&srv, "alice");
    t.sudo = SudoMode::NoPasswd;
    assert!(matches!(
        wol_ssh::power(&t, PowerAction::Restart, &PowerOverrides::default()),
        Err(SshError::SudoPasswordRequired)
    ));
    assert_eq!(privileged(&srv).len(), 1);

    // Password: goes straight to sudo -S.
    let host = FakeHost::linux(1000, "alice", FakeSudo::Password(PW.into()));
    let srv = pw_server(host.behavior());
    let mut t = pw_target(&srv, "alice");
    t.sudo = SudoMode::Password;
    assert_eq!(
        wol_ssh::power(&t, PowerAction::Restart, &PowerOverrides::default())
            .unwrap()
            .elevation,
        Elevation::SudoPassword
    );
    let cmds = privileged(&srv);
    assert_eq!(cmds.len(), 1);
    assert!(cmds[0].command.starts_with(PREFIX_PASSWORD));

    // Root: a non-root login is refused without running anything privileged.
    let host = FakeHost::linux(1000, "alice", FakeSudo::NoPasswd);
    let srv = pw_server(host.behavior());
    let mut t = pw_target(&srv, "alice");
    t.sudo = SudoMode::Root;
    assert!(matches!(
        wol_ssh::power(&t, PowerAction::Restart, &PowerOverrides::default()),
        Err(SshError::NotRoot)
    ));
    assert!(privileged(&srv).is_empty());
}

#[test]
fn sudo_missing_and_requiretty() {
    for (sudo, want) in [
        (FakeSudo::Missing, "SudoMissing"),
        (FakeSudo::RequireTty, "SudoNeedsTty"),
    ] {
        let srv = pw_server(FakeHost::linux(1000, "alice", sudo).behavior());
        let e = wol_ssh::power(
            &pw_target(&srv, "alice"),
            PowerAction::Restart,
            &PowerOverrides::default(),
        )
        .unwrap_err();
        assert!(format!("{e:?}").starts_with(want), "{e:?}");
    }
}

// ---------------------------------------------------------------- sudo-rs (Ubuntu 25.10 / 26.04 LTS)

fn password_attempts(srv: &TestServer) -> usize {
    privileged(srv)
        .iter()
        .filter(|e| e.command.starts_with(PREFIX_PASSWORD))
        .count()
}

#[test]
fn sudo_rs_auto_falls_back_to_password_exactly_once() {
    let host = FakeHost::linux(1000, "alice", FakeSudo::RsPassword(PW.into()));
    let srv = pw_server(host.behavior());
    let p = wol_ssh::power(
        &pw_target(&srv, "alice"),
        PowerAction::Restart,
        &PowerOverrides::default(),
    )
    .unwrap();
    assert_eq!(p.elevation, Elevation::SudoPassword);
    let cmds = privileged(&srv);
    assert_eq!(cmds.len(), 2, "sudo -n, then one sudo -S");
    assert!(cmds[0].command.starts_with(PREFIX_NOPASSWD));
    assert_eq!(password_attempts(&srv), 1);
    assert_eq!(cmds[1].stdin, format!("{PW}\n").as_bytes());
}

#[test]
fn sudo_rs_wrong_password_is_reported_and_not_retried() {
    let host = FakeHost::linux(1000, "alice", FakeSudo::RsPassword("other".into()));
    let srv = pw_server(host.behavior());
    let e = wol_ssh::power(
        &pw_target(&srv, "alice"),
        PowerAction::Restart,
        &PowerOverrides::default(),
    )
    .unwrap_err();
    assert!(matches!(e, SshError::SudoWrongPassword), "{e:?}");
    assert_eq!(password_attempts(&srv), 1);
}

#[test]
fn sudo_rs_without_a_password_or_in_nopasswd_mode() {
    // Key login, no stored password: Auto stops after `sudo -n`.
    let dir = tempfile::tempdir().unwrap();
    let key = random_ed25519();
    let host = FakeHost::linux(1000, "k", FakeSudo::RsPassword(PW.into()));
    let user = User {
        name: "k".into(),
        key: Some(key.public_key().clone()),
        ..Default::default()
    };
    let srv = TestServer::start(ServerSpec::new(vec![user], host.behavior()));
    let mut t = srv.target("k");
    t.auth.key_file = Some(write_key(dir.path(), "id", &key, None));
    let e = wol_ssh::power(&t, PowerAction::Restart, &PowerOverrides::default()).unwrap_err();
    assert!(matches!(e, SshError::SudoPasswordRequired), "{e:?}");
    assert_eq!(password_attempts(&srv), 0);

    // NoPasswd mode: the password is never used.
    let host = FakeHost::linux(1000, "alice", FakeSudo::RsPassword(PW.into()));
    let srv = pw_server(host.behavior());
    let mut t = pw_target(&srv, "alice");
    t.sudo = SudoMode::NoPasswd;
    let e = wol_ssh::power(&t, PowerAction::Restart, &PowerOverrides::default()).unwrap_err();
    assert!(matches!(e, SshError::SudoPasswordRequired), "{e:?}");
    assert_eq!(privileged(&srv).len(), 1);
    assert_eq!(password_attempts(&srv), 0);
}

#[test]
fn sudo_rs_password_mode() {
    let host = FakeHost::linux(1000, "alice", FakeSudo::RsPassword(PW.into()));
    let srv = pw_server(host.behavior());
    let mut t = pw_target(&srv, "alice");
    t.sudo = SudoMode::Password;
    let p = wol_ssh::power(&t, PowerAction::Shutdown, &PowerOverrides::default()).unwrap();
    assert_eq!(p.elevation, Elevation::SudoPassword);
    assert_eq!(privileged(&srv).len(), 1);

    t.sudo_password = zs("wrong");
    let e = wol_ssh::power(&t, PowerAction::Shutdown, &PowerOverrides::default()).unwrap_err();
    assert!(matches!(e, SshError::SudoWrongPassword), "{e:?}");
    assert_eq!(privileged(&srv).len(), 2);
}

#[test]
fn sudo_rs_user_without_sudo_rights() {
    let host = FakeHost::linux(1000, "alice", FakeSudo::RsNotAllowed);
    let srv = pw_server(host.behavior());
    let e = wol_ssh::power(
        &pw_target(&srv, "alice"),
        PowerAction::Restart,
        &PowerOverrides::default(),
    )
    .unwrap_err();
    assert!(matches!(e, SshError::SudoNotAllowed), "{e:?}");
    assert_eq!(
        password_attempts(&srv),
        0,
        "refused before authentication: no password sent"
    );
}

#[test]
fn power_without_marker_is_never_success() {
    let mut host = FakeHost::linux(0, "root", FakeSudo::Missing);
    host.power_stdout = String::new();
    host.power_exit = None;
    host.power_mode = Mode::CloseEarly;
    let srv = TestServer::start(ServerSpec::new(
        vec![User::password("root", PW)],
        host.behavior(),
    ));
    let e = wol_ssh::power(
        &pw_target(&srv, "root"),
        PowerAction::Shutdown,
        &PowerOverrides::default(),
    )
    .unwrap_err();
    assert!(matches!(e, SshError::PowerUnconfirmed), "{e:?}");

    // With the marker, a missing exit status does not matter.
    let mut host = FakeHost::linux(0, "root", FakeSudo::Missing);
    host.power_exit = None;
    host.power_mode = Mode::CloseEarly;
    host.power_stdout = "WOLM1 power ok=nohup cmd=shutdown -p now\n".into();
    let srv = TestServer::start(ServerSpec::new(
        vec![User::password("root", PW)],
        host.behavior(),
    ));
    let p = wol_ssh::power(
        &pw_target(&srv, "root"),
        PowerAction::Shutdown,
        &PowerOverrides::default(),
    )
    .unwrap();
    assert_eq!(
        (p.method.as_str(), p.command.as_str()),
        ("nohup", "shutdown -p now")
    );
}

#[test]
fn power_marker_without_close_is_scheduled() {
    // Review probe r4: marker + exit status 0 arrived, CLOSE withheld.
    let mut host = FakeHost::linux(0, "root", FakeSudo::Missing);
    host.power_mode = Mode::NoClose;
    let srv = TestServer::start(ServerSpec::new(
        vec![User::password("root", PW)],
        host.behavior(),
    ));
    let mut t = pw_target(&srv, "root");
    t.timeouts.command = Duration::from_millis(1500);
    let t0 = Instant::now();
    let p = wol_ssh::power(&t, PowerAction::Restart, &PowerOverrides::default()).unwrap();
    assert_eq!(p.command, "systemctl reboot");
    assert_eq!(p.unit.as_deref(), Some("wolm-power-0badf00d"));
    assert!(t0.elapsed() < Duration::from_secs(8), "{:?}", t0.elapsed());
}

#[test]
fn power_timeout_after_the_request_was_sent_is_unconfirmed() {
    // Accepted, then silence: the command may be scheduled, so no "network error, retry" and
    // no second (password) attempt.
    for sudo in [FakeSudo::NoPasswd, FakeSudo::Missing] {
        let uid = if matches!(sudo, FakeSudo::Missing) {
            0
        } else {
            1000
        };
        let mut host = FakeHost::linux(uid, "alice", sudo);
        host.power_mode = Mode::Hang;
        let srv = pw_server(host.behavior());
        let mut t = pw_target(&srv, "alice");
        t.timeouts.command = Duration::from_millis(1500);
        let e = wol_ssh::power(&t, PowerAction::Shutdown, &PowerOverrides::default()).unwrap_err();
        assert!(matches!(e, SshError::PowerUnconfirmed), "{e:?}");
        assert!(!e.is_network());
        assert_eq!(privileged(&srv).len(), 1, "never a second attempt");
    }
}

#[test]
fn invalid_override_is_rejected_before_anything_runs() {
    let host = FakeHost::linux(0, "root", FakeSudo::Missing);
    let srv = TestServer::start(ServerSpec::new(
        vec![User::password("root", PW)],
        host.behavior(),
    ));
    let o = PowerOverrides {
        reboot_command: Some("echo 'x'".into()),
        ..Default::default()
    };
    let e = wol_ssh::power(&pw_target(&srv, "root"), PowerAction::Restart, &o).unwrap_err();
    assert!(matches!(e, SshError::InvalidInput(_)), "{e:?}");
    assert!(srv.execs().is_empty());

    let o = PowerOverrides {
        reboot_command: Some("/usr/syno/sbin/synopoweroff -r || reboot".into()),
        shutdown_command: None,
        arm_wol_iface: None,
    };
    wol_ssh::power(&pw_target(&srv, "root"), PowerAction::Restart, &o).unwrap();
    let cmd = &privileged(&srv)[0].command;
    assert!(
        cmd.contains("o=\"/usr/syno/sbin/synopoweroff -r || reboot\""),
        "{cmd}"
    );
}

#[test]
fn one_session_for_boot_time_then_power() {
    let host = FakeHost::linux(0, "root", FakeSudo::Missing);
    let srv = TestServer::start(ServerSpec::new(
        vec![User::password("root", PW)],
        host.behavior(),
    ));
    let mut s = Session::connect(&pw_target(&srv, "root")).unwrap();
    let before = s.boot_time().unwrap();
    let p = s
        .power(PowerAction::Restart, &PowerOverrides::default())
        .unwrap();
    assert_eq!(p.elevation, Elevation::Direct);
    s.close();
    let mut after = before.clone();
    after.boot_id = Some("00000000-0000-0000-0000-000000000001".into());
    assert!(after.rebooted_since(&before));
}
