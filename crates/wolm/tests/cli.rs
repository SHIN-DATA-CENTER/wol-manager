//! End-to-end tests of `wolm`. Every run uses a temporary settings folder
//! (`WOL_MANAGER_CONFIG_DIR`) and a JSON file instead of the registry for PATH
//! (`WOL_MANAGER_PATH_BACKEND_FILE`, debug builds), a JSON file instead of Windows Credential
//! Manager (`WOL_MANAGER_SECRET_BACKEND_FILE`) and, for remote management, a scripted fake
//! (`WOL_MANAGER_REMOTE_FAKE`): no test stores a real credential or sends a real restart /
//! shutdown. Packets go to 127.0.0.1 only; remote error paths use closed loopback ports and
//! the TEST-NET address 192.0.2.1.

use std::io::{BufRead, BufReader, Read};
use std::net::UdpSocket;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_wolm");
const ENV_CONFIG_DIR: &str = "WOL_MANAGER_CONFIG_DIR";
const ENV_PATH_FILE: &str = "WOL_MANAGER_PATH_BACKEND_FILE";
const ENV_LANG: &str = "WOL_MANAGER_LANG";
const ENV_SECRET_FILE: &str = "WOL_MANAGER_SECRET_BACKEND_FILE";
const ENV_REMOTE_FAKE: &str = "WOL_MANAGER_REMOTE_FAKE";

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    fn json(&self) -> Value {
        assert!(
            self.stdout.is_ascii(),
            "stdout is not ASCII: {}",
            self.stdout
        );
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("stdout is not one JSON document ({e}): {}", self.stdout))
    }

    fn error_json(&self) -> Value {
        let lines: Vec<&str> = self
            .stderr
            .lines()
            .filter(|l| !l.trim().is_empty())
            .collect();
        let last = lines.last().expect("an error line on stderr");
        assert!(last.is_ascii(), "{last}");
        let v: Value = serde_json::from_str(last).expect("error line is JSON");
        assert_eq!(v["error"]["exit_code"].as_i64(), Some(i64::from(self.code)));
        v
    }
}

struct Env {
    tmp: TempDir,
}

impl Env {
    fn new() -> Env {
        Env {
            tmp: tempfile::tempdir().unwrap(),
        }
    }

    fn root(&self) -> &Path {
        self.tmp.path()
    }

    fn cfg_dir(&self) -> PathBuf {
        self.root().join("cfg")
    }

    fn secret_file(&self) -> PathBuf {
        self.root().join("secrets.json")
    }

    fn path_file(&self) -> PathBuf {
        self.root().join("path.json")
    }

    /// `wolm` with the test environment and no arguments.
    fn raw(&self) -> Command {
        let mut c = Command::new(BIN);
        c.env(ENV_CONFIG_DIR, self.cfg_dir())
            .env(ENV_PATH_FILE, self.path_file())
            .env(ENV_SECRET_FILE, self.secret_file())
            .env_remove(ENV_REMOTE_FAKE)
            .env_remove(ENV_LANG)
            .env("NO_COLOR", "1")
            .timeout(Duration::from_secs(60));
        c
    }

    fn exec(mut c: Command) -> Out {
        let o = c.output().expect("run wolm");
        Out {
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8(o.stdout).expect("stdout is UTF-8"),
            stderr: String::from_utf8(o.stderr).expect("stderr is UTF-8"),
        }
    }

    /// `wolm --lang en ARGS`.
    fn run(&self, args: &[&str]) -> Out {
        let mut c = self.raw();
        c.args(["--lang", "en"]).args(args);
        Env::exec(c)
    }

    /// `wolm ARGS` without `--lang`.
    fn run_nolang(&self, args: &[&str], envs: &[(&str, &str)]) -> Out {
        let mut c = self.raw();
        for (k, v) in envs {
            c.env(k, v);
        }
        c.args(args);
        Env::exec(c)
    }

    fn ok(&self, args: &[&str]) -> Out {
        let o = self.run(args);
        assert_eq!(
            o.code, 0,
            "wolm {args:?}\nstdout: {}\nstderr: {}",
            o.stdout, o.stderr
        );
        o
    }

    fn code(&self, args: &[&str]) -> i32 {
        self.run(args).code
    }

    fn write_config(&self, text: &str) {
        std::fs::create_dir_all(self.cfg_dir()).unwrap();
        std::fs::write(self.cfg_dir().join("config.toml"), text).unwrap();
    }

    fn two_hosts(&self) {
        self.ok(&[
            "add",
            "NAS",
            "--mac",
            "00:11:22:33:44:55",
            "--address",
            "192.0.2.110",
            "--group",
            "Home",
            "--notes",
            "書斎の NAS",
        ]);
        self.ok(&[
            "add",
            "テスト機",
            "--mac",
            "ＡＡ－ＢＢ－ＣＣ－ＤＤ－ＥＥ－０１",
            "--address",
            "１９２．０．２．１２０",
            "--port",
            "９",
            "--group",
            "ラボ",
        ]);
    }
}

fn names(list: &Value) -> Vec<String> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|h| h["name"].as_str().unwrap().to_owned())
        .collect()
}

// ------------------------------------------------------------------ basics

#[test]
fn version_contains_the_cargo_version() {
    let env = Env::new();
    let want = format!("wolm {}", env!("CARGO_PKG_VERSION"));
    for flag in ["--version", "-V"] {
        let o = env.run_nolang(&[flag], &[]);
        assert_eq!(o.code, 0);
        assert!(o.stdout.contains(&want), "{}", o.stdout);
    }
}

#[test]
fn usage_errors_exit_2() {
    let env = Env::new();
    assert_eq!(env.code(&["frobnicate"]), 2);
    assert_eq!(env.code(&["wake", "--repeat"]), 2);
    assert_eq!(
        env.code(&["wake", "--timeout", "2s", "--mac", "AA:BB:CC:DD:EE:FF"]),
        2
    );
    assert_eq!(env.code(&["path", "add", "--scope", "bogus"]), 2);
    assert_eq!(
        env.code(&["add", "X", "--mac", "00:11:22:33:44:55", "--arp"]),
        2
    );
    // Values parsed by wol-core.
    assert_eq!(
        env.code(&[
            "wake",
            "--mac",
            "AA:BB:CC:DD:EE:FF",
            "--repeat",
            "11",
            "--dry-run"
        ]),
        2
    );
    assert_eq!(env.code(&["wake", "--mac", "zz", "--dry-run"]), 2);
    assert_eq!(env.code(&["status", "--timeout", "soon"]), 2);
    // With --json the usage error is one JSON line.
    for args in [
        &["frobnicate", "--json"][..],
        &["--json", "config"],
        &["path", "--json"],
    ] {
        let o = env.run(args);
        assert_eq!(o.code, 2, "{args:?}");
        assert_eq!(o.error_json()["error"]["kind"], "usage", "{args:?}");
        assert!(o.stdout.is_empty(), "{args:?}");
    }
    // The JSON message names the missing arguments (clap prints them on the next lines).
    for (args, missing) in [
        (&["--json", "wake", "PC1", "--timeout", "5"][..], "--wait"),
        (&["--json", "show"], "<HOST>"),
        (&["--json", "add"], "<NAME>"),
        (&["--json", "config", "set", "wake.repeat"], "<VALUE>"),
    ] {
        let o = env.run(args);
        assert_eq!(o.code, 2, "{args:?}");
        let e = o.error_json();
        let m = e["error"]["message"].as_str().unwrap();
        assert!(
            m.starts_with("the following required arguments were not provided: ")
                && m.contains(missing),
            "{args:?}: {m}"
        );
        assert!(!m.contains("Usage"), "{m}");
    }
    // Help and version are not errors.
    assert_eq!(env.code(&["--help"]), 0);
    assert_eq!(env.code(&["wake", "--help"]), 0);
}

/// Runs `wolm ARGS` with stdin connected to NUL (closed) and returns the exit code, or
/// `None` when it did not finish within `limit` (it is killed then).
fn run_with_closed_stdin(env: &Env, args: &[&str], limit: Duration) -> Option<i32> {
    let mut child = StdCommand::new(BIN)
        .env(ENV_CONFIG_DIR, env.cfg_dir())
        .env(ENV_PATH_FILE, env.path_file())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let start = Instant::now();
    while start.elapsed() < limit {
        if let Some(st) = child.try_wait().unwrap() {
            return st.code();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

#[test]
fn no_arguments_never_waits_when_not_double_clicked() {
    let env = Env::new();
    assert_eq!(
        run_with_closed_stdin(&env, &[], Duration::from_secs(5)),
        Some(2)
    );
    // Piped stdin: prints the usage on stderr and exits 2 at once.
    let start = Instant::now();
    let mut c = env.raw();
    c.write_stdin("\n").timeout(Duration::from_secs(5));
    let o = Env::exec(c);
    assert_eq!(o.code, 2, "{}", o.stderr);
    assert!(o.stderr.contains("Usage"), "{}", o.stderr);
    assert!(start.elapsed() < Duration::from_secs(5));
}

// ------------------------------------------------------------------ hosts

#[test]
fn add_list_show_edit_remove_round_trip() {
    let env = Env::new();
    // Nothing is created by reading.
    let o = env.ok(&["list"]);
    assert!(o.stdout.is_empty());
    assert!(
        !env.cfg_dir().exists(),
        "list must not create the settings folder"
    );

    env.two_hosts();
    let list = env.ok(&["list", "--json"]).json();
    assert_eq!(names(&list), ["NAS", "テスト機"]);
    assert_eq!(list[1]["mac"], "AA:BB:CC:DD:EE:01");
    assert_eq!(list[1]["address"], "192.0.2.120");
    assert_eq!(list[1]["port"], 9);
    assert_eq!(list[0]["notes"], "書斎の NAS");

    // Human table: both names, CJK-aligned columns.
    let o = env.ok(&["list"]);
    let lines: Vec<&str> = o.stdout.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].starts_with("NAME"));
    assert!(!o.stdout.contains('\u{1b}'), "no colors when piped");

    // Lookup: full-width / case-insensitive name, MAC in another notation, id prefix.
    let nas = env.ok(&["show", "ｎａｓ", "--json"]).json();
    assert_eq!(nas["name"], "NAS");
    let id = nas["id"].as_str().unwrap().to_owned();
    assert_eq!(
        env.ok(&["show", "aa-bb-cc-dd-ee-01", "--json"]).json()["name"],
        "テスト機"
    );
    assert_eq!(env.ok(&["show", &id[..8], "--json"]).json()["name"], "NAS");
    let o = env.ok(&["show", "テスト機"]);
    assert!(o.stdout.contains("AA:BB:CC:DD:EE:01"));
    assert!(o.stdout.contains("192.0.2.120"));

    // Group filter.
    assert_eq!(
        names(&env.ok(&["ls", "--group", "ラボ", "--json"]).json()),
        ["テスト機"]
    );
    assert_eq!(
        names(&env.ok(&["ls", "-g", "ＨＯＭＥ", "--json"]).json()),
        ["NAS"]
    );
    assert_eq!(env.code(&["list", "--group", "nope"]), 3);

    // Edit: rename, change, clear.
    let o = env.ok(&[
        "edit",
        "NAS",
        "--name",
        "NAS-2",
        "--group",
        "Lab",
        "--clear-notes",
        "--port",
        "7",
        "--to",
        "198.51.100.255",
        "--to",
        "relay.lan:9",
        "--tcp-port",
        "3389,22",
    ]);
    assert!(o.stderr.contains("Updated host \"NAS-2\""), "{}", o.stderr);
    let h = env.ok(&["show", "NAS-2", "--json"]).json();
    assert_eq!(h["id"], id.as_str());
    assert_eq!(h["group"], "Lab");
    assert!(h["notes"].is_null());
    assert_eq!(h["port"], 7);
    assert_eq!(
        h["targets"],
        serde_json::json!(["198.51.100.255", "relay.lan:9"])
    );
    assert_eq!(h["tcp_ports"], serde_json::json!([3389, 22]));
    assert_eq!(h["mac"], "00:11:22:33:44:55");
    // Nothing given / same value in another notation: no change, exit 1.
    assert_eq!(env.code(&["edit", "NAS-2"]), 1);
    assert_eq!(
        env.code(&["edit", "NAS-2", "--mac", "00-11-22-33-44-55"]),
        1
    );
    env.ok(&[
        "edit",
        "NAS-2",
        "--clear-port",
        "--clear-targets",
        "--no-broadcast",
    ]);
    let h = env.ok(&["show", "NAS-2", "--json"]).json();
    assert!(h["port"].is_null());
    assert_eq!(h["targets"], serde_json::json!([]));
    assert_eq!(h["broadcast"], false);
    assert_eq!(h["effective_port"], 9);

    // Remove (several at once).
    env.ok(&["add", "Extra", "--mac", "02:00:00:00:00:09"]);
    let o = env.ok(&["rm", "テスト機", "extra", "--json"]);
    assert_eq!(o.json()["removed"].as_array().unwrap().len(), 2);
    assert_eq!(names(&env.ok(&["list", "--json"]).json()), ["NAS-2"]);
    assert!(env.cfg_dir().join("config.toml.bak").is_file());
}

#[test]
fn duplicate_ambiguous_and_not_found_exit_codes() {
    let env = Env::new();
    env.two_hosts();
    // Duplicates (case / width folded), invalid values: exit 2.
    assert_eq!(env.code(&["add", "NAS", "--mac", "02:00:00:00:00:01"]), 2);
    assert_eq!(
        env.code(&["add", "ｎａｓ", "--mac", "02:00:00:00:00:01"]),
        2
    );
    assert_eq!(
        env.code(&["add", "AA:BB:CC:DD:EE:02", "--mac", "02:00:00:00:00:01"]),
        2
    );
    assert_eq!(env.code(&["add", "NoMac"]), 2);
    assert_eq!(env.code(&["add", "BadMac", "--mac", "zz"]), 2);
    assert_eq!(env.code(&["add", "Kana", "--mac", "あいうえお"]), 2);
    assert_eq!(
        env.code(&[
            "add",
            "BadPort",
            "--mac",
            "02:00:00:00:00:01",
            "--port",
            "0"
        ]),
        2
    );
    assert_eq!(
        env.code(&[
            "add",
            "BadProbe",
            "--mac",
            "02:00:00:00:00:01",
            "--probe",
            "arp"
        ]),
        2
    );
    assert_eq!(env.code(&["edit", "NAS", "--name", "テスト機"]), 2);
    let o = env.run(&["add", "NoMac", "--json"]);
    assert_eq!(o.code, 2);
    assert_eq!(o.error_json()["error"]["kind"], "invalid_input");

    // Not found: exit 3.
    for args in [
        &["show", "nope"][..],
        &["edit", "nope", "--group", "x"],
        &["remove", "nope"],
        &["wake", "nope", "--dry-run"],
        &["wake", "--group", "nope", "--dry-run"],
        &["status", "nope"],
    ] {
        assert_eq!(env.code(args), 3, "{args:?}");
    }
    let o = env.run(&["show", "nope", "--json"]);
    assert_eq!(o.error_json()["error"]["kind"], "not_found");

    // Ambiguous (two hosts with one MAC): exit 2.
    env.ok(&["add", "Twin-1", "--mac", "02:00:00:00:00:77"]);
    env.ok(&["add", "Twin-2", "--mac", "02-00-00-00-00-77"]);
    let o = env.run(&["show", "02:00:00:00:00:77", "--json"]);
    assert_eq!(o.code, 2);
    assert_eq!(o.error_json()["error"]["kind"], "ambiguous");
    assert_eq!(env.code(&["wake", "020000000077", "--dry-run"]), 2);
}

#[test]
fn json_output_is_ascii_and_parseable() {
    let env = Env::new();
    env.two_hosts();
    env.ok(&[
        "add",
        "絵文字😀",
        "--mac",
        "02:00:00:00:00:03",
        "--notes",
        "行1\n行2",
    ]);
    for args in [
        &["list", "--json"][..],
        &["show", "テスト機", "--json"],
        &["config", "get", "--json"],
        &["config", "path", "--json"],
        &["config", "validate", "--json"],
        &["config", "show", "--json"],
        &["export", "--json"],
        &[
            "wake",
            "テスト機",
            "--dry-run",
            "--no-broadcast",
            "--to",
            "127.0.0.1:9",
            "--json",
        ],
    ] {
        let o = env.run(args);
        assert_eq!(o.code, 0, "{args:?}: {}", o.stderr);
        let v = o.json();
        assert!(!v.is_null());
    }
    let list = env.ok(&["list", "--json"]).json();
    assert_eq!(list[2]["name"], "絵文字😀");
    assert_eq!(list[2]["notes"], "行1\n行2");
    let raw = env.ok(&["list", "--json"]).stdout;
    assert!(raw.contains("\\u30c6\\u30b9\\u30c8"), "{raw}");
    assert!(raw.contains("\\ud83d\\ude00"), "{raw}");
    // Japanese error text is escaped too.
    let o = env.run_nolang(&["--lang", "ja", "show", "nope", "--json"], &[]);
    assert_eq!(o.code, 3);
    let e = o.error_json();
    assert!(
        e["error"]["message"]
            .as_str()
            .unwrap()
            .contains("ホストが見つかりません")
    );
}

#[test]
fn language_priority_flag_env_settings() {
    let env = Env::new();
    let ja = "ホストが見つかりません";
    let en = "Host not found";
    let stderr = |args: &[&str], envs: &[(&str, &str)]| env.run_nolang(args, envs).stderr;
    assert!(stderr(&["--lang", "ja", "show", "x"], &[]).contains(ja));
    assert!(stderr(&["show", "x"], &[(ENV_LANG, "ja")]).contains(ja));
    assert!(stderr(&["--lang", "en", "show", "x"], &[(ENV_LANG, "ja")]).contains(en));
    env.ok(&["config", "set", "language", "ja"]);
    assert!(stderr(&["show", "x"], &[]).contains(ja));
    assert!(stderr(&["show", "x"], &[(ENV_LANG, "en")]).contains(en));
    assert!(stderr(&["--lang", "en", "show", "x"], &[]).contains(en));
    env.ok(&["config", "set", "language", "en"]);
    assert!(stderr(&["show", "x"], &[]).contains(en));
}

#[test]
fn quiet_suppresses_progress_but_not_errors() {
    let env = Env::new();
    let o = env.ok(&["-q", "add", "Q", "--mac", "02:00:00:00:00:04"]);
    assert!(o.stderr.is_empty(), "{}", o.stderr);
    let o = env.run(&["-q", "show", "nope"]);
    assert_eq!(o.code, 3);
    assert!(o.stderr.contains("Host not found"));
}

#[test]
fn secureon_is_never_printed() {
    let env = Env::new();
    env.ok(&[
        "add",
        "S",
        "--mac",
        "02:00:00:00:00:05",
        "--secureon",
        "0A:0B:0C:0D:0E:0F",
    ]);
    let o = env.ok(&["show", "S"]);
    assert!(o.stdout.contains("set"));
    let j = env.ok(&["show", "S", "--json"]);
    assert_eq!(j.json()["secureon"], true);
    for out in [&o.stdout, &j.stdout, &env.ok(&["list", "--json"]).stdout] {
        assert!(!out.contains("0A:0B:0C"), "{out}");
    }
}

// ------------------------------------------------------------------ config

#[test]
fn config_get_set_validate() {
    let env = Env::new();
    // show / path without a file: defaults, nothing created.
    let o = env.ok(&["config", "show"]);
    assert!(o.stdout.contains("schema_version = 1"));
    let o = env.ok(&["config", "path"]);
    assert_eq!(
        PathBuf::from(o.stdout.trim()),
        env.cfg_dir().join("config.toml")
    );
    assert!(!env.cfg_dir().exists());

    assert_eq!(env.ok(&["config", "get", "wake.repeat"]).stdout.trim(), "3");
    assert_eq!(env.code(&["config", "set", "wake.repeat", "５"]), 0);
    assert_eq!(env.ok(&["config", "get", "wake.repeat"]).stdout.trim(), "5");
    assert_eq!(env.code(&["config", "set", "wake.repeat", "5"]), 1);
    assert_eq!(env.code(&["config", "set", "wake.repeat", "11"]), 2);
    assert_eq!(env.code(&["config", "set", "no.such.key", "1"]), 2);
    assert_eq!(env.code(&["config", "get", "no.such.key"]), 2);
    env.ok(&[
        "config",
        "set",
        "wake.interfaces",
        "イーサネット 2, Ethernet",
    ]);
    let v = env
        .ok(&["config", "get", "wake.interfaces", "--json"])
        .json();
    assert_eq!(
        v["value"],
        serde_json::json!(["イーサネット 2", "Ethernet"])
    );
    env.ok(&["config", "set", "wake.interfaces", ""]);
    let all = env.ok(&["config", "get", "--json"]).json();
    let keys: Vec<&String> = all.as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), 24);
    assert_eq!(all["remote.shutdown_delay_secs"], 30);
    assert_eq!(all["remote.auto_boot_time"], true);
    assert_eq!(all["wake.repeat"], 5);
    assert_eq!(all["probe.tcp_ports"], serde_json::json!([3389, 445, 22]));
    // --clear empties a list without an empty argument (Windows PowerShell 5.1 drops "").
    env.ok(&["config", "set", "wake.interfaces", "Ethernet"]);
    let v = env
        .ok(&["config", "set", "wake.interfaces", "--clear", "--json"])
        .json();
    assert_eq!(v["value"], serde_json::json!([]));
    assert_eq!(v["changed"], true);
    assert_eq!(
        env.code(&["config", "set", "wake.interfaces", "--clear"]),
        1
    );
    env.ok(&["config", "set", "probe.tcp_ports", "--clear"]);
    assert_eq!(
        env.ok(&["config", "get", "probe.tcp_ports", "--json"])
            .json()["value"],
        serde_json::json!([])
    );
    env.ok(&["config", "set", "probe.tcp_ports", "3389, 445, 22"]);
    // Not a list: refused, nothing changes. VALUE and --clear together: usage error.
    assert_eq!(env.code(&["config", "set", "wake.repeat", "--clear"]), 2);
    assert_eq!(env.ok(&["config", "get", "wake.repeat"]).stdout.trim(), "5");
    assert_eq!(
        env.code(&["config", "set", "wake.interfaces", "x", "--clear"]),
        2
    );
    let o = env
        .ok(&["config", "set", "probe.method", "tcp", "--json"])
        .json();
    assert_eq!(o["changed"], true);

    assert_eq!(env.code(&["config", "validate"]), 0);
    let v = env.ok(&["config", "validate", "--json"]).json();
    assert_eq!(v["valid"], true);

    // Out of range in a hand-edited file: warnings, exit 1.
    env.write_config("schema_version = 1\n[settings.wake]\nrepeat = 50\n");
    let o = env.run(&["config", "validate", "--json"]);
    assert_eq!(o.code, 1);
    let v = o.json();
    assert_eq!(v["valid"], false);
    assert_eq!(v["issues"][0]["key"], "wake.repeat");
    // Broken file: exit 6 everywhere, and it is not overwritten.
    env.write_config("schema_version = [\n");
    assert_eq!(env.code(&["config", "validate"]), 6);
    assert_eq!(env.code(&["list"]), 6);
    assert_eq!(env.code(&["add", "X", "--mac", "02:00:00:00:00:01"]), 6);
    assert_eq!(
        std::fs::read_to_string(env.cfg_dir().join("config.toml")).unwrap(),
        "schema_version = [\n"
    );
}

#[test]
fn config_open_creates_the_file_and_runs_the_editor() {
    let env = Env::new();
    let mut c = env.raw();
    c.args(["--lang", "en", "config", "open"])
        .env("EDITOR", "cmd.exe /d /c rem")
        .env_remove("VISUAL");
    let o = Env::exec(c);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let text = std::fs::read_to_string(env.cfg_dir().join("config.toml")).unwrap();
    assert!(text.contains("schema_version = 1"), "{text}");
}

#[test]
fn config_open_runs_a_cmd_shim_from_path() {
    // `EDITOR=code --wait` with VS Code's `code.cmd`: found through PATH + PATHEXT.
    let env = Env::new();
    let bin = env.root().join("edbin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(
        bin.join("myed.cmd"),
        "@echo off\r\necho %*> \"%~dp0called.txt\"\r\n",
    )
    .unwrap();
    let path = std::env::join_paths(std::iter::once(bin.clone()).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .unwrap();
    let mut c = env.raw();
    c.args(["--lang", "en", "config", "open", "--json"])
        .env("EDITOR", "myed --wait")
        .env_remove("VISUAL")
        .env("PATH", path);
    let o = Env::exec(c);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let v = o.json();
    assert!(
        v["editor"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase()
            .ends_with("myed.cmd"),
        "{v}"
    );
    let called = std::fs::read_to_string(bin.join("called.txt")).expect("the shim ran");
    assert!(called.contains("--wait"), "{called}");
    assert!(called.contains("config.toml"), "{called}");
}

// ------------------------------------------------------------------ export / import

#[test]
fn export_import_toml_json_csv() {
    let src = Env::new();
    src.two_hosts();
    src.ok(&[
        "edit",
        "NAS",
        "--to",
        "198.51.100.255",
        "--secureon",
        "01:02:03:04:05:06",
    ]);
    let out = src.ok(&["export"]).stdout;
    assert!(out.contains("[[hosts]]"), "{out}");
    let csv = src.run(&["export", "--format", "csv"]);
    assert!(csv.stdout.starts_with('\u{feff}'), "CSV starts with a BOM");

    for ext in ["toml", "json", "csv"] {
        let file = src.root().join(format!("hosts.{ext}"));
        let o = src.ok(&["export", "-o", file.to_str().unwrap()]);
        assert!(o.stderr.contains("Exported 2 host(s)"), "{}", o.stderr);
        let dst = Env::new();
        // Dry run: nothing is written.
        let o = dst.ok(&["import", file.to_str().unwrap(), "--dry-run", "--json"]);
        assert_eq!(o.json()["added"].as_array().unwrap().len(), 2);
        assert!(!dst.cfg_dir().exists());
        let o = dst.ok(&["import", file.to_str().unwrap()]);
        assert!(o.stdout.contains("+ NAS"), "{}", o.stdout);
        assert_eq!(
            names(&dst.ok(&["list", "--json"]).json()),
            ["NAS", "テスト機"],
            "{ext}"
        );
        let nas = dst.ok(&["show", "NAS", "--json"]).json();
        assert_eq!(
            nas["targets"],
            serde_json::json!(["198.51.100.255"]),
            "{ext}"
        );
        assert_eq!(nas["secureon"], true, "{ext}");
        assert_eq!(nas["notes"], "書斎の NAS", "{ext}");
        // Same file again: nothing changes, exit 1.
        assert_eq!(dst.code(&["import", file.to_str().unwrap()]), 1, "{ext}");
    }

    // Replace mode removes hosts that are not in the file.
    let dst = Env::new();
    dst.ok(&["add", "Old", "--mac", "02:00:00:00:00:10"]);
    let file = src.root().join("hosts.json");
    let v = dst
        .ok(&["import", file.to_str().unwrap(), "--replace", "--json"])
        .json();
    assert_eq!(v["removed"], serde_json::json!(["Old"]));
    assert_eq!(
        names(&dst.ok(&["list", "--json"]).json()),
        ["NAS", "テスト機"]
    );

    // Group export.
    let o = src.ok(&["export", "--group", "ラボ", "--format", "json"]);
    let v: Value = serde_json::from_str(&o.stdout).unwrap();
    assert_eq!(v["hosts"].as_array().unwrap().len(), 1);
    assert_eq!(src.code(&["export", "--group", "none"]), 3);
}

/// `名前,MAC アドレス,IP アドレス,グループ,メモ` / `テストサーバー,00-11-22-33-44-66,
/// 192.0.2.30,書斎,日本語のメモ` encoded in Shift_JIS (Windows-31J), as Excel writes it.
fn shift_jis_csv() -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    b.extend([0x96, 0xBC, 0x91, 0x4F]); // 名前
    b.extend(b",MAC ");
    b.extend([0x83, 0x41, 0x83, 0x68, 0x83, 0x8C, 0x83, 0x58]); // アドレス
    b.extend(b",IP ");
    b.extend([0x83, 0x41, 0x83, 0x68, 0x83, 0x8C, 0x83, 0x58]); // アドレス
    b.extend(b",");
    b.extend([0x83, 0x4F, 0x83, 0x8B, 0x81, 0x5B, 0x83, 0x76]); // グループ
    b.extend(b",");
    b.extend([0x83, 0x81, 0x83, 0x82]); // メモ
    b.extend(b"\r\n");
    b.extend([
        0x83, 0x65, 0x83, 0x58, 0x83, 0x67, 0x83, 0x54, 0x81, 0x5B, 0x83, 0x6F, 0x81, 0x5B,
    ]); // テストサーバー
    b.extend(b",00-11-22-33-44-66,192.0.2.30,");
    b.extend([0x8F, 0x91, 0x8D, 0xD6]); // 書斎
    b.extend(b",");
    b.extend([
        0x93, 0xFA, 0x96, 0x7B, 0x8C, 0xEA, 0x82, 0xCC, 0x83, 0x81, 0x83, 0x82,
    ]); // 日本語のメモ
    b.extend(b"\r\n");
    b
}

#[test]
fn import_shift_jis_csv() {
    let env = Env::new();
    let bytes = shift_jis_csv();
    assert!(
        std::str::from_utf8(&bytes).is_err(),
        "fixture must not be UTF-8"
    );
    let file = env.root().join("excel.csv");
    std::fs::write(&file, bytes).unwrap();
    let o = env.ok(&["import", file.to_str().unwrap()]);
    assert!(o.stderr.contains("1 added"), "{}", o.stderr);
    let h = env.ok(&["show", "テストサーバー", "--json"]).json();
    assert_eq!(h["mac"], "00:11:22:33:44:66");
    assert_eq!(h["address"], "192.0.2.30");
    assert_eq!(h["group"], "書斎");
    assert_eq!(h["notes"], "日本語のメモ");
}

#[test]
fn export_json_without_output_is_always_one_json_document() {
    let env = Env::new();
    env.two_hosts();
    for format in ["csv", "toml"] {
        let o = env.ok(&["export", "--json", "--format", format]);
        let v = o.json();
        assert_eq!(v["format"], format);
        assert_eq!(v["count"], 2);
        let content = v["content"].as_str().unwrap();
        assert!(content.contains("書斎の NAS"), "{content}");
        assert!(!content.starts_with('\u{feff}'), "no BOM in the text");
        // Same text as the plain export (without the CSV BOM).
        let plain = env.ok(&["export", "--format", format]).stdout;
        assert_eq!(plain.trim_start_matches('\u{feff}'), content);
    }
    // JSON is printed as is (and still ASCII only).
    let v = env.ok(&["export", "--json"]).json();
    assert_eq!(v["hosts"].as_array().unwrap().len(), 2);
}

#[test]
fn import_errors_are_localized_and_write_nothing() {
    let env = Env::new();
    let file = env.root().join("in.csv");
    std::fs::write(&file, "name,mac\r\nok,00:11:22:33:44:55\r\nbad,zz\r\n").unwrap();
    let f = file.to_str().unwrap();
    let o = env.run_nolang(&["--lang", "ja", "import", f], &[]);
    assert_eq!(o.code, 2, "{}", o.stderr);
    assert!(o.stderr.contains("3 行目"), "{}", o.stderr);
    assert!(o.stderr.contains("bad: MAC アドレス"), "{}", o.stderr);
    assert!(!o.stderr.contains("InvalidMac"), "{}", o.stderr);
    assert!(!env.cfg_dir().exists(), "nothing is created");
    let o = env.run(&["import", f, "--json"]);
    assert_eq!(o.code, 2);
    let e = o.error_json();
    assert_eq!(e["error"]["kind"], "invalid_input");
    let m = e["error"]["message"].as_str().unwrap();
    assert!(
        m.starts_with("Cannot import (row 3): bad: MAC address: "),
        "{m}"
    );
    // Dry run: the same error.
    let o = env.run(&["import", f, "--dry-run"]);
    assert_eq!(o.code, 2);
    assert!(
        o.stderr.contains("(row 3): bad: MAC address"),
        "{}",
        o.stderr
    );
    // --skip-invalid: the same localized reason as a warning.
    let o = env.run_nolang(&["--lang", "ja", "import", f, "--skip-invalid"], &[]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(
        o.stderr.contains("スキップ（3 行目）: bad: MAC アドレス"),
        "{}",
        o.stderr
    );

    // A name used twice is found while applying: also localized, and nothing is written.
    let before = std::fs::read(env.cfg_dir().join("config.toml")).unwrap();
    let dup = env.root().join("dup.csv");
    std::fs::write(
        &dup,
        "name,mac\r\nnew1,02:00:00:00:00:31\r\nNEW1,02:00:00:00:00:32\r\n",
    )
    .unwrap();
    let o = env.run_nolang(&["--lang", "ja", "import", dup.to_str().unwrap()], &[]);
    assert_eq!(o.code, 2, "{}", o.stderr);
    assert!(o.stderr.contains("3 行目"), "{}", o.stderr);
    assert!(!o.stderr.contains("DuplicateName"), "{}", o.stderr);
    assert_eq!(
        std::fs::read(env.cfg_dir().join("config.toml")).unwrap(),
        before
    );
    let o = env.run(&["import", dup.to_str().unwrap(), "--skip-invalid", "--json"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(o.json()["skipped"][0]["location"], "row 3");
}

// ------------------------------------------------------------------ PATH (installer contract)

fn path_doc(o: &Out) -> Value {
    o.json()
}

#[test]
fn path_add_remove_status_exit_codes() {
    let env = Env::new();
    let dir = env.root().join("WoL Manager").join("bin");
    let d = dir.to_str().unwrap().to_owned();
    let with_slash = format!("{d}\\");
    let p = |action: &str, dir: &str| {
        env.run(&[
            "path", action, "--scope", "user", "--json", "--lang", "en", dir,
        ])
    };
    let o = p("status", &d);
    assert_eq!(o.code, 1);
    assert_eq!(path_doc(&o)["present"], false);
    let o = p("add", &d);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(path_doc(&o)["result"], "added");
    assert_eq!(path_doc(&o)["dir"], d.as_str());
    // Idempotent, also with a trailing backslash.
    let o = p("add", &d);
    assert_eq!(o.code, 1);
    assert_eq!(path_doc(&o)["result"], "already_present");
    assert_eq!(p("add", &with_slash).code, 1);
    assert_eq!(p("status", &with_slash).code, 0);
    let file: Value =
        serde_json::from_str(&std::fs::read_to_string(env.path_file()).unwrap()).unwrap();
    assert_eq!(file["user"]["value"], d.as_str());
    assert_eq!(file["user"]["kind"], "expand_string");
    let o = p("remove", &with_slash);
    assert_eq!(o.code, 0);
    assert_eq!(path_doc(&o)["result"], "removed");
    assert_eq!(p("remove", &d).code, 1);
    assert_eq!(p("status", &d).code, 1);

    // Bad directory: exit 2.
    let o = p("add", r"C:\a;b");
    assert_eq!(o.code, 2);
    assert_eq!(o.error_json()["error"]["kind"], "invalid_input");

    // Machine scope without elevation: exit 7 (reading still works).
    std::fs::write(env.path_file(), r#"{"machine_requires_elevation": true}"#).unwrap();
    let o = env.run(&[
        "path", "add", "--scope", "machine", "--json", "--lang", "en", &d,
    ]);
    assert_eq!(o.code, 7);
    assert_eq!(o.error_json()["error"]["kind"], "permission");
    assert_eq!(
        env.code(&["path", "status", "--scope", "machine", "--json", &d]),
        1
    );
    assert_eq!(
        env.code(&["path", "remove", "--scope", "machine", "--json", &d]),
        1
    );

    // Human output.
    let o = env.run(&["path", "status", &d]);
    assert!(o.stdout.contains("Not on the user PATH"), "{}", o.stdout);
}

#[test]
fn path_json_is_ascii_for_japanese_folders() {
    let env = Env::new();
    let dir = env.root().join("ツール").join("bin");
    let o = env.run(&["path", "add", "--json", dir.to_str().unwrap()]);
    assert_eq!(o.code, 0);
    let v = path_doc(&o);
    assert_eq!(v["dir"], dir.to_str().unwrap());
    assert!(o.stdout.contains("\\u30c4\\u30fc\\u30eb"));
}

#[test]
fn path_default_dir_is_the_exe_folder() {
    let env = Env::new();
    let o = env.run(&["path", "status", "--json"]);
    assert_eq!(o.code, 1);
    let exe_dir = Path::new(BIN).parent().unwrap();
    assert_eq!(
        PathBuf::from(path_doc(&o)["dir"].as_str().unwrap()),
        std::path::absolute(exe_dir).unwrap()
    );
}

#[test]
fn path_tolerates_the_quote_left_by_a_trailing_backslash() {
    // What NSIS / cmd produce for "C:\...\bin\": the \" is an escaped quote, so the argument
    // arrives as `C:\...\bin"`.
    let env = Env::new();
    let dir = env.root().join("WoL Manager").join("bin");
    let d = dir.to_str().unwrap();
    let mut c = StdCommand::new(BIN);
    c.env(ENV_CONFIG_DIR, env.cfg_dir())
        .env(ENV_PATH_FILE, env.path_file())
        .raw_arg("path add --scope user --json --lang en")
        .raw_arg(format!("\"{d}\\\""));
    let o = c.output().unwrap();
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["dir"], d);
}

#[test]
fn path_refuses_a_dir_that_swallowed_the_following_arguments() {
    // `"C:\...\bin\" --scope machine --json --lang en`: the \" escapes the closing quote, so
    // every later argument ends up in DIR. Nothing may be written (not even to user scope).
    let env = Env::new();
    std::fs::write(env.path_file(), r#"{"machine_requires_elevation": true}"#).unwrap();
    let before = std::fs::read_to_string(env.path_file()).unwrap();
    let dir = env.root().join("inst").join("WoL Manager").join("bin");
    let d = dir.to_str().unwrap();
    for action in ["add", "remove", "status"] {
        let mut c = StdCommand::new(BIN);
        c.env(ENV_CONFIG_DIR, env.cfg_dir())
            .env(ENV_PATH_FILE, env.path_file())
            .env(ENV_LANG, "en")
            .env("NO_COLOR", "1")
            .raw_arg(format!("path {action}"))
            .raw_arg(format!("\"{d}\\\""))
            .raw_arg("--scope machine --json --lang en");
        let o = c.output().unwrap();
        let stderr = String::from_utf8_lossy(&o.stderr);
        assert_eq!(o.status.code(), Some(2), "{action}: {stderr}");
        assert!(o.stdout.is_empty(), "{action}");
        assert!(stderr.contains("cannot be put on PATH"), "{stderr}");
        assert!(stderr.contains("Leave out the trailing"), "{stderr}");
    }
    assert_eq!(std::fs::read_to_string(env.path_file()).unwrap(), before);
    // Without the trailing backslash the same command line works as intended (exit 7).
    let mut c = StdCommand::new(BIN);
    c.env(ENV_CONFIG_DIR, env.cfg_dir())
        .env(ENV_PATH_FILE, env.path_file())
        .raw_arg(format!("path add \"{d}\" --scope machine --json --lang en"));
    assert_eq!(c.output().unwrap().status.code(), Some(7));
}

#[test]
fn path_never_touches_the_settings() {
    let env = Env::new();
    let dir = env.root().join("x").join("bin");
    let d = dir.to_str().unwrap();
    for action in ["status", "add", "status", "remove"] {
        env.run(&["path", action, d]);
    }
    assert!(!env.cfg_dir().exists(), "path created the settings folder");
    // An existing settings folder stays untouched (no lock file, no probe file).
    std::fs::create_dir_all(env.cfg_dir()).unwrap();
    std::fs::write(env.cfg_dir().join("config.toml"), "not toml [").unwrap();
    assert_eq!(env.run(&["path", "add", d]).code, 0);
    assert_eq!(env.run(&["path", "status", d]).code, 0);
    let entries: Vec<_> = std::fs::read_dir(env.cfg_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(entries, ["config.toml"]);
}

#[test]
fn path_status_with_piped_or_closed_stdin_is_fast() {
    let env = Env::new();
    let args = [
        "path", "status", "--scope", "user", "--json", "--lang", "en",
    ];
    let code = run_with_closed_stdin(&env, &args, Duration::from_secs(5));
    assert!(matches!(code, Some(0 | 1)), "closed stdin: {code:?}");

    let start = Instant::now();
    let mut c = env.raw();
    c.args(args)
        .write_stdin("y\n")
        .timeout(Duration::from_secs(5));
    let o = Env::exec(c);
    assert!(matches!(o.code, 0 | 1), "piped stdin: {}", o.stderr);
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(!env.cfg_dir().exists());
}

// ------------------------------------------------------------------ wake / status / listen

#[test]
fn wake_dry_run_shows_the_plan_and_the_packet() {
    let env = Env::new();
    let o = env.ok(&[
        "wake",
        "--mac",
        "AA:BB:CC:DD:EE:FF",
        "--to",
        "127.0.0.1:40009",
        "--no-broadcast",
        "--dry-run",
    ]);
    assert!(o.stdout.contains("127.0.0.1:40009"), "{}", o.stdout);
    assert!(o.stdout.contains("explicit target"), "{}", o.stdout);
    assert!(
        o.stdout.contains("FF FF FF FF FF FF AA BB CC DD EE FF"),
        "{}",
        o.stdout
    );
    assert!(o.stdout.contains("102 bytes x 3"), "{}", o.stdout);

    let v = env
        .ok(&[
            "wake",
            "--mac",
            "AA:BB:CC:DD:EE:FF",
            "--to",
            "127.0.0.1:40009",
            "--no-broadcast",
            "--dry-run",
            "--json",
            "--repeat",
            "２",
            "--secureon",
            "01:02:03:04:05:06",
        ])
        .json();
    assert_eq!(v["dry_run"], true);
    let plan = &v["plans"][0];
    assert_eq!(plan["packet_len"], 108);
    assert_eq!(plan["repeat"], 2);
    assert_eq!(plan["sends"][0]["dest"], "127.0.0.1:40009");
    assert_eq!(plan["sends"][0]["via"], "routed");
    assert!(
        plan["packet_hex"]
            .as_str()
            .unwrap()
            .starts_with("FF FF FF FF FF FF AA BB")
    );

    // Registered host by name, deduplicated with its MAC.
    env.ok(&[
        "add",
        "NAS",
        "--mac",
        "00:11:22:33:44:55",
        "--to",
        "127.0.0.1:40010",
    ]);
    let v = env
        .ok(&[
            "wake",
            "NAS",
            "00-11-22-33-44-55",
            "--no-broadcast",
            "--dry-run",
            "--json",
        ])
        .json();
    assert_eq!(v["plans"].as_array().unwrap().len(), 1);
    assert_eq!(v["plans"][0]["label"], "NAS");
    assert_eq!(v["plans"][0]["sends"][0]["dest"], "127.0.0.1:40010");
}

#[test]
fn wake_errors() {
    let env = Env::new();
    assert_eq!(env.code(&["wake"]), 2);
    assert_eq!(env.code(&["wake", "--all", "--dry-run"]), 3);
    // Nothing to send to: network error (5), dry run too.
    assert_eq!(
        env.code(&["wake", "--mac", "AA:BB:CC:DD:EE:FF", "--no-broadcast"]),
        5
    );
    let o = env.run(&[
        "wake",
        "--mac",
        "AA:BB:CC:DD:EE:FF",
        "--no-broadcast",
        "--dry-run",
        "--json",
    ]);
    assert_eq!(o.code, 5);
    assert_eq!(o.json()["plans"][0]["error"], "no_destinations");
    // --wait needs something to check.
    assert_eq!(
        env.code(&[
            "wake",
            "AA:BB:CC:DD:EE:FF",
            "--no-broadcast",
            "--to",
            "127.0.0.1:9",
            "--wait"
        ]),
        2
    );
}

fn receiver() -> (UdpSocket, u16) {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let port = s.local_addr().unwrap().port();
    (s, port)
}

#[test]
fn wake_sends_real_packets_to_loopback() {
    let env = Env::new();
    let (sock, port) = receiver();
    let to = format!("127.0.0.1:{port}");
    let o = env.ok(&[
        "wake",
        "--mac",
        "AA:BB:CC:DD:EE:FF",
        "--to",
        &to,
        "--no-broadcast",
        "--repeat",
        "3",
        "--interval-ms",
        "0",
        "--json",
    ]);
    let v = o.json();
    assert_eq!(v["reports"][0]["outcome"], "ok");
    assert_eq!(v["reports"][0]["sent"], 3);
    let mut buf = [0u8; 512];
    for _ in 0..3 {
        let (n, _) = sock.recv_from(&mut buf).expect("a magic packet");
        assert_eq!(n, 102);
        assert_eq!(&buf[..6], &[0xFF; 6]);
        assert_eq!(&buf[6..12], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(&buf[96..102], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }
    // Human output.
    let o = env.ok(&[
        "wake",
        "--mac",
        "AA:BB:CC:DD:EE:FF",
        "--to",
        &to,
        "--no-broadcast",
        "--repeat",
        "1",
    ]);
    assert!(
        o.stdout.contains("Magic packet sent to AA:BB:CC:DD:EE:FF"),
        "{}",
        o.stdout
    );
}

#[test]
fn listen_receives_what_wake_sends() {
    let env = Env::new();
    let port = {
        let (s, p) = receiver();
        drop(s);
        p
    };
    let p = port.to_string();
    let mut child = StdCommand::new(BIN)
        .env(ENV_CONFIG_DIR, env.cfg_dir())
        .env("NO_COLOR", "1")
        .args([
            "--lang",
            "en",
            "listen",
            "--bind",
            "127.0.0.1",
            "--port",
            &p,
            "--count",
            "3",
            "--timeout",
            "30s",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let ready = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("listen prints a line");
    assert!(ready.contains("Listening on UDP port"), "{ready}");

    env.ok(&[
        "wake",
        "--mac",
        "AA:BB:CC:DD:EE:FF",
        "--to",
        &format!("127.0.0.1:{port}"),
        "--no-broadcast",
        "--repeat",
        "3",
    ]);
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "{stdout}");
    for l in lines {
        assert!(
            l.contains("AA:BB:CC:DD:EE:FF") && l.contains("(102 bytes)"),
            "{l}"
        );
    }
}

#[test]
fn listen_times_out_with_exit_4() {
    let env = Env::new();
    let port = {
        let (s, p) = receiver();
        drop(s);
        p
    };
    let o = env.run(&[
        "listen",
        "--bind",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--count",
        "1",
        "--timeout",
        "500ms",
        "--json",
    ]);
    assert_eq!(o.code, 4);
    let v = o.json();
    assert_eq!(v["timed_out"], true);
    assert_eq!(v["packets"], serde_json::json!([]));
}

#[test]
fn wait_times_out_with_exit_4() {
    let env = Env::new();
    let (_sock, port) = receiver();
    env.ok(&[
        "add",
        "Lab",
        "--mac",
        "02:00:00:00:00:01",
        "--address",
        "192.0.2.1",
    ]);
    let start = Instant::now();
    let o = env.run(&[
        "wake",
        "Lab",
        "--no-broadcast",
        "--to",
        &format!("127.0.0.1:{port}"),
        "--wait",
        "--timeout",
        "2s",
        "--poll",
        "500ms",
        "--probe",
        "icmp",
    ]);
    assert_eq!(o.code, 4, "{}\n{}", o.stdout, o.stderr);
    assert!(
        o.stdout.contains("did not respond within 2 s"),
        "{}",
        o.stdout
    );
    assert!(start.elapsed() < Duration::from_secs(30));

    let o = env.run(&[
        "wake",
        "Lab",
        "--no-broadcast",
        "--to",
        &format!("127.0.0.1:{port}"),
        "--wait",
        "--timeout",
        "1s",
        "--probe",
        "icmp",
        "--json",
    ]);
    assert_eq!(o.code, 4);
    assert_eq!(o.json()["wait"][0]["outcome"]["result"], "timed_out");
}

#[test]
fn wait_succeeds_for_loopback() {
    let env = Env::new();
    let (_sock, port) = receiver();
    env.ok(&[
        "add",
        "Loop",
        "--mac",
        "02:00:00:00:00:02",
        "--address",
        "127.0.0.1",
        "--probe",
        "icmp",
    ]);
    let o = env.run(&[
        "wake",
        "Loop",
        "--no-broadcast",
        "--to",
        &format!("127.0.0.1:{port}"),
        "--wait",
        "--timeout",
        "20s",
        "--json",
    ]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(o.json()["wait"][0]["outcome"]["result"], "up");
}

#[test]
fn status_probes_hosts() {
    let env = Env::new();
    env.ok(&[
        "add",
        "Loop",
        "--mac",
        "02:00:00:00:00:02",
        "--address",
        "127.0.0.1",
    ]);
    env.ok(&[
        "add",
        "Lab",
        "--mac",
        "02:00:00:00:00:01",
        "--address",
        "192.0.2.1",
    ]);
    env.ok(&["add", "NoAddr", "--mac", "02:00:00:00:00:03"]);
    let o = env.run(&["status", "Loop", "NoAddr", "--probe", "icmp", "--json"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let v = o.json();
    assert_eq!(v[0]["status"], "online");
    assert_eq!(v[1]["status"], "not_monitored");
    // Something down: exit 1.
    let o = env.run(&["st", "--probe", "icmp", "--timeout", "300ms"]);
    assert_eq!(o.code, 1, "{}", o.stderr);
    assert!(
        o.stdout.contains("Online") && o.stdout.contains("Offline"),
        "{}",
        o.stdout
    );
    assert!(o.stderr.contains("1 of 2 online"), "{}", o.stderr);
    // A bare IPv4 address.
    assert_eq!(env.code(&["status", "127.0.0.1", "--probe", "icmp"]), 0);
}

#[test]
fn interfaces_and_arp() {
    let env = Env::new();
    let o = env.ok(&["interfaces", "--all", "--json"]);
    assert!(o.json().is_array());
    env.ok(&["if"]);
    assert_eq!(env.code(&["arp", "not-an-ip"]), 2);
    // TEST-NET-1 is never on a local subnet.
    assert_eq!(env.code(&["arp", "192.0.2.1"]), 3);
}

#[test]
fn completions_register_both_command_names() {
    let env = Env::new();
    let o = env.ok(&["completions"]);
    assert!(
        o.stdout.contains("-CommandName 'wolm', 'wolm.exe'"),
        "{}",
        o.stdout
    );
    assert!(o.stdout.contains("'wolm;wake'"));
    let o = env.ok(&["completions", "bash"]);
    assert!(o.stdout.contains("wolm"));
}

// ------------------------------------------------------------------ portable / gui (copied exe)

/// `<tmp>\<name>\bin\wolm.exe`, optionally with the app exe and an uninstaller.
fn app_layout(env: &Env, name: &str, gui: Option<&[u8]>, installed: bool) -> (PathBuf, PathBuf) {
    let root = env.root().join(name);
    std::fs::create_dir_all(root.join("bin")).unwrap();
    let cli = root.join("bin").join("wolm.exe");
    std::fs::copy(BIN, &cli).unwrap();
    if let Some(bytes) = gui {
        std::fs::write(root.join("wol-manager.exe"), bytes).unwrap();
    }
    if installed {
        std::fs::write(root.join("uninstall.exe"), b"").unwrap();
    }
    (root, cli)
}

fn run_exe(exe: &Path, args: &[&str], config_dir: Option<&Path>) -> Out {
    let mut c = Command::new(exe);
    c.env_remove(ENV_CONFIG_DIR)
        .env_remove(ENV_LANG)
        .env("NO_COLOR", "1")
        .timeout(Duration::from_secs(60))
        .args(["--lang", "en"])
        .args(args);
    if let Some(d) = config_dir {
        c.env(ENV_CONFIG_DIR, d);
    }
    Env::exec(c)
}

#[test]
fn portable_enable_status_disable() {
    let env = Env::new();
    let (root, cli) = app_layout(&env, "app", Some(b""), false);
    assert_eq!(run_exe(&cli, &["portable", "status"], None).code, 1);

    // Enable with the current settings copied from a custom folder.
    env.ok(&["add", "Carry", "--mac", "02:00:00:00:00:21"]);
    let o = run_exe(
        &cli,
        &["portable", "enable", "--copy-settings"],
        Some(&env.cfg_dir()),
    );
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(root.join("wol-manager.portable").is_file());
    assert!(root.join("data").join("config.toml").is_file());
    let o = run_exe(&cli, &["portable", "status", "--json"], None);
    assert_eq!(o.code, 0);
    assert_eq!(o.json()["active"], true);

    // Without overrides the copy now uses <root>\data.
    let v = run_exe(&cli, &["config", "path", "--json"], None).json();
    assert_eq!(v["source"], "portable");
    assert_eq!(PathBuf::from(v["dir"].as_str().unwrap()), root.join("data"));
    assert_eq!(
        names(&run_exe(&cli, &["list", "--json"], None).json()),
        ["Carry"]
    );

    assert_eq!(run_exe(&cli, &["portable", "enable"], None).code, 1);
    assert_eq!(run_exe(&cli, &["portable", "disable"], None).code, 0);
    assert!(!root.join("wol-manager.portable").exists());
    assert!(root.join("data").is_dir(), "data is kept");
    assert_eq!(run_exe(&cli, &["portable", "disable"], None).code, 1);
}

#[test]
fn portable_is_refused_on_an_installed_copy() {
    let env = Env::new();
    let (root, cli) = app_layout(&env, "inst", Some(b""), true);
    let o = run_exe(
        &cli,
        &["portable", "enable", "--json"],
        Some(&env.cfg_dir()),
    );
    assert_eq!(o.code, 7, "{}", o.stderr);
    assert_eq!(o.error_json()["error"]["kind"], "unsupported");
    assert!(!root.join("wol-manager.portable").exists());
    let o = run_exe(
        &cli,
        &["portable", "status", "--json"],
        Some(&env.cfg_dir()),
    );
    assert_eq!(o.json()["installed"], true);
}

/// The gui tests share the session-wide "running app" block: one at a time.
static GUI_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Takes [`GUI_TESTS`]; `None` when a WoL Manager of the person running the tests is open
/// (with its own settings the gui tests would, correctly, be refused).
fn gui_test_lock() -> Option<std::sync::MutexGuard<'static, ()>> {
    let guard = GUI_TESTS.lock().unwrap_or_else(|p| p.into_inner());
    if wol_core::instance::running_gui_settings_dir().is_some() {
        eprintln!("skipped: WoL Manager is running on this machine");
        return None;
    }
    Some(guard)
}

/// `wolm gui` must not leave a caller that reads its output through a pipe waiting for the
/// app: the app must not inherit wolm's stdout / stderr (it runs on, e.g. in the tray).
#[test]
fn gui_does_not_keep_the_callers_pipe_open() {
    let Some(_gui) = gui_test_lock() else {
        return;
    };
    let stub = Path::new(BIN)
        .parent()
        .unwrap()
        .join("examples")
        .join("gui_stub.exe");
    assert!(
        stub.is_file(),
        "{} is missing (`cargo test` builds the examples)",
        stub.display()
    );
    let env = Env::new();
    let (_root, cli) = app_layout(&env, "pipe", Some(&std::fs::read(&stub).unwrap()), false);
    let cfg = env.root().join("pipe-cfg");
    std::fs::create_dir_all(&cfg).unwrap();
    struct Stop(PathBuf);
    impl Drop for Stop {
        fn drop(&mut self) {
            let _ = std::fs::write(&self.0, b"");
        }
    }
    let _stop = Stop(cfg.join("stop"));

    let mut child = StdCommand::new(&cli)
        .args(["--lang", "en", "gui", "--json", "--config-dir"])
        .arg(&cfg)
        .env_remove(ENV_CONFIG_DIR)
        .env_remove(ENV_LANG)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut o = String::new();
        let _ = out.read_to_string(&mut o);
        let mut e = String::new();
        let _ = err.read_to_string(&mut e);
        let _ = tx.send((o, e));
    });
    let (stdout, stderr) = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("stdout / stderr of `wolm gui` stayed open while the app runs");
    assert!(child.wait().unwrap().success(), "{stderr}");
    let v: Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["pid"].as_u64().is_some(), "{v}");
    // The pipe closed although the stand-in app is still running.
    let start = Instant::now();
    while !cfg.join("running").exists() && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        cfg.join("running").exists(),
        "the stand-in app did not start"
    );
    assert!(
        !cfg.join("exited").exists(),
        "the stand-in app ended too early"
    );
}

/// The app is a single instance: `wolm gui` for other settings than the running app's says
/// so (exit 7) instead of reporting a start that would only show the other window.
#[test]
fn gui_refuses_other_settings_than_the_running_apps() {
    let Some(_gui) = gui_test_lock() else {
        return;
    };
    let env = Env::new();
    let (_root, cli) = app_layout(&env, "single", Some(&std::fs::read(BIN).unwrap()), false);
    let running = env.root().join("running-cfg");
    // What the running app publishes (see wol_core::instance).
    let _beacon = wol_core::instance::SettingsBeacon::create(&running).unwrap();
    let other = env.root().join("other-cfg");
    let mut c = Command::new(&cli);
    c.env_remove(ENV_CONFIG_DIR)
        .env_remove(ENV_LANG)
        .env("NO_COLOR", "1")
        .timeout(Duration::from_secs(60))
        .args(["--lang", "en", "gui", "--json", "--config-dir"])
        .arg(&other);
    let o = Env::exec(c);
    assert_eq!(o.code, 7, "{}", o.stderr);
    let e = o.error_json();
    assert_eq!(e["error"]["kind"], "unsupported");
    assert!(
        e["error"]["message"]
            .as_str()
            .unwrap()
            .contains("already running"),
        "{e}"
    );
    // The same folder (spelled differently) is fine: the running window is shown.
    let mut c = Command::new(&cli);
    c.env_remove(ENV_CONFIG_DIR)
        .env_remove(ENV_LANG)
        .env("NO_COLOR", "1")
        .timeout(Duration::from_secs(60))
        .args(["--lang", "en", "gui", "--json", "--config-dir"])
        .arg(format!(
            "{}\\",
            running.display().to_string().to_uppercase()
        ));
    let o = Env::exec(c);
    assert_eq!(o.code, 0, "{}", o.stderr);
}

#[test]
fn gui_starts_the_app_next_to_wolm() {
    let Some(_gui) = gui_test_lock() else {
        return;
    };
    let env = Env::new();
    let (_root, cli) = app_layout(&env, "nogui", None, false);
    assert_eq!(run_exe(&cli, &["gui"], Some(&env.cfg_dir())).code, 3);

    // A stand-in app (a copy of wolm itself: it exits at once with a usage error).
    let exe = std::fs::read(BIN).unwrap();
    let (root, cli) = app_layout(&env, "withgui", Some(&exe), false);
    let o = run_exe(&cli, &["gui", "--json", "--config-dir", "cfg"], None);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let v = o.json();
    assert_eq!(
        PathBuf::from(v["path"].as_str().unwrap()),
        root.join("wol-manager.exe")
    );
    assert_eq!(
        PathBuf::from(v["config_dir"].as_str().unwrap()),
        std::path::absolute("cfg").unwrap()
    );

    // The app starts in its own folder: a relative WOL_MANAGER_CONFIG_DIR is handed on as
    // the absolute folder this run resolved (relative to the current folder).
    let work = env.root().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let mut c = Command::new(&cli);
    c.env(ENV_CONFIG_DIR, "rel-cfg")
        .env_remove(ENV_LANG)
        .env("NO_COLOR", "1")
        .current_dir(&work)
        .timeout(Duration::from_secs(60))
        .args(["--lang", "en", "gui", "--json"]);
    let o = Env::exec(c);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(
        PathBuf::from(o.json()["config_dir"].as_str().unwrap()),
        work.join("rel-cfg")
    );

    // Portable (and AppData): the app finds the folder itself.
    std::fs::write(root.join("wol-manager.portable"), b"").unwrap();
    let o = run_exe(&cli, &["gui", "--json"], None);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.json()["config_dir"].is_null());
}

// ------------------------------------------------------------------ review fixes

#[test]
fn help_examples_and_settings_order() {
    let env = Env::new();
    let o = env.ok(&["--help"]);
    // `||` is not a statement separator in Windows PowerShell 5.1: the example must work there.
    assert!(
        o.stdout.contains("if ($LASTEXITCODE -ne 0)"),
        "{}",
        o.stdout
    );
    for l in o.stdout.lines().filter(|l| l.contains("||")) {
        assert!(l.contains("(cmd.exe)"), "{l}");
    }
    // Resolution order: flag > WOL_MANAGER_CONFIG_DIR > portable data folder > AppData.
    let flat = o.stdout.split_whitespace().collect::<Vec<_>>().join(" ");
    let env_pos = flat.find("WOL_MANAGER_CONFIG_DIR").unwrap();
    let portable_pos = flat.find("portable marker").unwrap();
    let appdata_pos = flat.find(r"%APPDATA%\wol-manager").unwrap();
    assert!(
        env_pos < portable_pos && portable_pos < appdata_pos,
        "{flat}"
    );
}

/// A JSON file whose unknown keys nest deeper than the TOML parser accepts used to make
/// config.toml unreadable for good.
#[test]
fn deeply_nested_imports_never_break_the_settings() {
    let env = Env::new();
    env.ok(&["add", "d", "--mac", "00:11:22:33:44:dd"]);
    let deep = env.root().join("deep.json");
    std::fs::write(
        &deep,
        format!(
            r#"{{"hosts":[{{"name":"d","mac":"00:11:22:33:44:dd","deep":{}1{}}}]}}"#,
            "[".repeat(100),
            "]".repeat(100)
        ),
    )
    .unwrap();
    let f = deep.to_str().unwrap();
    for args in [
        &["import", f, "--dry-run"][..],
        &["import", f, "--replace"][..],
        &["import", f][..],
    ] {
        let o = env.run(args);
        assert_eq!(o.code, 2, "{args:?}: {}", o.stderr);
        assert!(o.stderr.contains("nested"), "{}", o.stderr);
    }
    assert_eq!(names(&env.ok(&["list", "--json"]).json()), ["d"]);
    env.ok(&["add", "x", "--mac", "00:11:22:33:44:ee"]);
}

#[test]
fn dry_run_hides_the_secureon_password() {
    let env = Env::new();
    env.ok(&[
        "add",
        "pc1",
        "--mac",
        "00:11:22:33:44:55",
        "--secureon",
        "0A:0B:0C:0D:0E:0F",
        "--to",
        "127.0.0.1:40009",
        "--no-broadcast",
    ]);
    let o = env.ok(&["wake", "pc1", "--dry-run"]);
    assert!(o.stdout.contains("** ** ** ** ** **"), "{}", o.stdout);
    let v = env.ok(&["wake", "pc1", "--dry-run", "--json"]);
    assert_eq!(v.json()["plans"][0]["has_secureon"], true);
    assert_eq!(v.json()["plans"][0]["packet_len"], 108);
    for out in [&o.stdout, &v.stdout, &o.stderr] {
        assert!(!out.contains("0A 0B 0C"), "{out}");
        assert!(!out.contains("0A:0B:0C"), "{out}");
    }
}

/// Names and notes from a hand-edited file or an import reach the terminal without the
/// control characters that would set the title, clear the screen or hide text.
#[test]
fn terminal_escapes_in_host_data_are_not_printed() {
    let env = Env::new();
    env.write_config(concat!(
        "schema_version = 1\n\n[[hosts]]\n",
        "id = \"11111111-1111-4111-8111-111111111111\"\n",
        "name = \"evil\\u001b]0;PWNED\\u0007\\u001b[8mX\"\n",
        "mac = \"00:11:22:33:44:66\"\n",
        "notes = \"n\\u001b[2Jote\"\n",
        "targets = [\"127.0.0.1:40009\"]\n",
        "broadcast = false\n",
    ));
    for args in [
        &["show", "11111111"][..],
        &["wake", "11111111", "--dry-run"][..],
        &["list"][..],
    ] {
        let mut c = env.raw();
        c.env_remove("NO_COLOR")
            .env("CLICOLOR_FORCE", "1")
            .args(["--lang", "en"])
            .args(args);
        let o = Env::exec(c);
        assert_eq!(o.code, 0, "{args:?}: {}", o.stderr);
        for out in [&o.stdout, &o.stderr] {
            assert!(!out.contains('\u{7}'), "{args:?}: {out:?}");
            assert!(!out.contains("\u{1b}]"), "{args:?}: {out:?}");
            assert!(!out.contains("\u{1b}[8m"), "{args:?}: {out:?}");
            assert!(!out.contains("\u{1b}[2J"), "{args:?}: {out:?}");
        }
    }
    // Imported notes lose them for good.
    let csv = env.root().join("ctl.csv");
    std::fs::write(
        &csv,
        "name,mac,notes\r\nctl,02:00:00:00:00:71,\"n\u{1b}[31mote\"\r\n",
    )
    .unwrap();
    env.ok(&["import", csv.to_str().unwrap()]);
    let v = env.ok(&["show", "ctl", "--json"]).json();
    assert_eq!(v["notes"], "n[31mote");
}

#[test]
fn port_lists_and_timeouts_are_limited() {
    let env = Env::new();
    let seventeen: Vec<String> = (1..=17).map(|p| p.to_string()).collect();
    let o = env.run(&[
        "add",
        "many",
        "--mac",
        "02:00:00:00:00:81",
        "--tcp-port",
        &seventeen.join(","),
    ]);
    assert_eq!(o.code, 2, "{}", o.stderr);
    assert!(o.stderr.contains("at most 16 ports"), "{}", o.stderr);
    let o = env.run(&["config", "set", "probe.tcp_ports", &seventeen.join(",")]);
    assert_eq!(o.code, 2, "{}", o.stderr);
    // --timeout 0 used to report every live host as offline.
    for t in ["0", "0.0001ms", "50ms", "31s"] {
        let o = env.run(&["status", "--timeout", t]);
        assert_eq!(o.code, 2, "{t}: {}", o.stderr);
        assert!(o.stderr.contains("100ms..=30s"), "{}", o.stderr);
    }
}

#[test]
fn multicast_macs_get_a_precise_reason() {
    let env = Env::new();
    let o = env.run(&[
        "wake",
        "--mac",
        "11-22-33-44-55-66",
        "--to",
        "127.0.0.1:40009",
        "--no-broadcast",
        "--dry-run",
    ]);
    assert_eq!(o.code, 2);
    assert!(o.stderr.contains("Multicast, broadcast"), "{}", o.stderr);
    let o = env.run_nolang(
        &["--lang", "ja", "add", "x", "--mac", "FF:FF:FF:FF:FF:FF"],
        &[],
    );
    assert_eq!(o.code, 2);
    assert!(o.stderr.contains("マルチキャスト"), "{}", o.stderr);
}

/// `listen` binds 0.0.0.0 by default: one large datagram from anywhere must not end it.
#[test]
fn listen_ignores_oversized_datagrams() {
    let env = Env::new();
    let port = {
        let (s, p) = receiver();
        drop(s);
        p
    };
    let mut child = StdCommand::new(BIN)
        .env(ENV_CONFIG_DIR, env.cfg_dir())
        .args([
            "--lang",
            "en",
            "--json",
            "listen",
            "--bind",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--count",
            "1",
            "--timeout",
            "30s",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut magic = vec![0xFFu8; 6];
    for _ in 0..16 {
        magic.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x61]);
    }
    let big = vec![0x41u8; 3000];
    let start = Instant::now();
    // Until listen has bound the port, datagrams are lost: repeat, oversized ones first.
    while child.try_wait().unwrap().is_none() && start.elapsed() < Duration::from_secs(20) {
        let _ = sender.send_to(&big, ("127.0.0.1", port));
        let _ = sender.send_to(&big, ("127.0.0.1", port));
        std::thread::sleep(Duration::from_millis(100));
        let _ = sender.send_to(&magic, ("127.0.0.1", port));
        std::thread::sleep(Duration::from_millis(100));
    }
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["received"], 1);
    assert_eq!(v["packets"][0]["mac"], "02:00:00:00:00:61");
}

/// Export errors are about the export file, and an existing "<name>.tmp" survives.
#[test]
fn export_errors_name_the_file() {
    let env = Env::new();
    env.ok(&["add", "e", "--mac", "02:00:00:00:00:91"]);
    let missing = env.root().join("no such folder").join("out.csv");
    let o = env.run(&["export", "-o", missing.to_str().unwrap()]);
    assert_eq!(o.code, 6, "{}", o.stderr);
    assert!(o.stderr.contains("out.csv"), "{}", o.stderr);
    assert!(!o.stderr.contains("settings folder"), "{}", o.stderr);
    let out = env.root().join("out.csv");
    std::fs::write(env.root().join("out.csv.tmp"), "precious").unwrap();
    env.ok(&["export", "-o", out.to_str().unwrap()]);
    assert_eq!(
        std::fs::read_to_string(env.root().join("out.csv.tmp")).unwrap(),
        "precious"
    );
}

/// A folder every user may change is not put on the system PATH without --force, and a
/// user PATH entry for it gets a warning.
#[test]
fn path_add_warns_about_folders_every_user_can_change() {
    let env = Env::new();
    let shared = env.root().join("shared tools").join("bin");
    std::fs::create_dir_all(&shared).unwrap();
    let st = StdCommand::new("icacls")
        .arg(env.root().join("shared tools"))
        .args(["/grant", "*S-1-5-11:(OI)(CI)M", "/Q"])
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success());
    let d = shared.to_str().unwrap();
    let o = env.run(&["path", "add", "--scope", "machine", "--json", d]);
    assert_eq!(o.code, 2, "{}", o.stderr);
    assert!(
        o.error_json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--force")
    );
    let o = env.run(&["path", "add", "--scope", "machine", "--force", d]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(
        o.stderr.contains("Every user of this computer"),
        "{}",
        o.stderr
    );
    let o = env.run(&["path", "add", "--scope", "user", d]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(
        o.stderr.contains("Every user of this computer"),
        "{}",
        o.stderr
    );
    // A private folder: no warning.
    let private = env.root().join("mine").join("bin");
    std::fs::create_dir_all(&private).unwrap();
    let o = env.run(&[
        "path",
        "add",
        "--scope",
        "machine",
        private.to_str().unwrap(),
    ]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(!o.stderr.contains("Every user"), "{}", o.stderr);
}

// ------------------------------------------------------------------ remote management (v0.2.0)
//
// Remote operations run against the scripted fake (`WOL_MANAGER_REMOTE_FAKE`), which answers
// and logs every call without touching the network, or, for error paths with the real
// backends, against a closed loopback port / the TEST-NET address 192.0.2.1. Passwords go to a
// JSON file (`WOL_MANAGER_SECRET_BACKEND_FILE`), never to Windows Credential Manager.

use serde_json::json;

/// A valid SSH host key that differs from the fake's default one.
const OTHER_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";

impl Env {
    fn fake_script(&self) -> PathBuf {
        self.root().join("fake.json")
    }

    fn fake_log(&self) -> PathBuf {
        self.root().join("fake.log")
    }

    /// Replaces the fake's script (the call log is kept).
    fn set_fake(&self, script: Value) {
        let mut s = script;
        s["log"] = json!(self.fake_log().display().to_string());
        std::fs::write(self.fake_script(), s.to_string()).unwrap();
    }

    /// `wolm --lang en ARGS` with the remote fake (an empty script unless one was set).
    fn run_fake(&self, args: &[&str]) -> Out {
        if !self.fake_script().exists() {
            self.set_fake(json!({}));
        }
        let mut c = self.raw();
        c.env(ENV_REMOTE_FAKE, self.fake_script())
            .args(["--lang", "en"])
            .args(args);
        Env::exec(c)
    }

    /// `wolm --lang en ARGS` with `stdin` as standard input.
    fn run_stdin(&self, args: &[&str], stdin: &[u8]) -> Out {
        let mut c = self.raw();
        c.args(["--lang", "en"])
            .args(args)
            .write_stdin(stdin.to_vec());
        Env::exec(c)
    }

    /// Every call the fake received.
    fn calls(&self) -> Vec<Value> {
        std::fs::read_to_string(self.fake_log())
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn calls_of(&self, op: &str) -> Vec<Value> {
        self.calls().into_iter().filter(|c| c["op"] == op).collect()
    }

    fn clear_calls(&self) {
        let _ = std::fs::remove_file(self.fake_log());
    }

    /// The test secret store.
    fn secrets(&self) -> Value {
        match std::fs::read_to_string(self.secret_file()) {
            Ok(t) => serde_json::from_str(&t).unwrap(),
            Err(_) => json!({}),
        }
    }

    /// The test secret store without the sign-in confirmations (`…/sign-in`, no secret).
    fn passwords(&self) -> Value {
        let mut v = self.secrets();
        if let Some(m) = v.as_object_mut() {
            m.retain(|k, _| !k.ends_with("/sign-in"));
        }
        v
    }

    /// Targets of the sign-in confirmations in the test store.
    fn sign_ins(&self) -> Vec<String> {
        self.secrets()
            .as_object()
            .map(|m| {
                m.keys()
                    .filter(|k| k.ends_with("/sign-in"))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The id of a host.
    fn id_of(&self, name: &str) -> String {
        self.ok(&["show", name, "--json"]).json()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// A host with remote management.
    fn managed(&self, name: &str, mac: &str, kind: &str, address: &str) {
        self.ok(&["add", name, "--mac", mac, "--address", address]);
        self.ok(&["remote", "set", name, "--kind", kind]);
    }
}

fn assert_code(o: &Out, code: i32, what: &str) {
    assert_eq!(
        o.code, code,
        "{what}\nstdout: {}\nstderr: {}",
        o.stdout, o.stderr
    );
}

/// A loopback TCP port nothing listens on.
fn closed_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn is_iso_local(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() == 25
        && b[4] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && (b[19] == b'+' || b[19] == b'-')
        && b[22] == b':'
}

#[test]
fn remote_set_show_clear_round_trip() {
    let env = Env::new();
    env.ok(&[
        "add",
        "PC",
        "--mac",
        "02:00:00:00:00:01",
        "--address",
        "192.0.2.10",
    ]);
    // Not set up: `remote show` exits 1 with `remote: null`.
    let o = env.run(&["remote", "show", "PC", "--json"]);
    assert_code(&o, 1, "show unmanaged");
    assert!(o.json()["remote"].is_null());
    assert_eq!(env.code(&["remote", "set", "PC"]), 2, "--kind needed");
    assert_eq!(env.code(&["remote", "set", "PC", "--kind", "vnc"]), 2);

    let v = env
        .ok(&[
            "remote",
            "set",
            "PC",
            "--kind",
            "windows",
            "--user",
            r"PC\admin",
            "--address",
            "198.51.100.2",
            "--json",
        ])
        .json();
    assert_eq!(v["changed"], true);
    assert_eq!(v["remote"]["kind"], "windows");
    assert_eq!(v["remote"]["user"], r"PC\admin");
    assert_eq!(v["remote"]["address"], "198.51.100.2");
    assert_eq!(v["remote"]["effective_address"], "198.51.100.2");
    assert!(v["remote"]["port"].is_null() && v["remote"]["sudo"].is_null());
    // Only given fields change; the same values again change nothing (exit 1).
    assert_eq!(env.code(&["remote", "set", "PC", "--user", r"PC\admin"]), 1);
    // SSH-only flags and invalid values: exit 2, nothing written.
    assert_eq!(env.code(&["remote", "set", "PC", "--port", "22"]), 2);
    let o = env.run(&["remote", "set", "PC", "--user", "bad:user"]);
    assert_code(&o, 2, "bad user");
    let o = env.ok(&["remote", "show", "PC"]);
    assert!(o.stdout.contains("198.51.100.2"), "{}", o.stdout);
    assert!(o.stdout.contains("not stored"), "{}", o.stdout);
    // An account other than this sign-in needs its password before anything connects.
    let o = env.run(&["remote", "set", "PC", "--address", "198.51.100.3"]);
    assert_code(&o, 0, "note about the password");
    assert!(
        o.stderr.contains(r"Store the password of PC\admin"),
        "{}",
        o.stderr
    );
    env.ok(&["remote", "set", "PC", "--address", "198.51.100.2"]);
    // `show` / `list` include it.
    assert_eq!(
        env.ok(&["show", "PC", "--json"]).json()["remote"]["kind"],
        "windows"
    );
    assert!(env.ok(&["show", "PC"]).stdout.contains("Windows"));
    // --clear-address: the host's address again.
    let v = env
        .ok(&["remote", "set", "PC", "--clear-address", "--json"])
        .json();
    assert!(v["remote"]["address"].is_null());
    assert_eq!(v["remote"]["effective_address"], "192.0.2.10");

    // SSH with every option.
    env.ok(&[
        "add",
        "NAS",
        "--mac",
        "02:00:00:00:00:02",
        "--address",
        "192.0.2.20",
    ]);
    let key = env.root().join("id_ed25519");
    std::fs::write(&key, "test").unwrap();
    let quoted = format!("\"{}\"", key.display());
    let o = env.run(&[
        "remote",
        "set",
        "NAS",
        "--kind",
        "ssh",
        "--user",
        "admin",
        "--port",
        "2222",
        "--key-file",
        &quoted,
        "--sudo",
        "nopasswd",
        "--reboot-command",
        "systemctl reboot",
        "--json",
    ]);
    assert_code(&o, 0, "remote set ssh");
    let v = o.json();
    assert_eq!(v["remote"]["kind"], "ssh");
    assert_eq!(v["remote"]["port"], 2222);
    assert_eq!(v["remote"]["key_file"], key.display().to_string());
    assert_eq!(v["remote"]["sudo"], "nopasswd");
    assert_eq!(v["remote"]["reboot_command"], "systemctl reboot");
    assert!(v["remote"]["host_key"].is_null());
    // Human output suggests the next steps.
    let o = env.run(&["remote", "set", "NAS", "--user", "root"]);
    assert_code(&o, 0, "change user");
    assert!(o.stderr.contains("wolm ssh trust NAS"), "{}", o.stderr);
    assert!(o.stderr.contains("wolm remote test NAS"), "{}", o.stderr);
    assert_eq!(env.code(&["remote", "set", "NAS", "--sudo", "doas"]), 2);
    assert_eq!(
        env.code(&[
            "remote",
            "set",
            "NAS",
            "--reboot-command",
            "reboot; echo $HOME"
        ]),
        2
    );
    assert_eq!(env.code(&["remote", "set", "NAS", "--port", "0"]), 2);
    let o = env.run(&["remote", "set", "NAS", "--key-file", "C:\\no\\such\\key"]);
    assert_code(&o, 0, "missing key file is a warning");
    assert!(o.stderr.contains("does not exist"), "{}", o.stderr);
    let v = env
        .ok(&[
            "remote",
            "set",
            "NAS",
            "--clear-port",
            "--clear-key-file",
            "--clear-reboot-command",
            "--json",
        ])
        .json();
    assert_eq!(v["remote"]["port"], 22);
    assert!(v["remote"]["key_file"].is_null());
    assert!(v["remote"]["reboot_command"].is_null());
    let text = std::fs::read_to_string(env.cfg_dir().join("config.toml")).unwrap();
    assert!(text.contains("[hosts.remote]"), "{text}");
    assert!(text.contains("kind = \"ssh\""), "{text}");

    // A password: stored in the test store, never printed.
    let o = env.run_stdin(&["cred", "set", "PC", "--password-stdin"], b"Secret-pw\r\n");
    assert_code(&o, 0, "cred set");
    assert!(!o.stdout.contains("Secret-pw") && !o.stderr.contains("Secret-pw"));
    let s = env.secrets();
    let (target, entry) = s.as_object().unwrap().iter().next().unwrap();
    assert!(
        target.starts_with("wol-manager/host/") && target.ends_with("/login"),
        "{target}"
    );
    // Bound to the connection it was stored for (wol-core seals kind, address and port).
    let sealed = entry["secret"].as_str().unwrap();
    assert!(sealed.ends_with("\0Secret-pw"), "{sealed:?}");
    assert!(
        sealed.contains("windows") && sealed.contains("192.0.2.10"),
        "{sealed:?}"
    );
    assert_eq!(entry["user"], r"PC\admin");
    let o = env.ok(&["remote", "show", "PC", "--json"]);
    assert!(!o.stdout.contains("Secret-pw"));
    assert_eq!(o.json()["secrets"]["login"]["state"], "usable");
    assert!(env.ok(&["remote", "show", "PC"]).stdout.contains("stored"));
    // The user moves the host to another address: the password follows it.
    let o = env.run(&["remote", "set", "PC", "--address", "198.51.100.5"]);
    assert_code(&o, 0, "new management address");
    assert!(!o.stderr.contains("Store it again"), "{}", o.stderr);
    let v = env.ok(&["remote", "show", "PC", "--json"]).json();
    assert_eq!(v["secrets"]["login"]["state"], "usable");
    // Another account: the stored password is never sent for it.
    let o = env.run(&["remote", "set", "PC", "--user", r"PC\other"]);
    assert_code(&o, 0, "new user");
    assert!(o.stderr.contains("wolm cred set PC"), "{}", o.stderr);
    let v = env.ok(&["remote", "show", "PC", "--json"]).json();
    assert_eq!(v["secrets"]["login"]["state"], "stale");
    assert!(
        v["secrets"]["login"]["stored_for"]
            .as_str()
            .unwrap()
            .contains(r"PC\admin"),
        "{v}"
    );
    let o = env.ok(&["remote", "show", "PC"]);
    assert!(o.stdout.contains("not used"), "{}", o.stdout);
    env.ok(&["remote", "set", "PC", "--user", r"PC\admin"]);
    assert_eq!(
        env.ok(&["remote", "show", "PC", "--json"]).json()["secrets"]["login"]["state"],
        "usable"
    );
    // `wolm edit --address` of a host without a management address moves it too.
    env.ok(&["remote", "set", "PC", "--clear-address"]);
    let o = env.run(&["edit", "PC", "--address", "192.0.2.11"]);
    assert_code(&o, 0, "edit --address");
    assert!(!o.stderr.contains("Store it again"), "{}", o.stderr);
    assert_eq!(
        env.ok(&["remote", "show", "PC", "--json"]).json()["secrets"]["login"]["state"],
        "usable"
    );

    // `remote clear` asks first: stdin is not a console and no --yes → exit 2, unchanged.
    let o = env.run(&["remote", "clear", "PC"]);
    assert_code(&o, 2, "clear without --yes");
    assert!(o.stderr.contains("--yes"), "{}", o.stderr);
    assert_eq!(
        env.ok(&["remote", "show", "PC", "--json"]).json()["remote"]["kind"],
        "windows"
    );
    let v = env.ok(&["remote", "clear", "PC", "--yes", "--json"]).json();
    assert_eq!(v["changed"], true);
    assert_eq!(v["secrets_deleted"], 1);
    assert_eq!(env.secrets(), json!({}));
    assert_eq!(env.code(&["remote", "clear", "PC", "--yes"]), 1);
    assert_eq!(env.run(&["remote", "show", "PC", "--json"]).code, 1);
}

#[test]
fn cred_set_delete_list_prune() {
    let env = Env::new();
    // Prune without a settings file would delete the passwords of other settings folders.
    assert_eq!(env.code(&["cred", "prune", "--yes"]), 2);
    env.ok(&[
        "add",
        "NAS",
        "--mac",
        "02:00:00:00:00:02",
        "--address",
        "192.0.2.20",
    ]);
    env.ok(&[
        "add",
        "PC",
        "--mac",
        "02:00:00:00:00:01",
        "--address",
        "192.0.2.10",
    ]);
    // No remote management: exit 2 with a pointer to `wolm remote set`.
    let o = env.run_stdin(&["cred", "set", "NAS", "--password-stdin"], b"x\n");
    assert_code(&o, 2, "unmanaged");
    assert!(o.stderr.contains("wolm remote set"), "{}", o.stderr);
    env.ok(&["remote", "set", "NAS", "--kind", "ssh", "--user", "admin"]);
    env.ok(&["remote", "set", "PC", "--kind", "windows"]);
    // `remote set` of a Windows host without a password confirmed the Windows sign-in for it
    // (a marker, not a password).
    assert_eq!(env.sign_ins().len(), 1);
    // Not a console and no --password-stdin: never waits for input.
    let o = env.run(&["cred", "set", "NAS"]);
    assert_code(&o, 2, "no console");
    assert!(o.stderr.contains("--password-stdin"), "{}", o.stderr);
    // A password is never an argument.
    assert_eq!(env.code(&["cred", "set", "NAS", "--password", "x"]), 2);
    let too_long = vec![b'x'; 64 * 1024 + 1];
    // Cross review n10: the test store has the limits of Credential Manager; wol-core refuses
    // a password above 1000 characters (exit 2) before it adds the binding, as for real.
    let over_limit = vec![b'y'; 1001];
    for bad in [
        &b""[..],
        b"\n",
        b"a\nb\n",
        &[0xC3, 0x28],
        &too_long,
        &over_limit,
    ] {
        let o = env.run_stdin(&["cred", "set", "NAS", "--password-stdin"], bad);
        assert_code(&o, 2, "bad stdin");
    }
    assert_eq!(env.passwords(), json!({}));
    let o = env.run_stdin(
        &["cred", "set", "NAS", "--password-stdin"],
        &vec![b'z'; 1000],
    );
    assert_code(&o, 0, "1000 characters fit");
    assert_eq!(env.code(&["cred", "delete", "NAS"]), 0);
    // UTF-8 with BOM, one trailing line break removed.
    let o = env.run_stdin(
        &["cred", "set", "NAS", "--password-stdin", "--json"],
        "\u{feff}p\u{e4}ssw\u{f6}rd\n".as_bytes(),
    );
    assert_code(&o, 0, "cred set NAS");
    let v = o.json();
    assert_eq!(v["kind"], "login");
    assert_eq!(v["user"], "admin");
    assert_eq!(v["stored"], true);
    // A key passphrase without key file is stored with a warning.
    let o = env.run_stdin(
        &[
            "cred",
            "set",
            "NAS",
            "--kind",
            "key-passphrase",
            "--password-stdin",
        ],
        b"pp-secret\n",
    );
    assert_code(&o, 0, "passphrase");
    assert!(o.stderr.contains("No key file"), "{}", o.stderr);
    // Windows hosts only have a login password; unknown kinds are usage errors.
    for kind in ["sudo", "key-passphrase", "pin"] {
        let o = env.run_stdin(
            &["cred", "set", "PC", "--kind", kind, "--password-stdin"],
            b"x\n",
        );
        assert_code(&o, 2, kind);
    }
    let values: Vec<String> = env
        .secrets()
        .as_object()
        .unwrap()
        .values()
        .map(|v| v["secret"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        values.iter().any(|v| v.ends_with("\0p\u{e4}ssw\u{f6}rd")),
        "{values:?}"
    );
    assert!(
        values.iter().any(|v| v.ends_with("\0pp-secret")),
        "{values:?}"
    );

    // list: host, kind, user; never the passwords.
    let o = env.ok(&["cred", "list", "--json"]);
    assert!(!o.stdout.contains("pp-secret") && !o.stdout.contains("ssw"));
    let v = o.json();
    let list = v.as_array().unwrap();
    assert_eq!(list.len(), 2);
    assert!(
        list.iter()
            .all(|e| e["host"] == "NAS" && e["orphan"] == false)
    );
    assert!(list.iter().all(|e| e["state"]["state"] == "usable"), "{v}");
    assert!(list.iter().any(|e| e["kind"] == "key-passphrase"));
    // SSH passwords belong to the login user; --user cannot change that.
    let o = env.run_stdin(
        &["cred", "set", "NAS", "--user", "bob", "--password-stdin"],
        "p\u{e4}ssw\u{f6}rd\n".as_bytes(),
    );
    assert_code(&o, 0, "ssh --user");
    assert!(o.stderr.contains("(admin) is used"), "{}", o.stderr);
    // Another kind of remote management: the login password is not used any more.
    let o = env.run(&["remote", "set", "NAS", "--kind", "windows"]);
    assert_code(&o, 0, "kind switch");
    assert!(o.stderr.contains("Store it again"), "{}", o.stderr);
    let v = env.ok(&["cred", "list", "--json"]).json();
    let login = v
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "login")
        .unwrap()
        .clone();
    assert_eq!(login["state"]["state"], "stale", "{v}");
    assert!(env.ok(&["cred", "list"]).stdout.contains("not used"));
    env.ok(&["remote", "set", "NAS", "--kind", "ssh"]);
    let v = env.ok(&["cred", "list", "--json"]).json();
    assert!(
        v.as_array()
            .unwrap()
            .iter()
            .all(|e| e["state"]["state"] == "usable"),
        "{v}"
    );
    let o = env.ok(&["cred", "list"]);
    assert!(o.stdout.contains("login password") && o.stdout.contains("admin"));
    assert!(!o.stdout.contains("pp-secret"));

    // delete
    assert_eq!(env.code(&["cred", "delete", "NAS", "--kind", "sudo"]), 1);
    let v = env
        .ok(&[
            "cred",
            "delete",
            "NAS",
            "--kind",
            "key-passphrase",
            "--json",
        ])
        .json();
    assert_eq!(v["deleted"], json!(["key-passphrase"]));

    // prune: a password left behind by a removed host.
    let gone = "11111111-2222-4333-8444-555555555555";
    let mut s = env.secrets();
    s[format!("wol-manager/host/{gone}/login")] = json!({"user": "root", "secret": "old"});
    std::fs::write(env.secret_file(), s.to_string()).unwrap();
    let v = env.ok(&["cred", "list", "--json"]).json();
    let orphan = v
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["host_id"] == gone)
        .unwrap()
        .clone();
    assert!(orphan["host"].is_null() && orphan["orphan"] == true);
    let o = env.run(&["cred", "prune"]);
    assert_code(&o, 2, "prune without --yes");
    let v = env.ok(&["cred", "prune", "--dry-run", "--json"]).json();
    assert_eq!(v["entries"].as_array().unwrap().len(), 1);
    assert_eq!(v["deleted"], false);
    let v = env.ok(&["cred", "prune", "--yes", "--json"]).json();
    assert_eq!(v["deleted"], true);
    assert_eq!(v["entries"][0]["host_id"], gone);
    assert_eq!(env.code(&["cred", "prune", "--yes"]), 1);
    assert_eq!(
        env.ok(&["cred", "list", "--json"])
            .json()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // A removed host's password can also be deleted by its full id.
    let mut s = env.secrets();
    s[format!("wol-manager/host/{gone}/sudo")] = json!({"user": "root", "secret": "old"});
    std::fs::write(env.secret_file(), s.to_string()).unwrap();
    assert_eq!(env.code(&["cred", "delete", gone]), 0);

    // Removing a host deletes its passwords (rm, and import --replace).
    let o = env.run_stdin(&["cred", "set", "PC", "--password-stdin"], b"pc-pw\n");
    assert_code(&o, 0, "cred set PC");
    let v = env.ok(&["rm", "NAS", "--json"]).json();
    assert_eq!(v["secrets_deleted"], 1);
    assert_eq!(env.passwords().as_object().unwrap().len(), 1);
    let csv = env.root().join("other.csv");
    std::fs::write(&csv, "name,mac\nOther,02:00:00:00:00:09\n").unwrap();
    env.ok(&["import", csv.to_str().unwrap(), "--replace"]);
    assert_eq!(env.secrets(), json!({}));

    // Credential Manager unavailable (network logon): exit 7.
    env.managed("PC2", "02:00:00:00:00:03", "windows", "192.0.2.30");
    std::fs::write(env.secret_file(), r#"{"__unavailable": true}"#).unwrap();
    let o = env.run_stdin(&["cred", "set", "PC2", "--password-stdin"], b"x\n");
    assert_code(&o, 7, "store unavailable");
    assert!(o.stderr.contains("Credential Manager"), "{}", o.stderr);
}

/// A hand-written config.toml without host ids: the id is only assigned while reading, so a
/// password stored under it could be orphaned. `cred set` writes the ids first (review m12)
/// and refuses only when the file cannot be written (here: a newer version's file).
#[test]
fn cred_set_saves_the_host_ids_first() {
    let env = Env::new();
    let hosts = "[[hosts]]\nname = \"NAS\"\nmac = \"02:00:00:00:00:02\"\naddress = \"192.0.2.20\"\n\n[hosts.remote]\nkind = \"ssh\"\n";
    env.write_config(&format!("schema_version = 2\n\n{hosts}"));
    let o = env.run_stdin(&["cred", "set", "NAS", "--password-stdin"], b"pw\n");
    assert_code(&o, 2, "newer version: id not saved");
    assert!(
        o.stderr.contains("not saved in config.toml"),
        "{}",
        o.stderr
    );
    assert_eq!(env.secrets(), json!({}));

    env.write_config(&format!("schema_version = 1\n\n{hosts}"));
    let id = env.ok(&["show", "NAS", "--json"]).json()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let path = env.cfg_dir().join("config.toml");
    assert!(!std::fs::read_to_string(&path).unwrap().contains(&id));
    let o = env.run_stdin(&["cred", "set", "NAS", "--password-stdin"], b"pw\n");
    assert_code(&o, 0, "ids written first");
    assert!(std::fs::read_to_string(&path).unwrap().contains(&id));
    let s = env.secrets();
    let target = s.as_object().unwrap().keys().next().unwrap();
    assert!(target.contains(&id), "{target}");
    // The id stays the one the password is stored under.
    assert_eq!(env.ok(&["show", "NAS", "--json"]).json()["id"], id.as_str());
    assert_eq!(
        env.ok(&["remote", "show", "NAS", "--json"]).json()["secrets"]["login"]["state"],
        "usable"
    );
    // `remote set` needs no extra step: its own save writes every id.
    env.write_config(&format!("schema_version = 1\n\n{hosts}"));
    assert!(!std::fs::read_to_string(&path).unwrap().contains(&id));
    env.ok(&["remote", "set", "NAS", "--port", "2222"]);
    assert!(std::fs::read_to_string(&path).unwrap().contains(&id));
}

#[test]
fn newer_remote_tables_and_imports_that_repoint_hosts() {
    let env = Env::new();
    // A remote kind this version does not know: the host is not managed here, the table is
    // kept, and the messages say why.
    env.write_config(
        "schema_version = 1\n\n[[hosts]]\nid = \"6f0b2c1e-3d4a-4b5c-8d6e-7f8091a2b3c4\"\nname = \"BMC\"\nmac = \"02:00:00:00:00:05\"\naddress = \"192.0.2.50\"\n\n[hosts.remote]\nkind = \"ipmi\"\n",
    );
    let o = env.run(&["remote", "show", "BMC"]);
    assert_code(&o, 1, "newer kind");
    assert!(o.stderr.contains("newer version"), "{}", o.stderr);
    let o = env.run_fake(&["boot-time", "BMC"]);
    assert_code(&o, 2, "newer kind: boot-time");
    assert!(o.stderr.contains("newer version"), "{}", o.stderr);
    env.ok(&["edit", "BMC", "--notes", "kept"]);
    let text = std::fs::read_to_string(env.cfg_dir().join("config.toml")).unwrap();
    assert!(text.contains("ipmi"), "{text}");

    // An import that points a managed host elsewhere: its saved passwords are not used any
    // more, and the user is told so.
    env.managed("NAS", "02:00:00:00:00:02", "ssh", "192.0.2.20");
    let o = env.run_stdin(&["cred", "set", "NAS", "--password-stdin"], b"pw\n");
    assert_code(&o, 0, "cred set");
    let export = env.ok(&["export", "--format", "json"]).stdout;
    let mut doc: Value = serde_json::from_str(&export).unwrap();
    // Only NAS (re-importing BMC's newer-version table is a wol-core matter).
    doc["hosts"]
        .as_array_mut()
        .unwrap()
        .retain(|h| h["name"] == "NAS");
    doc["hosts"][0]["remote"]["address"] = json!("192.0.2.77");
    let file = env.root().join("repoint.json");
    std::fs::write(&file, doc.to_string()).unwrap();
    let o = env.run(&["import", file.to_str().unwrap()]);
    assert_code(&o, 0, "import");
    assert!(o.stderr.contains("entered again"), "{}", o.stderr);
    let v = env.ok(&["remote", "show", "NAS", "--json"]).json();
    assert_eq!(v["secrets"]["login"]["state"], "stale");

    // Export → import of everything, BMC included, is not refused: BMC stays unmanaged with
    // its table kept (TOML / JSON carry it, with a warning; CSV has empty remote cells for it
    // and leaves the table of the existing host alone).
    for format in ["json", "toml", "csv"] {
        let file = env.root().join(format!("all.{format}"));
        let file = file.to_str().unwrap();
        env.ok(&["export", "--format", format, "--output", file]);
        let o = env.run(&["import", file]);
        assert_code(&o, 1, format); // no changes
        assert!(o.stderr.contains("2 unchanged"), "{format}: {}", o.stderr);
        // (the load warning about config.toml is printed in every case)
        assert_eq!(
            o.stderr.contains("the host is not managed here"),
            format != "csv",
            "{format}: {}",
            o.stderr
        );
        let text = std::fs::read_to_string(env.cfg_dir().join("config.toml")).unwrap();
        assert!(text.contains("kind = \"ipmi\""), "{format}: {text}");
        let other = Env::new();
        let o = other.run(&["import", file]);
        assert_code(&o, 0, format);
        let text = std::fs::read_to_string(other.cfg_dir().join("config.toml")).unwrap();
        assert_eq!(text.contains("ipmi"), format != "csv", "{format}: {text}");
    }
}

#[test]
fn power_needs_confirmation_and_maps_the_options() {
    let env = Env::new();
    env.managed("PC", "02:00:00:00:00:01", "windows", "192.0.2.10");
    env.managed("NAS", "02:00:00:00:00:02", "ssh", "192.0.2.20");
    env.ok(&[
        "add",
        "Plain",
        "--mac",
        "02:00:00:00:00:03",
        "--address",
        "192.0.2.30",
    ]);
    // stdin is not a console and no --yes: exit 2, nothing is sent.
    for cmd in ["restart", "shutdown"] {
        let o = env.run_fake(&[cmd, "PC"]);
        assert_code(&o, 2, cmd);
        assert!(o.stderr.contains("--yes"), "{}", o.stderr);
        let o = env.run_fake(&[cmd, "PC", "--json"]);
        assert_code(&o, 2, cmd);
        assert_eq!(o.error_json()["error"]["kind"], "usage");
    }
    assert!(env.calls().is_empty(), "{:?}", env.calls());
    // Without remote management: exit 2 before anything is sent, also in a batch.
    let o = env.run_fake(&["restart", "Plain", "--yes"]);
    assert_code(&o, 2, "unmanaged");
    assert!(o.stderr.contains("wolm remote set"), "{}", o.stderr);
    assert_eq!(env.run_fake(&["restart", "PC", "Plain", "--yes"]).code, 2);
    assert_eq!(env.run_fake(&["shutdown", "Nope", "--yes"]).code, 3);
    assert!(env.calls().is_empty(), "{:?}", env.calls());

    // Defaults from [settings.remote]: 30 s countdown, applications closed.
    let o = env.run_fake(&["restart", "PC", "--yes", "--json"]);
    assert_code(&o, 0, "restart");
    let v = o.json();
    assert_eq!(v["action"], "restart");
    assert_eq!(v["options"]["delay_secs"], 30);
    let r = &v["results"][0];
    assert_eq!(r["host"], "PC");
    assert_eq!(r["ok"], true);
    assert_eq!(
        r["outcome"],
        json!({"result": "scheduled", "delay_secs": 30})
    );
    assert!(r["error"].is_null() && r["wait"].is_null());
    let c = env.calls_of("power");
    assert_eq!(c.len(), 1);
    assert_eq!(c[0]["action"], "restart");
    assert_eq!(c[0]["delay_secs"], 30);
    assert_eq!(c[0]["force"], true);
    assert!(c[0]["message"].is_null());
    // Flags.
    let o = env.run_fake(&[
        "shutdown",
        "PC",
        "--yes",
        "--now",
        "--no-force",
        "--message",
        "Maintenance",
        "--json",
    ]);
    assert_code(&o, 0, "shutdown");
    assert_eq!(
        o.json()["results"][0]["outcome"],
        json!({"result": "accepted"})
    );
    let c = env.calls_of("power");
    let last = c.last().unwrap();
    assert_eq!(last["action"], "shutdown");
    assert_eq!(last["delay_secs"], 0);
    assert_eq!(last["force"], false);
    assert_eq!(last["message"], "Maintenance");
    env.ok(&["config", "set", "remote.force_apps_closed", "false"]);
    let o = env.run_fake(&["restart", "PC", "--yes", "--delay", "2m", "--force"]);
    assert_code(&o, 0, "restart --delay 2m");
    assert!(
        o.stdout.contains("PC will restart in 120 s"),
        "{}",
        o.stdout
    );
    let c = env.calls_of("power");
    assert_eq!(c.last().unwrap()["delay_secs"], 120);
    assert_eq!(c.last().unwrap()["force"], true);
    let o = env.run_fake(&["restart", "PC", "--yes"]);
    assert_code(&o, 0, "force from the settings");
    assert_eq!(env.calls_of("power").last().unwrap()["force"], false);
    for bad in [
        &["restart", "PC", "--yes", "--delay", "601"][..],
        &["restart", "PC", "--yes", "--delay", "5", "--now"],
        &["restart", "PC", "--yes", "--force", "--no-force"],
    ] {
        assert_eq!(env.run_fake(bad).code, 2, "{bad:?}");
    }
    // SSH hosts ignore the Windows options (a note says so).
    let o = env.run_fake(&["restart", "NAS", "--yes", "--delay", "10"]);
    assert_code(&o, 0, "ssh restart");
    assert!(o.stderr.contains("do not apply"), "{}", o.stderr);
    assert!(o.stdout.contains("NAS"), "{}", o.stdout);
    // Several hosts at once.
    let v = env
        .run_fake(&["shutdown", "PC", "NAS", "--yes", "--json"])
        .json();
    assert_eq!(v["results"].as_array().unwrap().len(), 2);
    assert_eq!(v["results"][1]["outcome"], json!({"result": "accepted"}));
}

#[test]
fn power_failures_and_wait() {
    let env = Env::new();
    env.managed("PC", "02:00:00:00:00:01", "windows", "192.0.2.10");
    env.managed("NAS", "02:00:00:00:00:02", "ssh", "192.0.2.20");
    for (error, code, kind) in [
        ("access_denied", 7, "permission"),
        ("unreachable", 5, "network"),
        ("power_unconfirmed", 1, "remote"),
    ] {
        env.set_fake(json!({"power": {"error": error}}));
        let o = env.run_fake(&["restart", "PC", "--yes", "--json"]);
        assert_code(&o, code, error);
        let v = o.json();
        let r = &v["results"][0];
        assert_eq!(r["ok"], false);
        assert_eq!(r["error"]["kind"], kind);
        assert_eq!(r["error"]["exit_code"], code);
        let o = env.run_fake(&["restart", "PC", "--yes"]);
        assert_code(&o, code, error);
        assert!(o.stderr.contains("error:"), "{}", o.stderr);
    }
    // Sent but unconfirmed: --wait decides.
    env.set_fake(json!({"power": {"error": "power_unconfirmed"}, "verify_shutdown": "shut_down"}));
    let o = env.run_fake(&["shutdown", "PC", "--yes", "--wait"]);
    assert_code(&o, 0, "unconfirmed, verified");

    // --wait: the boot time is read first, then the request, then the verification.
    env.set_fake(json!({"verify_restart": "restarted"}));
    env.clear_calls();
    let o = env.run_fake(&["restart", "NAS", "--yes", "--wait", "--json"]);
    assert_code(&o, 0, "restart --wait");
    let ops: Vec<String> = env
        .calls()
        .iter()
        .map(|c| c["op"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ops, ["boot_time", "power", "verify_restart"]);
    let v = o.json();
    let w = &v["results"][0]["wait"];
    assert_eq!(w["result"], "restarted");
    assert_eq!(w["timeout_secs"], 600);
    assert!(
        is_iso_local(w["boot"]["boot_time"].as_str().unwrap()),
        "{w}"
    );
    let o = env.run_fake(&["restart", "PC", "--yes", "--wait"]);
    assert_code(&o, 0, "restart --wait (human)");
    assert!(o.stderr.contains("no answer"), "{}", o.stderr);
    assert!(o.stdout.contains("Up since"), "{}", o.stdout);
    for (verdict, code) in [
        ("timed_out", 4),
        ("cancelled", 130),
        ("failed:unknown_host_key", 7),
    ] {
        env.set_fake(json!({ "verify_restart": verdict }));
        let o = env.run_fake(&["restart", "PC", "--yes", "--wait", "--json"]);
        assert_code(&o, code, verdict);
        assert_eq!(o.json()["results"][0]["ok"], false);
    }
    env.set_fake(json!({"verify_shutdown": "timed_out"}));
    let o = env.run_fake(&[
        "shutdown",
        "PC",
        "--yes",
        "--wait",
        "--timeout",
        "1m",
        "--json",
    ]);
    assert_code(&o, 4, "shutdown timeout");
    let v = o.json();
    assert_eq!(v["results"][0]["wait"]["result"], "timed_out");
    // --timeout plus the 30 s countdown.
    assert_eq!(v["results"][0]["wait"]["timeout_secs"], 90);
    assert_eq!(
        env.run_fake(&["restart", "PC", "--yes", "--timeout", "5m"])
            .code,
        2
    );
    // A shutdown of a host whose status is not checked cannot be confirmed: refused before
    // anything is sent.
    env.ok(&["edit", "PC", "--probe", "none"]);
    env.clear_calls();
    let o = env.run_fake(&["shutdown", "PC", "--yes", "--wait"]);
    assert_code(&o, 2, "shutdown --wait unmonitored");
    assert!(env.calls().is_empty(), "{:?}", env.calls());

    // Unknown SSH host key: the fingerprint and how to trust it; never trusted automatically.
    env.set_fake(json!({"power": {"error": "unknown_host_key"}}));
    let o = env.run_fake(&["restart", "NAS", "--yes"]);
    assert_code(&o, 7, "unknown host key");
    assert!(o.stderr.contains("SHA256:"), "{}", o.stderr);
    assert!(o.stderr.contains("hint: "), "{}", o.stderr);
    assert!(o.stderr.contains("wolm ssh trust NAS"), "{}", o.stderr);
    assert!(env.ok(&["remote", "show", "NAS", "--json"]).json()["remote"]["host_key"].is_null());

    // abort: Windows only, no confirmation needed; nothing pending → exit 1.
    env.set_fake(json!({}));
    let v = env.run_fake(&["abort", "PC", "--json"]).json();
    assert_eq!(v["aborted"], true);
    env.set_fake(json!({"abort": {"error": "no_shutdown_in_progress"}}));
    let o = env.run_fake(&["abort", "PC", "--json"]);
    assert_code(&o, 1, "nothing to abort");
    assert_eq!(o.json()["aborted"], false);
    let o = env.run_fake(&["abort", "NAS"]);
    assert_code(&o, 2, "abort on ssh");
    assert!(
        o.stderr.contains("only available for Windows"),
        "{}",
        o.stderr
    );
}

#[test]
fn remote_error_paths_with_the_real_backends() {
    let env = Env::new();
    env.ok(&["config", "set", "remote.connect_timeout_ms", "1000"]);
    // SSH on a closed loopback port. No host key is pinned, so even a server there could
    // never receive a command.
    let port = closed_port().to_string();
    env.ok(&[
        "add",
        "NAS",
        "--mac",
        "02:00:00:00:00:02",
        "--address",
        "127.0.0.1",
    ]);
    env.ok(&["remote", "set", "NAS", "--kind", "ssh", "--port", &port]);
    let o = env.run(&["ssh", "trust", "NAS", "--accept-new", "--json"]);
    assert_code(&o, 5, "ssh trust, closed port");
    assert_eq!(o.error_json()["error"]["kind"], "network");
    assert_eq!(env.run(&["boot-time", "NAS"]).code, 5);
    assert_eq!(env.run(&["remote", "test", "NAS"]).code, 5);
    let o = env.run(&["restart", "NAS", "--yes"]);
    assert_code(&o, 5, "restart, closed port");
    assert!(env.ok(&["remote", "show", "NAS", "--json"]).json()["remote"]["host_key"].is_null());
    // A Windows host at a TEST-NET address (never routed): exit 5 after the connect timeout.
    env.ok(&[
        "add",
        "PC",
        "--mac",
        "02:00:00:00:00:01",
        "--address",
        "192.0.2.1",
    ]);
    env.ok(&["remote", "set", "PC", "--kind", "windows"]);
    let o = env.run(&["shutdown", "PC", "--yes", "--json"]);
    assert_code(&o, 5, "shutdown, TEST-NET");
    assert_eq!(o.json()["results"][0]["error"]["kind"], "network");
    // Windows hosts have no SSH host key.
    assert_eq!(env.run(&["ssh", "trust", "PC"]).code, 2);
}

#[test]
fn boot_time_and_connection_test() {
    let env = Env::new();
    assert_eq!(env.run_fake(&["boot-time"]).code, 3, "no managed host");
    env.managed("PC", "02:00:00:00:00:01", "windows", "192.0.2.10");
    env.managed("NAS", "02:00:00:00:00:02", "ssh", "192.0.2.20");
    env.ok(&[
        "add",
        "Plain",
        "--mac",
        "02:00:00:00:00:03",
        "--address",
        "192.0.2.30",
    ]);
    let o = env.run_fake(&["boot-time", "Plain"]);
    assert_code(&o, 2, "unmanaged");
    assert!(o.stderr.contains("wolm remote set"), "{}", o.stderr);
    env.set_fake(
        json!({"boot_time": {"uptime_secs": 3725, "source": "fake/test", "approximate": true}}),
    );
    let o = env.run_fake(&["boot-time", "PC", "-v"]);
    assert_code(&o, 0, "boot-time");
    for s in ["PC", "1h 2m", "(approx.)", "fake/test"] {
        assert!(o.stdout.contains(s), "{s}: {}", o.stdout);
    }
    let mut c = env.raw();
    c.env(ENV_REMOTE_FAKE, env.fake_script())
        .args(["--lang", "ja", "uptime", "PC"]);
    let o = Env::exec(c);
    assert!(
        o.stdout.contains("1時間2分") && o.stdout.contains("概算"),
        "{}",
        o.stdout
    );
    // Every managed host without arguments; ISO-8601 times with seconds in JSON.
    let o = env.run_fake(&["uptime", "--json"]);
    assert_code(&o, 0, "uptime --json");
    let v = o.json();
    let list = v.as_array().unwrap();
    assert_eq!(list.len(), 2);
    let b = &list[0]["boot"];
    assert_eq!(list[0]["ok"], true);
    assert!(list[0]["error"].is_null());
    assert!(is_iso_local(b["boot_time"].as_str().unwrap()), "{b}");
    let utc = b["boot_time_utc"].as_str().unwrap();
    assert!(utc.len() == 20 && utc.ends_with('Z'), "{utc}");
    assert_eq!(b["uptime_secs"], 3725);
    assert_eq!(b["approximate"], true);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let boot_ms = b["boot_time_unix_ms"].as_i64().unwrap();
    assert!((now_ms - 3_725_000 - boot_ms).abs() < 60_000, "{boot_ms}");
    // Failures are reported per host; the exit code is the first failure's.
    env.set_fake(json!({"boot_time": {"error": "unknown_host_key"}}));
    let o = env.run_fake(&["boot-time", "NAS", "--json"]);
    assert_code(&o, 7, "unknown key");
    let v = o.json();
    let e = &v[0]["error"];
    assert!(
        e["host_key"]["fingerprint"]
            .as_str()
            .unwrap()
            .starts_with("SHA256:")
    );
    assert!(e["hint"].as_str().unwrap().contains("wolm ssh trust NAS"));
    // A stored password that belongs to another connection is not sent: how to replace it.
    for (error, hint) in [
        ("secret_mismatch", "wolm cred set NAS"),
        ("password_required", "wolm cred set PC"),
    ] {
        env.set_fake(json!({"boot_time": {"error": error}}));
        let host = if error == "secret_mismatch" {
            "NAS"
        } else {
            "PC"
        };
        let o = env.run_fake(&["boot-time", host]);
        assert_code(&o, 7, error);
        assert!(o.stderr.contains(hint), "{}", o.stderr);
    }
    env.set_fake(json!({"boot_time": {"error": "unknown_host_key"}}));
    let o = env.run_fake(&["boot-time", "NAS"]);
    assert!(
        o.stderr.contains("hint: ") && o.stderr.contains("wolm ssh trust NAS"),
        "{}",
        o.stderr
    );

    // Connection test.
    env.set_fake(
        json!({"test": {"os": "Debian GNU/Linux 12", "kernel": "Linux 6.1",
        "user": "admin", "admin_hint": false, "boot": {"uptime_secs": 60}}}),
    );
    let o = env.run_fake(&["remote", "test", "NAS"]);
    assert_code(&o, 0, "remote test");
    assert!(o.stdout.contains("Debian GNU/Linux 12"), "{}", o.stdout);
    assert!(o.stderr.contains("warning:"), "{}", o.stderr);
    let v = env.run_fake(&["remote", "test", "NAS", "--json"]).json();
    assert_eq!(v["os"], "Debian GNU/Linux 12");
    assert_eq!(v["admin_hint"], false);
    assert_eq!(v["boot"]["uptime_secs"], 60);
    env.set_fake(json!({"test": {"error": "auth_failed"}}));
    let o = env.run_fake(&["remote", "test", "NAS", "--json"]);
    assert_code(&o, 7, "auth failed");
    assert_eq!(o.error_json()["error"]["kind"], "permission");
}

#[test]
fn mac_lookup_through_arp_or_remote_management() {
    let env = Env::new();
    // A VPN address (100.64.0.0/10) without remote management: explained, exit 3, and
    // nothing is sent (the decision uses only the local routing table).
    let o = env.run(&["mac", "100.105.1.2"]);
    assert_code(&o, 3, "vpn address");
    assert!(o.stderr.contains("VPN"), "{}", o.stderr);
    assert!(o.stderr.contains("remote management"), "{}", o.stderr);
    let o = env.run(&["mac", "100.105.1.2", "--json"]);
    assert_eq!(o.error_json()["error"]["kind"], "not_found");
    // A mistyped host name is "not found", not a DNS lookup.
    assert_eq!(env.code(&["mac", "NoSuchHost"]), 3);
    assert_eq!(env.code(&["mac", "100.105.1.2", "--save"]), 2);
    // `add --arp` uses the same lookup: the explanation, and nothing is added.
    let o = env.run(&["add", "VpnPC", "--address", "100.105.1.9", "--arp"]);
    assert_code(&o, 3, "add --arp over VPN");
    assert!(o.stderr.contains("remote management"), "{}", o.stderr);
    assert!(!env.ok(&["list", "--json"]).stdout.contains("VpnPC"));
    // A registered host, also found by its address.
    env.ok(&[
        "add",
        "PC",
        "--mac",
        "02:00:00:00:00:01",
        "--address",
        "100.105.1.3",
    ]);
    assert_eq!(env.code(&["mac", "PC"]), 3);
    assert_eq!(env.code(&["mac", "100.105.1.3"]), 3);

    // Remote management: the host's own adapters (fake).
    env.ok(&["remote", "set", "PC", "--kind", "windows"]);
    env.set_fake(json!({"mac": {"candidates": [
        {"iface": "Ethernet", "mac": "AA:BB:CC:00:00:01", "kind": "physical", "score": 100,
         "on_default_route": true, "link_up": true, "lan_ipv4": "192.0.2.20/24"},
        {"iface": "Wi-Fi", "mac": "AA:BB:CC:00:00:02", "kind": "wifi", "score": 10,
         "link_up": false, "wol_enabled": false}]}}));
    let o = env.run_fake(&["mac", "PC"]);
    assert_code(&o, 0, "mac PC");
    for s in ["Ethernet", "AA:BB:CC:00:00:01", "Wi-Fi", "192.0.2.20/24"] {
        assert!(o.stdout.contains(s), "{s}: {}", o.stdout);
    }
    assert!(o.stderr.contains("Wake-on-LAN"), "{}", o.stderr);
    let o = env.run_fake(&["mac", "PC", "--save", "--json"]);
    assert_code(&o, 0, "mac --save");
    let v = o.json();
    assert_eq!(v["source"], "remote");
    assert_eq!(v["selected"], "AA:BB:CC:00:00:01");
    assert_eq!(v["saved"], true);
    assert_eq!(v["changed"], true);
    assert_eq!(v["candidates"][0]["recommended"], true);
    assert_eq!(v["candidates"][1]["index"], 2);
    assert_eq!(v["candidates"][1]["kind"], "wifi");
    assert!(v["candidates"][0].get("score").is_none());
    assert_eq!(
        env.ok(&["show", "PC", "--json"]).json()["mac"],
        "AA:BB:CC:00:00:01"
    );
    let v = env
        .run_fake(&["mac", "100.105.1.3", "--pick", "2", "--save", "--json"])
        .json();
    assert_eq!(v["host"], "PC");
    assert_eq!(v["selected"], "AA:BB:CC:00:00:02");
    assert_eq!(
        env.ok(&["show", "PC", "--json"]).json()["mac"],
        "AA:BB:CC:00:00:02"
    );
    // Equally good adapters: no automatic choice.
    env.set_fake(json!({"mac": {"candidates": [
        {"iface": "eth0", "mac": "AA:BB:CC:00:00:03", "score": 5},
        {"iface": "eth1", "mac": "AA:BB:CC:00:00:04", "score": 5}]}}));
    let o = env.run_fake(&["mac", "PC", "--save"]);
    assert_code(&o, 2, "ambiguous --save");
    assert!(o.stderr.contains("--pick"), "{}", o.stderr);
    assert_eq!(
        env.run_fake(&["mac", "PC", "--save", "--pick", "3"]).code,
        2
    );
    let v = env.run_fake(&["mac", "PC", "--json"]).json();
    assert!(v["selected"].is_null());
    let o = env.run_fake(&["edit", "PC", "--arp"]);
    assert_code(&o, 2, "edit --arp, ambiguous");
    assert!(o.stderr.contains("wolm mac PC"), "{}", o.stderr);
    env.set_fake(json!({"mac": {"error": "access_denied"}}));
    assert_eq!(env.run_fake(&["mac", "PC"]).code, 7);
}

#[test]
fn ssh_trust_and_forget() {
    let env = Env::new();
    env.managed("NAS", "02:00:00:00:00:02", "ssh", "192.0.2.20");
    env.managed("PC", "02:00:00:00:00:01", "windows", "192.0.2.10");
    // Not a console and no flag: shows the key, trusts nothing (exit 2).
    let o = env.run_fake(&["ssh", "trust", "NAS"]);
    assert_code(&o, 2, "trust without flags");
    assert!(o.stdout.contains("ssh-ed25519 SHA256:"), "{}", o.stdout);
    let fp = o
        .stdout
        .split_whitespace()
        .find(|w| w.starts_with("SHA256:"))
        .unwrap()
        .to_owned();
    assert!(env.ok(&["remote", "show", "NAS", "--json"]).json()["remote"]["host_key"].is_null());
    // A fingerprint that does not match: refused (exit 7).
    let o = env.run_fake(&[
        "ssh",
        "trust",
        "NAS",
        "--fingerprint",
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ]);
    assert_code(&o, 7, "wrong fingerprint");
    // The checked fingerprint pins the key.
    let o = env.run_fake(&["ssh", "trust", "NAS", "--fingerprint", &fp, "--json"]);
    assert_code(&o, 0, "trust");
    let v = o.json();
    assert_eq!(v["trusted"], true);
    assert_eq!(v["changed"], true);
    assert_eq!(v["fingerprint"], fp.as_str());
    assert_eq!(v["algorithm"], "ssh-ed25519");
    let v = env.ok(&["remote", "show", "NAS", "--json"]).json();
    assert_eq!(v["remote"]["host_key"]["fingerprint"], fp.as_str());
    // The same key again: nothing to do.
    assert_eq!(
        env.run_fake(&["ssh", "trust", "NAS", "--accept-new"]).code,
        1
    );
    // Another key is never pinned over the trusted one.
    env.set_fake(json!({"scan_host_key": {"host_key": OTHER_KEY}}));
    let o = env.run_fake(&["ssh", "trust", "NAS", "--accept-new"]);
    assert_code(&o, 7, "changed key");
    assert!(o.stderr.contains("WARNING"), "{}", o.stderr);
    assert!(o.stderr.contains("wolm ssh forget NAS"), "{}", o.stderr);
    assert_eq!(env.code(&["ssh", "forget", "NAS"]), 0);
    assert_eq!(env.code(&["ssh", "forget", "NAS"]), 1);
    let v = env
        .run_fake(&["ssh", "trust", "NAS", "--accept-new", "--json"])
        .json();
    assert_ne!(v["fingerprint"], fp.as_str());
    assert_eq!(
        env.run_fake(&["ssh", "trust", "PC", "--accept-new"]).code,
        2
    );
    env.ok(&["remote", "clear", "PC", "--yes"]);
    assert_eq!(env.code(&["ssh", "forget", "PC"]), 2);
}

#[test]
fn remote_help_and_settings() {
    let env = Env::new();
    let o = env.ok(&["--help"]);
    for s in [
        "restart",
        "shutdown",
        "abort",
        "boot-time",
        "uptime",
        "remote",
        "cred",
        "wolm cred set PC",
        "wolm ssh trust NAS",
        "wolm restart PC --wait",
        "7 permission / authentication / SSH host key",
    ] {
        assert!(o.stdout.contains(s), "{s}: {}", o.stdout);
    }
    let o = env.ok(&["restart", "--help"]);
    for s in [
        "--yes",
        "--wait",
        "--delay",
        "--now",
        "--no-force",
        "--message",
        "--timeout",
    ] {
        assert!(o.stdout.contains(s), "{s}: {}", o.stdout);
    }
    let o = env.ok(&["cred", "set", "--help"]);
    assert!(o.stdout.contains("--password-stdin"), "{}", o.stdout);
    assert!(!o.stdout.contains("--password <"), "{}", o.stdout);
    env.ok(&["uptime", "--help"]);
    assert!(
        env.ok(&["remote", "set", "--help"])
            .stdout
            .contains("--clear-user")
    );
    // [settings.remote] keys.
    env.ok(&["config", "set", "remote.shutdown_delay_secs", "60"]);
    assert_eq!(
        env.ok(&["config", "get", "remote.shutdown_delay_secs"])
            .stdout
            .trim(),
        "60"
    );
    assert_eq!(
        env.code(&["config", "set", "remote.shutdown_delay_secs", "601"]),
        2
    );
    assert_eq!(
        env.code(&["config", "set", "remote.connect_timeout_ms", "500"]),
        2
    );
    env.ok(&["config", "set", "remote.auto_boot_time", "off"]);
    assert_eq!(
        env.ok(&["config", "get", "remote.auto_boot_time", "--json"])
            .json()["value"],
        false
    );
}

/// Cross review X1: an SSH host's own restart / shutdown command runs as root, so every
/// restart / shutdown shows it (with --yes on stderr, also with -q), and an import can never
/// set or change it on a host that is already here.
#[test]
fn x1_custom_power_commands_are_shown_and_never_imported() {
    let env = Env::new();
    env.managed("NAS", "02:00:00:00:00:02", "ssh", "192.0.2.20");
    env.ok(&[
        "remote",
        "set",
        "NAS",
        "--reboot-command",
        "/sbin/reboot -f",
    ]);
    let o = env.run_fake(&["restart", "NAS", "--yes"]);
    assert_code(&o, 0, "restart --yes");
    assert!(
        o.stderr.contains("custom command") && o.stderr.contains("/sbin/reboot -f"),
        "{}",
        o.stderr
    );
    let o = env.run_fake(&["restart", "NAS", "--yes", "-q"]);
    assert_code(&o, 0, "restart --yes -q");
    assert!(o.stderr.contains("/sbin/reboot -f"), "{}", o.stderr);
    let o = env.run_fake(&["restart", "NAS", "--yes", "--json"]);
    assert_code(&o, 0, "restart --yes --json");
    assert_eq!(o.json()["results"][0]["custom_command"], "/sbin/reboot -f");
    let warning: Value = serde_json::from_str(o.stderr.lines().next().unwrap()).unwrap();
    assert!(
        warning["warning"]["message"]
            .as_str()
            .unwrap()
            .contains("/sbin/reboot -f"),
        "{}",
        o.stderr
    );
    // Only the action that has one.
    let o = env.run_fake(&["shutdown", "NAS", "--yes", "--json"]);
    assert!(o.json()["results"][0]["custom_command"].is_null());
    assert!(!o.stderr.contains("custom command"), "{}", o.stderr);

    // A file with other commands for NAS and a new host with its own.
    let file = env.root().join("commands.json");
    std::fs::write(
        &file,
        json!([
            {"name": "NAS", "mac": "02:00:00:00:00:02", "address": "192.0.2.20",
             "remote": {"kind": "ssh", "reboot_command": "/bin/sh /tmp/x",
                        "shutdown_command": "poweroff; curl http://203.0.113.9/x"}},
            {"name": "NewNAS", "mac": "02:00:00:00:00:0B", "address": "192.0.2.21",
             "remote": {"kind": "ssh", "shutdown_command": "/usr/sbin/poweroff"}}
        ])
        .to_string(),
    )
    .unwrap();
    let file = file.to_str().unwrap();
    let o = env.run(&["import", file, "--dry-run"]);
    assert_code(&o, 0, "dry run");
    assert!(
        o.stderr.contains("not applied to existing hosts") && o.stderr.contains(": NAS"),
        "{}",
        o.stderr
    );
    assert!(
        o.stderr.contains("custom restart / shutdown commands") && o.stderr.contains("NewNAS"),
        "{}",
        o.stderr
    );
    let v = env.ok(&["import", file, "--json"]).json();
    assert_eq!(v["commands_kept"], json!(["NAS"]));
    assert_eq!(v["commands_imported"], json!(["NewNAS"]));
    let r = &env.ok(&["remote", "show", "NAS", "--json"]).json()["remote"];
    assert_eq!(r["reboot_command"], "/sbin/reboot -f");
    assert!(r["shutdown_command"].is_null());
    // The new host's command is shown before its shutdown like any other.
    let o = env.run_fake(&["shutdown", "NewNAS", "--yes"]);
    assert_code(&o, 0, "shutdown NewNAS");
    assert!(o.stderr.contains("/usr/sbin/poweroff"), "{}", o.stderr);
}

/// Cross review X2: a Windows host without a saved password connects with this user's
/// Windows sign-in. Explicit actions confirm that per host and management address; runs that
/// did not name the host (`boot-time` without arguments, like the app's automatic boot time)
/// skip hosts that an import added or re-pointed.
#[test]
fn x2_the_windows_sign_in_needs_a_confirmation_per_host() {
    let env = Env::new();
    env.ok(&[
        "add",
        "PC",
        "--mac",
        "02:00:00:00:00:01",
        "--address",
        "192.0.2.10",
    ]);
    let o = env.run(&["remote", "set", "PC", "--kind", "windows"]);
    assert_code(&o, 0, "remote set");
    assert!(
        o.stderr.contains("Windows sign-in") && o.stderr.contains("Recorded as confirmed"),
        "{}",
        o.stderr
    );
    let pc = env.id_of("PC");
    assert_eq!(
        env.sign_ins(),
        vec![format!("wol-manager/host/{pc}/sign-in")]
    );
    assert!(
        env.ok(&["cred", "list", "--json"])
            .json()
            .as_array()
            .unwrap()
            .is_empty(),
        "not a password"
    );
    env.managed("NAS", "02:00:00:00:00:02", "ssh", "192.0.2.20");
    let o = env.run_fake(&["boot-time", "--json"]);
    assert_code(&o, 0, "every host, confirmed");
    let calls = env.calls_of("boot_time");
    assert_eq!(calls.len(), 2);
    assert!(
        calls
            .iter()
            .any(|c| c["host"] == "PC" && c["sign_in_confirmed"] == true),
        "{calls:?}"
    );

    // An import points PC elsewhere and adds another Windows host.
    let file = env.root().join("repoint.json");
    std::fs::write(
        &file,
        json!([
            {"name": "PC", "mac": "02:00:00:00:00:01", "address": "192.0.2.99",
             "remote": {"kind": "windows"}},
            {"name": "New", "mac": "02:00:00:00:00:0A", "address": "192.0.2.60",
             "remote": {"kind": "windows"}}
        ])
        .to_string(),
    )
    .unwrap();
    env.ok(&["import", file.to_str().unwrap()]);
    env.clear_calls();
    let o = env.run_fake(&["boot-time"]);
    assert_code(&o, 7, "unconfirmed hosts are not asked");
    assert!(o.stderr.contains("not been confirmed"), "{}", o.stderr);
    assert!(o.stderr.contains("wolm remote test PC"), "{}", o.stderr);
    assert!(o.stderr.contains("wolm remote test New"), "{}", o.stderr);
    let asked: Vec<Value> = env.calls_of("boot_time");
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(asked[0]["host"], "NAS");
    let v = env.run_fake(&["boot-time", "--json"]).json();
    let pc_entry = v
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["host"] == "PC")
        .unwrap()
        .clone();
    assert_eq!(pc_entry["ok"], false);
    assert_eq!(pc_entry["error"]["kind"], "permission");
    assert!(
        pc_entry["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("wolm remote test PC")
    );
    // Naming the host is the confirmation (once), then runs without names include it.
    env.clear_calls();
    let o = env.run_fake(&["boot-time", "PC"]);
    assert_code(&o, 0, "named");
    assert!(o.stderr.contains("Recorded as confirmed"), "{}", o.stderr);
    assert_eq!(env.calls_of("boot_time")[0]["sign_in_confirmed"], true);
    let o = env.run_fake(&["boot-time", "PC"]);
    assert!(!o.stderr.contains("Recorded as confirmed"), "only once");
    let o = env.run_fake(&["remote", "test", "New"]);
    assert_code(&o, 0, "remote test New");
    assert!(o.stderr.contains("Recorded as confirmed"), "{}", o.stderr);
    let o = env.run_fake(&["boot-time"]);
    assert_code(&o, 0, "all confirmed");
    // Editing other fields confirms nothing new; moving the address does.
    let o = env.run(&["edit", "PC", "--notes", "desk"]);
    assert!(!o.stderr.contains("Windows sign-in"), "{}", o.stderr);
    let o = env.run(&["edit", "PC", "--address", "192.0.2.11"]);
    assert_code(&o, 0, "edit --address");
    assert!(o.stderr.contains("Recorded as confirmed"), "{}", o.stderr);
    assert_code(&env.run_fake(&["boot-time"]), 0, "still confirmed");
    // A saved password needs no confirmation (and none is recorded for SSH hosts).
    assert_eq!(env.sign_ins().len(), 2);
    // Removing the host removes its confirmation.
    env.ok(&["rm", "New"]);
    assert_eq!(env.sign_ins().len(), 1);
    env.ok(&["remote", "clear", "PC", "--yes"]);
    assert!(env.sign_ins().is_empty());
    assert_eq!(env.secrets(), json!({}));
}

/// Cross review m4, m11, m12: key files on network paths are refused when they are set; a
/// newer version's remote table is only replaced after a confirmation, and `remote clear`
/// leaves it alone (only the passwords go).
#[test]
fn remote_set_refuses_network_key_files_and_asks_before_replacing_newer_tables() {
    let env = Env::new();
    env.managed("NAS", "02:00:00:00:00:02", "ssh", "192.0.2.20");
    for unc in [r"\\server\share\id_ed25519", "//server/share/id_ed25519"] {
        let o = env.run(&["remote", "set", "NAS", "--key-file", unc]);
        assert_code(&o, 2, unc);
        assert!(o.stderr.contains("network path"), "{}", o.stderr);
    }
    assert!(env.ok(&["remote", "show", "NAS", "--json"]).json()["remote"]["key_file"].is_null());

    let id = "6f0b2c1e-3d4a-4b5c-8d6e-7f8091a2b3c4";
    let bmc = format!(
        "schema_version = 1\n\n[[hosts]]\nid = \"{id}\"\nname = \"BMC\"\nmac = \"02:00:00:00:00:05\"\naddress = \"192.0.2.50\"\n\n[hosts.remote]\nkind = \"ipmi\"\n"
    );
    env.write_config(&bmc);
    let o = env.run(&["remote", "set", "BMC", "--kind", "ssh"]);
    assert_code(&o, 2, "needs --yes");
    assert!(o.stderr.contains("--yes"), "{}", o.stderr);
    let text = std::fs::read_to_string(env.cfg_dir().join("config.toml")).unwrap();
    assert!(text.contains("ipmi"), "{text}");
    // `remote clear` of such a host: only a stored password goes, the table stays.
    let mut s = env.secrets();
    s[format!("wol-manager/host/{id}/login")] = json!({"user": "admin", "secret": "old"});
    std::fs::write(env.secret_file(), s.to_string()).unwrap();
    let o = env.run(&["remote", "clear", "BMC", "--yes", "--json"]);
    assert_code(&o, 0, "clear the password");
    assert_eq!(o.json()["secrets_deleted"], 1);
    assert_eq!(o.json()["changed"], false);
    let text = std::fs::read_to_string(env.cfg_dir().join("config.toml")).unwrap();
    assert!(text.contains("ipmi"), "{text}");
    let o = env.run(&["remote", "clear", "BMC", "--yes"]);
    assert_code(&o, 1, "nothing left");
    assert!(o.stderr.contains("newer version"), "{}", o.stderr);
    // With --yes the table is replaced.
    env.ok(&["remote", "set", "BMC", "--kind", "ssh", "--yes"]);
    let text = std::fs::read_to_string(env.cfg_dir().join("config.toml")).unwrap();
    assert!(
        !text.contains("ipmi") && text.contains("kind = \"ssh\""),
        "{text}"
    );
}

/// Cross review m5 / m6 / n9: a single adapter that is not chosen automatically is named with
/// the reason (never "1 candidates"), and a chosen Wi-Fi / disconnected adapter gets a note.
#[test]
fn mac_messages_for_a_single_or_doubtful_candidate() {
    let env = Env::new();
    env.managed("PC", "02:00:00:00:00:01", "windows", "192.0.2.10");
    env.set_fake(json!({"mac": {"candidates": [
        {"iface": "Wi-Fi", "mac": "AA:BB:CC:00:00:02", "kind": "wifi", "score": 10}]}}));
    let o = env.run_fake(&["mac", "PC", "--save"]);
    assert_code(&o, 2, "single wifi");
    assert!(
        o.stderr.contains("The only adapter found, Wi-Fi")
            && o.stderr.contains("Wi-Fi adapter")
            && o.stderr.contains("--pick 1"),
        "{}",
        o.stderr
    );
    assert!(!o.stderr.contains("1 candidates"), "{}", o.stderr);
    let o = env.run_fake(&["edit", "PC", "--arp"]);
    assert_code(&o, 2, "edit --arp, single wifi");
    assert!(
        o.stderr.contains("reported only Wi-Fi") && o.stderr.contains("wolm mac PC"),
        "{}",
        o.stderr
    );
    assert!(!o.stderr.contains("1 network adapters"), "{}", o.stderr);
    // --pick 1 saves it, with a note why it may not work.
    let o = env.run_fake(&["mac", "PC", "--save", "--pick", "1"]);
    assert_code(&o, 0, "pick 1");
    assert!(o.stderr.contains("Wi-Fi adapter"), "{}", o.stderr);
    // Several, the best one disconnected: the reason, not "fit equally well".
    env.set_fake(json!({"mac": {"candidates": [
        {"iface": "eth0", "mac": "AA:BB:CC:00:00:03", "score": 9, "link_up": false},
        {"iface": "eth1", "mac": "AA:BB:CC:00:00:04", "score": 5, "link_up": false}]}}));
    let o = env.run_fake(&["mac", "PC", "--save"]);
    assert_code(&o, 2, "best one down");
    assert!(
        o.stderr.contains("2 candidates") && o.stderr.contains("not connected"),
        "{}",
        o.stderr
    );
    let o = env.run_fake(&["mac", "PC", "--save", "--pick", "2"]);
    assert_code(&o, 0, "pick 2");
    assert!(
        o.stderr.contains("eth1: it is not connected"),
        "{}",
        o.stderr
    );
}

/// Review R1 / R3 / R4 / R9 / R10 (CLI texts; fake backend and file secret store, nothing is
/// sent anywhere: 192.0.2.x is off-link, so the MAC lookup decides locally).
#[test]
fn review_cli_vpn_hosts_accounts_and_notes() {
    let env = Env::new();
    let all = |o: &Out| format!("{}{}", o.stdout, o.stderr);

    // R1: `add --arp` for an address ARP cannot reach names the steps that work; nothing is
    // added. `edit --arp` of an unmanaged host points to `remote set`.
    let o = env.run_fake(&["add", "VPNPC", "--address", "192.0.2.50", "--arp"]);
    assert_code(&o, 3, "add --arp off-link");
    for s in [
        "hint:",
        "wolm add VPNPC --address 192.0.2.50 --mac 02-00-00-00-00-01",
        "wolm remote set VPNPC --kind windows",
        "wolm mac VPNPC --save",
    ] {
        assert!(o.stderr.contains(s), "{s}: {}", o.stderr);
    }
    let e = env
        .run_fake(&["add", "VPNPC", "--address", "192.0.2.50", "--arp", "--json"])
        .error_json();
    assert_eq!(e["error"]["exit_code"], 3);
    assert!(
        e["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("wolm mac VPNPC --save"),
        "{e}"
    );
    assert!(env.run(&["show", "VPNPC"]).code != 0, "not added");
    env.ok(&[
        "add",
        "Plain",
        "--mac",
        "02:00:00:00:00:03",
        "--address",
        "192.0.2.51",
    ]);
    let o = env.run_fake(&["edit", "Plain", "--arp"]);
    assert_code(&o, 3, "edit --arp unmanaged");
    assert!(
        o.stderr.contains("wolm remote set Plain --kind windows"),
        "{}",
        o.stderr
    );
    // ... and the documented sequence works.
    env.ok(&[
        "add",
        "VPNPC",
        "--address",
        "192.0.2.50",
        "--mac",
        "02-00-00-00-00-01",
    ]);
    let o = env.ok(&["remote", "set", "VPNPC", "--kind", "windows"]);
    // R4: the next step names the sign-in and how to use the target's own account.
    assert!(
        o.stderr.contains(r"--user PC\user") && o.stderr.contains("e-mail address"),
        "{}",
        o.stderr
    );
    env.set_fake(json!({"mac": {"candidates": [{"iface": "Ethernet",
        "mac": "00:11:22:33:44:5A", "kind": "physical", "score": 10,
        "on_default_route": true, "link_up": true}]}}));
    let o = env.run_fake(&["mac", "VPNPC", "--save"]);
    assert_code(&o, 0, "mac --save");
    assert_eq!(
        env.ok(&["show", "VPNPC", "--json"]).json()["mac"],
        "00:11:22:33:44:5A"
    );

    // R3: the note under a Windows connection test follows the WMI outcome.
    for (check, stream_has, text) in [
        ("wmi_denied", "warning:", "KB951016"),
        (
            "wmi_unreachable",
            "note:",
            "Windows Management Instrumentation",
        ),
        ("unknown", "note:", "could not be checked"),
    ] {
        env.set_fake(
            json!({"test": {"os": "Microsoft Windows 11 Pro", "admin_check": check,
            "boot": {"uptime_secs": 60}}}),
        );
        let o = env.run_fake(&["remote", "test", "VPNPC"]);
        assert_code(&o, 0, check);
        assert!(
            o.stderr.contains(stream_has) && o.stderr.contains(text),
            "{check}: {}",
            o.stderr
        );
        let v = env.run_fake(&["remote", "test", "VPNPC", "--json"]).json();
        assert_eq!(v["admin_check"], check);
    }
    env.set_fake(
        json!({"test": {"os": "Microsoft Windows 11 Pro", "admin_check": "not_checked",
        "boot": {"uptime_secs": 60}}}),
    );
    let o = env.run_fake(&["remote", "test", "VPNPC"]);
    assert!(
        !o.stderr.contains("note:") && !o.stderr.contains("warning:"),
        "this PC: no note: {}",
        o.stderr
    );

    // R4: `cred set` for a Windows host without a user name says which account it stores
    // the password for; `remote show` names it.
    let o = env.run(&["remote", "show", "VPNPC"]);
    assert!(
        o.stdout
            .contains("(the current Windows sign-in; no password is stored)"),
        "{}",
        o.stdout
    );
    let o = env.run_stdin(&["cred", "set", "VPNPC", "--password-stdin"], b"pw1\n");
    assert_code(&o, 0, "cred set");
    let account = env.ok(&["cred", "list", "--json"]).json()[0]["user"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!account.is_empty());
    assert!(
        o.stderr.contains(&format!("sign-in account ({account})")) && o.stderr.contains("--user"),
        "{}",
        o.stderr
    );
    assert!(
        all(&o).contains(&format!("(account: {account})")),
        "{}",
        all(&o)
    );
    let o = env.run(&["remote", "show", "VPNPC"]);
    assert!(
        o.stdout
            .contains(&format!("{account} (the account stored with the password)")),
        "{}",
        o.stdout
    );

    // R9: a password of a host that lost its remote management (hand edit) is not a prune
    // candidate; `cred list` says how to delete it instead of "store it again".
    let path = env.cfg_dir().join("config.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let mut out = String::new();
    let mut skipping = false;
    for line in text.lines() {
        if line.trim() == "[hosts.remote]" {
            skipping = true;
            continue;
        }
        if skipping && line.starts_with('[') {
            skipping = false;
        }
        if !skipping {
            out.push_str(line);
            out.push('\n');
        }
    }
    assert!(!out.contains("kind = \"windows\""), "{out}");
    std::fs::write(&path, out).unwrap();
    let o = env.ok(&["cred", "list"]);
    assert!(
        o.stdout.contains("wolm cred delete VPNPC") && !o.stdout.contains("store it again"),
        "{}",
        o.stdout
    );
    assert_eq!(env.code(&["cred", "prune", "-n"]), 1, "not an orphan");
    let help = env.ok(&["cred", "prune", "--help"]).stdout;
    assert!(
        help.contains("no longer in these settings") && help.contains("delete HOST"),
        "{help}"
    );

    // R10: %VAR% and a leading ~ are expanded in key file paths (as cmd.exe would).
    env.ok(&[
        "add",
        "NAS",
        "--mac",
        "02:00:00:00:00:04",
        "--address",
        "192.0.2.52",
    ]);
    let keys = env.root().join("keys");
    let mut c = env.raw();
    c.env("WOLM_TEST_KEYS", &keys).args([
        "--lang",
        "en",
        "remote",
        "set",
        "NAS",
        "--kind",
        "ssh",
        "--key-file",
        r"%WOLM_TEST_KEYS%\id_test",
    ]);
    let o = Env::exec(c);
    assert_code(&o, 0, "remote set --key-file %VAR%");
    let v = env.ok(&["remote", "show", "NAS", "--json"]).json();
    assert_eq!(
        v["remote"]["key_file"],
        keys.join("id_test").display().to_string()
    );
    let mut c = env.raw();
    c.env("USERPROFILE", env.root()).args([
        "--lang",
        "en",
        "remote",
        "set",
        "NAS",
        "--key-file",
        r"~\.ssh\id_home",
    ]);
    assert_code(&Env::exec(c), 0, "remote set --key-file ~");
    let v = env.ok(&["remote", "show", "NAS", "--json"]).json();
    assert_eq!(
        v["remote"]["key_file"],
        env.root()
            .join(".ssh")
            .join("id_home")
            .display()
            .to_string()
    );
    let help = env.ok(&["--help"]).stdout;
    assert!(
        help.contains("$env:USERPROFILE") && help.contains("(cmd.exe)"),
        "{help}"
    );
}
