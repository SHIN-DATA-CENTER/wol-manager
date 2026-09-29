//! End-to-end tests of `wolm`. Every run uses a temporary settings folder
//! (`WOL_MANAGER_CONFIG_DIR`) and a JSON file instead of the registry for PATH
//! (`WOL_MANAGER_PATH_BACKEND_FILE`, debug builds). Packets go to 127.0.0.1 only.

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

    fn path_file(&self) -> PathBuf {
        self.root().join("path.json")
    }

    /// `wolm` with the test environment and no arguments.
    fn raw(&self) -> Command {
        let mut c = Command::new(BIN);
        c.env(ENV_CONFIG_DIR, self.cfg_dir())
            .env(ENV_PATH_FILE, self.path_file())
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
            "192.168.1.10",
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
            "１９２．１６８．１．２０",
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
    assert_eq!(list[1]["address"], "192.168.1.20");
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
    assert!(o.stdout.contains("192.168.1.20"));

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
        "10.0.20.255",
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
        serde_json::json!(["10.0.20.255", "relay.lan:9"])
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
    assert_eq!(keys.len(), 18);
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
        "10.0.20.255",
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
        assert_eq!(nas["targets"], serde_json::json!(["10.0.20.255"]), "{ext}");
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
/// 192.168.1.30,書斎,日本語のメモ` encoded in Shift_JIS (Windows-31J), as Excel writes it.
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
    b.extend(b",00-11-22-33-44-66,192.168.1.30,");
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
    assert_eq!(h["address"], "192.168.1.30");
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
