use super::*;
use std::net::Ipv4Addr;

const SAMPLE: &str = r#"
schema_version = 1
future_top_level = "keep me"

[settings]
language = "ja"
future_setting = 42

[settings.wake]
port = 9
repeat = 3
interval_ms = 100
limited_broadcast = true
include_virtual = false
interfaces = []
verify_timeout_secs = 120
wake_future = [1, 2]

[settings.probe]
method = "auto"
timeout_ms = 1000
tcp_ports = [3389, 445, 22]

[settings.gui]
theme = "system"
show_tray = true
close_to_tray = false
minimize_to_tray = false
start_in_tray = false
poll_interval_secs = 30
renderer = "auto"
gui_future = { a = 1 }

[settings.future_section]
x = "y"

[[hosts]]
id = "5f0c6a1e-3b7d-4f5e-9a51-2d6c1f0e8b44"
name = "NAS"
mac = "00:11:22:33:44:55"
address = "192.168.1.10"
group = "Home"
notes = "書斎の NAS"
host_future = "kept"

[[hosts]]
name = "Lab-PC"
mac = "AA-BB-CC-DD-EE-FF"
address = "lab-pc.example.lan"
group = "Lab"
port = 7
secureon = "01:23:45:67:89:AB"
targets = ["10.0.20.255", "wol-relay.example.lan:9"]
broadcast = false
interfaces = ["{00000000-0000-0000-0000-000000000001}"]
probe = "tcp"
tcp_ports = [3389]

[future_table]
answer = 42
"#;

fn sample() -> Config {
    Config::from_toml(SAMPLE).unwrap().0
}

#[test]
fn parses_sample() {
    let (cfg, notes) = Config::from_toml(SAMPLE).unwrap();
    assert_eq!(notes, vec![ParseNote::AssignedIds { count: 1 }]);
    assert_eq!(cfg.schema_version, 1);
    assert_eq!(cfg.settings.language, crate::i18n::LangSetting::Ja);
    assert_eq!(cfg.hosts.len(), 2);
    let nas = &cfg.hosts[0];
    assert_eq!(nas.id.to_string(), "5f0c6a1e-3b7d-4f5e-9a51-2d6c1f0e8b44");
    assert_eq!(
        nas.address,
        Some(HostAddr::V4(Ipv4Addr::new(192, 168, 1, 10)))
    );
    assert!(nas.broadcast);
    let lab = &cfg.hosts[1];
    assert_eq!(lab.mac.to_string(), "AA:BB:CC:DD:EE:FF");
    assert_eq!(lab.port, Some(7));
    assert_eq!(lab.targets.len(), 2);
    assert!(!lab.broadcast);
    assert_eq!(lab.probe, Some(ProbeMethod::Tcp));
    assert_eq!(lab.id.get_version_num(), 5);
    assert!(cfg.validate().is_empty(), "{:?}", cfg.validate());
}

#[test]
fn unknown_keys_survive_round_trip() {
    let cfg = sample();
    let text = cfg.to_toml().unwrap();
    assert!(text.starts_with(FILE_HEADER));
    for needle in [
        "future_top_level",
        "future_setting",
        "wake_future",
        "gui_future",
        "future_section",
        "host_future",
        "future_table",
    ] {
        assert!(text.contains(needle), "{needle} missing in:\n{text}");
    }
    let (again, notes) = Config::from_toml(&text).unwrap();
    assert!(notes.is_empty(), "ids were persisted: {notes:?}");
    assert_eq!(again, cfg);
    // Serializing twice gives identical text.
    assert_eq!(again.to_toml().unwrap(), text);
}

#[test]
fn deterministic_ids_are_stable() {
    let a = sample();
    let b = sample();
    assert_eq!(a.hosts[1].id, b.hosts[1].id);
    assert_eq!(
        a.hosts[1].id,
        Config::deterministic_id(1, "Lab-PC", &"AA:BB:CC:DD:EE:FF".parse().unwrap())
    );
}

#[test]
fn duplicate_ids_are_replaced_deterministically() {
    let text = r#"
[[hosts]]
id = "5f0c6a1e-3b7d-4f5e-9a51-2d6c1f0e8b44"
name = "A"
mac = "00:11:22:33:44:55"
[[hosts]]
id = "5f0c6a1e-3b7d-4f5e-9a51-2d6c1f0e8b44"
name = "B"
mac = "00:11:22:33:44:56"
"#;
    let (a, notes) = Config::from_toml(text).unwrap();
    let (b, _) = Config::from_toml(text).unwrap();
    assert_eq!(notes.len(), 1);
    assert_ne!(a.hosts[0].id, a.hosts[1].id);
    assert_eq!(a.hosts[1].id, b.hosts[1].id);
}

#[test]
fn bom_and_parse_errors() {
    let (cfg, _) = Config::from_toml("\u{FEFF}schema_version = 1\n").unwrap();
    assert_eq!(cfg.schema_version, 1);
    let err = Config::from_toml("schema_version = 1\n[settings\nx=1").unwrap_err();
    match err {
        Error::ConfigParse { line, .. } => assert_eq!(line, Some(2)),
        other => panic!("unexpected {other:?}"),
    }
    let err = Config::from_toml("[[hosts]]\nname = \"x\"\nmac = \"zz\"\n").unwrap_err();
    assert!(
        matches!(err, Error::ConfigParse { line: Some(3), .. }),
        "{err:?}"
    );
}

#[test]
fn empty_file_gives_defaults() {
    let (cfg, notes) = Config::from_toml("").unwrap();
    assert_eq!(cfg, Config::default());
    assert!(notes.is_empty());
    assert!(!cfg.is_newer_schema());
    let (newer, _) = Config::from_toml("schema_version = 2").unwrap();
    assert!(newer.is_newer_schema());
}

/// Plan §5.2: a newer file opens read-only even when it uses values this build does not
/// know; the current version stays strict.
#[test]
fn newer_schema_with_unknown_values_parses_leniently() {
    let text = r#"
schema_version = 2
future_top = { a = 1 }
[settings]
language = "de"
[settings.wake]
port = 70000
repeat = 5
[settings.probe]
method = "arp"
timeout_ms = 2500
[settings.gui]
theme = "neon"
renderer = "skia"
show_tray = false

[[hosts]]
id = "5f0c6a1e-3b7d-4f5e-9a51-2d6c1f0e8b44"
name = "NAS"
mac = "00:11:22:33:44:55"
address = "fe80::1"
probe = "arp"
targets = ["[fe80::1]:9"]
notes = "kept"

[[hosts]]
name = "Broken"
mac = "not a mac"
"#;
    let (cfg, _) = Config::from_toml(text).unwrap();
    assert!(cfg.is_newer_schema());
    assert_eq!(cfg.schema_version, 2);
    let s = &cfg.settings;
    assert_eq!(s.language, crate::i18n::LangSetting::Auto);
    assert_eq!(s.wake.port, 9);
    assert_eq!(s.wake.repeat, 5);
    assert_eq!(s.probe.method, ProbeMethod::Auto);
    assert_eq!(s.probe.timeout_ms, 2500);
    assert_eq!(s.gui.theme, Theme::System);
    assert_eq!(s.gui.renderer, Renderer::Auto);
    assert!(!s.gui.show_tray);
    assert!(cfg.extra.contains_key("future_top"));
    assert_eq!(cfg.hosts.len(), 2);
    let nas = &cfg.hosts[0];
    assert_eq!(nas.id.to_string(), "5f0c6a1e-3b7d-4f5e-9a51-2d6c1f0e8b44");
    assert_eq!(nas.address, None);
    assert_eq!(nas.probe, None);
    assert!(nas.targets.is_empty());
    assert_eq!(nas.notes.as_deref(), Some("kept"));
    assert!(cfg.hosts[1].mac.is_zero());

    // A huge version still counts as newer.
    let (big, _) =
        Config::from_toml("schema_version = 99999999999\n[settings.probe]\nmethod = \"x\"\n")
            .unwrap();
    assert!(big.is_newer_schema());

    // The current version is strict (typos keep their line), and syntax errors in a newer
    // file are still errors.
    for text in [
        "schema_version = 1\n[settings.probe]\nmethod = \"arp\"\n",
        "[settings.probe]\nx = 1\nmethod = \"arp\"\n",
    ] {
        assert!(
            matches!(
                Config::from_toml(text),
                Err(Error::ConfigParse { line: Some(3), .. })
            ),
            "{text}"
        );
    }
    assert!(matches!(
        Config::from_toml("schema_version = 2\n[settings\n"),
        Err(Error::ConfigParse { .. })
    ));
}

#[test]
fn find_rules() {
    let mut cfg = sample();
    let nas_id = cfg.hosts[0].id;
    // 1. exact id
    assert_eq!(cfg.find(&nas_id.to_string()).unwrap().name, "NAS");
    // 2. name, width-folded and case-insensitive
    assert_eq!(cfg.find("ｎａｓ").unwrap().id, nas_id);
    assert_eq!(cfg.find(" lab-pc ").unwrap().name, "Lab-PC");
    // 3. id prefix (>= 8)
    assert_eq!(cfg.find("5f0c6a1e").unwrap().id, nas_id);
    assert_eq!(cfg.find("5F0C6A1E-3B7D").unwrap().id, nas_id);
    assert!(matches!(cfg.find("5f0c6a1"), Err(Error::HostNotFound(_))));
    // 4. MAC
    assert_eq!(cfg.find("00-11-22-33-44-55").unwrap().id, nas_id);
    assert_eq!(cfg.find("aabbccddeeff").unwrap().name, "Lab-PC");
    // Not found
    assert!(matches!(cfg.find("nothing"), Err(Error::HostNotFound(_))));
    // Name beats MAC: a host named like another host's id prefix is found by name first.
    let mut h = Host::new("deadbeefcafe0", "02:00:00:00:00:01".parse().unwrap());
    h.id = "5f0c6a1e-0000-4000-8000-000000000000".parse().unwrap();
    cfg.hosts.push(h);
    assert!(matches!(
        cfg.find("5f0c6a1e"),
        Err(Error::AmbiguousHost { .. })
    ));
    assert_eq!(cfg.find("deadbeefcafe0").unwrap().name, "deadbeefcafe0");
    // Same MAC twice -> ambiguous
    let dup = Host::new("Other", "00:11:22:33:44:55".parse().unwrap());
    cfg.hosts.push(dup);
    let e = cfg.find("00:11:22:33:44:55").unwrap_err();
    assert_eq!(e.kind(), crate::ErrorKind::Ambiguous);
}

#[test]
fn groups_and_membership() {
    let mut cfg = sample();
    let mut extra = Host::new("X", "02:00:00:00:00:02".parse().unwrap());
    extra.group = Some("ｈｏｍｅ".into());
    cfg.hosts.push(extra);
    assert_eq!(cfg.groups(), vec!["Home".to_string(), "Lab".to_string()]);
    assert_eq!(cfg.hosts_in_group("HOME").len(), 2);
    assert!(cfg.hosts_in_group("none").is_empty());
}

#[test]
fn name_rules() {
    let cfg = sample();
    assert_eq!(cfg.check_name("", None), Err(FieldIssue::Required));
    assert_eq!(cfg.check_name("  \t ", None), Err(FieldIssue::Required));
    assert_eq!(
        cfg.check_name(&"x".repeat(65), None),
        Err(FieldIssue::NameTooLong)
    );
    assert!(cfg.check_name(&"あ".repeat(64), None).is_ok());
    assert_eq!(
        cfg.check_name("00-11-22-33-44-66", None),
        Err(FieldIssue::NameLooksLikeMac)
    );
    assert_eq!(
        cfg.check_name("ＮＡＳ", None),
        Err(FieldIssue::DuplicateName)
    );
    assert!(cfg.check_name("nas", Some(cfg.hosts[0].id)).is_ok());
    assert_eq!(cfg.unique_name("NAS"), "NAS (2)");
    assert_eq!(cfg.unique_name("New"), "New");
}

#[test]
fn draft_round_trip_preserves_everything() {
    let cfg = sample();
    for h in &cfg.hosts {
        let d = HostDraft::from_host(h);
        let built = d.build(&cfg, Some(&EditBase::of(h))).unwrap();
        assert_eq!(&built, h, "unchanged draft must give the identical host");
    }
}

#[test]
fn draft_overwrites_only_edited_fields() {
    let cfg = sample();
    let lab = cfg.hosts[1].clone();
    let mut d = HostDraft::from_host(&lab);
    d.notes = "新しいメモ".into();
    d.port = "".into();
    let built = d.build(&cfg, Some(&EditBase::of(&lab))).unwrap();
    assert_eq!(built.notes.as_deref(), Some("新しいメモ"));
    assert_eq!(built.port, None);
    // Everything else, including hidden fields and extra, is unchanged.
    assert_eq!(built.id, lab.id);
    assert_eq!(built.targets, lab.targets);
    assert_eq!(built.interfaces, lab.interfaces);
    assert_eq!(built.secureon, lab.secureon);
    assert_eq!(built.tcp_ports, lab.tcp_ports);
    assert_eq!(built.probe, lab.probe);
    assert!(!built.broadcast);
    let nas = &cfg.hosts[0];
    let mut d = HostDraft::from_host(nas);
    d.mac = "ＡＡ－ＢＢ－ＣＣ－００－１１－２２".into();
    let built = d.build(&cfg, Some(&EditBase::of(nas))).unwrap();
    assert_eq!(built.mac.to_string(), "AA:BB:CC:00:11:22");
    assert_eq!(
        built.extra.get("host_future").unwrap().as_str(),
        Some("kept")
    );
}

#[test]
fn draft_collects_all_errors() {
    let cfg = sample();
    let d = HostDraft {
        name: "nas".into(),
        mac: "xx".into(),
        address: "1.2.3.400".into(),
        port: "70000".into(),
        secureon: "12".into(),
        targets: "a b:0".into(),
        tcp_ports: "22,x".into(),
        ..HostDraft::default()
    };
    let errs = d.build(&cfg, None).unwrap_err();
    let issues: Vec<(Field, FieldIssue)> = errs.iter().map(|e| (e.field, e.issue)).collect();
    assert_eq!(
        issues,
        vec![
            (Field::Name, FieldIssue::DuplicateName),
            (Field::Mac, FieldIssue::InvalidMac),
            (Field::Address, FieldIssue::InvalidAddress),
            (Field::Port, FieldIssue::InvalidPort),
            (Field::SecureOn, FieldIssue::InvalidSecureOn),
            (Field::Targets, FieldIssue::InvalidTarget),
            (Field::TcpPorts, FieldIssue::InvalidPortList),
        ]
    );
    let empty = HostDraft::default().build(&cfg, None).unwrap_err();
    assert_eq!(
        empty,
        vec![
            FieldError::new(Field::Name, FieldIssue::Required),
            FieldError::new(Field::Mac, FieldIssue::Required)
        ]
    );
    let kana = HostDraft {
        name: "PC".into(),
        mac: "あ".into(),
        ..HostDraft::default()
    };
    assert_eq!(
        kana.build(&cfg, None).unwrap_err(),
        vec![FieldError::new(Field::Mac, FieldIssue::ImeKana)]
    );
}

#[test]
fn draft_new_host_and_save() {
    let mut cfg = sample();
    let d = HostDraft {
        name: " Desk ".into(),
        mac: "02:00:00:00:00:09".into(),
        address: "desk.lan".into(),
        group: "Home".into(),
        tcp_ports: "3389".into(),
        ..HostDraft::default()
    };
    let id = cfg.save_draft(&d, None).unwrap();
    let h = cfg.get(id).unwrap();
    assert_eq!(h.name, "Desk");
    assert!(h.broadcast);
    assert_eq!(h.id.get_version_num(), 4);
    assert_eq!(h.tcp_ports, vec![3389]);
    // Editing a host deleted meanwhile.
    let base = EditBase::of(h);
    cfg.remove_host(id).unwrap();
    assert!(matches!(
        cfg.save_draft(&d, Some(&base)),
        Err(Error::HostIdNotFound(_))
    ));
    // "Save as new" after that: every field of the draft is used.
    let again = cfg.save_draft(&d, None).unwrap();
    assert_eq!(
        cfg.get(again).unwrap().address,
        Some("desk.lan".parse().unwrap())
    );
}

/// Plan §11.10: a field another process changed while the editor was open is not reverted
/// by a save that did not touch it; fields the user did change win.
#[test]
fn draft_save_keeps_concurrent_changes_to_untouched_fields() {
    let mut on_disk = sample();
    let lab = on_disk.hosts[1].clone();
    // The editor opens on the host as it was.
    let base = EditBase::of(&lab);
    let mut draft = base.draft.clone();
    // Meanwhile another process (wolm edit) changes the port and the group.
    {
        let h = on_disk.get_mut(lab.id).unwrap();
        h.port = Some(9);
        h.group = Some("Rack 2".into());
    }
    // The user edits only the notes and saves.
    draft.notes = "moved to rack 2".into();
    let id = on_disk.save_draft(&draft, Some(&base)).unwrap();
    let saved = on_disk.get(id).unwrap();
    assert_eq!(saved.notes.as_deref(), Some("moved to rack 2"));
    assert_eq!(saved.port, Some(9), "concurrent port change was reverted");
    assert_eq!(saved.group.as_deref(), Some("Rack 2"));
    assert_eq!(saved.targets, lab.targets);

    // A field both changed: the user's edit wins.
    let base = EditBase::of(on_disk.get(id).unwrap());
    let mut draft = base.draft.clone();
    on_disk.get_mut(id).unwrap().port = Some(40000);
    draft.port = String::new();
    on_disk.save_draft(&draft, Some(&base)).unwrap();
    assert_eq!(on_disk.get(id).unwrap().port, None);

    // A concurrent rename is kept when the user did not touch the name, and the name
    // check uses the resulting (current) name.
    let base = EditBase::of(on_disk.get(id).unwrap());
    let mut draft = base.draft.clone();
    on_disk.get_mut(id).unwrap().name = "Lab-PC renamed".into();
    draft.notes = "x".into();
    on_disk.save_draft(&draft, Some(&base)).unwrap();
    assert_eq!(on_disk.get(id).unwrap().name, "Lab-PC renamed");
}

#[test]
fn port_zero_falls_back_to_the_default() {
    let mut s = Settings::default();
    let mut h = Host::new("PC", "02:00:00:00:00:01".parse().unwrap());
    h.port = Some(0);
    assert_eq!(h.effective_port(&s), 9);
    s.wake.port = 7;
    assert_eq!(h.effective_port(&s), 7);
    h.port = Some(40000);
    assert_eq!(h.effective_port(&s), 40000);
    h.port = None;
    s.wake.port = 0;
    assert_eq!(h.effective_port(&s), 9);
}

#[test]
fn insert_and_replace_store_cleaned_names() {
    let mut cfg = Config::default();
    let id = cfg
        .insert_host(Host::new(" a\tb\n ", "02:00:00:00:00:01".parse().unwrap()))
        .unwrap();
    assert_eq!(cfg.get(id).unwrap().name, "a b");
    let mut h = cfg.get(id).unwrap().clone();
    h.name = "\u{3000}c\r\n".into();
    cfg.replace_host(h).unwrap();
    assert_eq!(cfg.get(id).unwrap().name, "c");
    assert!(cfg.validate().is_empty());
    assert!(matches!(
        cfg.insert_host(Host::new(" \t ", "02:00:00:00:00:02".parse().unwrap())),
        Err(Error::InvalidFields(_))
    ));
}

#[test]
fn draft_copy_keeps_hidden_fields() {
    let cfg = sample();
    let lab = &cfg.hosts[1];
    let mut d = HostDraft::from_host(lab);
    d.name = cfg.unique_name("Lab-PC");
    let copy = d.build_copy(&cfg, lab).unwrap();
    assert_ne!(copy.id, lab.id);
    assert_eq!(copy.name, "Lab-PC (2)");
    assert_eq!(copy.interfaces, lab.interfaces);
    assert_eq!(copy.extra, lab.extra);
}

#[test]
fn check_field_live_validation() {
    assert_eq!(check_field(Field::Mac, ""), Err(FieldIssue::Required));
    assert_eq!(check_field(Field::Mac, "ab"), Err(FieldIssue::InvalidMac));
    assert_eq!(
        check_field(Field::Mac, "11-22-33-44-55-66"),
        Err(FieldIssue::MacNotUnicast)
    );
    assert!(check_field(Field::Mac, "001122334455").is_ok());
    assert_eq!(
        check_field(Field::TcpPorts, "1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17"),
        Err(FieldIssue::TooManyPorts)
    );
    assert!(check_field(Field::Address, "").is_ok());
    assert_eq!(check_field(Field::Address, "あ"), Err(FieldIssue::ImeKana));
    assert!(check_field(Field::Port, "").is_ok());
    assert_eq!(check_field(Field::Port, "0"), Err(FieldIssue::InvalidPort));
    assert_eq!(
        check_field(Field::Name, "00:11:22:33:44:55"),
        Err(FieldIssue::NameLooksLikeMac)
    );
    assert!(check_field(Field::Notes, "anything").is_ok());
}

#[test]
fn validate_reports_problems() {
    let mut cfg = sample();
    cfg.hosts[1].name = "nas".into();
    cfg.hosts[1].mac = MacAddr::default();
    cfg.hosts[0].tcp_ports = (20000..=20016).collect();
    cfg.settings.wake.repeat = 0;
    let issues = cfg.validate();
    assert!(issues.contains(&ConfigIssue::Host {
        id: cfg.hosts[0].id,
        name: cfg.hosts[0].name.clone(),
        field: Field::TcpPorts,
        issue: FieldIssue::TooManyPorts
    }));
    assert!(issues.contains(&ConfigIssue::Host {
        id: cfg.hosts[1].id,
        name: "nas".into(),
        field: Field::Mac,
        issue: FieldIssue::MacNotUnicast
    }));
    assert_eq!(
        issues
            .iter()
            .filter(|i| matches!(
                i,
                ConfigIssue::Host {
                    issue: FieldIssue::DuplicateName,
                    ..
                }
            ))
            .count(),
        2
    );
    assert!(issues.iter().any(|i| matches!(
        i,
        ConfigIssue::Setting {
            key: "wake.repeat",
            ..
        }
    )));
}

#[test]
fn search() {
    let cfg = sample();
    let nas = &cfg.hosts[0];
    assert!(nas.matches_search("書斎"));
    assert!(nas.matches_search("ｈｏｍｅ"));
    assert!(nas.matches_search("001122"));
    assert!(nas.matches_search("00:11"));
    assert!(nas.matches_search("192.168"));
    assert!(!nas.matches_search("lab"));
    assert!(nas.matches_search(""));
}

#[test]
fn insert_replace_remove() {
    let mut cfg = sample();
    let h = Host::new("NAS", "02:00:00:00:00:03".parse().unwrap());
    assert!(cfg.insert_host(h).is_err());
    let h = Host::new("NAS2", "02:00:00:00:00:03".parse().unwrap());
    let id = cfg.insert_host(h).unwrap();
    let mut h = cfg.get(id).unwrap().clone();
    h.notes = Some("x".into());
    cfg.replace_host(h).unwrap();
    assert_eq!(cfg.get(id).unwrap().notes.as_deref(), Some("x"));
    cfg.remove_host(id).unwrap();
    assert!(cfg.remove_host(id).is_err());
}

// ---- v0.2.0: remote management ------------------------------------------------------------------

const ED25519: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

const REMOTE_SAMPLE: &str = r#"
schema_version = 1

[settings.remote]
shutdown_delay_secs = 60
force_apps_closed = false
restart_verify_timeout_secs = 900
shutdown_verify_timeout_secs = 120
connect_timeout_ms = 3000
auto_boot_time = false
remote_future = "kept"

[[hosts]]
id = "5f0c6a1e-3b7d-4f5e-9a51-2d6c1f0e8b44"
name = "Desk"
mac = "F4:B5:20:42:72:5C"
address = "192.168.1.199"

[hosts.remote]
kind = "windows"
user = 'DESKTOP-6FDOQLK\admin'
address = "100.105.128.173"
win_future = { a = 1 }

[[hosts]]
id = "6f0c6a1e-3b7d-4f5e-9a51-2d6c1f0e8b45"
name = "pve"
mac = "02:00:00:00:00:02"
address = "pve.example.lan"

[hosts.remote]
kind = "linux"
user = "root"
port = 2222
key_file = 'C:\Users\me\.ssh\id_ed25519'
host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
sudo = "separate"
reboot_command = "/sbin/reboot"
shutdown_command = "/sbin/poweroff"
ssh_future = [1, 2]
"#;

#[test]
fn remote_tables_parse_and_round_trip_with_unknown_keys() {
    let (cfg, _) = Config::from_toml(REMOTE_SAMPLE).unwrap();
    let s = &cfg.settings.remote;
    assert_eq!(
        (
            s.shutdown_delay_secs,
            s.force_apps_closed,
            s.restart_verify_timeout_secs,
            s.shutdown_verify_timeout_secs,
            s.connect_timeout_ms,
            s.auto_boot_time
        ),
        (60, false, 900, 120, 3000, false)
    );
    assert_eq!(s.extra["remote_future"].as_str(), Some("kept"));
    let w = cfg.hosts[0].remote.as_ref().unwrap();
    assert_eq!(w.kind, RemoteKind::Windows);
    assert_eq!(w.user.as_deref(), Some(r"DESKTOP-6FDOQLK\admin"));
    assert_eq!(
        w.address.as_ref().map(ToString::to_string).as_deref(),
        Some("100.105.128.173")
    );
    assert!(w.extra.contains_key("win_future"));
    assert_eq!(
        cfg.hosts[0].management_address().map(ToString::to_string),
        Some("100.105.128.173".into())
    );
    assert_eq!(cfg.hosts[0].remote_kind(), Some(RemoteKind::Windows));
    let l = cfg.hosts[1].remote.as_ref().unwrap();
    assert_eq!(l.kind, RemoteKind::Ssh, "`linux` is an alias of ssh");
    assert_eq!(l.ssh_port(), 2222);
    assert_eq!(l.sudo, SudoMode::Separate);
    assert_eq!(l.host_key(), Some(ED25519));
    assert_eq!(l.reboot_command.as_deref(), Some("/sbin/reboot"));
    assert_eq!(
        l.key_file.as_deref(),
        Some(std::path::Path::new(r"C:\Users\me\.ssh\id_ed25519"))
    );
    assert_eq!(l.extra["ssh_future"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        cfg.hosts[1].management_address().map(ToString::to_string),
        Some("pve.example.lan".into())
    );
    assert!(cfg.validate().is_empty(), "{:?}", cfg.validate());

    // Round trip: identical config, unknown keys kept, kind written as "ssh".
    let text = cfg.to_toml_checked().unwrap();
    let (back, _) = Config::from_toml(&text).unwrap();
    assert_eq!(back, cfg);
    assert!(text.contains("[hosts.remote]"), "{text}");
    assert!(text.contains("kind = \"ssh\""), "{text}");
    assert!(text.contains("ssh_future"), "{text}");
    assert!(text.contains("remote_future"), "{text}");
    // Defaults are not written; unmanaged hosts have no table.
    let mut plain = cfg.clone();
    plain.hosts[0].remote = Some(RemoteConfig::new(RemoteKind::Ssh));
    plain.hosts[1].remote = None;
    let text = plain.to_toml().unwrap();
    assert_eq!(text.matches("[hosts.remote]").count(), 1, "{text}");
    assert!(!text.contains("sudo ="), "{text}");
    // Settings defaults.
    let d = Settings::default().remote;
    assert_eq!(
        (
            d.shutdown_delay_secs,
            d.force_apps_closed,
            d.restart_verify_timeout_secs,
            d.shutdown_verify_timeout_secs,
            d.connect_timeout_ms,
            d.auto_boot_time
        ),
        (30, true, 600, 300, 5000, true)
    );
}

#[test]
fn remote_table_needs_a_valid_kind() {
    let base = "[[hosts]]\nname = \"a\"\nmac = \"02:00:00:00:00:01\"\n[hosts.remote]\n";
    // Missing kind, mistyped known values and bad values stay parse errors with a position.
    let e = Config::from_toml(&format!("{base}user = \"x\"\n")).unwrap_err();
    assert!(matches!(e, Error::ConfigParse { line: Some(_), .. }), "{e}");
    let e = Config::from_toml(&format!("{base}kind = \"Windows\"\n")).unwrap_err();
    assert!(matches!(e, Error::ConfigParse { line: Some(_), .. }), "{e}");
    let e = Config::from_toml(&format!("{base}kind = \"ssh\"\nsudo = \"NOPASSWD\"\n")).unwrap_err();
    assert!(matches!(e, Error::ConfigParse { .. }), "{e}");
    let e = Config::from_toml(&format!("{base}kind = \"ssh\"\naddress = \"1.2.3\"\n")).unwrap_err();
    assert!(matches!(e, Error::ConfigParse { .. }), "{e}");
    // A newer schema keeps an unreadable remote table aside as a whole (read-only view):
    // no fallback to root / port 22 / the host address for what it could not read.
    let newer = format!(
        "schema_version = 2\n[settings.remote]\nconnect_timeout_ms = \"fast\"\nshutdown_delay_secs = 10\n{base}kind = \"ipmi\"\n"
    );
    let newer = format!(
        "{newer}[[hosts]]\nname = \"b\"\nmac = \"02:00:00:00:00:02\"\n[hosts.remote]\nkind = \"ssh\"\nuser = \"pi\"\nsudo = \"doas\"\n"
    );
    let newer = format!(
        "{newer}[[hosts]]\nname = \"c\"\nmac = \"02:00:00:00:00:03\"\n[hosts.remote]\nkind = \"ssh\"\naddress = \"fe80::1\"\n"
    );
    let newer = format!(
        "{newer}[[hosts]]\nname = \"d\"\nmac = \"02:00:00:00:00:04\"\n[hosts.remote]\nkind = \"ssh\"\nuser = \"pi\"\nfuture = 1\n"
    );
    let (cfg, notes) = Config::from_toml(&newer).unwrap();
    for h in &cfg.hosts[..3] {
        assert!(h.remote.is_none(), "{}", h.name);
        assert!(h.unsupported_remote().is_some(), "{}", h.name);
    }
    assert_eq!(
        cfg.hosts[1].unsupported_remote().unwrap()["sudo"].as_str(),
        Some("doas")
    );
    // Unknown keys alone are fine (kept in `extra` of the table).
    let d = cfg.hosts[3].remote.as_ref().unwrap();
    assert_eq!(d.user.as_deref(), Some("pi"));
    assert!(d.extra.contains_key("future"));
    assert_eq!(
        notes
            .iter()
            .filter(|n| matches!(n, ParseNote::UnsupportedRemote { .. }))
            .count(),
        3
    );
    assert_eq!(cfg.settings.remote.connect_timeout_ms, 5000);
    assert_eq!(cfg.settings.remote.shutdown_delay_secs, 10);
    let (cfg, _) = Config::from_toml(&format!("{base}kind = \"ssh\"\n")).unwrap();
    assert!(cfg.hosts[0].extra.is_empty());
    assert_eq!(cfg.hosts[0].remote_kind(), Some(RemoteKind::Ssh));
}

/// Review m9: a future additive `kind` / `sudo` value in a schema-1 file does not fail the
/// whole config: the host is not managed here and the table survives a save unchanged.
#[test]
fn review_m9_unknown_remote_values_in_schema_1_are_kept() {
    let text = r#"schema_version = 1
[[hosts]]
id = "5f0c6a1e-3b7d-4f5e-9a51-2d6c1f0e8b44"
name = "bmc"
mac = "02:00:00:00:00:01"
[hosts.remote]
kind = "ipmi"
user = "admin"
cipher = 3

[[hosts]]
id = "9d7e2b10-8c4f-4a36-b1e2-6f3a0c5d7e91"
name = "bsd"
mac = "02:00:00:00:00:02"
address = "10.0.0.2"
[hosts.remote]
kind = "ssh"
sudo = "doas"

[[hosts]]
id = "1e9a5b2c-0000-4000-8000-00000000000a"
name = "ok"
mac = "02:00:00:00:00:03"
[hosts.remote]
kind = "windows"
"#;
    let (cfg, notes) = Config::from_toml(text).unwrap();
    assert!(!cfg.is_newer_schema());
    assert_eq!(
        notes,
        vec![
            ParseNote::UnsupportedRemote {
                name: "bmc".into(),
                value: "kind = \"ipmi\"".into()
            },
            ParseNote::UnsupportedRemote {
                name: "bsd".into(),
                value: "sudo = \"doas\"".into()
            },
        ]
    );
    assert!(cfg.hosts[0].remote.is_none() && cfg.hosts[1].remote.is_none());
    assert_eq!(cfg.hosts[2].remote_kind(), Some(RemoteKind::Windows));
    assert!(cfg.validate().is_empty());
    // Saved and read again: unchanged (a newer version finds its table again).
    let saved = cfg.to_toml_checked().unwrap();
    let (again, _) = Config::from_toml(&saved).unwrap();
    assert_eq!(again, cfg);
    let raw: toml::Table = toml::from_str(&saved).unwrap();
    let bmc = &raw["hosts"].as_array().unwrap()[0]["remote"];
    assert_eq!(bmc["kind"].as_str(), Some("ipmi"));
    assert_eq!(bmc["cipher"].as_integer(), Some(3));
    // Setting up remote management here replaces the kept table (no duplicate key).
    let mut edited = cfg.clone();
    edited.hosts[0].remote = Some(RemoteConfig::new(RemoteKind::Ssh));
    let saved = edited.to_toml_checked().unwrap();
    assert_eq!(saved.matches("ipmi").count(), 0, "{saved}");
    let (again, _) = Config::from_toml(&saved).unwrap();
    assert_eq!(again.hosts[0].remote_kind(), Some(RemoteKind::Ssh));
    assert!(again.hosts[0].unsupported_remote().is_none());
    let json = serde_json::to_value(&edited.hosts[0]).unwrap();
    assert_eq!(json["remote"]["kind"], "ssh");
}

#[test]
fn validate_reports_remote_problems() {
    let (mut cfg, _) = Config::from_toml(REMOTE_SAMPLE).unwrap();
    {
        let r = cfg.hosts[1].remote.as_mut().unwrap();
        r.port = Some(0);
        r.user = Some("bad user".into());
        r.host_key = Some("ssh-ed25519 ???".into());
        r.shutdown_command = Some("echo $PATH".into());
    }
    cfg.settings.remote.connect_timeout_ms = 10;
    let issues = cfg.validate();
    let fields: Vec<(Field, FieldIssue)> = issues
        .iter()
        .filter_map(|i| match i {
            ConfigIssue::Host { field, issue, .. } => Some((*field, *issue)),
            _ => None,
        })
        .collect();
    assert_eq!(
        fields,
        vec![
            (Field::RemoteUser, FieldIssue::InvalidUser),
            (Field::SshPort, FieldIssue::InvalidPort),
            (Field::SshHostKey, FieldIssue::InvalidHostKey),
            (Field::ShutdownCommand, FieldIssue::InvalidCommand),
        ]
    );
    assert!(issues.iter().any(|i| matches!(
        i,
        ConfigIssue::Setting {
            key: "remote.connect_timeout_ms",
            ..
        }
    )));
    // A Windows user with a backslash is fine; the same user is invalid for SSH.
    let mut h = cfg.hosts[0].clone();
    assert!(h.remote.as_ref().unwrap().check().is_empty());
    h.remote.as_mut().unwrap().kind = RemoteKind::Ssh;
    assert_eq!(
        h.remote.as_ref().unwrap().check(),
        vec![FieldError::new(Field::RemoteUser, FieldIssue::InvalidUser)]
    );
}

fn remote_host() -> (Config, Host) {
    let (cfg, _) = Config::from_toml(REMOTE_SAMPLE).unwrap();
    let h = cfg.hosts[1].clone();
    (cfg, h)
}

#[test]
fn remote_draft_round_trip_and_untouched_section() {
    let (cfg, h) = remote_host();
    let d = HostDraft::from_host(&h);
    assert_eq!(d.remote.kind, Some(RemoteKind::Ssh));
    assert_eq!(d.remote.port, "2222");
    assert_eq!(d.remote.sudo, SudoMode::Separate);
    assert_eq!(d.remote.host_key, ED25519);
    assert_eq!(d.remote.key_file, r"C:\Users\me\.ssh\id_ed25519");
    let base = EditBase::of(&h);
    // Untouched section: the host (incl. unknown keys in the table) is unchanged.
    assert_eq!(d.build(&cfg, Some(&base)).unwrap(), h);
    // Unmanaged host: empty section.
    let plain = HostDraft::from_host(&Host::default());
    assert_eq!(plain.remote, RemoteDraft::default());
    assert_eq!(RemoteDraft::default().build(), Ok(None));
}

#[test]
fn remote_draft_merges_only_edited_fields() {
    let (mut cfg, h) = remote_host();
    let base = EditBase::of(&h);
    let mut d = base.draft.clone();
    d.remote.user = "pi".into();
    d.remote.host_key = String::new(); // "forget" in the editor
    // Meanwhile another process changed the port and an unknown key.
    {
        let r = cfg.hosts[1].remote.as_mut().unwrap();
        r.port = Some(2200);
        r.extra.insert("other".into(), toml::Value::Integer(1));
    }
    let id = cfg.save_draft(&d, Some(&base)).unwrap();
    let r = cfg.get(id).unwrap().remote.clone().unwrap();
    assert_eq!(r.user.as_deref(), Some("pi"));
    assert_eq!(r.host_key, None);
    assert_eq!(
        r.port,
        Some(2200),
        "concurrent change to an untouched field kept"
    );
    assert!(r.extra.contains_key("other") && r.extra.contains_key("ssh_future"));
    assert_eq!(r.sudo, SudoMode::Separate);
    assert_eq!(r.reboot_command.as_deref(), Some("/sbin/reboot"));

    // Kind None removes the table.
    let h = cfg.get(id).unwrap().clone();
    let base = EditBase::of(&h);
    let mut d = base.draft.clone();
    d.remote.kind = None;
    cfg.save_draft(&d, Some(&base)).unwrap();
    assert!(cfg.get(id).unwrap().remote.is_none());

    // Setting it up again: a new table from every field of the draft.
    let h = cfg.get(id).unwrap().clone();
    let base = EditBase::of(&h);
    let mut d = base.draft.clone();
    d.remote = RemoteDraft {
        kind: Some(RemoteKind::Windows),
        user: r" .\Administrator ".into(),
        address: "１００.１０５.１.２".into(),
        sudo: SudoMode::Auto,
        ..RemoteDraft::default()
    };
    cfg.save_draft(&d, Some(&base)).unwrap();
    let r = cfg.get(id).unwrap().remote.clone().unwrap();
    assert_eq!(r.kind, RemoteKind::Windows);
    assert_eq!(r.user.as_deref(), Some(r".\Administrator"));
    assert_eq!(
        r.address.map(|a| a.to_string()).as_deref(),
        Some("100.105.1.2")
    );
    assert_eq!((r.port, r.host_key, r.key_file), (None, None, None));
    assert!(r.extra.is_empty());
}

#[test]
fn remote_draft_kind_change_rechecks_the_user_and_reports_errors() {
    let (mut cfg, _) = remote_host();
    // Windows host with a DOMAIN\user: switching to SSH without touching the user fails.
    let win = cfg.hosts[0].clone();
    let base = EditBase::of(&win);
    let mut d = base.draft.clone();
    d.remote.kind = Some(RemoteKind::Ssh);
    let errs = d.build(&cfg, Some(&base)).unwrap_err();
    assert_eq!(
        errs,
        vec![FieldError::new(Field::RemoteUser, FieldIssue::InvalidUser)]
    );
    d.remote.user = "admin".into();
    cfg.save_draft(&d, Some(&base)).unwrap();
    assert_eq!(cfg.hosts[0].remote.as_ref().unwrap().kind, RemoteKind::Ssh);
    // Every remote field error, in field order.
    let h = cfg.hosts[0].clone();
    let base = EditBase::of(&h);
    let mut d = base.draft.clone();
    d.remote.user = "a b".into();
    d.remote.address = "1.2.3".into();
    d.remote.port = "70000".into();
    d.remote.host_key = "junk".into();
    d.remote.reboot_command = "a'b".into();
    d.remote.shutdown_command = "`x`".into();
    let errs = d.build(&cfg, Some(&base)).unwrap_err();
    let fields: Vec<Field> = errs.iter().map(|e| e.field).collect();
    assert_eq!(
        fields,
        vec![
            Field::RemoteUser,
            Field::RemoteAddress,
            Field::SshPort,
            Field::SshHostKey,
            Field::RebootCommand,
            Field::ShutdownCommand
        ]
    );
    let err: Error = errs.into();
    assert!(!crate::i18n::describe_error(&err, crate::i18n::Lang::Ja).is_empty());
    // RemoteDraft::build on its own.
    let rd = RemoteDraft {
        kind: Some(RemoteKind::Ssh),
        port: "22".into(),
        key_file: "\"C:\\k\\id\"".into(),
        host_key: format!("{ED25519} me@pc"),
        ..RemoteDraft::default()
    };
    let r = rd.build().unwrap().unwrap();
    assert_eq!(r.port, Some(22));
    assert_eq!(
        r.key_file.as_deref(),
        Some(std::path::Path::new(r"C:\k\id"))
    );
    assert_eq!(r.host_key.as_deref(), Some(ED25519));
}

#[test]
fn remote_live_checks() {
    assert_eq!(check_field(Field::RemoteUser, r"PC\admin"), Ok(()));
    assert_eq!(
        check_remote_field(Field::RemoteUser, RemoteKind::Ssh, r"PC\admin"),
        Err(FieldIssue::InvalidUser)
    );
    assert_eq!(
        check_remote_field(Field::RemoteUser, RemoteKind::Ssh, "るーと"),
        Err(FieldIssue::ImeKana)
    );
    assert_eq!(check_field(Field::RemoteAddress, ""), Ok(()));
    assert_eq!(
        check_field(Field::RemoteAddress, "1.2.3"),
        Err(FieldIssue::InvalidAddress)
    );
    assert_eq!(
        check_field(Field::SshPort, "0"),
        Err(FieldIssue::InvalidPort)
    );
    assert_eq!(check_field(Field::SshHostKey, ED25519), Ok(()));
    assert_eq!(
        check_field(Field::RebootCommand, "echo $x"),
        Err(FieldIssue::InvalidCommand)
    );
    assert_eq!(check_field(Field::SshKeyFile, "日本語\\id"), Ok(()));
    assert_eq!(
        check_remote_field(Field::SshPort, RemoteKind::Windows, "22"),
        Ok(())
    );
}
