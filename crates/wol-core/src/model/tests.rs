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
