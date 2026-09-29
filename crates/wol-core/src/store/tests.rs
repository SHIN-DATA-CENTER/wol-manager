use super::*;
use crate::model::Host;
use std::sync::Arc;

fn temp_store() -> (tempfile::TempDir, Store) {
    let t = tempfile::tempdir().unwrap();
    let s = Store::new(ConfigLocation::custom(t.path().join("cfg")));
    (t, s)
}

fn add_host(name: &str, mac_last: u8) -> impl FnOnce(&mut Config) -> Result<HostId> {
    let name = name.to_owned();
    move |c: &mut Config| {
        c.insert_host(Host::new(
            name,
            crate::MacAddr([0x02, 0, 0, 0, mac_last, 1]),
        ))
    }
}

#[test]
fn missing_file_gives_defaults_and_creates_nothing() {
    let (_t, s) = temp_store();
    let l = s.load().unwrap();
    assert!(!l.exists);
    assert_eq!(l.config, Config::default());
    assert!(!l.read_only);
    assert!(!s.location().dir.exists());
}

#[test]
fn update_writes_and_reloads() {
    let (_t, s) = temp_store();
    let up = s.update(add_host("NAS", 1)).unwrap();
    assert!(up.written);
    let id = up.value;
    let l = s.load().unwrap();
    assert!(l.exists);
    assert_eq!(l.config.get(id).unwrap().name, "NAS");
    let text = fs::read_to_string(s.config_path()).unwrap();
    assert!(text.starts_with(crate::model::FILE_HEADER));
    assert!(!s.location().temp_file().exists());
    // Second update creates the backup.
    s.update(add_host("PC", 2)).unwrap();
    assert!(s.location().backup_file().exists());
}

#[test]
fn unchanged_update_does_not_write() {
    let (_t, s) = temp_store();
    s.update(add_host("NAS", 1)).unwrap();
    let before = fs::metadata(s.config_path()).unwrap().modified().unwrap();
    let text_before = fs::read(s.config_path()).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    let up = s.update(|_c| Ok(())).unwrap();
    assert!(!up.written);
    assert_eq!(fs::read(s.config_path()).unwrap(), text_before);
    assert_eq!(
        fs::metadata(s.config_path()).unwrap().modified().unwrap(),
        before
    );
}

#[test]
fn concurrent_updates_are_not_lost() {
    let (_t, s) = temp_store();
    let dir = s.location().dir.clone();
    let threads = 8;
    let per_thread = 10;
    let barrier = Arc::new(std::sync::Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let dir = dir.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                // Each thread has its own Store, like separate processes.
                let store = Store::new(ConfigLocation::custom(dir));
                barrier.wait();
                for i in 0..per_thread {
                    store
                        .update(add_host(
                            &format!("host-{t}-{i}"),
                            (t * per_thread + i) as u8,
                        ))
                        .unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let l = s.load().unwrap();
    assert_eq!(l.config.hosts.len(), threads * per_thread);
    let mut names: Vec<String> = l.config.hosts.iter().map(|h| h.name.clone()).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), threads * per_thread);
}

#[test]
fn parse_error_never_overwrites() {
    let (_t, s) = temp_store();
    fs::create_dir_all(&s.location().dir).unwrap();
    let broken = "schema_version = 1\n[[hosts]\nname = 'x'\n";
    fs::write(s.config_path(), broken).unwrap();
    let e = s.update(add_host("NAS", 1)).unwrap_err();
    match &e {
        Error::ConfigParse { path, line, .. } => {
            assert_eq!(path.as_deref(), Some(s.config_path().as_path()));
            assert_eq!(*line, Some(2));
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(e.kind(), crate::ErrorKind::Config);
    assert_eq!(fs::read_to_string(s.config_path()).unwrap(), broken);
    assert!(!s.location().backup_file().exists());
    assert!(matches!(s.load(), Err(Error::ConfigParse { .. })));
}

#[test]
fn invalid_utf8_is_a_parse_error() {
    let (_t, s) = temp_store();
    fs::create_dir_all(&s.location().dir).unwrap();
    fs::write(s.config_path(), b"schema_version = 1\nx = \"\x82\xa0\"\n").unwrap();
    match s.load() {
        Err(Error::ConfigParse { line, .. }) => assert_eq!(line, Some(2)),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn newer_schema_is_read_only() {
    let (_t, s) = temp_store();
    fs::create_dir_all(&s.location().dir).unwrap();
    let text = "schema_version = 99\nnew_thing = true\n";
    fs::write(s.config_path(), text).unwrap();
    let l = s.load().unwrap();
    assert!(l.read_only);
    assert_eq!(
        l.read_only_reason,
        Some(ReadOnlyReason::NewerSchema {
            found: 99,
            supported: SCHEMA_VERSION
        })
    );
    let e = s.update(add_host("NAS", 1)).unwrap_err();
    assert!(matches!(e, Error::NewerSchema { found: 99, .. }));
    assert_eq!(fs::read_to_string(s.config_path()).unwrap(), text);
}

/// A newer file using enum values this build does not know still opens read-only (it used
/// to be a ConfigParse error, so the GUI could not even show it).
#[test]
fn newer_schema_with_unknown_values_is_read_only_not_an_error() {
    let (_t, s) = temp_store();
    fs::create_dir_all(&s.location().dir).unwrap();
    let text = "schema_version = 2\n[settings.probe]\nmethod = \"arp\"\n[settings.gui]\nrenderer = \"skia\"\n\n[[hosts]]\nname = \"NAS\"\nmac = \"02:00:00:00:00:01\"\nprobe = \"arp\"\n";
    fs::write(s.config_path(), text).unwrap();
    let l = s.load().unwrap();
    assert!(l.read_only);
    assert_eq!(
        l.read_only_reason,
        Some(ReadOnlyReason::NewerSchema {
            found: 2,
            supported: SCHEMA_VERSION
        })
    );
    assert_eq!(l.config.hosts.len(), 1);
    assert!(s.poll_changed().unwrap().is_none());
    let e = s.update(add_host("PC", 2)).unwrap_err();
    assert!(matches!(e, Error::NewerSchema { found: 2, .. }), "{e:?}");
    assert_eq!(fs::read_to_string(s.config_path()).unwrap(), text);
}

#[test]
fn bom_is_tolerated() {
    let (_t, s) = temp_store();
    fs::create_dir_all(&s.location().dir).unwrap();
    fs::write(
        s.config_path(),
        "\u{FEFF}[[hosts]]\nname = \"NAS\"\nmac = \"00:11:22:33:44:55\"\n",
    )
    .unwrap();
    let l = s.load().unwrap();
    assert_eq!(l.config.hosts.len(), 1);
    let up = s.update(add_host("PC", 2)).unwrap();
    assert!(up.written);
    assert!(
        !fs::read(s.config_path())
            .unwrap()
            .starts_with(b"\xEF\xBB\xBF")
    );
}

#[test]
fn deterministic_ids_stable_across_load_and_update() {
    let (_t, s) = temp_store();
    fs::create_dir_all(&s.location().dir).unwrap();
    fs::write(
        s.config_path(),
        "[[hosts]]\nname = \"NAS\"\nmac = \"00:11:22:33:44:55\"\nfuture = 1\n",
    )
    .unwrap();
    let a = s.load().unwrap();
    let b = s.load().unwrap();
    let id = a.config.hosts[0].id;
    assert_eq!(id, b.config.hosts[0].id);
    assert!(
        a.warnings
            .contains(&LoadWarning::Parse(ParseNote::AssignedIds { count: 1 }))
    );
    // A no-op update does not persist the id...
    assert!(!s.update(|_| Ok(())).unwrap().written);
    assert!(
        !fs::read_to_string(s.config_path())
            .unwrap()
            .contains("id =")
    );
    // ...the next real save does, with the same id; unknown keys are kept.
    let up = s.update(add_host("PC", 2)).unwrap();
    assert!(up.written);
    let text = fs::read_to_string(s.config_path()).unwrap();
    assert!(text.contains(&id.to_string()), "{text}");
    assert!(text.contains("future = 1"), "{text}");
    let c = s.load().unwrap();
    assert_eq!(c.config.hosts[0].id, id);
    assert!(
        c.warnings
            .iter()
            .all(|w| !matches!(w, LoadWarning::Parse(_)))
    );
}

/// Review m12: ids assigned while reading a hand-edited file are written by
/// `persist_assigned_ids` (and only then), with the usual lock / `.bak` / atomic rules.
#[test]
fn persist_assigned_ids_writes_only_when_ids_were_assigned() {
    let (_t, s) = temp_store();
    // No file: nothing to do, nothing created.
    let up = s.persist_assigned_ids().unwrap();
    assert_eq!(up.value, HostIdsState::Saved);
    assert!(!up.written);
    assert!(!s.location().dir.exists());

    fs::create_dir_all(&s.location().dir).unwrap();
    let dup = "5f0c6a1e-3b7d-4f5e-9a51-2d6c1f0e8b44";
    let original = format!(
        "# my notes\n[[hosts]]\nname = \"NAS\"\nmac = \"00:11:22:33:44:55\"\nfuture = 1\n\n[[hosts]]\nid = \"{dup}\"\nname = \"PC\"\nmac = \"00:11:22:33:44:66\"\n\n[[hosts]]\nid = \"{dup}\"\nname = \"PC2\"\nmac = \"00:11:22:33:44:77\"\n"
    );
    fs::write(s.config_path(), &original).unwrap();
    let loaded = s.load().unwrap();
    assert!(s.poll_changed().unwrap().is_none());
    let ids: Vec<HostId> = loaded.config.hosts.iter().map(|h| h.id).collect();
    assert_ne!(ids[2].to_string(), dup);

    let up = s.persist_assigned_ids().unwrap();
    assert_eq!(up.value, HostIdsState::Saved);
    assert!(up.written);
    assert!(up.value.is_saved(ids[0]));
    // The ids that were only in memory are now the file's; nothing else changed.
    assert_eq!(up.config, loaded.config);
    let text = fs::read_to_string(s.config_path()).unwrap();
    for id in &ids {
        assert!(text.contains(&id.to_string()), "{text}");
    }
    assert!(text.contains("future = 1"), "{text}");
    let again = s.load().unwrap();
    assert_eq!(again.config, loaded.config);
    assert!(
        again
            .warnings
            .iter()
            .all(|w| !matches!(w, LoadWarning::Parse(_))),
        "{:?}",
        again.warnings
    );
    // The previous file is the backup; our own write is not reported as external.
    assert_eq!(
        fs::read_to_string(s.location().backup_file()).unwrap(),
        original
    );
    assert!(!s.location().temp_file().exists());
    assert!(s.poll_changed().unwrap().is_none());

    // Every id in the file: a no-op that does not touch the file.
    let bytes = fs::read(s.config_path()).unwrap();
    let up = s.persist_assigned_ids().unwrap();
    assert_eq!(up.value, HostIdsState::Saved);
    assert!(!up.written);
    assert_eq!(up.config, loaded.config);
    assert_eq!(fs::read(s.config_path()).unwrap(), bytes);

    // A parse error is reported, never "fixed".
    fs::write(s.config_path(), "[[hosts]\nbroken").unwrap();
    assert!(matches!(
        s.persist_assigned_ids().unwrap_err(),
        Error::ConfigParse { .. }
    ));
    assert_eq!(
        fs::read_to_string(s.config_path()).unwrap(),
        "[[hosts]\nbroken"
    );
}

/// A newer-schema file (read-only) is left alone; the in-memory ids are reported.
#[test]
fn persist_assigned_ids_leaves_read_only_files_alone() {
    let (_t, s) = temp_store();
    fs::create_dir_all(&s.location().dir).unwrap();
    let text = "schema_version = 2\n[[hosts]]\nid = \"5f0c6a1e-3b7d-4f5e-9a51-2d6c1f0e8b44\"\nname = \"NAS\"\nmac = \"00:11:22:33:44:55\"\n\n[[hosts]]\nname = \"PC\"\nmac = \"00:11:22:33:44:66\"\n";
    fs::write(s.config_path(), text).unwrap();
    let loaded = s.load().unwrap();
    let (nas, pc) = (loaded.config.hosts[0].id, loaded.config.hosts[1].id);
    let up = s.persist_assigned_ids().unwrap();
    assert!(!up.written);
    assert_eq!(
        up.value,
        HostIdsState::Unsaved {
            reason: ReadOnlyReason::NewerSchema {
                found: 2,
                supported: SCHEMA_VERSION
            },
            ids: vec![pc],
        }
    );
    assert!(up.value.is_saved(nas));
    assert!(!up.value.is_saved(pc));
    assert_eq!(up.config, loaded.config);
    assert_eq!(fs::read_to_string(s.config_path()).unwrap(), text);
    assert!(!s.location().lock_file().exists());
}

#[test]
fn closure_error_aborts_without_writing() {
    let (_t, s) = temp_store();
    s.update(add_host("NAS", 1)).unwrap();
    let bytes = fs::read(s.config_path()).unwrap();
    let missing = uuid::Uuid::new_v4();
    let e = s
        .update(|c| {
            c.settings.wake.repeat = 9;
            c.remove_host(missing)
        })
        .unwrap_err();
    assert!(matches!(e, Error::HostIdNotFound(_)));
    assert_eq!(fs::read(s.config_path()).unwrap(), bytes);
}

#[test]
fn only_new_validation_issues_abort() {
    let (_t, s) = temp_store();
    fs::create_dir_all(&s.location().dir).unwrap();
    // Pre-existing problem: duplicate names written by hand.
    fs::write(
        s.config_path(),
        "[[hosts]]\nname = \"A\"\nmac = \"02:00:00:00:00:01\"\n[[hosts]]\nname = \"a\"\nmac = \"02:00:00:00:00:02\"\n",
    )
    .unwrap();
    // Unrelated change still works.
    assert!(
        s.update(|c| {
            c.settings.wake.repeat = 4;
            Ok(())
        })
        .unwrap()
        .written
    );
    // Introducing a new problem is refused.
    let e = s
        .update(|c| {
            c.settings.wake.repeat = 0;
            Ok(())
        })
        .unwrap_err();
    assert!(matches!(e, Error::Validation(_)));
    assert_eq!(e.kind(), crate::ErrorKind::InvalidInput);
}

#[test]
fn poll_changed_detects_content_changes() {
    let (_t, s) = temp_store();
    assert!(s.poll_changed().unwrap().is_some(), "first poll reports");
    assert!(s.poll_changed().unwrap().is_none());
    s.update(add_host("NAS", 1)).unwrap();
    assert!(
        s.poll_changed().unwrap().is_none(),
        "own writes are not reported"
    );
    // Another process changes the file (same length edit: port 9 -> 7).
    let other = Store::new(s.location().clone());
    other
        .update(|c| {
            c.settings.wake.port = 7;
            Ok(())
        })
        .unwrap();
    let l = s.poll_changed().unwrap().expect("change detected");
    assert_eq!(l.config.settings.wake.port, 7);
    assert!(s.poll_changed().unwrap().is_none());
    // Broken file: reported once.
    fs::write(s.config_path(), "[[[").unwrap();
    assert!(s.poll_changed().is_err());
    assert!(s.poll_changed().unwrap().is_none());
}

/// An update that writes nothing must not mark another process's change as seen.
#[test]
fn noop_update_does_not_swallow_external_changes() {
    let (_t, gui) = temp_store();
    gui.update(add_host("NAS", 1)).unwrap();
    assert!(gui.poll_changed().unwrap().is_none());
    // The CLI adds a host.
    let cli = Store::new(gui.location().clone());
    cli.update(add_host("PC", 2)).unwrap();
    // The GUI runs an update that changes nothing (show_tray is already true).
    let up = gui
        .update(|c| {
            c.settings.gui.show_tray = true;
            Ok(())
        })
        .unwrap();
    assert!(!up.written);
    assert_eq!(up.config.hosts.len(), 2);
    let l = gui
        .poll_changed()
        .unwrap()
        .expect("external change still reported");
    assert_eq!(l.config.hosts.len(), 2);
    assert!(gui.poll_changed().unwrap().is_none());
}

/// Plan §11.10 through the store: the GUI's notes-only save does not revert the port the
/// CLI changed while the editor was open.
#[test]
fn gui_edit_keeps_concurrent_cli_edit() {
    use crate::model::EditBase;
    let (_t, gui) = temp_store();
    let id = gui.update(add_host("PC", 1)).unwrap().value;
    // GUI opens the editor.
    let loaded = gui.load().unwrap();
    let base = EditBase::of(loaded.config.get(id).unwrap());
    let mut draft = base.draft.clone();
    // CLI: `wolm edit PC --port 7` (draft taken from its own load).
    let cli = Store::new(gui.location().clone());
    let cli_base = EditBase::of(cli.load().unwrap().config.find("PC").unwrap());
    let mut cli_draft = cli_base.draft.clone();
    cli_draft.port = "7".into();
    cli.update(|c| c.save_draft(&cli_draft, Some(&cli_base)))
        .unwrap();
    // GUI saves a notes change.
    draft.notes = "moved to rack 2".into();
    let up = gui.update(|c| c.save_draft(&draft, Some(&base))).unwrap();
    assert!(up.written);
    let h = gui.load().unwrap().config.get(id).unwrap().clone();
    assert_eq!(h.port, Some(7));
    assert_eq!(h.notes.as_deref(), Some("moved to rack 2"));
}

#[test]
fn lock_timeout_when_held() {
    let (_t, s) = temp_store();
    fs::create_dir_all(&s.location().dir).unwrap();
    let held = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(s.location().lock_file())
        .unwrap();
    held.lock().unwrap();
    let start = Instant::now();
    let e = s.update(add_host("NAS", 1)).unwrap_err();
    assert!(matches!(e, Error::LockTimeout { .. }), "{e:?}");
    assert!(start.elapsed() >= Duration::from_secs(4));
    held.unlock().unwrap();
    s.update(add_host("NAS", 1)).unwrap();
}

#[test]
fn write_file_atomic_replaces() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("gui-state.toml");
    write_file_atomic(&p, b"a = 1\n").unwrap();
    write_file_atomic(&p, b"a = 2\n").unwrap();
    assert_eq!(fs::read_to_string(&p).unwrap(), "a = 2\n");
    assert!(!t.path().join("gui-state.toml.tmp").exists());
}

#[test]
fn write_output_file_keeps_other_files_and_names_the_target() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("out.csv");
    fs::write(t.path().join("out.csv.tmp"), b"precious").unwrap();
    write_output_file(&p, b"a,b\n").unwrap();
    write_output_file(&p, b"c,d\n").unwrap();
    assert_eq!(fs::read_to_string(&p).unwrap(), "c,d\n");
    assert_eq!(
        fs::read_to_string(t.path().join("out.csv.tmp")).unwrap(),
        "precious"
    );
    let names: Vec<String> = fs::read_dir(t.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
    // A folder that does not exist: the error is about the export file, not the settings.
    let missing = t.path().join("nope").join("out.csv");
    match write_output_file(&missing, b"x").unwrap_err() {
        Error::Io { path, .. } => assert_eq!(path.as_deref(), Some(missing.as_path())),
        e => panic!("{e:?}"),
    }
}

/// An update whose result the TOML parser could not read back is refused, so the file stays
/// usable (a JSON import can nest deeper than TOML allows).
#[test]
fn update_never_writes_an_unreadable_file() {
    let (_t, s) = temp_store();
    s.update(add_host("NAS", 1)).unwrap();
    let before = fs::read_to_string(s.config_path()).unwrap();
    let mut deep = toml::Value::Integer(1);
    for _ in 0..150 {
        deep = toml::Value::Array(vec![deep]);
    }
    let e = s
        .update(|c| {
            c.hosts[0].extra.insert("deep".into(), deep);
            Ok(())
        })
        .unwrap_err();
    assert!(matches!(e, Error::Serialize(_)), "{e:?}");
    assert_eq!(fs::read_to_string(s.config_path()).unwrap(), before);
    s.load().unwrap();
    s.update(add_host("PC", 2)).unwrap();
}

#[test]
fn marker_ignored_warning() {
    let t = tempfile::tempdir().unwrap();
    let mut loc = ConfigLocation::custom(t.path().join("cfg"));
    loc.marker_ignored = true;
    loc.marker_path = Some(t.path().join("wol-manager.portable"));
    let l = Store::new(loc).load().unwrap();
    assert!(
        l.warnings
            .iter()
            .any(|w| matches!(w, LoadWarning::MarkerIgnored { .. }))
    );
}
