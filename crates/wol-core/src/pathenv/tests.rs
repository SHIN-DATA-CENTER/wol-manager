use super::*;

fn vars(name: &str) -> Option<String> {
    match name.to_ascii_uppercase().as_str() {
        "USERPROFILE" => Some(r"C:\Users\taro".to_owned()),
        "SYSTEMROOT" => Some(r"C:\Windows".to_owned()),
        _ => None,
    }
}

fn expand(value: &str, entry: &str) -> bool {
    !find_entries(value, entry, &vars).is_empty()
}

#[test]
fn expansion() {
    assert_eq!(
        expand_vars(r"%USERPROFILE%\bin;%NOPE%;50%;%%", &vars),
        r"C:\Users\taro\bin;%NOPE%;50%;%%"
    );
}

#[test]
fn normalization_rules() {
    let n = |s: &str| normalize_entry(s, &vars);
    assert_eq!(n(r#"  "C:\Tools\WoL\bin\"  "#), r"c:\tools\wol\bin");
    assert_eq!(n("C:/Tools/WoL/bin/"), r"c:\tools\wol\bin");
    assert_eq!(n(r"%USERPROFILE%\bin"), r"c:\users\taro\bin");
    assert_eq!(n(r"\\?\C:\x"), r"c:\x");
}

#[test]
fn whole_entry_comparison() {
    let value = r"C:\Windows\system32;C:\Windows\system32\wbem;%USERPROFILE%\bin";
    assert!(expand(value, r"C:\WINDOWS\System32\"));
    assert!(expand(value, r"C:\Users\taro\bin"));
    assert!(!expand(value, r"C:\Windows"));
    assert_eq!(
        remove_entries(value, r"C:\Windows\System32", &vars).as_deref(),
        Some(r"C:\Windows\system32\wbem;%USERPROFILE%\bin")
    );
}

#[test]
fn append_is_idempotent_and_keeps_everything_else() {
    let v = r"C:\a;;C:\b";
    let added = append_entry(v, r"D:\WoL Manager\bin", &vars)
        .unwrap()
        .unwrap();
    assert_eq!(added, r"C:\a;;C:\b;D:\WoL Manager\bin");
    assert_eq!(
        append_entry(&added, r"d:\wol manager\BIN\", &vars).unwrap(),
        None
    );
    // A trailing separator is kept after the new entry.
    assert_eq!(
        append_entry("C:\\a;", r"D:\x", &vars).unwrap().unwrap(),
        r"C:\a;D:\x;"
    );
    assert_eq!(append_entry("", r"D:\x", &vars).unwrap().unwrap(), r"D:\x");
}

#[test]
fn add_then_remove_restores_the_value_byte_for_byte() {
    // Found on the GitHub runner, whose user PATH ends with ';'.
    for original in [
        r"%USERPROFILE%\.dotnet\tools;%USERPROFILE%\.cargo\bin;%USERPROFILE%\AppData\Local\Microsoft\WindowsApps;",
        r"C:\a;C:\b",
        r"C:\a;;",
        r"C:\a;;C:\b",
        ";",
        "",
    ] {
        let dir = r"C:\Users\x\AppData\Local\Programs\WoL Manager\bin";
        let added = append_entry(original, dir, &vars).unwrap().unwrap();
        assert_eq!(find_entries(&added, dir, &vars).len(), 1, "{original:?}");
        let removed = remove_entries(&added, dir, &vars).unwrap();
        assert_eq!(
            removed, original,
            "round trip of {original:?} via {added:?}"
        );
    }
}

#[test]
fn length_limit() {
    let long = "C:\\".to_owned() + &"x".repeat(MAX_VALUE_LEN - 10);
    let e = append_entry(&long, r"D:\WoL Manager\bin", &vars).unwrap_err();
    assert!(matches!(e, Error::PathTooLong { .. }));
    assert_eq!(e.kind(), crate::ErrorKind::Io);
}

#[test]
fn prepare_dir_rules() {
    assert_eq!(
        prepare_dir(Path::new(r"C:\Program Files\WoL Manager\bin\")).unwrap(),
        r"C:\Program Files\WoL Manager\bin"
    );
    assert_eq!(
        prepare_dir(Path::new(r"\\?\C:\Tools\bin")).unwrap(),
        r"C:\Tools\bin"
    );
    assert_eq!(prepare_dir(Path::new(r"C:\")).unwrap(), r"C:\");
    for bad in [r"C:\a;b", "", r#"C:\"x"#] {
        let e = prepare_dir(Path::new(bad)).unwrap_err();
        assert!(matches!(e, Error::InvalidPathEntry { .. }), "{bad}: {e:?}");
    }
    let rel = prepare_dir(Path::new("bin")).unwrap();
    assert!(Path::new(&rel).is_absolute());
}

#[test]
fn mem_backend_add_remove_status() {
    let b = MemBackend::with(
        Some(PathValue {
            value: r"%USERPROFILE%\AppData\Local\Microsoft\WindowsApps".into(),
            kind: ValueKind::ExpandString,
        }),
        None,
    );
    b.set_var("USERPROFILE", r"C:\Users\taro");
    let dir = Path::new(r"D:\Tools\wol\bin");

    let st = status(&b, Scope::User, dir).unwrap();
    assert!(!st.present);
    assert_eq!(st.value_kind, Some(ValueKind::ExpandString));

    assert_eq!(add(&b, Scope::User, dir).unwrap(), PathChange::Added);
    assert_eq!(
        add(&b, Scope::User, dir).unwrap(),
        PathChange::AlreadyPresent
    );
    let v = b.get(Scope::User).unwrap();
    assert_eq!(
        v.value,
        r"%USERPROFILE%\AppData\Local\Microsoft\WindowsApps;D:\Tools\wol\bin"
    );
    assert_eq!(v.kind, ValueKind::ExpandString, "type preserved");
    assert_eq!(b.broadcast_count(), 1);

    let st = status(&b, Scope::User, Path::new(r"d:\tools\WOL\bin\")).unwrap();
    assert!(st.present);
    assert_eq!(st.matching_entries, vec![r"D:\Tools\wol\bin".to_string()]);

    assert_eq!(remove(&b, Scope::User, dir).unwrap(), PathChange::Removed);
    assert_eq!(
        remove(&b, Scope::User, dir).unwrap(),
        PathChange::NotPresent
    );
    assert_eq!(
        b.get(Scope::User).unwrap().value,
        r"%USERPROFILE%\AppData\Local\Microsoft\WindowsApps"
    );
    assert_eq!(b.broadcast_count(), 2);
}

#[test]
fn removes_entries_written_through_variables() {
    let b = MemBackend::with(
        Some(PathValue {
            value: r"C:\a;%USERPROFILE%\wol\bin;C:\b;%userprofile%\wol\bin\".into(),
            kind: ValueKind::String,
        }),
        None,
    );
    b.set_var("USERPROFILE", r"C:\Users\taro");
    assert_eq!(
        remove(&b, Scope::User, Path::new(r"C:\Users\taro\wol\bin")).unwrap(),
        PathChange::Removed
    );
    let v = b.get(Scope::User).unwrap();
    assert_eq!(v.value, r"C:\a;C:\b");
    assert_eq!(v.kind, ValueKind::String, "REG_SZ stays REG_SZ");
}

#[test]
fn missing_value_is_created_as_expand_string() {
    let b = MemBackend::new();
    assert_eq!(
        remove(&b, Scope::User, Path::new(r"C:\x")).unwrap(),
        PathChange::NotPresent
    );
    assert_eq!(b.broadcast_count(), 0);
    assert_eq!(
        add(&b, Scope::User, Path::new(r"C:\x")).unwrap(),
        PathChange::Added
    );
    assert_eq!(
        b.get(Scope::User),
        Some(PathValue {
            value: r"C:\x".into(),
            kind: ValueKind::ExpandString
        })
    );
    assert_eq!(b.get(Scope::Machine), None);
}

#[test]
fn machine_write_requires_elevation() {
    let b = MemBackend::new().deny_machine_writes();
    let e = add(&b, Scope::Machine, Path::new(r"C:\x")).unwrap_err();
    assert!(matches!(e, Error::ElevationRequired));
    assert_eq!(e.kind(), crate::ErrorKind::Permission);
    // Status still works.
    assert!(
        !status(&b, Scope::Machine, Path::new(r"C:\x"))
            .unwrap()
            .present
    );
}

#[cfg(debug_assertions)]
#[test]
fn file_backend_round_trip() {
    let t = tempfile::tempdir().unwrap();
    let f = FileBackend::new(t.path().join("path.json"));
    assert_eq!(f.read(Scope::User).unwrap(), None);
    assert_eq!(
        add(&f, Scope::User, Path::new(r"C:\x")).unwrap(),
        PathChange::Added
    );
    assert_eq!(
        f.read(Scope::User).unwrap().unwrap().kind,
        ValueKind::ExpandString
    );
    std::fs::write(
        t.path().join("path.json"),
        r#"{"machine": {"value": "C:\\m", "kind": "string"}, "machine_requires_elevation": true}"#,
    )
    .unwrap();
    assert!(matches!(
        add(&f, Scope::Machine, Path::new(r"C:\x")),
        Err(Error::ElevationRequired)
    ));
    assert!(
        status(&f, Scope::Machine, Path::new(r"C:\m"))
            .unwrap()
            .present
    );
}

#[test]
fn scope_parsing() {
    assert_eq!("User".parse::<Scope>(), Ok(Scope::User));
    assert_eq!("machine".parse::<Scope>(), Ok(Scope::Machine));
    assert!("both".parse::<Scope>().is_err());
    assert_eq!(Scope::Machine.to_string(), "machine");
}

#[test]
fn cli_dir_for_gui_and_cli() {
    assert_eq!(
        cli_dir_for(Path::new(r"D:\Tools\wol\wol-manager.exe")),
        PathBuf::from(r"D:\Tools\wol\bin")
    );
    assert_eq!(
        cli_dir_for(Path::new(r"D:\Tools\wol\bin\WOLM.EXE")),
        PathBuf::from(r"D:\Tools\wol\bin")
    );
}
