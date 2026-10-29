use std::process::Command;

use asc_apk::{
    dump_apk, find_refs, get_class_source, list_classes, manifest_xml, Engine, Options,
};
use asc_dex::{find_in_dex, smali_class, MemberSel, RefQuery};

#[path = "support.rs"]
mod support;

fn opts(threads: usize) -> Options {
    Options {
        threads,
        debug: false,
        engine: Engine::Ddc,
        resources: None,
        cache_dir: None,
    }
}

fn smali_opts(threads: usize) -> Options {
    Options {
        threads,
        debug: false,
        engine: Engine::Smali,
        resources: None,
        cache_dir: None,
    }
}

fn write_apk(
    dir: &std::path::Path,
    name: &str,
    files: &[(&str, &[u8])],
    deflate: bool,
) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, support::zip_archive(files, deflate)).unwrap();
    path
}

#[test]
fn string_refs_cover_both_methods_sharing_code() {
    let lines = find_in_dex(
        "fixture.dex",
        &support::make_dex(),
        &RefQuery::String("token".into()),
    )
    .unwrap();
    assert_eq!(
        lines,
        vec![
            "fixture.dex | Lexample/Test;->first | matched=(token)".to_string(),
            "fixture.dex | Lexample/Test;->second | matched=(token)".to_string(),
        ]
    );
}

#[test]
fn method_and_field_refs_name_the_caller() {
    let methods = find_in_dex(
        "fixture.dex",
        &support::make_invoke_dex(),
        &RefQuery::Method(MemberSel {
            class_name: None,
            fuzzy_class: false,
            name: Some("callToMethod".into()),
        }),
    )
    .unwrap();
    assert_eq!(
        methods,
        vec![
            "fixture.dex | Lexample/Test;->run | matched=(Lexample/Target;->callToMethod)"
                .to_string()
        ]
    );
    let fields = find_in_dex(
        "fixture.dex",
        &support::make_field_dex(),
        &RefQuery::Field(MemberSel {
            class_name: Some("Lexample/Test;".into()),
            fuzzy_class: false,
            name: Some("a".into()),
        }),
    )
    .unwrap();
    assert_eq!(
        fields,
        vec!["fixture.dex | Lexample/Test;->getA | matched=(Lexample/Test;->a)".to_string()]
    );
}

#[test]
fn missing_class_data_map_still_finds_refs() {
    let mut data = support::make_dex();
    let map_off = u32::from_le_bytes(data[0x34..0x38].try_into().unwrap()) as usize;
    let count = u32::from_le_bytes(data[map_off..map_off + 4].try_into().unwrap());
    for off in (map_off + 4..map_off + 4 + count as usize * 12).step_by(12) {
        let kind = u16::from_le_bytes(data[off..off + 2].try_into().unwrap());
        if kind == 0x2000 {
            data[off..off + 2].copy_from_slice(&0xffffu16.to_le_bytes());
        }
    }
    let lines = find_in_dex("fixture.dex", &data, &RefQuery::String("token".into())).unwrap();
    assert_eq!(lines.len(), 2);
}

#[test]
fn class_without_method_bodies_has_no_references() {
    let mut data = support::make_dex();
    let class_off = u32::from_le_bytes(data[0x64..0x68].try_into().unwrap()) as usize;
    let class_data =
        u32::from_le_bytes(data[class_off + 24..class_off + 28].try_into().unwrap()) as usize;
    data[class_data..class_data + 10].copy_from_slice(&[0, 0, 2, 0, 0, 9, 0, 1, 9, 0]);
    let lines = find_in_dex("fixture.dex", &data, &RefQuery::String("token".into())).unwrap();
    assert!(lines.is_empty(), "{lines:?}");
}

#[test]
fn decompile_prints_class_and_methods() {
    let source = smali_class(&support::make_dex(), "Lexample/Test;").unwrap();
    assert!(source.contains(".class public Lexample/Test;"), "{source}");
    assert!(source.contains(".method public static first()V"), "{source}");
    assert!(source.contains(".method public static second()V"), "{source}");
    assert!(source.contains("const-string v0, \"token\""), "{source}");
    assert!(source.contains("return-void"), "{source}");
    assert!(source.contains(".end method"), "{source}");
}

#[test]
fn listclass_filters_prefix_for_stored_and_deflated_dex() {
    let data = support::make_class_only_dex(
        &[
            "Lcom/xxx/First;",
            "Lcom/xxx/internal/Second;",
            "Lorg/example/Other;",
        ],
        0,
        b"035",
    );
    let expected = vec![
        "Lcom/xxx/First;".to_string(),
        "Lcom/xxx/internal/Second;".to_string(),
    ];
    let dir = std::env::temp_dir().join(format!("asc-list-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for deflate in [false, true] {
        for prefix in ["com.xxx", "com/xxx", "Lcom/xxx"] {
            let apk = write_apk(
                &dir,
                "classes.apk",
                &[("classes.dex", data.as_slice())],
                deflate,
            );
            let names = list_classes(&apk, Some(prefix), &opts(2)).unwrap();
            assert_eq!(names, expected, "deflate={deflate} prefix={prefix}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn listclass_keeps_dex_order_and_041_container_order() {
    let dir = std::env::temp_dir().join(format!("asc-order-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let first = support::make_dex();
    let second = support::make_field_dex();
    let third = support::make_dex();
    let apk = write_apk(
        &dir,
        "multi.apk",
        &[
            ("classes.dex", first.as_slice()),
            ("classes2.dex", second.as_slice()),
            ("classes3.dex", third.as_slice()),
        ],
        true,
    );
    let names = list_classes(&apk, None, &opts(4)).unwrap();
    assert_eq!(
        names,
        vec![
            "Lexample/Test;".to_string(),
            "Lexample/Test;".to_string(),
            "Lexample/Test;".to_string(),
        ]
    );
    let container = support::make_dex041_container();
    let apk = write_apk(
        &dir,
        "c041.apk",
        &[("classes.dex", container.as_slice())],
        false,
    );
    let names = list_classes(&apk, None, &opts(1)).unwrap();
    assert_eq!(
        names,
        vec![
            "Lalpha/First;".to_string(),
            "Lshared/Duplicate;".to_string(),
            "Lbeta/Second;".to_string(),
            "Lshared/Duplicate;".to_string(),
        ]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_getclass_and_findrefs_on_compressed_multidex() {
    let dir = std::env::temp_dir().join(format!("asc-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dex = support::make_dex();
    let apk = write_apk(
        &dir,
        "app.apk",
        &[
            ("classes.dex", dex.as_slice()),
            ("classes2.dex", dex.as_slice()),
        ],
        true,
    );
    let exe = env!("CARGO_BIN_EXE_asc");
    let search = Command::new(exe)
        .args([
            "findrefs",
            apk.to_str().unwrap(),
            "--threads",
            "2",
            "string",
            "token",
        ])
        .output()
        .unwrap();
    assert!(
        search.status.success(),
        "{}",
        String::from_utf8_lossy(&search.stderr)
    );
    let stdout = String::from_utf8(search.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 4, "{stdout}");
    let source = Command::new(exe)
        .args([
            "getclass",
            apk.to_str().unwrap(),
            "example.Test",
            "--threads",
            "2",
        ])
        .output()
        .unwrap();
    assert!(
        source.status.success(),
        "{}",
        String::from_utf8_lossy(&source.stderr)
    );
    let text = String::from_utf8(source.stdout).unwrap();
    assert!(text.contains("class Test"), "{text}");
    let missing = Command::new(exe)
        .args(["getclass", apk.to_str().unwrap(), "com.missing.NoSuch"])
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("not found"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn manifest_roundtrip_through_apk() {
    let xml_bytes = sample_manifest();
    let dir = std::env::temp_dir().join(format!("asc-xml-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let apk = write_apk(
        &dir,
        "app.apk",
        &[
            ("AndroidManifest.xml", xml_bytes.as_slice()),
            ("classes.dex", &support::make_dex()),
        ],
        true,
    );
    let xml = manifest_xml(&apk).unwrap();
    assert!(xml.contains("package=\"com.example\""), "{xml}");
    assert!(xml.contains("android:label=\"Demo\""), "{xml}");
    let exe = env!("CARGO_BIN_EXE_asc");
    let out = dir.join("AndroidManifest.xml");
    let cmd = Command::new(exe)
        .args([
            "getmanifest",
            apk.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        cmd.status.success(),
        "{}",
        String::from_utf8_lossy(&cmd.stderr)
    );
    let saved = std::fs::read_to_string(&out).unwrap();
    assert!(saved.contains("<manifest"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn refs_after_switch_and_fill_array_payloads_are_kept() {
    for kind in [1u8, 2, 3] {
        let lines = find_in_dex(
            "fixture.dex",
            &support::make_payload_dex(kind),
            &RefQuery::String("token".into()),
        )
        .unwrap();
        assert_eq!(
            lines,
            vec!["fixture.dex | Lexample/Test;->after | matched=(token)".to_string()],
            "kind={kind}"
        );
    }
}

/// Labels a `.packed-switch`/`.sparse-switch` block names but never defines.
fn undefined_switch_labels(smali: &str) -> Vec<String> {
    let defined: std::collections::HashSet<&str> = smali
        .lines()
        .filter_map(|line| line.strip_prefix(':'))
        .filter_map(|rest| rest.split_whitespace().next())
        .collect();
    let mut missing = Vec::new();
    let mut inside = false;
    for line in smali.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(".packed-switch") || trimmed.starts_with(".sparse-switch") {
            inside = true;
            continue;
        }
        if trimmed.starts_with(".end packed-switch") || trimmed.starts_with(".end sparse-switch") {
            inside = false;
            continue;
        }
        if !inside {
            continue;
        }
        for token in trimmed.split_whitespace() {
            if let Some(name) = token.strip_prefix(':') {
                if !defined.contains(name) {
                    missing.push(name.to_string());
                }
            }
        }
    }
    missing
}

#[test]
fn switch_case_targets_follow_the_switch_instruction_not_the_payload() {
    for packed in [true, false] {
        let dex = support::make_switch_dex(packed);
        let smali = smali_class(&dex, "Lexample/Test;").unwrap();
        // The single case jumps back to `return-void` at pc 4. Resolving it
        // against the payload at pc 6 would print `:l_9` instead.
        assert!(smali.contains(":l_4"), "packed={packed}: {smali}");
        assert!(
            undefined_switch_labels(&smali).is_empty(),
            "packed={packed}: {:?}\n{smali}",
            undefined_switch_labels(&smali)
        );
    }
}

#[test]
fn fill_array_data_rejects_an_impossible_element_width() {
    for width in [0u16, 3, 9, 4096] {
        let dex = support::make_array_data_dex(width, 1);
        let err = smali_class(&dex, "Lexample/Test;").unwrap_err();
        assert!(
            err.to_string().contains("element width"),
            "width={width}: {err}"
        );
    }
}

#[test]
fn overlapping_buckets_keep_the_method_that_owns_the_instruction() {
    let lines = find_in_dex(
        "fixture.dex",
        &support::make_bucket_overlap_dex(),
        &RefQuery::String("token".into()),
    )
    .unwrap();
    assert!(
        lines
            .iter()
            .any(|line| line.contains("Lexample/Test;->kept")),
        "{lines:?}"
    );
}

#[test]
fn string_refs_follow_string_ids_when_data_is_not_in_index_order() {
    let lines = find_in_dex(
        "fixture.dex",
        &support::make_reordered_string_dex(),
        &RefQuery::String("token".into()),
    )
    .unwrap();
    assert_eq!(
        lines,
        vec!["fixture.dex | Lexample/Test;->m | matched=(mytoken)".to_string()]
    );
}

#[test]
fn member_names_do_not_match_substrings() {
    let dex = support::make_field_named_dex(b"apiKey");
    let precise = find_in_dex(
        "fixture.dex",
        &dex,
        &RefQuery::Field(MemberSel {
            class_name: Some("Lexample/Test;".into()),
            fuzzy_class: false,
            name: Some("a".into()),
        }),
    )
    .unwrap();
    assert!(precise.is_empty(), "{precise:?}");
    let exact = find_in_dex(
        "fixture.dex",
        &dex,
        &RefQuery::Field(MemberSel {
            class_name: Some("example.Test".into()),
            fuzzy_class: false,
            name: Some("apiKey".into()),
        }),
    )
    .unwrap();
    assert_eq!(exact.len(), 1, "{exact:?}");
    let unanchored = find_in_dex(
        "fixture.dex",
        &dex,
        &RefQuery::Field(MemberSel {
            class_name: None,
            fuzzy_class: false,
            name: Some("a".into()),
        }),
    )
    .unwrap();
    assert!(unanchored.is_empty(), "{unanchored:?}");
    let regex = find_in_dex(
        "fixture.dex",
        &dex,
        &RefQuery::Field(MemberSel {
            class_name: Some("Test".into()),
            fuzzy_class: true,
            name: Some("api.*".into()),
        }),
    )
    .unwrap();
    assert_eq!(regex.len(), 1, "{regex:?}");
}

#[test]
fn new_array_keeps_remaining_dimensions() {
    let source = smali_class(&support::make_array_dex(), "Lexample/Test;").unwrap();
    assert!(source.contains("new-array v0, p0, [[I"), "{source}");
}

#[test]
fn root_dex_names_are_all_visible() {
    let primary = support::make_class_only_dex(&["Lcom/app/Main;"], 0, b"035");
    let extra = support::make_class_only_dex(&["Lcom/app/Payload;"], 0, b"035");
    let hidden = support::make_class_only_dex(&["Lcom/app/Hidden;"], 0, b"035");
    let dir = std::env::temp_dir().join(format!("asc-names-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let apk = write_apk(
        &dir,
        "mixed.apk",
        &[
            ("classes.dex", primary.as_slice()),
            ("payload.dex", extra.as_slice()),
            ("assets/classes.dex", hidden.as_slice()),
        ],
        false,
    );
    let names = list_classes(&apk, None, &opts(2)).unwrap();
    assert_eq!(
        names,
        vec![
            "Lcom/app/Main;".to_string(),
            "Lcom/app/Payload;".to_string()
        ]
    );
    let only = write_apk(
        &dir,
        "secondary.apk",
        &[("secondary.dex", extra.as_slice())],
        true,
    );
    assert_eq!(
        list_classes(&only, None, &opts(1)).unwrap(),
        vec!["Lcom/app/Payload;".to_string()]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn duplicate_class_follows_multidex_load_order() {
    let early = support::make_marked_dex(b"from-classes2-longer");
    let later = support::make_marked_dex(b"short");
    let manifest = sample_manifest();
    let dir = std::env::temp_dir().join(format!("asc-dup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let apk = write_apk(
        &dir,
        "dup.apk",
        &[
            ("AndroidManifest.xml", manifest.as_slice()),
            ("classes10.dex", later.as_slice()),
            ("classes2.dex", early.as_slice()),
        ],
        false,
    );
    let source = get_class_source(&apk, "example.Test", &smali_opts(4)).unwrap();
    assert!(source.contains("from-classes2-longer"), "{source}");
    assert!(!source.contains("\"short\""), "{source}");
    let out = dir.join("tree");
    let stats = dump_apk(&apk, &out, &smali_opts(4)).unwrap();
    assert_eq!(stats.classes, 1);
    assert_eq!(stats.errors, 0);
    let dumped = std::fs::read_to_string(out.join("example/Test.smali")).unwrap();
    assert!(dumped.contains("from-classes2-longer"), "{dumped}");
    assert!(!dumped.contains("\"short\""), "{dumped}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn zip64_data_descriptor_and_crc_are_honored() {
    let dex = support::make_class_only_dex(&["Lcom/app/Main;"], 0, b"035");
    let dir = std::env::temp_dir().join(format!("asc-zip-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let zip64 = dir.join("zip64.apk");
    std::fs::write(&zip64, support::zip64_stored("classes.dex", &dex)).unwrap();
    assert_eq!(
        list_classes(&zip64, None, &opts(1)).unwrap(),
        vec!["Lcom/app/Main;".to_string()]
    );
    let described = dir.join("desc.apk");
    std::fs::write(
        &described,
        support::zip_stored_flags("classes.dex", &dex, crc32fast::hash(&dex), 0x0008),
    )
    .unwrap();
    assert_eq!(
        list_classes(&described, None, &opts(1)).unwrap(),
        vec!["Lcom/app/Main;".to_string()]
    );
    let zero = dir.join("zero.apk");
    std::fs::write(&zero, support::zip_stored_flags("classes.dex", &dex, 0, 0)).unwrap();
    assert_eq!(list_classes(&zero, None, &opts(1)).unwrap().len(), 1);
    let bad = dir.join("bad.apk");
    std::fs::write(
        &bad,
        support::zip_stored_flags("classes.dex", &dex, 0x00de_adbe, 0),
    )
    .unwrap();
    assert_eq!(
        list_classes(&bad, None, &opts(1)).unwrap(),
        vec!["Lcom/app/Main;".to_string()]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn aab_reads_module_dex_and_base_manifest() {
    let base = support::make_class_only_dex(&["Lcom/app/Base;"], 0, b"035");
    let feature = support::make_class_only_dex(&["Lcom/app/Feature;"], 0, b"035");
    let hidden = support::make_class_only_dex(&["Lcom/app/Hidden;"], 0, b"035");
    let manifest = sample_manifest();
    let dir = std::env::temp_dir().join(format!("asc-aab-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let aab = write_apk(
        &dir,
        "app.aab",
        &[
            ("base/manifest/AndroidManifest.xml", manifest.as_slice()),
            ("base/dex/classes.dex", base.as_slice()),
            ("feature/dex/classes.dex", feature.as_slice()),
            ("base/assets/classes.dex", hidden.as_slice()),
        ],
        false,
    );
    assert_eq!(
        list_classes(&aab, None, &opts(2)).unwrap(),
        vec![
            "Lcom/app/Base;".to_string(),
            "Lcom/app/Feature;".to_string()
        ]
    );
    let xml = manifest_xml(&aab).unwrap();
    assert!(xml.contains("package=\"com.example\""), "{xml}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn aab_duplicate_class_prefers_base_then_classes_ordinal() {
    let base = support::make_marked_dex(b"from-base-module!");
    let feature = support::make_marked_dex(b"from-feature-mod");
    let early = support::make_marked_dex(b"from-classes2-longer");
    let later = support::make_marked_dex(b"short");
    let dir = std::env::temp_dir().join(format!("asc-aab-dup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let aab = write_apk(
        &dir,
        "dup.aab",
        &[
            ("feature/dex/classes.dex", feature.as_slice()),
            ("base/dex/classes.dex", base.as_slice()),
        ],
        false,
    );
    let source = get_class_source(&aab, "example.Test", &smali_opts(4)).unwrap();
    assert!(source.contains("from-base-module!"), "{source}");
    assert!(!source.contains("from-feature-mod"), "{source}");
    let lines = find_refs(&aab, &RefQuery::String("from-feature-mod".into()), &opts(2))
        .unwrap()
        .lines;
    assert!(
        lines.iter().any(|line| line.contains("from-feature-mod")),
        "{lines:?}"
    );
    let ordered = write_apk(
        &dir,
        "order.aab",
        &[
            ("base/dex/classes10.dex", later.as_slice()),
            ("base/dex/classes2.dex", early.as_slice()),
        ],
        false,
    );
    let source = get_class_source(&ordered, "example.Test", &smali_opts(2)).unwrap();
    assert!(source.contains("from-classes2-longer"), "{source}");
    assert!(!source.contains("\"short\""), "{source}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cached_dex_entries_with_colliding_sanitized_names_stay_distinct() {
    let base = support::make_class_only_dex(&["Lexample/Test;"], 0, b"035");
    let extra = support::make_class_only_dex(&["Lexample/Best;"], 0, b"035");
    assert_eq!(base.len(), extra.len());
    let dir = std::env::temp_dir().join(format!("asc-cache-names-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let aab = write_apk(
        &dir,
        "app.aab",
        &[
            ("base/dex/classes.dex", base.as_slice()),
            ("base_dex_classes.dex", extra.as_slice()),
        ],
        false,
    );
    let expected = list_classes(&aab, None, &opts(1)).unwrap();
    assert_eq!(expected, vec!["Lexample/Test;", "Lexample/Best;"]);
    let mut cached = opts(1);
    cached.cache_dir = Some(dir.join("cache"));
    assert_eq!(list_classes(&aab, None, &cached).unwrap(), expected);
    cached.threads = 2;
    assert_eq!(list_classes(&aab, None, &cached).unwrap(), expected);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn cli_reports_an_invalid_float_encoding_without_panicking() {
    let mut data = support::make_field_dex();
    let class_off =
        usize::try_from(u32::from_le_bytes(data[0x64..0x68].try_into().unwrap())).unwrap();
    let values_off = u32::try_from(data.len()).unwrap();
    data[class_off + 28..class_off + 32].copy_from_slice(&values_off.to_le_bytes());
    data.extend_from_slice(&[1, 0x90, 0, 0, 0, 0, 0]);
    let file_size = u32::try_from(data.len()).unwrap();
    data[0x20..0x24].copy_from_slice(&file_size.to_le_bytes());
    let dir = std::env::temp_dir().join(format!("asc-invalid-float-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("classes.dex");
    std::fs::write(&path, data).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_asc"))
        .arg("getclass")
        .arg(path)
        .args(["Lexample/Test;", "--engine", "smali", "--no-cache"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("value_arg"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn ddc_getclass_prints_structured_java() {
    let dir = std::env::temp_dir().join(format!("asc-ddc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let straight = write_apk(
        &dir,
        "straight.apk",
        &[("classes.dex", support::make_dex().as_slice())],
        false,
    );
    let source = get_class_source(&straight, "example.Test", &opts(2)).unwrap();
    assert!(source.contains("class Test"), "{source}");
    assert!(source.contains("first"), "{source}");
    assert!(source.contains("second"), "{source}");
    assert!(!source.contains("const-string"), "{source}");

    let branch = write_apk(
        &dir,
        "branch.apk",
        &[("classes.dex", support::make_branch_dex().as_slice())],
        false,
    );
    let source = get_class_source(&branch, "example.Test", &opts(2)).unwrap();
    assert!(source.contains("class Test"), "{source}");
    assert!(source.contains("choose"), "{source}");
    assert!(source.contains("if"), "{source}");
    let manifest = sample_manifest();
    let dump_apk_path = write_apk(
        &dir,
        "branch-dump.apk",
        &[
            ("AndroidManifest.xml", manifest.as_slice()),
            ("classes.dex", support::make_branch_dex().as_slice()),
        ],
        false,
    );
    let out = dir.join("branch-out");
    let stats = dump_apk(&dump_apk_path, &out, &opts(2)).unwrap();
    assert_eq!(stats.classes, 1);
    assert_eq!(stats.errors, 0);
    let dumped = std::fs::read_to_string(out.join("example/Test.java")).unwrap();
    assert!(dumped.contains("if"), "{dumped}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ddc_getclass_rewrites_string_resources() {
    let dex = support::make_return_string_dex(b"@string/app_name");
    let dir = std::env::temp_dir().join(format!("asc-ddc-res-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let apk = write_apk(
        &dir,
        "res.apk",
        &[
            ("classes.dex", dex.as_slice()),
            ("resources.arsc", hello_arsc().as_slice()),
        ],
        false,
    );
    let source = get_class_source(&apk, "example.Test", &opts(2)).unwrap();
    assert!(source.contains("Hello"), "{source}");
    assert!(!source.contains("@string/app_name"), "{source}");
    let mut rejected = opts(2);
    rejected.resources = Some(dir.join("resources.arsc"));
    let err = get_class_source(&apk, "example.Test", &rejected).unwrap_err();
    assert!(err.to_string().contains("bare DEX or ABC"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bare_dex_resolves_resources_only_when_arsc_is_given() {
    let dex = support::make_return_string_dex(b"@string/app_name");
    let dir = std::env::temp_dir().join(format!("asc-bare-dex-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dex_path = dir.join("classes.dex");
    std::fs::write(&dex_path, &dex).unwrap();
    let plain = get_class_source(&dex_path, "example.Test", &opts(2)).unwrap();
    assert!(plain.contains("@string/app_name"), "{plain}");
    assert!(!plain.contains("Hello"), "{plain}");
    let names = list_classes(&dex_path, Some("Lexample/Test"), &opts(2)).unwrap();
    assert_eq!(names, vec!["Lexample/Test;".to_string()]);
    let raw = find_refs(
        &dex_path,
        &RefQuery::String("Hello".into()),
        &opts(2),
    )
    .unwrap()
    .lines;
    assert!(raw.is_empty(), "{raw:?}");

    let arsc = dir.join("resources.arsc");
    std::fs::write(&arsc, hello_arsc()).unwrap();
    let mut with = opts(2);
    with.resources = Some(arsc.clone());
    let rewritten = get_class_source(&dex_path, "example.Test", &with).unwrap();
    assert!(rewritten.contains("Hello"), "{rewritten}");
    assert!(!rewritten.contains("@string/app_name"), "{rewritten}");
    let resolved = find_refs(
        &dex_path,
        &RefQuery::String("Hello".into()),
        &with,
    )
    .unwrap()
    .lines;
    assert!(
        resolved.iter().any(|line| line.contains("Hello")),
        "{resolved:?}"
    );
    let out = dir.join("out");
    let stats = dump_apk(&dex_path, &out, &with).unwrap();
    assert_eq!(stats.classes, 1);
    assert_eq!(stats.errors, 0);
    let dumped = std::fs::read_to_string(out.join("example/Test.java")).unwrap();
    assert!(dumped.contains("Hello"), "{dumped}");
    let mut smali = smali_opts(2);
    smali.resources = Some(dir.join("missing.arsc"));
    let err = get_class_source(&dex_path, "example.Test", &smali).unwrap_err();
    assert!(err.to_string().contains("missing.arsc"), "{err}");
    smali.resources = Some(arsc);
    let smali_text = get_class_source(&dex_path, "example.Test", &smali).unwrap();
    assert!(smali_text.contains("@string/app_name"), "{smali_text}");
    assert!(!smali_text.contains("Hello"), "{smali_text}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_broken_dex_entry_keeps_the_other_hits_and_exits_2() {
    let dir = std::env::temp_dir().join(format!("asc-partial-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let apk = write_apk(
        &dir,
        "partial.apk",
        &[
            ("classes.dex", support::make_dex().as_slice()),
            ("classes2.dex", b"dex\n035\0not-a-dex"),
        ],
        false,
    );
    let report = find_refs(&apk, &RefQuery::String("token".into()), &opts(2)).unwrap();
    assert!(report.partial, "{:?}", report.lines);
    assert!(report.lines.iter().any(|line| line.contains("token")), "{:?}", report.lines);
    let output = Command::new(env!("CARGO_BIN_EXE_asc"))
        .args([
            "findrefs",
            "--no-cache",
            apk.to_str().unwrap(),
            "string",
            "token",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("token"), "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn fuzzy_class_is_rejected_for_a_bare_abc() {
    let dir = std::env::temp_dir().join(format!("asc-fuzzy-abc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let abc = dir.join("modules.abc");
    let mut bytes = b"PANDA\0\0\0".to_vec();
    bytes.resize(64, 0);
    std::fs::write(&abc, bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_asc"))
        .args([
            "findrefs",
            abc.to_str().unwrap(),
            "method",
            "main",
            "--class",
            "demo.App",
            "--fuzzy-class",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--fuzzy-class"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

fn hello_arsc() -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn utf8_pool(strings: &[&str]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut offsets = Vec::new();
        for text in strings {
            offsets.push(body.len() as u32);
            body.push(text.chars().count() as u8);
            body.push(text.len() as u8);
            body.extend_from_slice(text.as_bytes());
            body.push(0);
        }
        let header_size = 28;
        let strings_start = header_size + strings.len() * 4;
        let mut pool = vec![0u8; strings_start];
        put_u16(&mut pool, 0, 0x0001);
        put_u16(&mut pool, 2, header_size as u16);
        put_u32(&mut pool, 8, strings.len() as u32);
        put_u32(&mut pool, 16, 1 << 8);
        put_u32(&mut pool, 20, strings_start as u32);
        for (index, offset) in offsets.iter().enumerate() {
            put_u32(&mut pool, header_size + index * 4, *offset);
        }
        pool.extend(body);
        let len = pool.len() as u32;
        put_u32(&mut pool, 4, len);
        pool
    }
    let global = utf8_pool(&["Hello"]);
    let types = utf8_pool(&["string"]);
    let keys = utf8_pool(&["app_name"]);
    let config_size = 28u32;
    let header_size = 20 + config_size as usize;
    let entries_start = header_size + 4;
    let mut chunk = vec![0u8; entries_start + 16];
    put_u16(&mut chunk, 0, 0x0201);
    put_u16(&mut chunk, 2, header_size as u16);
    chunk[8] = 1;
    put_u32(&mut chunk, 12, 1);
    put_u32(&mut chunk, 16, entries_start as u32);
    put_u32(&mut chunk, 20, config_size);
    put_u32(&mut chunk, header_size, 0);
    put_u16(&mut chunk, entries_start, 8);
    put_u32(&mut chunk, entries_start + 4, 0);
    put_u16(&mut chunk, entries_start + 8, 8);
    chunk[entries_start + 11] = 0x03;
    put_u32(&mut chunk, entries_start + 12, 0);
    let chunk_len = chunk.len() as u32;
    put_u32(&mut chunk, 4, chunk_len);

    let mut package = vec![0u8; 288];
    put_u16(&mut package, 0, 0x0200);
    put_u16(&mut package, 2, 288);
    put_u32(&mut package, 8, 0x7f);
    let type_off = package.len();
    package.extend(types);
    let key_off = package.len();
    package.extend(keys);
    put_u32(&mut package, 268, type_off as u32);
    put_u32(&mut package, 276, key_off as u32);
    package.extend(chunk);
    let package_len = package.len() as u32;
    put_u32(&mut package, 4, package_len);

    let mut table = vec![0u8; 12];
    put_u16(&mut table, 0, 0x0002);
    put_u16(&mut table, 2, 12);
    put_u32(&mut table, 8, 1);
    table.extend(global);
    table.extend(package);
    let table_len = table.len() as u32;
    put_u32(&mut table, 4, table_len);
    table
}

fn sample_manifest() -> Vec<u8> {
    // Built by the library test; reconstruct the same bytes the unit test uses
    // by shelling through a tiny encoder kept here so the APK path is covered.
    fn push_u16(buf: &mut Vec<u8>, value: u16) {
        buf.extend_from_slice(&value.to_le_bytes());
    }
    fn push_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }
    fn encode_pool(strings: &[&str]) -> Vec<u8> {
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for value in strings {
            offsets.push(data.len() as u32);
            data.push(value.chars().count() as u8);
            data.push(value.len() as u8);
            data.extend_from_slice(value.as_bytes());
            data.push(0);
        }
        while data.len() % 4 != 0 {
            data.push(0);
        }
        let strings_start = 28 + strings.len() as u32 * 4;
        let mut buf = Vec::new();
        push_u16(&mut buf, 0x0001);
        push_u16(&mut buf, 28);
        push_u32(&mut buf, strings_start + data.len() as u32);
        push_u32(&mut buf, strings.len() as u32);
        push_u32(&mut buf, 0);
        push_u32(&mut buf, 1 << 8);
        push_u32(&mut buf, strings_start);
        push_u32(&mut buf, 0);
        for offset in offsets {
            push_u32(&mut buf, offset);
        }
        buf.extend(data);
        buf
    }
    let strings = [
        "android",
        "http://schemas.android.com/apk/res/android",
        "manifest",
        "package",
        "com.example",
        "application",
        "label",
        "Demo",
    ];
    let mut body = encode_pool(&strings);
    let mut ns = Vec::new();
    push_u16(&mut ns, 0x0100);
    push_u16(&mut ns, 16);
    push_u32(&mut ns, 24);
    push_u32(&mut ns, 1);
    push_u32(&mut ns, 0xffff_ffff);
    push_u32(&mut ns, 0);
    push_u32(&mut ns, 1);
    body.extend(ns);
    body.extend(element(0xffff_ffff, 2, &[(0xffff_ffff, 3, 4)]));
    body.extend(element(0xffff_ffff, 5, &[(1, 6, 7)]));
    body.extend(end_element(0xffff_ffff, 5));
    body.extend(end_element(0xffff_ffff, 2));
    let mut end_ns = Vec::new();
    push_u16(&mut end_ns, 0x0101);
    push_u16(&mut end_ns, 16);
    push_u32(&mut end_ns, 24);
    push_u32(&mut end_ns, 1);
    push_u32(&mut end_ns, 0xffff_ffff);
    push_u32(&mut end_ns, 0);
    push_u32(&mut end_ns, 1);
    body.extend(end_ns);
    let mut file = Vec::new();
    push_u16(&mut file, 0x0003);
    push_u16(&mut file, 8);
    push_u32(&mut file, (8 + body.len()) as u32);
    file.extend(body);
    file
}

fn element(ns: u32, name: u32, attrs: &[(u32, u32, u32)]) -> Vec<u8> {
    let mut buf = Vec::new();
    let size = 16 + 20 + attrs.len() * 20;
    buf.extend_from_slice(&0x0102u16.to_le_bytes());
    buf.extend_from_slice(&16u16.to_le_bytes());
    buf.extend_from_slice(&(size as u32).to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    buf.extend_from_slice(&ns.to_le_bytes());
    buf.extend_from_slice(&name.to_le_bytes());
    buf.extend_from_slice(&20u16.to_le_bytes());
    buf.extend_from_slice(&20u16.to_le_bytes());
    buf.extend_from_slice(&(attrs.len() as u16).to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    for (ans, aname, raw) in attrs {
        buf.extend_from_slice(&ans.to_le_bytes());
        buf.extend_from_slice(&aname.to_le_bytes());
        buf.extend_from_slice(&raw.to_le_bytes());
        buf.extend_from_slice(&8u16.to_le_bytes());
        buf.push(0);
        buf.push(0x03);
        buf.extend_from_slice(&raw.to_le_bytes());
    }
    buf
}

fn end_element(ns: u32, name: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x0103u16.to_le_bytes());
    buf.extend_from_slice(&16u16.to_le_bytes());
    buf.extend_from_slice(&24u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    buf.extend_from_slice(&ns.to_le_bytes());
    buf.extend_from_slice(&name.to_le_bytes());
    buf
}
