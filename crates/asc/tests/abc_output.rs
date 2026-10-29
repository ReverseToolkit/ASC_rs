use std::io::Write;
use std::process::Command;

const CLASS: &[u8] = include_bytes!("../../asc-abc-dec/tests/fixtures/class.abc");

enum ZipCompression {
    Stored,
    Deflated,
}

fn hap_archive(compression: ZipCompression) -> Vec<u8> {
    let mut archive = Vec::new();
    let mut central = Vec::new();
    for (name, payload) in [
        ("ets/modules.abc", CLASS),
        ("module.json", b"{}".as_slice()),
    ] {
        let (method, encoded) = match compression {
            ZipCompression::Stored => (0u16, payload.to_vec()),
            ZipCompression::Deflated => {
                let mut encoder =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(payload).unwrap();
                (8, encoder.finish().unwrap())
            }
        };
        let offset = u32::try_from(archive.len()).unwrap();
        let crc = crc32fast::hash(payload);
        let compressed = u32::try_from(encoded.len()).unwrap();
        let size = u32::try_from(payload.len()).unwrap();
        let name_len = u16::try_from(name.len()).unwrap();
        archive.extend(b"PK\x03\x04");
        for value in [20, 0, method, 0, 0] {
            archive.extend(value.to_le_bytes());
        }
        for value in [crc, compressed, size] {
            archive.extend(value.to_le_bytes());
        }
        for value in [name_len, 0] {
            archive.extend(value.to_le_bytes());
        }
        archive.extend(name.as_bytes());
        archive.extend(encoded);
        central.extend(b"PK\x01\x02");
        for value in [20, 20, 0, method, 0, 0] {
            central.extend(value.to_le_bytes());
        }
        for value in [crc, compressed, size] {
            central.extend(value.to_le_bytes());
        }
        for value in [name_len, 0, 0, 0, 0] {
            central.extend(value.to_le_bytes());
        }
        for value in [0, offset] {
            central.extend(value.to_le_bytes());
        }
        central.extend(name.as_bytes());
    }
    let offset = u32::try_from(archive.len()).unwrap();
    let size = u32::try_from(central.len()).unwrap();
    archive.extend(central);
    archive.extend(b"PK\x05\x06");
    for value in [0u16, 0, 2, 2] {
        archive.extend(value.to_le_bytes());
    }
    for value in [size, offset] {
        archive.extend(value.to_le_bytes());
    }
    archive.extend(0u16.to_le_bytes());
    archive
}

#[test]
fn cli_getclass_selects_abc_source_or_assembly_for_bare_and_hap_inputs() {
    let dir = std::env::temp_dir().join(format!("asc-cli-abc-output-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bare = dir.join("class.abc");
    std::fs::write(&bare, CLASS).unwrap();
    let hap = dir.join("app.hap");
    std::fs::write(&hap, hap_archive(ZipCompression::Deflated)).unwrap();
    for input in [&bare, &hap] {
        let source = Command::new(env!("CARGO_BIN_EXE_asc"))
            .arg("getclass")
            .arg(input)
            .arg("L_GLOBAL;")
            .output()
            .unwrap();
        assert!(
            source.status.success(),
            "{}",
            String::from_utf8_lossy(&source.stderr)
        );
        assert!(String::from_utf8(source.stdout)
            .unwrap()
            .contains("class Test"));
        let output = dir.join("class.pa");
        let assembly = Command::new(env!("CARGO_BIN_EXE_asc"))
            .arg("getclass")
            .arg(input)
            .args(["L_GLOBAL;", "--abc-output", "asm", "-o"])
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            assembly.status.success(),
            "{}",
            String::from_utf8_lossy(&assembly.stderr)
        );
        assert!(assembly.stdout.is_empty());
        let text = std::fs::read_to_string(&output).unwrap();
        assert!(text.contains("defineclasswithbuffer"), "{text}");
        assert!(text.contains("label_0000:"), "{text}");
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn cli_dump_uses_js_or_pa_extensions_for_abc_and_hap() {
    let dir = std::env::temp_dir().join(format!("asc-cli-abc-dump-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bare = dir.join("class.abc");
    std::fs::write(&bare, CLASS).unwrap();
    let hap = dir.join("app.hap");
    std::fs::write(&hap, hap_archive(ZipCompression::Stored)).unwrap();
    for (index, input) in [&bare, &hap].into_iter().enumerate() {
        for (mode, extension, expected) in [
            ("source", "js", "class Test"),
            ("asm", "pa", "defineclasswithbuffer"),
        ] {
            let output = dir.join(format!("{index}-{mode}"));
            let result = Command::new(env!("CARGO_BIN_EXE_asc"))
                .arg("dump")
                .arg(input)
                .args(["--abc-output", mode, "-o"])
                .arg(&output)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(String::from_utf8(result.stderr)
                .unwrap()
                .contains("0 errors"));
            let text =
                std::fs::read_to_string(output.join(format!("_GLOBAL.{extension}"))).unwrap();
            assert!(text.contains(expected), "{text}");
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}
