use std::io::Write;
use std::path::Path;

use asc_diff::{Archive, ArchiveDiff, Group};
use flate2::{write::DeflateEncoder, Compression};

fn store_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut locals = Vec::new();
    let mut central = Vec::new();
    for (name, bytes) in files {
        let name = name.as_bytes();
        let crc = crc32fast::hash(bytes);
        let offset = u32::try_from(locals.len()).unwrap();
        locals.extend_from_slice(b"PK\x03\x04");
        locals.extend_from_slice(&20u16.to_le_bytes());
        locals.extend_from_slice(&0u16.to_le_bytes());
        locals.extend_from_slice(&0u16.to_le_bytes());
        locals.extend_from_slice(&0u16.to_le_bytes());
        locals.extend_from_slice(&0u16.to_le_bytes());
        locals.extend_from_slice(&crc.to_le_bytes());
        locals.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        locals.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        locals.extend_from_slice(&(name.len() as u16).to_le_bytes());
        locals.extend_from_slice(&0u16.to_le_bytes());
        locals.extend_from_slice(name);
        locals.extend_from_slice(bytes);

        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        central.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name);
    }
    let cd_off = u32::try_from(locals.len()).unwrap();
    let cd_size = u32::try_from(central.len()).unwrap();
    let mut archive = locals;
    archive.extend_from_slice(&central);
    archive.extend_from_slice(b"PK\x05\x06");
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&(files.len() as u16).to_le_bytes());
    archive.extend_from_slice(&(files.len() as u16).to_le_bytes());
    archive.extend_from_slice(&cd_size.to_le_bytes());
    archive.extend_from_slice(&cd_off.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive
}

fn deflated_zip(name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut archive = store_zip(&[(name, bytes)]);
    let payload_off = 30 + name.len();
    archive.splice(
        payload_off..payload_off + bytes.len(),
        compressed.iter().copied(),
    );
    let cd_off = payload_off + compressed.len();
    let compressed_size = u32::try_from(compressed.len()).unwrap().to_le_bytes();
    archive[8..10].copy_from_slice(&8u16.to_le_bytes());
    archive[18..22].copy_from_slice(&compressed_size);
    archive[cd_off + 10..cd_off + 12].copy_from_slice(&8u16.to_le_bytes());
    archive[cd_off + 20..cd_off + 24].copy_from_slice(&compressed_size);
    let eocd = archive.len() - 22;
    archive[eocd + 16..eocd + 20].copy_from_slice(&u32::try_from(cd_off).unwrap().to_le_bytes());
    archive
}

#[test]
fn archive_reader_rejects_incorrect_declared_sizes() {
    let name = "assets/test.txt";
    let dir = std::env::temp_dir().join(format!("asc-diff-sizes-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (index, valid) in [
        store_zip(&[(name, b"abcdef")]),
        deflated_zip(name, b"abcdef"),
    ]
    .into_iter()
    .enumerate()
    {
        for size in [0u32, 3, 7] {
            let mut bytes = valid.clone();
            let eocd = bytes.len() - 22;
            let cd_off = usize::try_from(u32::from_le_bytes(
                bytes[eocd + 16..eocd + 20].try_into().unwrap(),
            ))
            .unwrap();
            bytes[cd_off + 24..cd_off + 28].copy_from_slice(&size.to_le_bytes());
            let path = dir.join(format!("{index}-{size}.zip"));
            std::fs::write(&path, bytes).unwrap();
            let err = Archive::open(&path).unwrap().read(name).unwrap_err();
            assert!(err.to_string().contains(name), "{err}");
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn archive_reader_preserves_complete_and_empty_entries() {
    let name = "assets/test.txt";
    let dir = std::env::temp_dir().join(format!("asc-diff-complete-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for payload in [b"abcdef".as_slice(), b""] {
        for (index, bytes) in [store_zip(&[(name, payload)]), deflated_zip(name, payload)]
            .into_iter()
            .enumerate()
        {
            let path = dir.join(format!("{index}-{}.zip", payload.len()));
            std::fs::write(&path, bytes).unwrap();
            assert_eq!(Archive::open(&path).unwrap().read(name).unwrap(), payload);
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn archive_reader_rejects_invalid_local_headers() {
    let name = "assets/test.txt";
    let dir = std::env::temp_dir().join(format!("asc-diff-local-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut bytes = store_zip(&[(name, b"abcdef")]);
    bytes[0] = 0;
    let path = dir.join("bad.zip");
    std::fs::write(&path, bytes).unwrap();
    let err = Archive::open(&path).unwrap().read(name).unwrap_err();
    assert!(err.to_string().contains("local header"), "{err}");
    std::fs::remove_dir_all(dir).unwrap();
}

fn write_pair(
    dir: &Path,
    left: &[(&str, &[u8])],
    right: &[(&str, &[u8])],
) -> (std::path::PathBuf, std::path::PathBuf) {
    let left_path = dir.join("left.zip");
    let right_path = dir.join("right.zip");
    std::fs::write(&left_path, store_zip(left)).unwrap();
    std::fs::write(&right_path, store_zip(right)).unwrap();
    (left_path, right_path)
}

#[test]
fn groups_assets_separately_from_dex_and_keeps_identical_files() {
    let dir = std::env::temp_dir().join(format!("asc-diff-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (left, right) = write_pair(
        &dir,
        &[
            ("assets/same.txt", b"same"),
            ("assets/old.txt", b"gone"),
            ("assets/changed.txt", b"v1"),
            ("classes.dex", b"dex-v1"),
            ("res/a.xml", b"<a/>"),
            ("META-INF/MANIFEST.MF", b"left-sign"),
        ],
        &[
            ("assets/same.txt", b"same"),
            ("assets/new.txt", b"fresh"),
            ("assets/changed.txt", b"v2"),
            ("classes.dex", b"dex-v2"),
            ("res/a.xml", b"<a/>"),
            ("META-INF/MANIFEST.MF", b"right-sign"),
        ],
    );
    let diff = ArchiveDiff::between(
        &Archive::open(&left).unwrap(),
        &Archive::open(&right).unwrap(),
    );
    assert_eq!(diff.unchanged_count(), 2);
    assert_eq!(diff.added_count(), 1);
    assert_eq!(diff.removed_count(), 1);
    assert_eq!(diff.changed_count(), 2);
    let assets = diff
        .groups
        .iter()
        .find(|group| group.group == Group::Assets)
        .unwrap();
    assert_eq!(assets.unchanged, 1);
    assert_eq!(assets.added[0].name, "assets/new.txt");
    assert_eq!(assets.removed[0].name, "assets/old.txt");
    assert_eq!(assets.changed[0].name, "assets/changed.txt");
    assert_eq!(assets.changed[0].left_size, 2);
    assert_eq!(assets.changed[0].right_size, 2);
    let prefixed = ArchiveDiff::between_prefix(
        &Archive::open(&left).unwrap(),
        &Archive::open(&right).unwrap(),
        "assets/",
    );
    assert_eq!(prefixed.changed_count(), 1);
    assert!(prefixed
        .groups
        .iter()
        .all(|group| group.group == Group::Assets));
    let shown = diff.to_string();
    assert!(shown.contains("assets/changed.txt"), "{shown}");
    assert!(shown.contains("classes.dex"), "{shown}");
    assert!(!shown.contains("META-INF"), "{shown}");
    assert!(shown.contains("certificate: none"), "{shown}");
    assert!(!prefixed.to_string().contains("certificate:"), "{prefixed}");
    let _ = std::fs::remove_dir_all(&dir);
}

fn self_signed(name: &str) -> Vec<u8> {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, name);
        dn
    };
    params.self_signed(&key).unwrap().der().to_vec()
}

#[test]
fn signature_blocks_compare_certificates_not_file_bytes() {
    let dir = std::env::temp_dir().join(format!("asc-diff-cert-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let first = self_signed("alpha");
    let second = self_signed("beta");
    let (left, right) = write_pair(
        &dir,
        &[
            ("assets/a.txt", b"same"),
            ("META-INF/CERT.RSA", first.as_slice()),
            ("META-INF/MANIFEST.MF", b"mf-left"),
        ],
        &[
            ("assets/a.txt", b"same"),
            ("META-INF/CERT.RSA", second.as_slice()),
            ("META-INF/MANIFEST.MF", b"mf-right"),
        ],
    );
    let diff = ArchiveDiff::between(
        &Archive::open(&left).unwrap(),
        &Archive::open(&right).unwrap(),
    );
    assert_eq!(diff.changed_count(), 0, "{}", diff);
    assert_eq!(diff.certificates.as_ref().unwrap().removed.len(), 1);
    assert_eq!(diff.certificates.as_ref().unwrap().added.len(), 1);
    let shown = diff.to_string();
    assert!(shown.contains("Subject:"), "{shown}");
    assert!(shown.contains("CN=alpha"), "{shown}");
    assert!(shown.contains("CN=beta"), "{shown}");
    assert!(!shown.contains("MANIFEST.MF"), "{shown}");
    assert!(!shown.contains("~ META-INF/CERT.RSA"), "{shown}");
    assert!(shown.contains("Source: META-INF/CERT.RSA"), "{shown}");
    let _ = std::fs::remove_dir_all(&dir);
}

fn with_hap_sign(zip: &[u8], cert: &[u8]) -> Vec<u8> {
    let eocd = zip.len() - 22;
    let cd_off = u32::from_le_bytes(zip[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    let size = u64::try_from(cert.len() + 8).unwrap();
    let mut out = Vec::new();
    out.extend_from_slice(&zip[..cd_off]);
    out.extend_from_slice(cert);
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(b"<hap sign block>");
    let new_cd = u32::try_from(out.len()).unwrap();
    out.extend_from_slice(&zip[cd_off..]);
    let new_eocd = out.len() - 22;
    out[new_eocd + 16..new_eocd + 20].copy_from_slice(&new_cd.to_le_bytes());
    out
}

#[test]
fn hap_entries_are_grouped_and_the_sign_block_is_a_certificate() {
    let dir = std::env::temp_dir().join(format!("asc-diff-hap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let alpha = self_signed("alpha");
    let beta = self_signed("beta");
    let left_zip = with_hap_sign(
        &store_zip(&[
            ("module.json", b"{\"v\":1}"),
            ("ets/modules.abc", b"abc-v1"),
            ("libs/arm64-v8a/libapp.so", b"so"),
            ("resources/base/element/string.json", b"[]"),
        ]),
        &alpha,
    );
    let right_zip = with_hap_sign(
        &store_zip(&[
            ("module.json", b"{\"v\":2}"),
            ("ets/modules.abc", b"abc-v1"),
            ("libs/arm64-v8a/libapp.so", b"so2"),
            ("resources/base/element/string.json", b"[]"),
        ]),
        &beta,
    );
    let left = dir.join("left.hap");
    let right = dir.join("right.hap");
    std::fs::write(&left, left_zip).unwrap();
    std::fs::write(&right, right_zip).unwrap();
    let diff = ArchiveDiff::between(
        &Archive::open(&left).unwrap(),
        &Archive::open(&right).unwrap(),
    );
    let shown = diff.to_string();
    assert!(shown.contains("module:"), "{shown}");
    assert!(shown.contains("abc:"), "{shown}");
    assert!(shown.contains("lib:"), "{shown}");
    assert!(shown.contains("elf: not an ELF file"), "{shown}");
    assert!(shown.contains("resources:"), "{shown}");
    assert!(shown.contains("CN=alpha"), "{shown}");
    assert!(shown.contains("CN=beta"), "{shown}");
    assert!(shown.contains("Source: hap sign block"), "{shown}");
    assert!(!shown.contains("hap sign block>"), "{shown}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn changed_x86_so_prints_disassembly() {
    let dir = std::env::temp_dir().join(format!("asc-diff-so-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let left_so = elf32(&[0x90, 0xc3]);
    let right_so = elf32(&[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]);
    let (left, right) = write_pair(
        &dir,
        &[("lib/x86/libdemo.so", left_so.as_slice())],
        &[("lib/x86/libdemo.so", right_so.as_slice())],
    );
    let diff = ArchiveDiff::between(
        &Archive::open(&left).unwrap(),
        &Archive::open(&right).unwrap(),
    );
    let shown = diff.to_string();
    assert!(shown.contains("disasm code 0x1000"), "{shown}");
    assert!(shown.contains("< "), "{shown}");
    assert!(shown.contains("nop"), "{shown}");
    assert!(shown.contains("> "), "{shown}");
    assert!(shown.contains("mov"), "{shown}");
    assert!(!shown.contains("symbols unchanged"), "{shown}");
    let _ = std::fs::remove_dir_all(&dir);
}

fn elf32(code: &[u8]) -> Vec<u8> {
    let shoff = 52usize;
    let shentsize = 40usize;
    let text_off = shoff + 4 * shentsize;
    let sym_off = text_off + code.len();
    let str_off = sym_off + 32;
    let strings = b"\0work\0";
    let mut file = vec![0u8; str_off + strings.len()];
    file[0..4].copy_from_slice(b"\x7fELF");
    file[4] = 1;
    file[5] = 1;
    file[6] = 1;
    file[16..18].copy_from_slice(&3u16.to_le_bytes());
    file[18..20].copy_from_slice(&3u16.to_le_bytes());
    file[20..24].copy_from_slice(&1u32.to_le_bytes());
    file[32..36].copy_from_slice(&(shoff as u32).to_le_bytes());
    file[40..42].copy_from_slice(&52u16.to_le_bytes());
    file[46..48].copy_from_slice(&(shentsize as u16).to_le_bytes());
    file[48..50].copy_from_slice(&4u16.to_le_bytes());
    write_sh32(
        &mut file,
        shoff,
        1,
        section(1, 6, text_off, code.len(), 0x1000),
    );
    write_sh32(&mut file, shoff, 2, section(11, 2, sym_off, 32, 0));
    write_sh32(
        &mut file,
        shoff,
        3,
        section(3, 0, str_off, strings.len(), 0),
    );
    file[sym_off + 16..sym_off + 20].copy_from_slice(&1u32.to_le_bytes());
    file[sym_off + 20..sym_off + 24].copy_from_slice(&0x1000u32.to_le_bytes());
    file[sym_off + 24..sym_off + 28].copy_from_slice(&(code.len() as u32).to_le_bytes());
    file[sym_off + 28] = 0x12;
    file[sym_off + 30..sym_off + 32].copy_from_slice(&1u16.to_le_bytes());
    file[text_off..text_off + code.len()].copy_from_slice(code);
    file[str_off..str_off + strings.len()].copy_from_slice(strings);
    file
}

struct Section {
    kind: u32,
    flags: u32,
    offset: usize,
    size: usize,
    addr: u32,
}

fn section(kind: u32, flags: u32, offset: usize, size: usize, addr: u32) -> Section {
    Section {
        kind,
        flags,
        offset,
        size,
        addr,
    }
}

fn write_sh32(file: &mut [u8], shoff: usize, index: usize, section: Section) {
    let at = shoff + index * 40;
    file[at + 4..at + 8].copy_from_slice(&section.kind.to_le_bytes());
    file[at + 8..at + 12].copy_from_slice(&section.flags.to_le_bytes());
    file[at + 12..at + 16].copy_from_slice(&section.addr.to_le_bytes());
    file[at + 16..at + 20].copy_from_slice(&u32::try_from(section.offset).unwrap().to_le_bytes());
    file[at + 20..at + 24].copy_from_slice(&u32::try_from(section.size).unwrap().to_le_bytes());
    file[at + 24..at + 28].copy_from_slice(&3u32.to_le_bytes());
    let entsize = if section.kind == 11 { 16u32 } else { 1 };
    file[at + 36..at + 40].copy_from_slice(&entsize.to_le_bytes());
}

#[test]
fn shortened_resource_paths_match_by_restored_name() {
    let dir = std::env::temp_dir().join(format!("asc-diff-res-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (left, right) = write_pair(
        &dir,
        &[
            ("resources.arsc", &file_arsc("r/d/c.xml")),
            ("r/d/c.xml", b"icon"),
            ("assets/a.txt", b"same"),
        ],
        &[
            ("resources.arsc", &file_arsc("r/ab/z.xml")),
            ("r/ab/z.xml", b"icon2"),
            ("assets/a.txt", b"same"),
        ],
    );
    let diff = ArchiveDiff::between(
        &Archive::open(&left).unwrap(),
        &Archive::open(&right).unwrap(),
    );
    let shown = diff.to_string();
    assert!(
        shown.contains("res: changed 1, added 0, removed 0, unchanged 0"),
        "{shown}"
    );
    assert!(shown.contains("~ res/drawable-hdpi/icon.xml"), "{shown}");
    assert!(!shown.contains("r/d/c.xml"), "{shown}");
    assert!(!shown.contains("r/ab/z.xml"), "{shown}");
    let _ = std::fs::remove_dir_all(&dir);
}

fn file_arsc(path: &str) -> Vec<u8> {
    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn pool(strings: &[&str]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut offsets = Vec::new();
        for text in strings {
            offsets.push(u32::try_from(body.len()).unwrap());
            body.push(u8::try_from(text.chars().count()).unwrap());
            body.push(u8::try_from(text.len()).unwrap());
            body.extend_from_slice(text.as_bytes());
            body.push(0);
        }
        let header = 28usize;
        let strings_start = header + strings.len() * 4;
        let mut out = vec![0u8; strings_start];
        put_u16(&mut out, 0, 1);
        put_u16(&mut out, 2, 28);
        put_u32(&mut out, 8, u32::try_from(strings.len()).unwrap());
        put_u32(&mut out, 16, 1 << 8);
        put_u32(&mut out, 20, u32::try_from(strings_start).unwrap());
        for (index, offset) in offsets.iter().enumerate() {
            put_u32(&mut out, header + index * 4, *offset);
        }
        out.extend(body);
        let len = u32::try_from(out.len()).unwrap();
        put_u32(&mut out, 4, len);
        out
    }
    let global = pool(&[path]);
    let mut package = vec![0u8; 288];
    put_u16(&mut package, 0, 0x0200);
    put_u16(&mut package, 2, 288);
    put_u32(&mut package, 8, 0x7f);
    let type_off = package.len();
    package.extend(pool(&["drawable"]));
    let key_off = package.len();
    package.extend(pool(&["icon"]));
    put_u32(&mut package, 268, u32::try_from(type_off).unwrap());
    put_u32(&mut package, 276, u32::try_from(key_off).unwrap());
    let config_size = 28u32;
    let header_size = 20 + config_size as usize;
    let entries_start = header_size + 4;
    let mut chunk = vec![0u8; entries_start + 16];
    put_u16(&mut chunk, 0, 0x0201);
    put_u16(&mut chunk, 2, u16::try_from(header_size).unwrap());
    chunk[8] = 1;
    put_u32(&mut chunk, 12, 1);
    put_u32(&mut chunk, 16, u32::try_from(entries_start).unwrap());
    put_u32(&mut chunk, 20, config_size);
    put_u16(&mut chunk, 34, 240);
    put_u16(&mut chunk, entries_start, 8);
    put_u16(&mut chunk, entries_start + 8, 8);
    chunk[entries_start + 11] = 0x03;
    let chunk_len = u32::try_from(chunk.len()).unwrap();
    put_u32(&mut chunk, 4, chunk_len);
    package.extend(chunk);
    let package_len = u32::try_from(package.len()).unwrap();
    put_u32(&mut package, 4, package_len);
    let mut table = vec![0u8; 12];
    put_u16(&mut table, 0, 0x0002);
    put_u16(&mut table, 2, 12);
    put_u32(&mut table, 8, 1);
    table.extend(global);
    table.extend(package);
    let table_len = u32::try_from(table.len()).unwrap();
    put_u32(&mut table, 4, table_len);
    table
}

#[test]
fn identical_decoded_xml_is_unchanged_when_bytes_differ() {
    let dir = std::env::temp_dir().join(format!("asc-diff-xml-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut right = binary_layout("Hello");
    right.push(0);
    let (left, right) = write_pair(
        &dir,
        &[("res/layout/a.xml", &binary_layout("Hello"))],
        &[("res/layout/a.xml", &right)],
    );
    let diff = ArchiveDiff::between(
        &Archive::open(&left).unwrap(),
        &Archive::open(&right).unwrap(),
    );
    let shown = diff.to_string();
    assert!(
        shown.contains("res: changed 0, added 0, removed 0, unchanged 1"),
        "{shown}"
    );
    assert!(!shown.contains("~ res/layout/a.xml"), "{shown}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn decoded_xml_differences_are_shown() {
    let dir = std::env::temp_dir().join(format!("asc-diff-xml2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (left, right) = write_pair(
        &dir,
        &[("res/layout/a.xml", &binary_layout("Hello"))],
        &[("res/layout/a.xml", &binary_layout("World"))],
    );
    let diff = ArchiveDiff::between(
        &Archive::open(&left).unwrap(),
        &Archive::open(&right).unwrap(),
    );
    let shown = diff.to_string();
    assert!(shown.contains("~ res/layout/a.xml"), "{shown}");
    assert!(shown.contains("xml"), "{shown}");
    assert!(shown.contains("< "), "{shown}");
    assert!(shown.contains("text=\"Hello\""), "{shown}");
    assert!(shown.contains("> "), "{shown}");
    assert!(shown.contains("text=\"World\""), "{shown}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn export_writes_both_sides_as_decoded_xml() {
    let dir = std::env::temp_dir().join(format!("asc-diff-export-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("out");
    let (left, right) = write_pair(
        &dir,
        &[
            (
                "AndroidManifest.xml",
                br#"<manifest android:versionCode="10" />"#,
            ),
            ("resources.arsc", &file_arsc("r/d/c.xml")),
            ("r/d/c.xml", &binary_layout("Hello")),
            ("assets/keep.txt", b"same"),
            ("assets/gone.txt", b"old"),
        ],
        &[
            (
                "AndroidManifest.xml",
                br#"<manifest android:versionCode="20" />"#,
            ),
            ("resources.arsc", &file_arsc("r/ab/z.xml")),
            ("r/ab/z.xml", &binary_layout("World")),
            ("assets/keep.txt", b"same"),
            ("assets/new.txt", b"fresh"),
        ],
    );
    let left_archive = Archive::open(&left).unwrap();
    let right_archive = Archive::open(&right).unwrap();
    let diff = ArchiveDiff::between(&left_archive, &right_archive);
    diff.export(&left_archive, &right_archive, &out).unwrap();
    let old_xml = std::fs::read_to_string(out.join("10/res/drawable-hdpi/icon.xml")).unwrap();
    let new_xml = std::fs::read_to_string(out.join("20/res/drawable-hdpi/icon.xml")).unwrap();
    assert!(old_xml.starts_with("<?xml"), "{old_xml}");
    assert!(old_xml.contains("text=\"Hello\""), "{old_xml}");
    assert!(new_xml.contains("text=\"World\""), "{new_xml}");
    assert_eq!(
        std::fs::read(out.join("10/assets/gone.txt")).unwrap(),
        b"old"
    );
    assert_eq!(
        std::fs::read(out.join("20/assets/new.txt")).unwrap(),
        b"fresh"
    );
    assert!(!out.join("10/assets/keep.txt").exists());
    assert!(!out.join("20/assets/keep.txt").exists());
    assert!(!out.join("old").exists());
    assert!(!out.join("10/r").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

fn binary_layout(label: &str) -> Vec<u8> {
    fn push_u16(buf: &mut Vec<u8>, value: u16) {
        buf.extend_from_slice(&value.to_le_bytes());
    }
    fn push_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }
    let strings = ["layout", "text", label];
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    for value in strings {
        offsets.push(u32::try_from(data.len()).unwrap());
        data.push(u8::try_from(value.chars().count()).unwrap());
        data.push(u8::try_from(value.len()).unwrap());
        data.extend_from_slice(value.as_bytes());
        data.push(0);
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let strings_start = 28 + u32::try_from(strings.len()).unwrap() * 4;
    let mut pool = Vec::new();
    push_u16(&mut pool, 0x0001);
    push_u16(&mut pool, 28);
    push_u32(
        &mut pool,
        strings_start + u32::try_from(data.len()).unwrap(),
    );
    push_u32(&mut pool, u32::try_from(strings.len()).unwrap());
    push_u32(&mut pool, 0);
    push_u32(&mut pool, 1 << 8);
    push_u32(&mut pool, strings_start);
    push_u32(&mut pool, 0);
    for offset in offsets {
        push_u32(&mut pool, offset);
    }
    pool.extend_from_slice(&data);
    let mut element = Vec::new();
    push_u16(&mut element, 0x0102);
    push_u16(&mut element, 16);
    push_u32(&mut element, 16 + 20 + 20);
    push_u32(&mut element, 1);
    push_u32(&mut element, 0xffff_ffff);
    push_u32(&mut element, 0xffff_ffff);
    push_u32(&mut element, 0);
    push_u16(&mut element, 20);
    push_u16(&mut element, 20);
    push_u16(&mut element, 1);
    push_u16(&mut element, 0);
    push_u16(&mut element, 0);
    push_u16(&mut element, 0);
    push_u32(&mut element, 0xffff_ffff);
    push_u32(&mut element, 1);
    push_u32(&mut element, 2);
    push_u16(&mut element, 8);
    element.push(0);
    element.push(0x03);
    push_u32(&mut element, 2);
    let mut end = Vec::new();
    push_u16(&mut end, 0x0103);
    push_u16(&mut end, 16);
    push_u32(&mut end, 24);
    push_u32(&mut end, 1);
    push_u32(&mut end, 0xffff_ffff);
    push_u32(&mut end, 0xffff_ffff);
    push_u32(&mut end, 0);
    let mut body = pool;
    body.extend(element);
    body.extend(end);
    let mut file = Vec::new();
    push_u16(&mut file, 0x0003);
    push_u16(&mut file, 8);
    push_u32(&mut file, u32::try_from(8 + body.len()).unwrap());
    file.extend(body);
    file
}
