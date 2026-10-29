use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Component, Path};

use crate::archive::{Archive, FileEntry};
use crate::cert::Certificate;
use crate::Result;

/// Where an archive entry sits. The order of the variants is the report order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    Manifest,
    Module,
    ResourceTable,
    Resources,
    Dex,
    Abc,
    Native,
    Assets,
    Res,
    Other,
}

impl Group {
    pub fn label(self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::Module => "module",
            Self::ResourceTable => "resources.arsc",
            Self::Resources => "resources",
            Self::Dex => "dex",
            Self::Abc => "abc",
            Self::Native => "lib",
            Self::Assets => "assets",
            Self::Res => "res",
            Self::Other => "other",
        }
    }

    pub fn of(name: &str) -> Self {
        let file = name.rsplit('/').next().unwrap_or(name);
        if file == "AndroidManifest.xml" || name.ends_with("/AndroidManifest.xml") {
            Self::Manifest
        } else if is_hap_module_file(name) {
            Self::Module
        } else if file == "resources.arsc" {
            Self::ResourceTable
        } else if name.starts_with("resources/") || file == "resources.index" {
            Self::Resources
        } else if file.ends_with(".dex") {
            Self::Dex
        } else if file.ends_with(".abc") {
            Self::Abc
        } else if (name.starts_with("lib/") || name.starts_with("libs/")) && file.ends_with(".so") {
            Self::Native
        } else if name.starts_with("assets/") {
            Self::Assets
        } else if name.starts_with("res/") || name.starts_with("r/") {
            Self::Res
        } else {
            Self::Other
        }
    }
}

/// A path that exists on only one side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileChange {
    pub name: String,
    /// Path inside the archive. `name` may be the restored resource path.
    pub member: String,
    pub size: u64,
}

/// A path whose uncompressed bytes differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentChange {
    pub name: String,
    /// Archive path of the earlier file.
    pub left_member: String,
    /// Archive path of the later file.
    pub right_member: String,
    pub left_size: u64,
    pub right_size: u64,
    pub native: Option<NativeDiff>,
    /// Decoded XML lines that differ. `None` when the entry is not compared as XML.
    pub xml: Option<XmlDiff>,
}

/// One side of a decoded resource XML difference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XmlSide {
    Left,
    Right,
}

/// A short window of the decoded XML difference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlDiff {
    pub lines: Vec<XmlLine>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlLine {
    pub side: XmlSide,
    pub text: String,
}

/// ELF comparison for one shared object whose bytes changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeDiff {
    Elf {
        diff: asc_so::ElfDiff,
        disassembly: Vec<asc_so::DisasmBlock>,
        /// Present when a file's section headers and program headers disagreed.
        link_notes: Vec<String>,
    },
    Unreadable(String),
}

/// Added, removed, and changed files in one group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupDiff {
    pub group: Group,
    pub unchanged: usize,
    pub added: Vec<FileChange>,
    pub removed: Vec<FileChange>,
    pub changed: Vec<ContentChange>,
}

impl GroupDiff {
    pub fn has_changes(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty() || !self.changed.is_empty()
    }
}

/// Signing certificates matched by their SHA-256 fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateDiff {
    pub unchanged: Vec<Certificate>,
    pub added: Vec<Certificate>,
    pub removed: Vec<Certificate>,
}

impl CertificateDiff {
    fn between(left: &[Certificate], right: &[Certificate]) -> Self {
        let mut unchanged = Vec::new();
        let mut removed = Vec::new();
        for cert in left {
            if right.iter().any(|other| other.sha256 == cert.sha256) {
                unchanged.push(cert.clone());
            } else {
                removed.push(cert.clone());
            }
        }
        let added = right
            .iter()
            .filter(|cert| !left.iter().any(|other| other.sha256 == cert.sha256))
            .cloned()
            .collect();
        Self {
            unchanged,
            added,
            removed,
        }
    }

    fn is_empty(&self) -> bool {
        self.unchanged.is_empty() && self.added.is_empty() && self.removed.is_empty()
    }
}

/// File-level difference of two archives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveDiff {
    pub groups: Vec<GroupDiff>,
    /// `None` when this report was limited to a prefix that is not `META-INF`.
    pub certificates: Option<CertificateDiff>,
}

impl ArchiveDiff {
    pub fn between(left: &Archive, right: &Archive) -> Self {
        Self::between_prefix(left, right, "")
    }

    /// Writes changed, added, and removed files under `dir`.
    ///
    /// Each archive is placed in a directory named with its `versionCode`.
    /// XML is written as decoded text. Paths use the restored resource name.
    pub fn export(&self, left: &Archive, right: &Archive, dir: &Path) -> Result<()> {
        let left_code = version_code(left, "earlier")?;
        let right_code = version_code(right, "later")?;
        if left_code == right_code {
            bail!("both archives have versionCode {left_code}");
        }
        let left_symbols = load_resources(left).symbols;
        let right_symbols = load_resources(right).symbols;
        let old = dir.join(&left_code);
        let new = dir.join(&right_code);
        for group in &self.groups {
            for file in &group.removed {
                write_export(left, &file.member, &file.name, &left_symbols, &old)?;
            }
            for file in &group.added {
                write_export(right, &file.member, &file.name, &right_symbols, &new)?;
            }
            for file in &group.changed {
                write_export(left, &file.left_member, &file.name, &left_symbols, &old)?;
                write_export(right, &file.right_member, &file.name, &right_symbols, &new)?;
            }
        }
        Ok(())
    }

    /// Like [`between`](Self::between), but only entries whose path starts with `prefix`.
    pub fn between_prefix(left: &Archive, right: &Archive, prefix: &str) -> Self {
        let left_res = load_resources(left);
        let right_res = load_resources(right);
        let left_map = by_name(left.entries(), prefix, &left_res.paths);
        let right_map = by_name(right.entries(), prefix, &right_res.paths);
        let mut groups: BTreeMap<Group, GroupDiff> = BTreeMap::new();
        for (name, entry) in &left_map {
            let group = ensure(&mut groups, name);
            match right_map.get(name) {
                None => group.removed.push(FileChange {
                    name: name.to_string(),
                    member: entry.name.clone(),
                    size: entry.size,
                }),
                Some(other) if other.crc == entry.crc && other.size == entry.size => {
                    group.unchanged += 1;
                }
                Some(other) => match xml_delta(
                    left,
                    right,
                    entry,
                    other,
                    name,
                    &left_res.symbols,
                    &right_res.symbols,
                ) {
                    Some(XmlDelta::Same) => group.unchanged += 1,
                    Some(XmlDelta::Different(xml)) => group.changed.push(ContentChange {
                        name: name.to_string(),
                        left_member: entry.name.clone(),
                        right_member: other.name.clone(),
                        left_size: entry.size,
                        right_size: other.size,
                        native: None,
                        xml: Some(xml),
                    }),
                    None => group.changed.push(ContentChange {
                        name: name.to_string(),
                        left_member: entry.name.clone(),
                        right_member: other.name.clone(),
                        left_size: entry.size,
                        right_size: other.size,
                        native: native_diff(left, right, name),
                        xml: None,
                    }),
                },
            }
        }
        for (name, entry) in &right_map {
            if left_map.contains_key(name) {
                continue;
            }
            ensure(&mut groups, name).added.push(FileChange {
                name: name.to_string(),
                member: entry.name.clone(),
                size: entry.size,
            });
        }
        for group in groups.values_mut() {
            group
                .added
                .sort_by(|left, right| left.name.cmp(&right.name));
            group
                .removed
                .sort_by(|left, right| left.name.cmp(&right.name));
            group
                .changed
                .sort_by(|left, right| left.name.cmp(&right.name));
        }
        let certificates = wants_certificates(prefix)
            .then(|| CertificateDiff::between(left.certificates(), right.certificates()));
        Self {
            groups: groups.into_values().collect(),
            certificates,
        }
    }

    pub fn added_count(&self) -> usize {
        self.groups.iter().map(|group| group.added.len()).sum()
    }

    pub fn removed_count(&self) -> usize {
        self.groups.iter().map(|group| group.removed.len()).sum()
    }

    pub fn changed_count(&self) -> usize {
        self.groups.iter().map(|group| group.changed.len()).sum()
    }

    pub fn unchanged_count(&self) -> usize {
        self.groups.iter().map(|group| group.unchanged).sum()
    }
}

fn is_hap_module_file(name: &str) -> bool {
    matches!(
        name,
        "module.json" | "config.json" | "pack.info" | "pkgContextInfo.json"
    )
}

fn native_diff(left: &Archive, right: &Archive, name: &str) -> Option<NativeDiff> {
    if Group::of(name) != Group::Native {
        return None;
    }
    let parsed = match (left.read(name), right.read(name)) {
        (Ok(left_bytes), Ok(right_bytes)) => {
            match (
                asc_so::ElfInfo::parse(&left_bytes),
                asc_so::ElfInfo::parse(&right_bytes),
            ) {
                (Ok(left_elf), Ok(right_elf)) => {
                    let diff = left_elf.diff(&right_elf);
                    let disassembly = asc_so::disassemble_changes(
                        &left_bytes,
                        &right_bytes,
                        &left_elf,
                        &right_elf,
                    );
                    let link_notes = link_notes(&left_elf, &right_elf);
                    NativeDiff::Elf {
                        diff,
                        disassembly,
                        link_notes,
                    }
                }
                (Err(err), _) | (_, Err(err)) => NativeDiff::Unreadable(err.to_string()),
            }
        }
        (Err(err), _) | (_, Err(err)) => NativeDiff::Unreadable(err.to_string()),
    };
    Some(parsed)
}

fn link_notes(left: &asc_so::ElfInfo, right: &asc_so::ElfInfo) -> Vec<String> {
    if left.program_headers_preferred || right.program_headers_preferred {
        vec!["link: program headers override sections".to_string()]
    } else {
        Vec::new()
    }
}

fn wants_certificates(prefix: &str) -> bool {
    prefix.is_empty() || "META-INF/".starts_with(prefix) || prefix.starts_with("META-INF/")
}

fn ensure<'a>(groups: &'a mut BTreeMap<Group, GroupDiff>, name: &str) -> &'a mut GroupDiff {
    let kind = Group::of(name);
    groups.entry(kind).or_insert(GroupDiff {
        group: kind,
        unchanged: 0,
        added: Vec::new(),
        removed: Vec::new(),
        changed: Vec::new(),
    })
}

fn version_code(archive: &Archive, side: &str) -> Result<String> {
    if let Some(name) = archive_member(archive, &["AndroidManifest.xml"], &["/AndroidManifest.xml"])
    {
        let text = manifest_text(&archive.read(name)?)?;
        if let Some(code) = quoted_attr(&text, "versionCode") {
            return Ok(code);
        }
    }
    if let Some(name) = archive_member(
        archive,
        &["module.json", "config.json"],
        &["/module.json", "/config.json"],
    ) {
        let text = String::from_utf8_lossy(&archive.read(name)?).into_owned();
        if let Some(code) = json_version_code(&text) {
            return Ok(code);
        }
    }
    bail!("versionCode was not found in the {side} archive");
}

fn archive_member<'a>(archive: &'a Archive, exact: &[&str], suffixes: &[&str]) -> Option<&'a str> {
    let entries = archive.entries();
    for want in exact {
        if let Some(entry) = entries.iter().find(|entry| entry.name == *want) {
            return Some(entry.name.as_str());
        }
    }
    for suffix in suffixes {
        if let Some(entry) = entries.iter().find(|entry| entry.name.ends_with(suffix)) {
            return Some(entry.name.as_str());
        }
    }
    None
}

fn manifest_text(bytes: &[u8]) -> Result<String> {
    let text = String::from_utf8_lossy(bytes);
    if text.trim_start().starts_with('<') {
        return Ok(text.into_owned());
    }
    asc_axml::manifest_xml(bytes).map_err(|err| crate::Error::new(err.to_string()))
}

fn quoted_attr(text: &str, name: &str) -> Option<String> {
    let key = format!("{name}=\"");
    let mut rest = text;
    while let Some(pos) = rest.find(&key) {
        let value = &rest[pos + key.len()..];
        let end = value.find('"')?;
        let value = &value[..end];
        if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Some(value.to_string());
        }
        rest = &rest[pos + key.len()..];
    }
    None
}

fn json_version_code(text: &str) -> Option<String> {
    let key = "\"versionCode\"";
    let mut rest = text;
    while let Some(pos) = rest.find(key) {
        let after = rest[pos + key.len()..].trim_start();
        if let Some(after) = after.strip_prefix(':') {
            let digits: String = after
                .trim_start()
                .bytes()
                .take_while(|byte| byte.is_ascii_digit())
                .map(char::from)
                .collect();
            if !digits.is_empty() {
                return Some(digits);
            }
        }
        rest = &rest[pos + key.len()..];
    }
    None
}

fn write_export(
    archive: &Archive,
    member: &str,
    restored: &str,
    symbols: &BTreeMap<u32, String>,
    side_dir: &Path,
) -> Result<()> {
    let bytes = archive.read(member)?;
    let payload = if Group::of(restored) == Group::Manifest {
        apply_symbols(&manifest_text(&bytes)?, symbols).into_bytes()
    } else if is_xml_name(restored) {
        decoded_xml(&bytes, symbols).map(Vec::from).unwrap_or(bytes)
    } else {
        bytes
    };
    let path = export_path(side_dir, restored)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| crate::Error::Io {
            action: "create",
            path: parent.to_path_buf(),
            source,
        })?;
    }
    fs::write(&path, payload).map_err(|source| crate::Error::Io {
        action: "write",
        path,
        source,
    })
}

fn is_xml_name(name: &str) -> bool {
    name.rsplit('/').next().unwrap_or(name).ends_with(".xml")
}

fn export_path(dir: &Path, name: &str) -> Result<std::path::PathBuf> {
    if name.is_empty() {
        bail!("{name} is not a safe export path");
    }
    let mut out = dir.to_path_buf();
    for component in Path::new(name).components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => bail!("{name} is not a safe export path"),
        }
    }
    Ok(out)
}

fn load_resources(archive: &Archive) -> asc_apk::CompiledResources {
    let Ok(bytes) = archive.read("resources.arsc") else {
        return asc_apk::CompiledResources::default();
    };
    asc_apk::compiled_resources(&bytes).unwrap_or_default()
}

enum XmlDelta {
    Same,
    Different(XmlDiff),
}

fn xml_delta(
    left: &Archive,
    right: &Archive,
    left_entry: &FileEntry,
    right_entry: &FileEntry,
    name: &str,
    left_symbols: &BTreeMap<u32, String>,
    right_symbols: &BTreeMap<u32, String>,
) -> Option<XmlDelta> {
    if Group::of(name) != Group::Res || !name.ends_with(".xml") {
        return None;
    }
    let left_bytes = left.read(&left_entry.name).ok()?;
    let right_bytes = right.read(&right_entry.name).ok()?;
    let left_text = decoded_xml(&left_bytes, left_symbols)?;
    let right_text = decoded_xml(&right_bytes, right_symbols)?;
    if left_text == right_text {
        Some(XmlDelta::Same)
    } else {
        Some(XmlDelta::Different(XmlDiff {
            lines: xml_window(&left_text, &right_text),
        }))
    }
}

fn decoded_xml(bytes: &[u8], symbols: &BTreeMap<u32, String>) -> Option<String> {
    let text = if bytes.len() >= 2 && bytes[0] == 0x03 && bytes[1] == 0x00 {
        asc_axml::xml_text(bytes).ok()?
    } else {
        let text = String::from_utf8_lossy(bytes).into_owned();
        if !text.trim_start().starts_with('<') {
            return None;
        }
        text
    };
    Some(apply_symbols(&text, symbols))
}

fn apply_symbols(text: &str, symbols: &BTreeMap<u32, String>) -> String {
    if symbols.is_empty() {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if let Some(end) = hex_ref_end(bytes, index) {
            if let Ok(id) = u32::from_str_radix(&text[index + 3..end], 16) {
                if let Some(name) = symbols.get(&id) {
                    out.push('@');
                    out.push_str(name);
                    index = end;
                    continue;
                }
            }
        }
        let Some(ch) = text[index..].chars().next() else {
            break;
        };
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

fn hex_ref_end(bytes: &[u8], index: usize) -> Option<usize> {
    if bytes.get(index) != Some(&b'@')
        || bytes.get(index + 1) != Some(&b'0')
        || !matches!(bytes.get(index + 2), Some(b'x' | b'X'))
    {
        return None;
    }
    let mut end = index + 3;
    while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
        end += 1;
    }
    (end - (index + 3) == 8).then_some(end)
}

const XML_LINES: usize = 12;

fn xml_window(left: &str, right: &str) -> Vec<XmlLine> {
    let left: Vec<&str> = left.lines().collect();
    let right: Vec<&str> = right.lines().collect();
    let mut start = 0;
    while start < left.len() && start < right.len() && left[start] == right[start] {
        start += 1;
    }
    let mut end_left = left.len();
    let mut end_right = right.len();
    while end_left > start && end_right > start && left[end_left - 1] == right[end_right - 1] {
        end_left -= 1;
        end_right -= 1;
    }
    let mut lines = Vec::new();
    for line in left.iter().take(end_left).skip(start) {
        if lines.len() >= XML_LINES {
            break;
        }
        lines.push(XmlLine {
            side: XmlSide::Left,
            text: (*line).to_string(),
        });
    }
    for line in right.iter().take(end_right).skip(start) {
        if lines.len() >= XML_LINES {
            break;
        }
        lines.push(XmlLine {
            side: XmlSide::Right,
            text: (*line).to_string(),
        });
    }
    lines
}

fn by_name<'a>(
    entries: &'a [FileEntry],
    prefix: &str,
    paths: &BTreeMap<String, String>,
) -> BTreeMap<String, &'a FileEntry> {
    let mut out = BTreeMap::new();
    for entry in entries {
        let restored = paths
            .get(&entry.name)
            .map(String::as_str)
            .unwrap_or(entry.name.as_str());
        if !prefix.is_empty() && !entry.name.starts_with(prefix) && !restored.starts_with(prefix) {
            continue;
        }
        let key = if out.contains_key(restored) {
            disambiguate(&out, &entry.name)
        } else {
            restored.to_string()
        };
        out.insert(key, entry);
    }
    out
}

fn disambiguate(taken: &BTreeMap<String, &FileEntry>, original: &str) -> String {
    if !taken.contains_key(original) {
        return original.to_string();
    }
    let mut index = 2u32;
    loop {
        let candidate = format!("{original}#{index}");
        if !taken.contains_key(&candidate) {
            return candidate;
        }
        index = index.saturating_add(1);
    }
}

impl fmt::Display for ArchiveDiff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            formatter,
            "changed {}, added {}, removed {}, unchanged {}",
            self.changed_count(),
            self.added_count(),
            self.removed_count(),
            self.unchanged_count()
        )?;
        for group in &self.groups {
            if !group.has_changes() && group.unchanged == 0 {
                continue;
            }
            writeln!(
                formatter,
                "{}: changed {}, added {}, removed {}, unchanged {}",
                group.group.label(),
                group.changed.len(),
                group.added.len(),
                group.removed.len(),
                group.unchanged
            )?;
            for entry in &group.removed {
                writeln!(formatter, "  - {} ({} bytes)", entry.name, entry.size)?;
            }
            for entry in &group.added {
                writeln!(formatter, "  + {} ({} bytes)", entry.name, entry.size)?;
            }
            for entry in &group.changed {
                writeln!(
                    formatter,
                    "  ~ {}  {} -> {} bytes",
                    entry.name, entry.left_size, entry.right_size
                )?;
                if let Some(xml) = &entry.xml {
                    writeln!(formatter, "    xml")?;
                    for line in &xml.lines {
                        let mark = match line.side {
                            XmlSide::Left => '<',
                            XmlSide::Right => '>',
                        };
                        writeln!(formatter, "      {mark} {}", line.text)?;
                    }
                }
                if let Some(native) = &entry.native {
                    write_native(formatter, native)?;
                }
            }
        }
        if let Some(certificates) = &self.certificates {
            write_certificates(formatter, certificates)?;
        }
        Ok(())
    }
}

fn write_native(formatter: &mut fmt::Formatter<'_>, native: &NativeDiff) -> fmt::Result {
    match native {
        NativeDiff::Unreadable(err) => writeln!(formatter, "    elf: {err}"),
        NativeDiff::Elf {
            diff,
            disassembly,
            link_notes,
        } if diff.is_empty() && disassembly.is_empty() && link_notes.is_empty() => {
            writeln!(formatter, "    elf: symbols unchanged")
        }
        NativeDiff::Elf {
            diff,
            disassembly,
            link_notes,
        } => {
            for note in link_notes {
                writeln!(formatter, "    {note}")?;
            }
            if diff.is_empty() && disassembly.is_empty() {
                return writeln!(formatter, "    elf: symbols unchanged");
            }
            for (name, left, right) in &diff.header {
                writeln!(formatter, "    {name}: {left} -> {right}")?;
            }
            for name in &diff.needed_removed {
                writeln!(formatter, "    needed - {name}")?;
            }
            for name in &diff.needed_added {
                writeln!(formatter, "    needed + {name}")?;
            }
            for name in &diff.imports_removed {
                writeln!(formatter, "    import - {name}")?;
            }
            for name in &diff.imports_added {
                writeln!(formatter, "    import + {name}")?;
            }
            for name in &diff.exports_removed {
                writeln!(formatter, "    export - {name}")?;
            }
            for name in &diff.exports_added {
                writeln!(formatter, "    export + {name}")?;
            }
            for block in disassembly {
                writeln!(formatter, "    disasm {}", block.title)?;
                for line in &block.left {
                    writeln!(formatter, "      < {line}")?;
                }
                for line in &block.right {
                    writeln!(formatter, "      > {line}")?;
                }
            }
            Ok(())
        }
    }
}

fn write_certificates(formatter: &mut fmt::Formatter<'_>, diff: &CertificateDiff) -> fmt::Result {
    if diff.is_empty() {
        return writeln!(formatter, "certificate: none");
    }
    writeln!(
        formatter,
        "certificate: added {}, removed {}, unchanged {}",
        diff.added.len(),
        diff.removed.len(),
        diff.unchanged.len()
    )?;
    for cert in &diff.removed {
        writeln!(formatter, "  - {}", cert.sha256)?;
        write_cert_body(formatter, cert)?;
    }
    for cert in &diff.added {
        writeln!(formatter, "  + {}", cert.sha256)?;
        write_cert_body(formatter, cert)?;
    }
    for cert in &diff.unchanged {
        writeln!(formatter, "  = {}", cert.sha256)?;
        write_cert_body(formatter, cert)?;
    }
    Ok(())
}

fn write_cert_body(formatter: &mut fmt::Formatter<'_>, cert: &Certificate) -> fmt::Result {
    writeln!(formatter, "    Subject: {}", cert.subject)?;
    writeln!(formatter, "    Issuer: {}", cert.issuer)?;
    writeln!(formatter, "    Serial: {}", cert.serial)?;
    writeln!(
        formatter,
        "    Valid: {} .. {}",
        cert.not_before, cert.not_after
    )?;
    writeln!(formatter, "    Source: {}", cert.source)
}
