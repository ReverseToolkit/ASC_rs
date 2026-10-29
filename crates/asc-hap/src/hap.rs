//! HAP commands. Each `.abc` member is inflated at the moment a query reads it.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use flate2::read::DeflateDecoder;
use memmap2::Mmap;

use crate::{Error, Result};
use asc_abc::{
    class_names, class_text_optional, find_members, find_strings_resolved, find_types, MemberKind,
};
use asc_abc_dec::{Decompiler, OutputMode};

/// Ceiling on one inflated ZIP entry. A real `.abc` stays far below it, and a
/// crafted entry can never make the reader allocate without bound.
const MAX_INFLATED_BYTES: u64 = 1 << 30;

#[derive(Clone, Debug)]
pub struct Options {
    pub threads: usize,
    pub debug: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DumpStats {
    pub classes: usize,
    pub errors: usize,
}

#[derive(Clone, Copy)]
pub enum Query<'a> {
    String(&'a str),
    Type(&'a str),
    Method {
        name: Option<&'a str>,
        class_name: Option<&'a str>,
    },
    Field {
        name: Option<&'a str>,
        class_name: Option<&'a str>,
    },
}

pub(crate) struct ZipEntry {
    pub(crate) name: String,
    crc: u32,
    method: u16,
    pub(crate) comp_size: u64,
    pub(crate) uncomp_size: u64,
    local_header_off: u64,
    index: u32,
}

pub fn is_hap(path: &Path) -> Result<bool> {
    let (_file, map) = open_hap(path)?;
    // A directory this reader cannot walk is not a HAP it can use; the APK path
    // reports the damage.
    let Ok(entries) = zip_entries(&map) else {
        return Ok(false);
    };
    Ok(entries.iter().any(|entry| is_hap_marker(&entry.name)))
}

pub fn list_classes(path: &Path, prefix: Option<&str>, options: &Options) -> Result<Vec<String>> {
    check_threads(options.threads)?;
    let (_file, map) = open_hap(path)?;
    let entries = abc_entries(&map)?;
    let groups = run_indexed(entries.len(), options.threads, |index| {
        let bytes = inflate(&map, &entries[index])?;
        class_names(&bytes, prefix).map_err(Error::from)
    })?;
    let mut names = Vec::new();
    for group in groups {
        names.extend(group);
    }
    Ok(names)
}

pub fn get_class_source(path: &Path, class_name: &str, options: &Options) -> Result<String> {
    get_class_output_impl(path, class_name, options, None)
}

/// Read one ABC record as JavaScript source or Ark assembly.
pub fn get_class_output(
    path: &Path,
    class_name: &str,
    options: &Options,
    mode: OutputMode,
) -> Result<String> {
    get_class_output_impl(path, class_name, options, Some(mode))
}

fn abc_output(data: &[u8], class_name: &str, mode: Option<OutputMode>) -> Result<Option<String>> {
    match mode {
        Some(mode) => Ok(Decompiler::new(data)?.render_class_optional(class_name, mode)?),
        None => Ok(class_text_optional(data, class_name)?),
    }
}

fn get_class_output_impl(
    path: &Path,
    class_name: &str,
    options: &Options,
    mode: Option<OutputMode>,
) -> Result<String> {
    check_threads(options.threads)?;
    let (_file, map) = open_hap(path)?;
    let entries = zip_entries(&map)?;
    for entry in ranked_code(&entries) {
        let bytes = inflate(&map, entry)?;
        if let Some(text) = abc_output(&bytes, class_name, mode)? {
            if options.debug {
                eprintln!("[HAP] hit {}", entry.name);
            }
            if mode != Some(OutputMode::Assembly) && text.as_bytes().contains(&b'$') {
                let resources = crate::resources::HapResources::index(&map, &entries);
                return Ok(resources.annotate(&text).into_owned());
            }
            return Ok(text);
        }
    }
    bail!("Class {class_name} not found in HAP.");
}

pub fn module_json(path: &Path) -> Result<String> {
    let files = package_files(path)?;
    let mut out = String::new();
    for (name, text) in files {
        out.push_str("===== ");
        out.push_str(&name);
        out.push_str(" =====\n");
        out.push_str(&text);
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }
    Ok(out)
}

fn package_files(path: &Path) -> Result<Vec<(String, String)>> {
    let (_file, map) = open_hap(path)?;
    let entries = zip_entries(&map)?;
    let resources = crate::resources::HapResources::index(&map, &entries);
    package_texts(&map, &entries, &resources)
}

fn package_texts(
    map: &Mmap,
    entries: &[ZipEntry],
    resources: &crate::resources::HapResources,
) -> Result<Vec<(String, String)>> {
    let mut files = Vec::new();
    if let Some(entry) = choose_manifest(entries) {
        files.push((
            entry.name.clone(),
            resources.annotate(&read_text(map, entry)?).into_owned(),
        ));
    }
    if let Some(entry) = choose_pack_info(entries) {
        files.push((
            entry.name.clone(),
            resources.annotate(&read_text(map, entry)?).into_owned(),
        ));
    }
    if files.is_empty() {
        bail!("module.json and pack.info not found in HAP");
    }
    Ok(files)
}

fn read_text(map: &Mmap, entry: &ZipEntry) -> Result<String> {
    let bytes = inflate(map, entry)?;
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if text.starts_with('\u{feff}') {
        text.remove(0);
    }
    if !text.ends_with('\n') {
        text.push('\n');
    }
    Ok(text)
}

pub fn find_refs(path: &Path, query: Query<'_>, options: &Options) -> Result<Vec<String>> {
    check_threads(options.threads)?;
    let (_file, map) = open_hap(path)?;
    let stored = zip_entries(&map)?;
    let groups = match query {
        Query::String(pattern) => find_string_refs(&map, &stored, pattern, options)?,
        Query::Type(pattern) => scan_code(&map, stored, options, |name, bytes| {
            find_types(bytes, name, pattern).map_err(Error::from)
        })?,
        Query::Method { name, class_name } => scan_code(&map, stored, options, |entry, bytes| {
            find_members(
                bytes,
                entry,
                MemberKind::Method,
                name.unwrap_or(".*"),
                class_name,
            )
            .map_err(Error::from)
        })?,
        Query::Field { name, class_name } => scan_code(&map, stored, options, |entry, bytes| {
            find_members(
                bytes,
                entry,
                MemberKind::Field,
                name.unwrap_or(".*"),
                class_name,
            )
            .map_err(Error::from)
        })?,
    };
    let mut lines = Vec::new();
    for group in groups {
        lines.extend(group);
    }
    Ok(lines)
}

fn find_string_refs(
    map: &Mmap,
    stored: &[ZipEntry],
    pattern: &str,
    options: &Options,
) -> Result<Vec<Vec<String>>> {
    let code = ranked_code(stored);
    let (resources, inflated) = std::thread::scope(|scope| {
        let load = scope.spawn(|| crate::resources::HapResources::index(map, stored));
        let inflated = run_indexed(code.len(), options.threads, |index| {
            let entry = code[index];
            inflate(map, entry).map(|bytes| (entry.name.clone(), bytes))
        });
        (load.join().expect("resource index panicked"), inflated)
    });
    let inflated = inflated?;
    run_indexed(inflated.len(), options.threads, |index| {
        let (name, bytes) = &inflated[index];
        match find_strings_resolved(bytes, name, pattern, &|raw| resolve_literal(&resources, raw)) {
            Ok(lines) => Ok(lines),
            // One unsearchable member must not hide the hits from the rest.
            Err(asc_abc::Error::Unsupported(message)) => {
                eprintln!("warning: {name}: {message}");
                Ok(Vec::new())
            }
            Err(err) => Err(Error::from(err)),
        }
    })
}

fn resolve_literal(resources: &crate::resources::HapResources, bytes: &[u8]) -> Option<String> {
    resources.resolve_literal(bytes)
}

/// Loads Harmony resources for a bare ABC file.
///
/// `path` is a `resources/` directory, a directory that contains `resources/`,
/// or a HAP/ZIP that stores that tree. A bare ABC does not consult this unless
/// the caller asks.
pub fn load_resources(path: &Path) -> Result<crate::resources::HapResources> {
    if path.is_dir() {
        return crate::resources::HapResources::from_dir(path);
    }
    let (_file, map) = open_hap(path)?;
    let entries = match zip_entries(&map) {
        Ok(entries) => entries,
        Err(Error::NoEocd) => {
            bail!(
                "{} is not a Harmony resource directory or HAP",
                path.display()
            );
        }
        Err(err) => return Err(err),
    };
    let resources = crate::resources::HapResources::index(&map, &entries);
    if resources.is_empty() {
        bail!("{} contains no Harmony resources", path.display());
    }
    Ok(resources)
}

/// Writes one bare ABC file. Resource tokens stay as written unless `resources`
/// has entries.
pub fn dump_abc(
    data: &[u8],
    out_dir: &Path,
    resources: &crate::resources::HapResources,
) -> Result<DumpStats> {
    dump_abc_impl(data, out_dir, resources, None)
}

pub fn dump_abc_with_mode(
    data: &[u8],
    out_dir: &Path,
    resources: &crate::resources::HapResources,
    mode: OutputMode,
) -> Result<DumpStats> {
    dump_abc_impl(data, out_dir, resources, Some(mode))
}

fn dump_abc_impl(
    data: &[u8],
    out_dir: &Path,
    resources: &crate::resources::HapResources,
    mode: Option<OutputMode>,
) -> Result<DumpStats> {
    fs::create_dir_all(out_dir)?;
    let names = class_names(data, None)?;
    let mut classes = 0usize;
    let mut errors = 0usize;
    for name in names {
        let text = match abc_output(data, &name, mode) {
            Ok(Some(text)) if mode == Some(OutputMode::Assembly) => text,
            Ok(Some(text)) => resources.annotate(&text).into_owned(),
            Ok(None) => {
                errors += 1;
                eprintln!("warning: {name} is indexed but has no body");
                continue;
            }
            Err(err) => {
                errors += 1;
                eprintln!("warning: {name}: {err}");
                continue;
            }
        };
        let dest = class_output_path_with_extension(
            out_dir,
            &name,
            mode.map(OutputMode::extension).unwrap_or("ets"),
        );
        if let Some(parent) = dest.parent() {
            if let Err(err) = fs::create_dir_all(parent) {
                errors += 1;
                eprintln!("warning: {name}: {err}");
                continue;
            }
        }
        match fs::write(&dest, text) {
            Ok(()) => classes += 1,
            Err(err) => {
                errors += 1;
                eprintln!("warning: {}: {err}", dest.display());
            }
        }
    }
    Ok(DumpStats { classes, errors })
}

fn scan_code<F>(
    map: &Mmap,
    stored: Vec<ZipEntry>,
    options: &Options,
    work: F,
) -> Result<Vec<Vec<String>>>
where
    F: Fn(&str, &[u8]) -> Result<Vec<String>> + Sync,
{
    let entries = code_entries(stored);
    run_indexed(entries.len(), options.threads, |index| {
        let entry = &entries[index];
        let bytes = inflate(map, entry)?;
        work(&entry.name, &bytes)
    })
}

pub fn dump_hap(path: &Path, out_dir: &Path, options: &Options) -> Result<DumpStats> {
    dump_hap_impl(path, out_dir, options, None)
}

pub fn dump_hap_with_mode(
    path: &Path,
    out_dir: &Path,
    options: &Options,
    mode: OutputMode,
) -> Result<DumpStats> {
    dump_hap_impl(path, out_dir, options, Some(mode))
}

fn dump_hap_impl(
    path: &Path,
    out_dir: &Path,
    options: &Options,
    mode: Option<OutputMode>,
) -> Result<DumpStats> {
    check_threads(options.threads)?;
    fs::create_dir_all(out_dir)?;
    let (_file, map) = open_hap(path)?;
    let stored = zip_entries(&map)?;
    let resources = crate::resources::HapResources::index(&map, &stored);
    let mut classes = 0usize;
    let mut errors = 0usize;
    // One unreadable member must not cost the whole dump; every failure is
    // reported and counted so the summary reflects what was left out.
    match package_texts(&map, &stored, &resources) {
        Ok(files) => {
            for (name, text) in files {
                let file_name = Path::new(&name)
                    .file_name()
                    .unwrap_or(std::ffi::OsStr::new("module.json"));
                if let Err(err) = fs::write(out_dir.join(file_name), text) {
                    errors += 1;
                    eprintln!("warning: {name}: {err}");
                }
            }
        }
        Err(err) => {
            errors += 1;
            eprintln!("warning: {err}");
        }
    }
    for entry in code_entries(stored) {
        let label = entry.name.clone();
        let bytes = match inflate(&map, &entry) {
            Ok(bytes) => bytes,
            Err(err) => {
                errors += 1;
                eprintln!("warning: {label}: {err}");
                continue;
            }
        };
        let names = match class_names(&bytes, None) {
            Ok(names) => names,
            Err(err) => {
                errors += 1;
                eprintln!("warning: {label}: {err}");
                continue;
            }
        };
        for name in names {
            let text = match abc_output(&bytes, &name, mode) {
                Ok(Some(text)) => text,
                // The name came from this file, so not finding it again means
                // the index and the class body disagree.
                Ok(None) => {
                    errors += 1;
                    eprintln!("warning: {label}: {name} is indexed but has no body");
                    continue;
                }
                Err(err) => {
                    errors += 1;
                    eprintln!("warning: {label}: {name}: {err}");
                    continue;
                }
            };
            let dest = class_output_path_with_extension(
                out_dir,
                &name,
                mode.map(OutputMode::extension).unwrap_or("ets"),
            );
            if let Some(parent) = dest.parent() {
                if let Err(err) = fs::create_dir_all(parent) {
                    errors += 1;
                    eprintln!("warning: {name}: {err}");
                    continue;
                }
            }
            let text = if mode == Some(OutputMode::Assembly) {
                text
            } else {
                resources.annotate(&text).into_owned()
            };
            match fs::write(&dest, text) {
                Ok(()) => classes += 1,
                Err(err) => {
                    errors += 1;
                    eprintln!("warning: {}: {err}", dest.display());
                }
            }
        }
        if options.debug {
            eprintln!("[HAP] dumped {label}");
        }
    }
    Ok(DumpStats { classes, errors })
}

fn abc_entries(data: &[u8]) -> Result<Vec<ZipEntry>> {
    Ok(code_entries(zip_entries(data)?))
}

fn code_entries(entries: Vec<ZipEntry>) -> Vec<ZipEntry> {
    let mut entries: Vec<ZipEntry> = entries
        .into_iter()
        .filter(|entry| is_code_abc(&entry.name))
        .collect();
    entries.sort_by(code_cmp);
    entries
}

fn ranked_code(entries: &[ZipEntry]) -> Vec<&ZipEntry> {
    let mut ranked: Vec<&ZipEntry> = entries
        .iter()
        .filter(|entry| is_code_abc(&entry.name))
        .collect();
    ranked.sort_by(|left, right| code_cmp(left, right));
    ranked
}

fn code_cmp(left: &ZipEntry, right: &ZipEntry) -> std::cmp::Ordering {
    abc_rank(&left.name)
        .cmp(&abc_rank(&right.name))
        .then(left.index.cmp(&right.index))
}

fn abc_rank(name: &str) -> u8 {
    if name == "ets/modules.abc" {
        0
    } else if name.starts_with("ets/") || name.contains("/ets/") {
        1
    } else if name.starts_with("js/") || name.contains("/js/") || name.starts_with("assets/js/") {
        2
    } else {
        3
    }
}

fn is_code_abc(name: &str) -> bool {
    name.ends_with(".abc") && !name.ends_with('/')
}

fn is_hap_marker(name: &str) -> bool {
    // `config.json` is only a manifest fallback after the file is already a
    // HAP. Android apps ship the same name under assets/, so it cannot mark
    // the container by itself.
    is_code_abc(name) || is_hap_identity(name)
}

fn is_hap_identity(name: &str) -> bool {
    matches!(name, "module.json" | "pack.info")
        || name.ends_with("/module.json")
        || name.ends_with("/pack.info")
}

fn choose_manifest(entries: &[ZipEntry]) -> Option<&ZipEntry> {
    entries
        .iter()
        .filter(|entry| manifest_rank(&entry.name).is_some())
        .min_by_key(|entry| (manifest_rank(&entry.name).unwrap_or(u8::MAX), entry.index))
}

fn choose_pack_info(entries: &[ZipEntry]) -> Option<&ZipEntry> {
    entries
        .iter()
        .filter(|entry| pack_info_rank(&entry.name).is_some())
        .min_by_key(|entry| (pack_info_rank(&entry.name).unwrap_or(u8::MAX), entry.index))
}

fn manifest_rank(name: &str) -> Option<u8> {
    match name {
        "module.json" => Some(0),
        "config.json" => Some(1),
        other if other.ends_with("/module.json") => Some(2),
        other if other.ends_with("/config.json") => Some(3),
        _ => None,
    }
}

fn pack_info_rank(name: &str) -> Option<u8> {
    match name {
        "pack.info" => Some(0),
        other if other.ends_with("/pack.info") => Some(1),
        _ => None,
    }
}

/// Maps a descriptor to an output file.
///
/// Sanitizing alone is not injective: two descriptors can differ only in a
/// character that has to be replaced. A changed part carries a short hash of
/// the original so they stay distinct files.
#[cfg(test)]
fn class_output_path(out_dir: &Path, descriptor: &str) -> PathBuf {
    class_output_path_with_extension(out_dir, descriptor, "ets")
}

fn class_output_path_with_extension(out_dir: &Path, descriptor: &str, extension: &str) -> PathBuf {
    let trimmed = descriptor
        .strip_prefix('L')
        .unwrap_or(descriptor)
        .strip_suffix(';')
        .unwrap_or(descriptor);
    let mut path = out_dir.to_path_buf();
    if trimmed.is_empty() {
        path.push(format!("class.{extension}"));
        return path;
    }
    for part in trimmed.split('/') {
        path.push(sanitize_part(part));
    }
    path.set_extension(extension);
    path
}

fn sanitize_part(part: &str) -> String {
    let safe: String = part
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if safe == part && !safe.is_empty() {
        return safe;
    }
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in part.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{safe}~{hash:08x}")
}

fn check_threads(threads: usize) -> Result<()> {
    if threads == 0 {
        bail!("threads must be >= 1");
    }
    Ok(())
}

fn open_hap(path: &Path) -> Result<(File, Mmap)> {
    let file = File::open(path).map_err(|source| Error::IoPath {
        action: "open",
        path: path.display().to_string(),
        source,
    })?;
    // SAFETY: `file` is returned with the map, so the descriptor outlives it.
    let map = unsafe { Mmap::map(&file) }.map_err(|source| Error::IoPath {
        action: "map",
        path: path.display().to_string(),
        source,
    })?;
    Ok((file, map))
}

fn run_indexed<T, F>(len: usize, threads: usize, work: F) -> Result<Vec<T>>
where
    T: Send,
    F: Fn(usize) -> Result<T> + Sync,
{
    if len == 0 {
        return Ok(Vec::new());
    }
    let workers = threads.min(len).max(1);
    let results: Mutex<Vec<Option<T>>> = Mutex::new((0..len).map(|_| None).collect());
    let error: Mutex<Option<Error>> = Mutex::new(None);
    let cursor = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                if error.lock().expect("mutex poisoned").is_some() {
                    break;
                }
                let index = cursor.fetch_add(1, Ordering::Relaxed);
                if index >= len {
                    break;
                }
                match work(index) {
                    Ok(value) => results.lock().expect("mutex poisoned")[index] = Some(value),
                    Err(err) => {
                        let mut slot = error.lock().expect("mutex poisoned");
                        if slot.is_none() {
                            *slot = Some(err);
                        }
                        break;
                    }
                }
            });
        }
    });
    if let Some(err) = error.into_inner().expect("mutex poisoned") {
        return Err(err);
    }
    results
        .into_inner()
        .expect("mutex poisoned")
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            value.ok_or_else(|| Error::new(format!("missing worker result {index}")))
        })
        .collect()
}

struct ZipBytes<'a> {
    name: &'a str,
    method: u16,
    crc: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    header_offset: u64,
}

pub(crate) fn inflate(hap: &[u8], entry: &ZipEntry) -> Result<Vec<u8>> {
    inflate_bytes(
        hap,
        ZipBytes {
            name: &entry.name,
            method: entry.method,
            crc: entry.crc,
            compressed_size: entry.comp_size,
            uncompressed_size: entry.uncomp_size,
            header_offset: entry.local_header_off,
        },
    )
}

fn inflate_bytes(hap: &[u8], entry: ZipBytes<'_>) -> Result<Vec<u8>> {
    let ZipBytes {
        name,
        method,
        crc,
        compressed_size,
        uncompressed_size,
        header_offset,
    } = entry;
    let off = usize::try_from(header_offset)
        .map_err(|_| Error::new(format!("zip offset for {name} exceeds this platform")))?;
    // A crafted ZIP64 offset must not wrap the addition before it is checked.
    let sig_end = off
        .checked_add(4)
        .ok_or_else(|| Error::new(format!("zip offset for {name} exceeds this platform")))?;
    if hap.get(off..sig_end) != Some(b"PK\x03\x04") {
        bail!("bad local header signature");
    }
    let name_len = u16_at(hap, off + 26)? as usize;
    let extra_len = u16_at(hap, off + 28)? as usize;
    let data_off = off + 30 + name_len + extra_len;
    let comp_len = usize::try_from(compressed_size)
        .map_err(|_| Error::new(format!("compressed size for {name} exceeds this platform")))?;
    let data_end = data_off
        .checked_add(comp_len)
        .ok_or_else(|| Error::new(format!("truncated zip entry {name}")))?;
    let comp = hap
        .get(data_off..data_end)
        .ok_or_else(|| Error::new(format!("truncated zip entry {name}")))?;
    let data = match method {
        0 => comp.to_vec(),
        8 => {
            // Deflate never expands more than 1032 times its input, so a larger
            // declared size is a lie and the ratio bound is used instead. The
            // hard ceiling keeps a crafted entry from allocating without bound.
            let ratio_bound = (comp.len() as u64).saturating_mul(1032);
            let declared = if uncompressed_size == 0 {
                ratio_bound
            } else {
                uncompressed_size
            };
            let limit = declared.min(MAX_INFLATED_BYTES);
            let mut out = Vec::new();
            DeflateDecoder::new(comp)
                .take(limit + 1)
                .read_to_end(&mut out)?;
            if out.len() as u64 > limit {
                bail!("zip entry {name} inflates past {limit} bytes");
            }
            out
        }
        other => bail!("unsupported compression method: {other}"),
    };
    if uncompressed_size != 0 && data.len() as u64 != uncompressed_size {
        bail!(
            "size mismatch: expect {uncompressed_size}, got {}",
            data.len()
        );
    }
    if crc != 0 {
        let actual = crc32fast::hash(&data);
        if actual != crc {
            eprintln!("warning: crc mismatch for {name}: stored {crc:08x}, computed {actual:08x}");
        }
    }
    Ok(data)
}

fn zip_entries(data: &[u8]) -> Result<Vec<ZipEntry>> {
    let (start, end) = cd_bounds(data)?;
    let mut entries = Vec::new();
    let mut ptr = start;
    let mut index = 0u32;
    while ptr + 46 <= end {
        let (maybe, next) = read_cd_record(data, ptr, end)?;
        if let Some(mut entry) = maybe {
            entry.index = index;
            index += 1;
            entries.push(entry);
        }
        if next <= ptr {
            bail!("central directory record at {ptr:#x} does not advance");
        }
        ptr = next;
    }
    Ok(entries)
}

fn cd_bounds(data: &[u8]) -> Result<(usize, usize)> {
    let eocd = find_eocd(data).ok_or(Error::NoEocd)?;
    let cd_size_32 = u32_at(data, eocd + 12)?;
    let cd_off_32 = u32_at(data, eocd + 16)?;
    let (cd_off, cd_size) = if cd_size_32 == u32::MAX || cd_off_32 == u32::MAX {
        zip64_cd_bounds(data, eocd)?
    } else {
        (u64::from(cd_off_32), u64::from(cd_size_32))
    };
    let start =
        usize::try_from(cd_off).map_err(|_| Error::new("central directory offset is too large"))?;
    let size =
        usize::try_from(cd_size).map_err(|_| Error::new("central directory size is too large"))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| Error::new("central directory exceeds file"))?;
    if end > data.len() {
        bail!("central directory exceeds file");
    }
    Ok((start, end))
}

fn zip64_cd_bounds(data: &[u8], eocd: usize) -> Result<(u64, u64)> {
    if eocd < 20 || data.get(eocd - 20..eocd - 16) != Some(b"PK\x06\x07") {
        bail!("ZIP64 locator not found");
    }
    let loc = eocd - 20;
    let eocd64 = u64_at(data, loc + 8)?;
    let at = usize::try_from(eocd64).map_err(|_| Error::new("ZIP64 EOCD offset is too large"))?;
    // Bound the record before any relative read, so a wild offset cannot wrap.
    let end = at
        .checked_add(56)
        .ok_or_else(|| Error::new("ZIP64 EOCD offset is too large"))?;
    if end > data.len() || data.get(at..at + 4) != Some(b"PK\x06\x06") {
        bail!("ZIP64 EOCD not found");
    }
    Ok((u64_at(data, at + 48)?, u64_at(data, at + 40)?))
}

/// Reads one central directory record.
///
/// A record that cannot be trusted is an error rather than a stop condition:
/// stopping quietly would drop every entry after it, which reads as "the
/// archive has no such file" instead of "the directory is damaged".
fn read_cd_record(
    data: &[u8],
    header: usize,
    cd_end: usize,
) -> Result<(Option<ZipEntry>, usize)> {
    if header + 46 > cd_end {
        bail!("central directory record at {header:#x} runs past the directory");
    }
    if data.get(header..header + 4) != Some(b"PK\x01\x02") {
        bail!("central directory record at {header:#x} has a bad signature");
    }
    let method = u16_at(data, header + 10)?;
    let crc = u32_at(data, header + 16)?;
    let comp_size = u64::from(u32_at(data, header + 20)?);
    let uncomp_size = u64::from(u32_at(data, header + 24)?);
    let name_len = u16_at(data, header + 28)? as usize;
    let extra_len = u16_at(data, header + 30)? as usize;
    let comment_len = u16_at(data, header + 32)? as usize;
    let disk = u16_at(data, header + 34)?;
    let local_off = u64::from(u32_at(data, header + 42)?);
    let name_start = header + 46;
    let extra_start = name_start + name_len;
    let extra_end = extra_start + extra_len;
    let next = extra_end + comment_len;
    if next > cd_end || next > data.len() {
        bail!("central directory record at {header:#x} runs past the archive");
    }
    let (uncomp_size, comp_size, local_off, disk) = zip64_resolve(
        &data[extra_start..extra_end],
        uncomp_size,
        comp_size,
        local_off,
        disk,
    )?;
    if disk != 0 {
        // Multi disk archives are not supported; keep walking past the entry.
        return Ok((None, next));
    }
    Ok((
        Some(ZipEntry {
            name: String::from_utf8_lossy(&data[name_start..name_start + name_len]).into_owned(),
            crc,
            method,
            comp_size,
            uncomp_size,
            local_header_off: local_off,
            index: 0,
        }),
        next,
    ))
}

fn zip64_resolve(
    extra: &[u8],
    mut uncomp: u64,
    mut comp: u64,
    mut local_off: u64,
    disk: u16,
) -> Result<(u64, u64, u64, u32)> {
    let need_uncomp = uncomp == u64::from(u32::MAX);
    let need_comp = comp == u64::from(u32::MAX);
    let need_off = local_off == u64::from(u32::MAX);
    let need_disk = disk == u16::MAX;
    if !need_uncomp && !need_comp && !need_off && !need_disk {
        return Ok((uncomp, comp, local_off, u32::from(disk)));
    }
    let data = zip64_extra(extra)?;
    let mut pos = 0usize;
    if need_uncomp {
        uncomp = zip64_u64(data, &mut pos)?;
    }
    if need_comp {
        comp = zip64_u64(data, &mut pos)?;
    }
    if need_off {
        local_off = zip64_u64(data, &mut pos)?;
    }
    let resolved_disk = if need_disk {
        if pos + 4 > data.len() {
            bail!("truncated ZIP64 extra field");
        }
        u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
    } else {
        u32::from(disk)
    };
    Ok((uncomp, comp, local_off, resolved_disk))
}

fn zip64_extra(extra: &[u8]) -> Result<&[u8]> {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[pos], extra[pos + 1]]);
        let size = u16::from_le_bytes([extra[pos + 2], extra[pos + 3]]) as usize;
        let start = pos + 4;
        let end = start
            .checked_add(size)
            .ok_or_else(|| Error::new("truncated ZIP64 extra field"))?;
        if end > extra.len() {
            bail!("truncated ZIP64 extra field");
        }
        if id == 0x0001 {
            return Ok(&extra[start..end]);
        }
        pos = end;
    }
    bail!("ZIP64 extra field is missing");
}

fn zip64_u64(data: &[u8], pos: &mut usize) -> Result<u64> {
    if *pos + 8 > data.len() {
        bail!("truncated ZIP64 extra field");
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[*pos..*pos + 8]);
    *pos += 8;
    Ok(u64::from_le_bytes(buf))
}

/// Finds the end of central directory record. The archive comment may hold any
/// bytes, including this signature, so a candidate only counts when its
/// declared comment length reaches the end of the file.
fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < 22 {
        return None;
    }
    let search_start = data.len().saturating_sub(65536 + 22);
    let tail = &data[search_start..];
    let mut fallback = None;
    for rel in (0..tail.len().saturating_sub(3)).rev() {
        if &tail[rel..rel + 4] != b"PK\x05\x06" {
            continue;
        }
        let at = search_start + rel;
        if at + 22 > data.len() {
            continue;
        }
        let comment_len = u16::from_le_bytes([data[at + 20], data[at + 21]]) as usize;
        let end = at + 22 + comment_len;
        if end == data.len() {
            return Some(at);
        }
        if end < data.len() && fallback.is_none() {
            fallback = Some(at);
        }
    }
    fallback
}

fn u16_at(data: &[u8], off: usize) -> Result<u16> {
    let bytes = data
        .get(off..off + 2)
        .ok_or_else(|| Error::new(format!("truncated read at {off:#x}")))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], off: usize) -> Result<u32> {
    let bytes = data
        .get(off..off + 4)
        .ok_or_else(|| Error::new(format!("truncated read at {off:#x}")))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn u64_at(data: &[u8], off: usize) -> Result<u64> {
    let bytes = data
        .get(off..off + 8)
        .ok_or_else(|| Error::new(format!("truncated read at {off:#x}")))?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_wild_zip64_local_offset_is_an_error_not_an_overflow() {
        use super::{inflate_bytes, ZipBytes};
        let data = vec![0u8; 64];
        let entry = ZipBytes {
            name: "ets/modules.abc",
            method: 0,
            crc: 0,
            compressed_size: 0,
            uncompressed_size: 0,
            header_offset: u64::MAX,
        };
        let err = inflate_bytes(&data, entry).unwrap_err();
        assert!(err.to_string().contains("exceeds this platform"), "{err}");
    }

    #[test]
    fn a_wild_zip64_eocd_offset_is_an_error_not_an_overflow() {
        use super::zip64_cd_bounds;
        let mut data = vec![0u8; 42];
        data[0..4].copy_from_slice(b"PK\x06\x07");
        data[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        data[20..24].copy_from_slice(b"PK\x05\x06");
        let err = zip64_cd_bounds(&data, 20).unwrap_err();
        assert!(err.to_string().contains("ZIP64 EOCD offset"), "{err}");
    }

    /// An end of central directory record with the given archive comment.
    fn eocd_with_comment(comment: &[u8]) -> Vec<u8> {
        let mut archive = Vec::new();
        archive.extend_from_slice(b"PK\x05\x06");
        archive.extend_from_slice(&[0u8; 8]); // disk, entries fields
        archive.extend_from_slice(&0u32.to_le_bytes()); // central directory size
        archive.extend_from_slice(&0u32.to_le_bytes()); // central directory offset
        archive.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        archive.extend_from_slice(comment);
        archive
    }

    #[test]
    fn a_comment_holding_the_eocd_signature_does_not_shadow_the_record() {
        use super::find_eocd;
        let comment = b"see PK\x05\x06 inside";
        let archive = eocd_with_comment(comment);
        assert_eq!(find_eocd(&archive), Some(0), "comment={comment:?}");
    }

    #[test]
    fn a_damaged_central_directory_record_is_an_error() {
        use super::{cd_bounds, zip_entries};
        let mut archive = vec![0u8; 46];
        archive[0..4].copy_from_slice(b"XXXX");
        archive.extend_from_slice(b"PK\x05\x06");
        archive.extend_from_slice(&[0u8; 8]);
        archive.extend_from_slice(&46u32.to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(cd_bounds(&archive).unwrap(), (0, 46));
        let Err(err) = zip_entries(&archive) else {
            panic!("a damaged record must be reported");
        };
        assert!(err.to_string().contains("bad signature"), "{err}");
    }

    #[test]
    fn a_lying_uncompressed_size_bounds_the_inflation() {
        use std::io::Write;

        use super::{inflate_bytes, ZipBytes};
        let payload = vec![0u8; 1 << 20];
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&payload).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut archive = vec![0u8; 30];
        archive[0..4].copy_from_slice(b"PK\x03\x04");
        archive.extend_from_slice(&compressed);
        let entry = ZipBytes {
            name: "ets/modules.abc",
            method: 8,
            crc: 0,
            compressed_size: compressed.len() as u64,
            uncompressed_size: 16,
            header_offset: 0,
        };
        let err = inflate_bytes(&archive, entry).unwrap_err();
        assert!(err.to_string().contains("inflates past"), "{err}");
    }

    #[test]
    fn distinct_descriptors_never_share_an_output_path() {
        use super::class_output_path;
        use std::path::Path;
        let left = class_output_path(Path::new("out"), "La.b;");
        let right = class_output_path(Path::new("out"), "La_b;");
        assert_ne!(left, right, "{left:?} {right:?}");
        assert_eq!(
            class_output_path(Path::new("out"), "Ldemo/App;"),
            Path::new("out/demo/App.ets")
        );
    }
}
