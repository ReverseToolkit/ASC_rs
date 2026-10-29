use std::fs::File;
use std::io::Read;
use std::path::Path;

use flate2::read::DeflateDecoder;
use memmap2::Mmap;

use crate::cert::{self, Certificate};
use crate::{Error, Result};

/// One file in a ZIP central directory.
///
/// `crc` is the CRC-32 of the uncompressed bytes. Directory entries are omitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    pub name: String,
    pub crc: u32,
    pub size: u64,
}

/// The file list of one archive, keyed by entry path.
#[derive(Clone, Debug)]
pub struct Archive {
    path: std::path::PathBuf,
    items: Vec<Stored>,
    entries: Vec<FileEntry>,
    certificates: Vec<Certificate>,
}

impl Archive {
    /// Reads the central directory of `path`. The file payloads are not inflated.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).map_err(|source| Error::Io {
            action: "open",
            path: path.to_path_buf(),
            source,
        })?;
        // SAFETY: the map is read-only and dropped before this function returns.
        // The file is not written while the map is alive.
        let map = unsafe { Mmap::map(&file) }.map_err(|source| Error::Io {
            action: "map",
            path: path.to_path_buf(),
            source,
        })?;
        let (items, mut certificates) = read_entries(&map)?;
        certificates.extend(cert::hap_certificates(&map));
        certificates.sort_by(|left, right| left.sha256.cmp(&right.sha256));
        certificates.dedup_by(|right, left| right.sha256 == left.sha256);
        let entries = items.iter().map(|item| item.entry.clone()).collect();
        Ok(Self {
            path: path.to_path_buf(),
            items,
            entries,
            certificates,
        })
    }

    /// Inflates one archive member. Used when a shared object's CRC changed.
    pub fn read(&self, name: &str) -> Result<Vec<u8>> {
        let item = self
            .items
            .iter()
            .find(|item| item.entry.name == name)
            .ok_or_else(|| Error::new(format!("{name} is not in the archive")))?;
        let file = File::open(&self.path).map_err(|source| Error::Io {
            action: "open",
            path: self.path.clone(),
            source,
        })?;
        // SAFETY: the map is read-only and dropped before this function returns.
        let map = unsafe { Mmap::map(&file) }.map_err(|source| Error::Io {
            action: "map",
            path: self.path.clone(),
            source,
        })?;
        let limit = item.entry.size.min(512 * 1024 * 1024);
        inflate_entry(&map, item, limit)
    }

    pub fn entries(&self) -> &[FileEntry] {
        &self.entries
    }

    pub fn certificates(&self) -> &[Certificate] {
        &self.certificates
    }
}

fn is_meta_inf(name: &str) -> bool {
    name == "META-INF" || name.starts_with("META-INF/")
}

#[derive(Clone, Debug)]
struct Stored {
    entry: FileEntry,
    method: u16,
    compressed_size: u64,
    local_header_offset: u64,
}

fn read_entries(apk: &[u8]) -> Result<(Vec<Stored>, Vec<Certificate>)> {
    let (start, end) = cd_bounds(apk)?;
    let mut stored = Vec::new();
    let mut ptr = start;
    while ptr + 46 <= end {
        let (entry, next) = read_record(apk, ptr, end)?;
        if next <= ptr {
            bail!("central directory record at {ptr:#x} does not advance");
        }
        if let Some(entry) = entry {
            if !entry.entry.name.ends_with('/') {
                stored.push(entry);
            }
        }
        ptr = next;
    }
    let mut certificates = Vec::new();
    let mut items = Vec::new();
    for item in stored {
        if is_meta_inf(&item.entry.name) {
            if cert::is_signature_block(&item.entry.name) {
                let bytes = inflate_entry(apk, &item, 2 * 1024 * 1024)?;
                certificates.extend(cert::certificates_in(&item.entry.name, &bytes));
            }
            continue;
        }
        items.push(item);
    }
    items.sort_by(|left, right| left.entry.name.cmp(&right.entry.name));
    items.dedup_by(|right, left| right.entry.name == left.entry.name);
    certificates.sort_by(|left, right| left.sha256.cmp(&right.sha256));
    certificates.dedup_by(|right, left| right.sha256 == left.sha256);
    Ok((items, certificates))
}

fn inflate_entry(apk: &[u8], item: &Stored, limit: u64) -> Result<Vec<u8>> {
    if item.entry.size > limit {
        bail!("{} is larger than {limit} bytes", item.entry.name);
    }
    let off = usize::try_from(item.local_header_offset)
        .map_err(|_| Error::new(format!("zip offset for {} is too large", item.entry.name)))?;
    let header_end = off
        .checked_add(30)
        .ok_or_else(|| Error::new(format!("zip offset for {} is too large", item.entry.name)))?;
    let header = apk
        .get(off..header_end)
        .ok_or_else(|| Error::new(format!("truncated local header for {}", item.entry.name)))?;
    if &header[..4] != b"PK\x03\x04" {
        bail!("bad local header signature for {}", item.entry.name);
    }
    let name_len = usize::from(u16_at(header, 26)?);
    let extra_len = usize::from(u16_at(header, 28)?);
    let data_off = header_end
        .checked_add(name_len + extra_len)
        .ok_or_else(|| Error::new(format!("truncated zip entry {}", item.entry.name)))?;
    let comp_len = usize::try_from(item.compressed_size).map_err(|_| {
        Error::new(format!(
            "compressed size for {} is too large",
            item.entry.name
        ))
    })?;
    let data_end = data_off
        .checked_add(comp_len)
        .ok_or_else(|| Error::new(format!("truncated zip entry {}", item.entry.name)))?;
    let compressed = apk
        .get(data_off..data_end)
        .ok_or_else(|| Error::new(format!("truncated zip entry {}", item.entry.name)))?;
    let expected = usize::try_from(item.entry.size)
        .map_err(|_| Error::new(format!("size for {} is too large", item.entry.name)))?;
    let data = match item.method {
        0 => {
            if compressed.len() != expected {
                bail!(
                    "size mismatch for {}: expect {expected}, got {}",
                    item.entry.name,
                    compressed.len()
                );
            }
            compressed.to_vec()
        }
        8 => {
            let mut out = Vec::new();
            DeflateDecoder::new(compressed)
                .take(item.entry.size + 1)
                .read_to_end(&mut out)
                .map_err(|source| Error::Io {
                    action: "inflate",
                    path: std::path::PathBuf::from(&item.entry.name),
                    source,
                })?;
            if out.len() > expected {
                bail!(
                    "zip entry {} inflates past {expected} bytes",
                    item.entry.name
                );
            }
            out
        }
        other => bail!(
            "unsupported compression method {other} for {}",
            item.entry.name
        ),
    };
    if data.len() != expected {
        bail!(
            "size mismatch for {}: expect {expected}, got {}",
            item.entry.name,
            data.len()
        );
    }
    Ok(data)
}

fn cd_bounds(apk: &[u8]) -> Result<(usize, usize)> {
    let eocd = find_eocd(apk).ok_or(Error::NoEocd)?;
    let cd_size_32 = u32_at(apk, eocd + 12)?;
    let cd_off_32 = u32_at(apk, eocd + 16)?;
    let (cd_off, cd_size) = if cd_size_32 == u32::MAX || cd_off_32 == u32::MAX {
        zip64_cd_bounds(apk, eocd)?
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
    if end > apk.len() {
        bail!("central directory exceeds file");
    }
    Ok((start, end))
}

fn find_eocd(apk: &[u8]) -> Option<usize> {
    if apk.len() < 22 {
        return None;
    }
    let search_start = apk.len().saturating_sub(65536 + 22);
    let tail = &apk[search_start..];
    let mut fallback = None;
    for rel in (0..tail.len().saturating_sub(3)).rev() {
        if &tail[rel..rel + 4] != b"PK\x05\x06" {
            continue;
        }
        let at = search_start + rel;
        if at + 22 > apk.len() {
            continue;
        }
        let comment_len = u16::from_le_bytes([apk[at + 20], apk[at + 21]]) as usize;
        let end = at + 22 + comment_len;
        if end == apk.len() {
            return Some(at);
        }
        if end < apk.len() && fallback.is_none() {
            fallback = Some(at);
        }
    }
    fallback
}

fn zip64_cd_bounds(apk: &[u8], eocd: usize) -> Result<(u64, u64)> {
    if eocd < 20 || apk.get(eocd - 20..eocd - 16) != Some(b"PK\x06\x07") {
        bail!("ZIP64 locator not found");
    }
    let eocd64 = u64_at(apk, eocd - 12)?;
    let at = usize::try_from(eocd64).map_err(|_| Error::new("ZIP64 EOCD offset is too large"))?;
    let end = at
        .checked_add(56)
        .ok_or_else(|| Error::new("ZIP64 EOCD offset is too large"))?;
    if end > apk.len() || apk.get(at..at + 4) != Some(b"PK\x06\x06") {
        bail!("ZIP64 EOCD not found");
    }
    Ok((u64_at(apk, at + 48)?, u64_at(apk, at + 40)?))
}

fn read_record(apk: &[u8], header: usize, cd_end: usize) -> Result<(Option<Stored>, usize)> {
    if header + 46 > cd_end {
        bail!("central directory record at {header:#x} runs past the directory");
    }
    if apk.get(header..header + 4) != Some(b"PK\x01\x02") {
        bail!("central directory record at {header:#x} has a bad signature");
    }
    let method = u16_at(apk, header + 10)?;
    let crc = u32_at(apk, header + 16)?;
    let mut comp_size = u64::from(u32_at(apk, header + 20)?);
    let mut size = u64::from(u32_at(apk, header + 24)?);
    let name_len = usize::from(u16_at(apk, header + 28)?);
    let extra_len = usize::from(u16_at(apk, header + 30)?);
    let comment_len = usize::from(u16_at(apk, header + 32)?);
    let mut disk = u32::from(u16_at(apk, header + 34)?);
    let mut local_header_offset = u64::from(u32_at(apk, header + 42)?);
    let name_start = header + 46;
    let extra_start = name_start + name_len;
    let extra_end = extra_start + extra_len;
    let next = extra_end + comment_len;
    if next > cd_end || next > apk.len() {
        bail!("central directory record at {header:#x} runs past the archive");
    }
    resolve_zip64(
        &apk[extra_start..extra_end],
        &mut size,
        &mut comp_size,
        &mut local_header_offset,
        &mut disk,
    )?;
    if disk != 0 {
        return Ok((None, next));
    }
    let name = String::from_utf8_lossy(&apk[name_start..name_start + name_len]).into_owned();
    Ok((
        Some(Stored {
            entry: FileEntry { name, crc, size },
            method,
            compressed_size: comp_size,
            local_header_offset,
        }),
        next,
    ))
}

fn resolve_zip64(
    extra: &[u8],
    size: &mut u64,
    comp: &mut u64,
    local_off: &mut u64,
    disk: &mut u32,
) -> Result<()> {
    let need_size = *size == u64::from(u32::MAX);
    let need_comp = *comp == u64::from(u32::MAX);
    let need_off = *local_off == u64::from(u32::MAX);
    let need_disk = *disk == u32::from(u16::MAX);
    if !need_size && !need_comp && !need_off && !need_disk {
        return Ok(());
    }
    let data = zip64_extra(extra)?;
    let mut pos = 0usize;
    if need_size {
        *size = zip64_u64(data, &mut pos)?;
    }
    if need_comp {
        *comp = zip64_u64(data, &mut pos)?;
    }
    if need_off {
        *local_off = zip64_u64(data, &mut pos)?;
    }
    if need_disk {
        if pos + 4 > data.len() {
            bail!("truncated ZIP64 extra field");
        }
        *disk = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    }
    Ok(())
}

fn zip64_extra(extra: &[u8]) -> Result<&[u8]> {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[pos], extra[pos + 1]]);
        let size = usize::from(u16::from_le_bytes([extra[pos + 2], extra[pos + 3]]));
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

fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| Error::new("truncated ZIP header"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| Error::new("truncated ZIP header"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn u64_at(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or_else(|| Error::new("truncated ZIP header"))?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(buf))
}
