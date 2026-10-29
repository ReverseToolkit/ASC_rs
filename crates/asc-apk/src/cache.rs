//! Lazy disk cache of inflated DEX entries.
//!
//! The first query pays to inflate an entry and stores the bytes. The next
//! query on the same archive maps them back. Nothing is written ahead of a query.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use memmap2::Mmap;

const STEM_MAX: usize = 40;
const HASH_HEX_LEN: usize = 16;
const CACHEDIR_TAG: &str = "CACHEDIR.TAG";
const CACHEDIR_TAG_CONTENT: &str = "Signature: 8a477f597d28d172789f06886806bc55\n\
# This file is a cache directory tag created by asc.\n\
# For information about cache directory tags, see: https://bford.info/cachedir/\n";

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("cache io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is not an asc cache directory (no {CACHEDIR_TAG}); refusing to touch it")]
    NotACacheDir { path: PathBuf },
}

fn io_at(path: &Path, source: std::io::Error) -> CacheError {
    CacheError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Identity of one archive: file name, size, mtime, and central directory.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApkKey(String);

impl ApkKey {
    pub fn new(path: &Path, len: u64, mtime_nanos: u128, central_directory: &[u8]) -> Self {
        let mut hash = fnv64(central_directory);
        hash ^= len.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        hash ^= (mtime_nanos as u64).rotate_left(17);
        let stem = path
            .file_stem()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let stem: String = stem
            .chars()
            .filter(|ch| is_key_char(*ch))
            .take(STEM_MAX)
            .collect();
        Self(format!("{stem}-{hash:0HASH_HEX_LEN$x}"))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_key_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.'
}

fn fnv64(bytes: &[u8]) -> u64 {
    const PRIME: u64 = 0x0100_0000_01b3;
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut chunks = bytes.chunks_exact(8);
    for chunk in &mut chunks {
        let mut lane = [0u8; 8];
        lane.copy_from_slice(chunk);
        hash ^= u64::from_le_bytes(lane);
        hash = hash.wrapping_mul(PRIME);
    }
    for byte in chunks.remainder() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn is_cache_dir_name(name: &str) -> bool {
    let Some((stem, hash)) = name.rsplit_once('-') else {
        return false;
    };
    hash.len() == HASH_HEX_LEN
        && hash
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        && stem.len() <= STEM_MAX
        && stem.chars().all(is_key_char)
}

pub struct DiskCache {
    dir: PathBuf,
    cap_bytes: u64,
}

impl DiskCache {
    pub const DEFAULT_CAP: u64 = 4 << 30;

    /// `$ASC_CACHE_DIR`, else `$XDG_CACHE_HOME/asc`, else `~/.cache/asc`.
    pub fn default_dir() -> Option<PathBuf> {
        if let Some(dir) = std::env::var_os("ASC_CACHE_DIR") {
            return Some(PathBuf::from(dir));
        }
        if let Some(dir) = std::env::var_os("XDG_CACHE_HOME") {
            return Some(PathBuf::from(dir).join("asc"));
        }
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache").join("asc"))
    }

    pub fn open(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            cap_bytes: Self::DEFAULT_CAP,
        }
    }

    pub fn check(&self) -> Result<(), CacheError> {
        if self.is_cache_dir() {
            Ok(())
        } else {
            Err(CacheError::NotACacheDir {
                path: self.dir.clone(),
            })
        }
    }

    pub fn get(&self, key: &ApkKey, entry_name: &str, expected_len: u64) -> Option<Vec<u8>> {
        let path = self.entry_path(key, entry_name);
        let file = File::open(&path).ok()?;
        let len = file.metadata().ok()?.len();
        if expected_len != 0 && len != expected_len {
            return None;
        }
        if let Some(parent) = path.parent() {
            let _ = fs::write(parent.join(".lru"), b"1");
        }
        // SAFETY: read-only map of a file this cache wrote atomically. A later
        // replace changes the directory entry, not this inode.
        let map = unsafe { Mmap::map(&file) }.ok()?;
        Some(map.to_vec())
    }

    pub fn put(&self, key: &ApkKey, entry_name: &str, bytes: &[u8]) -> Result<(), CacheError> {
        self.check()?;
        let path = self.entry_path(key, entry_name);
        let parent = path
            .parent()
            .ok_or_else(|| CacheError::NotACacheDir {
                path: self.dir.clone(),
            })?;
        fs::create_dir_all(parent).map_err(|err| io_at(parent, err))?;
        let _ = self.ensure_tag();
        let tmp = parent.join(format!(
            ".{}.{}.tmp",
            path.file_name().unwrap_or_default().to_string_lossy(),
            std::process::id()
        ));
        {
            let mut file = File::create(&tmp).map_err(|err| io_at(&tmp, err))?;
            file.write_all(bytes).map_err(|err| io_at(&tmp, err))?;
        }
        fs::rename(&tmp, &path).map_err(|err| io_at(&path, err))?;
        Ok(())
    }

    pub fn evict(&self) {
        if !self.is_cache_dir() {
            return;
        }
        let mut dirs = self.apk_dirs();
        let mut total: u64 = dirs.iter().map(|item| item.2).sum();
        if total <= self.cap_bytes {
            return;
        }
        dirs.sort_by_key(|item| item.0);
        for (_mtime, path, size) in dirs {
            if total <= self.cap_bytes {
                break;
            }
            if fs::remove_dir_all(&path).is_ok() {
                total = total.saturating_sub(size);
            }
        }
    }

    fn entry_path(&self, key: &ApkKey, entry_name: &str) -> PathBuf {
        let safe: String = entry_name
            .chars()
            .map(|ch| if is_key_char(ch) { ch } else { '_' })
            .take(STEM_MAX)
            .collect();
        let hash = fnv64(entry_name.as_bytes());
        // The version prefix excludes legacy entries whose names could collide.
        self.dir
            .join(key.as_str())
            .join(format!("v2-{safe}-{hash:0HASH_HEX_LEN$x}"))
    }

    fn ensure_tag(&self) -> Result<(), CacheError> {
        if self.dir.join(CACHEDIR_TAG).is_file() {
            return Ok(());
        }
        let tag = self.dir.join(CACHEDIR_TAG);
        match fs::OpenOptions::new().write(true).create_new(true).open(&tag) {
            Ok(mut file) => file
                .write_all(CACHEDIR_TAG_CONTENT.as_bytes())
                .map_err(|err| io_at(&tag, err)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(err) => Err(io_at(&tag, err)),
        }
    }

    fn is_cache_dir(&self) -> bool {
        if self.dir.join(CACHEDIR_TAG).is_file() {
            return true;
        }
        match fs::read_dir(&self.dir) {
            Ok(entries) => entries.flatten().all(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                match entry.file_type() {
                    Ok(kind) if kind.is_dir() => is_cache_dir_name(&name),
                    Ok(kind) if kind.is_file() => name == ".DS_Store",
                    _ => false,
                }
            }),
            Err(err) => err.kind() == std::io::ErrorKind::NotFound,
        }
    }

    fn apk_dirs(&self) -> Vec<(SystemTime, PathBuf, u64)> {
        let mut out = Vec::new();
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return out;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() || !is_cache_dir_name(&entry.file_name().to_string_lossy()) {
                continue;
            }
            let mtime = entry
                .metadata()
                .and_then(|meta| meta.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            let mut size = 0u64;
            if let Ok(files) = fs::read_dir(&path) {
                for file in files.flatten() {
                    if let Ok(meta) = file.metadata() {
                        size += meta.len();
                    }
                }
            }
            out.push((mtime, path, size));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_entries_are_not_reused() {
        let root = std::env::temp_dir().join(format!("asc-cache-legacy-{}", std::process::id()));
        let cache = DiskCache::open(&root);
        let key = ApkKey::new(Path::new("app.apk"), 3, 1, b"cd");
        let legacy_dir = root.join(key.as_str());
        fs::create_dir_all(&legacy_dir).unwrap();
        fs::write(legacy_dir.join("classes.dex"), b"bad").unwrap();

        assert_eq!(cache.get(&key, "classes.dex", 3), None);
        cache.put(&key, "classes.dex", b"dex").unwrap();
        assert_eq!(cache.get(&key, "classes.dex", 3), Some(b"dex".to_vec()));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn put_then_get_roundtrips_and_a_foreign_directory_is_refused() {
        let root = std::env::temp_dir().join(format!("asc-cache-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let cache = DiskCache::open(&root);
        let key = ApkKey::new(Path::new("app.apk"), 3, 1, b"cd");
        cache.put(&key, "classes.dex", b"dex-bytes").unwrap();
        assert_eq!(
            cache.get(&key, "classes.dex", 9),
            Some(b"dex-bytes".to_vec())
        );
        let foreign = root.join("foreign");
        fs::create_dir_all(&foreign).unwrap();
        fs::write(foreign.join("notes.txt"), b"keep").unwrap();
        let bad = DiskCache::open(&foreign);
        assert!(bad.put(&key, "classes.dex", b"no").is_err());
        assert!(foreign.join("notes.txt").is_file());
        let _ = fs::remove_dir_all(&root);
    }
}
