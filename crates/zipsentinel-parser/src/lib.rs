//! Low-level ZIP structural parser.
//!
//! Parses the End Of Central Directory record, the ZIP64 EOCD chain when
//! present, and every central directory file header. All reads are
//! bounds-checked; malformed or truncated input produces
//! [`ZSError::Malformed`] rather than a panic.

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use zipsentinel_core::{ArchiveMetadata, EntryInfo, ResourceLimits, ZSError};

const EOCD_SIG: u32 = 0x0605_4b50;
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
const ZIP64_EOCD_LOCATOR_SIG: u32 = 0x0706_4b50;
const CD_FILE_HEADER_SIG: u32 = 0x0201_4b50;
const EOCD_MIN_LEN: usize = 22;
const EOCD_MAX_SEARCH: usize = 65_536 + EOCD_MIN_LEN;

/// Archive extensions treated as nested-archive indicators.
const NESTED_EXTENSIONS: &[&str] = &[
    ".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".epub", ".whl", ".egg",
];

/// A successfully parsed archive: metadata plus the raw file bytes needed by
/// downstream stages (content sniffing, local header checks).
pub struct ParsedArchive {
    pub path: PathBuf,
    pub metadata: ArchiveMetadata,
    /// Raw archive bytes. Callers should treat this as untrusted input.
    pub bytes: Vec<u8>,
}

/// Locates the End Of Central Directory record by scanning backwards from EOF.
fn find_eocd(bytes: &[u8]) -> Result<usize, ZSError> {
    if bytes.len() < EOCD_MIN_LEN {
        return Err(ZSError::malformed("file too small to contain an EOCD record"));
    }
    let search_start = bytes.len().saturating_sub(EOCD_MAX_SEARCH);
    let mut pos = bytes.len() - EOCD_MIN_LEN;
    loop {
        let sig = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        if sig == EOCD_SIG {
            // Validate: comment length must reach exactly EOF.
            let comment_len = u16::from_le_bytes([bytes[pos + 20], bytes[pos + 21]]) as usize;
            if pos + EOCD_MIN_LEN + comment_len == bytes.len() {
                return Ok(pos);
            }
        }
        if pos == search_start {
            break;
        }
        pos -= 1;
    }
    Err(ZSError::malformed("end of central directory record not found"))
}

#[derive(Debug, Default)]
struct CentralDirectoryInfo {
    entry_count_disk: u64,
    entry_count_total: u64,
    cd_size: u64,
    cd_offset: u64,
    zip64: bool,
}

/// Reads the EOCD and, when ZIP64 markers are present, the ZIP64 EOCD chain.
fn read_central_directory_info(bytes: &[u8], eocd: usize) -> Result<CentralDirectoryInfo, ZSError> {
    let rd16 = |o: usize| -> Result<u16, ZSError> {
        bytes
            .get(o..o + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .ok_or_else(|| ZSError::malformed("truncated EOCD record"))
    };
    let rd32 = |o: usize| -> Result<u32, ZSError> {
        bytes
            .get(o..o + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or_else(|| ZSError::malformed("truncated EOCD record"))
    };

    let mut info = CentralDirectoryInfo {
        entry_count_disk: rd16(eocd + 8)? as u64,
        entry_count_total: rd16(eocd + 10)? as u64,
        cd_size: rd32(eocd + 12)? as u64,
        cd_offset: rd32(eocd + 16)? as u64,
        zip64: false,
    };

    let needs_zip64 = info.entry_count_total == 0xFFFF
        || info.cd_offset == 0xFFFF_FFFF
        || info.cd_size == 0xFFFF_FFFF
        || info.entry_count_disk == 0xFFFF;
    if !needs_zip64 {
        return Ok(info);
    }

    // ZIP64 EOCD locator is the 20 bytes immediately before the EOCD.
    let loc = eocd
        .checked_sub(20)
        .ok_or_else(|| ZSError::malformed("missing ZIP64 EOCD locator"))?;
    let loc_sig = u32::from_le_bytes([bytes[loc], bytes[loc + 1], bytes[loc + 2], bytes[loc + 3]]);
    if loc_sig != ZIP64_EOCD_LOCATOR_SIG {
        return Err(ZSError::malformed("missing ZIP64 EOCD locator"));
    }
    let z64_off = u64::from_le_bytes(
        bytes
            .get(loc + 8..loc + 16)
            .ok_or_else(|| ZSError::malformed("truncated ZIP64 locator"))?
            .try_into()
            .unwrap(),
    ) as usize;
    let sig = u32::from_le_bytes([bytes[z64_off], bytes[z64_off + 1], bytes[z64_off + 2], bytes[z64_off + 3]]);
    if sig != ZIP64_EOCD_SIG {
        return Err(ZSError::malformed("invalid ZIP64 EOCD signature"));
    }
    let rd64 = |o: usize| -> Result<u64, ZSError> {
        bytes
            .get(o..o + 8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            .ok_or_else(|| ZSError::malformed("truncated ZIP64 EOCD record"))
    };
    info.entry_count_disk = rd64(z64_off + 24)?;
    info.entry_count_total = rd64(z64_off + 32)?;
    info.cd_size = rd64(z64_off + 40)?;
    info.cd_offset = rd64(z64_off + 48)?;
    info.zip64 = true;
    Ok(info)
}

/// Parses the extra field of a central directory record, resolving ZIP64
/// placeholders (0xFFFFFFFF / 0xFFFF) for sizes and the local header offset.
fn apply_zip64_extra(
    extra: &[u8],
    uncompressed: &mut u64,
    compressed: &mut u64,
    offset: &mut u64,
) -> Result<(), ZSError> {
    let mut cursor = 0usize;
    while cursor + 4 <= extra.len() {
        let tag = u16::from_le_bytes([extra[cursor], extra[cursor + 1]]);
        let len = u16::from_le_bytes([extra[cursor + 2], extra[cursor + 3]]) as usize;
        let start = cursor + 4;
        let end = start.checked_add(len).ok_or_else(|| ZSError::malformed("extra field overflow"))?;
        if end > extra.len() {
            return Err(ZSError::malformed("truncated extra field"));
        }
        if tag == 0x0001 {
            let mut p = start;
            let take64 = |p: &mut usize| -> Result<u64, ZSError> {
                let b = extra
                    .get(*p..*p + 8)
                    .ok_or_else(|| ZSError::malformed("truncated ZIP64 extra field"))?;
                *p += 8;
                Ok(u64::from_le_bytes(b.try_into().unwrap()))
            };
            if *uncompressed == u64::from(u32::MAX) {
                *uncompressed = take64(&mut p)?;
            }
            if *compressed == u64::from(u32::MAX) {
                *compressed = take64(&mut p)?;
            }
            if *offset == u64::from(u32::MAX) {
                *offset = take64(&mut p)?;
            }
            return Ok(());
        }
        cursor = end;
    }
    Ok(())
}

/// Parses every central directory file header into [`EntryInfo`] values.
fn parse_central_directory(
    bytes: &[u8],
    info: &CentralDirectoryInfo,
    limits: &ResourceLimits,
) -> Result<Vec<EntryInfo>, ZSError> {
    if info.entry_count_total > limits.max_entries.saturating_mul(4).max(1_000_000) {
        return Err(ZSError::LimitExceeded {
            limit: format!("central directory entries <= {}", limits.max_entries.saturating_mul(4)),
            observed: info.entry_count_total.to_string(),
        });
    }
    let cd_offset = usize::try_from(info.cd_offset)
        .map_err(|_| ZSError::malformed("central directory offset overflows usize"))?;
    let cd_end = cd_offset
        .checked_add(usize::try_from(info.cd_size).unwrap_or(usize::MAX))
        .ok_or_else(|| ZSError::malformed("central directory size overflow"))?;
    if cd_end > bytes.len() {
        return Err(ZSError::malformed("central directory extends past end of file"));
    }

    let mut entries = Vec::with_capacity(usize::try_from(info.entry_count_total).unwrap_or(0).min(4096));
    let mut pos = cd_offset;
    let mut seen = 0u64;

    while pos + 46 <= cd_end {
        let sig = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        if sig != CD_FILE_HEADER_SIG {
            break;
        }
        let rd16 = |o: usize| u16::from_le_bytes([bytes[o], bytes[o + 1]]);
        let rd32 = |o: usize| u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);

        let flags = rd16(pos + 8) as u32;
        let method = rd16(pos + 10);
        let crc32 = rd32(pos + 16);
        let mut compressed = u64::from(rd32(pos + 20));
        let mut uncompressed = u64::from(rd32(pos + 24));
        let name_len = rd16(pos + 28) as usize;
        let extra_len = rd16(pos + 30) as usize;
        let comment_len = rd16(pos + 32) as usize;
        let mut local_offset = u64::from(rd32(pos + 42));

        let name_start = pos + 46;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or_else(|| ZSError::malformed("entry name length overflow"))?;
        let extra_start = name_end;
        let extra_end = extra_start
            .checked_add(extra_len)
            .ok_or_else(|| ZSError::malformed("entry extra length overflow"))?;
        let next = extra_end
            .checked_add(comment_len)
            .ok_or_else(|| ZSError::malformed("entry comment length overflow"))?;
        if next > cd_end || name_end > bytes.len() {
            return Err(ZSError::malformed("central directory entry overruns record bounds"));
        }

        apply_zip64_extra(&bytes[extra_start..extra_end], &mut uncompressed, &mut compressed, &mut local_offset)?;

        let raw_name = &bytes[name_start..name_end];
        let name = String::from_utf8_lossy(raw_name).into_owned();

        entries.push(EntryInfo {
            name,
            compression_method: method,
            compressed_size: compressed,
            uncompressed_size: uncompressed,
            crc32,
            encrypted: flags & 0x1 != 0,
            data_descriptor: flags & 0x8 != 0,
            utf8_names: flags & 0x800 != 0,
            local_header_offset: local_offset,
            compression_ratio: None,
            nested_archive: false,
        });

        pos = next;
        seen += 1;
        if seen > limits.max_entries.saturating_mul(4).max(1_000_000) {
            return Err(ZSError::LimitExceeded {
                limit: "central directory entries".to_string(),
                observed: seen.to_string(),
            });
        }
    }
    Ok(entries)
}

/// Returns the offset of an entry's file data by parsing its local header.
fn local_data_offset(bytes: &[u8], local_offset: u64) -> Option<usize> {
    let off = usize::try_from(local_offset).ok()?;
    if off + 30 > bytes.len() {
        return None;
    }
    let sig = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
    if sig != 0x0403_4b50 {
        return None;
    }
    let name_len = u16::from_le_bytes([bytes[off + 26], bytes[off + 27]]) as usize;
    let extra_len = u16::from_le_bytes([bytes[off + 28], bytes[off + 29]]) as usize;
    off.checked_add(30)?.checked_add(name_len)?.checked_add(extra_len)
}

/// Detects well-known archive/container magic at the start of entry data.
fn sniff_nested_magic(bytes: &[u8], data_off: usize) -> bool {
    let magic: &[u8] = match bytes.get(data_off..data_off + 4) {
        Some(m) => m,
        None => return false,
    };
    magic.starts_with(b"PK\x03\x04")
        || magic.starts_with(b"PK\x05\x06")
        || magic.starts_with(b"7z\xbc\xaf")
        || magic.starts_with(&[0x1f, 0x8b])
        || magic.starts_with(b"Rar!")
        || magic.starts_with(b"\xfd7zXZ")
}

/// Parses `path` into an [`ArchiveMetadata`] structure.
///
/// The entire file is read into memory; archives larger than
/// `limits.max_memory_bytes` are rejected to keep memory usage bounded.
pub fn parse_archive(path: &Path, limits: &ResourceLimits) -> Result<ParsedArchive, ZSError> {
    let file_size = fs::metadata(path)?.len();
    if file_size > limits.max_memory_bytes {
        return Err(ZSError::LimitExceeded {
            limit: format!("archive size <= {} bytes", limits.max_memory_bytes),
            observed: file_size.to_string(),
        });
    }
    let mut bytes = Vec::with_capacity(file_size as usize);
    fs::File::open(path)?.read_to_end(&mut bytes)?;
    let bytes_len = bytes.len();

    let eocd = find_eocd(&bytes)?;
    let cd_info = read_central_directory_info(&bytes, eocd)?;
    let mut entries = parse_central_directory(&bytes, &cd_info, limits)?;

    // Fill derived fields and nested-archive indicators.
    for entry in &mut entries {
        entry.compression_ratio = entry.compression_ratio();
        let lower = entry.name.to_lowercase();
        let ext_match = NESTED_EXTENSIONS.iter().any(|ext| lower.ends_with(ext));
        let magic_match = if entry.compression_method == 0 && entry.compressed_size >= 4 {
            local_data_offset(&bytes, entry.local_header_offset)
                .map(|off| sniff_nested_magic(&bytes, off))
                .unwrap_or(false)
        } else {
            false
        };
        entry.nested_archive = ext_match || magic_match;
    }

    let total_uncompressed = entries.iter().try_fold(0u64, |acc, e| acc.checked_add(e.uncompressed_size));
    let total_compressed = entries.iter().try_fold(0u64, |acc, e| acc.checked_add(e.compressed_size));
    let (total_uncompressed, total_compressed) = match (total_uncompressed, total_compressed) {
        (Some(u), Some(c)) => (u, c),
        _ => {
            return Err(ZSError::malformed("entry sizes overflow u64"));
        }
    };

    Ok(ParsedArchive {
        path: path.to_path_buf(),
        metadata: ArchiveMetadata {
            path: path.to_path_buf(),
            file_size: bytes_len as u64,
            entry_count: entries.len() as u64,
            eocd_offset: eocd as u64,
            zip64: cd_info.zip64,
            total_uncompressed,
            total_compressed,
            entries,
        },
        bytes,
    })
}

/// Cheap check whether a file looks like a ZIP archive (EOCD present).
pub fn is_zip_file(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else { return false };
    if meta.len() < EOCD_MIN_LEN as u64 {
        return false;
    }
    let mut f = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let tail_len = (meta.len() as usize).min(EOCD_MAX_SEARCH);
    let mut buf = vec![0u8; tail_len];
    if f.seek(SeekFrom::End(-(tail_len as i64))).is_err() {
        return false;
    }
    if f.read_exact(&mut buf).is_err() {
        return false;
    }
    buf.windows(4).any(|w| w == EOCD_SIG.to_le_bytes())
}
