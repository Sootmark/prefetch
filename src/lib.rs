//! Windows Prefetch files (`.pf`): what ran, how often, when, and which
//! files and volumes it touched.
//!
//! Versions 17 (Windows XP/2003), 23 (Vista/7), 26 (8.1) and 30/31
//! (Windows 10/11), including the compressed form Windows 8 and later
//! write (`MAM`, LZ77+Huffman, [`xpress`]). Written from the public format
//! documentation (libyal's "Windows Prefetch File (PF) format" and
//! Microsoft's MS-XCA).
//!
//! Parsing is total: the header and run times either parse or the file is
//! refused with the reason; a damaged file table or volume table is
//! reported in [`Prefetch::problems`] and the rest is kept.

pub mod xpress;

use core::fmt;

/// This crate's version, for provenance.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const SIGNATURE: &[u8; 4] = b"SCCA";
const HEADER: usize = 84;
/// `MAM\x04`: compressed with LZ77+Huffman.
const MAM: &[u8; 3] = b"MAM";

/// Why a file couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// Byte offset in the (decompressed) file where it went wrong.
    pub offset: usize,
    /// What went wrong.
    pub reason: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at byte {})", self.reason, self.offset)
    }
}

impl std::error::Error for Error {}

fn error(offset: usize, reason: impl Into<String>) -> Error {
    Error {
        offset,
        reason: reason.into(),
    }
}

/// A volume the program's files were on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
    /// Device path, e.g. `\VOLUME{01db8b4b23888202-5ab3c3d2}`.
    pub device_path: String,
    /// Volume serial number.
    pub serial: u32,
    /// When the volume was created (FILETIME).
    pub created: u64,
    /// Directories on it the program touched.
    pub directories: Vec<String>,
}

/// A file the program loaded in its first seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetric {
    /// Its path, e.g. `\VOLUME{…}\WINDOWS\SYSTEM32\NTDLL.DLL`.
    pub path: String,
    /// Its NTFS file reference (MFT entry and sequence), when recorded
    /// (version 23 and later).
    pub file_reference: Option<u64>,
}

/// A parsed prefetch file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefetch {
    /// Format version: 17, 23, 26, 30 or 31.
    pub version: u32,
    /// Whether the file was compressed (`MAM`).
    pub compressed: bool,
    /// The executable's name, as recorded (at most 29 characters).
    pub executable: String,
    /// The prefetch hash (of the executable's path and, for some hosts,
    /// its command line).
    pub hash: u32,
    /// How many times it ran.
    pub run_count: u32,
    /// Its last run times, most recent first (FILETIME): one before
    /// version 26, up to eight since; unused slots dropped.
    pub last_runs: Vec<u64>,
    /// Files loaded.
    pub files: Vec<FileMetric>,
    /// Volumes, with the directories touched.
    pub volumes: Vec<Volume>,
    /// Sections that couldn't be read, and why; the rest is kept.
    pub problems: Vec<String>,
}

/// Bounds-checked little-endian reads.
struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn slice(&self, at: usize, len: usize) -> Result<&[u8], Error> {
        at.checked_add(len)
            .and_then(|end| self.0.get(at..end))
            .ok_or_else(|| error(at, format!("{len} bytes past the end of the file")))
    }

    fn u32(&self, at: usize) -> Result<u32, Error> {
        let b = self.slice(at, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&self, at: usize) -> Result<u64, Error> {
        let b = self.slice(at, 8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn offset(&self, at: usize) -> Result<usize, Error> {
        Ok(self.u32(at)? as usize)
    }

    /// UTF-16LE text of `chars` characters (a NUL ends it early).
    fn utf16(&self, at: usize, chars: usize) -> Result<String, Error> {
        let bytes = self.slice(
            at,
            chars
                .checked_mul(2)
                .ok_or_else(|| error(at, "string too long"))?,
        )?;
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        Ok(String::from_utf16_lossy(&units))
    }
}

/// Where a version keeps what's read here.
struct Layout {
    last_runs: usize,
    last_run_slots: usize,
    run_count: usize,
    metric_size: usize,
    volume_size: usize,
}

fn layout(version: u32, metrics_offset: usize) -> Option<Layout> {
    Some(match version {
        17 => Layout {
            last_runs: 120,
            last_run_slots: 1,
            run_count: 144,
            metric_size: 20,
            volume_size: 40,
        },
        23 => Layout {
            last_runs: 128,
            last_run_slots: 1,
            run_count: 152,
            metric_size: 32,
            volume_size: 104,
        },
        26 => Layout {
            last_runs: 128,
            last_run_slots: 8,
            run_count: 208,
            metric_size: 32,
            volume_size: 104,
        },
        // Two layouts of the file information, told apart by where the
        // metrics table follows it (0x128 or 0x130), which moves the run
        // count (checked against PECmd on both).
        30 | 31 => Layout {
            last_runs: 128,
            last_run_slots: 8,
            run_count: if metrics_offset == 0x128 { 200 } else { 208 },
            metric_size: 32,
            volume_size: 96,
        },
        _ => return None,
    })
}

/// Parse a prefetch file, compressed or not.
///
/// # Errors
/// When it isn't a prefetch file, is of an unknown version, or its header
/// or compressed data is damaged.
pub fn parse(file: &[u8]) -> Result<Prefetch, Error> {
    if file.starts_with(MAM) {
        let data = decompressed(file)?;
        let mut prefetch = parse_scca(&data)?;
        prefetch.compressed = true;
        return Ok(prefetch);
    }
    parse_scca(file)
}

/// The SCCA data inside a `MAM` file.
fn decompressed(file: &[u8]) -> Result<Vec<u8>, Error> {
    let bytes = Bytes(file);
    let size = bytes.offset(4)?;
    let data_at = match file.get(3) {
        Some(0x04) => 8,
        // The checksummed form: a CRC-32 before the data.
        Some(0x84) => 12,
        other => {
            return Err(error(
                3,
                format!(
                    "unknown MAM compression {:#04x}",
                    other.copied().unwrap_or(0)
                ),
            ));
        }
    };
    // Prefetch files are small: a larger claim is damage, not a file.
    if size > 64 << 20 {
        return Err(error(4, format!("implausible decompressed size {size}")));
    }
    xpress::decompress(&file[data_at.min(file.len())..], size)
        .map_err(|e| error(data_at, format!("compressed data: {e}")))
}

fn parse_scca(data: &[u8]) -> Result<Prefetch, Error> {
    let bytes = Bytes(data);
    if bytes.slice(4, 4)? != SIGNATURE {
        return Err(error(4, "not a prefetch file (no SCCA signature)"));
    }
    let version = bytes.u32(0)?;
    let metrics_offset = bytes.offset(HEADER)?;
    let layout = layout(version, metrics_offset)
        .ok_or_else(|| error(0, format!("unknown prefetch version {version}")))?;
    let mut last_runs = Vec::new();
    for slot in 0..layout.last_run_slots {
        let time = bytes.u64(layout.last_runs + 8 * slot)?;
        if time != 0 {
            last_runs.push(time);
        }
    }
    let mut prefetch = Prefetch {
        version,
        compressed: false,
        executable: bytes.utf16(16, 30)?,
        hash: bytes.u32(76)?,
        run_count: bytes.u32(layout.run_count)?,
        last_runs,
        files: Vec::new(),
        volumes: Vec::new(),
        problems: Vec::new(),
    };
    match files(&bytes, &layout) {
        Ok(files) => prefetch.files = files,
        Err(e) => prefetch.problems.push(format!("file metrics: {e}")),
    }
    match volumes(&bytes, &layout) {
        Ok(volumes) => prefetch.volumes = volumes,
        Err(e) => prefetch.problems.push(format!("volumes: {e}")),
    }
    Ok(prefetch)
}

fn files(bytes: &Bytes<'_>, layout: &Layout) -> Result<Vec<FileMetric>, Error> {
    let (metrics, count) = (bytes.offset(HEADER)?, bytes.offset(HEADER + 4)?);
    let strings = bytes.offset(HEADER + 16)?;
    let mut files = Vec::with_capacity(count.min(4096));
    for i in 0..count {
        let entry = metrics + i * layout.metric_size;
        let (name_at, name_chars, reference) = if layout.metric_size == 20 {
            (bytes.offset(entry + 8)?, bytes.offset(entry + 12)?, None)
        } else {
            (
                bytes.offset(entry + 12)?,
                bytes.offset(entry + 16)?,
                Some(bytes.u64(entry + 24)?),
            )
        };
        files.push(FileMetric {
            path: bytes.utf16(strings + name_at, name_chars)?,
            file_reference: reference.filter(|&r| r != 0),
        });
    }
    Ok(files)
}

fn volumes(bytes: &Bytes<'_>, layout: &Layout) -> Result<Vec<Volume>, Error> {
    let (table, count) = (bytes.offset(HEADER + 24)?, bytes.offset(HEADER + 28)?);
    let mut volumes = Vec::with_capacity(count.min(64));
    for i in 0..count {
        let entry = table + i * layout.volume_size;
        let path_at = table + bytes.offset(entry)?;
        let path_chars = bytes.offset(entry + 4)?;
        let directories_at = table + bytes.offset(entry + 28)?;
        let directory_count = bytes.offset(entry + 32)?;
        let mut directories = Vec::with_capacity(directory_count.min(4096));
        let mut at = directories_at;
        for _ in 0..directory_count {
            let chars = usize::from(u16::from_le_bytes(
                bytes.slice(at, 2)?.try_into().unwrap_or([0, 0]),
            ));
            directories.push(bytes.utf16(at + 2, chars)?);
            // The characters and their terminating NUL.
            at += 2 + 2 * (chars + 1);
        }
        volumes.push(Volume {
            device_path: bytes.utf16(path_at, path_chars)?,
            serial: bytes.u32(entry + 16)?,
            created: bytes.u64(entry + 8)?,
            directories,
        });
    }
    Ok(volumes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_what_isnt_prefetch() {
        assert!(parse(b"").is_err());
        assert!(parse(&[0; 200]).unwrap_err().reason.contains("SCCA"));
        let mut unknown = vec![0_u8; 300];
        unknown[0] = 99;
        unknown[4..8].copy_from_slice(SIGNATURE);
        assert!(parse(&unknown).unwrap_err().reason.contains("version 99"));
        assert!(parse(b"MAM\x05\x10\0\0\0")
            .unwrap_err()
            .reason
            .contains("compression"));
    }

    #[test]
    fn survives_damaged_tables() {
        // A version 30 header with tables pointing far past the end.
        let mut data = vec![0_u8; 300];
        data[0] = 30;
        data[4..8].copy_from_slice(SIGNATURE);
        data[HEADER..HEADER + 4].copy_from_slice(&0x0130_u32.to_le_bytes());
        data[HEADER + 4..HEADER + 8].copy_from_slice(&5_u32.to_le_bytes());
        data[HEADER + 24..HEADER + 28].copy_from_slice(&u32::MAX.to_le_bytes());
        data[HEADER + 28..HEADER + 32].copy_from_slice(&1_u32.to_le_bytes());
        let prefetch = parse(&data).unwrap();
        assert_eq!(prefetch.problems.len(), 2, "{:?}", prefetch.problems);
    }
}
