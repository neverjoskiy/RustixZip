//! Format definitions, magic-header detection, and operation options.

use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Every archive and disk-image format supported by RustixZip (native + plugin-backed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArchiveFormat {
    // Read + Write Native Rust Formats
    SevenZip,
    Zip,
    Tar,
    TarGz,
    TarZst,
    TarXz,
    TarLz4,
    TarBz2,
    Gz,
    Zst,
    Xz,
    Lz4,
    Bz2,

    // Read + Test Formats (Plugin-backed & Specialized Containers)
    Rar,
    Iso,
    Cab,
    Wim,
    Dmg,
    Deb,
    Rpm,
    Msi,
    Cpio,
    Arj,
    Lzh,
    Chm,
}

impl ArchiveFormat {
    pub const ALL: &'static [ArchiveFormat] = &[
        Self::SevenZip,
        Self::Zip,
        Self::Tar,
        Self::TarGz,
        Self::TarZst,
        Self::TarXz,
        Self::TarLz4,
        Self::TarBz2,
        Self::Gz,
        Self::Zst,
        Self::Xz,
        Self::Lz4,
        Self::Bz2,
        Self::Rar,
        Self::Iso,
        Self::Cab,
        Self::Wim,
        Self::Dmg,
        Self::Deb,
        Self::Rpm,
        Self::Msi,
        Self::Cpio,
        Self::Arj,
        Self::Lzh,
        Self::Chm,
    ];

    pub const WRITABLE: &'static [ArchiveFormat] = &[
        Self::SevenZip,
        Self::Zip,
        Self::TarZst,
        Self::TarGz,
        Self::TarXz,
        Self::TarLz4,
        Self::TarBz2,
        Self::Tar,
        Self::Zst,
        Self::Gz,
        Self::Xz,
        Self::Lz4,
        Self::Bz2,
    ];

    pub const fn id(self) -> &'static str {
        match self {
            Self::SevenZip => "7z",
            Self::Zip => "zip",
            Self::Tar => "tar",
            Self::TarGz => "tar.gz",
            Self::TarZst => "tar.zst",
            Self::TarXz => "tar.xz",
            Self::TarLz4 => "tar.lz4",
            Self::TarBz2 => "tar.bz2",
            Self::Gz => "gz",
            Self::Zst => "zst",
            Self::Xz => "xz",
            Self::Lz4 => "lz4",
            Self::Bz2 => "bz2",
            Self::Rar => "rar",
            Self::Iso => "iso",
            Self::Cab => "cab",
            Self::Wim => "wim",
            Self::Dmg => "dmg",
            Self::Deb => "deb",
            Self::Rpm => "rpm",
            Self::Msi => "msi",
            Self::Cpio => "cpio",
            Self::Arj => "arj",
            Self::Lzh => "lzh",
            Self::Chm => "chm",
        }
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::SevenZip => "7z Archive",
            Self::Zip => "ZIP Archive",
            Self::Tar => "TAR Archive",
            Self::TarGz => "TAR + Gzip (.tar.gz / .tgz)",
            Self::TarZst => "TAR + Zstandard (.tar.zst / .tzst)",
            Self::TarXz => "TAR + XZ (.tar.xz / .txz)",
            Self::TarLz4 => "TAR + LZ4 (.tar.lz4 / .tlz4)",
            Self::TarBz2 => "TAR + BZip2 (.tar.bz2 / .tbz2)",
            Self::Gz => "Gzip Stream (.gz)",
            Self::Zst => "Zstandard Stream (.zst)",
            Self::Xz => "XZ Stream (.xz)",
            Self::Lz4 => "LZ4 Frame (.lz4)",
            Self::Bz2 => "BZip2 Stream (.bz2)",
            Self::Rar => "RAR / RAR5 Archive",
            Self::Iso => "ISO / UDF Optical Image",
            Self::Cab => "Microsoft Cabinet (.cab)",
            Self::Wim => "Windows Imaging Format (.wim)",
            Self::Dmg => "Apple Disk Image (.dmg)",
            Self::Deb => "Debian Software Package (.deb)",
            Self::Rpm => "RPM Software Package (.rpm)",
            Self::Msi => "Windows Installer Package (.msi)",
            Self::Cpio => "CPIO Archive (.cpio)",
            Self::Arj => "ARJ Archive (.arj)",
            Self::Lzh => "LZH / LHA Archive (.lzh)",
            Self::Chm => "Compiled HTML Help (.chm)",
        }
    }

    pub const fn default_extension(self) -> &'static str {
        self.id()
    }

    pub const fn can_write(self) -> bool {
        matches!(
            self,
            Self::SevenZip
                | Self::Zip
                | Self::Tar
                | Self::TarGz
                | Self::TarZst
                | Self::TarXz
                | Self::TarLz4
                | Self::TarBz2
                | Self::Gz
                | Self::Zst
                | Self::Xz
                | Self::Lz4
                | Self::Bz2
        )
    }

    pub const fn is_single_file_stream(self) -> bool {
        matches!(self, Self::Gz | Self::Zst | Self::Xz | Self::Lz4 | Self::Bz2)
    }

    pub const fn supports_encryption(self) -> bool {
        matches!(self, Self::SevenZip | Self::Zip | Self::Rar)
    }

    pub fn from_id(id: &str) -> Option<Self> {
        let lower = id.trim().trim_start_matches('.').to_ascii_lowercase();
        match lower.as_str() {
            "7z" => Some(Self::SevenZip),
            "zip" | "zipx" | "jar" | "apk" | "ipa" | "xpi" | "nupkg" | "whl" => Some(Self::Zip),
            "tar" => Some(Self::Tar),
            "tar.gz" | "tgz" => Some(Self::TarGz),
            "tar.zst" | "tzst" | "tar.zstd" => Some(Self::TarZst),
            "tar.xz" | "txz" => Some(Self::TarXz),
            "tar.lz4" | "tlz4" => Some(Self::TarLz4),
            "tar.bz2" | "tbz2" | "tbz" => Some(Self::TarBz2),
            "gz" | "gzip" => Some(Self::Gz),
            "zst" | "zstd" => Some(Self::Zst),
            "xz" => Some(Self::Xz),
            "lz4" => Some(Self::Lz4),
            "bz2" | "bzip2" => Some(Self::Bz2),
            "rar" | "r00" => Some(Self::Rar),
            "iso" | "udf" | "img" => Some(Self::Iso),
            "cab" => Some(Self::Cab),
            "wim" | "esd" | "swm" => Some(Self::Wim),
            "dmg" => Some(Self::Dmg),
            "deb" | "udeb" => Some(Self::Deb),
            "rpm" => Some(Self::Rpm),
            "msi" | "msp" => Some(Self::Msi),
            "cpio" => Some(Self::Cpio),
            "arj" => Some(Self::Arj),
            "lzh" | "lha" => Some(Self::Lzh),
            "chm" => Some(Self::Chm),
            _ => None,
        }
    }

    /// Strips numeric split suffixes (`.001`, `.002`, `.part1.rar`, etc.) and detects by filename.
    pub fn detect_from_filename(name: &str) -> Option<Self> {
        let mut lower = name.to_ascii_lowercase();

        // Strip trailing `.001`, `.002`, etc. if preceded by another extension
        if let Some(dot_pos) = lower.rfind('.') {
            let ext = &lower[dot_pos + 1..];
            if ext.len() == 3 && ext.bytes().all(|b| b.is_ascii_digit()) && dot_pos > 0 {
                lower.truncate(dot_pos);
            }
        }

        let compound_mappings: &[(&str, ArchiveFormat)] = &[
            (".tar.zst", Self::TarZst),
            (".tar.zstd", Self::TarZst),
            (".tar.gz", Self::TarGz),
            (".tar.xz", Self::TarXz),
            (".tar.lz4", Self::TarLz4),
            (".tar.bz2", Self::TarBz2),
        ];
        for &(suffix, fmt) in compound_mappings {
            if lower.ends_with(suffix) {
                return Some(fmt);
            }
        }

        if let Some(dot_pos) = lower.rfind('.') {
            Self::from_id(&lower[dot_pos + 1..])
        } else {
            None
        }
    }

    /// Detects archive format by combining magic header bytes and optional path hint.
    pub fn detect(path: Option<&Path>, header: &[u8]) -> Option<Self> {
        let filename_hint = path
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .and_then(Self::detect_from_filename);

        // If filename explicitly says compound `.tar.*` (`tgz`, `tzst`, `txz`, `tlz4`, `tbz2`),
        // validate outer compression magic and preserve the compound TAR classification.
        if let Some(hint) = filename_hint {
            match hint {
                Self::TarZst if header.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) => return Some(Self::TarZst),
                Self::TarGz if header.starts_with(&[0x1F, 0x8B]) => return Some(Self::TarGz),
                Self::TarXz if header.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) => return Some(Self::TarXz),
                Self::TarLz4 if header.starts_with(&[0x04, 0x22, 0x4D, 0x18]) => return Some(Self::TarLz4),
                Self::TarBz2 if header.starts_with(b"BZh") => return Some(Self::TarBz2),
                _ => {}
            }
        }

        // Exact magic signatures
        if header.starts_with(&[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C]) {
            return Some(Self::SevenZip);
        }
        if header.starts_with(b"PK\x03\x04")
            || header.starts_with(b"PK\x05\x06")
            || header.starts_with(b"PK\x07\x08")
        {
            return Some(Self::Zip);
        }
        if header.starts_with(b"Rar!\x1A\x07\x00") || header.starts_with(b"Rar!\x1A\x07\x01\x00") {
            return Some(Self::Rar);
        }
        if header.starts_with(b"MSCF") {
            return Some(Self::Cab);
        }
        if header.starts_with(b"MSWIM\0\0\0") || header.starts_with(b"WLPWM\0\0\0") {
            return Some(Self::Wim);
        }
        if header.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
            return Some(Self::Msi);
        }
        if header.starts_with(b"!<arch>\n") {
            return Some(Self::Deb);
        }
        if header.starts_with(&[0xED, 0xAB, 0xEE, 0xDB]) {
            return Some(Self::Rpm);
        }
        if header.starts_with(b"070701")
            || header.starts_with(b"070702")
            || header.starts_with(b"070707")
            || header.starts_with(&[0xC7, 0x71])
            || header.starts_with(&[0x71, 0xC7])
        {
            return Some(Self::Cpio);
        }
        if header.starts_with(&[0x60, 0xEA]) {
            return Some(Self::Arj);
        }
        if header.len() >= 7 && &header[2..5] == b"-lh" && header[6] == b'-' {
            return Some(Self::Lzh);
        }
        if header.starts_with(b"ITSF") {
            return Some(Self::Chm);
        }
        if header.len() >= 262 && &header[257..262] == b"ustar" {
            return Some(Self::Tar);
        }
        // ISO9660 primary volume descriptor at 0x8001 ("CD001") or UDF ("BEA01")
        for &offset in &[0x8001usize, 0x8801usize, 0x9001usize] {
            if header.len() >= offset + 5
                && (&header[offset..offset + 5] == b"CD001"
                    || &header[offset..offset + 5] == b"BEA01")
            {
                return Some(Self::Iso);
            }
        }
        if header.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
            return Some(filename_hint.filter(|&h| h == Self::TarZst).unwrap_or(Self::Zst));
        }
        if header.starts_with(&[0x1F, 0x8B]) {
            return Some(filename_hint.filter(|&h| h == Self::TarGz).unwrap_or(Self::Gz));
        }
        if header.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
            return Some(filename_hint.filter(|&h| h == Self::TarXz).unwrap_or(Self::Xz));
        }
        if header.starts_with(&[0x04, 0x22, 0x4D, 0x18]) {
            return Some(filename_hint.filter(|&h| h == Self::TarLz4).unwrap_or(Self::Lz4));
        }
        if header.starts_with(b"BZh") {
            return Some(filename_hint.filter(|&h| h == Self::TarBz2).unwrap_or(Self::Bz2));
        }

        filename_hint
    }
}

/// Compression method inside ZIP containers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ZipCompressionMethod {
    Stored,
    #[default]
    Deflate,
    Zstd,
    Bzip2,
    Lzma,
    Xz,
}

/// Behavior when extracting over an existing filesystem entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum OverwritePolicy {
    #[default]
    Overwrite,
    SkipExisting,
    RenameAuto,
}

/// Normalized metadata for a single file, folder, or symlink inside an archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub index: usize,
    /// Normalized forward-slash relative path inside the archive (no leading `/`).
    pub path: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub symlink_target: Option<String>,
    pub unpacked_size: u64,
    pub packed_size: u64,
    /// Unix timestamp in seconds (UTC).
    pub mtime: Option<i64>,
    pub crc32: Option<u32>,
    pub attributes: u32,
    pub is_encrypted: bool,
    pub method: String,
}

impl ArchiveEntry {
    pub fn compression_ratio_percent(&self) -> f32 {
        if self.unpacked_size == 0 {
            return 100.0;
        }
        ((self.packed_size as f64 / self.unpacked_size as f64) * 100.0) as f32
    }
}

/// Input specification for packing a file or folder into an archive.
#[derive(Debug, Clone)]
pub struct PackInput {
    /// Source path on the host filesystem.
    pub disk_path: PathBuf,
    /// Target path inside the archive (forward-slash separated).
    pub archive_path: String,
}

/// Options controlling archive creation or update.
#[derive(Debug, Clone)]
pub struct PackOptions {
    pub format: ArchiveFormat,
    /// Normalized compression level `0..=9` (`0` = store, `5` = normal, `9` = ultra).
    pub level: u8,
    pub solid: bool,
    /// Number of worker threads (`0` = use all logical CPU cores).
    pub threads: usize,
    pub password: Option<Zeroizing<String>>,
    pub encrypt_headers: bool,
    /// Optional volume size in bytes (`Some(100 * 1024 * 1024)` -> `.001, .002, ...`).
    pub split_volume_size: Option<u64>,
    pub zip_method: ZipCompressionMethod,
}

impl Default for PackOptions {
    fn default() -> Self {
        Self {
            format: ArchiveFormat::SevenZip,
            level: 5,
            solid: true,
            threads: 0,
            password: None,
            encrypt_headers: false,
            split_volume_size: None,
            zip_method: ZipCompressionMethod::Deflate,
        }
    }
}

impl PackOptions {
    pub fn effective_threads(&self) -> usize {
        if self.threads == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        } else {
            self.threads
        }
    }
}

/// Options controlling archive extraction.
#[derive(Debug, Clone, Default)]
pub struct ExtractOptions {
    pub overwrite: OverwritePolicy,
    pub password: Option<Zeroizing<String>>,
    /// Preserve directory hierarchy (`true` = `x`, `false` = `e` flat extraction).
    pub preserve_paths: bool,
    /// Optional virtual directory prefix stripped from extracted paths (used when dragging
    /// a subfolder out of VFS so only relative children are created at the target).
    pub strip_prefix: Option<String>,
    /// Optional explicit subset of entry indices to extract (`None` = extract all).
    pub selected_indices: Option<Vec<usize>>,
}

impl ExtractOptions {
    pub fn full_with_paths() -> Self {
        Self {
            overwrite: OverwritePolicy::Overwrite,
            password: None,
            preserve_paths: true,
            strip_prefix: None,
            selected_indices: None,
        }
    }
}

/// Summary statistics for the "Info" toolbar dialog and CLI `info` command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveSummary {
    pub format: ArchiveFormat,
    pub physical_size: u64,
    pub total_unpacked_size: u64,
    pub total_packed_size: u64,
    pub file_count: usize,
    pub dir_count: usize,
    pub encrypted_entries: usize,
    pub volume_count: usize,
    pub is_solid: bool,
}

/// Sanitizes an untrusted archive entry path to prevent Zip-Slip / path traversal (`..`, drive letters, absolute roots).
pub fn sanitize_archive_path(raw: &str) -> Option<String> {
    let normalized = raw.replace('\\', "/");
    let mut parts = Vec::new();
    for segment in normalized.split('/') {
        let seg = segment.trim_end_matches('\0');
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return None;
        }
        // Reject Windows drive prefixes like `C:`
        if seg.len() >= 2 && seg.as_bytes()[1] == b':' && seg.as_bytes()[0].is_ascii_alphabetic() {
            return None;
        }
        parts.push(seg);
    }
    Some(parts.join("/"))
}
