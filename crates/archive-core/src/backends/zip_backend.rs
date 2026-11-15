//! Pure-Rust `.zip` backend (`zip` v2.2) with `rayon` parallel compression (`merge_archive`),
//! zero-recompression entry updates (`raw_copy_file`), Zip64, Deflate/Zstd/XZ/BZip2/LZMA,
//! and WinZip AE-2 AES-256 encryption + ZipCrypto/AES decryption.

use std::collections::HashSet;
use std::io::{self, Cursor, Read, Seek, Write};
use std::path::Path;
use std::time::UNIX_EPOCH;
use rayon::prelude::*;
use zip::result::ZipError;
use zip::write::SimpleFileOptions;
use zip::{AesMode, CompressionMethod, DateTime, ZipArchive, ZipWriter};

use crate::backends::{
    build_selection_set, resolve_output_path, stream_reader_to_dest,
};
use crate::error::{ArchiveError, Result};
use crate::memory::{BufferPool, SmartFileReader};
use crate::progress::{ProgressTracker, TaskControl};
use crate::types::{
    sanitize_archive_path, ArchiveEntry, ExtractOptions, PackInput, PackOptions,
};

fn map_zip_error(err: ZipError, had_password: bool) -> ArchiveError {
    match err {
        ZipError::Io(io_err) => ArchiveError::Io(io_err),
        ZipError::InvalidPassword => {
            if had_password {
                ArchiveError::InvalidPassword
            } else {
                ArchiveError::PasswordRequired
            }
        }
        ZipError::FileNotFound => ArchiveError::EntryNotFound("zip entry not found".to_string()),
        ZipError::InvalidArchive(msg) => ArchiveError::CorruptedArchive(msg.to_string()),
        ZipError::UnsupportedArchive(msg) => {
            if !had_password && msg.to_ascii_lowercase().contains("password") {
                ArchiveError::PasswordRequired
            } else {
                ArchiveError::Backend(format!("unsupported zip feature: {msg}"))
            }
        }
        other => ArchiveError::Backend(format!("zip error: {other}")),
    }
}

fn zip_datetime_to_unix(dt: Option<DateTime>) -> Option<i64> {
    let dt = dt?;
    if !dt.is_valid() {
        return None;
    }
    let y = i64::from(dt.year());
    let m = i64::from(dt.month());
    let d = i64::from(dt.day());
    let hh = i64::from(dt.hour());
    let mm = i64::from(dt.minute());
    let ss = i64::from(dt.second());
    let days = days_from_civil(y, m, d);
    Some(days * 86_400 + hh * 3_600 + mm * 60 + ss)
}

fn unix_to_zip_datetime(secs: i64) -> Option<DateTime> {
    if secs <= 0 {
        return None;
    }
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    if !(1980..=2107).contains(&year) {
        return None;
    }
    let hour = (rem / 3_600) as u8;
    let minute = ((rem % 3_600) / 60) as u8;
    let second = (rem % 60) as u8;
    DateTime::from_date_and_time(year as u16, month as u8, day as u8, hour, minute, second).ok()
}

/// Howard Hinnant's civil-from-days / days-from-civil algorithms (proleptic Gregorian, UTC).
const fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + (d as u64) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + (doe as i64) - 719_468
}

const fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as i64, d as i64)
}

fn format_method_name(m: CompressionMethod) -> &'static str {
    match m {
        CompressionMethod::Stored => "Store",
        CompressionMethod::Deflated => "Deflate",
        CompressionMethod::Deflate64 => "Deflate64",
        CompressionMethod::Bzip2 => "BZip2",
        CompressionMethod::Zstd => "Zstd",
        CompressionMethod::Lzma => "LZMA",
        CompressionMethod::Xz => "XZ",
        CompressionMethod::Aes => "AES",
        _ => "ZIP",
    }
}

fn convert_zip_file<R: Read>(index: usize, zf: &zip::read::ZipFile<'_, R>) -> Option<ArchiveEntry> {
    let raw_name = zf.name();
    let is_dir = zf.is_dir() || raw_name.ends_with('/') || raw_name.ends_with('\\');
    let clean = sanitize_archive_path(raw_name)?;
    let encrypted = zf.encrypted();
    let crc = if is_dir { None } else { Some(zf.crc32()) };
    Some(ArchiveEntry {
        index,
        path: clean,
        is_dir,
        is_symlink: zf.is_symlink(),
        symlink_target: None,
        unpacked_size: zf.size(),
        packed_size: zf.compressed_size(),
        mtime: zip_datetime_to_unix(zf.last_modified()),
        crc32: crc,
        attributes: zf.unix_mode().unwrap_or(0),
        is_encrypted: encrypted,
        method: format_method_name(zf.compression()).to_string(),
    })
}

/// Lists all entries inside a `.zip` archive using central directory headers without decompressing data.
pub fn list_entries<R: Read + Seek>(
    reader: R,
    control: Option<&TaskControl>,
) -> Result<Vec<ArchiveEntry>> {
    let mut archive = ZipArchive::new(reader).map_err(|e| map_zip_error(e, false))?;
    let len = archive.len();
    let mut entries = Vec::with_capacity(len);

    for idx in 0..len {
        if let Some(ctrl) = control {
            ctrl.checkpoint()?;
        }
        // `by_index_raw` reads central directory metadata even on encrypted entries without needing a password.
        let zf = archive
            .by_index_raw(idx)
            .map_err(|e| map_zip_error(e, false))?;
        if let Some(entry) = convert_zip_file(idx, &zf) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// Extracts or tests selected entries from a `.zip` stream.
pub fn extract_or_test<R: Read + Seek>(
    reader: R,
    dest_dir: Option<&Path>,
    options: &ExtractOptions,
    test_only: bool,
    pool: &BufferPool,
    control: Option<&TaskControl>,
    progress: Option<&ProgressTracker>,
) -> Result<()> {
    let password = options.password.as_deref().map(String::as_str);
    let had_pw = password.is_some_and(|s| !s.is_empty());
    let mut archive = ZipArchive::new(reader).map_err(|e| map_zip_error(e, had_pw))?;
    let selection = build_selection_set(options);
    let len = archive.len();

    for idx in 0..len {
        if let Some(ctrl) = control {
            ctrl.checkpoint()?;
        }
        if let Some(sel) = &selection {
            if !sel.contains(&idx) {
                continue;
            }
        }

        // Inspect header first to detect encrypted entries cleanly when no password was given.
        let (entry_meta, is_encrypted) = {
            let raw = archive
                .by_index_raw(idx)
                .map_err(|e| map_zip_error(e, had_pw))?;
            let enc = raw.encrypted();
            (convert_zip_file(idx, &raw), enc)
        };

        let Some(entry) = entry_meta else {
            continue;
        };

        if entry.is_dir {
            if !test_only {
                if let Some(root) = dest_dir {
                    if let Some(dir_path) = resolve_output_path(root, &entry.path, true, options)? {
                        std::fs::create_dir_all(&dir_path)?;
                        crate::backends::apply_entry_metadata(
                            &dir_path,
                            entry.mtime,
                            entry.attributes,
                        );
                    }
                }
            }
            continue;
        }

        if is_encrypted && !had_pw {
            return Err(ArchiveError::PasswordRequired);
        }

        let target_path = if test_only {
            None
        } else if let Some(root) = dest_dir {
            match resolve_output_path(root, &entry.path, false, options)? {
                Some(p) => Some(p),
                None => continue,
            }
        } else {
            None
        };

        let mut zf = if let Some(pw) = password.filter(|s| !s.is_empty()) {
            archive
                .by_index_decrypt(idx, pw.as_bytes())
                .map_err(|e| map_zip_error(e, true))?
        } else {
            archive
                .by_index(idx)
                .map_err(|e| map_zip_error(e, false))?
        };

        // WinZip AE-2 stores `0` in the header CRC32 field and authenticates via HMAC-SHA1 inside `zip` reader.
        let verify_crc = !(is_encrypted && entry.crc32 == Some(0));
        stream_reader_to_dest(
            &mut zf,
            target_path.as_deref(),
            &entry,
            verify_crc,
            pool,
            control,
            progress,
        )?;
    }

    Ok(())
}

/// Reads a single `.zip` entry into memory (up to `max_bytes` if specified).
pub fn read_entry_bytes<R: Read + Seek>(
    reader: R,
    target_index: usize,
    max_bytes: Option<usize>,
    password: Option<&str>,
    control: Option<&TaskControl>,
) -> Result<Vec<u8>> {
    let had_pw = password.is_some_and(|s| !s.is_empty());
    let mut archive = ZipArchive::new(reader).map_err(|e| map_zip_error(e, had_pw))?;
    if target_index >= archive.len() {
        return Err(ArchiveError::EntryNotFound(format!("index {target_index}")));
    }

    let is_encrypted = {
        let raw = archive
            .by_index_raw(target_index)
            .map_err(|e| map_zip_error(e, had_pw))?;
        if raw.is_dir() {
            return Ok(Vec::new());
        }
        raw.encrypted()
    };
    if is_encrypted && !had_pw {
        return Err(ArchiveError::PasswordRequired);
    }

    let mut zf = if let Some(pw) = password.filter(|s| !s.is_empty()) {
        archive
            .by_index_decrypt(target_index, pw.as_bytes())
            .map_err(|e| map_zip_error(e, true))?
    } else {
        archive
            .by_index(target_index)
            .map_err(|e| map_zip_error(e, false))?
    };

    let cap = max_bytes.unwrap_or(zf.size() as usize).min(16 * 1024 * 1024);
    let mut out = Vec::with_capacity(cap);
    let mut buf = [0u8; 64 * 1024];
    loop {
        if let Some(ctrl) = control {
            ctrl.checkpoint()?;
        }
        let remaining = max_bytes.map(|limit| limit.saturating_sub(out.len()));
        if remaining == Some(0) {
            break;
        }
        let to_read = remaining.map_or(buf.len(), |r| r.min(buf.len()));
        let n = zf.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

fn select_zip_method_and_level(options: &PackOptions) -> (CompressionMethod, Option<i64>) {
    if options.level == 0 {
        return (CompressionMethod::Stored, None);
    }
    let method_hint = options.zip_method;
    let method = match method_hint {
        crate::types::ZipCompressionMethod::Stored => CompressionMethod::Stored,
        crate::types::ZipCompressionMethod::Deflate => CompressionMethod::Deflated,
        crate::types::ZipCompressionMethod::Zstd => CompressionMethod::Zstd,
        crate::types::ZipCompressionMethod::Bzip2 => CompressionMethod::Bzip2,
        crate::types::ZipCompressionMethod::Lzma => CompressionMethod::Lzma,
    };
    let level = if method == CompressionMethod::Stored {
        None
    } else {
        Some(i64::from(options.level.clamp(1, 9)))
    };
    (method, level)
}

fn build_file_options(
    file_size: u64,
    mtime_secs: Option<i64>,
    unix_mode: Option<u32>,
    options: &PackOptions,
) -> SimpleFileOptions {
    let (method, level) = select_zip_method_and_level(options);
    let mut fo = SimpleFileOptions::default()
        .compression_method(method)
        .compression_level(level)
        .large_file(file_size >= 0xFFFF_FFFF);

    if let Some(secs) = mtime_secs {
        if let Some(dt) = unix_to_zip_datetime(secs) {
            fo = fo.last_modified_time(dt);
        }
    }
    if let Some(mode) = unix_mode {
        if mode != 0 {
            fo = fo.unix_permissions(mode);
        }
    }
    if let Some(pw) = options.password.as_deref() {
        if !pw.is_empty() {
            fo = fo.with_aes_encryption(AesMode::Aes256, pw);
        }
    }
    fo
}

fn metadata_mtime_and_mode(meta: &std::fs::Metadata) -> (Option<i64>, Option<u32>) {
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64);
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        Some(meta.permissions().mode())
    };
    #[cfg(not(unix))]
    let mode = None;
    (mtime, mode)
}

/// Creates a `.zip` archive using parallel `rayon` mini-archive compression + `merge_archive`
/// for small/medium files (`<= 16 MiB`) and direct streaming for large files (`> 16 MiB`).
pub fn pack_entries<W: Write + Seek>(
    dest: W,
    inputs: &[PackInput],
    options: &PackOptions,
    pool: &BufferPool,
    control: Option<&TaskControl>,
    progress: Option<&ProgressTracker>,
) -> Result<W> {
    const PARALLEL_FILE_LIMIT: u64 = 16 * 1024 * 1024;
    const PARALLEL_BATCH_MAX_BYTES: u64 = 32 * 1024 * 1024;

    let mut main_writer = ZipWriter::new(dest);
    let mut small_files: Vec<(String, PathBufWithMeta)> = Vec::new();
    let mut large_files: Vec<(String, PathBufWithMeta)> = Vec::new();

    #[derive(Clone)]
    struct PathBufWithMeta {
        path: std::path::PathBuf,
        len: u64,
        mtime: Option<i64>,
        mode: Option<u32>,
    }

    for item in inputs {
        if let Some(ctrl) = control {
            ctrl.checkpoint()?;
        }
        let clean = sanitize_archive_path(&item.archive_path)
            .ok_or_else(|| ArchiveError::UnsafePath(item.archive_path.clone()))?;
        let meta = std::fs::symlink_metadata(&item.disk_path)?;
        let (mtime, mode) = metadata_mtime_and_mode(&meta);

        if meta.is_dir() {
            let dir_opts = build_file_options(0, mtime, mode, options)
                .compression_method(CompressionMethod::Stored)
                .compression_level(None);
            main_writer
                .add_directory(format!("{clean}/"), dir_opts)
                .map_err(|e| map_zip_error(e, options.password.is_some()))?;
        } else {
            let info = PathBufWithMeta {
                path: item.disk_path.clone(),
                len: meta.len(),
                mtime,
                mode,
            };
            if info.len <= PARALLEL_FILE_LIMIT && options.threads != 1 {
                small_files.push((clean, info));
            } else {
                large_files.push((clean, info));
            }
        }
    }

    // Partition small/medium files into bounded memory chunks and compress in parallel across `rayon`.
    if !small_files.is_empty() {
        let mut batches: Vec<Vec<(String, PathBufWithMeta)>> = Vec::new();
        let mut cur_batch = Vec::new();
        let mut cur_bytes = 0u64;

        for entry in small_files {
            if !cur_batch.is_empty() && cur_bytes + entry.1.len > PARALLEL_BATCH_MAX_BYTES {
                batches.push(std::mem::take(&mut cur_batch));
                cur_bytes = 0;
            }
            cur_bytes += entry.1.len;
            cur_batch.push(entry);
        }
        if !cur_batch.is_empty() {
            batches.push(cur_batch);
        }

        // Process batches in windows of `num_cpus` so peak memory never exceeds `num_cpus * 32 MiB`.
        let parallelism = if options.threads == 0 {
            rayon::current_num_threads().max(1)
        } else {
            options.threads
        };

        for window in batches.chunks(parallelism) {
            if let Some(ctrl) = control {
                ctrl.checkpoint()?;
            }
            let compressed_blobs: Vec<Result<Vec<u8>>> = window
                .par_iter()
                .map(|batch| {
                    let mut sub_writer = ZipWriter::new(Cursor::new(Vec::new()));
                    let mut io_buf = pool.checkout_io();
                    let buf = io_buf.as_mut_slice();

                    for (virt_name, info) in batch {
                        if let Some(ctrl) = control {
                            ctrl.checkpoint()?;
                        }
                        if let Some(p) = progress {
                            p.set_current_item(virt_name);
                        }
                        let fo = build_file_options(info.len, info.mtime, info.mode, options);
                        sub_writer
                            .start_file(virt_name.clone(), fo)
                            .map_err(|e| map_zip_error(e, options.password.is_some()))?;
                        let (mut reader, _) = SmartFileReader::open(&info.path)?;
                        loop {
                            if let Some(ctrl) = control {
                                ctrl.checkpoint()?;
                            }
                            let n = reader.read(buf)?;
                            if n == 0 {
                                break;
                            }
                            sub_writer.write_all(&buf[..n])?;
                            if let Some(p) = progress {
                                p.add_bytes(n as u64);
                            }
                        }
                        if let Some(p) = progress {
                            p.inc_files(1);
                        }
                    }

                    let cursor = sub_writer
                        .finish()
                        .map_err(|e| map_zip_error(e, options.password.is_some()))?;
                    Ok(cursor.into_inner())
                })
                .collect();

            for blob_res in compressed_blobs {
                let blob = blob_res?;
                let sub_archive = ZipArchive::new(Cursor::new(blob))
                    .map_err(|e| map_zip_error(e, options.password.is_some()))?;
                main_writer
                    .merge_archive(sub_archive)
                    .map_err(|e| map_zip_error(e, options.password.is_some()))?;
            }
        }
    }

    // Stream large files directly using `SmartFileReader` (`Mmap` + fallback) so RAM stays flat.
    if !large_files.is_empty() {
        let mut io_buf = pool.checkout_io();
        let buf = io_buf.as_mut_slice();

        for (virt_name, info) in large_files {
            if let Some(ctrl) = control {
                ctrl.checkpoint()?;
            }
            if let Some(p) = progress {
                p.set_current_item(&virt_name);
            }
            let fo = build_file_options(info.len, info.mtime, info.mode, options);
            main_writer
                .start_file(virt_name, fo)
                .map_err(|e| map_zip_error(e, options.password.is_some()))?;
            let (mut reader, _) = SmartFileReader::open(&info.path)?;
            loop {
                if let Some(ctrl) = control {
                    ctrl.checkpoint()?;
                }
                let n = reader.read(buf)?;
                if n == 0 {
                    break;
                }
                main_writer.write_all(&buf[..n])?;
                if let Some(p) = progress {
                    p.add_bytes(n as u64);
                }
            }
            if let Some(p) = progress {
                p.inc_files(1);
            }
        }
    }

    main_writer
        .finish()
        .map_err(|e| map_zip_error(e, options.password.is_some()))
}

/// Fast zero-recompression `.zip` mutation: copies all untouched entries via `raw_copy_file`,
/// skips any paths in `remove_virtual_paths`, and appends `additions` (used for Add, Delete, and Live-Edit).
pub fn modify_zip_archive<R: Read + Seek, W: Write + Seek>(
    existing_reader: R,
    dest_writer: W,
    remove_virtual_paths: &HashSet<String>,
    additions: &[PackInput],
    options: &PackOptions,
    pool: &BufferPool,
    control: Option<&TaskControl>,
    progress: Option<&ProgressTracker>,
) -> Result<W> {
    let mut src_zip = ZipArchive::new(existing_reader).map_err(|e| map_zip_error(e, false))?;
    let mut out_zip = ZipWriter::new(dest_writer);

    let addition_names: HashSet<String> = additions
        .iter()
        .filter_map(|inp| sanitize_archive_path(&inp.archive_path))
        .collect();

    for idx in 0..src_zip.len() {
        if let Some(ctrl) = control {
            ctrl.checkpoint()?;
        }
        let raw_entry = src_zip
            .by_index_raw(idx)
            .map_err(|e| map_zip_error(e, false))?;
        let Some(clean) = sanitize_archive_path(raw_entry.name()) else {
            continue;
        };
        let skip = remove_virtual_paths.iter().any(|rem| {
            let norm = rem.trim_matches('/');
            clean == norm || clean.starts_with(&format!("{norm}/"))
        }) || addition_names.contains(&clean);

        if skip {
            continue;
        }
        out_zip
            .raw_copy_file(raw_entry)
            .map_err(|e| map_zip_error(e, false))?;
    }

    if !additions.is_empty() {
        let sub_buf = pack_entries(
            Cursor::new(Vec::new()),
            additions,
            options,
            pool,
            control,
            progress,
        )?;
        let sub_archive = ZipArchive::new(Cursor::new(sub_buf.into_inner()))
            .map_err(|e| map_zip_error(e, options.password.is_some()))?;
        out_zip
            .merge_archive(sub_archive)
            .map_err(|e| map_zip_error(e, options.password.is_some()))?;
    }

    out_zip
        .finish()
        .map_err(|e| map_zip_error(e, options.password.is_some()))
        .map_err(|e| match e {
            ArchiveError::Io(ioe) => ArchiveError::Io(io::Error::other(ioe.to_string())),
            other => other,
        })
}
