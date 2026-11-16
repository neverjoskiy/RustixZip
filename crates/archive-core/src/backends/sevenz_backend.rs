//! Pure-Rust `.7z` backend (`sevenz-rust2`) supporting LZMA2 presets, solid & non-solid
//! blocks, BCJ/Zstd/BZip2/LZ4 decoding, and AES-256 data + header encryption.

use std::io::{Read, Seek, Write};
use std::path::Path;
use sevenz_rust2::{
    lzma::LZMA2Options, AesEncoderOptions, Error as SevenZError, Password, SeqReader,
    SevenZArchiveEntry, SevenZMethod, SevenZMethodConfiguration, SevenZReader, SevenZWriter,
    SourceReader,
};

use crate::backends::{build_selection_set, DiskExtractSink};
use crate::error::{ArchiveError, Result};
use crate::memory::{BufferPool, SmartFileReader};
use crate::progress::{ProgressTracker, TaskControl};
use crate::types::{
    sanitize_archive_path, ArchiveEntry, ExtractOptions, PackInput, PackOptions,
};

fn make_password(pw: Option<&str>) -> Password {
    match pw {
        Some(s) if !s.is_empty() => Password::from(s),
        _ => Password::empty(),
    }
}

fn map_sevenz_error(err: SevenZError, had_password: bool) -> ArchiveError {
    match err {
        SevenZError::PasswordRequired => ArchiveError::PasswordRequired,
        SevenZError::MaybeBadPassword(_) => {
            if had_password {
                ArchiveError::InvalidPassword
            } else {
                ArchiveError::PasswordRequired
            }
        }
        SevenZError::ChecksumVerificationFailed | SevenZError::NextHeaderCrcMismatch => {
            if had_password {
                ArchiveError::InvalidPassword
            } else {
                ArchiveError::ChecksumMismatch {
                    entry: ".7z".to_string(),
                    expected: "valid 7z block/header CRC".to_string(),
                    actual: "CRC verification failed".to_string(),
                }
            }
        }
        SevenZError::BadSignature(_)
        | SevenZError::BadTerminatedStreamsInfo(_)
        | SevenZError::BadTerminatedUnpackInfo
        | SevenZError::BadTerminatedPackInfo(_)
        | SevenZError::BadTerminatedSubStreamsInfo
        | SevenZError::BadTerminatedheader(_) => ArchiveError::CorruptedArchive(err.to_string()),
        SevenZError::Io(io_err, _) | SevenZError::FileOpen(io_err, _) => ArchiveError::Io(io_err),
        other => ArchiveError::Backend(format!("7z error: {other}")),
    }
}

fn convert_sevenz_entry(
    index: usize,
    sz: &SevenZArchiveEntry,
    method_label: &str,
    encrypted: bool,
) -> Option<ArchiveEntry> {
    if sz.is_anti_item {
        return None;
    }
    let clean = sanitize_archive_path(sz.name())?;
    let mtime = if sz.has_last_modified_date {
        Some(sz.last_modified_date.to_unix_time_secs())
    } else {
        None
    };
    let crc32 = if sz.has_crc {
        Some(sz.crc as u32)
    } else {
        None
    };
    Some(ArchiveEntry {
        index,
        path: clean,
        is_dir: sz.is_directory,
        is_symlink: false,
        symlink_target: None,
        unpacked_size: sz.size,
        packed_size: sz.compressed_size,
        mtime,
        crc32,
        attributes: if sz.has_windows_attributes {
            sz.windows_attributes
        } else {
            0
        },
        is_encrypted: encrypted,
        method: method_label.to_string(),
    })
}

/// Lists all entries inside a `.7z` stream (supports header-encrypted `.7z` when `password` is supplied).
pub fn list_entries<R: Read + Seek>(
    reader: R,
    password: Option<&str>,
    control: Option<&TaskControl>,
) -> Result<(Vec<ArchiveEntry>, bool)> {
    let had_pw = password.is_some_and(|s| !s.is_empty());
    let sz_reader = SevenZReader::new(reader, make_password(password))
        .map_err(|e| map_sevenz_error(e, had_pw))?;
    let archive = sz_reader.archive();
    let is_solid = archive.is_solid;

    let mut entries = Vec::with_capacity(archive.files.len());
    let mut methods_buf = Vec::new();

    for (raw_idx, item) in archive.files.iter().enumerate() {
        if let Some(ctrl) = control {
            ctrl.checkpoint()?;
        }
        methods_buf.clear();
        let _ = sz_reader.file_compression_methods(item.name(), &mut methods_buf);
        let encrypted = methods_buf
            .iter()
            .any(|m| m.id() == SevenZMethod::AES256SHA256.id());
        let method_label = if methods_buf.is_empty() {
            if item.is_directory {
                String::new()
            } else {
                "LZMA2".to_string()
            }
        } else {
            methods_buf
                .iter()
                .map(|m| m.name())
                .collect::<Vec<_>>()
                .join("+")
        };

        if let Some(entry) = convert_sevenz_entry(raw_idx, item, &method_label, encrypted) {
            entries.push(entry);
        }
    }

    Ok((entries, is_solid))
}

/// Extracts or tests entries from a `.7z` stream.
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
    let mut sz_reader = SevenZReader::new(reader, make_password(password))
        .map_err(|e| map_sevenz_error(e, had_pw))?;

    let selection = build_selection_set(options);
    let total_files = sz_reader.archive().files.len();
    let mut sink = DiskExtractSink::new(dest_dir, options, test_only, progress);
    let mut host_err: Option<ArchiveError> = None;
    let mut raw_idx = 0usize;
    let mut remaining_selected = selection.as_ref().map(std::collections::HashSet::len);

    let res = sz_reader.for_each_entries(|sz_entry, content_reader| {
        let current_idx = raw_idx;
        raw_idx += 1;

        if let Some(ctrl) = control {
            if let Err(e) = ctrl.checkpoint() {
                host_err = Some(e);
                return Ok(false);
            }
        }

        let want = selection
            .as_ref()
            .is_none_or(|set| set.contains(&current_idx));
        if !want {
            return Ok(current_idx + 1 < total_files);
        }

        if let Some(entry) = convert_sevenz_entry(current_idx, sz_entry, "LZMA2", had_pw) {
            if let Err(e) = sink.begin_entry(&entry) {
                host_err = Some(e);
                return Ok(false);
            }
            if !entry.is_dir && sz_entry.has_stream {
                let mut io_buf = pool.checkout_io();
                let buf = io_buf.as_mut_slice();
                loop {
                    if let Some(ctrl) = control {
                        if let Err(e) = ctrl.checkpoint() {
                            host_err = Some(e);
                            return Ok(false);
                        }
                    }
                    let n = content_reader.read(buf)?;
                    if n == 0 {
                        break;
                    }
                    if let Err(e) = sink.write_chunk(&buf[..n]) {
                        host_err = Some(e);
                        return Ok(false);
                    }
                }
            }
            if let Err(e) = sink.finish_entry() {
                host_err = Some(e);
                return Ok(false);
            }
        }

        if let Some(rem) = remaining_selected.as_mut() {
            *rem = rem.saturating_sub(1);
            if *rem == 0 {
                return Ok(false);
            }
        }
        Ok(true)
    });

    if let Some(err) = host_err {
        return Err(err);
    }
    res.map_err(|e| map_sevenz_error(e, had_pw))
}

/// Reads a single `.7z` entry into memory (used for `F3` preview, live-edit staging, and nested archives).
pub fn read_entry_bytes<R: Read + Seek>(
    reader: R,
    target_path: &str,
    max_bytes: Option<usize>,
    password: Option<&str>,
    control: Option<&TaskControl>,
) -> Result<Vec<u8>> {
    let had_pw = password.is_some_and(|s| !s.is_empty());
    let mut sz_reader = SevenZReader::new(reader, make_password(password))
        .map_err(|e| map_sevenz_error(e, had_pw))?;

    let mut out = Vec::new();
    let mut found = false;
    let mut host_err: Option<ArchiveError> = None;

    let res = sz_reader.for_each_entries(|sz_entry, content_reader| {
        let sz_path = sanitize_archive_path(sz_entry.name()).unwrap_or_default();
        if sz_path != target_path {
            return Ok(true);
        }
        found = true;
        if sz_entry.is_directory || !sz_entry.has_stream {
            return Ok(false);
        }
        let cap = max_bytes.unwrap_or(sz_entry.size as usize);
        out.reserve(cap.min(16 * 1024 * 1024));
        let mut buf = [0u8; 64 * 1024];
        loop {
            if let Some(ctrl) = control {
                if let Err(e) = ctrl.checkpoint() {
                    host_err = Some(e);
                    return Ok(false);
                }
            }
            let remaining = max_bytes.map(|limit| limit.saturating_sub(out.len()));
            if remaining == Some(0) {
                break;
            }
            let to_read = remaining.map_or(buf.len(), |r| r.min(buf.len()));
            let n = content_reader.read(&mut buf[..to_read])?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        Ok(false)
    });

    if let Some(err) = host_err {
        return Err(err);
    }
    res.map_err(|e| map_sevenz_error(e, had_pw))?;
    if !found {
        return Err(ArchiveError::EntryNotFound(format!("path {target_path}")));
    }
    Ok(out)
}

/// Progress-reporting reader wrapper so solid & non-solid `.7z` compression streams report live `MB/s` and honor Pause/Cancel.
struct TrackedInputReader<'a, R> {
    inner: R,
    control: Option<&'a TaskControl>,
    progress: Option<&'a ProgressTracker>,
}

impl<R: Read> Read for TrackedInputReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(ctrl) = self.control {
            ctrl.checkpoint()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Interrupted, e.to_string()))?;
        }
        let n = self.inner.read(buf)?;
        if n > 0 {
            if let Some(p) = self.progress {
                p.add_bytes(n as u64);
            }
        }
        Ok(n)
    }
}

/// Creates a `.7z` archive into `dest` (`Write + Seek`) from `inputs` with LZMA2 / Copy and optional AES-256 + header encryption.
pub fn pack_entries<W: Write + Seek>(
    dest: W,
    inputs: &[PackInput],
    options: &PackOptions,
    control: Option<&TaskControl>,
    progress: Option<&ProgressTracker>,
) -> Result<W> {
    let mut writer =
        SevenZWriter::new(dest).map_err(|e| map_sevenz_error(e, options.password.is_some()))?;

    let level = options.level.clamp(0, 9);
    let mut methods: Vec<SevenZMethodConfiguration> = Vec::new();

    if let Some(pw) = options.password.as_deref() {
        if !pw.is_empty() {
            methods.push(AesEncoderOptions::new(Password::from(pw.as_str())).into());
            writer.set_encrypt_header(options.encrypt_headers);
        } else {
            writer.set_encrypt_header(false);
        }
    } else {
        writer.set_encrypt_header(false);
    }

    if level == 0 {
        methods.push(SevenZMethodConfiguration::new(SevenZMethod::COPY));
    } else {
        let lzma_opts = LZMA2Options::with_preset(level as u32);
        methods.push(lzma_opts.into());
    }
    writer.set_content_methods(methods);

    // Solid block grouping (`64 MiB` solid blocks) for high compression ratio while preserving fast bounded seeks.
    const SOLID_BLOCK_TARGET_BYTES: u64 = 64 * 1024 * 1024;
    let mut solid_batch_meta: Vec<(SevenZArchiveEntry, std::path::PathBuf, u64)> = Vec::new();
    let mut solid_batch_bytes = 0u64;

    let flush_solid_batch = |writer: &mut SevenZWriter<W>,
                             batch: &mut Vec<(SevenZArchiveEntry, std::path::PathBuf, u64)>|
     -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let mut entries_vec = Vec::with_capacity(batch.len());
        let mut readers_vec = Vec::with_capacity(batch.len());
        for (sz_entry, disk_path, _) in batch.drain(..) {
            if let Some(p) = progress {
                p.set_current_item(sz_entry.name());
            }
            let (smart_reader, _) = SmartFileReader::open(&disk_path)?;
            let tracked = TrackedInputReader {
                inner: smart_reader,
                control,
                progress,
            };
            entries_vec.push(sz_entry);
            readers_vec.push(SourceReader::new(tracked));
        }
        let count = entries_vec.len() as u64;
        writer
            .push_archive_entries(entries_vec, SeqReader::new(readers_vec))
            .map_err(|e| map_sevenz_error(e, options.password.is_some()))?;
        if let Some(p) = progress {
            p.inc_files(count);
        }
        Ok(())
    };

    for item in inputs {
        if let Some(ctrl) = control {
            ctrl.checkpoint()?;
        }
        let clean_name = sanitize_archive_path(&item.archive_path)
            .ok_or_else(|| ArchiveError::UnsafePath(item.archive_path.clone()))?;
        let meta = std::fs::symlink_metadata(&item.disk_path)?;

        if meta.is_dir() {
            let sz_entry = SevenZArchiveEntry::from_path(&item.disk_path, clean_name);
            writer
                .push_archive_entry::<std::io::Empty>(sz_entry, None)
                .map_err(|e| map_sevenz_error(e, options.password.is_some()))?;
            continue;
        }

        let file_len = meta.len();
        let sz_entry = SevenZArchiveEntry::from_path(&item.disk_path, clean_name);

        if options.solid && level > 0 && file_len > 0 && file_len < SOLID_BLOCK_TARGET_BYTES {
            solid_batch_bytes += file_len;
            solid_batch_meta.push((sz_entry, item.disk_path.clone(), file_len));
            if solid_batch_bytes >= SOLID_BLOCK_TARGET_BYTES {
                flush_solid_batch(&mut writer, &mut solid_batch_meta)?;
                solid_batch_bytes = 0;
            }
        } else {
            flush_solid_batch(&mut writer, &mut solid_batch_meta)?;
            solid_batch_bytes = 0;
            if let Some(p) = progress {
                p.set_current_item(sz_entry.name());
            }
            if file_len == 0 {
                writer
                    .push_archive_entry(sz_entry, Some(std::io::empty()))
                    .map_err(|e| map_sevenz_error(e, options.password.is_some()))?;
            } else {
                let (smart_reader, _) = SmartFileReader::open(&item.disk_path)?;
                let tracked = TrackedInputReader {
                    inner: smart_reader,
                    control,
                    progress,
                };
                writer
                    .push_archive_entry(sz_entry, Some(tracked))
                    .map_err(|e| map_sevenz_error(e, options.password.is_some()))?;
            }
            if let Some(p) = progress {
                p.inc_files(1);
            }
        }
    }

    flush_solid_batch(&mut writer, &mut solid_batch_meta)?;
    writer.finish().map_err(ArchiveError::Io)
}
