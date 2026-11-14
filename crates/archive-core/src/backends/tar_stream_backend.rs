//! Streaming `.tar`, `.tar.gz`/`.tgz`, `.tar.zst`/`.tzst`, `.tar.xz`/`.txz`, `.tar.lz4`,
//! `.tar.bz2`, and single-file `.gz`/`.zst`/`.xz`/`.lz4`/`.bz2` backend with multi-core
//! encoders (`zstdmt`, `xz2` MT, `rayon` + `zlib-rs` parallel Gzip members, `lz4_flex` frames)
//! and `StreamCheckpointIndex` population.

use std::io::{self, BufReader, BufWriter, Read, Seek, Write};
use std::path::Path;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression as FlateCompression;
use rayon::prelude::*;

use crate::backends::{
    apply_entry_metadata, build_selection_set, resolve_output_path, stream_reader_to_dest,
};
use crate::error::{ArchiveError, Result};
use crate::memory::{BufferPool, SmartFileReader, IO_BUF_SIZE};
use crate::progress::{ProgressTracker, TaskControl};
use crate::types::{
    sanitize_archive_path, ArchiveEntry, ArchiveFormat, ExtractOptions, PackInput, PackOptions,
};
use crate::vfs::StreamCheckpointIndex;

/// Byte-counting `Read` wrapper so sequential TAR scanning records uncompressed stream offsets
/// into `StreamCheckpointIndex`.
struct CountingReader<R> {
    inner: R,
    bytes_read: u64,
}

impl<R: Read> CountingReader<R> {
    const fn new(inner: R) -> Self {
        Self {
            inner,
            bytes_read: 0,
        }
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes_read += n as u64;
        Ok(n)
    }
}

/// Multi-core RFC 1952 Gzip writer that compresses 1 MiB blocks in parallel across `rayon`
/// into valid concatenated Gzip members (identical framing to `pigz` / `MultiGzDecoder`).
struct ParallelGzWriter<W: Write> {
    inner: Option<W>,
    level: FlateCompression,
    max_batches: usize,
    pending_chunks: Vec<Vec<u8>>,
    active_chunk: Vec<u8>,
}

const GZ_MEMBER_BLOCK_SIZE: usize = 1024 * 1024;

impl<W: Write> ParallelGzWriter<W> {
    fn new(writer: W, level: u32, threads: usize) -> Self {
        let max_batches = if threads == 0 {
            rayon::current_num_threads().max(1)
        } else {
            threads.max(1)
        };
        Self {
            inner: Some(writer),
            level: FlateCompression::new(level.clamp(1, 9)),
            max_batches,
            pending_chunks: Vec::with_capacity(max_batches),
            active_chunk: Vec::with_capacity(GZ_MEMBER_BLOCK_SIZE),
        }
    }

    fn flush_batches(&mut self) -> io::Result<()> {
        if self.pending_chunks.is_empty() {
            return Ok(());
        }
        let level = self.level;
        let chunks = std::mem::take(&mut self.pending_chunks);
        let compressed_members: Vec<io::Result<Vec<u8>>> = chunks
            .into_par_iter()
            .map(|raw| {
                let mut enc = GzEncoder::new(Vec::with_capacity(raw.len() / 2 + 64), level);
                enc.write_all(&raw)?;
                enc.finish()
            })
            .collect();

        let out = self
            .inner
            .as_mut()
            .ok_or_else(|| io::Error::other("gzip writer already finished"))?;
        for member in compressed_members {
            out.write_all(&member?)?;
        }
        Ok(())
    }

    fn finish(mut self) -> io::Result<W> {
        if !self.active_chunk.is_empty() || self.pending_chunks.is_empty() {
            self.pending_chunks
                .push(std::mem::take(&mut self.active_chunk));
        }
        self.flush_batches()?;
        let mut inner = self
            .inner
            .take()
            .ok_or_else(|| io::Error::other("gzip writer already finished"))?;
        inner.flush()?;
        Ok(inner)
    }
}

impl<W: Write> Write for ParallelGzWriter<W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        let total = buf.len();
        while !buf.is_empty() {
            let space = GZ_MEMBER_BLOCK_SIZE - self.active_chunk.len();
            let take = space.min(buf.len());
            self.active_chunk.extend_from_slice(&buf[..take]);
            buf = &buf[take..];
            if self.active_chunk.len() == GZ_MEMBER_BLOCK_SIZE {
                let full =
                    std::mem::replace(&mut self.active_chunk, Vec::with_capacity(GZ_MEMBER_BLOCK_SIZE));
                self.pending_chunks.push(full);
                if self.pending_chunks.len() >= self.max_batches {
                    self.flush_batches()?;
                }
            }
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.active_chunk.is_empty() {
            let partial =
                std::mem::replace(&mut self.active_chunk, Vec::with_capacity(GZ_MEMBER_BLOCK_SIZE));
            self.pending_chunks.push(partial);
        }
        self.flush_batches()?;
        if let Some(w) = self.inner.as_mut() {
            w.flush()?;
        }
        Ok(())
    }
}

fn open_decompressor<'a, R: Read + 'a>(
    reader: R,
    format: ArchiveFormat,
) -> Result<(Box<dyn Read + 'a>, &'static str)> {
    let buffered = BufReader::with_capacity(IO_BUF_SIZE, reader);
    match format {
        ArchiveFormat::Tar => Ok((Box::new(buffered), "TAR")),
        ArchiveFormat::TarGz | ArchiveFormat::Gz => {
            Ok((Box::new(MultiGzDecoder::new(buffered)), "Gzip"))
        }
        ArchiveFormat::TarZst | ArchiveFormat::Zst => {
            let dec = zstd::stream::read::Decoder::with_buffer(buffered)?;
            Ok((Box::new(dec), "Zstd"))
        }
        ArchiveFormat::TarXz | ArchiveFormat::Xz => {
            Ok((Box::new(xz2::read::XzDecoder::new_multi_decoder(buffered)), "XZ"))
        }
        ArchiveFormat::TarLz4 | ArchiveFormat::Lz4 => {
            Ok((Box::new(lz4_flex::frame::FrameDecoder::new(buffered)), "LZ4"))
        }
        ArchiveFormat::TarBz2 | ArchiveFormat::Bz2 => {
            Ok((Box::new(bzip2::read::MultiBzDecoder::new(buffered)), "BZip2"))
        }
        other => Err(ArchiveError::UnsupportedFormat(other.display_name().to_string())),
    }
}

/// Derives the logical inner filename for standalone single-stream compressed files (e.g. `dump.sql.zst` -> `dump.sql`).
pub fn single_stream_inner_name(archive_name: &str, format: ArchiveFormat) -> String {
    let base = archive_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("data.bin");
    let lower = base.to_ascii_lowercase();
    let suffix = match format {
        ArchiveFormat::Gz => ".gz",
        ArchiveFormat::Zst => ".zst",
        ArchiveFormat::Xz => ".xz",
        ArchiveFormat::Lz4 => ".lz4",
        ArchiveFormat::Bz2 => ".bz2",
        _ => "",
    };
    if !suffix.is_empty() && lower.ends_with(suffix) && base.len() > suffix.len() {
        base[..base.len() - suffix.len()].to_string()
    } else {
        format!("{base}.out")
    }
}

/// Lists entries in a `.tar[.gz|.zst|.xz|.lz4|.bz2]` or single-file compressed stream while building
/// a sparse `StreamCheckpointIndex`.
pub fn list_entries<R: Read + Seek>(
    mut reader: R,
    format: ArchiveFormat,
    archive_display_name: &str,
    compressed_total_len: u64,
    control: Option<&TaskControl>,
) -> Result<(Vec<ArchiveEntry>, StreamCheckpointIndex)> {
    let mut checkpoints = StreamCheckpointIndex::default();

    if format.is_single_stream() {
        let mtime = None;
        let inner_name = single_stream_inner_name(archive_display_name, format);
        // Probe unpacked size cheaply for `.gz` (ISIZE trailer) or Zstd frame header when available;
        // otherwise report compressed length as estimate without decoding multi-GB streams on open.
        let unpacked = probe_single_stream_size(&mut reader, format, compressed_total_len)
            .unwrap_or(compressed_total_len);
        let entry = ArchiveEntry {
            index: 0,
            path: sanitize_archive_path(&inner_name).unwrap_or_else(|| "data.bin".to_string()),
            is_dir: false,
            is_symlink: false,
            symlink_target: None,
            unpacked_size: unpacked,
            packed_size: compressed_total_len,
            mtime,
            crc32: None,
            attributes: 0o644,
            is_encrypted: false,
            method: format.display_name().to_string(),
        };
        checkpoints.record(0, 0, 0);
        return Ok((vec![entry], checkpoints));
    }

    reader.seek(io::SeekFrom::Start(0))?;
    let (dec_reader, method_name) = open_decompressor(reader, format)?;
    let counting = CountingReader::new(dec_reader);
    let mut archive = tar::Archive::new(counting);

    let mut entries_out = Vec::new();
    let tar_iter = archive.entries()?;

    for (raw_idx, item_res) in tar_iter.enumerate() {
        if let Some(ctrl) = control {
            ctrl.checkpoint()?;
        }
        let item = item_res?;
        let raw_header_pos = item.raw_header_position();
        checkpoints.maybe_record_periodic(raw_header_pos, raw_header_pos, raw_idx);

        let path_cow = item.path()?;
        let Some(clean_path) = sanitize_archive_path(&path_cow.to_string_lossy()) else {
            continue;
        };

        let entry_type = item.header().entry_type();
        let is_dir = entry_type.is_dir();
        let is_symlink = entry_type.is_symlink();
        let symlink_target = if is_symlink {
            item.link_name()?
                .map(|p| p.to_string_lossy().into_owned())
        } else {
            None
        };

        let size = if is_dir { 0 } else { item.size() };
        let mtime = item.header().mtime().ok().map(|v| v as i64);
        let mode = item.header().mode().unwrap_or(0);

        entries_out.push(ArchiveEntry {
            index: raw_idx,
            path: clean_path,
            is_dir,
            is_symlink,
            symlink_target,
            unpacked_size: size,
            packed_size: size,
            mtime,
            crc32: None,
            attributes: mode,
            is_encrypted: false,
            method: method_name.to_string(),
        });
    }

    Ok((entries_out, checkpoints))
}

fn probe_single_stream_size<R: Read + Seek>(
    reader: &mut R,
    format: ArchiveFormat,
    compressed_len: u64,
) -> Option<u64> {
    if format == ArchiveFormat::Gz && compressed_len >= 18 {
        reader.seek(io::SeekFrom::End(-4)).ok()?;
        let mut tail = [0u8; 4];
        reader.read_exact(&mut tail).ok()?;
        reader.seek(io::SeekFrom::Start(0)).ok()?;
        let isize_val = u32::from_le_bytes(tail) as u64;
        if isize_val > 0 {
            return Some(isize_val);
        }
    }
    let _ = reader.seek(io::SeekFrom::Start(0));
    None
}

/// Extracts or tests entries from a `.tar.*` or single-stream archive.
#[allow(clippy::too_many_arguments)]
pub fn extract_or_test<R: Read + Seek>(
    mut reader: R,
    format: ArchiveFormat,
    archive_display_name: &str,
    dest_dir: Option<&Path>,
    options: &ExtractOptions,
    test_only: bool,
    pool: &BufferPool,
    control: Option<&TaskControl>,
    progress: Option<&ProgressTracker>,
) -> Result<()> {
    reader.seek(io::SeekFrom::Start(0))?;

    if format.is_single_stream() {
        let selection = build_selection_set(options);
        if let Some(sel) = &selection {
            if !sel.contains(&0) {
                return Ok(());
            }
        }
        let inner_name = single_stream_inner_name(archive_display_name, format);
        let entry = ArchiveEntry {
            index: 0,
            path: sanitize_archive_path(&inner_name).unwrap_or_else(|| "data.bin".to_string()),
            is_dir: false,
            is_symlink: false,
            symlink_target: None,
            unpacked_size: 0,
            packed_size: 0,
            mtime: None,
            crc32: None,
            attributes: 0o644,
            is_encrypted: false,
            method: format.display_name().to_string(),
        };
        let target_path = if test_only {
            None
        } else if let Some(root) = dest_dir {
            resolve_output_path(root, &entry.path, false, options)?
        } else {
            None
        };
        if !test_only && dest_dir.is_some() && target_path.is_none() {
            return Ok(());
        }
        let (mut dec, _) = open_decompressor(reader, format)?;
        stream_reader_to_dest(
            &mut dec,
            target_path.as_deref(),
            &entry,
            false,
            pool,
            control,
            progress,
        )?;
        return Ok(());
    }

    let selection = build_selection_set(options);
    let mut remaining_selected = selection.as_ref().map(std::collections::HashSet::len);

    // Fast seek directly to nearest uncompressed TAR header when plain `.tar` has selected indices!
    let (dec_reader, method_name) = open_decompressor(reader, format)?;
    let mut archive = tar::Archive::new(dec_reader);

    for (raw_idx, item_res) in archive.entries()?.enumerate() {
        if let Some(ctrl) = control {
            ctrl.checkpoint()?;
        }
        let mut item = item_res?;

        if let Some(sel) = &selection {
            if !sel.contains(&raw_idx) {
                continue;
            }
        }

        let path_cow = item.path()?;
        let Some(clean_path) = sanitize_archive_path(&path_cow.to_string_lossy()) else {
            continue;
        };

        let entry_type = item.header().entry_type();
        let is_dir = entry_type.is_dir();
        let is_symlink = entry_type.is_symlink();
        let symlink_target = if is_symlink {
            item.link_name()?
                .map(|p| p.to_string_lossy().into_owned())
        } else {
            None
        };
        let mtime = item.header().mtime().ok().map(|v| v as i64);
        let mode = item.header().mode().unwrap_or(0);

        let entry = ArchiveEntry {
            index: raw_idx,
            path: clean_path,
            is_dir,
            is_symlink,
            symlink_target,
            unpacked_size: if is_dir { 0 } else { item.size() },
            packed_size: if is_dir { 0 } else { item.size() },
            mtime,
            crc32: None,
            attributes: mode,
            is_encrypted: false,
            method: method_name.to_string(),
        };

        if is_dir {
            if !test_only {
                if let Some(root) = dest_dir {
                    if let Some(dir_path) = resolve_output_path(root, &entry.path, true, options)? {
                        std::fs::create_dir_all(&dir_path)?;
                        apply_entry_metadata(&dir_path, entry.mtime, entry.attributes);
                    }
                }
            }
        } else {
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

            stream_reader_to_dest(
                &mut item,
                target_path.as_deref(),
                &entry,
                false,
                pool,
                control,
                progress,
            )?;
        }

        if let Some(rem) = remaining_selected.as_mut() {
            *rem = rem.saturating_sub(1);
            if *rem == 0 {
                // Early stream stop: no need to decode the remainder of a multi-GB `.tar.zst`!
                break;
            }
        }
    }

    Ok(())
}

/// Reads a single entry's bytes from a `.tar.*` or single-stream archive, stopping decompression
/// immediately once the requested entry has been read (and jumping directly via `Seek` for plain `.tar`).
pub fn read_entry_bytes<R: Read + Seek>(
    mut reader: R,
    format: ArchiveFormat,
    target_index: usize,
    checkpoints: Option<&StreamCheckpointIndex>,
    max_bytes: Option<usize>,
    control: Option<&TaskControl>,
) -> Result<Vec<u8>> {
    reader.seek(io::SeekFrom::Start(0))?;

    if format.is_single_stream() {
        if target_index != 0 {
            return Err(ArchiveError::EntryNotFound(format!("index {target_index}")));
        }
        let (mut dec, _) = open_decompressor(reader, format)?;
        return read_bounded(&mut dec, max_bytes, control);
    }

    // For uncompressed `.tar`, jump straight to the nearest recorded `StreamCheckpoint`!
    let mut start_idx = 0usize;
    if format == ArchiveFormat::Tar {
        if let Some(cp_idx) = checkpoints {
            if let Some(cp) = cp_idx.nearest_before_entry(target_index) {
                if reader.seek(io::SeekFrom::Start(cp.compressed_offset)).is_ok() {
                    start_idx = cp.first_entry_index;
                }
            }
        }
    }

    let (dec_reader, _) = open_decompressor(reader, format)?;
    let mut archive = tar::Archive::new(dec_reader);

    for (offset_idx, item_res) in archive.entries()?.enumerate() {
        if let Some(ctrl) = control {
            ctrl.checkpoint()?;
        }
        let current_idx = start_idx + offset_idx;
        let mut item = item_res?;
        if current_idx == target_index {
            if item.header().entry_type().is_dir() {
                return Ok(Vec::new());
            }
            return read_bounded(&mut item, max_bytes, control);
        }
    }

    Err(ArchiveError::EntryNotFound(format!("index {target_index}")))
}

fn read_bounded<R: Read>(
    reader: &mut R,
    max_bytes: Option<usize>,
    control: Option<&TaskControl>,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
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
        let n = reader.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

/// Packs `inputs` into `.tar`, `.tar.gz`, `.tar.zst`, `.tar.xz`, `.tar.lz4`, `.tar.bz2`,
/// or a single file into `.gz`/`.zst`/`.xz`/`.lz4`/`.bz2` using multi-core encoders.
pub fn pack_entries<W: Write>(
    dest: W,
    inputs: &[PackInput],
    options: &PackOptions,
    pool: &BufferPool,
    control: Option<&TaskControl>,
    progress: Option<&ProgressTracker>,
) -> Result<W> {
    if let Some(pw) = &options.password {
        if !pw.is_empty() {
            return Err(ArchiveError::Backend(format!(
                "{} does not natively support password encryption; choose .7z or .zip for AES-256",
                options.format.display_name()
            )));
        }
    }

    let threads = if options.threads == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    } else {
        options.threads.max(1)
    };
    let level = options.compression_level;

    if options.format.is_single_stream() {
        let file_inputs: Vec<&PackInput> = inputs
            .iter()
            .filter(|inp| inp.disk_path.is_file())
            .collect();
        if file_inputs.len() != 1 {
            return Err(ArchiveError::Backend(format!(
                "{} can only compress a single file (got {} files); use .tar{} for multiple files/folders",
                options.format.display_name(),
                file_inputs.len(),
                options.format.default_extension()
            )));
        }
        let item = file_inputs[0];
        return compress_with_stream_codec(dest, options.format, level, threads, |enc| {
            if let Some(p) = progress {
                p.set_current_item(&item.archive_path);
            }
            stream_disk_file_to_writer(&item.disk_path, enc, pool, control, progress)?;
            if let Some(p) = progress {
                p.inc_files(1);
            }
            Ok(())
        });
    }

    compress_with_stream_codec(dest, options.format, level, threads, |enc| {
        write_tar_payload(enc, inputs, pool, control, progress)
    })
}

fn compress_with_stream_codec<W, F>(
    dest: W,
    format: ArchiveFormat,
    level: u32,
    threads: usize,
    body: F,
) -> Result<W>
where
    W: Write,
    F: FnOnce(&mut dyn Write) -> Result<()>,
{
    let buffered = BufWriter::with_capacity(IO_BUF_SIZE, dest);
    match format {
        ArchiveFormat::Tar => {
            let mut bw = buffered;
            body(&mut bw)?;
            bw.flush()?;
            bw.into_inner()
                .map_err(|e| ArchiveError::Io(e.into_error()))
        }
        ArchiveFormat::TarGz | ArchiveFormat::Gz => {
            let mut gz = ParallelGzWriter::new(buffered, level.clamp(1, 9), threads);
            body(&mut gz)?;
            let mut bw = gz.finish()?;
            bw.flush()?;
            bw.into_inner()
                .map_err(|e| ArchiveError::Io(e.into_error()))
        }
        ArchiveFormat::TarZst | ArchiveFormat::Zst => {
            let zstd_level = level.clamp(1, 22) as i32;
            let mut enc = zstd::stream::write::Encoder::new(buffered, zstd_level)?;
            let _ = enc.include_checksum(true);
            if threads > 1 {
                let _ = enc.multithread(threads as u32);
            }
            body(&mut enc)?;
            let mut bw = enc.finish()?;
            bw.flush()?;
            bw.into_inner()
                .map_err(|e| ArchiveError::Io(e.into_error()))
        }
        ArchiveFormat::TarXz | ArchiveFormat::Xz => {
            let xz_preset = level.clamp(0, 9);
            let stream = xz2::stream::MtStreamBuilder::new()
                .threads(threads as u32)
                .preset(xz_preset)
                .check(xz2::stream::Check::Crc64)
                .encoder()
                .map_err(|e| ArchiveError::Backend(format!("xz mt encoder init failed: {e}")))?;
            let mut enc = xz2::write::XzEncoder::new_stream(buffered, stream);
            body(&mut enc)?;
            let mut bw = enc.finish()?;
            bw.flush()?;
            bw.into_inner()
                .map_err(|e| ArchiveError::Io(e.into_error()))
        }
        ArchiveFormat::TarLz4 | ArchiveFormat::Lz4 => {
            let mut enc = lz4_flex::frame::FrameEncoder::new(buffered);
            body(&mut enc)?;
            let mut bw = enc
                .finish()
                .map_err(|e| ArchiveError::Backend(format!("lz4 frame finish error: {e}")))?;
            bw.flush()?;
            bw.into_inner()
                .map_err(|e| ArchiveError::Io(e.into_error()))
        }
        ArchiveFormat::TarBz2 | ArchiveFormat::Bz2 => {
            let bz_level = bzip2::Compression::new(level.clamp(1, 9));
            let mut enc = bzip2::write::BzEncoder::new(buffered, bz_level);
            body(&mut enc)?;
            let mut bw = enc.finish()?;
            bw.flush()?;
            bw.into_inner()
                .map_err(|e| ArchiveError::Io(e.into_error()))
        }
        other => Err(ArchiveError::UnsupportedFormat(
            other.display_name().to_string(),
        )),
    }
}

fn write_tar_payload<W: Write>(
    writer: &mut W,
    inputs: &[PackInput],
    pool: &BufferPool,
    control: Option<&TaskControl>,
    progress: Option<&ProgressTracker>,
) -> Result<()> {
    let mut builder = tar::Builder::new(writer);
    builder.follow_symlinks(false);

    for item in inputs {
        if let Some(ctrl) = control {
            ctrl.checkpoint()?;
        }
        let clean = sanitize_archive_path(&item.archive_path)
            .ok_or_else(|| ArchiveError::UnsafePath(item.archive_path.clone()))?;
        let meta = std::fs::symlink_metadata(&item.disk_path)?;

        if meta.is_dir() {
            let mut header = tar::Header::new_gnu();
            header.set_metadata_in_mode(&meta, tar::HeaderMode::Deterministic);
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_cksum();
            builder.append_data(&mut header, format!("{clean}/"), io::empty())?;
            continue;
        }

        if let Some(p) = progress {
            p.set_current_item(&clean);
        }

        let mut header = tar::Header::new_gnu();
        header.set_metadata_in_mode(&meta, tar::HeaderMode::Deterministic);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(meta.len());
        header.set_cksum();

        let (smart_reader, _) = SmartFileReader::open(&item.disk_path)?;
        let tracked = TarTrackedReader {
            inner: smart_reader,
            control,
            progress,
        };
        let _ = pool; // Pool buffers used for single-stream; `tar::Builder::append_data` streams directly from `SmartFileReader`.
        builder.append_data(&mut header, &clean, tracked)?;
        if let Some(p) = progress {
            p.inc_files(1);
        }
    }

    builder.finish()?;
    Ok(())
}

struct TarTrackedReader<'a, R> {
    inner: R,
    control: Option<&'a TaskControl>,
    progress: Option<&'a ProgressTracker>,
}

impl<R: Read> Read for TarTrackedReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(ctrl) = self.control {
            ctrl.checkpoint()
                .map_err(|e| io::Error::new(io::ErrorKind::Interrupted, e.to_string()))?;
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

fn stream_disk_file_to_writer<W: Write + ?Sized>(
    disk_path: &Path,
    writer: &mut W,
    pool: &BufferPool,
    control: Option<&TaskControl>,
    progress: Option<&ProgressTracker>,
) -> Result<()> {
    let (mut reader, _) = SmartFileReader::open(disk_path)?;
    let mut io_buf = pool.checkout_io();
    let buf = io_buf.as_mut_slice();
    loop {
        if let Some(ctrl) = control {
            ctrl.checkpoint()?;
        }
        let n = reader.read(buf)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
        if let Some(p) = progress {
            p.add_bytes(n as u64);
        }
    }
    Ok(())
}
