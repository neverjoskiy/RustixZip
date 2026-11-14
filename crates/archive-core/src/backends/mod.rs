//! Shared extraction sink, overwrite/rename policy, and filesystem input walker for native
//! and plugin-backed archive backends.

pub mod sevenz_backend;
pub mod tar_stream_backend;
pub mod zip_backend;

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use filetime::{set_file_mtime, FileTime};

use crate::error::{ArchiveError, Result};
use crate::memory::{BufferPool, IO_BUF_SIZE};
use crate::progress::{ProgressTracker, TaskControl};
use crate::types::{
    sanitize_archive_path, ArchiveEntry, ExtractOptions, OverwritePolicy, PackInput,
};

/// Expands a list of user-supplied files/directories into normalized `PackInput` items,
/// preserving empty directories as explicit directory entries (trailing `/`).
pub fn collect_pack_inputs(sources: &[PathBuf], base_prefix_inside_archive: &str) -> Result<Vec<PackInput>> {
    let clean_prefix = base_prefix_inside_archive
        .replace('\\', "/")
        .trim_matches('/')
        .to_string();

    let mut out = Vec::new();
    for src in sources {
        if !src.exists() {
            return Err(ArchiveError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("input path does not exist: {}", src.display()),
            )));
        }
        let root_name = src
            .file_name()
            .and_then(|n| n.to_str())
            .or_else(|| {
                src.canonicalize()
                    .ok()
                    .and_then(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_owned))
                    .as_deref()
                    .map(|_| "")
            })
            .unwrap_or("root");

        if src.is_file() || src.is_symlink() {
            let archive_path = join_virtual(&clean_prefix, root_name);
            out.push(PackInput {
                disk_path: src.clone(),
                archive_path,
            });
        } else if src.is_dir() {
            let base_parent = src.parent().unwrap_or_else(|| Path::new(""));
            for entry in walkdir::WalkDir::new(src).follow_links(false) {
                let entry = entry.map_err(|e| ArchiveError::Io(io::Error::other(e.to_string())))?;
                let disk_path = entry.path().to_path_buf();
                let rel = disk_path.strip_prefix(base_parent).unwrap_or(&disk_path);
                let rel_slash = rel
                    .components()
                    .filter_map(|c| match c {
                        std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("/");
                if rel_slash.is_empty() {
                    continue;
                }
                let mut archive_path = join_virtual(&clean_prefix, &rel_slash);
                if entry.file_type().is_dir() && !archive_path.ends_with('/') {
                    archive_path.push('/');
                }
                out.push(PackInput {
                    disk_path,
                    archive_path,
                });
            }
        }
    }
    Ok(out)
}

pub fn join_virtual(prefix: &str, child: &str) -> String {
    let p = prefix.trim_matches('/');
    let c = child.trim_start_matches('/');
    if p.is_empty() {
        c.to_string()
    } else if c.is_empty() {
        p.to_string()
    } else {
        format!("{p}/{c}")
    }
}

/// Computes the safe destination path on disk for an archive entry according to `ExtractOptions`.
/// Returns `Ok(None)` when `strip_prefix` filters out an entry outside the requested subtree,
/// or when `SkipExisting` skips an already-existing file.
pub fn resolve_output_path(
    dest_dir: &Path,
    entry_virtual_path: &str,
    is_dir: bool,
    options: &ExtractOptions,
) -> Result<Option<PathBuf>> {
    let clean = sanitize_archive_path(entry_virtual_path)
        .ok_or_else(|| ArchiveError::UnsafePath(entry_virtual_path.to_string()))?;

    let stripped = if let Some(prefix) = &options.strip_prefix {
        let norm_prefix = prefix.replace('\\', "/");
        let norm_prefix = norm_prefix.trim_matches('/');
        if norm_prefix.is_empty() {
            clean.as_str()
        } else if clean == norm_prefix {
            ""
        } else if let Some(rest) = clean.strip_prefix(norm_prefix) {
            if let Some(after_slash) = rest.strip_prefix('/') {
                after_slash
            } else {
                return Ok(None);
            }
        } else {
            return Ok(None);
        }
    } else {
        clean.as_str()
    };

    if stripped.is_empty() {
        return Ok(None);
    }

    let relative = if options.preserve_paths {
        stripped.to_string()
    } else {
        if is_dir {
            return Ok(None);
        }
        stripped
            .rsplit('/')
            .next()
            .unwrap_or(stripped)
            .to_string()
    };

    let mut target = dest_dir.to_path_buf();
    for seg in relative.split('/') {
        if !seg.is_empty() {
            target.push(seg);
        }
    }

    if is_dir {
        return Ok(Some(target));
    }

    if target.exists() {
        match options.overwrite {
            OverwritePolicy::Overwrite => Ok(Some(target)),
            OverwritePolicy::SkipExisting => Ok(None),
            OverwritePolicy::RenameAuto => Ok(Some(find_auto_rename_path(&target))),
        }
    } else {
        Ok(Some(target))
    }
}

fn find_auto_rename_path(original: &Path) -> PathBuf {
    let parent = original.parent().unwrap_or_else(|| Path::new("."));
    let stem = original
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let ext = original.extension().and_then(|e| e.to_str());
    for idx in 1u32..100_000 {
        let candidate_name = match ext {
            Some(e) if !e.is_empty() => format!("{stem}_{idx}.{e}"),
            _ => format!("{stem}_{idx}"),
        };
        let candidate = parent.join(candidate_name);
        if !candidate.exists() {
            return candidate;
        }
    }
    parent.join(format!("{stem}_copy"))
}

/// Applies modification timestamp (`mtime`) to an extracted file if available.
pub fn apply_entry_metadata(path: &Path, mtime_secs: Option<i64>, _attributes: u32) {
    if let Some(secs) = mtime_secs {
        if secs > 0 {
            let ft = FileTime::from_unix_time(secs, 0);
            let _ = set_file_mtime(path, ft);
        }
    }
    #[cfg(unix)]
    if _attributes != 0 {
        use std::os::unix::fs::PermissionsExt;
        let mode = _attributes & 0o7777;
        if mode != 0 {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
        }
    }
}

/// Builds an O(1) index filter set from `ExtractOptions::selected_indices`.
pub fn build_selection_set(options: &ExtractOptions) -> Option<HashSet<usize>> {
    options
        .selected_indices
        .as_ref()
        .map(|v| v.iter().copied().collect())
}

/// Copies a reader to a file (or null sink when `test_only == true`), updating progress,
/// checking pause/cancel, and computing optional CRC32 verification.
pub fn stream_reader_to_dest<R: Read>(
    reader: &mut R,
    dest_path: Option<&Path>,
    entry: &ArchiveEntry,
    verify_crc: bool,
    pool: &BufferPool,
    control: Option<&TaskControl>,
    progress: Option<&ProgressTracker>,
) -> Result<()> {
    if let Some(p) = progress {
        p.set_current_item(&entry.path);
    }

    let mut writer = if let Some(target) = dest_path {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(target)?;
        Some(BufWriter::with_capacity(IO_BUF_SIZE, file))
    } else {
        None
    };

    let mut io_buf = pool.checkout_io();
    let buf = io_buf.as_mut_slice();
    let mut hasher = crc32fast::Hasher::new();

    loop {
        if let Some(ctrl) = control {
            ctrl.checkpoint()?;
        }
        let n = reader.read(buf)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        if verify_crc && entry.crc32.is_some() {
            hasher.update(chunk);
        }
        if let Some(w) = writer.as_mut() {
            w.write_all(chunk)?;
        }
        if let Some(p) = progress {
            p.add_bytes(n as u64);
        }
    }

    if let Some(mut w) = writer {
        w.flush()?;
    }

    if verify_crc {
        if let Some(expected_crc) = entry.crc32 {
            let actual_crc = hasher.finalize();
            if actual_crc != expected_crc {
                return Err(ArchiveError::ChecksumMismatch {
                    entry: entry.path.clone(),
                    expected: format!("{expected_crc:08X}"),
                    actual: format!("{actual_crc:08X}"),
                });
            }
        }
    }

    if let Some(target) = dest_path {
        apply_entry_metadata(target, entry.mtime, entry.attributes);
    }
    if let Some(p) = progress {
        p.inc_files(1);
    }
    Ok(())
}

/// Stateful sink used when extracting/testing via callback-driven backends (`.7z`, plugins).
pub struct DiskExtractSink<'a> {
    dest_dir: Option<&'a Path>,
    options: &'a ExtractOptions,
    test_only: bool,
    progress: Option<&'a ProgressTracker>,
    active_entry: Option<ArchiveEntry>,
    active_path: Option<PathBuf>,
    active_writer: Option<BufWriter<File>>,
    active_crc: crc32fast::Hasher,
}

impl<'a> DiskExtractSink<'a> {
    pub fn new(
        dest_dir: Option<&'a Path>,
        options: &'a ExtractOptions,
        test_only: bool,
        progress: Option<&'a ProgressTracker>,
    ) -> Self {
        Self {
            dest_dir,
            options,
            test_only,
            progress,
            active_entry: None,
            active_path: None,
            active_writer: None,
            active_crc: crc32fast::Hasher::new(),
        }
    }

    pub fn begin_entry(&mut self, entry: &ArchiveEntry) -> Result<()> {
        if let Some(p) = self.progress {
            p.set_current_item(&entry.path);
        }
        self.active_entry = Some(entry.clone());
        self.active_crc = crc32fast::Hasher::new();
        self.active_writer = None;
        self.active_path = None;

        if self.test_only {
            return Ok(());
        }
        let Some(dest_root) = self.dest_dir else {
            return Ok(());
        };
        let Some(out_path) =
            resolve_output_path(dest_root, &entry.path, entry.is_dir, self.options)?
        else {
            return Ok(());
        };

        if entry.is_dir {
            std::fs::create_dir_all(&out_path)?;
            apply_entry_metadata(&out_path, entry.mtime, entry.attributes);
            return Ok(());
        }

        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        if entry.is_symlink {
            if let Some(link_target) = &entry.symlink_target {
                if sanitize_archive_path(link_target).is_some() {
                    let _ = create_safe_symlink(link_target, &out_path);
                    return Ok(());
                }
            }
        }

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&out_path)?;
        self.active_writer = Some(BufWriter::with_capacity(IO_BUF_SIZE, file));
        self.active_path = Some(out_path);
        Ok(())
    }

    pub fn write_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        if chunk.is_empty() {
            return Ok(());
        }
        if let Some(entry) = &self.active_entry {
            if entry.crc32.is_some() {
                self.active_crc.update(chunk);
            }
        }
        if let Some(w) = self.active_writer.as_mut() {
            w.write_all(chunk)?;
        }
        if let Some(p) = self.progress {
            p.add_bytes(chunk.len() as u64);
        }
        Ok(())
    }

    pub fn finish_entry(&mut self) -> Result<()> {
        if let Some(mut w) = self.active_writer.take() {
            w.flush()?;
        }
        if let Some(entry) = self.active_entry.take() {
            if (self.test_only || self.active_path.is_some()) && !entry.is_dir {
                if let Some(expected_crc) = entry.crc32 {
                    let actual_crc = self.active_crc.clone().finalize();
                    if actual_crc != expected_crc {
                        return Err(ArchiveError::ChecksumMismatch {
                            entry: entry.path,
                            expected: format!("{expected_crc:08X}"),
                            actual: format!("{actual_crc:08X}"),
                        });
                    }
                }
            }
            if let Some(path) = self.active_path.take() {
                apply_entry_metadata(&path, entry.mtime, entry.attributes);
            }
            if let Some(p) = self.progress {
                p.inc_files(1);
            }
        }
        Ok(())
    }
}

fn create_safe_symlink(target: &str, link_path: &Path) -> io::Result<()> {
    let _ = std::fs::remove_file(link_path);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link_path)
    }
    #[cfg(windows)]
    {
        // On non-elevated Windows accounts without Developer Mode, symlink creation may fail;
        // write the link target text fallback only if OS symlink fails.
        std::os::windows::fs::symlink_file(target, link_path)
            .or_else(|_| std::fs::write(link_path, target.as_bytes()))
    }
}
