//! High-level multi-format `ArchiveEngine`, `OpenArchive`, and recursive `VfsMountStack`.
//!
//! Coordinates native multi-core Rust backends (`.7z`, `.zip`, `.tar.*`, single-stream codecs),
//! dynamic C-ABI plugins (`.rar`, `.iso`, `.cab`, `.wim`, `.dmg`, `.deb`, `.rpm`, `.msi`, etc.),
//! transparent `.001` split-volume streams, in-memory/temp nested archive mounting, and atomic
//! archive updates (Add / Delete / Live-Edit save-back).

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use parking_lot::RwLock;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::backends::{
    build_selection_set, collect_pack_inputs, sevenz_backend, tar_stream_backend, zip_backend,
    DiskExtractSink,
};
use crate::error::{ArchiveError, Result};
use crate::memory::{BufferPool, IO_BUF_SIZE};
use crate::plugin_host::PluginRegistry;
use crate::progress::{ProgressTracker, TaskControl};
use crate::split::{resolve_volume_paths, SplitVolumeReader, SplitVolumeWriter};
use crate::types::{
    sanitize_archive_path, ArchiveEntry, ArchiveFormat, ArchiveSummary, ExtractOptions,
    OverwritePolicy, PackInput, PackOptions,
};
use crate::vfs::{
    NestedBacking, NodeId, StreamCheckpointIndex, VfsTree, NESTED_RAM_THRESHOLD_BYTES,
};

/// Unified `Read + Seek` stream over a disk file, `.001` split volume set, RAM buffer, or temp file.
pub enum ArchiveSourceStream {
    Disk(SplitVolumeReader),
    Memory(Cursor<Arc<[u8]>>),
    TempFile(BufReader<File>),
}

impl Read for ArchiveSourceStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Disk(r) => r.read(buf),
            Self::Memory(c) => c.read(buf),
            Self::TempFile(f) => f.read(buf),
        }
    }
}

impl Seek for ArchiveSourceStream {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match self {
            Self::Disk(r) => r.seek(pos),
            Self::Memory(c) => c.seek(pos),
            Self::TempFile(f) => f.seek(pos),
        }
    }
}

/// An opened and indexed archive layer ready for instant VFS browsing, previewing, or extraction.
#[derive(Debug)]
pub struct OpenArchive {
    pub format: ArchiveFormat,
    pub display_name: String,
    pub backing: NestedBacking,
    pub entries: Vec<ArchiveEntry>,
    pub vfs: VfsTree,
    pub checkpoints: Option<StreamCheckpointIndex>,
    pub compressed_size: u64,
    pub volume_count: usize,
    pub has_encrypted_entries: bool,
    pub password: Option<Zeroizing<String>>,
}

impl OpenArchive {
    /// Opens a fresh independent `Read + Seek` stream positioned at byte 0.
    pub fn open_stream(&self) -> Result<(ArchiveSourceStream, u64, Option<PathBuf>)> {
        match &self.backing {
            NestedBacking::RootDiskPath(path) => {
                let reader = SplitVolumeReader::open(path)?;
                let len = reader.total_len();
                let disk_path = if reader.volume_count() == 1 {
                    reader.primary_path().map(Path::to_path_buf)
                } else {
                    Some(path.clone())
                };
                Ok((ArchiveSourceStream::Disk(reader), len, disk_path))
            }
            NestedBacking::InMemory { bytes, .. } => {
                let len = bytes.len() as u64;
                Ok((
                    ArchiveSourceStream::Memory(Cursor::new(Arc::clone(bytes))),
                    len,
                    None,
                ))
            }
            NestedBacking::TempFile { temp_file, .. } => {
                let reopened = temp_file.reopen()?;
                let len = reopened.metadata()?.len();
                Ok((
                    ArchiveSourceStream::TempFile(BufReader::with_capacity(IO_BUF_SIZE, reopened)),
                    len,
                    Some(temp_file.path().to_path_buf()),
                ))
            }
        }
    }

    pub fn disk_path(&self) -> Option<&Path> {
        match &self.backing {
            NestedBacking::RootDiskPath(p) => Some(p.as_path()),
            _ => None,
        }
    }

    pub fn total_unpacked_size(&self) -> u64 {
        self.entries
            .iter()
            .filter(|e| !e.is_dir)
            .map(|e| e.unpacked_size)
            .sum()
    }

    pub fn file_count(&self) -> usize {
        self.entries.iter().filter(|e| !e.is_dir).count()
    }

    pub fn dir_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_dir).count()
    }

    pub fn summary(&self) -> ArchiveSummary {
        let total_unpacked_size = self.total_unpacked_size();
        let total_packed_size: u64 = self.entries.iter().map(|e| e.packed_size).sum();
        let encrypted_entries = self.entries.iter().filter(|e| e.is_encrypted).count();
        ArchiveSummary {
            format: self.format,
            physical_size: self.compressed_size,
            total_unpacked_size,
            total_packed_size: if total_packed_size > 0 {
                total_packed_size
            } else {
                self.compressed_size
            },
            file_count: self.file_count(),
            dir_count: self.dir_count(),
            encrypted_entries,
            volume_count: self.volume_count,
            is_solid: matches!(
                self.format,
                ArchiveFormat::SevenZip
                    | ArchiveFormat::TarGz
                    | ArchiveFormat::TarZst
                    | ArchiveFormat::TarXz
                    | ArchiveFormat::TarLz4
                    | ArchiveFormat::TarBz2
            ),
        }
    }
}

/// One segment in the unified GUI/CLI breadcrumb bar across nested archives and subfolders.
#[derive(Debug, Clone)]
pub struct BreadcrumbSegment {
    pub label: String,
    pub layer_index: usize,
    pub node_id: NodeId,
    pub is_archive_boundary: bool,
}

/// Outcome of activating (`Enter` / double-clicking) a node inside `VfsMountStack`.
#[derive(Debug, Clone)]
pub enum EnterOutcome {
    EnteredDirectory(NodeId),
    MountedNestedArchive,
    LeafFile {
        backend_index: usize,
        virtual_path: String,
    },
}

/// Single mounted layer within `VfsMountStack`.
#[derive(Debug)]
pub struct MountLayer {
    pub archive: OpenArchive,
    pub current_dir: NodeId,
    pub parent_virtual_path: Option<String>,
}

/// Recursive VFS navigation stack (`outer.7z -> inner.tar.zst -> pkg.deb`).
#[derive(Debug)]
pub struct VfsMountStack {
    layers: Vec<MountLayer>,
}

impl VfsMountStack {
    pub fn open_root(
        engine: &ArchiveEngine,
        path: &Path,
        password: Option<Zeroizing<String>>,
        control: Option<&TaskControl>,
    ) -> Result<Self> {
        let archive = engine.open_path(path, password, control)?;
        Ok(Self {
            layers: vec![MountLayer {
                archive,
                current_dir: NodeId::ROOT,
                parent_virtual_path: None,
            }],
        })
    }

    pub fn from_open_archive(archive: OpenArchive) -> Self {
        Self {
            layers: vec![MountLayer {
                archive,
                current_dir: NodeId::ROOT,
                parent_virtual_path: None,
            }],
        }
    }

    pub fn depth(&self) -> usize {
        self.layers.len()
    }

    pub fn layers(&self) -> &[MountLayer] {
        &self.layers
    }

    pub fn active(&self) -> &MountLayer {
        self.layers
            .last()
            .expect("VfsMountStack always contains at least the root layer")
    }

    pub fn active_mut(&mut self) -> &mut MountLayer {
        self.layers
            .last_mut()
            .expect("VfsMountStack always contains at least the root layer")
    }

    pub fn root_archive(&self) -> &OpenArchive {
        &self.layers[0].archive
    }

    /// Enters a folder, mounts a nested archive transparently, or reports a regular leaf file.
    pub fn enter_node(
        &mut self,
        engine: &ArchiveEngine,
        node_id: NodeId,
        password: Option<Zeroizing<String>>,
        control: Option<&TaskControl>,
    ) -> Result<EnterOutcome> {
        let (is_dir, backend_idx, name_hint, virtual_path) = {
            let top = self.active();
            let node = top.archive.vfs.node(node_id);
            (
                node.is_dir(),
                node.entry_index(),
                top.archive.vfs.node_name(node_id).to_string(),
                top.archive.vfs.full_path(node_id),
            )
        };

        if is_dir {
            self.active_mut().current_dir = node_id;
            return Ok(EnterOutcome::EnteredDirectory(node_id));
        }

        let Some(entry_index) = backend_idx else {
            return Err(ArchiveError::EntryNotFound(virtual_path));
        };

        if ArchiveFormat::detect_from_filename(&name_hint).is_some() {
            let effective_pw = password.or_else(|| self.active().archive.password.clone());
            if let Ok(nested_archive) =
                engine.open_nested(&self.active().archive, entry_index, effective_pw, control)
            {
                self.layers.push(MountLayer {
                    archive: nested_archive,
                    current_dir: NodeId::ROOT,
                    parent_virtual_path: Some(virtual_path),
                });
                return Ok(EnterOutcome::MountedNestedArchive);
            }
        }

        Ok(EnterOutcome::LeafFile {
            backend_index: entry_index,
            virtual_path,
        })
    }

    /// Navigates to the parent folder, popping nested archive layers automatically when at root.
    pub fn navigate_up(&mut self) -> bool {
        let current = self.active().current_dir;
        if current != NodeId::ROOT {
            if let Some(parent) = self.active().archive.vfs.node(current).parent {
                self.active_mut().current_dir = parent;
                return true;
            }
        }
        if self.layers.len() > 1 {
            self.layers.pop();
            return true;
        }
        false
    }

    /// Jumps directly to any breadcrumb segment (`layer_index` + `node_id`).
    pub fn jump_to(&mut self, layer_index: usize, node_id: NodeId) {
        if layer_index < self.layers.len() {
            self.layers.truncate(layer_index + 1);
            self.active_mut().current_dir = node_id;
        }
    }

    /// Returns unified breadcrumb segments across all mounted archive layers.
    pub fn breadcrumbs(&self) -> Vec<BreadcrumbSegment> {
        let mut out = Vec::new();
        for (layer_idx, layer) in self.layers.iter().enumerate() {
            out.push(BreadcrumbSegment {
                label: layer.archive.display_name.clone(),
                layer_index: layer_idx,
                node_id: NodeId::ROOT,
                is_archive_boundary: true,
            });
            let mut chain = Vec::new();
            let mut cursor = layer.current_dir;
            while cursor != NodeId::ROOT {
                chain.push(cursor);
                match layer.archive.vfs.node(cursor).parent {
                    Some(p) => cursor = p,
                    None => break,
                }
            }
            chain.reverse();
            for nid in chain {
                out.push(BreadcrumbSegment {
                    label: layer.archive.vfs.node_name(nid).to_string(),
                    layer_index: layer_idx,
                    node_id: nid,
                    is_archive_boundary: false,
                });
            }
        }
        out
    }
}

/// Thread-safe, multi-format archive engine shared across CLI commands and GUI worker threads.
#[derive(Clone)]
pub struct ArchiveEngine {
    pool: BufferPool,
    plugins: Arc<RwLock<PluginRegistry>>,
}

impl Default for ArchiveEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveEngine {
    /// Creates an engine with adaptive `BufferPool` sizing and discovers dynamic plugins from
    /// `<exe_dir>/plugins` and optional `RUSTIXZIP_PLUGIN_DIR`.
    pub fn new() -> Self {
        let pool = BufferPool::new_adaptive();
        let mut registry = PluginRegistry::new();

        for dir in default_plugin_search_dirs() {
            let _ = registry.load_from_dir(&dir);
        }

        Self {
            pool,
            plugins: Arc::new(RwLock::new(registry)),
        }
    }

    pub fn with_plugin_dir(dir: &Path) -> Result<Self> {
        let engine = Self::new();
        engine.load_plugins_from_dir(dir)?;
        Ok(engine)
    }

    pub fn load_plugins_from_dir(&self, dir: &Path) -> Result<usize> {
        self.plugins.write().load_from_dir(dir)
    }

    pub fn pool(&self) -> &BufferPool {
        &self.pool
    }

    pub fn plugins(&self) -> Arc<RwLock<PluginRegistry>> {
        Arc::clone(&self.plugins)
    }

    /// Detects `ArchiveFormat` from magic bytes (including ISO-9660 sector 16 `CD001` probe)
    /// combined with an optional filename hint.
    pub fn detect_format<R: Read + Seek>(
        reader: &mut R,
        path_hint: Option<&Path>,
    ) -> Result<ArchiveFormat> {
        let start_pos = reader.stream_position()?;
        let mut header = [0u8; 2048];
        let mut read_total = 0usize;
        while read_total < header.len() {
            let n = reader.read(&mut header[read_total..])?;
            if n == 0 {
                break;
            }
            read_total += n;
        }
        let detected = ArchiveFormat::detect(path_hint, &header[..read_total]);
        if let Some(fmt) = detected {
            reader.seek(SeekFrom::Start(start_pos))?;
            return Ok(fmt);
        }

        // Probe ISO-9660 / UDF Primary Volume Descriptor at 0x8001 ("CD001" or "BEA01")
        if reader.seek(SeekFrom::Start(start_pos + 0x8001)).is_ok() {
            let mut iso_magic = [0u8; 5];
            if reader.read_exact(&mut iso_magic).is_ok()
                && (&iso_magic == b"CD001" || &iso_magic == b"BEA01" || &iso_magic == b"NSR02" || &iso_magic == b"NSR03")
            {
                reader.seek(SeekFrom::Start(start_pos))?;
                return Ok(ArchiveFormat::Iso);
            }
        }

        reader.seek(SeekFrom::Start(start_pos))?;
        let label = path_hint
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<stream>".to_string());
        Err(ArchiveError::UnsupportedFormat(label))
    }

    /// Opens and indexes an archive from disk (automatically stitching `.001, .002, ...` volumes).
    pub fn open_path(
        &self,
        path: &Path,
        password: Option<Zeroizing<String>>,
        control: Option<&TaskControl>,
    ) -> Result<OpenArchive> {
        let mut reader = SplitVolumeReader::open(path)?;
        let total_len = reader.total_len();
        let volume_count = reader.volume_count();
        let primary = reader
            .primary_path()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| path.to_path_buf());

        let format = Self::detect_format(&mut reader, Some(&primary))?;
        let display_name = primary
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("archive")
            .to_string();

        let disk_single_path = if volume_count == 1 {
            Some(primary.as_path())
        } else {
            None
        };

        self.index_stream(
            reader,
            format,
            display_name,
            NestedBacking::RootDiskPath(primary.clone()),
            total_len,
            volume_count,
            disk_single_path,
            password,
            control,
        )
    }

    /// Extracts a nested archive entry into RAM (`< 256 MiB`) or a session `NamedTempFile` (`>= 256 MiB`)
    /// and indexes its VFS tree.
    pub fn open_nested(
        &self,
        parent: &OpenArchive,
        entry_index: usize,
        password: Option<Zeroizing<String>>,
        control: Option<&TaskControl>,
    ) -> Result<OpenArchive> {
        let entry = parent
            .entries
            .get(entry_index)
            .ok_or_else(|| ArchiveError::EntryNotFound(format!("index #{entry_index}")))?;
        let display_name = entry
            .path
            .rsplit('/')
            .next()
            .unwrap_or(&entry.path)
            .to_string();
        let hint_path = PathBuf::from(&display_name);

        if entry.unpacked_size < NESTED_RAM_THRESHOLD_BYTES {
            let bytes = self.read_entry_bytes(
                parent,
                entry_index,
                None,
                password.as_deref().map(String::as_str),
                control,
            )?;
            let total_len = bytes.len() as u64;
            let arc_bytes: Arc<[u8]> = Arc::from(bytes.into_boxed_slice());
            let mut cursor = Cursor::new(Arc::clone(&arc_bytes));
            let format = Self::detect_format(&mut cursor, Some(&hint_path))?;
            self.index_stream(
                cursor,
                format,
                display_name.clone(),
                NestedBacking::InMemory {
                    display_name,
                    bytes: arc_bytes,
                },
                total_len,
                1,
                None,
                password,
                control,
            )
        } else {
            let mut temp = tempfile::Builder::new()
                .prefix("rustixzip_nested_")
                .suffix(&format!("_{display_name}"))
                .tempfile()?;
            self.extract_single_entry_to_writer(
                parent,
                entry_index,
                &mut temp,
                password.as_deref().map(String::as_str),
                control,
            )?;
            temp.flush()?;
            let reopened = temp.reopen()?;
            let total_len = reopened.metadata()?.len();
            let mut buf_reader = BufReader::with_capacity(IO_BUF_SIZE, reopened);
            let format = Self::detect_format(&mut buf_reader, Some(&hint_path))?;
            let temp_disk_path = temp.path().to_path_buf();
            self.index_stream(
                buf_reader,
                format,
                display_name.clone(),
                NestedBacking::TempFile {
                    display_name,
                    temp_file: temp,
                },
                total_len,
                1,
                Some(&temp_disk_path),
                password,
                control,
            )
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn index_stream<R: Read + Seek>(
        &self,
        mut reader: R,
        format: ArchiveFormat,
        display_name: String,
        backing: NestedBacking,
        total_len: u64,
        volume_count: usize,
        disk_path: Option<&Path>,
        password: Option<Zeroizing<String>>,
        control: Option<&TaskControl>,
    ) -> Result<OpenArchive> {
        let pw_ref = password.as_deref().map(String::as_str);

        let (entries, checkpoints, has_encrypted) = match format {
            ArchiveFormat::SevenZip => {
                let (list, enc) = sevenz_backend::list_entries(&mut reader, pw_ref, control)?;
                (list, None, enc)
            }
            ArchiveFormat::Zip => {
                let list = zip_backend::list_entries(&mut reader, control)?;
                let enc = list.iter().any(|e| e.is_encrypted);
                (list, None, enc)
            }
            ArchiveFormat::Tar
            | ArchiveFormat::TarGz
            | ArchiveFormat::TarZst
            | ArchiveFormat::TarXz
            | ArchiveFormat::TarLz4
            | ArchiveFormat::TarBz2
            | ArchiveFormat::Gz
            | ArchiveFormat::Zst
            | ArchiveFormat::Xz
            | ArchiveFormat::Lz4
            | ArchiveFormat::Bz2 => {
                let (list, cp) = tar_stream_backend::list_entries(
                    &mut reader,
                    format,
                    &display_name,
                    total_len,
                    control,
                )?;
                (list, Some(cp), false)
            }
            _ => {
                let plugins = self.plugins.read();
                let list = plugins.list_entries(
                    format,
                    &mut reader,
                    total_len,
                    disk_path,
                    pw_ref,
                    control,
                )?;
                let enc = list.iter().any(|e| e.is_encrypted);
                (list, None, enc)
            }
        };

        let vfs = VfsTree::from_entries(&entries);

        Ok(OpenArchive {
            format,
            display_name,
            backing,
            entries,
            vfs,
            checkpoints,
            compressed_size: total_len,
            volume_count,
            has_encrypted_entries: has_encrypted,
            password,
        })
    }

    /// Extracts all or selected entries from `archive` into `dest_dir`.
    pub fn extract(
        &self,
        archive: &OpenArchive,
        dest_dir: &Path,
        options: &ExtractOptions,
        control: Option<&TaskControl>,
        progress: Option<&ProgressTracker>,
    ) -> Result<()> {
        std::fs::create_dir_all(dest_dir)?;
        self.extract_or_test_impl(archive, Some(dest_dir), options, false, control, progress)
    }

    /// Performs full decompression and CRC/AE-2 integrity verification without writing files to disk.
    pub fn test(
        &self,
        archive: &OpenArchive,
        options: &ExtractOptions,
        control: Option<&TaskControl>,
        progress: Option<&ProgressTracker>,
    ) -> Result<()> {
        self.extract_or_test_impl(archive, None, options, true, control, progress)
    }

    fn extract_or_test_impl(
        &self,
        archive: &OpenArchive,
        dest_dir: Option<&Path>,
        options: &ExtractOptions,
        test_only: bool,
        control: Option<&TaskControl>,
        progress: Option<&ProgressTracker>,
    ) -> Result<()> {
        let mut effective_opts = options.clone();
        if effective_opts.password.is_none() {
            effective_opts.password = archive.password.clone();
        }

        if let Some(p) = progress {
            let selection = build_selection_set(&effective_opts);
            let mut total_bytes = 0u64;
            let mut total_files = 0u64;
            for e in &archive.entries {
                if selection.as_ref().is_none_or(|s| s.contains(&e.index)) && !e.is_dir {
                    total_bytes = total_bytes.saturating_add(e.unpacked_size);
                    total_files += 1;
                }
            }
            p.set_totals(total_bytes, total_files);
        }

        let (mut stream, total_len, disk_path) = archive.open_stream()?;
        match archive.format {
            ArchiveFormat::SevenZip => sevenz_backend::extract_or_test(
                &mut stream,
                dest_dir,
                &effective_opts,
                test_only,
                &self.pool,
                control,
                progress,
            ),
            ArchiveFormat::Zip => zip_backend::extract_or_test(
                &mut stream,
                dest_dir,
                &effective_opts,
                test_only,
                &self.pool,
                control,
                progress,
            ),
            ArchiveFormat::Tar
            | ArchiveFormat::TarGz
            | ArchiveFormat::TarZst
            | ArchiveFormat::TarXz
            | ArchiveFormat::TarLz4
            | ArchiveFormat::TarBz2
            | ArchiveFormat::Gz
            | ArchiveFormat::Zst
            | ArchiveFormat::Xz
            | ArchiveFormat::Lz4
            | ArchiveFormat::Bz2 => tar_stream_backend::extract_or_test(
                &mut stream,
                archive.format,
                &archive.display_name,
                dest_dir,
                &effective_opts,
                test_only,
                &self.pool,
                control,
                progress,
            ),
            _ => {
                let plugins = self.plugins.read();
                use std::cell::RefCell;
                let sink = RefCell::new(DiskExtractSink::new(dest_dir, &effective_opts, test_only, progress));
                plugins.extract_entries(
                    archive.format,
                    &mut stream,
                    total_len,
                    disk_path.as_deref(),
                    effective_opts.password.as_deref().map(String::as_str),
                    effective_opts.selected_indices.as_deref(),
                    test_only,
                    control,
                    |entry| sink.borrow_mut().begin_entry(entry),
                    |chunk| sink.borrow_mut().write_chunk(chunk),
                    |_idx| sink.borrow_mut().finish_entry(),
                )
            }
        }
    }

    /// Reads up to `max_bytes` (or full file when `None`) of a single entry into memory for
    /// the `F3` Text/Hex viewer, nested mounting, or `LiveEditSession`.
    pub fn read_entry_bytes(
        &self,
        archive: &OpenArchive,
        entry_index: usize,
        max_bytes: Option<usize>,
        password_override: Option<&str>,
        control: Option<&TaskControl>,
    ) -> Result<Vec<u8>> {
        let effective_pw = password_override.or_else(|| archive.password.as_deref().map(String::as_str));
        let (mut stream, total_len, disk_path) = archive.open_stream()?;

        match archive.format {
            ArchiveFormat::SevenZip => sevenz_backend::read_entry_bytes(
                &mut stream,
                entry_index,
                max_bytes,
                effective_pw,
                control,
            ),
            ArchiveFormat::Zip => zip_backend::read_entry_bytes(
                &mut stream,
                entry_index,
                max_bytes,
                effective_pw,
                control,
            ),
            ArchiveFormat::Tar
            | ArchiveFormat::TarGz
            | ArchiveFormat::TarZst
            | ArchiveFormat::TarXz
            | ArchiveFormat::TarLz4
            | ArchiveFormat::TarBz2
            | ArchiveFormat::Gz
            | ArchiveFormat::Zst
            | ArchiveFormat::Xz
            | ArchiveFormat::Lz4
            | ArchiveFormat::Bz2 => tar_stream_backend::read_entry_bytes(
                &mut stream,
                archive.format,
                entry_index,
                archive.checkpoints.as_ref(),
                max_bytes,
                control,
            ),
            _ => {
                let plugins = self.plugins.read();
                let indices = [entry_index];
                let mut out = Vec::new();
                let cap = max_bytes.unwrap_or(usize::MAX);
                let mut hit_cap = false;

                let res = plugins.extract_entries(
                    archive.format,
                    &mut stream,
                    total_len,
                    disk_path.as_deref(),
                    effective_pw,
                    Some(&indices),
                    false,
                    control,
                    |_entry| Ok(()),
                    |chunk| {
                        let remaining = cap.saturating_sub(out.len());
                        let take = remaining.min(chunk.len());
                        out.extend_from_slice(&chunk[..take]);
                        if out.len() >= cap {
                            hit_cap = true;
                            return Err(ArchiveError::Cancelled);
                        }
                        Ok(())
                    },
                    |_idx| Ok(()),
                );

                match res {
                    Ok(()) => Ok(out),
                    Err(ArchiveError::Cancelled) if hit_cap => Ok(out),
                    Err(e) => Err(e),
                }
            }
        }
    }

    fn extract_single_entry_to_writer<W: Write>(
        &self,
        archive: &OpenArchive,
        entry_index: usize,
        writer: &mut W,
        password_override: Option<&str>,
        control: Option<&TaskControl>,
    ) -> Result<()> {
        let bytes = self.read_entry_bytes(archive, entry_index, None, password_override, control)?;
        writer.write_all(&bytes)?;
        Ok(())
    }

    /// Creates a new archive (single file or `.001, .002, ...` multi-volume set) from `inputs`.
    /// Returns the list of created output volume paths.
    pub fn pack(
        &self,
        output_path: &Path,
        inputs: &[PackInput],
        options: &PackOptions,
        control: Option<&TaskControl>,
        progress: Option<&ProgressTracker>,
    ) -> Result<Vec<PathBuf>> {
        if !options.format.is_writable() {
            return Err(ArchiveError::UnsupportedFormat(format!(
                "{} is read-only",
                options.format.display_name()
            )));
        }

        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        match options.format {
            ArchiveFormat::SevenZip | ArchiveFormat::Zip => {
                if let Some(vol_size) = options.split_volume_size {
                    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
                    let temp = NamedTempFile::new_in(parent)?;
                    {
                        let writer = BufWriter::with_capacity(IO_BUF_SIZE, temp.reopen()?);
                        let mut finished = if options.format == ArchiveFormat::SevenZip {
                            sevenz_backend::pack_entries(writer, inputs, options, control, progress)?
                        } else {
                            zip_backend::pack_entries(
                                writer, inputs, options, &self.pool, control, progress,
                            )?
                        };
                        finished.flush()?;
                    }
                    let mut src = BufReader::with_capacity(IO_BUF_SIZE, temp.reopen()?);
                    let mut split_writer = SplitVolumeWriter::create(output_path, Some(vol_size))?;
                    let mut io_buf = self.pool.checkout_io();
                    loop {
                        if let Some(ctrl) = control {
                            ctrl.checkpoint()?;
                        }
                        let n = src.read(io_buf.as_mut_slice())?;
                        if n == 0 {
                            break;
                        }
                        split_writer.write_all(&io_buf.as_slice()[..n])?;
                    }
                    Ok(split_writer.finish()?)
                } else {
                    let file = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(output_path)?;
                    let writer = BufWriter::with_capacity(IO_BUF_SIZE, file);
                    let mut finished = if options.format == ArchiveFormat::SevenZip {
                        sevenz_backend::pack_entries(writer, inputs, options, control, progress)?
                    } else {
                        zip_backend::pack_entries(
                            writer, inputs, options, &self.pool, control, progress,
                        )?
                    };
                    finished.flush()?;
                    Ok(vec![output_path.to_path_buf()])
                }
            }
            ArchiveFormat::Tar
            | ArchiveFormat::TarGz
            | ArchiveFormat::TarZst
            | ArchiveFormat::TarXz
            | ArchiveFormat::TarLz4
            | ArchiveFormat::TarBz2
            | ArchiveFormat::Gz
            | ArchiveFormat::Zst
            | ArchiveFormat::Xz
            | ArchiveFormat::Lz4
            | ArchiveFormat::Bz2 => {
                let split_writer =
                    SplitVolumeWriter::create(output_path, options.split_volume_size)?;
                let finished = tar_stream_backend::pack_entries(
                    split_writer,
                    inputs,
                    options,
                    &self.pool,
                    control,
                    progress,
                )?;
                Ok(finished.finish()?)
            }
            _ => Err(ArchiveError::UnsupportedFormat(
                options.format.display_name().to_string(),
            )),
        }
    }

    /// Convenience helper that walks `source_paths` on disk and packs them into `output_path`.
    pub fn pack_paths(
        &self,
        output_path: &Path,
        source_paths: &[PathBuf],
        base_prefix_inside_archive: &str,
        options: &PackOptions,
        control: Option<&TaskControl>,
        progress: Option<&ProgressTracker>,
    ) -> Result<Vec<PathBuf>> {
        let inputs = collect_pack_inputs(source_paths, base_prefix_inside_archive)?;
        self.pack(output_path, &inputs, options, control, progress)
    }

    /// Modifies an existing writable archive on disk atomically (removing `remove_virtual_paths`
    /// and inserting/replacing `additions`).
    ///
    /// - For `.zip`: uses zero-recompression `ZipWriter::raw_copy_file` for untouched entries.
    /// - For `.7z` and `.tar.*`: extracts kept entries into an isolated staging directory, merges
    ///   `additions`, and repacks atomically into a sibling temp file before replacing the target.
    pub fn modify_archive(
        &self,
        archive_path: &Path,
        remove_virtual_paths: &HashSet<String>,
        additions: &[PackInput],
        options: &PackOptions,
        control: Option<&TaskControl>,
        progress: Option<&ProgressTracker>,
    ) -> Result<()> {
        let volumes = resolve_volume_paths(archive_path)?;
        if volumes.len() > 1 {
            return Err(ArchiveError::Backend(
                "in-place modification of multi-volume (.001) archives is not supported; repack to a new archive".to_string(),
            ));
        }

        let clean_removes: HashSet<String> = remove_virtual_paths
            .iter()
            .filter_map(|p| sanitize_archive_path(p))
            .collect();

        let existing = self.open_path(archive_path, options.password.clone(), control)?;
        if !existing.format.is_writable() {
            return Err(ArchiveError::UnsupportedFormat(format!(
                "{} does not support modification",
                existing.format.display_name()
            )));
        }

        let parent_dir = archive_path.parent().unwrap_or_else(|| Path::new("."));

        if existing.format == ArchiveFormat::Zip {
            let temp_out = NamedTempFile::new_in(parent_dir)?;
            {
                let (src_stream, _, _) = existing.open_stream()?;
                let dst_writer = BufWriter::with_capacity(IO_BUF_SIZE, temp_out.reopen()?);
                let mut mod_opts = options.clone();
                mod_opts.format = ArchiveFormat::Zip;
                let mut finished = zip_backend::modify_zip_archive(
                    src_stream,
                    dst_writer,
                    &clean_removes,
                    additions,
                    &mod_opts,
                    &self.pool,
                    control,
                    progress,
                )?;
                finished.flush()?;
            }
            drop(existing);
            replace_file_atomically(temp_out, archive_path)?;
            return Ok(());
        }

        // General atomic staging update for .7z, .tar.*, and single-stream formats
        let staging = tempfile::Builder::new()
            .prefix("rustixzip_mod_stage_")
            .tempdir_in(parent_dir)?;

        let addition_paths: HashSet<String> = additions
            .iter()
            .filter_map(|a| sanitize_archive_path(&a.archive_path))
            .collect();

        let kept_indices: Vec<usize> = existing
            .entries
            .iter()
            .filter(|e| {
                let Some(clean) = sanitize_archive_path(&e.path) else {
                    return false;
                };
                if addition_paths.contains(&clean) {
                    return false;
                }
                !clean_removes.iter().any(|rem| {
                    clean == *rem || clean.starts_with(&format!("{rem}/"))
                })
            })
            .map(|e| e.index)
            .collect();

        if !kept_indices.is_empty() {
            let extract_opts = ExtractOptions {
                overwrite: OverwritePolicy::Overwrite,
                preserve_paths: true,
                password: options.password.clone(),
                selected_indices: Some(kept_indices),
                strip_prefix: None,
            };
            self.extract(&existing, staging.path(), &extract_opts, control, None)?;
        }

        let mut merged_inputs = Vec::new();
        for entry in walkdir::WalkDir::new(staging.path()).follow_links(false) {
            let entry = entry.map_err(|e| ArchiveError::Io(io::Error::other(e.to_string())))?;
            if entry.path() == staging.path() {
                continue;
            }
            let rel = entry
                .path()
                .strip_prefix(staging.path())
                .unwrap_or(entry.path());
            let mut archive_rel = rel
                .components()
                .filter_map(|c| match c {
                    std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("/");
            if archive_rel.is_empty() {
                continue;
            }
            if entry.file_type().is_dir() && !archive_rel.ends_with('/') {
                archive_rel.push('/');
            }
            merged_inputs.push(PackInput {
                disk_path: entry.path().to_path_buf(),
                archive_path: archive_rel,
            });
        }
        merged_inputs.extend(additions.iter().cloned());

        let mut repack_opts = options.clone();
        repack_opts.format = existing.format;
        repack_opts.split_volume_size = None;

        let temp_out = NamedTempFile::new_in(parent_dir)?;
        let temp_out_path = temp_out.path().to_path_buf();
        self.pack(&temp_out_path, &merged_inputs, &repack_opts, control, progress)?;
        drop(existing);
        replace_file_atomically(temp_out, archive_path)?;
        Ok(())
    }
}

fn replace_file_atomically(temp_file: NamedTempFile, target_path: &Path) -> Result<()> {
    // On Windows, `persist` replaces existing files via MoveFileExW(MOVEFILE_REPLACE_EXISTING)
    // as long as no open reader handle remains on `target_path`.
    temp_file
        .persist(target_path)
        .map(|_| ())
        .map_err(|e| ArchiveError::Io(e.error))
}

fn default_plugin_search_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(custom) = std::env::var("RUSTIXZIP_PLUGIN_DIR") {
        let p = PathBuf::from(custom);
        if p.is_dir() {
            dirs.push(p);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            let plugins_subdir = exe_dir.join("plugins");
            if plugins_subdir.is_dir() {
                dirs.push(plugins_subdir);
            }
            // Also support running from target/release where cdylib plugins sit alongside binaries
            dirs.push(exe_dir.to_path_buf());
        }
    }
    dirs
}
