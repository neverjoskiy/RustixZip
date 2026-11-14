//! High-density Arena Radix-Trie Virtual File System (`VfsTree`), sparse TAR stream
//! checkpoint index (`StreamCheckpointIndex`), and recursive nested archive mount stack.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::types::{sanitize_archive_path, ArchiveEntry, ArchiveFormat};

/// Compact handle into `StringArena` (`8 bytes`, `Copy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct StrRef {
    offset: u32,
    len: u32,
}

/// Contiguous UTF-8 slab storing hundreds of thousands of file/folder names with a single allocation.
#[derive(Debug, Clone, Default)]
pub struct StringArena {
    bytes: Vec<u8>,
}

impl StringArena {
    pub fn with_capacity(bytes_cap: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(bytes_cap),
        }
    }

    pub fn intern(&mut self, s: &str) -> StrRef {
        if s.is_empty() {
            return StrRef { offset: 0, len: 0 };
        }
        let offset = self.bytes.len() as u32;
        let len = s.len() as u32;
        self.bytes.extend_from_slice(s.as_bytes());
        StrRef { offset, len }
    }

    pub fn resolve(&self, r: StrRef) -> &str {
        if r.len == 0 {
            return "";
        }
        let start = r.offset as usize;
        let end = start + r.len as usize;
        // SAFETY: Only valid `&str` slices are pushed into `self.bytes`.
        unsafe { std::str::from_utf8_unchecked(&self.bytes[start..end]) }
    }

    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }
}

/// Compact node identifier in `VfsTree::nodes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub u32);

impl NodeId {
    pub const ROOT: Self = Self(0);
    pub const NONE: Self = Self(u32::MAX);

    pub fn is_none(self) -> bool {
        self.0 == u32::MAX
    }

    pub fn is_some(self) -> bool {
        self.0 != u32::MAX
    }
}

pub mod node_flags {
    pub const IS_DIR: u16 = 1 << 0;
    pub const IS_SYMLINK: u16 = 1 << 1;
    pub const IS_ENCRYPTED: u16 = 1 << 2;
    pub const IS_NESTED_ARCHIVE: u16 = 1 << 3;
    pub const SYNTHETIC_DIR: u16 = 1 << 4;
}

/// Single file or directory node inside the contiguous `VfsTree` arena.
#[derive(Debug, Clone)]
pub struct VfsNode {
    pub id: NodeId,
    pub parent: NodeId,
    pub first_child: NodeId,
    pub last_child: NodeId,
    pub next_sibling: NodeId,
    pub name: StrRef,
    pub ext: StrRef,
    pub method: StrRef,
    pub unpacked_size: u64,
    pub packed_size: u64,
    pub mtime: Option<i64>,
    pub crc32: Option<u32>,
    pub attributes: u32,
    pub flags: u16,
    /// Index in the underlying archive backend (`u32::MAX` for implicit intermediate directories).
    pub backend_entry_index: u32,
}

impl VfsNode {
    pub fn is_dir(&self) -> bool {
        (self.flags & node_flags::IS_DIR) != 0
    }

    pub fn is_symlink(&self) -> bool {
        (self.flags & node_flags::IS_SYMLINK) != 0
    }

    pub fn is_encrypted(&self) -> bool {
        (self.flags & node_flags::IS_ENCRYPTED) != 0
    }

    pub fn is_nested_archive(&self) -> bool {
        (self.flags & node_flags::IS_NESTED_ARCHIVE) != 0
    }

    pub fn entry_index(&self) -> Option<usize> {
        if self.backend_entry_index == u32::MAX {
            None
        } else {
            Some(self.backend_entry_index as usize)
        }
    }
}

/// Sort column selector matching the 7-Zip File Manager table columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    Name,
    Size,
    PackedSize,
    Ratio,
    Type,
    Modified,
    Attributes,
    Crc,
}

/// Contiguous Arena Radix-Trie indexing an entire archive for O(1) directory browsing.
#[derive(Debug, Clone)]
pub struct VfsTree {
    arena: StringArena,
    nodes: Vec<VfsNode>,
    /// Fast lookup `(parent_node_id, child_name_hash_or_str)` during construction and path resolution.
    dir_lookup: HashMap<(u32, String), NodeId>,
    total_files: usize,
    total_dirs: usize,
}

impl Default for VfsTree {
    fn default() -> Self {
        Self::new()
    }
}

impl VfsTree {
    pub fn new() -> Self {
        Self::with_capacity(256)
    }

    pub fn with_capacity(expected_entries: usize) -> Self {
        let mut nodes = Vec::with_capacity(expected_entries.saturating_add(16));
        nodes.push(VfsNode {
            id: NodeId::ROOT,
            parent: NodeId::NONE,
            first_child: NodeId::NONE,
            last_child: NodeId::NONE,
            next_sibling: NodeId::NONE,
            name: StrRef::default(),
            ext: StrRef::default(),
            method: StrRef::default(),
            unpacked_size: 0,
            packed_size: 0,
            mtime: None,
            crc32: None,
            attributes: 0,
            flags: node_flags::IS_DIR | node_flags::SYNTHETIC_DIR,
            backend_entry_index: u32::MAX,
        });
        Self {
            arena: StringArena::with_capacity(expected_entries.saturating_mul(32)),
            nodes,
            dir_lookup: HashMap::with_capacity(expected_entries / 4 + 16),
            total_files: 0,
            total_dirs: 0,
        }
    }

    /// Builds a `VfsTree` from a slice of `ArchiveEntry` records and aggregates cumulative folder sizes.
    pub fn from_entries(entries: &[ArchiveEntry]) -> Self {
        let mut tree = Self::with_capacity(entries.len());
        for entry in entries {
            tree.insert_entry(entry);
        }
        tree.recompute_directory_aggregates();
        tree
    }

    pub fn insert_entry(&mut self, entry: &ArchiveEntry) -> Option<NodeId> {
        let clean = sanitize_archive_path(&entry.path)?;
        if clean.is_empty() {
            return Some(NodeId::ROOT);
        }

        let parts: Vec<&str> = clean.split('/').collect();
        let mut parent_id = NodeId::ROOT;

        // Ensure all intermediate directories exist
        for &dir_name in &parts[..parts.len() - 1] {
            parent_id = self.ensure_child_dir(parent_id, dir_name);
        }

        let leaf_name = parts[parts.len() - 1];
        if entry.is_dir {
            let dir_id = self.ensure_child_dir(parent_id, leaf_name);
            let method_ref = self.arena.intern(&entry.method);
            let node = &mut self.nodes[dir_id.0 as usize];
            node.flags &= !node_flags::SYNTHETIC_DIR;
            if entry.is_encrypted {
                node.flags |= node_flags::IS_ENCRYPTED;
            }
            node.mtime = entry.mtime.or(node.mtime);
            node.attributes = entry.attributes;
            node.method = method_ref;
            node.backend_entry_index = entry.index as u32;
            return Some(dir_id);
        }

        // Check if duplicate leaf exists (e.g., updated entry in TAR stream)
        if let Some(&existing_id) = self.dir_lookup.get(&(parent_id.0, leaf_name.to_string())) {
            let method_ref = self.arena.intern(&entry.method);
            let node = &mut self.nodes[existing_id.0 as usize];
            node.unpacked_size = entry.unpacked_size;
            node.packed_size = entry.packed_size;
            node.mtime = entry.mtime;
            node.crc32 = entry.crc32;
            node.attributes = entry.attributes;
            node.method = method_ref;
            node.backend_entry_index = entry.index as u32;
            return Some(existing_id);
        }

        let name_ref = self.arena.intern(leaf_name);
        let ext_str = extract_extension_lower(leaf_name);
        let ext_ref = self.arena.intern(&ext_str);
        let method_ref = self.arena.intern(&entry.method);

        let mut flags = 0u16;
        if entry.is_symlink {
            flags |= node_flags::IS_SYMLINK;
        }
        if entry.is_encrypted {
            flags |= node_flags::IS_ENCRYPTED;
        }
        if ArchiveFormat::detect_from_filename(leaf_name).is_some() {
            flags |= node_flags::IS_NESTED_ARCHIVE;
        }

        let new_id = NodeId(self.nodes.len() as u32);
        self.nodes.push(VfsNode {
            id: new_id,
            parent: parent_id,
            first_child: NodeId::NONE,
            last_child: NodeId::NONE,
            next_sibling: NodeId::NONE,
            name: name_ref,
            ext: ext_ref,
            method: method_ref,
            unpacked_size: entry.unpacked_size,
            packed_size: entry.packed_size,
            mtime: entry.mtime,
            crc32: entry.crc32,
            attributes: entry.attributes,
            flags,
            backend_entry_index: entry.index as u32,
        });
        self.link_child(parent_id, new_id);
        self.dir_lookup
            .insert((parent_id.0, leaf_name.to_string()), new_id);
        self.total_files += 1;
        Some(new_id)
    }

    fn ensure_child_dir(&mut self, parent_id: NodeId, dir_name: &str) -> NodeId {
        if let Some(&id) = self.dir_lookup.get(&(parent_id.0, dir_name.to_string())) {
            return id;
        }
        let name_ref = self.arena.intern(dir_name);
        let new_id = NodeId(self.nodes.len() as u32);
        self.nodes.push(VfsNode {
            id: new_id,
            parent: parent_id,
            first_child: NodeId::NONE,
            last_child: NodeId::NONE,
            next_sibling: NodeId::NONE,
            name: name_ref,
            ext: StrRef::default(),
            method: StrRef::default(),
            unpacked_size: 0,
            packed_size: 0,
            mtime: None,
            crc32: None,
            attributes: 0,
            flags: node_flags::IS_DIR | node_flags::SYNTHETIC_DIR,
            backend_entry_index: u32::MAX,
        });
        self.link_child(parent_id, new_id);
        self.dir_lookup
            .insert((parent_id.0, dir_name.to_string()), new_id);
        self.total_dirs += 1;
        new_id
    }

    fn link_child(&mut self, parent_id: NodeId, child_id: NodeId) {
        let prev_last = self.nodes[parent_id.0 as usize].last_child;
        if prev_last.is_none() {
            self.nodes[parent_id.0 as usize].first_child = child_id;
            self.nodes[parent_id.0 as usize].last_child = child_id;
        } else {
            self.nodes[prev_last.0 as usize].next_sibling = child_id;
            self.nodes[parent_id.0 as usize].last_child = child_id;
        }
    }

    /// Bottom-up post-order pass computing cumulative unpacked & packed sizes for every folder.
    pub fn recompute_directory_aggregates(&mut self) {
        let mut order = Vec::with_capacity(self.nodes.len());
        let mut stack = vec![NodeId::ROOT];
        while let Some(id) = stack.pop() {
            order.push(id);
            let mut child = self.nodes[id.0 as usize].first_child;
            while child.is_some() {
                if self.nodes[child.0 as usize].is_dir() {
                    stack.push(child);
                }
                child = self.nodes[child.0 as usize].next_sibling;
            }
        }

        for &dir_id in order.iter().rev() {
            let mut sum_unpacked = 0u64;
            let mut sum_packed = 0u64;
            let mut child = self.nodes[dir_id.0 as usize].first_child;
            while child.is_some() {
                let cnode = &self.nodes[child.0 as usize];
                sum_unpacked = sum_unpacked.saturating_add(cnode.unpacked_size);
                sum_packed = sum_packed.saturating_add(cnode.packed_size);
                child = cnode.next_sibling;
            }
            let dnode = &mut self.nodes[dir_id.0 as usize];
            dnode.unpacked_size = sum_unpacked;
            dnode.packed_size = sum_packed;
        }
    }

    pub fn node(&self, id: NodeId) -> &VfsNode {
        &self.nodes[id.0 as usize]
    }

    pub fn node_name(&self, id: NodeId) -> &str {
        self.arena.resolve(self.nodes[id.0 as usize].name)
    }

    pub fn node_ext(&self, id: NodeId) -> &str {
        self.arena.resolve(self.nodes[id.0 as usize].ext)
    }

    pub fn node_method(&self, id: NodeId) -> &str {
        self.arena.resolve(self.nodes[id.0 as usize].method)
    }

    pub fn total_files(&self) -> usize {
        self.total_files
    }

    pub fn total_dirs(&self) -> usize {
        self.total_dirs
    }

    pub fn arena_bytes(&self) -> usize {
        self.arena.byte_len() + self.nodes.len() * std::mem::size_of::<VfsNode>()
    }

    /// Resolves a relative virtual path (e.g. `"src/core/lib.rs"`) into a `NodeId` in O(depth).
    pub fn resolve_path(&self, vpath: &str) -> Option<NodeId> {
        let trimmed = vpath.trim_matches(|c| c == '/' || c == '\\');
        if trimmed.is_empty() {
            return Some(NodeId::ROOT);
        }
        let mut current = NodeId::ROOT;
        for part in trimmed.split(['/', '\\']) {
            if part.is_empty() || part == "." {
                continue;
            }
            if part == ".." {
                let parent = self.nodes[current.0 as usize].parent;
                current = if parent.is_some() { parent } else { NodeId::ROOT };
                continue;
            }
            current = *self.dir_lookup.get(&(current.0, part.to_string()))?;
        }
        Some(current)
    }

    /// Reconstructs the full forward-slash path inside the archive for any `NodeId`.
    pub fn full_path(&self, mut id: NodeId) -> String {
        if id == NodeId::ROOT || id.is_none() {
            return String::new();
        }
        let mut segments = Vec::new();
        while id != NodeId::ROOT && id.is_some() {
            segments.push(self.node_name(id));
            id = self.nodes[id.0 as usize].parent;
        }
        segments.reverse();
        segments.join("/")
    }

    /// Lists direct children of `dir_id`, optionally filtered by case-insensitive query,
    /// sorted with directories always grouped first (classic 7-Zip File Manager convention).
    pub fn list_children(
        &self,
        dir_id: NodeId,
        filter_query: &str,
        sort_col: SortColumn,
        ascending: bool,
    ) -> Vec<NodeId> {
        let needle = filter_query.trim().to_ascii_lowercase();
        let mut out = Vec::new();
        let mut child = self.nodes[dir_id.0 as usize].first_child;
        while child.is_some() {
            if needle.is_empty()
                || self
                    .node_name(child)
                    .to_ascii_lowercase()
                    .contains(&needle)
            {
                out.push(child);
            }
            child = self.nodes[child.0 as usize].next_sibling;
        }

        out.sort_by(|&a, &b| {
            let na = &self.nodes[a.0 as usize];
            let nb = &self.nodes[b.0 as usize];
            // Directories always precede files regardless of sort direction
            match (na.is_dir(), nb.is_dir()) {
                (true, false) => return Ordering::Less,
                (false, true) => return Ordering::Greater,
                _ => {}
            }

            let ord = match sort_col {
                SortColumn::Name => cmp_natural_case_insensitive(self.node_name(a), self.node_name(b)),
                SortColumn::Size => na
                    .unpacked_size
                    .cmp(&nb.unpacked_size)
                    .then_with(|| cmp_natural_case_insensitive(self.node_name(a), self.node_name(b))),
                SortColumn::PackedSize => na
                    .packed_size
                    .cmp(&nb.packed_size)
                    .then_with(|| cmp_natural_case_insensitive(self.node_name(a), self.node_name(b))),
                SortColumn::Ratio => {
                    let ra = ratio_bp(na.packed_size, na.unpacked_size);
                    let rb = ratio_bp(nb.packed_size, nb.unpacked_size);
                    ra.cmp(&rb)
                }
                SortColumn::Type => self
                    .node_ext(a)
                    .cmp(self.node_ext(b))
                    .then_with(|| cmp_natural_case_insensitive(self.node_name(a), self.node_name(b))),
                SortColumn::Modified => na.mtime.unwrap_or(0).cmp(&nb.mtime.unwrap_or(0)),
                SortColumn::Attributes => na.attributes.cmp(&nb.attributes),
                SortColumn::Crc => na.crc32.unwrap_or(0).cmp(&nb.crc32.unwrap_or(0)),
            };

            if ascending {
                ord
            } else {
                ord.reverse()
            }
        });

        out
    }

    /// Collects all backend entry indices recursively contained under `selected_nodes`
    /// (so selecting a folder extracts/tests/deletes every file and subfolder inside it).
    pub fn collect_backend_indices(&self, selected_nodes: &[NodeId]) -> Vec<usize> {
        let mut indices = Vec::new();
        let mut stack: Vec<NodeId> = selected_nodes.to_vec();
        while let Some(id) = stack.pop() {
            let node = &self.nodes[id.0 as usize];
            if let Some(idx) = node.entry_index() {
                indices.push(idx);
            }
            let mut child = node.first_child;
            while child.is_some() {
                stack.push(child);
                child = self.nodes[child.0 as usize].next_sibling;
            }
        }
        indices.sort_unstable();
        indices.dedup();
        indices
    }
}

/// Sparse checkpoint recorded every `16 MiB` of uncompressed TAR stream (or frame boundary)
/// so random access in `.tar.zst` / `.tar.gz` / `.tar.xz` knows exact byte positions.
#[derive(Debug, Clone, Copy)]
pub struct StreamCheckpoint {
    pub entry_index: usize,
    pub uncompressed_tar_offset: u64,
    pub compressed_stream_offset: Option<u64>,
}

/// Index mapping TAR entry indices to uncompressed stream offsets and sparse checkpoints.
#[derive(Debug, Clone, Default)]
pub struct StreamCheckpointIndex {
    /// `(uncompressed_header_offset, payload_offset, payload_len)` per TAR entry index.
    entry_spans: Vec<(u64, u64, u64)>,
    checkpoints: Vec<StreamCheckpoint>,
}

impl StreamCheckpointIndex {
    pub const CHECKPOINT_INTERVAL: u64 = 16 * 1024 * 1024;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_entry(
        &mut self,
        entry_index: usize,
        header_offset: u64,
        payload_offset: u64,
        payload_len: u64,
        compressed_stream_offset: Option<u64>,
    ) {
        if self.entry_spans.len() <= entry_index {
            self.entry_spans.resize(entry_index + 1, (0, 0, 0));
        }
        self.entry_spans[entry_index] = (header_offset, payload_offset, payload_len);

        let should_checkpoint = self.checkpoints.last().is_none_or(|last| {
            header_offset.saturating_sub(last.uncompressed_tar_offset) >= Self::CHECKPOINT_INTERVAL
        });
        if should_checkpoint {
            self.checkpoints.push(StreamCheckpoint {
                entry_index,
                uncompressed_tar_offset: header_offset,
                compressed_stream_offset,
            });
        }
    }

    pub fn entry_payload_span(&self, entry_index: usize) -> Option<(u64, u64)> {
        self.entry_spans
            .get(entry_index)
            .map(|&(_, payload_off, len)| (payload_off, len))
    }

    pub fn nearest_checkpoint(&self, target_uncompressed_offset: u64) -> Option<StreamCheckpoint> {
        let idx = self
            .checkpoints
            .partition_point(|cp| cp.uncompressed_tar_offset <= target_uncompressed_offset);
        if idx == 0 {
            self.checkpoints.first().copied()
        } else {
            self.checkpoints.get(idx - 1).copied()
        }
    }

    pub fn checkpoints(&self) -> &[StreamCheckpoint] {
        &self.checkpoints
    }
}

/// Backing storage for a mounted nested archive layer (`< 256 MiB` in RAM, larger in temp file).
#[derive(Debug)]
pub enum NestedBacking {
    RootDiskPath(PathBuf),
    InMemory {
        display_name: String,
        bytes: std::sync::Arc<[u8]>,
    },
    TempFile {
        display_name: String,
        temp_file: tempfile::NamedTempFile,
    },
}

/// Threshold (`256 MiB`) below which nested archives stay purely in RAM.
pub const NESTED_RAM_THRESHOLD_BYTES: u64 = 256 * 1024 * 1024;

fn extract_extension_lower(name: &str) -> String {
    match name.rfind('.') {
        Some(idx) if idx > 0 && idx + 1 < name.len() => name[idx + 1..].to_ascii_lowercase(),
        _ => String::new(),
    }
}

fn ratio_bp(packed: u64, unpacked: u64) -> u64 {
    if unpacked == 0 {
        return 10_000;
    }
    packed.saturating_mul(10_000) / unpacked
}

fn cmp_natural_case_insensitive(a: &str, b: &str) -> Ordering {
    let mut ia = a.bytes();
    let mut ib = b.bytes();
    loop {
        match (ia.next(), ib.next()) {
            (Some(ca), Some(cb)) => {
                let la = ca.to_ascii_lowercase();
                let lb = cb.to_ascii_lowercase();
                if la != lb {
                    return la.cmp(&lb);
                }
            }
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (None, None) => return a.cmp(b),
        }
    }
}
