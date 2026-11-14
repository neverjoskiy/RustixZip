//! Dynamic C-ABI plugin loader and host adapter (`libloading` + `archive-plugin-api`).

use std::collections::HashSet;
use std::ffi::c_void;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use libloading::Library;

use archive_plugin_api::{
    entry_flags, ArchiveEntryFFI, EntrySinkVTable, ExtractSinkVTable, HostControl, OwnedStreamHost,
    PasswordProviderVTable, PluginExportV1, PluginStatus, Utf8SliceFFI,
    RUSTIXZIP_PLUGIN_ABI_VERSION, RUSTIXZIP_PLUGIN_MAGIC, RUSTIXZIP_PLUGIN_SYMBOL,
};

use crate::error::{ArchiveError, Result};
use crate::progress::TaskControl;
use crate::types::{sanitize_archive_path, ArchiveEntry, ArchiveFormat};

/// Metadata about a single archive format advertised by a loaded dynamic plugin.
#[derive(Debug, Clone)]
pub struct PluginFormatInfo {
    pub id: String,
    pub display_name: String,
    pub extensions: Vec<String>,
    pub capabilities: u32,
}

/// A dynamically loaded codec/format plugin (`.dll` on Windows, `.so` on Linux).
#[derive(Clone)]
pub struct LoadedPlugin {
    _lib: Arc<Library>,
    export: PluginExportV1,
    pub id: String,
    pub name: String,
    pub version: String,
    pub library_path: PathBuf,
    pub formats: Vec<PluginFormatInfo>,
}

impl std::fmt::Debug for LoadedPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedPlugin")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("version", &self.version)
            .field("library_path", &self.library_path)
            .field("formats", &self.formats)
            .finish()
    }
}

impl LoadedPlugin {
    pub fn supports_format_id(&self, format_id: &str) -> bool {
        self.formats
            .iter()
            .any(|fmt| fmt.id.eq_ignore_ascii_case(format_id))
    }

    fn read_last_error(&self) -> String {
        let mut buf = vec![0u8; 2048];
        let written = unsafe { (self.export.copy_last_error)(buf.as_mut_ptr(), buf.len()) };
        let valid = written.min(buf.len());
        String::from_utf8_lossy(&buf[..valid]).trim().to_string()
    }

    fn map_status_error(&self, code: i32) -> ArchiveError {
        let detail = self.read_last_error();
        let msg = if detail.is_empty() {
            format!("plugin '{}' returned status {code}", self.id)
        } else {
            detail
        };
        match PluginStatus::from_code(code) {
            PluginStatus::Ok => ArchiveError::Plugin {
                plugin: self.id.clone(),
                message: "unexpected ok status mapped as error".to_string(),
            },
            PluginStatus::UnsupportedFormat => ArchiveError::UnsupportedFormat(msg),
            PluginStatus::CorruptedArchive => ArchiveError::CorruptedArchive(msg),
            PluginStatus::PasswordRequired => ArchiveError::PasswordRequired,
            PluginStatus::WrongPassword => ArchiveError::InvalidPassword,
            PluginStatus::Cancelled => ArchiveError::Cancelled,
            PluginStatus::ChecksumMismatch => ArchiveError::ChecksumMismatch {
                entry: self.id.clone(),
                expected: "valid archive digest".to_string(),
                actual: msg,
            },
            PluginStatus::InvalidArgument | PluginStatus::IoError | PluginStatus::InternalPanic => {
                ArchiveError::Plugin {
                    plugin: self.id.clone(),
                    message: msg,
                }
            }
        }
    }
}

/// Host-side registry managing discovered dynamic plugins.
#[derive(Debug, Clone, Default)]
pub struct PluginRegistry {
    plugins: Vec<LoadedPlugin>,
    loaded_paths: HashSet<PathBuf>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Discovers plugins from `RUSTIXZIP_PLUGIN_DIR`, `<exe_dir>/plugins`, and `<exe_dir>`
    /// (for workspace test binaries built side-by-side in `target/release`).
    pub fn discover_default() -> Self {
        let mut reg = Self::new();
        if let Ok(custom_dir) = std::env::var("RUSTIXZIP_PLUGIN_DIR") {
            for part in std::env::split_paths(&custom_dir) {
                reg.scan_directory(&part, false);
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(exe_dir) = exe.parent() {
                reg.scan_directory(&exe_dir.join("plugins"), false);
                reg.scan_directory(exe_dir, true);
                if let Some(parent_dir) = exe_dir.parent() {
                    reg.scan_directory(&parent_dir.join("plugins"), false);
                    reg.scan_directory(parent_dir, true);
                }
            }
        }
        reg
    }

    pub fn plugins(&self) -> &[LoadedPlugin] {
        &self.plugins
    }

    /// Scans a directory for shared libraries exporting `rustixzip_plugin_entry_v1`.
    /// When `require_plugin_prefix` is true, only libraries whose stem contains `plugin_`
    /// are probed so sibling system DLLs in `<exe_dir>` are never touched.
    pub fn scan_directory(&mut self, dir: &Path, require_plugin_prefix: bool) {
        let entries = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() || !is_shared_library(&path) {
                continue;
            }
            if require_plugin_prefix {
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if !stem.contains("plugin_") && !stem.contains("plugin-") {
                    continue;
                }
            }
            let _ = self.load_library(&path);
        }
    }

    /// Explicitly loads and validates a dynamic plugin library from `path`.
    pub fn load_library(&mut self, path: &Path) -> Result<()> {
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if self.loaded_paths.contains(&canonical) {
            return Ok(());
        }

        // SAFETY: Loading RustixZip C-ABI plugin library and resolving versioned entry symbol.
        let lib = unsafe { Library::new(&canonical) }.map_err(|e| ArchiveError::Plugin {
            plugin: canonical.display().to_string(),
            message: format!("failed to load shared library: {e}"),
        })?;

        type EntryFn = unsafe extern "C" fn() -> PluginExportV1;
        let export = unsafe {
            let sym: libloading::Symbol<'_, EntryFn> = lib
                .get(RUSTIXZIP_PLUGIN_SYMBOL)
                .map_err(|e| ArchiveError::Plugin {
                    plugin: canonical.display().to_string(),
                    message: format!("missing plugin entry symbol: {e}"),
                })?;
            sym()
        };

        if export.magic != RUSTIXZIP_PLUGIN_MAGIC {
            return Err(ArchiveError::Plugin {
                plugin: canonical.display().to_string(),
                message: format!("invalid plugin magic 0x{:016X}", export.magic),
            });
        }
        if export.abi_version != RUSTIXZIP_PLUGIN_ABI_VERSION {
            return Err(ArchiveError::Plugin {
                plugin: canonical.display().to_string(),
                message: format!(
                    "incompatible plugin ABI version {} (expected {})",
                    export.abi_version, RUSTIXZIP_PLUGIN_ABI_VERSION
                ),
            });
        }

        let plugin_id = unsafe { export.plugin_id.as_str() }
            .unwrap_or("unknown")
            .to_string();
        if self.plugins.iter().any(|p| p.id == plugin_id) {
            self.loaded_paths.insert(canonical);
            return Ok(());
        }

        let plugin_name = unsafe { export.plugin_name.as_str() }
            .unwrap_or(&plugin_id)
            .to_string();
        let plugin_version = unsafe { export.plugin_version.as_str() }
            .unwrap_or("0.1.0")
            .to_string();

        let mut formats = Vec::with_capacity(export.formats_len);
        if !export.formats_ptr.is_null() && export.formats_len > 0 {
            let slice =
                unsafe { std::slice::from_raw_parts(export.formats_ptr, export.formats_len) };
            for desc in slice {
                let id = unsafe { desc.id.as_str() }.unwrap_or("").to_string();
                let display_name = unsafe { desc.display_name.as_str() }
                    .unwrap_or(&id)
                    .to_string();
                let ext_csv = unsafe { desc.extensions_csv.as_str() }.unwrap_or("");
                let extensions = ext_csv
                    .split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect();
                formats.push(PluginFormatInfo {
                    id,
                    display_name,
                    extensions,
                    capabilities: desc.capabilities,
                });
            }
        }

        self.loaded_paths.insert(canonical.clone());
        self.plugins.push(LoadedPlugin {
            _lib: Arc::new(lib),
            export,
            id: plugin_id,
            name: plugin_name,
            version: plugin_version,
            library_path: canonical,
            formats,
        });
        Ok(())
    }

    pub fn find_for_format(&self, format: ArchiveFormat) -> Option<&LoadedPlugin> {
        let id = format.id();
        self.plugins.iter().find(|p| p.supports_format_id(id))
    }

    pub fn list_entries<R: Read + Seek>(
        &self,
        format: ArchiveFormat,
        reader: &mut R,
        total_len: u64,
        disk_path: Option<&Path>,
        password: Option<&str>,
        control: Option<&TaskControl>,
    ) -> Result<Vec<ArchiveEntry>> {
        let plugin = self.find_for_format(format).ok_or_else(|| {
            ArchiveError::UnsupportedFormat(format!(
                "{} requires dynamic plugin (plugins/ directory)",
                format.display_name()
            ))
        })?;

        let disk_path_utf8 = disk_path.and_then(|p| p.to_str());
        let mut host_stream = OwnedStreamHost::new(reader, total_len, disk_path_utf8);
        let stream_vtable = host_stream.as_vtable();

        let mut pw_ctx = PasswordCtx { password };
        let pw_vtable = pw_ctx.as_vtable();

        let mut collector = EntryCollector {
            entries: Vec::new(),
            format_name: format.display_name(),
            control,
        };
        let sink_vtable = EntrySinkVTable {
            ctx: (&mut collector as *mut EntryCollector).cast::<c_void>(),
            on_entry: on_entry_trampoline,
        };

        let format_id_str = format.id();
        let rc = unsafe {
            (plugin.export.list_entries)(
                Utf8SliceFFI::from_utf8(format_id_str),
                &stream_vtable,
                &pw_vtable,
                &sink_vtable,
            )
        };
        if rc != PluginStatus::Ok as i32 {
            return Err(plugin.map_status_error(rc));
        }
        Ok(collector.entries)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn extract_entries<R, B, W, F>(
        &self,
        format: ArchiveFormat,
        reader: &mut R,
        total_len: u64,
        disk_path: Option<&Path>,
        password: Option<&str>,
        selected_indices: Option<&[usize]>,
        test_only: bool,
        control: Option<&TaskControl>,
        mut on_begin: B,
        mut on_write: W,
        mut on_finish: F,
    ) -> Result<()>
    where
        R: Read + Seek,
        B: FnMut(&ArchiveEntry) -> Result<()>,
        W: FnMut(&[u8]) -> Result<()>,
        F: FnMut(usize) -> Result<()>,
    {
        let plugin = self.find_for_format(format).ok_or_else(|| {
            ArchiveError::UnsupportedFormat(format!(
                "{} requires dynamic plugin (plugins/ directory)",
                format.display_name()
            ))
        })?;

        let disk_path_utf8 = disk_path.and_then(|p| p.to_str());
        let mut host_stream = OwnedStreamHost::new(reader, total_len, disk_path_utf8);
        let stream_vtable = host_stream.as_vtable();

        let mut pw_ctx = PasswordCtx { password };
        let pw_vtable = pw_ctx.as_vtable();

        let indices_u64: Vec<u64> = selected_indices
            .map(|slice| slice.iter().map(|&i| i as u64).collect())
            .unwrap_or_default();
        let (indices_ptr, indices_len) = if indices_u64.is_empty() {
            (std::ptr::null(), 0)
        } else {
            (indices_u64.as_ptr(), indices_u64.len())
        };

        let mut sink_ctx = ExtractCallbacksCtx {
            format_name: format.display_name(),
            control,
            last_error: None,
            on_begin: &mut on_begin,
            on_write: &mut on_write,
            on_finish: &mut on_finish,
        };

        let sink_vtable = ExtractSinkVTable {
            ctx: (&mut sink_ctx as *mut ExtractCallbacksCtx<'_, B, W, F>).cast::<c_void>(),
            begin_entry: begin_entry_trampoline::<B, W, F>,
            write_chunk: write_chunk_trampoline::<B, W, F>,
            finish_entry: finish_entry_trampoline::<B, W, F>,
        };

        let format_id_str = format.id();
        let rc = unsafe {
            (plugin.export.extract_entries)(
                Utf8SliceFFI::from_utf8(format_id_str),
                &stream_vtable,
                &pw_vtable,
                indices_ptr,
                indices_len,
                u32::from(test_only),
                &sink_vtable,
            )
        };

        if let Some(host_err) = sink_ctx.last_error.take() {
            return Err(host_err);
        }
        if rc != PluginStatus::Ok as i32 {
            return Err(plugin.map_status_error(rc));
        }
        Ok(())
    }
}

fn is_shared_library(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    #[cfg(target_os = "windows")]
    {
        ext == "dll"
    }
    #[cfg(not(target_os = "windows"))]
    {
        ext == "so" || ext == "dylib"
    }
}

fn convert_ffi_entry(ffi: &ArchiveEntryFFI, default_method: &str) -> Option<ArchiveEntry> {
    let raw_path = unsafe { ffi.path.as_str() }.ok()?;
    let clean_path = sanitize_archive_path(raw_path)?;
    let symlink_target = unsafe { ffi.symlink_target.as_str() }
        .ok()
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    let is_dir = (ffi.flags & entry_flags::IS_DIR) != 0 || raw_path.ends_with('/');
    let is_symlink = (ffi.flags & entry_flags::IS_SYMLINK) != 0;
    let is_encrypted = (ffi.flags & entry_flags::IS_ENCRYPTED) != 0;
    let crc32 = if (ffi.flags & entry_flags::HAS_CRC32) != 0 {
        Some(ffi.crc32)
    } else {
        None
    };
    let mtime = if ffi.mtime_secs > 0 {
        Some(ffi.mtime_secs)
    } else {
        None
    };

    Some(ArchiveEntry {
        index: ffi.index as usize,
        path: clean_path,
        is_dir,
        is_symlink,
        symlink_target,
        unpacked_size: ffi.unpacked_size,
        packed_size: ffi.packed_size,
        mtime,
        crc32,
        attributes: ffi.unix_mode,
        is_encrypted,
        method: default_method.to_string(),
    })
}

struct EntryCollector<'a> {
    entries: Vec<ArchiveEntry>,
    format_name: &'static str,
    control: Option<&'a TaskControl>,
}

unsafe extern "C" fn on_entry_trampoline(ctx: *mut c_void, entry: *const ArchiveEntryFFI) -> i32 {
    if ctx.is_null() || entry.is_null() {
        return HostControl::Cancel as i32;
    }
    let collector = unsafe { &mut *(ctx as *mut EntryCollector<'_>) };
    if let Some(ctrl) = collector.control {
        if ctrl.checkpoint().is_err() {
            return HostControl::Cancel as i32;
        }
    }
    let ffi_ref = unsafe { &*entry };
    if let Some(parsed) = convert_ffi_entry(ffi_ref, collector.format_name) {
        collector.entries.push(parsed);
    }
    HostControl::Continue as i32
}

struct PasswordCtx<'a> {
    password: Option<&'a str>,
}

impl<'a> PasswordCtx<'a> {
    fn as_vtable(&mut self) -> PasswordProviderVTable {
        if self.password.is_none() {
            return PasswordProviderVTable::empty();
        }
        PasswordProviderVTable {
            ctx: (self as *mut Self).cast::<c_void>(),
            get_password: password_trampoline,
        }
    }
}

unsafe extern "C" fn password_trampoline(
    ctx: *mut c_void,
    out_buf: *mut u8,
    buf_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if ctx.is_null() || out_len.is_null() {
        return -1;
    }
    let pw_ctx = unsafe { &*(ctx as *const PasswordCtx<'_>) };
    let Some(pw) = pw_ctx.password else {
        unsafe { *out_len = 0 };
        return -1;
    };
    let bytes = pw.as_bytes();
    if bytes.len() > buf_cap || (out_buf.is_null() && !bytes.is_empty()) {
        unsafe { *out_len = bytes.len() };
        return -2;
    }
    if !bytes.is_empty() {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
        }
    }
    unsafe { *out_len = bytes.len() };
    0
}

struct ExtractCallbacksCtx<'a, B, W, F> {
    format_name: &'static str,
    control: Option<&'a TaskControl>,
    last_error: Option<ArchiveError>,
    on_begin: &'a mut B,
    on_write: &'a mut W,
    on_finish: &'a mut F,
}

unsafe extern "C" fn begin_entry_trampoline<B, W, F>(
    ctx: *mut c_void,
    entry: *const ArchiveEntryFFI,
) -> i32
where
    B: FnMut(&ArchiveEntry) -> Result<()>,
    W: FnMut(&[u8]) -> Result<()>,
    F: FnMut(usize) -> Result<()>,
{
    if ctx.is_null() || entry.is_null() {
        return HostControl::Cancel as i32;
    }
    let state = unsafe { &mut *(ctx as *mut ExtractCallbacksCtx<'_, B, W, F>) };
    if let Some(ctrl) = state.control {
        if let Err(e) = ctrl.checkpoint() {
            state.last_error = Some(e);
            return HostControl::Cancel as i32;
        }
    }
    let ffi_ref = unsafe { &*entry };
    let Some(parsed) = convert_ffi_entry(ffi_ref, state.format_name) else {
        state.last_error = Some(ArchiveError::UnsafePath(
            unsafe { ffi_ref.path.as_str() }
                .unwrap_or("<invalid utf-8>")
                .to_string(),
        ));
        return HostControl::Cancel as i32;
    };
    if let Err(e) = (state.on_begin)(&parsed) {
        state.last_error = Some(e);
        return HostControl::Cancel as i32;
    }
    HostControl::Continue as i32
}

unsafe extern "C" fn write_chunk_trampoline<B, W, F>(
    ctx: *mut c_void,
    data: *const u8,
    len: usize,
) -> i32
where
    B: FnMut(&ArchiveEntry) -> Result<()>,
    W: FnMut(&[u8]) -> Result<()>,
    F: FnMut(usize) -> Result<()>,
{
    if ctx.is_null() || (data.is_null() && len > 0) {
        return HostControl::Cancel as i32;
    }
    let state = unsafe { &mut *(ctx as *mut ExtractCallbacksCtx<'_, B, W, F>) };
    if let Some(ctrl) = state.control {
        if let Err(e) = ctrl.checkpoint() {
            state.last_error = Some(e);
            return HostControl::Cancel as i32;
        }
    }
    let chunk = if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }
    };
    if let Err(e) = (state.on_write)(chunk) {
        state.last_error = Some(e);
        return HostControl::Cancel as i32;
    }
    HostControl::Continue as i32
}

unsafe extern "C" fn finish_entry_trampoline<B, W, F>(ctx: *mut c_void, entry_index: u64) -> i32
where
    B: FnMut(&ArchiveEntry) -> Result<()>,
    W: FnMut(&[u8]) -> Result<()>,
    F: FnMut(usize) -> Result<()>,
{
    if ctx.is_null() {
        return HostControl::Cancel as i32;
    }
    let state = unsafe { &mut *(ctx as *mut ExtractCallbacksCtx<'_, B, W, F>) };
    if let Err(e) = (state.on_finish)(entry_index as usize) {
        state.last_error = Some(e);
        return HostControl::Cancel as i32;
    }
    HostControl::Continue as i32
}
