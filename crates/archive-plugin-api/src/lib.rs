//! Stable `#[repr(C)]` C-ABI contract between `archive-core` and dynamic codec/format
//! plugins (`.dll` on Windows, `.so` on Linux).
//!
//! Every dynamic plugin exports a single symbol:
//! `pub extern "C" fn rustixzip_plugin_entry_v1() -> PluginExportV1`
//!
//! All data crosses the boundary via explicit C-compatible layouts, pointer+length slices,
//! and callback vtables so compiler versions or allocator layouts never collide.

use std::cell::RefCell;
use std::ffi::c_void;
use std::io::{self, Read, Seek, SeekFrom};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;
use zeroize::Zeroize;

/// Magic constant (`"RXZP_PLG"` in little-endian) identifying a valid RustixZip plugin header.
pub const RUSTIXZIP_PLUGIN_MAGIC: u64 = 0x504C_505F_505A_5852;

/// ABI revision implemented by this crate.
pub const RUSTIXZIP_PLUGIN_ABI_VERSION: u32 = 1;

/// Symbol name looked up via `libloading` when scanning the `plugins/` directory.
pub const RUSTIXZIP_PLUGIN_SYMBOL: &[u8] = b"rustixzip_plugin_entry_v1\0";

/// Result codes returned across the C-ABI boundary.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStatus {
    Ok = 0,
    InvalidArgument = -1,
    UnsupportedFormat = -2,
    IoError = -3,
    CorruptedArchive = -4,
    PasswordRequired = -5,
    WrongPassword = -6,
    Cancelled = -7,
    ChecksumMismatch = -8,
    InternalPanic = -99,
}

impl PluginStatus {
    pub fn from_code(code: i32) -> Self {
        match code {
            0 => Self::Ok,
            -1 => Self::InvalidArgument,
            -2 => Self::UnsupportedFormat,
            -3 => Self::IoError,
            -4 => Self::CorruptedArchive,
            -5 => Self::PasswordRequired,
            -6 => Self::WrongPassword,
            -7 => Self::Cancelled,
            -8 => Self::ChecksumMismatch,
            _ => Self::InternalPanic,
        }
    }
}

/// Flow-control signal returned by host progress/write callbacks.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostControl {
    Continue = 0,
    Cancel = 1,
}

/// Borrowed UTF-8 string slice with explicit pointer and byte length (`#[repr(C)]`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Utf8SliceFFI {
    pub ptr: *const u8,
    pub len: usize,
}

impl Utf8SliceFFI {
    pub const EMPTY: Self = Self {
        ptr: std::ptr::null(),
        len: 0,
    };

    pub fn from_str(s: &str) -> Self {
        Self {
            ptr: s.as_ptr(),
            len: s.len(),
        }
    }

    /// Converts the FFI slice into a borrowed `&str`, validating UTF-8.
    ///
    /// # Safety
    /// Caller must ensure `ptr` is valid for `len` bytes for lifetime `'a` when `len > 0`.
    pub unsafe fn as_str<'a>(self) -> Result<&'a str, std::str::Utf8Error> {
        if self.len == 0 || self.ptr.is_null() {
            return Ok("");
        }
        let bytes = unsafe { slice::from_raw_parts(self.ptr, self.len) };
        std::str::from_utf8(bytes)
    }
}

/// Capability bitflags advertised per format in a plugin.
pub mod capability_flags {
    pub const LIST: u32 = 1 << 0;
    pub const EXTRACT: u32 = 1 << 1;
    pub const TEST: u32 = 1 << 2;
    pub const ENCRYPTED_CONTENT: u32 = 1 << 3;
    pub const ENCRYPTED_HEADERS: u32 = 1 << 4;
    pub const MULTI_VOLUME: u32 = 1 << 5;
    pub const STREAM_INPUT: u32 = 1 << 6;
    pub const REQUIRES_FILESYSTEM_PATH: u32 = 1 << 7;
}

/// Entry attribute bitflags normalized across formats.
pub mod entry_flags {
    pub const IS_DIR: u32 = 1 << 0;
    pub const IS_SYMLINK: u32 = 1 << 1;
    pub const IS_ENCRYPTED: u32 = 1 << 2;
    pub const HAS_CRC32: u32 = 1 << 3;
}

/// Static metadata describing a single archive format handled by a plugin.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FormatDescriptorFFI {
    /// Short identifier such as `"rar"`, `"iso"`, `"wim"`, `"chm"`.
    pub id: Utf8SliceFFI,
    /// Human-readable display label such as `"RAR / RAR5 Archive"`.
    pub display_name: Utf8SliceFFI,
    /// Comma-separated lowercase extensions without leading dot (`"rar,r00"`).
    pub extensions_csv: Utf8SliceFFI,
    /// Bitmask of `capability_flags::*`.
    pub capabilities: u32,
}

unsafe impl Sync for FormatDescriptorFFI {}
unsafe impl Send for FormatDescriptorFFI {}

/// Seek origin constants for `StreamReaderVTable::seek`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeekOriginFFI {
    Start = 0,
    Current = 1,
    End = 2,
}

/// Host-supplied seekable input stream passed into plugins so plugins can read directly
/// from `SplitVolumeReader`, `Mmap`, or nested in-RAM buffers without temp copies.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StreamReaderVTable {
    pub ctx: *mut c_void,
    /// Optional UTF-8 filesystem path if the archive lives directly on disk (required by
    /// libraries like `unrar` when spanning multi-part `.part1.rar` volumes on disk).
    pub disk_path: Utf8SliceFFI,
    /// Reads up to `buf_len` bytes into `buf`, writing actual bytes read to `*out_read`.
    pub read: unsafe extern "C" fn(
        ctx: *mut c_void,
        buf: *mut u8,
        buf_len: usize,
        out_read: *mut usize,
    ) -> i32,
    /// Seeks relative to `origin`, writing the resulting absolute position to `*out_pos`.
    pub seek: unsafe extern "C" fn(
        ctx: *mut c_void,
        offset: i64,
        origin: u32,
        out_pos: *mut u64,
    ) -> i32,
    /// Total logical length of the input stream in bytes.
    pub total_len: u64,
}

/// Metadata record emitted for each archive entry during `list_entries`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ArchiveEntryFFI {
    pub index: u64,
    pub path: Utf8SliceFFI,
    pub symlink_target: Utf8SliceFFI,
    pub unpacked_size: u64,
    pub packed_size: u64,
    /// Unix timestamp in seconds (UTC).
    pub mtime_secs: i64,
    pub crc32: u32,
    pub unix_mode: u32,
    /// Bitmask of `entry_flags::*`.
    pub flags: u32,
}

/// Callback sink invoked by a plugin for each entry discovered in an archive.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EntrySinkVTable {
    pub ctx: *mut c_void,
    pub on_entry: unsafe extern "C" fn(ctx: *mut c_void, entry: *const ArchiveEntryFFI) -> i32,
}

/// Callback sink invoked by a plugin when extracting or testing selected entries.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExtractSinkVTable {
    pub ctx: *mut c_void,
    /// Begins extraction of `entry`. Returns `HostControl::Continue` (0) or `Cancel` (1).
    pub begin_entry: unsafe extern "C" fn(ctx: *mut c_void, entry: *const ArchiveEntryFFI) -> i32,
    /// Streams a decompressed data chunk for the active entry.
    pub write_chunk: unsafe extern "C" fn(ctx: *mut c_void, data: *const u8, len: usize) -> i32,
    /// Completes the active entry.
    pub finish_entry: unsafe extern "C" fn(ctx: *mut c_void, entry_index: u64) -> i32,
}

/// Optional password provider queried by a plugin when an archive or entry is encrypted.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PasswordProviderVTable {
    pub ctx: *mut c_void,
    /// Copies UTF-8 password bytes into `out_buf` (up to `buf_cap`), sets `*out_len`.
    /// Returns `0` if a password was supplied, `-1` if no password is available, `-2` if buffer too small.
    pub get_password: unsafe extern "C" fn(
        ctx: *mut c_void,
        out_buf: *mut u8,
        buf_cap: usize,
        out_len: *mut usize,
    ) -> i32,
}

impl PasswordProviderVTable {
    pub fn empty() -> Self {
        unsafe extern "C" fn no_password(
            _ctx: *mut c_void,
            _out_buf: *mut u8,
            _buf_cap: usize,
            out_len: *mut usize,
        ) -> i32 {
            if !out_len.is_null() {
                unsafe { *out_len = 0 };
            }
            -1
        }
        Self {
            ctx: std::ptr::null_mut(),
            get_password: no_password,
        }
    }

    /// Queries the host for a password, returning `Some(Zeroizing<String>)` if available.
    pub fn resolve_password(&self) -> Option<zeroize::Zeroizing<String>> {
        let mut buf = vec![0u8; 1024];
        let mut out_len = 0usize;
        let rc = unsafe { (self.get_password)(self.ctx, buf.as_mut_ptr(), buf.len(), &mut out_len) };
        if rc != 0 {
            buf.zeroize();
            return None;
        }
        let valid_len = out_len.min(buf.len());
        let parsed = std::str::from_utf8(&buf[..valid_len])
            .ok()
            .map(|s| zeroize::Zeroizing::new(s.to_owned()));
        buf.zeroize();
        parsed
    }
}

/// Exported vtable describing a dynamic codec/format plugin.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PluginExportV1 {
    pub magic: u64,
    pub abi_version: u32,
    pub plugin_id: Utf8SliceFFI,
    pub plugin_name: Utf8SliceFFI,
    pub plugin_version: Utf8SliceFFI,
    pub formats_ptr: *const FormatDescriptorFFI,
    pub formats_len: usize,

    /// Inspects magic header bytes (`header_ptr..header_len`) and file extension (`ext`),
    /// writing matched format ID into `out_format_id` if recognized.
    /// Returns `1` if matched, `0` if not recognized.
    pub probe_format: unsafe extern "C" fn(
        header_ptr: *const u8,
        header_len: usize,
        ext: Utf8SliceFFI,
        out_format_id: *mut Utf8SliceFFI,
    ) -> i32,

    /// Scans the archive and emits all entries to `sink`.
    pub list_entries: unsafe extern "C" fn(
        format_id: Utf8SliceFFI,
        stream: *const StreamReaderVTable,
        password: *const PasswordProviderVTable,
        sink: *const EntrySinkVTable,
    ) -> i32,

    /// Extracts selected entry indices (`indices_ptr..indices_len`; empty = extract all)
    /// into `sink`. If `test_only != 0`, decompresses and verifies checksums without
    /// requiring host disk output.
    pub extract_entries: unsafe extern "C" fn(
        format_id: Utf8SliceFFI,
        stream: *const StreamReaderVTable,
        password: *const PasswordProviderVTable,
        indices_ptr: *const u64,
        indices_len: usize,
        test_only: u32,
        sink: *const ExtractSinkVTable,
    ) -> i32,

    /// Copies the thread-local last error message into `out_buf` (up to `buf_cap` bytes),
    /// returning the number of UTF-8 bytes written.
    pub copy_last_error: unsafe extern "C" fn(out_buf: *mut u8, buf_cap: usize) -> usize,
}

unsafe impl Sync for PluginExportV1 {}
unsafe impl Send for PluginExportV1 {}

thread_local! {
    static LAST_PLUGIN_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Stores a human-readable error message in the plugin's thread-local error slot.
pub fn set_plugin_error(msg: impl Into<String>) {
    LAST_PLUGIN_ERROR.with(|slot| {
        *slot.borrow_mut() = msg.into();
    });
}

/// Standard implementation of `PluginExportV1::copy_last_error` usable by any plugin crate.
///
/// # Safety
/// If `buf_cap > 0`, `out_buf` must point to at least `buf_cap` writable bytes.
pub unsafe extern "C" fn default_copy_last_error(out_buf: *mut u8, buf_cap: usize) -> usize {
    if out_buf.is_null() || buf_cap == 0 {
        return 0;
    }
    LAST_PLUGIN_ERROR.with(|slot| {
        let err = slot.borrow();
        let bytes = err.as_bytes();
        let count = bytes.len().min(buf_cap);
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, count);
        }
        count
    })
}

/// Wraps an `extern "C"` plugin body in `catch_unwind`, converting panics into
/// `PluginStatus::InternalPanic` while recording the panic payload in thread-local error storage.
pub fn ffi_guard<F>(f: F) -> i32
where
    F: FnOnce() -> Result<(), (PluginStatus, String)>,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => PluginStatus::Ok as i32,
        Ok(Err((status, message))) => {
            set_plugin_error(message);
            status as i32
        }
        Err(payload) => {
            let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                format!("plugin panic: {s}")
            } else if let Some(s) = payload.downcast_ref::<String>() {
                format!("plugin panic: {s}")
            } else {
                "plugin panic: unknown payload".to_string()
            };
            set_plugin_error(msg);
            PluginStatus::InternalPanic as i32
        }
    }
}

/// Safe `Read + Seek` adapter used *inside* plugins to consume a `StreamReaderVTable`.
pub struct HostStreamAdapter {
    vtable: StreamReaderVTable,
}

impl HostStreamAdapter {
    /// Creates an adapter around a validated `StreamReaderVTable`.
    ///
    /// # Safety
    /// `stream` must point to a valid `StreamReaderVTable` outliving this adapter.
    pub unsafe fn from_raw(stream: *const StreamReaderVTable) -> io::Result<Self> {
        if stream.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "null StreamReaderVTable pointer",
            ));
        }
        Ok(Self {
            vtable: unsafe { *stream },
        })
    }

    pub fn total_len(&self) -> u64 {
        self.vtable.total_len
    }

    pub fn disk_path(&self) -> Option<&str> {
        let s = unsafe { self.vtable.disk_path.as_str().ok()? };
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
}

impl Read for HostStreamAdapter {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut out_read = 0usize;
        let rc = unsafe {
            (self.vtable.read)(
                self.vtable.ctx,
                buf.as_mut_ptr(),
                buf.len(),
                &mut out_read,
            )
        };
        if rc != 0 {
            return Err(io::Error::other(format!(
                "host stream read failed with code {rc}"
            )));
        }
        Ok(out_read)
    }
}

impl Seek for HostStreamAdapter {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let (offset, origin) = match pos {
            SeekFrom::Start(n) => {
                let off = i64::try_from(n).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "seek offset overflow")
                })?;
                (off, SeekOriginFFI::Start as u32)
            }
            SeekFrom::Current(off) => (off, SeekOriginFFI::Current as u32),
            SeekFrom::End(off) => (off, SeekOriginFFI::End as u32),
        };
        let mut out_pos = 0u64;
        let rc = unsafe { (self.vtable.seek)(self.vtable.ctx, offset, origin, &mut out_pos) };
        if rc != 0 {
            return Err(io::Error::other(format!(
                "host stream seek failed with code {rc}"
            )));
        }
        Ok(out_pos)
    }
}

/// Host-side wrapper exposing any `Read + Seek` Rust reader as a `StreamReaderVTable`.
pub struct OwnedStreamHost<'a, R: Read + Seek> {
    reader: &'a mut R,
    disk_path_bytes: Option<&'a str>,
    total_len: u64,
}

impl<'a, R: Read + Seek> OwnedStreamHost<'a, R> {
    pub fn new(reader: &'a mut R, total_len: u64, disk_path: Option<&'a str>) -> Self {
        Self {
            reader,
            disk_path_bytes: disk_path,
            total_len,
        }
    }

    pub fn as_vtable(&mut self) -> StreamReaderVTable {
        unsafe extern "C" fn read_trampoline<T: Read + Seek>(
            ctx: *mut c_void,
            buf: *mut u8,
            buf_len: usize,
            out_read: *mut usize,
        ) -> i32 {
            if ctx.is_null() || (buf.is_null() && buf_len > 0) || out_read.is_null() {
                return -1;
            }
            let reader = unsafe { &mut *(ctx as *mut T) };
            let slice = if buf_len == 0 {
                &mut []
            } else {
                unsafe { slice::from_raw_parts_mut(buf, buf_len) }
            };
            match reader.read(slice) {
                Ok(n) => {
                    unsafe { *out_read = n };
                    0
                }
                Err(_) => -3,
            }
        }

        unsafe extern "C" fn seek_trampoline<T: Read + Seek>(
            ctx: *mut c_void,
            offset: i64,
            origin: u32,
            out_pos: *mut u64,
        ) -> i32 {
            if ctx.is_null() || out_pos.is_null() {
                return -1;
            }
            let reader = unsafe { &mut *(ctx as *mut T) };
            let seek_from = match origin {
                0 => {
                    if offset < 0 {
                        return -1;
                    }
                    SeekFrom::Start(offset as u64)
                }
                1 => SeekFrom::Current(offset),
                2 => SeekFrom::End(offset),
                _ => return -1,
            };
            match reader.seek(seek_from) {
                Ok(pos) => {
                    unsafe { *out_pos = pos };
                    0
                }
                Err(_) => -3,
            }
        }

        let disk_path = match self.disk_path_bytes {
            Some(p) => Utf8SliceFFI::from_str(p),
            None => Utf8SliceFFI::EMPTY,
        };

        StreamReaderVTable {
            ctx: (self.reader as *mut R).cast::<c_void>(),
            disk_path,
            read: read_trampoline::<R>,
            seek: seek_trampoline::<R>,
            total_len: self.total_len,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_stream_vtable_read_and_seek() {
        let payload = b"RustixZip-C-ABI-Stream-Test-Payload-0123456789";
        let mut cursor = Cursor::new(payload.as_slice());
        let mut host = OwnedStreamHost::new(&mut cursor, payload.len() as u64, Some("/tmp/a.rar"));
        let vtable = host.as_vtable();

        let mut adapter = unsafe { HostStreamAdapter::from_raw(&vtable).expect("valid adapter") };
        assert_eq!(adapter.total_len(), payload.len() as u64);
        assert_eq!(adapter.disk_path(), Some("/tmp/a.rar"));

        let mut head = [0u8; 9];
        adapter.read_exact(&mut head).expect("read head");
        assert_eq!(&head, b"RustixZip");

        let pos = adapter.seek(SeekFrom::End(-10)).expect("seek end");
        assert_eq!(pos, (payload.len() - 10) as u64);

        let mut tail = Vec::new();
        adapter.read_to_end(&mut tail).expect("read tail");
        assert_eq!(&tail, b"0123456789");
    }

    #[test]
    fn ffi_guard_catches_panics_and_records_error() {
        let rc = ffi_guard(|| -> Result<(), (PluginStatus, String)> {
            panic!("simulated plugin crash");
        });
        assert_eq!(PluginStatus::from_code(rc), PluginStatus::InternalPanic);

        let mut buf = [0u8; 128];
        let written = unsafe { default_copy_last_error(buf.as_mut_ptr(), buf.len()) };
        let msg = std::str::from_utf8(&buf[..written]).expect("utf8 error");
        assert!(msg.contains("simulated plugin crash"), "actual msg: {msg}");
    }

    #[test]
    fn password_provider_zeroizes_and_resolves() {
        unsafe extern "C" fn supply_secret(
            _ctx: *mut c_void,
            out_buf: *mut u8,
            buf_cap: usize,
            out_len: *mut usize,
        ) -> i32 {
            let secret = b"S3cr3t!Pass";
            if buf_cap < secret.len() {
                return -2;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(secret.as_ptr(), out_buf, secret.len());
                *out_len = secret.len();
            }
            0
        }

        let provider = PasswordProviderVTable {
            ctx: std::ptr::null_mut(),
            get_password: supply_secret,
        };
        let resolved = provider.resolve_password().expect("password present");
        assert_eq!(resolved.as_str(), "S3cr3t!Pass");
    }
}
