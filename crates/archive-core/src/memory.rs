//! Bounded recycled buffer pool and adaptive memory-mapped / buffered file reader.

use std::fs::File;
use std::io::{self, Cursor, Read};
use std::path::Path;
use std::sync::Arc;
use crossbeam_channel::{bounded, Receiver, Sender};
use memmap2::Mmap;
use sysinfo::{MemoryRefreshKind, RefreshKind, System};

/// Threshold (`8 MiB`) at or above which regular files are mapped via `memmap2::Mmap`.
pub const MMAP_THRESHOLD_BYTES: u64 = 8 * 1024 * 1024;

/// Standard I/O copy buffer size (`128 KiB`).
pub const IO_BUF_SIZE: usize = 128 * 1024;

/// Standard block-compression buffer size (`4 MiB`).
pub const CHUNK_BUF_SIZE: usize = 4 * 1024 * 1024;

/// Computes a safe upper RAM bound (`min(512 MiB, 25% available system memory)`, at least `64 MiB`).
pub fn compute_optimal_memory_budget_bytes() -> usize {
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_memory(MemoryRefreshKind::new().with_ram()),
    );
    sys.refresh_memory();
    let avail = sys.available_memory();
    let quarter = (avail / 4) as usize;
    quarter.clamp(64 * 1024 * 1024, 512 * 1024 * 1024)
}

/// Recycled byte-vector slab pool preventing repeated OS page allocation/zeroing across `rayon` workers.
#[derive(Clone)]
pub struct BufferPool {
    io_tx: Sender<Vec<u8>>,
    io_rx: Receiver<Vec<u8>>,
    chunk_tx: Sender<Vec<u8>>,
    chunk_rx: Receiver<Vec<u8>>,
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::with_budget(compute_optimal_memory_budget_bytes())
    }
}

impl BufferPool {
    pub fn new_adaptive() -> Self {
        Self::default()
    }

    pub fn with_budget(budget_bytes: usize) -> Self {
        let max_chunks = (budget_bytes / CHUNK_BUF_SIZE).clamp(4, 128);
        let max_io = ((budget_bytes / 8) / IO_BUF_SIZE).clamp(16, 512);
        let (io_tx, io_rx) = bounded(max_io);
        let (chunk_tx, chunk_rx) = bounded(max_chunks);
        Self {
            io_tx,
            io_rx,
            chunk_tx,
            chunk_rx,
        }
    }

    pub fn checkout_io(&self) -> PooledBuffer {
        let mut buf = self
            .io_rx
            .try_recv()
            .unwrap_or_else(|_| Vec::with_capacity(IO_BUF_SIZE));
        buf.resize(IO_BUF_SIZE, 0);
        PooledBuffer {
            buf: Some(buf),
            return_tx: self.io_tx.clone(),
        }
    }

    pub fn checkout_chunk(&self) -> PooledBuffer {
        let mut buf = self
            .chunk_rx
            .try_recv()
            .unwrap_or_else(|_| Vec::with_capacity(CHUNK_BUF_SIZE));
        buf.clear();
        PooledBuffer {
            buf: Some(buf),
            return_tx: self.chunk_tx.clone(),
        }
    }
}

/// RAII buffer returned automatically to `BufferPool` on drop.
pub struct PooledBuffer {
    buf: Option<Vec<u8>>,
    return_tx: Sender<Vec<u8>>,
}

impl PooledBuffer {
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_deref().unwrap_or(&[])
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buf.as_deref_mut().unwrap_or(&mut [])
    }

    pub fn vec_mut(&mut self) -> &mut Vec<u8> {
        self.buf.as_mut().expect("pooled buffer active")
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(mut v) = self.buf.take() {
            v.clear();
            let _ = self.return_tx.try_send(v);
        }
    }
}

/// Adaptive read source: uses `memmap2::Mmap` for large regular files (`>= 8 MiB`) and
/// falls back cleanly to standard file descriptors for small/locked/special files.
pub enum SmartFileReader {
    Mapped(Cursor<Arc<Mmap>>),
    Buffered(io::BufReader<File>),
    Empty,
}

impl SmartFileReader {
    pub fn open(path: &Path) -> io::Result<(Self, u64)> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        if len == 0 {
            return Ok((Self::Empty, 0));
        }
        if len >= MMAP_THRESHOLD_BYTES {
            // SAFETY: Read-only mapping; falls back to buffered File I/O if OS rejects mmap.
            if let Ok(mmap) = unsafe { Mmap::map(&file) } {
                return Ok((Self::Mapped(Cursor::new(Arc::new(mmap))), len));
            }
        }
        Ok((Self::Buffered(io::BufReader::with_capacity(IO_BUF_SIZE, file)), len))
    }
}

impl Read for SmartFileReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Mapped(cursor) => cursor.read(buf),
            Self::Buffered(reader) => reader.read(buf),
            Self::Empty => Ok(0),
        }
    }
}
