//! Parallel checksum calculator supporting CRC32, CRC64-XZ, SHA-256, and SIMD/Rayon BLAKE3.

use std::io::Read;
use std::path::{Path, PathBuf};
use crc::{Crc, CRC_64_XZ};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::Result;
use crate::memory::{SmartFileReader, IO_BUF_SIZE, MMAP_THRESHOLD_BYTES};
use crate::progress::{ProgressTracker, TaskControl};

const CRC64_ENGINE: Crc<u64> = Crc::<u64>::new(&CRC_64_XZ);

/// Computed cryptographic and cyclic-redundancy digests for a single file or buffer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChecksumReport {
    pub path: Option<PathBuf>,
    pub size: u64,
    pub crc32: u32,
    pub crc64: u64,
    pub sha256: String,
    pub blake3: String,
}

impl ChecksumReport {
    pub fn crc32_hex(&self) -> String {
        format!("{:08X}", self.crc32)
    }

    pub fn crc64_hex(&self) -> String {
        format!("{:016X}", self.crc64)
    }
}

/// Computes CRC32, CRC64, SHA-256, and parallel BLAKE3 for an in-memory byte slice.
pub fn hash_bytes(data: &[u8]) -> ChecksumReport {
    let crc32 = crc32fast::hash(data);
    let crc64 = CRC64_ENGINE.checksum(data);
    let mut sha = Sha256::new();
    sha.update(data);
    let sha256 = hex_encode(&sha.finalize());

    let mut b3 = blake3::Hasher::new();
    if data.len() >= 128 * 1024 {
        b3.update_rayon(data);
    } else {
        b3.update(data);
    }
    let blake3 = b3.finalize().to_hex().to_string();

    ChecksumReport {
        path: None,
        size: data.len() as u64,
        crc32,
        crc64,
        sha256,
        blake3,
    }
}

/// Computes CRC32, CRC64, SHA-256, and BLAKE3 on a file with cooperative pause/cancel.
pub fn hash_file(
    path: &Path,
    control: Option<&TaskControl>,
    progress: Option<&ProgressTracker>,
) -> Result<ChecksumReport> {
    let meta = std::fs::metadata(path)?;
    let len = meta.len();

    if let Some(p) = progress {
        p.set_current_item(path.display().to_string());
    }

    // Fast path for memory-mappable large files: run BLAKE3 across all cores via `update_rayon`
    // in parallel with CRC32/CRC64/SHA-256!
    if len >= MMAP_THRESHOLD_BYTES {
        let file = std::fs::File::open(path)?;
        if let Ok(mmap) = unsafe { memmap2::Mmap::map(&file) } {
            if let Some(c) = control {
                c.checkpoint()?;
            }
            let slice: &[u8] = &mmap;
            let ((crc32, crc64), (sha256, blake3)) = rayon::join(
                || (crc32fast::hash(slice), CRC64_ENGINE.checksum(slice)),
                || {
                    rayon::join(
                        || {
                            let mut s = Sha256::new();
                            s.update(slice);
                            hex_encode(&s.finalize())
                        },
                        || {
                            let mut b3 = blake3::Hasher::new();
                            b3.update_rayon(slice);
                            b3.finalize().to_hex().to_string()
                        },
                    )
                },
            );
            if let Some(p) = progress {
                p.add_bytes(len);
                p.inc_files(1);
            }
            return Ok(ChecksumReport {
                path: Some(path.to_path_buf()),
                size: len,
                crc32,
                crc64,
                sha256,
                blake3,
            });
        }
    }

    let (mut reader, _) = SmartFileReader::open(path)?;
    let mut buf = vec![0u8; IO_BUF_SIZE];
    let mut crc32_hasher = crc32fast::Hasher::new();
    let mut crc64_digest = CRC64_ENGINE.digest();
    let mut sha256_hasher = Sha256::new();
    let mut blake3_hasher = blake3::Hasher::new();
    let mut total = 0u64;

    loop {
        if let Some(c) = control {
            c.checkpoint()?;
        }
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        crc32_hasher.update(chunk);
        crc64_digest.update(chunk);
        sha256_hasher.update(chunk);
        blake3_hasher.update(chunk);
        total += n as u64;
        if let Some(p) = progress {
            p.add_bytes(n as u64);
        }
    }

    if let Some(p) = progress {
        p.inc_files(1);
    }

    Ok(ChecksumReport {
        path: Some(path.to_path_buf()),
        size: total,
        crc32: crc32_hasher.finalize(),
        crc64: crc64_digest.finalize(),
        sha256: hex_encode(&sha256_hasher.finalize()),
        blake3: blake3_hasher.finalize().to_hex().to_string(),
    })
}

/// Computes checksum reports in parallel across files and recursively expanded directories.
pub fn hash_paths_parallel(
    paths: &[PathBuf],
    control: Option<&TaskControl>,
    progress: Option<&ProgressTracker>,
) -> Result<Vec<ChecksumReport>> {
    let mut files = Vec::new();
    let mut total_bytes = 0u64;
    for root in paths {
        if root.is_file() {
            total_bytes += root.metadata().map(|m| m.len()).unwrap_or(0);
            files.push(root.clone());
        } else if root.is_dir() {
            for entry in walkdir::WalkDir::new(root).into_iter().flatten() {
                if entry.file_type().is_file() {
                    total_bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
                    files.push(entry.into_path());
                }
            }
        }
    }

    if let Some(p) = progress {
        p.set_totals(total_bytes, files.len() as u64);
    }

    files
        .par_iter()
        .map(|file_path| hash_file(file_path, control, progress))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}
