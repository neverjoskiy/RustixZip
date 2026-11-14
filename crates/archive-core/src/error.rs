//! Error types for `archive-core`.

use std::io;
use std::path::PathBuf;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, ArchiveError>;

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Unsupported or unrecognized archive format: {0}")]
    UnsupportedFormat(String),

    #[error("Format '{0}' is read-only and does not support archive creation or modification")]
    ReadOnlyFormat(String),

    #[error("Password is required to access encrypted archive or entry")]
    PasswordRequired,

    #[error("Invalid password or authentication tag mismatch")]
    InvalidPassword,

    #[error("Corrupted archive structure: {0}")]
    CorruptedArchive(String),

    #[error("Checksum mismatch for '{entry}': expected {expected}, computed {actual}")]
    ChecksumMismatch {
        entry: String,
        expected: String,
        actual: String,
    },

    #[error("Operation cancelled by user")]
    Cancelled,

    #[error("Entry not found in archive: {0}")]
    EntryNotFound(String),

    #[error("Unsafe or invalid archive path rejected: {0}")]
    UnsafePath(String),

    #[error("Missing split volume file: {0}")]
    MissingVolume(PathBuf),

    #[error("Plugin '{plugin}' error: {message}")]
    Plugin { plugin: String, message: String },

    #[error("Backend codec error: {0}")]
    Backend(String),
}
