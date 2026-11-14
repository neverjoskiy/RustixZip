//! Live external file editing watcher (`notify::RecommendedWatcher`).
//!
//! When the user opens a file from inside an archive in an external editor (`Enter` / `F4`),
//! it is extracted to an isolated session directory and monitored for modifications so the
//! archive can be updated seamlessly when the editor saves changes.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use crossbeam_channel::{unbounded, Receiver};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::Mutex;
use tempfile::TempDir;

use crate::error::{ArchiveError, Result};

/// Event emitted to the GUI whenever a tracked extracted file has been modified and saved on disk.
#[derive(Debug, Clone)]
pub struct LiveEditEvent {
    pub archive_path: PathBuf,
    pub entry_virtual_path: String,
    pub temp_disk_path: PathBuf,
    pub new_size: u64,
}

#[derive(Clone)]
struct TrackedFile {
    archive_path: PathBuf,
    entry_virtual_path: String,
    last_mtime: Option<SystemTime>,
    last_size: u64,
    last_notified: Instant,
}

/// Manages temporary extracted files opened in external editors and emits `LiveEditEvent`s on save.
pub struct LiveEditSession {
    temp_dir: TempDir,
    tracked: Arc<Mutex<HashMap<PathBuf, TrackedFile>>>,
    _watcher: RecommendedWatcher,
    events_rx: Receiver<LiveEditEvent>,
}

impl LiveEditSession {
    pub fn new() -> Result<Self> {
        let temp_dir = tempfile::Builder::new()
            .prefix("rustixzip_live_edit_")
            .tempdir()?;

        let tracked: Arc<Mutex<HashMap<PathBuf, TrackedFile>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let tracked_cb = Arc::clone(&tracked);
        let (events_tx, events_rx) = unbounded();

        let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                if !matches!(
                    event.kind,
                    EventKind::Modify(_) | EventKind::Create(_) | EventKind::Any
                ) {
                    return;
                }
                for raw_path in event.paths {
                    let canonical = std::fs::canonicalize(&raw_path).unwrap_or(raw_path);
                    let mut map = tracked_cb.lock();
                    if let Some(entry) = map.get_mut(&canonical) {
                        if entry.last_notified.elapsed() < Duration::from_millis(400) {
                            continue;
                        }
                        if let Ok(meta) = std::fs::metadata(&canonical) {
                            let mtime = meta.modified().ok();
                            let size = meta.len();
                            if mtime != entry.last_mtime || size != entry.last_size {
                                entry.last_mtime = mtime;
                                entry.last_size = size;
                                entry.last_notified = Instant::now();
                                let _ = events_tx.send(LiveEditEvent {
                                    archive_path: entry.archive_path.clone(),
                                    entry_virtual_path: entry.entry_virtual_path.clone(),
                                    temp_disk_path: canonical.clone(),
                                    new_size: size,
                                });
                            }
                        }
                    }
                }
            }
        })
        .map_err(|e| ArchiveError::Backend(format!("failed to start file watcher: {e}")))?;

        watcher
            .watch(temp_dir.path(), RecursiveMode::Recursive)
            .map_err(|e| ArchiveError::Backend(format!("failed to watch temp edit dir: {e}")))?;

        Ok(Self {
            temp_dir,
            tracked,
            _watcher: watcher,
            events_rx,
        })
    }

    pub fn session_dir(&self) -> &Path {
        self.temp_dir.path()
    }

    /// Writes `bytes` for `entry_virtual_path` into the session temp directory and starts watching it.
    pub fn stage_and_track(
        &self,
        archive_path: &Path,
        entry_virtual_path: &str,
        bytes: &[u8],
    ) -> Result<PathBuf> {
        let rel = entry_virtual_path.trim_start_matches(['/', '\\']);
        let target = self.temp_dir.path().join(rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&target, bytes)?;
        let canonical = std::fs::canonicalize(&target).unwrap_or(target);
        let meta = std::fs::metadata(&canonical)?;

        self.tracked.lock().insert(
            canonical.clone(),
            TrackedFile {
                archive_path: archive_path.to_path_buf(),
                entry_virtual_path: entry_virtual_path.to_string(),
                last_mtime: meta.modified().ok(),
                last_size: meta.len(),
                last_notified: Instant::now(),
            },
        );
        Ok(canonical)
    }

    /// Non-blocking poll of pending external save notifications.
    pub fn drain_events(&self) -> Vec<LiveEditEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = self.events_rx.try_recv() {
            out.push(ev);
        }
        out
    }
}
