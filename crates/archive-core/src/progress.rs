//! Non-blocking progress tracking, rolling MB/s throughput calculation, and Pause/Cancel synchronization.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::{Condvar, Mutex};

use crate::error::{ArchiveError, Result};

/// Cooperative execution controller shared between UI/CLI and worker threads.
#[derive(Default)]
pub struct TaskControl {
    cancelled: AtomicBool,
    paused: AtomicBool,
    pause_lock: Mutex<()>,
    pause_cvar: Condvar,
}

impl TaskControl {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.paused.store(false, Ordering::SeqCst);
        self.pause_cvar.notify_all();
    }

    pub fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    pub fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
        self.pause_cvar.notify_all();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// Invoked periodically by worker threads. Blocks with zero CPU usage while paused
    /// and returns `Err(ArchiveError::Cancelled)` immediately if cancelled.
    pub fn checkpoint(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(ArchiveError::Cancelled);
        }
        if self.paused.load(Ordering::Acquire) {
            let mut guard = self.pause_lock.lock();
            while self.paused.load(Ordering::Acquire) && !self.cancelled.load(Ordering::Relaxed) {
                self.pause_cvar.wait(&mut guard);
            }
            if self.cancelled.load(Ordering::Relaxed) {
                return Err(ArchiveError::Cancelled);
            }
        }
        Ok(())
    }
}

/// Read-only snapshot consumed by GUI task cards at 60 FPS without locking worker I/O.
#[derive(Debug, Clone)]
pub struct ProgressSnapshot {
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub files_done: u64,
    pub files_total: u64,
    pub current_item: String,
    pub speed_bytes_per_sec: f64,
    pub elapsed: Duration,
    pub eta: Option<Duration>,
    /// Recent throughput history (`MB/s`) for rendering real-time sparklines in the GUI.
    pub throughput_history_mbs: Vec<f32>,
}

impl ProgressSnapshot {
    pub fn fraction(&self) -> f32 {
        if self.bytes_total > 0 {
            (self.bytes_done as f64 / self.bytes_total as f64).clamp(0.0, 1.0) as f32
        } else if self.files_total > 0 {
            (self.files_done as f64 / self.files_total as f64).clamp(0.0, 1.0) as f32
        } else {
            0.0
        }
    }
}

struct ThroughputState {
    started_at: Instant,
    samples: VecDeque<(Instant, u64)>,
    history_mbs: VecDeque<f32>,
    last_history_tick: Instant,
    current_item: String,
}

/// Thread-safe progress aggregator updated by `rayon` workers and polled by the GUI/CLI.
pub struct ProgressTracker {
    bytes_done: AtomicU64,
    bytes_total: AtomicU64,
    files_done: AtomicU64,
    files_total: AtomicU64,
    state: Mutex<ThroughputState>,
}

impl ProgressTracker {
    pub fn new(bytes_total: u64, files_total: u64) -> Arc<Self> {
        let now = Instant::now();
        let mut samples = VecDeque::with_capacity(32);
        samples.push_back((now, 0));
        Arc::new(Self {
            bytes_done: AtomicU64::new(0),
            bytes_total: AtomicU64::new(bytes_total),
            files_done: AtomicU64::new(0),
            files_total: AtomicU64::new(files_total),
            state: Mutex::new(ThroughputState {
                started_at: now,
                samples,
                history_mbs: VecDeque::with_capacity(64),
                last_history_tick: now,
                current_item: String::new(),
            }),
        })
    }

    pub fn set_totals(&self, bytes_total: u64, files_total: u64) {
        self.bytes_total.store(bytes_total, Ordering::Relaxed);
        self.files_total.store(files_total, Ordering::Relaxed);
    }

    pub fn add_bytes(&self, delta: u64) {
        self.bytes_done.fetch_add(delta, Ordering::Relaxed);
    }

    pub fn inc_files(&self, delta: u64) {
        self.files_done.fetch_add(delta, Ordering::Relaxed);
    }

    pub fn set_current_item(&self, item: impl Into<String>) {
        let mut guard = self.state.lock();
        guard.current_item = item.into();
    }

    pub fn snapshot(&self) -> ProgressSnapshot {
        let now = Instant::now();
        let bytes_done = self.bytes_done.load(Ordering::Relaxed);
        let bytes_total = self.bytes_total.load(Ordering::Relaxed);
        let files_done = self.files_done.load(Ordering::Relaxed);
        let files_total = self.files_total.load(Ordering::Relaxed);

        let mut guard = self.state.lock();
        let elapsed = now.duration_since(guard.started_at);

        if guard
            .samples
            .back()
            .is_none_or(|(t, _)| now.duration_since(*t) >= Duration::from_millis(100))
        {
            guard.samples.push_back((now, bytes_done));
            while guard.samples.len() > 25 {
                guard.samples.pop_front();
            }
        }

        let speed_bps = if let (Some(&(t0, b0)), Some(&(t1, b1))) =
            (guard.samples.front(), guard.samples.back())
        {
            let dt = t1.duration_since(t0).as_secs_f64();
            if dt > 0.02 && b1 >= b0 {
                (b1 - b0) as f64 / dt
            } else if elapsed.as_secs_f64() > 0.02 {
                bytes_done as f64 / elapsed.as_secs_f64()
            } else {
                0.0
            }
        } else {
            0.0
        };

        if now.duration_since(guard.last_history_tick) >= Duration::from_millis(200) {
            guard.last_history_tick = now;
            let mbs = (speed_bps / (1024.0 * 1024.0)) as f32;
            guard.history_mbs.push_back(mbs);
            while guard.history_mbs.len() > 60 {
                guard.history_mbs.pop_front();
            }
        }

        let eta = if speed_bps > 1.0 && bytes_total > bytes_done {
            let rem_secs = (bytes_total - bytes_done) as f64 / speed_bps;
            Some(Duration::from_secs_f64(rem_secs.min(86_400.0 * 30.0)))
        } else {
            None
        };

        ProgressSnapshot {
            bytes_done,
            bytes_total,
            files_done,
            files_total,
            current_item: guard.current_item.clone(),
            speed_bytes_per_sec: speed_bps,
            elapsed,
            eta,
            throughput_history_mbs: guard.history_mbs.iter().copied().collect(),
        }
    }
}
