//! Transparent multi-volume (`.001`, `.002`, ...) concatenated reader and volume-slicing writer.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Discovers all sequential split volumes (`.001`, `.002`, ...) starting from `.001`
/// when given any volume path or single-file path.
pub fn resolve_volume_paths(path: &Path) -> io::Result<Vec<PathBuf>> {
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid archive file name"))?;

    if let Some(dot_idx) = file_name.rfind('.') {
        let ext = &file_name[dot_idx + 1..];
        if ext.len() == 3 && ext.bytes().all(|b| b.is_ascii_digit()) {
            let prefix = &file_name[..dot_idx];
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            let mut volumes = Vec::new();
            let mut index = 1u32;
            loop {
                let candidate_name = format!("{prefix}.{index:03}");
                let candidate = parent.join(candidate_name);
                if candidate.is_file() {
                    volumes.push(candidate);
                    index += 1;
                } else {
                    break;
                }
            }
            if !volumes.is_empty() {
                return Ok(volumes);
            }
        }
    }

    if path.is_file() {
        Ok(vec![path.to_path_buf()])
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("archive file not found: {}", path.display()),
        ))
    }
}

struct VolumeSegment {
    path: PathBuf,
    start_offset: u64,
    len: u64,
    file: Option<File>,
}

/// Presents either a single archive file or a sequence of `.001, .002, ...` volumes
/// as a single contiguous `Read + Seek` stream.
pub struct SplitVolumeReader {
    segments: Vec<VolumeSegment>,
    total_len: u64,
    pos: u64,
}

impl SplitVolumeReader {
    pub fn open(path: &Path) -> io::Result<Self> {
        let paths = resolve_volume_paths(path)?;
        let mut segments = Vec::with_capacity(paths.len());
        let mut offset = 0u64;
        for p in paths {
            let len = std::fs::metadata(&p)?.len();
            segments.push(VolumeSegment {
                path: p,
                start_offset: offset,
                len,
                file: None,
            });
            offset = offset.saturating_add(len);
        }
        Ok(Self {
            segments,
            total_len: offset,
            pos: 0,
        })
    }

    pub fn total_len(&self) -> u64 {
        self.total_len
    }

    pub fn volume_count(&self) -> usize {
        self.segments.len()
    }

    pub fn primary_path(&self) -> Option<&Path> {
        self.segments.first().map(|s| s.path.as_path())
    }

    fn locate_segment_index(&self, pos: u64) -> Option<usize> {
        if pos >= self.total_len {
            return None;
        }
        self.segments
            .binary_search_by(|seg| {
                if pos < seg.start_offset {
                    std::cmp::Ordering::Greater
                } else if pos >= seg.start_offset + seg.len {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok()
    }
}

impl Read for SplitVolumeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.total_len {
            return Ok(0);
        }
        let seg_idx = match self.locate_segment_index(self.pos) {
            Some(idx) => idx,
            None => return Ok(0),
        };
        let seg = &mut self.segments[seg_idx];
        if seg.file.is_none() {
            seg.file = Some(File::open(&seg.path)?);
        }
        let local_offset = self.pos - seg.start_offset;
        let max_in_seg = (seg.len - local_offset) as usize;
        let to_read = buf.len().min(max_in_seg);

        let file = seg.file.as_mut().expect("segment file opened");
        file.seek(SeekFrom::Start(local_offset))?;
        let n = file.read(&mut buf[..to_read])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SplitVolumeReader {
    fn seek(&mut self, style: SeekFrom) -> io::Result<u64> {
        let next = match style {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::Current(off) => self.pos as i128 + off as i128,
            SeekFrom::End(off) => self.total_len as i128 + off as i128,
        };
        if next < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot seek before start of archive stream",
            ));
        }
        self.pos = next as u64;
        Ok(self.pos)
    }
}

/// Slices any output archive stream into `.001`, `.002`, ... volume files of `volume_size` bytes,
/// or writes a single file if `volume_size` is `None`.
pub struct SplitVolumeWriter {
    base_path: PathBuf,
    volume_size: Option<u64>,
    current_file: Option<File>,
    current_vol_index: u32,
    current_vol_written: u64,
    total_written: u64,
    created_paths: Vec<PathBuf>,
}

impl SplitVolumeWriter {
    pub fn create(base_path: &Path, volume_size: Option<u64>) -> io::Result<Self> {
        if let Some(vs) = volume_size {
            if vs < 4096 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "split volume size must be at least 4096 bytes",
                ));
            }
        }
        if let Some(parent) = base_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut writer = Self {
            base_path: base_path.to_path_buf(),
            volume_size,
            current_file: None,
            current_vol_index: 0,
            current_vol_written: 0,
            total_written: 0,
            created_paths: Vec::new(),
        };
        writer.open_next_volume()?;
        Ok(writer)
    }

    fn open_next_volume(&mut self) -> io::Result<()> {
        if let Some(mut prev) = self.current_file.take() {
            prev.flush()?;
        }
        self.current_vol_index += 1;
        self.current_vol_written = 0;

        let target_path = if self.volume_size.is_some() {
            let base = self.base_path.to_string_lossy();
            let stripped = base.strip_suffix(".001").unwrap_or(base.as_ref());
            PathBuf::from(format!("{stripped}.{:03}", self.current_vol_index))
        } else {
            self.base_path.clone()
        };

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&target_path)?;
        self.created_paths.push(target_path);
        self.current_file = Some(file);
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<Vec<PathBuf>> {
        if let Some(mut f) = self.current_file.take() {
            f.flush()?;
        }
        Ok(self.created_paths)
    }

    pub fn total_written(&self) -> u64 {
        self.total_written
    }
}

impl Write for SplitVolumeWriter {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let original_len = buf.len();
        match self.volume_size {
            None => {
                let f = self.current_file.as_mut().expect("output file open");
                let n = f.write(buf)?;
                self.current_vol_written += n as u64;
                self.total_written += n as u64;
                Ok(n)
            }
            Some(limit) => {
                while !buf.is_empty() {
                    if self.current_vol_written >= limit {
                        self.open_next_volume()?;
                    }
                    let room = (limit - self.current_vol_written) as usize;
                    let chunk_len = buf.len().min(room);
                    let f = self.current_file.as_mut().expect("volume open");
                    f.write_all(&buf[..chunk_len])?;
                    self.current_vol_written += chunk_len as u64;
                    self.total_written += chunk_len as u64;
                    buf = &buf[chunk_len..];
                }
                Ok(original_len)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(f) = self.current_file.as_mut() {
            f.flush()?;
        }
        Ok(())
    }
}
