# RustixZip

Ultra-fast, multi-core desktop archive manager and archiver written in Rust, inspired by 7-Zip File Manager.

## Architecture

- **`crates/archive-plugin-api`** — Stable `#[repr(C)]` C-ABI contract for dynamic format/codec plugins (`.dll` / `.so`).
- **`crates/archive-core`** — Multi-core compression/decompression engine, Arena Radix-Trie VFS, Sparse Stream Checkpoints, Recursive Nested Archive stack, Live External Editor watcher, Split Volumes (`.001`), AES-256 & SIMD Checksums (`CRC32`, `CRC64`, `SHA-256`, `BLAKE3`).
- **`crates/plugin-unrar`** — Dynamic plugin supporting RAR4 & RAR5 (encrypted headers, split volumes, testing & extraction).
- **`crates/plugin-libarchive`** — Dynamic plugin linking `libarchive` plus dedicated container decoders for `.iso`, `.cab`, `.wim`, `.dmg`, `.deb`, `.rpm`, `.msi`, `.cpio`, `.arj`, `.lzh`, and `.chm`.
- **`crates/rustixzip-cli`** — Multi-core command-line utility (`rustixzip`).
- **`crates/rustixzip-gui`** — Responsive `egui`/`eframe` File Manager (`rustixzip-fm`) with Dual-Pane (`F9`), Tabs (`Ctrl+T`), Fast Text/Hex Viewer (`F3`), non-blocking task cards, and bidirectional native OS Drag & Drop.
- **`crates/shell-ext-win`** — Windows 10 (`IContextMenu`) & Windows 11 (`IExplorerCommand` + Sparse Package) context menu shell extension (`rustixzip_shell.dll`).
- **`crates/shell-ext-linux`** — Desktop integration generator for KDE Dolphin, GNOME Nautilus, Cinnamon Nemo, XFCE Thunar, and XDG MIME associations.

## Building

All builds, tests, static C/C++ library linking, and release artifact packaging are automated via GitHub Actions (`ci.yml` and `release.yml`) for Windows x64 and Linux x64.
