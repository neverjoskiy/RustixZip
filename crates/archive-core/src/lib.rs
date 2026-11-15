//! `archive-core` — Multi-core archive engine, Arena Radix-Trie VFS, streaming checkpoint index,
//! recursive nested mounting, split-volume I/O, parallel checksums, and C-ABI plugin host for RustixZip.

pub mod backends;
pub mod checksum;
pub mod engine;
pub mod error;
pub mod memory;
pub mod plugin_host;
pub mod progress;
pub mod split;
pub mod types;
pub mod vfs;
pub mod watcher;

pub use backends::collect_pack_inputs;
pub use checksum::{hash_bytes, hash_file, ChecksumReport};
pub use engine::{
    ArchiveEngine, ArchiveSourceStream, BreadcrumbSegment, EnterOutcome, MountLayer, OpenArchive,
    VfsMountStack,
};
pub use error::{ArchiveError, Result};
pub use memory::{BufferPool, PooledBuffer, SmartFileReader};
pub use plugin_host::{LoadedPlugin, PluginFormatInfo, PluginRegistry};
pub use progress::{ProgressSnapshot, ProgressTracker, TaskControl};
pub use split::{resolve_volume_paths, SplitVolumeReader, SplitVolumeWriter};
pub use types::{
    sanitize_archive_path, ArchiveEntry, ArchiveFormat, ArchiveSummary, ExtractOptions,
    OverwritePolicy, PackInput, PackOptions, ZipCompressionMethod,
};
pub use vfs::{
    NestedBacking, NodeId, SortColumn, StrRef, StreamCheckpoint, StreamCheckpointIndex,
    StringArena, VfsNode, VfsTree,
};
pub use watcher::{LiveEditEvent, LiveEditSession};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    fn populate_sample_tree(root: &std::path::Path) -> Vec<PathBuf> {
        let src = root.join("sample_src");
        std::fs::create_dir_all(src.join("docs/nested")).unwrap();
        std::fs::create_dir_all(src.join("empty_folder")).unwrap();

        let readme = b"RustixZip multi-core archive engine sample README.\n".repeat(120);
        let binary: Vec<u8> = (0u32..48_000)
            .flat_map(|i| i.wrapping_mul(0x9E37_79B9).to_le_bytes())
            .collect();
        let nested_txt = b"Deeply nested configuration payload = 42\n";

        std::fs::write(src.join("README.md"), &readme).unwrap();
        std::fs::write(src.join("payload.bin"), &binary).unwrap();
        std::fs::write(src.join("docs/nested/config.toml"), nested_txt).unwrap();

        vec![src]
    }

    #[test]
    fn sanitize_rejects_traversal_and_absolute_paths() {
        assert_eq!(sanitize_archive_path("../../etc/passwd"), None);
        assert_eq!(sanitize_archive_path("foo/../../../bar"), None);
        assert_eq!(sanitize_archive_path("C:\\Windows\\System32\\cmd.exe"), None);
        assert_eq!(
            sanitize_archive_path("/var/log/syslog"),
            Some("var/log/syslog".to_string())
        );
        assert_eq!(
            sanitize_archive_path("folder\\sub\\item.txt"),
            Some("folder/sub/item.txt".to_string())
        );
    }

    #[test]
    fn checksum_engine_matches_known_vectors() {
        let report = hash_bytes(b"123456789");
        assert_eq!(report.crc32, 0xCBF4_3926);
        assert_eq!(report.crc64, 0x995D_C9BB_DF19_39FA);
        assert_eq!(
            report.sha256,
            "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225"
        );
        assert_eq!(report.blake3.len(), 64);
    }

    #[test]
    fn sevenz_solid_and_aes256_encrypted_headers_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let sources = populate_sample_tree(tmp.path());
        let engine = ArchiveEngine::new();

        // 1. Standard solid LZMA2 .7z
        let plain_7z = tmp.path().join("solid.7z");
        let opts = PackOptions {
            format: ArchiveFormat::SevenZip,
            level: 5,
            solid: true,
            ..Default::default()
        };
        engine
            .pack_paths(&plain_7z, &sources, "", &opts, None, None)
            .unwrap();

        let opened = engine.open_path(&plain_7z, None, None).unwrap();
        assert_eq!(opened.format, ArchiveFormat::SevenZip);
        assert!(opened.file_count() >= 3);

        engine
            .test(&opened, &ExtractOptions::full_with_paths(), None, None)
            .unwrap();

        let out_dir = tmp.path().join("out_7z");
        engine
            .extract(&opened, &out_dir, &ExtractOptions::full_with_paths(), None, None)
            .unwrap();
        assert_eq!(
            std::fs::read(out_dir.join("sample_src/docs/nested/config.toml")).unwrap(),
            b"Deeply nested configuration payload = 42\n"
        );

        // 2. AES-256 + Encrypted Headers .7z
        let enc_7z = tmp.path().join("secret.7z");
        let pw = Zeroizing::new("Rustix$Strong#Pass2026".to_string());
        let enc_opts = PackOptions {
            format: ArchiveFormat::SevenZip,
            level: 5,
            solid: true,
            password: Some(pw.clone()),
            encrypt_headers: true,
            ..Default::default()
        };
        engine
            .pack_paths(&enc_7z, &sources, "", &enc_opts, None, None)
            .unwrap();

        // Without password, opening encrypted-header 7z must demand a password
        let err_no_pw = engine.open_path(&enc_7z, None, None).unwrap_err();
        assert!(matches!(
            err_no_pw,
            ArchiveError::PasswordRequired | ArchiveError::InvalidPassword
        ));

        // With wrong password, opening must fail
        let wrong_pw = Zeroizing::new("wrong-password".to_string());
        assert!(engine.open_path(&enc_7z, Some(wrong_pw), None).is_err());

        // With valid password, listing, previewing, testing, and extracting succeed
        let enc_opened = engine.open_path(&enc_7z, Some(pw), None).unwrap();
        engine
            .test(&enc_opened, &ExtractOptions::full_with_paths(), None, None)
            .unwrap();
        let config_idx = enc_opened
            .entries
            .iter()
            .find(|e| e.path.ends_with("config.toml"))
            .unwrap()
            .index;
        let preview = engine
            .read_entry_bytes(&enc_opened, config_idx, Some(16), None, None)
            .unwrap();
        assert_eq!(&preview, b"Deeply nested co");
    }

    #[test]
    fn zip_parallel_aes256_and_zero_recompress_modify() {
        let tmp = TempDir::new().unwrap();
        let sources = populate_sample_tree(tmp.path());
        let engine = ArchiveEngine::new();

        for method in [
            ZipCompressionMethod::Deflate,
            ZipCompressionMethod::Zstd,
            ZipCompressionMethod::Bzip2,
            ZipCompressionMethod::Xz,
            ZipCompressionMethod::Stored,
        ] {
            let zip_path = tmp.path().join(format!("archive_{method:?}.zip"));
            let opts = PackOptions {
                format: ArchiveFormat::Zip,
                level: 5,
                zip_method: method,
                ..Default::default()
            };
            engine
                .pack_paths(&zip_path, &sources, "", &opts, None, None)
                .unwrap();
            let opened = engine.open_path(&zip_path, None, None).unwrap();
            engine
                .test(&opened, &ExtractOptions::full_with_paths(), None, None)
                .unwrap();
        }

        // Test zero-recompression modify_archive (remove payload.bin, add extra.txt)
        let mod_zip = tmp.path().join("modifiable.zip");
        let mod_opts = PackOptions {
            format: ArchiveFormat::Zip,
            level: 6,
            zip_method: ZipCompressionMethod::Deflate,
            ..Default::default()
        };
        engine
            .pack_paths(&mod_zip, &sources, "", &mod_opts, None, None)
            .unwrap();

        let extra_file = tmp.path().join("extra.txt");
        std::fs::write(&extra_file, b"Added via zero-recompress modify!").unwrap();

        let mut removals = HashSet::new();
        removals.insert("sample_src/payload.bin".to_string());
        let additions = vec![PackInput {
            disk_path: extra_file,
            archive_path: "sample_src/extra.txt".to_string(),
        }];

        engine
            .modify_archive(&mod_zip, &removals, &additions, &mod_opts, None, None)
            .unwrap();

        let updated = engine.open_path(&mod_zip, None, None).unwrap();
        assert!(!updated
            .entries
            .iter()
            .any(|e| e.path.ends_with("payload.bin")));
        let extra_idx = updated
            .entries
            .iter()
            .find(|e| e.path == "sample_src/extra.txt")
            .unwrap()
            .index;
        let extra_bytes = engine
            .read_entry_bytes(&updated, extra_idx, None, None, None)
            .unwrap();
        assert_eq!(extra_bytes, b"Added via zero-recompress modify!");

        // Test WinZip AE-2 AES-256 encrypted ZIP
        let aes_zip = tmp.path().join("aes256.zip");
        let pw = Zeroizing::new("ZipAes256!Secret".to_string());
        let aes_opts = PackOptions {
            format: ArchiveFormat::Zip,
            level: 5,
            password: Some(pw.clone()),
            ..Default::default()
        };
        engine
            .pack_paths(&aes_zip, &sources, "", &aes_opts, None, None)
            .unwrap();

        let aes_opened = engine.open_path(&aes_zip, None, None).unwrap();
        assert!(aes_opened.has_encrypted_entries);
        assert!(matches!(
            engine.test(&aes_opened, &ExtractOptions::full_with_paths(), None, None),
            Err(ArchiveError::PasswordRequired)
        ));

        let mut dec_opts = ExtractOptions::full_with_paths();
        dec_opts.password = Some(pw);
        engine.test(&aes_opened, &dec_opts, None, None).unwrap();
    }

    #[test]
    fn tar_and_single_stream_codecs_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let sources = populate_sample_tree(tmp.path());
        let engine = ArchiveEngine::new();

        for (ext, fmt) in [
            ("tar", ArchiveFormat::Tar),
            ("tar.gz", ArchiveFormat::TarGz),
            ("tar.zst", ArchiveFormat::TarZst),
            ("tar.xz", ArchiveFormat::TarXz),
            ("tar.lz4", ArchiveFormat::TarLz4),
            ("tar.bz2", ArchiveFormat::TarBz2),
        ] {
            let out_archive = tmp.path().join(format!("bundle.{ext}"));
            let opts = PackOptions {
                format: fmt,
                level: 4,
                ..Default::default()
            };
            engine
                .pack_paths(&out_archive, &sources, "", &opts, None, None)
                .unwrap();

            let opened = engine.open_path(&out_archive, None, None).unwrap();
            assert_eq!(opened.format, fmt);
            engine
                .test(&opened, &ExtractOptions::full_with_paths(), None, None)
                .unwrap();

            let cfg_idx = opened
                .entries
                .iter()
                .find(|e| e.path.ends_with("config.toml"))
                .unwrap()
                .index;
            let data = engine
                .read_entry_bytes(&opened, cfg_idx, None, None, None)
                .unwrap();
            assert_eq!(data, b"Deeply nested configuration payload = 42\n");
        }

        // Single-file streams (.zst, .gz, .xz, .lz4, .bz2)
        let single_src = tmp.path().join("report.json");
        let payload = br#"{"engine":"RustixZip","multicore":true}"#.repeat(250);
        std::fs::write(&single_src, &payload).unwrap();

        for (ext, fmt) in [
            ("zst", ArchiveFormat::Zst),
            ("gz", ArchiveFormat::Gz),
            ("xz", ArchiveFormat::Xz),
            ("lz4", ArchiveFormat::Lz4),
            ("bz2", ArchiveFormat::Bz2),
        ] {
            let stream_path = tmp.path().join(format!("report.json.{ext}"));
            let opts = PackOptions {
                format: fmt,
                level: 4,
                ..Default::default()
            };
            engine
                .pack_paths(
                    &stream_path,
                    std::slice::from_ref(&single_src),
                    "",
                    &opts,
                    None,
                    None,
                )
                .unwrap();
            let opened = engine.open_path(&stream_path, None, None).unwrap();
            assert_eq!(opened.entries.len(), 1);
            assert_eq!(opened.entries[0].path, "report.json");
            let extracted = engine
                .read_entry_bytes(&opened, 0, None, None, None)
                .unwrap();
            assert_eq!(extracted, payload);
        }
    }

    #[test]
    fn split_volumes_and_nested_vfs_mount_stack() {
        let tmp = TempDir::new().unwrap();
        let sources = populate_sample_tree(tmp.path());
        let engine = ArchiveEngine::new();

        // 1. Multi-volume .7z.001, .7z.002, ...
        let split_base = tmp.path().join("chunked.7z");
        let split_opts = PackOptions {
            format: ArchiveFormat::SevenZip,
            level: 3,
            split_volume_size: Some(16 * 1024),
            ..Default::default()
        };
        let vols = engine
            .pack_paths(&split_base, &sources, "", &split_opts, None, None)
            .unwrap();
        assert!(vols.len() >= 2, "expected multiple .001/.002 volumes");
        assert!(vols[0].to_string_lossy().ends_with(".001"));

        let opened_split = engine.open_path(&vols[0], None, None).unwrap();
        assert_eq!(opened_split.volume_count, vols.len());
        engine
            .test(&opened_split, &ExtractOptions::full_with_paths(), None, None)
            .unwrap();

        // 2. Recursive Nested Archive VfsMountStack: outer.7z -> inner.tar.zst -> config.toml
        let inner_tar_zst = tmp.path().join("inner.tar.zst");
        engine
            .pack_paths(
                &inner_tar_zst,
                &sources,
                "",
                &PackOptions {
                    format: ArchiveFormat::TarZst,
                    level: 3,
                    ..Default::default()
                },
                None,
                None,
            )
            .unwrap();

        let outer_7z = tmp.path().join("outer.7z");
        engine
            .pack_paths(
                &outer_7z,
                &[inner_tar_zst],
                "nested_pkg",
                &PackOptions {
                    format: ArchiveFormat::SevenZip,
                    level: 3,
                    ..Default::default()
                },
                None,
                None,
            )
            .unwrap();

        let mut stack = VfsMountStack::open_root(&engine, &outer_7z, None, None).unwrap();
        assert_eq!(stack.depth(), 1);

        let pkg_dir = stack
            .active()
            .archive
            .vfs
            .resolve_path("nested_pkg")
            .unwrap();
        assert!(matches!(
            stack.enter_node(&engine, pkg_dir, None, None).unwrap(),
            EnterOutcome::EnteredDirectory(_)
        ));

        let inner_node = stack
            .active()
            .archive
            .vfs
            .resolve_path("nested_pkg/inner.tar.zst")
            .unwrap();
        assert!(matches!(
            stack.enter_node(&engine, inner_node, None, None).unwrap(),
            EnterOutcome::MountedNestedArchive
        ));
        assert_eq!(stack.depth(), 2);
        assert_eq!(stack.active().archive.format, ArchiveFormat::TarZst);

        let crumbs = stack.breadcrumbs();
        assert!(crumbs.iter().any(|c| c.label == "outer.7z"));
        assert!(crumbs.iter().any(|c| c.label == "inner.tar.zst"));

        // Pop back out to outer.7z
        assert!(stack.navigate_up());
        assert_eq!(stack.depth(), 1);
    }
}
