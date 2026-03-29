use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

const VERSION: &str = "v1.6.1";

#[derive(Debug, Clone, Copy)]
pub enum Archive {
    General,
    Mainnet,
    Minimal,
}

impl Archive {
    pub fn dir_name(self) -> &'static str {
        match self {
            Archive::General => "general",
            Archive::Mainnet => "mainnet",
            Archive::Minimal => "minimal",
        }
    }
}

pub fn cache_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("SPEC_TESTS_DIR") {
        return PathBuf::from(dir);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("spec-tests has a parent dir")
        .join("target")
        .join("spec-tests")
        .join(VERSION)
}

pub fn archive_dir(archive: Archive) -> PathBuf {
    let root = cache_dir().join(archive.dir_name());
    let sentinel = root.join(".extracted");
    let tests_dir = root.join("tests");
    if !sentinel.exists() && !tests_dir.exists() {
        panic!(
            "Spec test vectors not found at {}. Run:\n  ./spec-tests/download-vectors.sh",
            root.display()
        );
    }
    root
}

pub fn archive_available(archive: Archive) -> bool {
    let root = cache_dir().join(archive.dir_name());
    root.join(".extracted").exists() || root.join("tests").exists()
}

pub fn ssz_generic_handler_path(handler: &str) -> PathBuf {
    archive_dir(Archive::General)
        .join("tests")
        .join("general")
        .join("phase0")
        .join("ssz_generic")
        .join(handler)
}

pub fn ssz_generic_valid_cases(handler: &str) -> Vec<(PathBuf, String)> {
    collect_cases(&ssz_generic_handler_path(handler).join("valid"))
}

pub fn ssz_generic_invalid_cases(handler: &str) -> Vec<(PathBuf, String)> {
    collect_cases(&ssz_generic_handler_path(handler).join("invalid"))
}

pub fn ssz_static_cases(archive: Archive, fork: &str, type_name: &str) -> Vec<(PathBuf, String)> {
    let dir = archive_dir(archive)
        .join("tests")
        .join(archive.dir_name())
        .join(fork)
        .join("ssz_static")
        .join(type_name);
    collect_nested_cases(&dir)
}

pub fn read_ssz_snappy(path: &Path) -> Vec<u8> {
    let compressed = fs::read(path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    let mut decoder = snap::raw::Decoder::new();
    decoder
        .decompress_vec(&compressed)
        .unwrap_or_else(|e| panic!("snappy decompress {}: {}", path.display(), e))
}

pub fn parse_root(path: &Path) -> [u8; 32] {
    #[derive(Deserialize)]
    struct Meta {
        root: String,
    }

    let content =
        fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    let meta: Meta = serde_yaml::from_str(&content)
        .unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e));
    let hex_str = meta.root.strip_prefix("0x").unwrap_or(&meta.root);
    let bytes = hex::decode(hex_str)
        .unwrap_or_else(|e| panic!("hex decode root in {}: {}", path.display(), e));
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes);
    root
}

pub fn read_yaml_value(path: &Path) -> serde_yaml::Value {
    let content =
        fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    serde_yaml::from_str(&content).unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e))
}

fn collect_cases(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut cases = Vec::new();
    if !dir.exists() {
        return cases;
    }
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {}", dir.display(), e))
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        cases.push((entry.path(), name));
    }
    cases
}

fn collect_nested_cases(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut cases = Vec::new();
    if !dir.exists() {
        return cases;
    }

    let mut suites: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {}", dir.display(), e))
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .collect();
    suites.sort_by_key(|e| e.file_name());

    for suite in suites {
        let suite_name = suite.file_name().to_string_lossy().into_owned();
        let suite_path = suite.path();
        let mut suite_cases: Vec<_> = fs::read_dir(&suite_path)
            .unwrap_or_else(|e| panic!("read_dir {}: {}", suite_path.display(), e))
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .collect();
        suite_cases.sort_by_key(|e| e.file_name());

        for case in suite_cases {
            let case_name = case.file_name().to_string_lossy().into_owned();
            cases.push((case.path(), format!("{suite_name}/{case_name}")));
        }
    }

    cases
}
