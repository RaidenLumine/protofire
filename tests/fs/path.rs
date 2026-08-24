//! tests/fs/path.rs
//!
//! Host-side integration tests for slash-only path normalization rules.

use protofire::kernel::fs::path::normalize_path;
use protofire::Error;

type NormalizeCase = (&'static str, &'static str, &'static str);
type InputCase = (&'static str, &'static str);

// Fixed corpora keep path regressions reproducible while still exercising
// repeated `/`, UTF-8 segments, and parent traversal cleanup.
const IDEMPOTENT_CORPUS: &[InputCase] = &[
    ("documents/../downloads/mod.jar", "/data/users/guest"),
    ("./runtime/../bin/init", "/system"),
    ("/apps/../catalog/demo-launcher.toml", "/"),
    ("./cache/./../logs/kernel.log", "/data/users/guest"),
    ("/data/users/guest/../downloads", "/"),
];

const ABSOLUTE_INPUT_CORPUS: &[&str] = &[
    "/system/./runtime/../bin/init",
    "/apps/../catalog/demo-launcher.toml",
    "///data/users/guest/desktop/../downloads/package.zip",
];

const EXPECTED_NORMALIZATION_CORPUS: &[NormalizeCase] = &[
    (
        "///system//runtime/../../apps///catalog/./demo.toml",
        "/",
        "/apps/catalog/demo.toml",
    ),
    (
        "././documents//archive///2026/../notes.md",
        "/data/users/guest",
        "/data/users/guest/documents/archive/notes.md",
    ),
    (
        "./cache/./../logs/2026/../kernel.log",
        "/data/users/guest",
        "/data/users/guest/logs/kernel.log",
    ),
    (
        "/../../../../system/./runtime/../bin/init",
        "/",
        "/system/bin/init",
    ),
    ("/../../../../", "/data/users/guest", "/"),
    (
        "/system/./Temp//logs/../kernel.log",
        "/",
        "/system/Temp/kernel.log",
    ),
    (
        "./../downloads//logs/./session.txt",
        "/data/users/guest/documents",
        "/data/users/guest/downloads/logs/session.txt",
    ),
    (
        "/data/测试/文档/README.txt",
        "/",
        "/data/测试/文档/README.txt",
    ),
];

const CANONICAL_INVARIANT_CORPUS: &[InputCase] = &[
    ("./././", "/apps/packages/demo"),
    (
        "../downloads///patches/../../logs/./boot.txt",
        "/data/users/guest/documents",
    ),
    ("/apps/../catalog/./launchers//demo.toml", "/"),
    ("/data/users/guest/../shared/../guest/notes.txt", "/"),
    ("/system//runtime///drivers/../../bin/init", "/"),
    ("../../../../../../", "/data/users/guest/documents"),
    ("/apps/../catalog/launcher.toml", "/"),
    ("/data/users/guest/../shared/./mods", "/"),
];

const INVALID_DRIVE_CORPUS: &[&str] = &[
    "C:/apps/demo.elf",
    "//?/c:/apps/demo.elf",
    "D:/apps/demo.elf",
    "b:relative/app.toml",
];

const INVALID_NON_NATIVE_PATH_CORPUS: &[&str] = &[
    r"\apps\demo.elf",
    r".\downloads\file.txt",
    r"/data\users\guest\notes.txt",
    "//?//data/users/guest",
    r"\\?\data\users\guest",
    r"\\?\C:\apps\demo.elf",
];

fn normalized(path: &str, cwd: &str) -> String {
    normalize_path(path, cwd).expect("normalize path")
}

fn assert_normalizes_to(path: &str, cwd: &str, expected: &str) {
    let got = normalized(path, cwd);
    assert_eq!(got, expected, "corpus mismatch: path={path} cwd={cwd}");
    assert_canonical(&got);
}

fn assert_rejected(path: &str, cwd: &str) {
    assert_eq!(
        normalize_path(path, cwd).unwrap_err(),
        Error::InvalidArgument,
        "expected invalid argument: path={path} cwd={cwd}"
    );
}

fn assert_idempotent(path: &str, cwd: &str) {
    let once = normalized(path, cwd);
    let twice = normalized(&once, "/apps/packages/demo");
    assert_eq!(
        twice, once,
        "normalization should be idempotent: path={path} cwd={cwd}"
    );
    assert_canonical(&once);
}

fn assert_expected_corpus(corpus: &[NormalizeCase]) {
    for &(path, cwd, expected) in corpus {
        assert_normalizes_to(path, cwd, expected);
    }
}

fn assert_canonical_invariant_corpus(corpus: &[InputCase]) {
    for &(path, cwd) in corpus {
        let canonical = normalized(path, cwd);
        assert_canonical(&canonical);
        assert_eq!(
            normalized(&canonical, "/system"),
            canonical,
            "canonical output should stay stable when normalized again: path={path} cwd={cwd}"
        );
    }
}

#[test]
fn normalizes_relative_paths_inside_the_data_zone() {
    let normalized = normalize_path("documents/../downloads/mod.jar", "/data/users/guest")
        .expect("normalize relative path");

    assert_eq!(normalized, "/data/users/guest/downloads/mod.jar");
}

#[test]
fn rejects_backslash_separated_zone_paths() {
    assert_rejected(r"\apps\..\system\bin\init", "/");
}

#[test]
fn rejects_nt_prefixed_paths() {
    assert_rejected("//?//data/users/guest", "/");
    assert_rejected(r"\\?\data\users\guest", "/");
}

#[test]
fn rejects_backslash_separated_data_zone_paths() {
    assert_rejected(r"\data\Users\Guest\Documents\README.txt", "/");
}

#[test]
fn parent_traversal_is_clamped_at_root() {
    let normalized = normalize_path("../../../../apps/demo.elf", "/")
        .expect("normalize parent traversal from root");

    assert_eq!(normalized, "/apps/demo.elf");
}

#[test]
fn rejects_drive_letter_paths() {
    assert_eq!(
        normalize_path("C:/apps/demo.elf", "/").unwrap_err(),
        Error::InvalidArgument
    );
}

#[test]
fn absolute_slash_paths_normalize_dot_segments() {
    let normalized = normalize_path("/system/./runtime/../bin/init", "/")
        .expect("normalize absolute root-tree path");

    assert_eq!(normalized, "/system/bin/init");
}

#[test]
fn rejects_empty_paths() {
    assert_eq!(
        normalize_path("   ", "/").unwrap_err(),
        Error::InvalidArgument
    );
}

#[test]
fn rejects_ascii_control_characters_in_path_inputs() {
    assert_eq!(
        normalize_path("/data/users/guest/\nnotes.txt", "/").unwrap_err(),
        Error::InvalidArgument
    );
    assert_eq!(
        normalize_path("notes.txt", "/data/users/\u{7f}guest").unwrap_err(),
        Error::InvalidArgument
    );
    assert_eq!(
        normalize_path("downloads/\0package.zip", "/data/users/guest").unwrap_err(),
        Error::InvalidArgument
    );
}

#[test]
fn normalization_is_idempotent_for_curated_corpus() {
    for &(path, cwd) in IDEMPOTENT_CORPUS {
        assert_idempotent(path, cwd);
    }
}

#[test]
fn absolute_inputs_ignore_cwd() {
    for input in ABSOLUTE_INPUT_CORPUS {
        let from_data = normalized(input, "/data/users/guest");
        let from_apps = normalized(input, "/apps/packages/demo");
        assert_eq!(
            from_data, from_apps,
            "absolute input should not depend on cwd: {input}"
        );
        assert_canonical(&from_data);
    }
}

#[test]
fn rejects_non_native_path_variants() {
    for path in INVALID_NON_NATIVE_PATH_CORPUS {
        assert_rejected(path, "/data/users/guest");
    }
}

#[test]
fn rejects_relative_cwd_inputs() {
    assert_eq!(
        normalize_path("downloads/file.txt", "data/users/guest").unwrap_err(),
        Error::InvalidArgument
    );
}

#[test]
fn absolute_input_still_rejects_relative_cwd() {
    assert_eq!(
        normalize_path("/system/bin/init", "data/users/guest").unwrap_err(),
        Error::InvalidArgument
    );
}

fn assert_canonical(path: &str) {
    assert!(
        path.starts_with('/'),
        "normalized path must be absolute: {path}"
    );
    assert!(
        !path.contains('\\'),
        "normalized path must not contain backslashes: {path}"
    );
    assert!(
        !path.contains("/./"),
        "normalized path must not contain dot segments: {path}"
    );
    assert!(
        !path.contains("/../"),
        "normalized path must not contain parent segments: {path}"
    );

    if path != "/" {
        assert!(
            !path.ends_with('/'),
            "non-root path must not end with '/': {path}"
        );
        assert!(
            !path.contains("//"),
            "normalized path must not contain repeated '/': {path}"
        );
    }
}

#[test]
fn corpus_driven_paths_normalize_to_expected_outputs() {
    assert_expected_corpus(EXPECTED_NORMALIZATION_CORPUS);
}

#[test]
fn expanded_fixed_corpus_preserves_canonical_invariants() {
    assert_canonical_invariant_corpus(CANONICAL_INVARIANT_CORPUS);
}

#[test]
fn corpus_driven_drive_letter_inputs_are_rejected() {
    for path in INVALID_DRIVE_CORPUS {
        assert_eq!(
            normalize_path(path, "/").unwrap_err(),
            Error::InvalidArgument,
            "expected drive-letter rejection: {path}"
        );
    }
}

#[test]
fn normalization_preserves_utf8_segments() {
    let normalized_path = normalized("/data/用户/文档/readme.txt", "/");
    assert_eq!(normalized_path, "/data/用户/文档/readme.txt");

    let absolute = normalized("/data/测试/文档/README.txt", "/");
    assert_eq!(absolute, "/data/测试/文档/README.txt");

    let relative = normalized("./共享/资料/README.txt", "/data/用户");
    assert_eq!(relative, "/data/用户/共享/资料/README.txt");
}
