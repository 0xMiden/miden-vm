//! Regenerates the packaged CSE'd constraint evaluators (`artifacts/vm-evaluator.rs.zlib`)
//! from the hand-written `MidenAir` constraint definitions.

use alloc::{format, string::String, vec::Vec};
use std::{fs, path::Path, println};

use miden_stark::capture::{
    backend::rust_eval::{AirEvaluator, emit_module},
    ir::capture,
};

pub use super::Mode;
use crate::vm::AIRS;

/// Package-local zlib transport of the exact generated Rust evaluator source.
pub const ARTIFACT_FILE: &str = "vm-evaluator.rs.zlib";

const HEADER: &str = "\
//! GENERATED globally-CSE'd constraint evaluators -- do not edit.
//!
//! Regenerate with:
//!   `cargo run -p miden-air-source --features tooling --bin air-codegen -- <workspace-root> --write`
//!
//! Equivalence with the hand-written definitions is machine-checked: identical
//! constraint values in the identical global order, so `ConstraintLayout`, alpha
//! assignment, and all proof artifacts are unchanged.

#![allow(clippy::eq_op)]
";

/// Generate the evaluator-module source from the current constraint definitions.
pub fn generate() -> String {
    // Ordinary source AIR evaluation cannot consume generated evaluator output.
    let captured: Vec<_> = AIRS.iter().copied().map(|air| (air, capture(&air))).collect();
    let labels: Vec<_> =
        captured.iter().map(|(air, _)| format!("MidenAir::{}", air.name())).collect();
    let evaluators: Vec<_> = captured
        .iter()
        .zip(&labels)
        .map(|((air, (graph, constraints)), label)| AirEvaluator {
            name: air.file_token(),
            air_label: label.as_str(),
            graph,
            constraints,
        })
        .collect();
    emit_module(HEADER, &evaluators)
}

/// Encode deterministically with the pinned host codec; this changes no Rust source bytes.
pub fn encode(source: &str) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(source.as_bytes(), 9)
}

/// Runs write (`--write`) or staleness-check (`--check`) mode.
pub fn run(path: &Path, mode: Mode) -> Result<(), String> {
    deliver(path, &generate(), mode)
}

/// Deliver an already generated evaluator after the caller validates other projections.
pub(super) fn deliver(path: &Path, content: &str, mode: Mode) -> Result<(), String> {
    let encoded = encode(content);
    match mode {
        Mode::Write => {
            // Write to a sibling temp file and rename, so an interrupted run
            // cannot leave a truncated packaged evaluator behind.
            let mut tmp_name = path.as_os_str().to_os_string();
            tmp_name.push(".tmp");
            let tmp = Path::new(&tmp_name);
            fs::write(tmp, &encoded)
                .map_err(|e| format!("failed to write {}: {e}", tmp.display()))?;
            fs::rename(tmp, path).map_err(|e| {
                format!("failed to rename {} to {}: {e}", tmp.display(), path.display())
            })?;
            println!("wrote {} ({} compressed bytes)", path.display(), encoded.len());
            Ok(())
        },
        Mode::Check => {
            let existing =
                fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
            if existing == encoded {
                println!("up to date: {}", path.display());
                Ok(())
            } else {
                Err(format!("{} does not match the generator output", path.display()))
            }
        },
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    use super::*;

    #[test]
    fn delivery_preserves_non_utf8_paths() {
        let root = std::env::temp_dir().join(format!(
            "miden-evaluator-path-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join(OsString::from_vec(b"evaluator-\xff.zlib".to_vec()));
        let source = "fn evaluate() {}\n";

        deliver(&path, source, Mode::Write).unwrap();
        assert_eq!(fs::read(&path).unwrap(), encode(source));
        deliver(&path, source, Mode::Check).unwrap();
        assert!(deliver(&path, "different source", Mode::Check).is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1, "temporary file must be renamed");

        fs::remove_dir_all(root).unwrap();
    }
}
