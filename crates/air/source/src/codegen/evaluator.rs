//! Regenerates the CSE'd constraint evaluators (`crates/air/generated/src/vm/generated.rs`)
//! from the hand-written `MidenAir` constraint definitions.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use std::{fs, path::Path, println};

use miden_stark::capture::{
    backend::rust_eval::{AirEvaluator, emit_module},
    ir::capture,
};

pub use super::Mode;
use crate::vm::AIRS;

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

/// Runs write (`--write`) or staleness-check (`--check`) mode.
pub fn run(path: &Path, mode: Mode) -> Result<(), String> {
    let content = generate();
    let path = path.display().to_string();
    match mode {
        Mode::Write => {
            // Write to a sibling temp file and rename, so an interrupted run
            // cannot leave a truncated `generated.rs` behind.
            let tmp = format!("{path}.tmp");
            fs::write(&tmp, &content).map_err(|e| format!("failed to write {tmp}: {e}"))?;
            fs::rename(&tmp, &path)
                .map_err(|e| format!("failed to rename {tmp} to {path}: {e}"))?;
            println!("wrote {path} ({} lines)", content.lines().count());
            Ok(())
        },
        Mode::Check => {
            let existing =
                fs::read_to_string(&path).map_err(|e| format!("failed to read {path}: {e}"))?;
            if existing == content {
                println!("up to date: {path}");
                Ok(())
            } else {
                Err(format!("{path} does not match the generator output"))
            }
        },
    }
}
