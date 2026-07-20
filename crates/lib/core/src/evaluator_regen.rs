//! Regenerates the CSE'd constraint evaluators (`air/src/constraints/generated.rs`)
//! from the hand-written `MidenAir` constraint definitions.

use alloc::{format, string::String, vec::Vec};
use std::{fs, println};

use miden_air::{AIRS, HandwrittenMidenAir};
use miden_constraint_compiler::{
    backend::rust_eval::{AirEvaluator, emit_module},
    ir::capture,
};

pub use crate::constraints_regen::Mode;

const GENERATED_EVAL_PATH: &str = "../../../air/src/constraints/generated.rs";

const HEADER: &str = "\
//! GENERATED globally-CSE'd constraint evaluators -- do not edit.
//!
//! Regenerate with:
//!   cargo run -p miden-core-lib --features constraints-tools --bin regenerate-evaluator -- --write
//!
//! Equivalence with the hand-written definitions is machine-checked: identical
//! constraint values in the identical global order, so `ConstraintLayout`, alpha
//! assignment, and all proof artifacts are unchanged.
";

/// Generate the evaluator-module source from the current constraint definitions.
fn generate() -> String {
    // `MidenAir::eval` executes the generated evaluators; the generator must
    // never consume its own output (miden-constraint-compiler crate invariant 1),
    // so capture goes through the handwritten-routing wrapper.
    let captured: Vec<_> = AIRS
        .iter()
        .copied()
        .map(|air| (air, capture(&HandwrittenMidenAir(air))))
        .collect();
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
pub fn run(mode: Mode) -> Result<(), String> {
    let content = generate();
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), GENERATED_EVAL_PATH);
    match mode {
        Mode::Write => {
            fs::write(&path, &content).map_err(|e| format!("failed to write {path}: {e}"))?;
            println!("wrote air/src/constraints/generated.rs ({} lines)", content.lines().count());
            Ok(())
        },
        Mode::Check => {
            let existing =
                fs::read_to_string(&path).map_err(|e| format!("failed to read {path}: {e}"))?;
            if existing == content {
                println!("up to date: air/src/constraints/generated.rs");
                Ok(())
            } else {
                Err("air/src/constraints/generated.rs does not match the generator output".into())
            }
        },
    }
}
