//! Regenerates the MVM and PVM native evaluators from their handwritten constraint definitions.

use alloc::{format, string::String, vec::Vec};
use std::{fs, println};

use miden_air::{AIRS, HandwrittenMidenAir};
use miden_constraint_compiler::{
    backend::rust_eval::{AirEvaluator, emit_module},
    ir::capture,
};
use miden_precompiles_air::{ChipletAir, HandwrittenChipletAir};

pub use crate::constraints_regen::Mode;

const MVM_EVAL_PATH: &str = "../../../air/src/constraints/generated.rs";

const MVM_HEADER: &str = "\
//! GENERATED globally-CSE'd constraint evaluators -- do not edit.
//!
//! Regenerate with:
//!   cargo run -p miden-core-lib --features constraints-tools --bin regenerate-evaluator -- --write
//!
//! Equivalence with the hand-written definitions is machine-checked: identical
//! constraint values in the identical global order, so `ConstraintLayout`, alpha
//! assignment, and all proof artifacts are unchanged.

#![allow(clippy::eq_op)]
";

/// Generate the evaluator-module source from the current constraint definitions.
fn generate_mvm() -> String {
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
    emit_module(MVM_HEADER, &evaluators)
}

const PVM_EVAL_PATH: &str = "../../precompiles-air/src/generated.rs";

const PVM_HEADER: &str = "\
//! GENERATED PVM constraint evaluators with shared subexpressions -- do not edit.
//!
//! Regenerate with:
//!   cargo run -p miden-core-lib --features constraints-tools --bin regenerate-evaluator -- --write
//!
//! Constraint order and base/extension classification match the handwritten AIRs.

#![allow(clippy::eq_op)]
";

fn generate_pvm() -> String {
    let captured: Vec<_> = ChipletAir::all()
        .into_iter()
        .map(|air| {
            let name = match air {
                ChipletAir::ChunkNodeSponge => "chunk_node_sponge",
                ChipletAir::EidosCompression => "eidos_compression",
                ChipletAir::KeccakRound => "keccak_round",
                ChipletAir::BytePairLut => "byte_pair_lut",
                ChipletAir::TranscriptEval => "transcript_eval",
                ChipletAir::UintStoreMul => "uint_store_mul",
                ChipletAir::UintAdd => "uint_add",
                ChipletAir::EcPointStoreGroups => "ec_point_store_groups",
                ChipletAir::EcGroupAdd => "ec_group_add",
                ChipletAir::EcMsm => "ec_msm",
                ChipletAir::Sha512 => "sha512",
                ChipletAir::Sha256 => "sha256",
            };
            let label = format!("ChipletAir::{air:?}");
            (name, label, capture(&HandwrittenChipletAir(air)))
        })
        .collect();
    let evaluators: Vec<_> = captured
        .iter()
        .map(|(name, label, (graph, constraints))| AirEvaluator {
            name,
            air_label: label,
            graph,
            constraints,
        })
        .collect();
    emit_module(PVM_HEADER, &evaluators)
}

/// Regenerate both VM evaluators (`--write`) or check their checked-in sources (`--check`).
pub fn run(mode: Mode) -> Result<(), String> {
    for (relative_path, content) in
        [(MVM_EVAL_PATH, generate_mvm()), (PVM_EVAL_PATH, generate_pvm())]
    {
        let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), relative_path);
        match mode {
            Mode::Write => {
                // A sibling temporary file keeps an interrupted write from truncating an evaluator.
                let tmp = format!("{path}.tmp");
                fs::write(&tmp, &content).map_err(|e| format!("failed to write {tmp}: {e}"))?;
                fs::rename(&tmp, &path)
                    .map_err(|e| format!("failed to rename {tmp} to {path}: {e}"))?;
                println!("wrote {relative_path} ({} lines)", content.lines().count());
            },
            Mode::Check => {
                let existing =
                    fs::read_to_string(&path).map_err(|e| format!("failed to read {path}: {e}"))?;
                if existing != content {
                    return Err(format!("{relative_path} does not match the generator output"));
                }
                println!("up to date: {relative_path}");
            },
        }
    }
    Ok(())
}
