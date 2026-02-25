//! ACE circuit codegen for Plonky3-based Miden AIRs.
//!
//! The pipeline is:
//! 1. Record AIR constraints with `RecordingAirBuilder`.
//! 2. Lower symbolic expressions into a DAG that mirrors verifier constraints evaluation.
//! 3. Emit an ACE circuit plus an `InputLayout` describing the MASM ACE-READ section order.
//!
//! The resulting circuit is intended to run inside the recursive verifier. All
//! input layout decisions (point-major OOD ordering, aux/quotient coords, and
//! alpha/beta randomness expansion) are centralized in this crate so tests can
//! validate both layout and evaluation.
//!
//! Quick start:
//! ```ignore
//! use miden_ace_codegen::{AceConfig, LayoutKind, build_ace_circuit_for_air};
//! use miden_air::ProcessorAir;
//! use miden_core::{Felt, field::QuadFelt};
//!
//! let air = ProcessorAir::new();
//! let config = AceConfig { num_quotient_chunks: 8, num_aux_inputs: 14, layout: LayoutKind::Masm };
//! let circuit = build_ace_circuit_for_air::<_, Felt, QuadFelt>(&air, config)?;
//! ```
//!
//! Module map (data flow):
//! - `pipeline`: public entry points that orchestrate layout + DAG + circuit emission.
//! - `builder`: AIR recorder that captures symbolic constraints.
//! - `dag`: verifier-style DAG IR and lowering helpers.
//! - `circuit`: off-VM circuit representation (inputs/constants/ops/root).
//! - `layout`: READ-section layout and index mapping.
//! - `encode`: ACE stream encoding + padding rules.
//! - `randomness`: challenge input planning for layouts + DAG lowering.
//! - `quotient`: barycentric quotient recomposition helpers (used by DAG + tests).

// Core IR and lowering.
mod builder;
mod circuit;
mod dag;

// Input layout and encoding.
mod encode;
mod layout;
mod quotient;
mod randomness;

// High-level orchestration.
mod pipeline;

use p3_miden_uni_stark::Entry;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

/// Errors returned by ACE codegen.
#[derive(Debug, thiserror::Error)]
pub enum AceError {
    #[error("unsupported entry: {0:?}")]
    UnsupportedEntry(Entry),
    #[error("invalid extension degree: expected {expected}, got {got}")]
    InvalidExtensionDegree { expected: usize, got: usize },
    #[error("invalid basis index: {0}")]
    InvalidBasisIndex(usize),
    #[error("preprocessed trace inputs are not supported yet")]
    PreprocessedTraceUnsupported,
    #[error("invalid number of quotient chunks: {got}")]
    InvalidQuotientChunks { got: usize },
    #[error("invalid input key: {0:?}")]
    InvalidInputKey(crate::layout::InputKey),
    #[error("invalid input length: expected {expected}, got {got}")]
    InvalidInputLength { expected: usize, got: usize },
    #[error("invalid input layout: {message}")]
    InvalidInputLayout { message: String },
    #[error("duplicate input key: {0:?}")]
    DuplicateInputKey(crate::layout::InputKey),
    #[error("missing required input keys: {keys:?}")]
    MissingInputKeys { keys: Vec<crate::layout::InputKey> },
    #[error("invalid periodic column: index={index}, count={count}")]
    InvalidPeriodicColumn { index: usize, count: usize },
    #[error(
        "invalid randomness inputs: num_randomness={num_randomness}, num_randomness_inputs={num_randomness_inputs}"
    )]
    InvalidRandomnessInputs {
        num_randomness: usize,
        num_randomness_inputs: usize,
    },
}

pub use crate::{
    circuit::AceCircuit,
    encode::EncodedCircuit,
    layout::{InputCounts, InputKey, InputLayout},
    pipeline::{AceConfig, LayoutKind, build_ace_circuit_for_air, build_layout_for_air},
};
