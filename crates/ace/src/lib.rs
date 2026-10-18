//! ACE runtime, circuit compilation, and shared recursive-verifier rendering.
//!
//! Runtime circuit data, canonical artifact decoding, selected-root evaluation and sequential
//! evaluated-wire records are available without the compiler. The optional `compiler` feature
//! captures AIR constraints through `miden_stark`, lowers them into a verifier DAG, and emits
//! circuit streams. MASM rendering belongs to source tooling. Enabling `std` alone does not
//! enable the compiler.

#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

use alloc::string::String;

mod circuit;
mod encode;
pub mod instruction;
mod layout;
mod ood_scatter;
mod proof_order;
mod randomness;
mod records;

#[cfg(feature = "compiler")]
mod artifact;
#[cfg(feature = "compiler")]
mod dag;
#[cfg(feature = "compiler")]
mod pipeline;
#[cfg(feature = "compiler")]
mod quotient;

#[cfg(all(test, feature = "compiler"))]
mod tests;
#[cfg(all(test, feature = "compiler"))]
mod unit_tests;

/// Extension field degree (quadratic extension for Miden VM).
pub const EXT_DEGREE: usize = 2;

/// External circuit format and guest-supplied execution errors.
#[derive(Debug, thiserror::Error)]
pub enum AceError {
    #[error("invalid input layout: {message}")]
    InvalidInputLayout { message: String },
    #[error("failed to decode instruction")]
    InvalidInstruction,
    #[error("failed to read from the wiring bus")]
    UnavailableWire,
}

#[cfg(all(feature = "compiler", any(test, feature = "testing")))]
pub mod testing;

#[cfg(all(feature = "compiler", any(test, feature = "testing")))]
pub use crate::dag::{PeriodicColumnData, build_verifier_dag, build_verifier_dag_from_ir};
#[cfg(feature = "compiler")]
pub use crate::{
    artifact::CompiledCircuit,
    circuit::emit_circuit,
    dag::{AceDag, DagBuilder, DagSnapshot, NodeId, NodeKind},
    pipeline::{
        AceArtifacts, AceConfig, LayoutKind, build_ace_circuit_for_air, build_ace_dag_for_air,
        build_canonical_multi_air_ace_circuit,
    },
};
pub use crate::{
    circuit::AceCircuit,
    encode::{EncodedCircuit, RecursiveAceCircuit},
    layout::{InputCounts, InputKey, InputLayout},
    ood_scatter::{OodScatterGroup, OodScatterPlan, OodScatterSegment},
    proof_order::{
        MAX_ORDER_AIRS, PROOF_ORDER_KEY_STRIDE, factorial, order_from_tag, order_tag,
        sorting_network as proof_order_comparators,
    },
    records::{EvalNode, EvaluationTrace, ReadNode},
};

/// Optional AIR capture, lowering, and circuit emission.
#[cfg(feature = "compiler")]
pub mod compiler {
    pub use crate::{
        AceArtifacts, AceConfig, AceDag, CompiledCircuit, DagBuilder, DagSnapshot, LayoutKind,
        NodeId, NodeKind, build_ace_circuit_for_air, build_ace_dag_for_air,
        build_canonical_multi_air_ace_circuit, emit_circuit,
    };
}
