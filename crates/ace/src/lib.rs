//! ACE circuit runtime and optional compiler for Miden AIRs.
//!
//! The default runtime supports `no_std` with `alloc`. It owns encoded circuits, instruction
//! packing and decoding, input layouts, and proof-order tags. Enable `compiler` in build
//! dependencies to capture AIRs and generate circuits.
//!
//! The compiler pipeline is:
//! 1. Capture AIR constraints into the `miden-constraint-compiler` IR.
//! 2. Lower the constraint graph into a DAG that mirrors verifier constraints evaluation.
//! 3. Emit an ACE circuit plus an `InputLayout` describing the MASM ACE-READ section order.
//!
//! The resulting circuit is intended to run inside the recursive verifier. All
//! input layout decisions (point-major OOD ordering, aux/quotient coords, and
//! alpha/beta randomness expansion) are centralized in this crate so tests can
//! validate both layout and evaluation.
//!
//! Quick start:
//! ```ignore
//! use miden_ace::{AceConfig, LayoutKind, build_ace_circuit_for_air};
//! use miden_air::MidenAir;
//!
//! let config = AceConfig { num_quotient_chunks: 8, layout: LayoutKind::Masm };
//! let circuit = build_ace_circuit_for_air(&MidenAir::CORE, config)?;
//! ```
//!
//! Module map (data flow):
//! - `pipeline`: public entry points that orchestrate layout + DAG + circuit emission.
//! - `dag`: verifier-style DAG IR and lowering helpers.
//! - `circuit`: off-VM circuit representation (inputs/constants/ops/root).
//! - `layout`: READ-section layout and index mapping.
//! - `encode`: ACE stream encoding + padding rules.
//! - `instruction`: packed arithmetic operations shared with the processor.
//! - `masm`: shared renderer for relation-local MASM constraint evaluators.
//! - `randomness`: challenge input planning for layouts + DAG lowering.
//! - `quotient`: barycentric quotient recomposition helpers (used by DAG + tests).
//! - `proof_order`: Lehmer ranking and the sorting network of a relation's committed-trace
//!   orderings.
//! - `order_maps`: shared renderer for the MASM proof-order pass that materializes inverse maps.
//! - `ood_scatter`: shared OOD scatter planning and MASM procedure generation.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
#[cfg(all(test, not(feature = "std")))]
extern crate std;

use alloc::string::String;

// Core IR and lowering.
#[cfg(feature = "compiler")]
mod circuit;
#[cfg(feature = "compiler")]
mod dag;

// Input layout and encoding.
mod encode;
pub mod instruction;
mod layout;
#[cfg(feature = "compiler")]
mod masm;
#[cfg(feature = "compiler")]
mod ood_scatter;
#[cfg(feature = "compiler")]
mod order_maps;
mod proof_order;
#[cfg(feature = "compiler")]
mod quotient;
mod randomness;

// High-level orchestration.
#[cfg(feature = "compiler")]
mod pipeline;
#[cfg(feature = "compiler")]
mod protocol;

#[cfg(all(test, feature = "compiler"))]
mod tests;
#[cfg(all(test, feature = "compiler"))]
mod unit_tests;

/// Extension field degree (quadratic extension for Miden VM).
pub const EXT_DEGREE: usize = 2;

/// Errors returned by ACE circuit operations.
#[derive(Debug, thiserror::Error)]
pub enum AceError {
    #[error("invalid input length: expected {expected}, got {got}")]
    InvalidInputLength { expected: usize, got: usize },
    #[error("invalid input layout: {message}")]
    InvalidInputLayout { message: String },
}

#[cfg(all(feature = "compiler", any(test, feature = "testing")))]
pub mod testing;

/// Exposed for the lowering differential tests (`crates/air/generated/tests/ace_codegen.rs`);
/// production consumes the IR lowering through the pipeline.
#[cfg(all(feature = "compiler", any(test, feature = "testing")))]
pub use crate::dag::{PeriodicColumnData, build_verifier_dag, build_verifier_dag_from_ir};
#[cfg(feature = "compiler")]
pub use crate::{
    circuit::{AceCircuit, emit_circuit},
    dag::{AceDag, DagBuilder, DagSnapshot, NodeId, NodeKind},
    masm::{FoldCoefficientStaging, MasmConstraintsEvalConfig, render_masm_constraints_eval},
    ood_scatter::OodScatterPlan,
    order_maps::{ProofOrderMapsConfig, render_proof_order_maps},
    pipeline::{
        AceArtifacts, AceConfig, LayoutKind, build_ace_circuit_for_air, build_ace_dag_for_air,
        build_canonical_multi_air_ace_circuit,
    },
    protocol::{AirGeometry, CapturedAir, CompiledRelation, RelationGeometry, RowSegment},
};
pub use crate::{
    encode::{EncodedCircuit, RecursiveAceCircuit},
    layout::{InputCounts, InputKey, InputLayout},
    proof_order::{MAX_ORDER_AIRS, factorial, order_from_tag, order_tag},
};
