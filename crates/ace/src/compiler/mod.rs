//! AIR capture, verifier-equivalent circuit compilation, and MASM generation.
//!
//! This module owns the generic compilation pipeline. Encoded circuit data, input layouts,
//! and proof-order encodings remain available from the crate root for runtime consumers.

mod circuit;
mod dag;
mod encode;
mod masm;
mod ood_scatter;
mod order_maps;
mod pipeline;
mod proof_order;
mod protocol;
mod quotient;
mod randomness;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

/// Exposed for the lowering differential tests (`crates/air/generated/tests/ace_codegen.rs`);
/// production consumes the IR lowering through the pipeline.
#[cfg(any(test, feature = "testing"))]
pub use dag::{PeriodicColumnData, build_verifier_dag, build_verifier_dag_from_ir};

pub use self::{
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
