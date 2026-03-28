//! ACE circuit codegen for Plonky3-based Miden AIRs.
//!
//! The pipeline is:
//! 1. Capture AIR constraints via the `SymbolicAirBuilder`.
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
//! let config = AceConfig { num_quotient_chunks: 8, num_vlpi_groups: 1, layout: LayoutKind::Masm };
//! let circuit = build_ace_circuit_for_air::<_, Felt, QuadFelt>(&ProcessorAir, config)?;
//! ```
//!
//! Module map (data flow):
//! - `pipeline`: public entry points that orchestrate layout + DAG + circuit emission.
//! - `dag`: verifier-style DAG IR and lowering helpers.
//! - `circuit`: off-VM circuit representation (inputs/constants/ops/root).
//! - `layout`: READ-section layout and index mapping.
//! - `encode`: ACE stream encoding + padding rules.
//! - `randomness`: challenge input planning for layouts + DAG lowering.
//! - `quotient`: barycentric quotient recomposition helpers (used by DAG + tests).

// Core IR and lowering.
mod circuit;
mod dag;

// Input layout and encoding.
mod encode;
mod layout;
mod quotient;
mod randomness;

// High-level orchestration.
mod pipeline;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

/// Extension field degree (quadratic extension for Miden VM).
pub const EXT_DEGREE: usize = 2;

/// Errors returned by ACE codegen.
#[derive(Debug, thiserror::Error)]
pub enum AceError {
    #[error("invalid input length: expected {expected}, got {got}")]
    InvalidInputLength { expected: usize, got: usize },
    #[error("invalid input layout: {message}")]
    InvalidInputLayout { message: String },
}

#[cfg(feature = "testing")]
pub mod testing {
    use super::{AceDag, AceError, InputLayout};

    /// Evaluate a lowered DAG against concrete inputs.
    pub fn eval_dag<EF>(
        dag: &AceDag<EF>,
        inputs: &[EF],
        layout: &InputLayout,
    ) -> Result<EF, AceError>
    where
        EF: miden_crypto::field::Field,
    {
        if inputs.len() != layout.total_inputs {
            return Err(AceError::InvalidInputLength {
                expected: layout.total_inputs,
                got: inputs.len(),
            });
        }

        let mut values: Vec<EF> = vec![EF::ZERO; dag.nodes().len()];
        for (idx, node) in dag.nodes().iter().enumerate() {
            let value = match node {
                crate::dag::NodeKind::Input(key) => {
                    let input_idx =
                        layout.index(*key).ok_or_else(|| AceError::InvalidInputLayout {
                            message: format!("missing input key in layout: {key:?}"),
                        })?;
                    inputs[input_idx]
                },
                crate::dag::NodeKind::Constant(c) => *c,
                crate::dag::NodeKind::Add(a, b) => values[a.index()] + values[b.index()],
                crate::dag::NodeKind::Sub(a, b) => values[a.index()] - values[b.index()],
                crate::dag::NodeKind::Mul(a, b) => values[a.index()] * values[b.index()],
                crate::dag::NodeKind::Neg(a) => -values[a.index()],
            };
            values[idx] = value;
        }

        Ok(values[dag.root().index()])
    }
}

pub use crate::{
    circuit::{AceCircuit, emit_circuit},
    dag::{AceDag, DagBuilder, DagSnapshot, NodeId, NodeKind},
    encode::EncodedCircuit,
    layout::{InputCounts, InputKey, InputLayout},
    pipeline::{
        AceArtifacts, AceConfig, LayoutKind, build_ace_circuit_for_air, build_ace_dag_for_air,
    },
};
