//! Symbolic circuit construction and compiled geometry for the authored VM relation.

mod multi_air;
mod recursive;

use miden_ace_codegen::compiler::CompiledRelation;
use p3_security::budget::{AirShape, LookupShape};

pub use self::{
    multi_air::build_canonical_multi_air_ace_circuit,
    recursive::{build_recursive_verifier_ace_circuit, recursive_verifier_ace_config},
};
use crate::{AIRS, geometry::NUM_OOD_POINTS, logup::MIDEN_MAX_MESSAGE_WIDTH};

/// Security shape from the same captured relation used for evaluators and ACE generation.
pub fn air_shape(relation: &CompiledRelation<'_>) -> AirShape {
    let geometry = relation.geometry();
    let fractions_per_row: usize =
        AIRS.iter().map(|air| air.column_shape().iter().sum::<usize>()).sum();
    AirShape {
        num_composed_constraints: (geometry.num_constraints + geometry.airs.len() - 1) as u32,
        max_constraint_degree: geometry.max_constraint_degree as u32,
        num_quotient_chunks: geometry.num_quotient_chunks as u32,
        max_combo: NUM_OOD_POINTS,
        num_deep_terms: Some(geometry.committed_width() as u32 + NUM_OOD_POINTS),
        lookup: Some(LookupShape {
            fractions_per_row: fractions_per_row as u32,
            max_message_width: MIDEN_MAX_MESSAGE_WIDTH as u32,
        }),
    }
}
