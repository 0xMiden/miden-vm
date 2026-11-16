//! Symbolic circuit construction and compiled geometry for the authored VM relation.

mod multi_air;
mod recursive;

use alloc::vec::Vec;

use miden_ace::AceError;
pub use miden_ace::compiler::{CapturedAir, CompiledRelation, LayoutKind};
use miden_stark::{
    air::DescriptorError,
    security::{AirShape, LookupShape},
};

pub use self::{
    multi_air::build_canonical_multi_air_ace_circuit,
    recursive::{build_recursive_verifier_ace_circuit, recursive_verifier_ace_config},
};
use crate::{
    shared::geometry::NUM_OOD_POINTS,
    vm::{AIRS, MidenAir, logup::MIDEN_MAX_MESSAGE_WIDTH},
};

/// Canonical authored captures shared by VM evaluator and ACE generation.
///
/// Pairing declarations with their native capture preserves instance order for every backend.
pub fn capture_vm_airs() -> Result<Vec<(MidenAir, CapturedAir)>, AceError> {
    AIRS.iter()
        .copied()
        .map(|air| Ok((air, CapturedAir::new_native(&air)?)))
        .collect()
}

/// Derive the checked security shape from the authored relation.
pub fn derive_air_shape() -> Result<AirShape, DescriptorError> {
    crate::shared::geometry::derive_air_shape(
        &AIRS,
        lookup_shape(),
        miden_crypto::hash::eidos::BLOCK_LEN,
    )
}

fn lookup_shape() -> LookupShape {
    LookupShape {
        fractions_per_row: AIRS
            .iter()
            .map(|air| air.column_shape().iter().sum::<usize>())
            .sum::<usize>() as u32,
        max_message_width: MIDEN_MAX_MESSAGE_WIDTH as u32,
    }
}

/// Security shape from the same captured relation used for evaluators and ACE generation.
pub fn air_shape(relation: &CompiledRelation<'_>) -> AirShape {
    let geometry = relation.geometry();
    AirShape {
        num_composed_constraints: (geometry.num_constraints + geometry.airs.len() - 1) as u32,
        max_constraint_degree: geometry.max_constraint_degree as u32,
        num_quotient_chunks: geometry.num_quotient_chunks as u32,
        max_combo: NUM_OOD_POINTS,
        num_deep_terms: Some(geometry.committed_width() as u32 + NUM_OOD_POINTS),
        lookup: Some(lookup_shape()),
    }
}
