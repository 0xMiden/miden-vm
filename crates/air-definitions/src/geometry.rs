use alloc::vec::Vec;

use miden_ace_codegen::{CapturedAir, CompiledRelation, EXT_DEGREE};
use p3_security::budget::{AirShape, LookupShape};

use crate::{AIRS, HandwrittenMidenAir, logup::MIDEN_MAX_MESSAGE_WIDTH};

/// Number of out-of-domain points opened per committed column.
///
/// The AIRs use `local` and `next` rotations only.
pub const NUM_OOD_POINTS: u32 = 2;

/// Derive the security shape for tooling and differential validation.
pub fn derive_air_shape() -> AirShape {
    let captures: Vec<_> = AIRS
        .iter()
        .map(|air| CapturedAir::new(&HandwrittenMidenAir(*air)).expect("capture VM AIR"))
        .collect();
    let airs: Vec<_> = captures.iter().collect();
    let relation = CompiledRelation::from_captured(&airs, crate::config::SPONGE_RATE)
        .expect("compile VM relation");
    air_shape(&relation)
}

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

/// Number of DEEP terms for raw committed widths emitted by the relation compiler.
/// Widths are base-field coordinates; each matrix is padded independently.
pub fn num_deep_terms_for_widths(
    raw_widths: &[(usize, usize, usize)],
    chunks: usize,
    alignment: usize,
) -> u32 {
    let columns: usize = raw_widths
        .iter()
        .map(|&(preprocessed, main, aux)| {
            preprocessed.next_multiple_of(alignment)
                + main.next_multiple_of(alignment)
                + aux.next_multiple_of(alignment)
        })
        .sum();
    (columns + (chunks * EXT_DEGREE).next_multiple_of(alignment)) as u32 + NUM_OOD_POINTS
}
