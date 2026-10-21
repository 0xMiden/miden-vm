//! Common committed-row geometry and independent symbolic security-shape validation.
use miden_ace::EXT_DEGREE;
#[cfg(any(test, feature = "compiler"))]
use miden_core::{Felt, field::QuadFelt};
#[cfg(any(test, feature = "compiler"))]
use miden_stark::air::{ConstraintCounts, ConstraintDegrees, LiftedAir};
#[cfg(any(test, feature = "compiler"))]
use p3_security::budget::{AirShape, LookupShape};

#[cfg(any(test, feature = "compiler"))]
pub(crate) fn derive_air_shape<A: LiftedAir<Felt, QuadFelt>>(
    airs: &[A],
    lookup: LookupShape,
    alignment: usize,
) -> AirShape {
    let constraints: usize = airs
        .iter()
        .map(|air| ConstraintCounts::from_air::<Felt, QuadFelt, _>(air).total())
        .sum();
    let degree = airs
        .iter()
        .map(|air| ConstraintDegrees::from_air::<Felt, QuadFelt, _>(air).max())
        .max()
        .unwrap_or(0);
    let chunks = degree.saturating_sub(1).max(1).next_power_of_two();
    let widths: usize = airs
        .iter()
        .map(|air| {
            air.preprocessed_width().next_multiple_of(alignment)
                + air.width().next_multiple_of(alignment)
                + (2 * air.aux_width()).next_multiple_of(alignment)
        })
        .sum();
    AirShape {
        num_composed_constraints: (constraints + airs.len() - 1) as u32,
        max_constraint_degree: degree as u32,
        num_quotient_chunks: chunks as u32,
        max_combo: 2,
        num_deep_terms: Some((widths + (2 * chunks).next_multiple_of(alignment) + 2) as u32),
        lookup: Some(lookup),
    }
}

/// Number of out-of-domain points opened per committed column.
///
/// The AIRs use `local` and `next` rotations only.
pub const NUM_OOD_POINTS: u32 = 2;

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
