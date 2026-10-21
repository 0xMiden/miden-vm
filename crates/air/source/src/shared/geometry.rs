//! Independent symbolic security-shape oracle for generated metadata.
use miden_core::{Felt, field::QuadFelt};
use miden_lifted_air::{ConstraintCounts, ConstraintDegrees, LiftedAir};
use p3_security::budget::{AirShape, LookupShape};

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
