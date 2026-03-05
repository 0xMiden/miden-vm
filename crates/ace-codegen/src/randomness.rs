//! Randomness helpers for ACE layout building and DAG lowering.
//!
//! The ACE circuit expands (alpha, beta) into the full coefficient
//! vector `[alpha, 1, beta, beta^2, ...]` used by the constraint system.

use p3_field::Field;

use crate::{
    dag::{DagBuilder, NodeId},
    layout::{InputKey, InputLayout, InputRegion},
};

/// Derive alpha/beta input indices from a randomness region.
///
/// Returns `(alpha_idx, beta_idx)` matching the memory-word layout `[beta, alpha]`.
pub(crate) fn aux_rand_indices(randomness: InputRegion) -> (usize, usize) {
    // Stored as [beta, alpha] in memory words.
    let beta_idx = randomness.index(0).expect("randomness region must have at least 2 slots");
    let alpha_idx = randomness.index(1).expect("randomness region must have at least 2 slots");
    (alpha_idx, beta_idx)
}

/// Lower a challenge index into DAG nodes.
///
/// Challenge indices map to:
/// - 0 → alpha
/// - 1 → 1 (beta^0)
/// - n → beta^(n-1)
pub(crate) fn lower_challenge<EF>(
    builder: &mut DagBuilder<EF>,
    layout: &InputLayout,
    index: usize,
) -> NodeId
where
    EF: Field,
{
    let num = layout.counts.num_randomness;
    assert!(index < num, "challenge index {index} out of range (num={num})");

    if index == 0 {
        return builder.input(InputKey::AuxRandAlpha);
    }
    if index == 1 {
        return builder.constant(EF::ONE);
    }
    let beta_node = builder.input(InputKey::AuxRandBeta);
    let mut power = beta_node;
    for _ in 2..index {
        power = builder.mul(power, beta_node);
    }
    power
}
