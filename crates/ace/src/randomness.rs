//! Randomness helpers for ACE layout building and DAG lowering.
//!
//! The ACE circuit expands (alpha, beta) into the full coefficient
//! vector `[alpha, 1, beta, beta^2, ...]` used by the constraint system.

use miden_crypto::field::Field;

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
/// The AIR's `Challenges::from_randomness` receives these two raw values and
/// internally expands beta into powers `[1, beta, beta^2, ...]` via symbolic
/// multiplication. This means the DAG will contain nodes for `beta^k` built
/// from `AuxRandBeta`, which is correct.
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

    match index {
        0 => builder.input(InputKey::AuxRandAlpha),
        1 => builder.input(InputKey::AuxRandBeta),
        _ => panic!(
            "challenge index {index} exceeds the 2-element randomness convention (alpha, beta)"
        ),
    }
}
