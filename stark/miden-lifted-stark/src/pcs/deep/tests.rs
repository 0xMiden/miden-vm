//! End-to-end tests for DEEP quotient prover/verifier agreement.

use alloc::vec;

use p3_util::reverse_bits_len;
use proof::DeepTranscript;
use prover::DeepPoly;
use rand::{RngExt, SeedableRng, distr::StandardUniform, prelude::SmallRng};
use verifier::DeepOracle;

use super::*;
use crate::{
    domain::LiftedDomain,
    lmcs::{Lmcs, LmcsTree, tree_indices::TreeIndices},
    testing::configs::goldilocks_poseidon2::{
        Felt, Lmcs as BaseLmcs, QuadFelt, prover_channel_with_commitment, test_lmcs,
        verifier_channel_with_commitment,
    },
};

/// End-to-end: prover's `DeepPoly.open()` must match verifier's channel-based openings.
#[test]
fn deep_quotient_end_to_end() {
    let rng = &mut SmallRng::seed_from_u64(42);
    let lmcs = test_lmcs();

    // Parameters
    let log_blowup: u8 = 2;
    let log_lde_height: u8 = 10;
    let lde_height = 1 << log_lde_height as usize;
    let max_domain: LiftedDomain<Felt> =
        LiftedDomain::canonical(log_lde_height - log_blowup, log_blowup);

    let params = DeepParams { deep_pow_bits: 1 };
    // Two random opening points
    let z1: QuadFelt = rng.sample(StandardUniform);
    let z2: QuadFelt = rng.sample(StandardUniform);

    // Create matrices of varying heights (ascending order required)
    // specs: (log_scaling, width) where height = n >> log_scaling
    let specs: Vec<(usize, usize)> = vec![(2, 2), (1, 3), (0, 4)]; // heights: n/4, n/2, n
    let matrices: Vec<RowMajorMatrix<Felt>> = specs
        .iter()
        .map(|&(log_scaling, width)| {
            let height = lde_height >> log_scaling;
            RowMajorMatrix::<Felt>::rand(rng, height, width)
        })
        .collect();

    // Step 1: Commit matrices via LMCS (aligned for trace commitments)
    let tree = lmcs.build_aligned_tree(matrices);
    let commitment = tree.root();
    let widths = tree.aligned_widths();

    // Step 3: Prover constructs DeepPoly (handles observe, grind, sample internally)
    let mut prover_channel = prover_channel_with_commitment(&commitment);
    let trace_trees: &[&_] = &[&tree];
    let deep_poly = DeepPoly::from_trees::<BaseLmcs, _, 2, _>(
        params,
        &max_domain,
        trace_trees,
        [z1, z2],
        &mut prover_channel,
    );
    // Sample domain indices. The LMCS tree is indexed by domain order.
    let tree_indices =
        TreeIndices::new([0, 1, lde_height / 4, lde_height / 2, lde_height - 1], log_lde_height)
            .expect("indices are in range");
    tree.prove_batch(&tree_indices, &mut prover_channel);
    let (prover_digest, transcript) = prover_channel.finalize();

    // Create commitments slice for multi-commitment API (single commitment in this case)
    let commitments = vec![(commitment, widths)];

    // Step 4: Verifier constructs DeepOracle with same transcript state
    let mut verifier_channel = verifier_channel_with_commitment(&transcript, &commitment);
    let (deep_oracle, _evals) =
        DeepOracle::new(params, &[z1, z2], commitments, &max_domain, &mut verifier_channel)
            .expect("DeepOracle construction should succeed");

    // Step 5: Verify at multiple query tree indices (proofs are read from transcript)
    let verifier_evals = deep_oracle
        .open_batch(&lmcs, &tree_indices, &mut verifier_channel)
        .expect("Merkle verification should pass");

    for &tree_idx in tree_indices.iter() {
        // Prover's deep_evals are in bit-reversed order internally:
        // deep_evals[bitrev(d)] = Q(g·ω^d). For domain index d, access bitrev(d).
        let bitrev_idx = reverse_bits_len(tree_idx, log_lde_height as usize);
        let prover_eval = deep_poly.deep_evals[bitrev_idx];
        let verifier_eval = verifier_evals[&tree_idx];
        assert_eq!(
            prover_eval, verifier_eval,
            "Prover and verifier disagree at tree index {tree_idx}"
        );
    }

    let verifier_digest = verifier_channel.finalize().expect("transcript should finalize cleanly");
    assert_eq!(prover_digest, verifier_digest);

    // Re-parse DeepTranscript (DEEP phase only) from a fresh channel.
    let reparse_commitments = vec![(commitment, tree.aligned_widths())];
    let mut reparse_channel = verifier_channel_with_commitment(&transcript, &commitment);
    DeepTranscript::<Felt, QuadFelt>::from_verifier_channel(
        &params,
        &reparse_commitments,
        2, // num_eval_points
        &mut reparse_channel,
    )
    .expect("DeepTranscript re-parse should succeed");
}
