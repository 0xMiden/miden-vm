//! Engine-level Eidos commitment regression, moved from crypto with its dependency.
use alloc::{vec, vec::Vec};

use miden_core::{Felt, field::PrimeCharacteristicRing};
use miden_crypto::{
    hash::eidos::{
        DIGEST_WIDTH, Eidos, EidosLmcsCompressor, EidosLmcsHasher, PACKED_LANES,
        domains::LmcsLeafDomain,
    },
    hasher::StatefulHasher,
};
use p3_matrix::{
    Matrix,
    bitrev::BitReversibleMatrix,
    dense::{RowMajorMatrix, RowMajorMatrixView},
};
use rand::{SeedableRng, rngs::SmallRng};

use crate::lmcs::{Lmcs, LmcsTree, hiding_config::HidingLmcsConfig};
type PackedFelt = [Felt; PACKED_LANES];
type PackedU64 = [u64; PACKED_LANES];

#[test]
fn block_hashing_preserves_length_bound_salted_commitment() {
    let lmcs =
        HidingLmcsConfig::<PackedFelt, PackedU64, _, _, _, DIGEST_WIDTH, DIGEST_WIDTH, 4>::new(
            EidosLmcsHasher,
            EidosLmcsCompressor,
            SmallRng::seed_from_u64(42),
        );
    for with_prefix in [false, true] {
        let mut matrices = Vec::new();
        if with_prefix {
            matrices.push(RowMajorMatrix::new(vec![Felt::ONE; 3], 3));
        }
        matrices.push(RowMajorMatrix::new(
            (1..=2 * PACKED_LANES * 9).map(Felt::from_usize).collect(),
            9,
        ));
        let expected = lmcs.clone().build_aligned_tree(
            matrices.iter().map(|matrix| matrix.as_view().bit_reverse_rows()).collect(),
        );
        let expected_root = expected.root();
        drop(expected);
        let matrix = matrices.pop().unwrap();
        let actual = lmcs.clone().build_aligned_tree_with_blocks(
            matrices,
            matrix.dimensions(),
            |make_consumer| {
                let consume = make_consumer.unwrap()(PACKED_LANES);
                for (index, values) in
                    matrix.values.chunks_exact(PACKED_LANES * matrix.width()).enumerate()
                {
                    consume(index * PACKED_LANES, RowMajorMatrixView::new(values, matrix.width()));
                }
                matrix
            },
        );
        assert_eq!(actual.root(), expected_root);
    }
}

#[test]
fn lmcs_paths_bind_the_sum_of_independently_padded_rows() {
    let first = (1..=3).map(Felt::new_unchecked).collect::<Vec<_>>();
    let second = (4..=12).map(Felt::new_unchecked).collect::<Vec<_>>();
    let matrices = vec![
        RowMajorMatrix::new(first.clone(), first.len()),
        RowMajorMatrix::new(second.clone(), second.len()),
    ];
    let lmcs = crate::config::lmcs_config();

    let hasher = EidosLmcsHasher;
    let mut expected_state: [u64; DIGEST_WIDTH] =
        Eidos::init_chaining_word_with_params(LmcsLeafDomain, [24, 0, 0])
            .into_elements()
            .map(|value| value.as_canonical_u64());
    <EidosLmcsHasher as StatefulHasher<Felt, [u64; DIGEST_WIDTH]>>::absorb_into(
        &hasher,
        &mut expected_state,
        first.iter().copied(),
    );
    <EidosLmcsHasher as StatefulHasher<Felt, [u64; DIGEST_WIDTH]>>::absorb_into(
        &hasher,
        &mut expected_state,
        second.iter().copied(),
    );

    let leaf = lmcs.hash([first.as_slice(), second.as_slice()]);
    assert_eq!(*leaf.as_ref(), expected_state);
    let tree = lmcs.build_tree(matrices.clone());
    let aligned_tree = lmcs.build_aligned_tree(matrices);
    assert_eq!(tree.root(), leaf);
    assert_eq!(aligned_tree.root(), leaf);
}
