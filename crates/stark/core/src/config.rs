//! STARK configuration trait and generic implementation.
//!
//! [`StarkConfig`] bundles the LMCS, DFT, and challenger as associated types.
//! The base field `F` and extension field `EF` are generic parameters so that
//! functions using `SC: StarkConfig<F, EF>` can refer to `F` and `EF` directly
//! instead of going through `SC::F` / `SC::EF`.
//!
//! [`GenericStarkConfig`] provides a ready-made implementation for tests and
//! examples. Production integrations can implement `StarkConfig` on their own
//! concrete struct.

use core::marker::PhantomData;

use miden_crypto::hash::eidos::{
    DIGEST_WIDTH, EidosLmcsCompressor, EidosLmcsHasher, PACKED_LANES, PackedFelt,
};
use miden_stark_transcript::TranscriptChallenger;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, TwoAdicField};
use p3_matrix::{bitrev::BitReversibleMatrix, dense::RowMajorMatrix};

use crate::{
    lmcs::{Lmcs, config::LmcsConfig},
    pcs::params::PcsParams,
};

/// Lifted STARK configuration.
///
/// `F` and `EF` are generic parameters rather than associated types so that
/// functions bounded by `SC: StarkConfig<F, EF>` can refer to them directly.
/// Bounds on `F` and `EF` are declared once here and inherited by every user.
pub trait StarkConfig<F: TwoAdicField, EF: ExtensionField<F>>: Clone {
    /// LMCS (Merkle commitment scheme).
    type Lmcs: Lmcs<F = F>;
    /// DFT for LDE computation.
    ///
    /// Its evaluations must bit-reverse to an owned [`RowMajorMatrix`] so committed LDEs are
    /// stored in a single concrete layout (e.g. `Radix2DitParallel`).
    type Dft: TwoAdicSubgroupDft<F, Evaluations: BitReversibleMatrix<F, BitRev = RowMajorMatrix<F>>>;
    /// Fiat-Shamir challenger.
    type Challenger: TranscriptChallenger<F, <Self::Lmcs as Lmcs>::Commitment>;

    /// PCS parameters (DEEP + FRI settings).
    fn pcs(&self) -> &PcsParams;
    /// LMCS instance for commitments.
    fn lmcs(&self) -> &Self::Lmcs;
    /// DFT implementation for LDE computation.
    fn dft(&self) -> &Self::Dft;
    /// Create a fresh challenger for a new proof/verification.
    fn challenger(&self) -> Self::Challenger;

    /// Hash completed blocks of the final trace LDE during its computation.
    ///
    /// Disabled by default. This changes prover scheduling only, preserving commitments and proofs.
    /// LMCS implementations without block support use eager hashing.
    fn hash_lde_blocks(&self) -> bool {
        false
    }
}

/// Generic [`StarkConfig`] implementation.
///
/// Stores the PCS parameters, LMCS, DFT, and a challenger prototype
/// (cloned for each proof/verification). Use this for tests and examples;
/// production code can implement `StarkConfig` on a custom struct.
pub struct GenericStarkConfig<F, EF, L, Dft, Ch> {
    pub pcs: PcsParams,
    pub lmcs: L,
    pub dft: Dft,
    pub challenger: Ch,
    /// Whether to hash completed blocks during the final trace LDE. Defaults to `false`.
    pub hash_lde_blocks: bool,
    _phantom: PhantomData<fn() -> (F, EF)>,
}

impl<F, EF, L, Dft, Ch> GenericStarkConfig<F, EF, L, Dft, Ch> {
    pub fn new(pcs: PcsParams, lmcs: L, dft: Dft, challenger: Ch) -> Self {
        Self {
            pcs,
            lmcs,
            dft,
            challenger,
            hash_lde_blocks: false,
            _phantom: PhantomData,
        }
    }
}

// Manual Clone: avoids requiring F: Clone, EF: Clone.
impl<F, EF, L: Clone, Dft: Clone, Ch: Clone> Clone for GenericStarkConfig<F, EF, L, Dft, Ch> {
    fn clone(&self) -> Self {
        Self {
            pcs: self.pcs,
            lmcs: self.lmcs.clone(),
            dft: self.dft.clone(),
            challenger: self.challenger.clone(),
            hash_lde_blocks: self.hash_lde_blocks,
            _phantom: PhantomData,
        }
    }
}

impl<F, EF, L, Dft, Ch> StarkConfig<F, EF> for GenericStarkConfig<F, EF, L, Dft, Ch>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    L: Lmcs<F = F>,
    Dft: TwoAdicSubgroupDft<F, Evaluations: BitReversibleMatrix<F, BitRev = RowMajorMatrix<F>>>
        + Clone,
    Ch: TranscriptChallenger<F, L::Commitment>,
{
    type Lmcs = L;
    type Dft = Dft;
    type Challenger = Ch;

    fn pcs(&self) -> &PcsParams {
        &self.pcs
    }

    fn lmcs(&self) -> &L {
        &self.lmcs
    }

    fn dft(&self) -> &Dft {
        &self.dft
    }

    fn challenger(&self) -> Ch {
        self.challenger.clone()
    }

    fn hash_lde_blocks(&self) -> bool {
        self.hash_lde_blocks
    }
}

/// Eidos LMCS configuration used by Miden STARK proofs.
pub type EidosLmcs = LmcsConfig<
    PackedFelt,
    [u64; PACKED_LANES],
    EidosLmcsHasher,
    EidosLmcsCompressor,
    DIGEST_WIDTH,
    DIGEST_WIDTH,
>;

/// Creates the Eidos LMCS configuration used by Miden STARK proofs.
pub const fn lmcs_config() -> EidosLmcs {
    LmcsConfig::new(EidosLmcsHasher, EidosLmcsCompressor)
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use miden_crypto::{Felt, hash::stateful::StatefulHasher};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::{Matrix, bitrev::BitReversibleMatrix, dense::RowMajorMatrixView};
    use rand::{SeedableRng, rngs::SmallRng};

    use super::*;
    use crate::lmcs::{LmcsTree, hiding_config::HidingLmcsConfig};

    type PackedU64 = [u64; PACKED_LANES];
    type Digest = [u64; DIGEST_WIDTH];

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
                        consume(
                            index * PACKED_LANES,
                            RowMajorMatrixView::new(values, matrix.width()),
                        );
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
        let lmcs = lmcs_config();

        let hasher = EidosLmcsHasher;
        let mut expected_state = Digest::default();
        <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::initialize_state(
            &hasher,
            &mut expected_state,
            24,
        );
        <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::absorb_into(
            &hasher,
            &mut expected_state,
            first.iter().copied(),
        );
        <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::absorb_into(
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
}
