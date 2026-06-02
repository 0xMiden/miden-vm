//! Hiding LMCS configuration types.

use alloc::vec::Vec;
use core::cell::RefCell;

use miden_stark_transcript::VerifierChannel;
use miden_stateful_hasher::{Alignable, StatefulHasher};
use p3_field::PackedValue;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_symmetric::{Hash, PseudoCompressionFunction};
use rand::{
    Rng,
    distr::{Distribution, StandardUniform},
};

use crate::{
    lmcs::{
        Lmcs, LmcsError, OpenedRows, config::LmcsConfig, lifted_tree::LiftedMerkleTree,
        proof::BatchProof, tree_indices::TreeIndices,
    },
    util::bitrev::BitReversibleMatrix,
};

/// Configuration for hiding LMCS with random salt.
///
/// This type wraps a [`LmcsConfig`] and adds an RNG for generating salt
/// during tree construction. The RNG is stored in a `RefCell` to allow
/// salt generation without `&mut self` (required by `Mmcs::commit`).
///
/// `open_batch` delegates to the inner `LmcsConfig`, so hint layout and proof shape
/// match the non-hiding implementation except for
/// the presence of salt. The RNG is only used during tree construction.
///
/// # Type Parameters
///
/// - `PF`: Packed field element type for SIMD operations.
/// - `PD`: Packed hash word element type.
/// - `H`: Stateful hasher/sponge type.
/// - `C`: 2-to-1 compression function type.
/// - `R`: Random number generator type.
/// - `WIDTH`: State width for the hasher.
/// - `DIGEST`: Number of elements in a hash.
/// - `SALT`: Number of salt elements per leaf (must be > 0).
///
/// # Security notes
/// - `SALT` should be sized so `SALT * sizeof(PF::Value)` meets the target security parameter.
/// - `R` should be an appropriately seeded CSPRNG; weaker RNGs can undermine hiding.
/// - Cloning this config clones RNG state. Re-seed if you need independent salts per config.
///
/// # Example
///
/// ```ignore
/// use p3_miden_lmcs::{HidingLmcsConfig, Lmcs, LmcsTree};
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
///
/// let rng = StdRng::seed_from_u64(42);
/// let config =
///     HidingLmcsConfig::<PF, PD, _, _, _, WIDTH, DIGEST, 4>::new(sponge, compress, rng);
///
/// let tree = config.build_aligned_tree(matrices);
/// let root = tree.root();
/// ```
#[derive(Clone, Debug)]
pub struct HidingLmcsConfig<
    PF,
    PD,
    H,
    C,
    R,
    const WIDTH: usize,
    const DIGEST: usize,
    const SALT: usize,
> {
    /// Inner non-hiding config with sponge and compression.
    pub inner: LmcsConfig<PF, PD, H, C, WIDTH, DIGEST, SALT>,
    /// RNG for salt generation. Uses `RefCell` for interior mutability.
    rng: RefCell<R>,
}

impl<PF, PD, H, C, R, const WIDTH: usize, const DIGEST: usize, const SALT: usize>
    HidingLmcsConfig<PF, PD, H, C, R, WIDTH, DIGEST, SALT>
{
    /// Create a new hiding LMCS configuration.
    ///
    /// # Compile-time Error
    ///
    /// Fails to compile if `SALT == 0`. Use [`LmcsConfig`] for non-hiding commitments.
    #[inline]
    pub fn new(sponge: H, compress: C, rng: R) -> Self {
        const { assert!(SALT > 0) }
        Self {
            inner: LmcsConfig::new(sponge, compress),
            rng: RefCell::new(rng),
        }
    }
}

impl<PF, PD, H, C, R, const WIDTH: usize, const DIGEST: usize, const SALT: usize> Lmcs
    for HidingLmcsConfig<PF, PD, H, C, R, WIDTH, DIGEST, SALT>
where
    PF: PackedValue + Default,
    PD: PackedValue + Default,
    R: Rng + Clone,
    StandardUniform: Distribution<PF::Value>,
    H: StatefulHasher<PF::Value, [PD::Value; DIGEST], State = [PD::Value; WIDTH]>
        + StatefulHasher<PF, [PD; DIGEST], State = [PD; WIDTH]>
        + Alignable<PF::Value, PD::Value>
        + Sync,
    C: PseudoCompressionFunction<[PD::Value; DIGEST], 2>
        + PseudoCompressionFunction<[PD; DIGEST], 2>
        + Sync,
{
    type F = PF::Value;
    type Commitment = Hash<PF::Value, PD::Value, DIGEST>;
    type Tree<M: Matrix<PF::Value>> = LiftedMerkleTree<PF::Value, PD::Value, M, DIGEST, SALT>;
    type BatchProof = BatchProof<PF::Value, Self::Commitment, SALT>;

    /// Build a tree with per-leaf salt sampled from the RNG.
    ///
    /// Preconditions match `LmcsConfig::build_tree`; panics if `leaves` is empty.
    fn build_tree<M: BitReversibleMatrix<Self::F>>(&self, leaves: Vec<M>) -> Self::Tree<M::BitRev> {
        let tree_height = leaves.last().map(Matrix::height).unwrap_or(0);
        let salt = RowMajorMatrix::rand(&mut *self.rng.borrow_mut(), tree_height, SALT);
        LiftedMerkleTree::build_with_alignment::<M, PF, PD, H, C, WIDTH>(
            &self.inner.sponge,
            &self.inner.compress,
            leaves,
            Some(salt),
            1,
        )
    }

    /// Build a tree with per-leaf salt sampled from the RNG and hasher alignment padding.
    ///
    /// Preconditions match `LmcsConfig::build_tree`; panics if `leaves` is empty.
    fn build_aligned_tree<M: BitReversibleMatrix<Self::F>>(
        &self,
        leaves: Vec<M>,
    ) -> Self::Tree<M::BitRev> {
        let tree_height = leaves.last().map(Matrix::height).unwrap_or(0);
        let salt = RowMajorMatrix::rand(&mut *self.rng.borrow_mut(), tree_height, SALT);
        LiftedMerkleTree::build_with_alignment::<M, PF, PD, H, C, WIDTH>(
            &self.inner.sponge,
            &self.inner.compress,
            leaves,
            Some(salt),
            <H as Alignable<PF::Value, PD::Value>>::ALIGNMENT,
        )
    }

    fn hash<'a, I>(&self, rows: I) -> Self::Commitment
    where
        I: IntoIterator<Item = &'a [Self::F]>,
        Self::F: 'a,
    {
        self.inner.hash(rows)
    }

    fn compress(&self, left: Self::Commitment, right: Self::Commitment) -> Self::Commitment {
        self.inner.compress(left, right)
    }

    fn open_batch<Ch>(
        &self,
        commitment: &Self::Commitment,
        widths: &[usize],
        indices: &TreeIndices,
        channel: &mut Ch,
    ) -> Result<OpenedRows<Self::F>, LmcsError>
    where
        Ch: VerifierChannel<F = Self::F, Commitment = Self::Commitment>,
    {
        self.inner.open_batch(commitment, widths, indices, channel)
    }

    fn read_batch_proof<Ch>(
        &self,
        widths: &[usize],
        indices: &TreeIndices,
        channel: &mut Ch,
    ) -> Result<Self::BatchProof, LmcsError>
    where
        Ch: VerifierChannel<F = Self::F, Commitment = Self::Commitment>,
    {
        self.inner.read_batch_proof(widths, indices, channel)
    }

    fn alignment(&self) -> usize {
        self.inner.alignment()
    }
}
