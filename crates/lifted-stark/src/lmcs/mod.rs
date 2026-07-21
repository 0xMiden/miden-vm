//! Lifted Matrix Commitment Scheme (LMCS) for matrices with power-of-two heights.
//!
//! This module provides a Merkle tree commitment scheme for matrices that store
//! polynomial evaluations over multiplicative cosets. The tree is indexed by
//! **domain order** (natural index): callers address leaves by domain index,
//! and bit-reversal concerns are encapsulated inside the LMCS.
//!
//! # Main Types
//!
//! - [`config::LmcsConfig`]: Configuration holding cryptographic primitives (sponge + compression)
//!   with packed types for SIMD parallelization.
//! - [`Lmcs`]: Trait for LMCS configurations, providing type-erased access to commitment
//!   operations.
//! - [`LmcsTree`]: Trait for built LMCS trees, providing opening operations.
//! - `lifted_tree::LiftedMerkleTree`: The underlying Merkle tree data structure.
//! - [`proof::Proof`]: Single-opening proof with rows, optional salt, and authentication path.
//! - [`proof::BatchProof`]: Batch opening data with Merkle witness for path extraction.
//!
//! # Mathematical Foundation
//!
//! Consider a polynomial `f(X)` of degree less than `d`, and let `g` be the coset generator and
//! `K` a subgroup of order `n ≥ d` with primitive root `ω`. The coset evaluations
//! `{f(g·ω^j) : j ∈ [0, n)}` can be stored in two orderings:
//!
//! - **Canonical order**: `[f(g·ω^0), f(g·ω^1), ..., f(g·ω^{n-1})]`
//! - **Bit-reversed order**: `[f(g·ω^{bitrev(0)}), f(g·ω^{bitrev(1)}), ..., f(g·ω^{bitrev(n-1)})]`
//!
//! where `bitrev(i)` is the bit-reversal of index `i` within `log2(n)` bits.
//!
//! # Lifting by Upsampling
//!
//! When we have matrices with different heights n₀ ≤ n₁ ≤ … ≤ nₜ₋₁ (each a power of two),
//! we "lift" smaller matrices to the maximum height N = nₜ₋₁ using **nearest-neighbor
//! upsampling**: each row is repeated contiguously `r = N/n` times.
//!
//! For a matrix of height `n` lifted to `N`, the index map is: `i ↦ floor(i / r) = i >> log2(r)`
//!
//! **Example** (`n=4`, `N=8`):
//! - Original rows: `[row0, row1, row2, row3]`
//! - Upsampled: `[row0, row0, row1, row1, row2, row2, row3, row3]` (blocks of 2)
//!
//! # Why Upsampling Works
//!
//! Given evaluations of `f(X)` over a coset, upsampling to height `N = n · r` (where `r = 2^k`)
//! produces evaluations of the lifted polynomial `f'(X) = f(Xʳ)` over the larger coset.
//!
//! The internal hashing uses matrices whose rows are in bit-reversed order (as produced by
//! `BitReversedMatrixView`). For such data, upsampling by nearest-neighbor repetition
//! (`i >> k`) produces the correct lifted evaluations. The LMCS then bit-reverses the
//! leaf digest array so the Merkle tree is indexed by domain order.
//!
//! # Opening Semantics
//!
//! When opening at domain index `d`, the LMCS maps `d` to bit-reversed row index
//! `bitrev(d) >> k` for each matrix. This returns the same values that were hashed
//! into Merkle leaf `d`.
//!
//! # Equivalence to Cyclic Lifting
//!
//! Upsampling bit-reversed data is equivalent to cyclically repeating canonically-ordered data:
//!
//! ```text
//! Upsample(BitReverse(data)) = BitReverse(Cyclic(data))
//! ```
//!
//! where cyclic repetition tiles the original `n` rows periodically: `[row0, row1, ..., row_{n-1},
//! row0, ...]`.
//!
//! This equivalence follows from the bit-reversal identity: for `r = N/n = 2^k`,
//! `bitrev_N(i) mod n = bitrev_n(i >> k)`.

pub mod config;
pub mod hiding_config;
pub(crate) mod lifted_tree;
pub mod merkle_witness;
#[cfg(all(feature = "metal", target_os = "macos"))]
pub(crate) mod metal;
pub(crate) mod node_id;
pub mod proof;
pub mod row_list;
pub(crate) mod tree_indices;

#[cfg(test)]
mod tests;

use alloc::{collections::BTreeMap, vec::Vec};

use miden_stark_transcript::{ProverChannel, TranscriptError, VerifierChannel};
use p3_matrix::{Matrix, bitrev::BitReversibleMatrix};
use proof::BatchProofView;
use row_list::RowList;
use thiserror::Error;
use tree_indices::TreeIndices;

use crate::util::align::aligned_len;

// ============================================================================
// Type Aliases
// ============================================================================

/// Opened rows keyed by tree or query index, returned by LMCS opening APIs.
pub type OpenedRows<F> = BTreeMap<usize, RowList<F>>;

// ============================================================================
// Traits
// ============================================================================

/// Trait for LMCS configurations.
pub trait Lmcs: Clone {
    /// Scalar field element type for matrix data.
    ///
    /// `Send + Sync` bounds required by [`Matrix<F>`].
    type F: Clone + Send + Sync;
    /// Commitment type (root hash).
    type Commitment: Clone + Eq;
    /// Tree type (prover data), parameterized by stored matrix type.
    type Tree<Stored: Matrix<Self::F>>: LmcsTree<Self::F, Self::Commitment, Stored>;
    /// Batch witness type returned by [`read_batch_proof`](Self::read_batch_proof) and
    /// [`read_lifted_batch_proof`](Self::read_lifted_batch_proof).
    type BatchProof: BatchProofView<Self::F, Self::Commitment>;

    /// Build a tree from domain-ordered matrices with no transcript padding (alignment = 1).
    ///
    /// The LMCS extracts the inner bit-reversed matrices via
    /// `BitReversibleMatrix::bit_reverse_rows` and stores them. The tree is indexed
    /// by domain order; [`LmcsTree::leaves`] returns the stored bit-reversed matrices.
    ///
    /// This affects only transcript hint formatting; the commitment root is unchanged.
    fn build_tree<M: BitReversibleMatrix<Self::F>>(&self, leaves: Vec<M>) -> Self::Tree<M::BitRev>;

    /// Build a tree from domain-ordered matrices using the hasher alignment for transcript
    /// padding.
    ///
    /// Rows are padded to the hasher's alignment when streaming hints.
    /// When the alignment is 1, this is identical to [`Self::build_tree`].
    fn build_aligned_tree<M: BitReversibleMatrix<Self::F>>(
        &self,
        leaves: Vec<M>,
    ) -> Self::Tree<M::BitRev>;

    /// Hash a sequence of field slices into a leaf hash.
    ///
    /// Inputs are absorbed in order. For salted leaves, append the salt slice to the
    /// iterator (or call this with a chained iterator).
    fn hash<'a, I>(&self, rows: I) -> Self::Commitment
    where
        I: IntoIterator<Item = &'a [Self::F]>,
        Self::F: 'a;

    /// Compress two hashes into their parent (2-to-1 compression).
    fn compress(&self, left: Self::Commitment, right: Self::Commitment) -> Self::Commitment;

    /// Open an exact batch proof by reading hint data from a transcript channel.
    ///
    /// The hint format is implementation-defined; callers must use the matching
    /// exact [`LmcsTree::prove_batch`] implementation to produce compatible hints.
    /// `widths` must match the committed tree (including any alignment padding
    /// if `build_aligned_tree` was used), and `indices` must already be in the
    /// committed tree's own index space.
    ///
    /// # Preconditions
    /// - `indices` must be non-empty.
    /// - `indices.depth()` must be the committed tree depth.
    ///
    /// # Postconditions
    /// On success, the returned map is keyed by the exact tree indices — one
    /// entry per unique index. Each entry's `RowList<F>` has one row per width
    /// in `widths`, with that row's length matching the corresponding width.
    fn open_batch<Ch>(
        &self,
        commitment: &Self::Commitment,
        widths: &[usize],
        indices: &TreeIndices,
        channel: &mut Ch,
    ) -> Result<OpenedRows<Self::F>, LmcsError>
    where
        Ch: VerifierChannel<F = Self::F, Commitment = Self::Commitment>;

    /// Open a virtually lifted batch proof.
    ///
    /// `query_indices` live in the query domain. They are projected to
    /// `tree_log_height`, opened with [`Self::open_batch`], then expanded back to the
    /// original query indices. The returned map is keyed by the original query
    /// indices, so callers can reduce all commitment groups uniformly.
    ///
    /// Returns [`LmcsError::InvalidProof`] if `tree_log_height > query_indices.depth()`.
    fn open_lifted_batch<Ch>(
        &self,
        commitment: &Self::Commitment,
        widths: &[usize],
        query_indices: &TreeIndices,
        tree_log_height: u8,
        channel: &mut Ch,
    ) -> Result<OpenedRows<Self::F>, LmcsError>
    where
        Ch: VerifierChannel<F = Self::F, Commitment = Self::Commitment>,
    {
        let leaf_indices = query_indices.fold_to_depth(tree_log_height)?;
        let rows_by_leaf = self.open_batch(commitment, widths, &leaf_indices, channel)?;
        query_indices.expand_leaf_values(tree_log_height, &rows_by_leaf)
    }

    /// Parse an exact batch opening from transcript hints without verification.
    ///
    /// Reads leaf openings and sibling hashes from the channel, hashes leaves,
    /// and reconstructs the Merkle witness. Does not verify against a commitment;
    /// validation happens in [`open_batch`](Lmcs::open_batch). The returned
    /// witness and openings are keyed by the exact tree indices, because Merkle
    /// paths are defined for leaves of the actual tree.
    ///
    /// Use [`merkle_witness::MerkleWitness::path`] on the returned witness to extract
    /// authentication paths.
    fn read_batch_proof<Ch>(
        &self,
        widths: &[usize],
        indices: &TreeIndices,
        channel: &mut Ch,
    ) -> Result<Self::BatchProof, LmcsError>
    where
        Ch: VerifierChannel<F = Self::F, Commitment = Self::Commitment>;

    /// Parse a virtually lifted batch opening from transcript hints.
    ///
    /// `query_indices` are projected to `tree_log_height`, then parsed with
    /// [`Self::read_batch_proof`]. The returned proof is the same `BatchProof`
    /// type as the exact parser and remains keyed by projected tree indices.
    ///
    /// Returns [`LmcsError::InvalidProof`] if `tree_log_height > query_indices.depth()`.
    fn read_lifted_batch_proof<Ch>(
        &self,
        widths: &[usize],
        query_indices: &TreeIndices,
        tree_log_height: u8,
        channel: &mut Ch,
    ) -> Result<Self::BatchProof, LmcsError>
    where
        Ch: VerifierChannel<F = Self::F, Commitment = Self::Commitment>,
    {
        let leaf_indices = query_indices.fold_to_depth(tree_log_height)?;
        self.read_batch_proof(widths, &leaf_indices, channel)
    }

    /// Get the alignment used by `build_aligned_tree`.
    ///
    /// This is the hasher's rate, used to pad rows when streaming hints.
    fn alignment(&self) -> usize;
}

/// Trait for built LMCS trees.
///
/// Provides methods for accessing tree data and generating proofs.
pub trait LmcsTree<F, Commitment, M> {
    /// Get the tree root (commitment).
    fn root(&self) -> Commitment;

    /// Get the height of the largest matrix (i.e. the number of leaves of the Merkle tree).
    fn height(&self) -> usize;

    /// Get references to the committed matrices.
    ///
    /// Matrix widths are not padded; use [`Self::aligned_widths`] for aligned widths.
    fn leaves(&self) -> &[M];

    /// Get the opened rows for a given leaf index (original matrix widths, no padding).
    fn rows(&self, index: usize) -> RowList<F>;

    /// Get the opened rows for a given leaf index, padded to the tree's alignment.
    ///
    /// Padding uses `Default::default()` and is not enforced by verification.
    fn aligned_rows(&self, index: usize) -> RowList<F>;

    /// Column alignment used when streaming openings.
    fn alignment(&self) -> usize;

    /// Get widths for each committed matrix (original, no padding).
    fn widths(&self) -> Vec<usize>;

    /// Get aligned widths for each committed matrix (padded to alignment).
    fn aligned_widths(&self) -> Vec<usize> {
        let alignment = self.alignment();
        self.widths().into_iter().map(|w| aligned_len(w, alignment)).collect()
    }

    /// Prove an exact batch opening and stream it into a transcript channel.
    ///
    /// The hint format is implementation-defined and must be consumed by the
    /// corresponding exact `Lmcs::open_batch` implementation. Rows are padded to
    /// the tree's alignment before being written to the channel. `indices` must
    /// already be in this tree's own index space.
    ///
    /// Leaf openings are written in **sorted tree index order** (ascending, deduplicated).
    fn prove_batch<Ch>(&self, indices: &TreeIndices, channel: &mut Ch)
    where
        Ch: ProverChannel<F = F, Commitment = Commitment>;

    /// Prove a virtually lifted batch opening.
    ///
    /// Projects `query_indices` to this tree's depth and then delegates to exact
    /// [`Self::prove_batch`].
    fn prove_lifted_batch<Ch>(&self, query_indices: &TreeIndices, channel: &mut Ch)
    where
        Ch: ProverChannel<F = F, Commitment = Commitment>,
    {
        let tree_log_height = miden_lifted_air::log2_strict_u8(self.height());
        let leaf_indices = query_indices
            .fold_to_depth(tree_log_height)
            .expect("query index depth must be at least the committed tree depth");
        self.prove_batch(&leaf_indices, channel);
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during LMCS operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LmcsError {
    #[error("invalid proof")]
    InvalidProof,
    #[error("root mismatch")]
    RootMismatch,
    #[error("transcript error: {0}")]
    TranscriptError(#[from] TranscriptError),
}
