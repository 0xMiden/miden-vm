//! LMCS configuration types.

use alloc::{collections::BTreeMap, vec::Vec};
use core::marker::PhantomData;

use miden_stark_transcript::VerifierChannel;
use miden_stateful_hasher::{Alignable, StatefulHasher};
use p3_field::PackedValue;
use p3_matrix::Matrix;
use p3_symmetric::{Hash, PseudoCompressionFunction};

use crate::{
    lmcs::{
        Lmcs, LmcsError, OpenedRows,
        lifted_tree::LiftedMerkleTree,
        merkle_witness::MerkleWitness,
        proof::{BatchProof, LeafOpening},
        row_list::RowList,
        tree_indices::TreeIndices,
    },
    util::bitrev::BitReversibleMatrix,
};

/// LMCS configuration holding cryptographic primitives (sponge + compression).
///
/// This implementation defines the transcript hint layout used by
/// [`LmcsTree::prove_batch`](crate::lmcs::LmcsTree::prove_batch) and consumed by
/// `open_batch` and [`Lmcs::read_batch_proof`]:
/// - For each distinct tree index (sorted ascending): one row per committed matrix (in committed
///   matrix order), then `SALT_ELEMS` field elements of salt.
/// - After all leaves: missing sibling hashes, level-by-level, left-to-right, bottom-to-top.
///
/// Hints are not observed into the Fiat-Shamir challenger.
///
/// `open_batch` expects `widths` and `indices.depth()` to match the committed tree,
/// rejects empty `indices`, and ignores extra hint data. Widths must match the
/// committed row lengths (including any alignment padding if `build_aligned_tree`
/// was used). Duplicate indices are coalesced in the returned openings.
/// [`read_batch_proof`](crate::lmcs::Lmcs::read_batch_proof) parses
/// the same hint stream, hashes leaves, and reconstructs leaf authentication paths without
/// verifying against a commitment. Empty indices are accepted by `read_batch_proof`;
/// out-of-range indices return `InvalidProof`.
///
/// Padding note:
/// - LMCS does not enforce that aligned padding values are zero. Verifiers cannot distinguish zero
///   padding from arbitrary values unless they check those columns in the opened rows or constrain
///   them elsewhere.
///
/// For hiding commitments with salt, use
/// [`HidingLmcsConfig`](crate::lmcs::hiding_config::HidingLmcsConfig) instead.
#[derive(Clone, Debug)]
pub struct LmcsConfig<
    PF,
    PD,
    H,
    C,
    const WIDTH: usize,
    const DIGEST: usize,
    const SALT_ELEMS: usize = 0,
> {
    /// Stateful sponge for hashing matrix rows into leaf hashes.
    pub sponge: H,
    /// 2-to-1 compression function for building internal tree nodes.
    pub compress: C,
    pub(crate) _phantom: PhantomData<(PF, PD)>,
}

impl<PF, PD, H, C, const WIDTH: usize, const DIGEST: usize, const SALT_ELEMS: usize>
    LmcsConfig<PF, PD, H, C, WIDTH, DIGEST, SALT_ELEMS>
{
    /// Create a new LMCS configuration.
    #[inline]
    pub const fn new(sponge: H, compress: C) -> Self {
        Self { sponge, compress, _phantom: PhantomData }
    }
}

impl<PF, PD, H, C, const WIDTH: usize, const DIGEST: usize, const SALT_ELEMS: usize> Lmcs
    for LmcsConfig<PF, PD, H, C, WIDTH, DIGEST, SALT_ELEMS>
where
    PF: PackedValue + Default,
    PD: PackedValue + Default,
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
    type Tree<M: Matrix<PF::Value>> = LiftedMerkleTree<PF::Value, PD::Value, M, DIGEST, SALT_ELEMS>;
    type BatchProof = BatchProof<PF::Value, Self::Commitment, SALT_ELEMS>;

    /// Build a tree from domain-ordered matrices with no transcript padding (alignment = 1).
    ///
    /// Extracts the inner bit-reversed matrices and stores them.
    ///
    /// Preconditions:
    /// - `leaves` is non-empty.
    /// - Matrix heights are powers of two and sorted by height (shortest to tallest).
    ///
    /// Panics if `leaves` is empty. Incorrect height order commits to a different
    /// lifted matrix than intended.
    fn build_tree<M: BitReversibleMatrix<Self::F>>(&self, leaves: Vec<M>) -> Self::Tree<M::BitRev> {
        const { assert!(SALT_ELEMS == 0) }
        LiftedMerkleTree::build_with_alignment::<M, PF, PD, H, C, WIDTH>(
            &self.sponge,
            &self.compress,
            leaves,
            None,
            1,
        )
    }

    /// Build a tree from domain-ordered matrices using the hasher alignment for transcript
    /// padding.
    ///
    /// Extracts the inner bit-reversed matrices and stores them.
    ///
    /// Preconditions:
    /// - `leaves` is non-empty.
    /// - Matrix heights are powers of two and sorted by height (shortest to tallest).
    ///
    /// Panics if `leaves` is empty. Incorrect height order commits to a different
    /// lifted matrix than intended.
    fn build_aligned_tree<M: BitReversibleMatrix<Self::F>>(
        &self,
        leaves: Vec<M>,
    ) -> Self::Tree<M::BitRev> {
        const { assert!(SALT_ELEMS == 0) }
        LiftedMerkleTree::build_with_alignment::<M, PF, PD, H, C, WIDTH>(
            &self.sponge,
            &self.compress,
            leaves,
            None,
            <H as Alignable<PF::Value, PD::Value>>::ALIGNMENT,
        )
    }

    fn hash<'a, I>(&self, rows: I) -> Self::Commitment
    where
        I: IntoIterator<Item = &'a [Self::F]>,
        Self::F: 'a,
    {
        let mut state = [PD::Value::default(); WIDTH];
        for row in rows {
            self.sponge.absorb_into(&mut state, row.iter().cloned());
        }
        let digest: [PD::Value; DIGEST] = self.sponge.squeeze(&state);
        Hash::from(digest)
    }

    fn compress(&self, left: Self::Commitment, right: Self::Commitment) -> Self::Commitment {
        let left_digest = *left.as_ref();
        let right_digest = *right.as_ref();
        Hash::from(self.compress.compress([left_digest, right_digest]))
    }

    /// Verify an exact batch opening from transcript hints.
    ///
    /// Security notes:
    /// - `widths` and `indices.depth()` must describe the committed tree; they are not checked.
    /// - `widths` must match the committed row lengths (including any alignment padding if
    ///   `build_aligned_tree` was used); LMCS does not enforce that padded values are zero.
    ///   Verifiers cannot distinguish zero padding from arbitrary values unless they check the
    ///   opened rows or constrain them elsewhere.
    /// - Empty `indices` returns `InvalidProof`.
    /// - Missing siblings or malformed hints return `InvalidProof`.
    /// - Extra hints are ignored and left unread.
    /// - Returns `RootMismatch` only after a well-formed proof yields a different root.
    ///
    /// Leaf openings are read in sorted tree index order (ascending, deduplicated).
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
        if indices.is_empty() {
            return Err(LmcsError::InvalidProof);
        }

        // 1. Read one opening per unique leaf and hash it.
        let mut leaf_rows: BTreeMap<usize, RowList<Self::F>> = BTreeMap::new();
        let mut leaf_hashes: Vec<(usize, Self::Commitment)> = Vec::with_capacity(indices.len());

        for &leaf in indices.iter() {
            let opening =
                LeafOpening::<_, SALT_ELEMS>::read_from_channel(widths.to_vec(), channel)?;
            leaf_hashes.push((leaf, opening.leaf_hash(self)));
            leaf_rows.insert(leaf, opening.rows);
        }

        // 2. Recompute root by streaming siblings directly from the channel.
        let tree = MerkleWitness::build(
            leaf_hashes,
            indices.depth() as usize,
            |_| -> Result<_, LmcsError> { Ok(*channel.receive_hint_commitment()?) },
            |l, r| self.compress(l, r),
        )?;
        let computed_commitment = tree.root().ok_or(LmcsError::InvalidProof)?;

        if *computed_commitment != *commitment {
            return Err(LmcsError::RootMismatch);
        }

        Ok(leaf_rows)
    }

    /// Parse batch hints into per-leaf opening proofs.
    ///
    /// Reads openings, hashes leaves, builds a pruned tree, and extracts
    /// authentication paths. Salt is stored as `Vec<F>` in the output.
    ///
    /// Notes:
    /// - `widths` must match the committed row lengths (including any alignment padding if
    ///   `build_aligned_tree` was used).
    fn read_batch_proof<Ch>(
        &self,
        widths: &[usize],
        indices: &TreeIndices,
        channel: &mut Ch,
    ) -> Result<Self::BatchProof, LmcsError>
    where
        Ch: VerifierChannel<F = Self::F, Commitment = Self::Commitment>,
    {
        let mut openings = BTreeMap::new();
        let mut leaf_hashes: Vec<(usize, Self::Commitment)> = Vec::with_capacity(indices.len());

        for &leaf in indices.iter() {
            let opening =
                LeafOpening::<_, SALT_ELEMS>::read_from_channel(widths.to_vec(), channel)?;
            leaf_hashes.push((leaf, opening.leaf_hash(self)));
            openings.insert(leaf, opening);
        }

        // 2. Build PrunedTree from leaf hashes + channel siblings.
        let witness = MerkleWitness::build(
            leaf_hashes,
            indices.depth() as usize,
            |_| -> Result<_, LmcsError> { Ok(*channel.receive_hint_commitment()?) },
            |l, r| self.compress(l, r),
        )?;

        Ok(BatchProof { openings, witness })
    }

    fn alignment(&self) -> usize {
        <H as Alignable<PF::Value, PD::Value>>::ALIGNMENT
    }
}
// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use alloc::vec;

    use miden_lifted_air::log2_strict_u8;
    use miden_stark_transcript::{ProverTranscript, TranscriptData, VerifierTranscript};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;
    use crate::{lmcs::LmcsTree, testing::configs::goldilocks_poseidon2 as gl};

    fn small_matrix(height: usize, width: usize, seed: u64) -> RowMajorMatrix<gl::Felt> {
        let values = (0..height * width).map(|i| gl::Felt::from_u64(seed + i as u64)).collect();
        RowMajorMatrix::new(values, width)
    }

    #[test]
    fn open_batch_cases() {
        let lmcs = gl::test_lmcs();
        let matrices = vec![small_matrix(4, 2, 0), small_matrix(4, 3, 100)];
        let tree = lmcs.build_tree(matrices);
        let widths = tree.aligned_widths();
        let log_max_height = log2_strict_u8(tree.height());
        let commitment = tree.root();

        let ti = |indices: &[usize], depth: u8| {
            TreeIndices::new(indices.iter().copied(), depth).unwrap()
        };

        let make_transcript = |indices: &TreeIndices| {
            let mut prover_channel = gl::prover_channel();
            tree.prove_batch(indices, &mut prover_channel);
            prover_channel.finalize()
        };

        let assert_open = |indices: &[usize]| {
            let tree_indices = ti(indices, log_max_height);
            let (prover_digest, transcript) = make_transcript(&tree_indices);
            let mut verifier_channel = gl::verifier_channel(&transcript);
            let opened = lmcs
                .open_batch(&commitment, &widths, &tree_indices, &mut verifier_channel)
                .unwrap();
            for &idx in indices {
                assert_eq!(opened[&idx], tree.aligned_rows(idx));
            }
            let verifier_digest =
                verifier_channel.finalize().expect("transcript should finalize cleanly");
            assert_eq!(prover_digest, verifier_digest);
        };

        assert_open(&[0]);
        assert_open(&[0, 1]);
        assert_open(&[0, 2]);
        assert_open(&[0, 1, 2, 3]);
        assert_open(&[2, 2]);

        let tiny_tree = lmcs.build_tree(vec![small_matrix(1, 1, 7)]);
        let widths_tiny = tiny_tree.aligned_widths();
        let log_tiny = log2_strict_u8(tiny_tree.height());
        let tiny_indices = ti(&[0], log_tiny);
        let mut prover_channel = gl::prover_channel();
        tiny_tree.prove_batch(&tiny_indices, &mut prover_channel);
        let (prover_digest, transcript) = prover_channel.finalize();
        let mut verifier_channel = gl::verifier_channel(&transcript);
        let opened = lmcs
            .open_batch(&tiny_tree.root(), &widths_tiny, &tiny_indices, &mut verifier_channel)
            .unwrap();
        assert_eq!(opened[&0], tiny_tree.aligned_rows(0));
        let verifier_digest =
            verifier_channel.finalize().expect("transcript should finalize cleanly");
        assert_eq!(prover_digest, verifier_digest);

        // oob index
        assert_eq!(TreeIndices::new([tree.height()], log_max_height), Err(LmcsError::InvalidProof));

        // wrong tree
        let tree_indices_0 = ti(&[0], log_max_height);
        let (_, transcript) = make_transcript(&tree_indices_0);
        let mut verifier_channel = gl::verifier_channel(&transcript);
        let wrong_tree = lmcs.build_tree(vec![small_matrix(4, 2, 999)]);
        assert_eq!(
            lmcs.open_batch(&wrong_tree.root(), &widths, &tree_indices_0, &mut verifier_channel),
            Err(LmcsError::RootMismatch)
        );

        // missing item from transcript
        let (_, transcript) = make_transcript(&tree_indices_0);
        let (fields, mut commitments) = transcript.into_parts();
        commitments.pop();
        let truncated = TranscriptData::new(fields, commitments);
        let mut verifier_channel = gl::verifier_channel(&truncated);
        assert_eq!(
            lmcs.open_batch(&commitment, &widths, &tree_indices_0, &mut verifier_channel),
            Err(LmcsError::TranscriptError(
                miden_stark_transcript::TranscriptError::NoMoreCommitments
            ))
        );

        // empty indices
        let empty_indices = ti(&[], log_max_height);
        let (_, transcript) = gl::prover_channel().finalize();
        let mut verifier_channel = gl::verifier_channel(&transcript);
        assert_eq!(
            lmcs.open_batch(&commitment, &widths, &empty_indices, &mut verifier_channel),
            Err(LmcsError::InvalidProof)
        );
    }

    #[test]
    fn virtual_lifted_indices_fold_to_committed_leaves() {
        let lmcs = gl::test_lmcs();
        let tree = lmcs.build_tree(vec![small_matrix(4, 2, 0)]);
        let widths = tree.aligned_widths();
        let commitment = tree.root();
        let tree_log_height = log2_strict_u8(tree.height());
        let query_depth = tree_log_height + 1;
        let indices = TreeIndices::new([0usize, 4, 5, 7], query_depth).unwrap();

        let make_transcript = || {
            let mut prover_channel = gl::prover_channel();
            tree.prove_lifted_batch(&indices, &mut prover_channel);
            prover_channel.finalize()
        };

        let (prover_digest, transcript) = make_transcript();
        let mut verifier_channel = gl::verifier_channel(&transcript);
        let opened = lmcs
            .open_lifted_batch(
                &commitment,
                &widths,
                &indices,
                tree_log_height,
                &mut verifier_channel,
            )
            .unwrap();

        assert_eq!(opened[&0], tree.aligned_rows(0));
        assert_eq!(opened[&4], tree.aligned_rows(0));
        assert_eq!(opened[&5], tree.aligned_rows(1));
        assert_eq!(opened[&7], tree.aligned_rows(3));
        let verifier_digest =
            verifier_channel.finalize().expect("transcript should finalize cleanly");
        assert_eq!(prover_digest, verifier_digest);

        let (_, transcript) = make_transcript();
        let mut verifier_channel = gl::verifier_channel(&transcript);
        let batch = lmcs
            .read_lifted_batch_proof(&widths, &indices, tree_log_height, &mut verifier_channel)
            .unwrap();
        assert_eq!(batch.openings.len(), 3);
        assert!(batch.openings.contains_key(&0));
        assert!(batch.openings.contains_key(&1));
        assert!(batch.openings.contains_key(&3));

        let invalid_tree_log_height = query_depth + 1;
        let (_, transcript) = gl::prover_channel().finalize();
        let mut verifier_channel = gl::verifier_channel(&transcript);
        assert_eq!(
            lmcs.open_lifted_batch(
                &commitment,
                &widths,
                &indices,
                invalid_tree_log_height,
                &mut verifier_channel,
            ),
            Err(LmcsError::InvalidProof)
        );

        let mut verifier_channel = gl::verifier_channel(&transcript);
        assert!(matches!(
            lmcs.read_lifted_batch_proof(
                &widths,
                &indices,
                invalid_tree_log_height,
                &mut verifier_channel
            ),
            Err(LmcsError::InvalidProof)
        ));
    }

    /// Reproduces the "root mismatch" bug when using Goldilocks + Blake3 (byte-based hash).
    ///
    /// The lifted STARK only tests with field-based Poseidon2, never with byte-based hashes.
    /// This test isolates the LMCS layer to confirm that ChainingHasher<Blake3> +
    /// CompressionFunctionFromHasher<Blake3> work correctly for commit-then-open.
    #[test]
    fn goldilocks_blake3_roundtrip() {
        use alloc::{vec, vec::Vec};

        use miden_stark_transcript::{ProverTranscript, VerifierTranscript};
        use miden_stateful_hasher::ChainingHasher;
        use p3_blake3::Blake3;
        use p3_challenger::{HashChallenger, SerializingChallenger64};
        use p3_symmetric::CompressionFunctionFromHasher;

        use crate::testing::configs::goldilocks_poseidon2::Felt;

        type Sponge = ChainingHasher<Blake3>;
        type Compress = CompressionFunctionFromHasher<Blake3, 2, 32>;
        const WIDTH: usize = 32;
        const DIGEST: usize = 32;
        type Blake3Lmcs = LmcsConfig<Felt, u8, Sponge, Compress, WIDTH, DIGEST>;
        type Challenger = SerializingChallenger64<Felt, HashChallenger<u8, Blake3, 32>>;

        fn challenger() -> Challenger {
            SerializingChallenger64::from_hasher(vec![], Blake3)
        }

        let sponge = ChainingHasher::new(Blake3);
        let compress = CompressionFunctionFromHasher::new(Blake3);
        let lmcs: Blake3Lmcs = LmcsConfig::new(sponge, compress);

        // Single 4x2 matrix of constant values.
        let values: Vec<Felt> = (0..4 * 2).map(|i| Felt::from_u64(i as u64)).collect();
        let matrix = RowMajorMatrix::new(values, 2);

        let tree = lmcs.build_tree(vec![matrix]);
        let widths = tree.aligned_widths();
        let log_max_height = log2_strict_u8(tree.height());
        let commitment = tree.root();

        // Prove then verify a single index.
        let indices = TreeIndices::new([0usize], log_max_height).unwrap();
        let mut prover_channel = ProverTranscript::new(challenger());
        tree.prove_batch(&indices, &mut prover_channel);
        let (prover_digest, transcript) = prover_channel.finalize();

        let mut verifier_channel = VerifierTranscript::from_data(challenger(), &transcript);
        let opened = lmcs
            .open_batch(&commitment, &widths, &indices, &mut verifier_channel)
            .expect("Goldilocks+Blake3 LMCS roundtrip should verify");

        assert_eq!(opened[&0], tree.aligned_rows(0));
        let verifier_digest =
            verifier_channel.finalize().expect("transcript should finalize cleanly");
        assert_eq!(prover_digest, verifier_digest);
    }

    /// Same as [`goldilocks_blake3_roundtrip`] but with a 24-byte BLAKE3 digest (BLAKE3-192).
    #[test]
    fn goldilocks_blake3_192_roundtrip() {
        use alloc::{vec, vec::Vec};

        use miden_stateful_hasher::{ChainingHasher, TruncatingHasher};
        use p3_blake3::Blake3;
        use p3_challenger::{HashChallenger, SerializingChallenger64};
        use p3_symmetric::CompressionFunctionFromHasher;

        use crate::testing::configs::goldilocks_poseidon2::Felt;

        pub type Blake3_192 = TruncatingHasher<Blake3, 32, 24>;

        type Sponge = ChainingHasher<Blake3_192>;
        type Compress = CompressionFunctionFromHasher<Blake3_192, 2, 24>;
        const WIDTH: usize = 24;
        const DIGEST: usize = 24;
        type Blake3Lmcs = LmcsConfig<Felt, u8, Sponge, Compress, WIDTH, DIGEST>;
        type Challenger = SerializingChallenger64<Felt, HashChallenger<u8, Blake3_192, DIGEST>>;

        fn challenger() -> Challenger {
            SerializingChallenger64::new(HashChallenger::new(Vec::new(), Blake3_192::new(Blake3)))
        }

        let sponge = ChainingHasher::new(Blake3_192::new(Blake3));
        let compress = CompressionFunctionFromHasher::new(Blake3_192::new(Blake3));
        let lmcs: Blake3Lmcs = LmcsConfig::new(sponge, compress);

        let values: Vec<Felt> = (0..4 * 2).map(|i| Felt::from_u64(i as u64)).collect();
        let matrix = RowMajorMatrix::new(values, 2);

        let tree = lmcs.build_tree(vec![matrix]);
        let widths = tree.widths();
        let log_max_height = log2_strict_u8(tree.height());
        let commitment = tree.root();

        let mut prover_channel = ProverTranscript::new(challenger());
        let indices = TreeIndices::new([0usize], log_max_height).unwrap();
        tree.prove_batch(&indices, &mut prover_channel);
        let (prover_digest, transcript) = prover_channel.finalize();

        let mut verifier_channel = VerifierTranscript::from_data(challenger(), &transcript);
        let opened = lmcs
            .open_batch(&commitment, &widths, &indices, &mut verifier_channel)
            .expect("Goldilocks+Blake3-192 LMCS roundtrip should verify");

        assert_eq!(opened[&0], tree.rows(0));
        let verifier_digest =
            verifier_channel.finalize().expect("transcript should finalize cleanly");
        assert_eq!(prover_digest, verifier_digest);
    }
}
