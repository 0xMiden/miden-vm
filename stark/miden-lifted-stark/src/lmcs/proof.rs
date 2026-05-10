//! LMCS proof structures.
//!
//! - [`Proof`]: Single-opening proof with rows, optional salt, and authentication path.
//! - [`BatchProof`]: Batch opening data with per-index rows/salt and a [`MerkleWitness`].
//!
//! Use [`Lmcs::read_batch_proof`] to parse transcript hints
//! into a [`BatchProof`] without verifying against a commitment.

use alloc::{collections::BTreeMap, vec::Vec};

use miden_stark_transcript::{ProverChannel, TranscriptError, VerifierChannel};

use crate::lmcs::{Lmcs, merkle_witness::MerkleWitness, row_list::RowList};

/// Single-opening Merkle proof with rows and authentication path.
///
/// Contains the opening (rows + salt) and siblings (bottom-to-top) for a single leaf.
///
/// # Type Parameters
///
/// - `F`: Field element type.
/// - `C`: Hash type (also used for commitments).
pub struct Proof<F, C, const SALT_ELEMS: usize = 0> {
    /// The leaf opening (rows + salt) for this query.
    pub opening: LeafOpening<F, SALT_ELEMS>,
    /// Sibling hashes from leaf level to root (bottom-to-top).
    pub siblings: Vec<C>,
}

/// Batch opening data parsed from transcript hints without verification.
///
/// Bundles opened leaf data (rows + salt) per index with the reconstructed
/// [`MerkleWitness`] for authentication path queries.
pub struct BatchProof<F, C, const SALT_ELEMS: usize = 0> {
    /// Opened leaf data keyed by leaf index.
    pub openings: BTreeMap<usize, LeafOpening<F, SALT_ELEMS>>,
    /// Reconstructed Merkle authentication structure.
    pub witness: MerkleWitness<C>,
}

/// Accessor trait for batch proof data.
///
/// Provides read access to individual openings, authentication paths, and query indices.
/// This allows consumers (e.g. the Miden VM recursive verifier) to work with batch proofs
/// through the opaque `Lmcs::BatchProof` associated type.
pub trait BatchProofView<F, C> {
    /// Get the opened rows for a given leaf index.
    fn opening(&self, index: usize) -> Option<&RowList<F>>;

    /// Get the salt for a given leaf index.
    ///
    /// Returns an empty slice for non-hiding configurations.
    fn salt(&self, index: usize) -> Option<&[F]>;

    /// Get the authentication path (bottom-to-top sibling hashes) for a given leaf index.
    fn path(&self, index: usize) -> Option<Vec<C>>;

    /// Iterate over the unique query indices (in sorted order).
    fn indices(&self) -> impl Iterator<Item = usize> + '_;
}

impl<F, C: Clone, const SALT_ELEMS: usize> BatchProofView<F, C> for BatchProof<F, C, SALT_ELEMS> {
    fn opening(&self, index: usize) -> Option<&RowList<F>> {
        self.openings.get(&index).map(|o| &o.rows)
    }

    fn salt(&self, index: usize) -> Option<&[F]> {
        self.openings.get(&index).map(|o| o.salt.as_slice())
    }

    fn path(&self, index: usize) -> Option<Vec<C>> {
        self.witness.path(index)
    }

    fn indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.openings.keys().copied()
    }
}

/// Opened rows and optional salt for a single leaf.
pub struct LeafOpening<F, const SALT_ELEMS: usize = 0> {
    /// Opened rows for this query.
    pub rows: RowList<F>,
    /// Salt for this leaf (zero-sized when the configuration is non-hiding).
    pub salt: [F; SALT_ELEMS],
}

impl<F, const SALT_ELEMS: usize> LeafOpening<F, SALT_ELEMS> {
    /// Read a single leaf opening (rows + salt) from a verifier channel.
    ///
    /// Reads `sum(widths)` field elements as a flat row, then `SALT_ELEMS` salt elements.
    /// When `SALT_ELEMS == 0`, the salt read is a no-op.
    pub fn read_from_channel<Ch>(
        widths: Vec<usize>,
        channel: &mut Ch,
    ) -> Result<Self, TranscriptError>
    where
        F: Copy,
        Ch: VerifierChannel<F = F>,
    {
        let total_width: usize = widths.iter().sum();
        let elems = channel.receive_hint_field_slice(total_width)?.to_vec();
        let rows = RowList::new(elems, widths);
        let salt: [F; SALT_ELEMS] = channel.receive_hint_field_array()?;
        Ok(Self { rows, salt })
    }

    /// Write this leaf opening (rows + salt) to a prover channel.
    ///
    /// Writes each row slice, then salt elements (when `SALT_ELEMS > 0`).
    /// Symmetric with [`read_from_channel`](Self::read_from_channel).
    pub fn write_to_channel<Ch>(&self, channel: &mut Ch)
    where
        F: Copy,
        Ch: ProverChannel<F = F>,
    {
        for row in self.rows.iter_rows() {
            channel.hint_field_slice(row);
        }
        channel.hint_field_slice(&self.salt);
    }

    /// Compute the leaf hash from this opening's rows and salt.
    ///
    /// Absorbs row slices in order, then salt (when `SALT_ELEMS > 0`).
    /// This is the canonical leaf hash used in Merkle tree construction.
    pub fn leaf_hash<L>(&self, lmcs: &L) -> L::Commitment
    where
        F: Copy,
        L: Lmcs<F = F>,
    {
        let rows_iter = self.rows.iter_rows();
        if SALT_ELEMS > 0 {
            lmcs.hash(rows_iter.chain(core::iter::once(self.salt.as_slice())))
        } else {
            lmcs.hash(rows_iter)
        }
    }
}

#[cfg(test)]
mod tests {
    use miden_lifted_air::log2_strict_u8;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{SeedableRng, rngs::SmallRng};

    use super::*;
    use crate::{
        lmcs::{LmcsTree, tests::roundtrip_open_batch, tree_indices::TreeIndices},
        testing::configs::goldilocks_poseidon2 as gl,
    };

    #[test]
    fn batch_proof_consistent_with_open_batch() {
        let lmcs = gl::test_lmcs();

        let test = |seed: u64, shapes: &[(usize, usize)], indices: &[usize]| {
            let mut rng = SmallRng::seed_from_u64(seed);
            let matrices: Vec<_> =
                shapes.iter().map(|&(h, w)| RowMajorMatrix::rand(&mut rng, h, w)).collect();
            let tree = lmcs.build_tree(matrices);
            let widths = tree.aligned_widths();
            let log_max_height = log2_strict_u8(tree.height());

            // Path A: open_batch (verification)
            let (transcript, opened_rows) =
                roundtrip_open_batch(&lmcs, &tree, indices).expect("open_batch should verify");

            // Path B: read_batch_proof (parse-only)
            let mut verifier_channel = gl::verifier_channel(&transcript);
            let tree_indices = TreeIndices::new(indices.iter().copied(), log_max_height).unwrap();
            let witness = lmcs
                .read_batch_proof(&widths, &tree_indices, &mut verifier_channel)
                .expect("batch witness should parse");
            assert!(verifier_channel.is_empty(), "parse path should fully consume transcript");

            // Same number of unique openings
            assert_eq!(opened_rows.len(), witness.openings.len());

            // Row data must match between the two paths
            for (&idx, verified_rows) in &opened_rows {
                let opening = witness.openings.get(&idx).expect("opening for index");
                assert_eq!(
                    *verified_rows, opening.rows,
                    "row mismatch between open_batch and batch witness at index {idx}"
                );
            }
        };

        test(1, &[(8, 4)], &[0, 3, 7]);
        test(42, &[(4, 3), (8, 5), (16, 7)], &[0, 5, 10, 15]);
        test(99, &[(4, 2), (8, 6)], &[3, 1, 3, 0, 1]); // duplicates
    }
}
