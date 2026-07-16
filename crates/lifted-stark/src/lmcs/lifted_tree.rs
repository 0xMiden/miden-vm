use alloc::{vec, vec::Vec};
use core::{array, mem};

use miden_stark_transcript::ProverChannel;
use miden_stateful_hasher::StatefulHasher;
use p3_field::PackedValue;
use p3_matrix::{Matrix, bitrev::BitReversibleMatrix, dense::RowMajorMatrix};
use p3_maybe_rayon::prelude::*;
use p3_symmetric::{Hash, PseudoCompressionFunction};
use p3_util::{log2_strict_usize, reverse_bits_len};
use tracing::info_span;

use crate::lmcs::{LmcsTree, proof::LeafOpening, row_list::RowList, tree_indices::TreeIndices};

/// A uniform binary Merkle tree whose leaves are constructed from matrices with power-of-two
/// heights.
///
/// # Type Parameters
///
/// * `F` – scalar field element type used in both matrices and hash words.
/// * `D` – digest element type.
/// * `M` – matrix type. Must implement [`Matrix<F>`].
/// * `DIGEST_ELEMS` – number of elements in one digest.
/// * `SALT_ELEMS` – number of salt elements per leaf (0 = non-hiding, >0 = hiding).
///
/// Unlike the standard `MerkleTree`, this uniform variant requires:
/// - **All matrix heights must be powers of two**
/// - **Matrices must be sorted by height** (shortest to tallest)
/// - Uses incremental hashing via [`StatefulHasher`] instead of one-shot hashing
///
/// The per-leaf row composition uses nearest-neighbor upsampling: each matrix Mᵢ is virtually
/// extended to height N (width unchanged) by repeating each row rᵢ = N/nᵢ times
/// contiguously. For physical row index `j`, the sponge absorbs the `j`-th row from each
/// lifted matrix in sequence. The sponge applies its own padding semantics during absorption;
/// LMCS alignment only affects transcript hints.
///
/// Leaf digests are squeezed directly into domain order (digest `i` comes from
/// state `bitrev(i)`) so the Merkle tree is indexed by **domain order** (natural index).
/// External callers address leaves by domain index; the internal row access maps
/// `domain_index → bitrev(domain_index)` to reach the same physical row that was hashed.
///
/// Note: alignment padding is a convention for transcript openings and does not affect the
/// commitment. It is independent of the sponge's absorption alignment. LMCS does not enforce
/// that padded columns are zero; verifiers cannot distinguish zero padding from arbitrary values
/// unless they check those columns or constrain them elsewhere.
///
/// Equivalent single-matrix view: this commitment is equivalent to first forming a single
/// height-`N` matrix by (a) lifting every input matrix to height `N`, (b) padding each lifted
/// matrix horizontally with zero columns to reflect the sponge's absorption alignment (if any),
/// and (c) concatenating the results side-by-side. The leaf hash at index `j` is then the
/// sponge of that single concatenated matrix's row `j`. This is a conceptual view: LMCS does
/// not enforce that those padded columns are zero.
///
/// Since [`StatefulHasher`] operates on a single field type, this tree uses the same type `F`
/// for both matrix elements and hash words, unlike `MerkleTree` which can hash `F → W`.
///
/// Use [`root`](Self::root) to fetch the final commitment once the tree is built.
///
/// ## Transcript Hints
///
/// `prove_batch` streams exact transcript hints in the format expected by
/// [`Lmcs::open_batch`](crate::lmcs::Lmcs::open_batch):
/// - For each unique tree index **in sorted tree index order** (ascending, deduplicated): one row
///   per committed matrix (in committed matrix order), then `SALT_ELEMS` field elements of salt.
/// - Each row is padded with explicit zeros to the LMCS alignment. This allows verifiers to absorb
///   fixed-size chunks without special-casing the final partial chunk; padding is not enforced to
///   be zero.
/// - After all indices: missing sibling hashes, level-by-level, left-to-right, bottom-to-top.
///
/// Use [`LmcsTree::prove_lifted_batch`] to open query indices from a larger domain against a
/// shorter committed tree.
///
/// Hints are not observed into the Fiat-Shamir challenger.
///
/// This generally shouldn't be used directly. If you're using a Merkle tree as an MMCS,
/// see the MMCS wrapper types.
#[derive(Debug)]
pub struct LiftedMerkleTree<F, D, M, const DIGEST_ELEMS: usize, const SALT_ELEMS: usize = 0> {
    /// All committed matrices in insertion order.
    ///
    /// Matrices must be sorted by height (shortest to tallest) and all heights must be
    /// powers of two. Each matrix's rows are absorbed into sponge states that are
    /// maintained and upsampled across matrices of increasing height.
    ///
    /// This vector is retained for inspection or re-opening of the tree; it is not used
    /// after construction time.
    pub(crate) leaves: Vec<M>,

    /// All hash layers (digest arrays) in top-down order: index 0 is the root
    /// (one hash) and the last layer contains the leaf hashes.
    ///
    /// This matches the top-down depth convention of [`NodeId`](crate::lmcs::node_id::NodeId):
    /// `digest_layers[d]` has `2^d` entries, so `digest_layers[node.depth()][node.position()]`
    /// gives direct access.
    pub(crate) digest_layers: Vec<Vec<[D; DIGEST_ELEMS]>>,

    /// Salt matrix for hiding commitment. Each row contains `SALT_ELEMS` random field elements.
    /// `None` when `SALT_ELEMS = 0` (non-hiding mode).
    pub(crate) salt: Option<RowMajorMatrix<F>>,
    /// Column alignment used for transcript proofs.
    pub(crate) alignment: usize,
}

impl<F, D, M, const DIGEST_ELEMS: usize, const SALT_ELEMS: usize>
    LmcsTree<F, Hash<F, D, DIGEST_ELEMS>, M> for LiftedMerkleTree<F, D, M, DIGEST_ELEMS, SALT_ELEMS>
where
    F: Copy + Default + PartialEq + Send + Sync,
    D: Copy + Default + PartialEq + Send + Sync,
    M: Matrix<F>,
{
    fn root(&self) -> Hash<F, D, DIGEST_ELEMS> {
        Hash::from(self.digest_layers[0][0])
    }

    fn height(&self) -> usize {
        self.leaves.last().unwrap().height()
    }

    fn leaves(&self) -> &[M] {
        &self.leaves
    }

    /// Return the upsampled rows for `index` with original matrix widths (no padding).
    ///
    /// Panics if `index` is out of range for the tree height.
    fn rows(&self, index: usize) -> RowList<F> {
        self.collect_rows(index, self.widths())
    }

    /// Return the upsampled rows for `index`, padded to the tree's alignment.
    ///
    /// Padding uses `Default::default()` and is not enforced by verification; callers
    /// that require zero padding must check these columns explicitly.
    ///
    /// Panics if `index` is out of range for the tree height.
    fn aligned_rows(&self, index: usize) -> RowList<F> {
        self.collect_rows(index, self.aligned_widths())
    }

    fn alignment(&self) -> usize {
        self.alignment
    }

    fn widths(&self) -> Vec<usize> {
        self.leaves.iter().map(Matrix::width).collect()
    }

    /// Prove an exact batch opening and stream it into a transcript channel.
    ///
    /// Panics if `indices.depth()` is not this tree's depth or any index is out of range. Rows are
    /// padded to `alignment` and those padding values are not validated by verification; callers
    /// that require zero padding must check the opened rows explicitly.
    ///
    /// Leaf openings are written in **sorted tree index order** (ascending, deduplicated).
    fn prove_batch<Ch>(&self, indices: &TreeIndices, channel: &mut Ch)
    where
        Ch: ProverChannel<F = F, Commitment = Hash<F, D, DIGEST_ELEMS>>,
    {
        let tree_log_height = log2_strict_usize(self.height()) as u8;
        assert_eq!(
            indices.depth(),
            tree_log_height,
            "exact batch indices must be in the committed tree's index space",
        );

        // Stream leaf openings in sorted tree index order.
        for &index in indices.iter() {
            let opening = LeafOpening {
                rows: self.aligned_rows(index),
                salt: self.salt(index),
            };
            opening.write_to_channel(channel);
        }

        // Emit missing sibling hashes left-to-right, bottom-to-top.
        for sibling in indices.missing_siblings() {
            let hash = self.digest_layers[sibling.depth()][sibling.position()];
            channel.hint_commitment(Hash::from(hash));
        }
    }
}

impl<F, D, M, const DIGEST_ELEMS: usize, const SALT_ELEMS: usize>
    LiftedMerkleTree<F, D, M, DIGEST_ELEMS, SALT_ELEMS>
where
    F: Copy + Default + PartialEq + Send + Sync,
    D: Copy + Default + PartialEq + Send + Sync,
    M: Matrix<F>,
{
    /// Build a tree from domain-ordered matrices with optional salt and explicit alignment.
    ///
    /// Matrices are bit-reversed internally before storage and hashing.
    ///
    /// Preconditions:
    /// - `leaves` is non-empty and heights are powers of two.
    /// - Matrices are sorted by height (shortest to tallest).
    ///
    /// `alignment` controls transcript padding only; it does not affect the commitment.
    /// LMCS does not enforce that padded columns are zero.
    ///
    /// Panics if `leaves` is empty.
    pub fn build_with_alignment<DomainM, PF, PD, H, C, const WIDTH: usize>(
        h: &H,
        c: &C,
        leaves: Vec<DomainM>,
        salt: Option<RowMajorMatrix<F>>,
        alignment: usize,
    ) -> Self
    where
        DomainM: BitReversibleMatrix<F, BitRev = M>,
        PF: PackedValue<Value = F>,
        PD: PackedValue<Value = D>,
        H: StatefulHasher<F, [D; DIGEST_ELEMS], State = [D; WIDTH]>
            + StatefulHasher<PF, [PD; DIGEST_ELEMS], State = [PD; WIDTH]>
            + Sync,
        C: PseudoCompressionFunction<[D; DIGEST_ELEMS], 2>
            + PseudoCompressionFunction<[PD; DIGEST_ELEMS], 2>
            + Sync,
    {
        const { assert!(PF::WIDTH == PD::WIDTH) }
        assert!(!leaves.is_empty(), "cannot commit empty batch");
        debug_assert!(alignment > 0, "alignment must be non-zero");

        let leaves: Vec<M> =
            leaves.into_iter().map(BitReversibleMatrix::bit_reverse_rows).collect();

        // Build leaf hashes: absorb all matrix rows into sponge states, then squeeze.
        let leaf_digests: Vec<[PD::Value; DIGEST_ELEMS]> =
            info_span!("hash leaves").in_scope(|| {
                let mut leaf_states: Vec<[PD::Value; WIDTH]> =
                    build_leaf_states_upsampled::<PF, PD, M, H, WIDTH, DIGEST_ELEMS>(&leaves, h);

                // Absorb salt into states using SIMD-parallelized path (no-op when salt is None)
                if let Some(ref salt_matrix) = salt {
                    debug_assert_eq!(salt_matrix.height(), leaf_states.len());
                    debug_assert_eq!(salt_matrix.width(), SALT_ELEMS);
                    info_span!("absorb salt", height = salt_matrix.height(), width = SALT_ELEMS)
                        .in_scope(|| {
                            absorb_matrix::<PF, PD, _, _, WIDTH, DIGEST_ELEMS>(
                                &mut leaf_states,
                                salt_matrix,
                                h,
                            );
                        });
                }

                // Squeeze leaf hashes and bit-reverse in one pass: digest[i] =
                // squeeze(state[bitrev(i)]). This places digests in domain order so
                // the Merkle tree is indexed naturally.
                let n = leaf_states.len();
                let log_n = log2_strict_usize(n);
                (0..n)
                    .into_par_iter()
                    .map(|i| {
                        let src = reverse_bits_len(i, log_n);
                        h.squeeze(&leaf_states[src])
                    })
                    .collect()
            });

        // Build digest layers by repeatedly compressing until we reach the root,
        // then reverse so index 0 = root, matching the top-down NodeId convention.
        let digest_layers = info_span!("compress tree layers").in_scope(|| {
            let mut digest_layers = vec![leaf_digests];
            loop {
                let prev_layer = digest_layers.last().unwrap();
                if prev_layer.len() == 1 {
                    break;
                }

                let next_layer = compress_uniform::<PD, C, DIGEST_ELEMS>(prev_layer, c);
                digest_layers.push(next_layer);
            }
            digest_layers.reverse();
            digest_layers
        });

        Self {
            leaves,
            digest_layers,
            salt,
            alignment: alignment.max(1),
        }
    }

    /// Column alignment used when streaming openings.
    pub fn alignment(&self) -> usize {
        self.alignment
    }

    /// Extract the salt for the given domain index.
    ///
    /// Maps `domain_index` to the physical salt row via `bitrev(domain_index)`, matching
    /// the row that was absorbed during tree construction.
    ///
    /// # Panics
    ///
    /// Panics if `domain_index` is out of range, or if `SALT_ELEMS > 0` but the tree was
    /// constructed without salt.
    pub fn salt(&self, domain_index: usize) -> [F; SALT_ELEMS] {
        match &self.salt {
            Some(salt_matrix) => {
                let physical_index =
                    reverse_bits_len(domain_index, log2_strict_usize(salt_matrix.height()));
                let row = salt_matrix.row_slice(physical_index).expect("index must be valid");
                // Tree construction guarantees salt width == SALT_ELEMS
                array::from_fn(|i| row[i])
            },
            None => {
                // For SALT_ELEMS == 0, this returns an empty array.
                // For SALT_ELEMS > 0, this should never be reached if using safe constructors.
                debug_assert!(SALT_ELEMS == 0, "tree constructed without salt but SALT_ELEMS > 0");
                [F::default(); SALT_ELEMS]
            },
        }
    }

    /// Collect upsampled rows for `domain_index` into a flat `RowList` with the given widths.
    ///
    /// Maps the domain index to a bit-reversed row index: `bitrev(domain_index) >> k`.
    /// This returns the same values that were hashed into Merkle leaf `domain_index`
    /// (the tree is indexed by domain order after leaf digest permutation).
    ///
    /// Uses `Matrix::row()` to extend directly into a single pre-allocated buffer
    /// without per-row allocations.
    fn collect_rows(&self, domain_index: usize, widths: Vec<usize>) -> RowList<F> {
        let max_height = self.leaves.last().unwrap().height();
        let log_max_height = log2_strict_usize(max_height);
        let bit_reversed = reverse_bits_len(domain_index, log_max_height);
        let mut elems = Vec::with_capacity(widths.iter().sum());
        for (m, &padded_len) in self.leaves.iter().zip(&widths) {
            // Map domain index to bit-reversed row: bitrev(domain_index) >> log₂(max_height/h).
            let log_scaling = log2_strict_usize(max_height / m.height());
            elems.extend(
                m.row(bit_reversed >> log_scaling)
                    .expect("row_index must be valid after upsampling"),
            );
            elems.resize(elems.len() + padded_len - m.width(), F::default());
        }
        RowList::new(elems, widths)
    }
}

/// Build leaf states using the upsampled view (nearest-neighbor upsampling).
///
/// Returns the sponge states after absorbing all matrix rows but **before squeezing**.
/// Callers must squeeze the states to obtain final leaf hashes.
///
/// Conceptually, each matrix is virtually extended to height `H` by repeating each row
/// `L = H / h` times (width unchanged), and the leaf `r` absorbs the `r`-th row from each
/// extended matrix in order. Each absorbed row is virtually padded with zeros to a multiple of the
/// hasher's padding width for absorption; see [`LiftedMerkleTree`](crate::lmcs::LiftedMerkleTree)
/// docs for the equivalent single-matrix view.
///
/// Padding is implicit and not checked; callers that require zero padding must enforce
/// it elsewhere.
///
/// # Preconditions
/// - `matrices` is non-empty and sorted by non-decreasing power-of-two heights.
/// - `P::WIDTH` is a power of two.
///
/// Panics in debug builds if preconditions are violated.
fn build_leaf_states_upsampled<PF, PD, M, H, const WIDTH: usize, const DIGEST_ELEMS: usize>(
    matrices: &[M],
    sponge: &H,
) -> Vec<[PD::Value; WIDTH]>
where
    PF: PackedValue,
    PD: PackedValue,
    M: Matrix<PF::Value>,
    H: StatefulHasher<PF::Value, [PD::Value; DIGEST_ELEMS], State = [PD::Value; WIDTH]>
        + StatefulHasher<PF, [PD; DIGEST_ELEMS], State = [PD; WIDTH]>
        + Sync,
{
    const { assert!(PF::WIDTH.is_power_of_two()) };
    const { assert!(PD::WIDTH.is_power_of_two()) };
    let final_height = validate_heights(matrices.iter().map(|d| d.dimensions().height));

    // Memory buffers:
    // - states: Per-leaf scalar states (one per final row), maintained across matrices.
    // - scratch_states: Temporary buffer used when duplicating states during upsampling.
    let default_state = [PD::Value::default(); WIDTH];
    let mut states = vec![default_state; final_height];
    let mut scratch_states = vec![default_state; final_height];

    let mut active_height = matrices.first().unwrap().height();

    for matrix in matrices {
        let height = matrix.height();

        // Upsample states when height increases (applies to both scalar and packed paths).
        // Duplicate each existing state to fill the expanded height.
        // E.g., [s0, s1] with scaling_factor=2 → [s0, s0, s1, s1]
        if height > active_height {
            let scaling_factor = height / active_height;

            // Copy `states` into `scratch_states`, repeating each entry `scaling_factor` times
            // so we keep the accumulated sponge states aligned with the taller matrix.
            scratch_states[..height]
                .par_chunks_mut(scaling_factor)
                .zip(states[..active_height].par_iter())
                .for_each(|(chunk, state)| chunk.fill(*state));

            // Copy upsampled states back to canonical buffer
            mem::swap(&mut scratch_states, &mut states);
        }

        // Absorb the rows of the matrix into the extended state vector
        info_span!("absorb matrix", height, width = matrix.width()).in_scope(|| {
            absorb_matrix::<PF, PD, _, _, _, _>(&mut states[..height], matrix, sponge)
        });

        active_height = height;
    }

    states
}

/// Incorporate one matrix's row-wise contribution into the running per-leaf states.
///
/// Semantics: given `states` of length `h = matrix.height()`, for each row index `r ∈ [0, h)`
/// update `states[r]` by absorbing the matrix row `r` into that state. In the overall tree
/// construction, callers ensure that `states` is the correct lifted view for the current matrix
/// (either the "nearest-neighbor" duplication or the "modulo" duplication across the final
/// height). This helper performs exactly one absorption round for that matrix and returns with the
/// states mutated; it does not change the lifting shape or squeeze hashes.
fn absorb_matrix<PF, PD, M, H, const WIDTH: usize, const DIGEST_ELEMS: usize>(
    states: &mut [[PD::Value; WIDTH]],
    matrix: &M,
    sponge: &H,
) where
    PF: PackedValue,
    PD: PackedValue,
    M: Matrix<PF::Value>,
    H: StatefulHasher<PF::Value, [PD::Value; DIGEST_ELEMS], State = [PD::Value; WIDTH]>
        + StatefulHasher<PF, [PD; DIGEST_ELEMS], State = [PD; WIDTH]>
        + Sync,
{
    let height = matrix.height();
    assert_eq!(height, states.len());

    if height < PF::WIDTH || PF::WIDTH == 1 {
        // Scalar path: walk every final leaf state and absorb the wrapped row for this matrix.
        states.par_iter_mut().zip(matrix.par_rows()).for_each(|(state, row)| {
            sponge.absorb_into(state, row);
        });
    } else {
        // SIMD path: gather → absorb wrapped packed row → scatter per chunk.
        states
            .par_chunks_mut(PF::WIDTH)
            .enumerate()
            .for_each(|(packed_idx, states_chunk)| {
                let mut packed_state: [PD; WIDTH] =
                    array::from_fn(|col| PD::from_fn(|lane| states_chunk[lane][col]));
                let row_idx = packed_idx * PF::WIDTH;
                let row = matrix.vertically_packed_row::<PF>(row_idx);
                sponge.absorb_into(&mut packed_state, row);
                PD::unpack_into(&packed_state, states_chunk);
            });
    }
}

/// Compress a layer of hashes in a uniform Merkle tree.
///
/// Takes a layer of hashes and compresses pairs into a new layer with half as many elements.
/// The layer length must be a power of two.
///
/// When the result would be smaller than the packing width, uses a pure scalar path.
/// Otherwise uses SIMD parallelization. Since both the result length and packing width are
/// powers of two, the result is always a multiple of the packing width in the SIMD path,
/// requiring no scalar fallback for remainders.
fn compress_uniform<
    P: PackedValue,
    C: PseudoCompressionFunction<[P::Value; DIGEST_ELEMS], 2>
        + PseudoCompressionFunction<[P; DIGEST_ELEMS], 2>
        + Sync,
    const DIGEST_ELEMS: usize,
>(
    prev_layer: &[[P::Value; DIGEST_ELEMS]],
    c: &C,
) -> Vec<[P::Value; DIGEST_ELEMS]> {
    assert!(prev_layer.len().is_power_of_two(), "previous layer length must be a power of 2");

    let next_len = prev_layer.len() / 2;
    let default_digest = [P::Value::default(); DIGEST_ELEMS];
    let mut next_digests = vec![default_digest; next_len];

    // Use scalar path when output is too small for packing
    if next_len < P::WIDTH || P::WIDTH == 1 {
        next_digests.par_iter_mut().zip(prev_layer.par_chunks_exact(2)).for_each(
            |(next_digest, prev_layer_pair)| {
                *next_digest = c.compress([prev_layer_pair[0], prev_layer_pair[1]]);
            },
        );
    } else {
        // Packed path: since next_len and P::WIDTH are both powers of 2,
        // next_len is a multiple of P::WIDTH, so no remainder handling needed.
        next_digests.par_chunks_exact_mut(P::WIDTH).enumerate().for_each(
            |(packed_chunk_idx, digests_chunk)| {
                let chunk_idx = packed_chunk_idx * P::WIDTH;
                let left: [P; DIGEST_ELEMS] =
                    array::from_fn(|j| P::from_fn(|k| prev_layer[2 * (chunk_idx + k)][j]));
                let right: [P; DIGEST_ELEMS] =
                    array::from_fn(|j| P::from_fn(|k| prev_layer[2 * (chunk_idx + k) + 1][j]));
                let packed_digest = c.compress([left, right]);
                P::unpack_into(&packed_digest, digests_chunk);
            },
        );
    }
    next_digests
}

/// Validate a sequence of matrix heights for LMCS.
///
/// Requirements enforced:
/// - Non-empty sequence (at least one matrix).
/// - Every height is a power of two and non-zero.
/// - Heights are in non-decreasing order (sorted by height), so the last height is the maximum `H`
///   used by lifting.
///
/// # Panics
/// Panics if any requirement is violated.
fn validate_heights(heights: impl IntoIterator<Item = usize>) -> usize {
    let mut active_height = 0;

    for (matrix, height) in heights.into_iter().enumerate() {
        assert_ne!(height, 0, "zero height at matrix {matrix}");
        assert!(height.is_power_of_two(), "non-power-of-two height at matrix {matrix}");
        assert!(height >= active_height, "matrices must be sorted by height");
        active_height = height;
    }

    assert_ne!(active_height, 0, "empty batch");
    active_height
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_field::{Field, PackedValue, PrimeCharacteristicRing};
    use rand::{SeedableRng, rngs::SmallRng};

    use super::*;
    use crate::{
        lmcs::tests::build_leaves_single,
        testing::configs::goldilocks_poseidon2::{
            self as gl, DIGEST, Felt, PackedFelt, RATE, Sponge,
        },
        util::align::aligned_len,
    };

    /// Common matrix group scenarios for testing lifting with varying heights.
    fn matrix_scenarios<P: PackedValue>(rate: usize) -> Vec<Vec<(usize, usize)>> {
        let pack_width = P::WIDTH.max(2);
        vec![
            // Single matrices
            vec![(1, 1)],
            vec![(1, rate - 1)],
            // Multiple heights (must be ascending)
            vec![(2, 3), (4, 5), (8, rate)],
            vec![(1, 5), (1, 3), (2, 7), (4, 1), (8, rate + 1)],
            // Packing boundary tests
            vec![(pack_width / 2, rate - 1), (pack_width, rate), (pack_width * 2, rate + 3)],
            vec![(pack_width, rate + 5), (pack_width * 2, 25)],
            vec![
                (1, rate * 2),
                (pack_width / 2, rate * 2 - 1),
                (pack_width, rate * 2),
                (pack_width * 2, rate * 3 - 2),
            ],
            // Same-height matrices
            vec![(4, rate - 1), (4, rate), (8, rate + 3), (8, rate * 2)],
            // Single tall matrix
            vec![(pack_width * 2, rate - 1)],
        ]
    }

    /// Concatenate matrices horizontally, padding each to a multiple of `R`.
    /// All matrices are lifted to the maximum height first.
    fn concatenate_matrices<F: Field + PrimeCharacteristicRing, const R: usize>(
        matrices: &[RowMajorMatrix<F>],
    ) -> RowMajorMatrix<F> {
        let max_height = matrices.last().unwrap().height();
        let width: usize = matrices.iter().map(|m| aligned_len(m.width(), R)).sum();

        let concatenated_data: Vec<_> = (0..max_height)
            .flat_map(|idx| {
                matrices.iter().flat_map(move |m| {
                    let mut row = m.row_slice(idx).unwrap().to_vec();
                    let padded_width = aligned_len(row.len(), R);
                    row.resize(padded_width, F::ZERO);
                    row
                })
            })
            .collect();
        RowMajorMatrix::new(concatenated_data, width)
    }

    /// Upsample matrix to exactly `target_height` rows via nearest-neighbor repetition.
    fn upsample_matrix<F: Clone + Send + Sync>(
        matrix: &impl Matrix<F>,
        target_height: usize,
    ) -> RowMajorMatrix<F> {
        let height = matrix.height();
        assert!(target_height >= height);
        assert!(height.is_power_of_two() && target_height.is_power_of_two());

        let repeat_factor = target_height / height;
        let width = matrix.width();

        let mut values = Vec::with_capacity(target_height * width);
        for row in matrix.rows() {
            let row_vec: Vec<F> = row.collect();
            for _ in 0..repeat_factor {
                values.extend(row_vec.iter().cloned());
            }
        }

        RowMajorMatrix::new(values, width)
    }

    fn build_leaves_upsampled(
        matrices: &[RowMajorMatrix<Felt>],
        sponge: &Sponge,
    ) -> Vec<[Felt; DIGEST]> {
        let mut states =
            build_leaf_states_upsampled::<PackedFelt, PackedFelt, _, _, _, _>(matrices, sponge);
        states.iter_mut().map(|s| sponge.squeeze(s)).collect()
    }

    /// Test that upsampled lifting produces correct results:
    /// 1. Incremental lifting equals explicit lifting
    /// 2. Explicit lifting equals single-matrix concatenation baseline
    #[test]
    fn upsampled_equivalence() {
        let (_, sponge, _compressor) = gl::test_components();
        let mut rng = SmallRng::seed_from_u64(42);

        for scenario in matrix_scenarios::<PackedFelt>(RATE) {
            let matrices: Vec<RowMajorMatrix<Felt>> = scenario
                .into_iter()
                .map(|(h, w)| RowMajorMatrix::rand(&mut rng, h, w))
                .collect();

            let max_height = matrices.last().unwrap().height();

            // Upsampled path equivalence vs explicit upsampled lifting and single-concat baseline
            let leaves = build_leaves_upsampled(&matrices, &sponge);

            let matrices_upsampled: Vec<_> = matrices
                .iter()
                .map(|m: &RowMajorMatrix<Felt>| upsample_matrix(m, max_height))
                .collect();
            let leaves_lifted = build_leaves_upsampled(&matrices_upsampled, &sponge);
            assert_eq!(leaves, leaves_lifted);

            let matrix_single = concatenate_matrices::<_, RATE>(&matrices_upsampled);
            let leaves_single = build_leaves_single(&matrix_single, &sponge);
            assert_eq!(leaves, leaves_single);
        }
    }
}
