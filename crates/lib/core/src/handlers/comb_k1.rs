//! Precomputes the joint 2D comb-style scalar-mult lookup table for a pair of secp256k1
//! points. Produces the data needed to populate `AdviceInputs` for the
//! precomputation-based ECDSA verifier (`ecdsa_k256_keccak::verify_prehash_native_precomp`):
//! a reusable per-public-key cache, selected entries for the advice stack, and the sparse
//! Merkle store needed to open those entries.
//!
//! The cache depends only on `(G, Q)`, so it can be reused across signatures for the same
//! public key. It stores compact axis tables and upper Merkle levels; per signature, it
//! selects 32 entries and constructs a sparse `MerkleStore` for those openings.
//!
//! Background: comb tables. A comb table is a precomputed lookup that lets a verifier
//! compute a scalar multiplication `k * P` without running the textbook 256-step double-
//! and-add. The scalar `k` is split into fixed-width windows -- here 32 windows of 8 bits
//! each -- and the table stores `[d * 2^(w*b)] * P` for every window position `b` and
//! every possible window digit `d` in `0..2^w`. At verification time, the driver reads
//! one table entry per window position and accumulates them; this replaces the 256
//! doublings of double-and-add with 32 host-supplied table lookups plus 32 additions.
//! The "comb" name comes from the per-window bit pattern resembling comb teeth across the
//! scalar.
//!
//! "Joint" extends the construction to two base points `(P_1, P_2)` that share the same
//! window schedule: a single entry at `(b, i, j)` holds
//!     [i * 256^b] * P_1 + [j * 256^b] * P_2
//! so a double scalar mult like ECDSA's `R = u_1*G + u_2*Q` reads one entry per window
//! instead of two and contributes one addition per window instead of two. Cost: the table
//! grows from `32 * 256 = 8,192` single-point entries to `32 * 65,536 = 2,097,152` joint
//! entries.
//!
//! Worked example (toy). With `w = 2` and two 4-bit scalars `k_1 = 0b1011 = 11`,
//! `k_2 = 0b0110 = 6`, the comb has `ceil(4/2) = 2` windows:
//!   - Window `b = 0` (bits 0..2): `k_1` digit = `0b11 = 3`, `k_2` digit = `0b10 = 2`. Look up
//!     `T[0][3][2] = 3*P_1 + 2*P_2`.
//!   - Window `b = 1` (bits 2..4): `k_1` digit = `0b10 = 2`, `k_2` digit = `0b01 = 1`. Look up
//!     `T[1][2][1] = (2*4)*P_1 + (1*4)*P_2 = 8*P_1 + 4*P_2`.
//!
//! Sum: `11*P_1 + 6*P_2 = k_1*P_1 + k_2*P_2`. 2 lookups + 2 adds, no doublings. The same
//! mechanic at the actual `w = 8` over 256-bit scalars gives 32 lookups + 32 adds with the
//! doubling chain absorbed entirely into the precomputed table.
//!
//! Layout. The table holds `JOINT_WINDOW_POSITIONS = 32` blocks at width `w = 8`. Block
//! `b` covers windows that select bits `[w*b, w*(b+1))` of the two 256-bit scalars; within
//! block `b`, the entry at index `(i, j)` for `i, j` in `0..2^w` stores
//!     `entry[b][i][j] = [i * 256^b] * P_1 + [j * 256^b] * P_2`
//! Each entry occupies 20 felts (`X[8]` + `Y[8]` + `is_infinity[1]` + 3 reserved zero felts). The
//! high block (`b = 31`) covers bits `[248, 256)`.

use alloc::{vec, vec::Vec};

#[cfg(feature = "std")]
use k256::{
    AffinePoint as K256AffinePoint, EncodedPoint as K256EncodedPoint, FieldBytes as K256FieldBytes,
    ProjectivePoint as K256ProjectivePoint,
    elliptic_curve::{
        group::{Curve, Group, prime::PrimeCurveAffine},
        point::BatchNormalize,
        sec1::{Coordinates, FromEncodedPoint, ToEncodedPoint},
    },
};
use miden_core::{
    Felt, Word,
    crypto::{
        hash::Poseidon2,
        merkle::{InnerNodeInfo, MerklePath, MerkleStore},
    },
};
use num::{Zero, bigint::BigUint};
#[cfg(feature = "std")]
use rayon::prelude::*;

use crate::handlers::secp256k1_constants::SECP256K1_BASE_PRIME_U32;

/// Comb window width. Each window selects 8 bits, so each block of the table is indexed by
/// a pair of 8-bit values, giving 65,536 entries per block.
pub const WINDOW_WIDTH: usize = 8;

/// `2^WINDOW_WIDTH`: the number of distinct values a single window can take.
pub const ENTRIES_PER_AXIS: usize = 1 << WINDOW_WIDTH;

/// Number of `(i, j)` pairs per block.
pub const ENTRIES_PER_BLOCK: usize = ENTRIES_PER_AXIS * ENTRIES_PER_AXIS;

/// Felt count for one stored point: 8 for X, 8 for Y, 1 for is_infinity, 3 reserved zeros.
pub const FELTS_PER_ENTRY: usize = 20;

/// Number of window blocks for a joint comb table over a pair of 256-bit scalars at width
/// `WINDOW_WIDTH`. Each scalar is 256 bits; `256 / 8 = 32` blocks cover all the bits.
pub const JOINT_WINDOW_POSITIONS: usize = 256_usize.div_ceil(WINDOW_WIDTH);

/// Total joint-table size in felts: 32 * 65,536 * 20 = 41,943,040.
pub const JOINT_TABLE_FELTS: usize = JOINT_WINDOW_POSITIONS * ENTRIES_PER_BLOCK * FELTS_PER_ENTRY;

/// Felt count for one Merkle-tree leaf entry: the 20-felt point representation padded with
/// 4 zeros to align to 24 felts.
pub const FELTS_PER_MERKLE_ENTRY: usize = 24;

// Number of non-padding u32 values in one compact table entry:
// X[8], Y[8], and the is-infinity flag.
const U32S_PER_COMPACT_ENTRY: usize = 17;

// Normalize joint entries in row batches to keep parallel cache builds from materializing
// one full block per worker.
#[cfg(feature = "std")]
const ROWS_PER_BATCH_NORMALIZE: usize = 64;
#[cfg(feature = "std")]
const _: () = assert!(ENTRIES_PER_AXIS.is_multiple_of(ROWS_PER_BATCH_NORMALIZE));

// The cache stores Merkle internal levels starting at this level above the leaves. Lower
// siblings are recomputed from the compact axis tables for the few openings used by each
// signature. With four dropped levels, each path recomputes the siblings covering 2, 4, 8,
// and 16 leaves before switching to stored levels.
const STORED_INTERNAL_LEVEL_START: usize = 4;

/// Number of leaves in the Merkle tree commitment over the joint comb table. One leaf per
/// table entry: 32 blocks * 65,536 entries = 2,097,152.
pub const MERKLE_LEAF_COUNT: usize = JOINT_WINDOW_POSITIONS * ENTRIES_PER_BLOCK;

/// Depth of the Merkle tree committing to the comb table. `MERKLE_LEAF_COUNT = 2^21`.
pub const MERKLE_TREE_DEPTH: u8 = 21;

const _: () = assert!(MERKLE_LEAF_COUNT == (1usize << (MERKLE_TREE_DEPTH as usize)));

/// Affine secp256k1 point in BigUint coordinates. `is_infinity` overrides `(x, y)`.
#[derive(Clone, Debug)]
pub struct AffinePoint {
    pub x: BigUint,
    pub y: BigUint,
    pub is_infinity: bool,
}

impl AffinePoint {
    pub fn infinity() -> Self {
        Self {
            x: BigUint::zero(),
            y: BigUint::zero(),
            is_infinity: true,
        }
    }

    pub fn finite(x: BigUint, y: BigUint) -> Self {
        Self { x, y, is_infinity: false }
    }
}

/// Compact representation of one comb-table entry.
///
/// Merkle leaves and advice entries use `X[8] || Y[8] || is_infinity || zeros_7`. The
/// cache stores only the 17 non-padding u32 values and synthesizes the zeros when needed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CompactCombEntry {
    limbs: [u32; U32S_PER_COMPACT_ENTRY],
}

impl CompactCombEntry {
    fn from_point(point: &AffinePoint) -> Self {
        let mut limbs = [0u32; U32S_PER_COMPACT_ENTRY];
        limbs[..8].copy_from_slice(&u256_to_u32_array(&point.x));
        limbs[8..16].copy_from_slice(&u256_to_u32_array(&point.y));
        limbs[16] = u32::from(point.is_infinity);
        Self { limbs }
    }

    fn padded_felts(&self) -> [Felt; FELTS_PER_MERKLE_ENTRY] {
        let mut out = [Felt::ZERO; FELTS_PER_MERKLE_ENTRY];
        for (dst, &src) in out.iter_mut().zip(self.limbs.iter()) {
            *dst = Felt::from_u32(src);
        }
        out
    }

    fn extend_padded_felts(&self, out: &mut Vec<Felt>) {
        out.extend(self.padded_felts());
    }

    fn extend_point_felts(&self, out: &mut Vec<Felt>) {
        for &value in &self.limbs {
            out.push(Felt::from_u32(value));
        }
        for _ in U32S_PER_COMPACT_ENTRY..FELTS_PER_ENTRY {
            out.push(Felt::ZERO);
        }
    }

    fn leaf_hash(&self) -> Word {
        Poseidon2::hash_elements(&self.padded_felts())
    }
}

/// Reusable comb-table cache for one `(G, Q)` pair.
///
/// [`PrecomputedK1PubKey::advice_for_windows`] returns the selected entries and sparse
/// `MerkleStore` for one scalar pair.
#[derive(Clone, Debug)]
pub struct PrecomputedK1PubKey {
    axis_p1: Vec<CompactCombEntry>,
    axis_p2: Vec<CompactCombEntry>,
    merkle_internal_levels: Vec<Vec<Word>>,
}

impl PrecomputedK1PubKey {
    /// Builds the joint comb-table cache for `(p1, p2)`.
    ///
    /// The cache depends only on the two base points, not on a signature.
    /// Both inputs must be valid secp256k1 affine points, or the point at infinity.
    pub fn new(p1: &AffinePoint, p2: &AffinePoint) -> Self {
        let (axis_p1, axis_p2, leaf_parents) = comb_axes_and_leaf_parents(p1, p2);

        debug_assert_eq!(axis_p1.len(), JOINT_WINDOW_POSITIONS * ENTRIES_PER_AXIS);
        debug_assert_eq!(axis_p2.len(), JOINT_WINDOW_POSITIONS * ENTRIES_PER_AXIS);
        debug_assert_eq!(leaf_parents.len(), MERKLE_LEAF_COUNT / 2);

        let merkle_internal_levels =
            build_internal_levels_from_leaf_parents(leaf_parents, MERKLE_TREE_DEPTH);

        Self { axis_p1, axis_p2, merkle_internal_levels }
    }

    /// Returns the Merkle root of the cached joint comb table.
    pub fn merkle_root(&self) -> [Felt; 4] {
        **self
            .merkle_internal_levels
            .last()
            .and_then(|level| level.first())
            .expect("merkle tree has a root")
    }

    /// Returns the selected table entries and sparse `MerkleStore` for `(u_1, u_2)`.
    pub fn advice_for_windows(&self, u_1: &BigUint, u_2: &BigUint) -> (Vec<Felt>, MerkleStore) {
        let indices = selected_leaf_indices(u_1, u_2);
        (self.entries_for_indices(&indices), self.merkle_store_for_indices(&indices))
    }

    /// Returns only the selected table entries, in verifier window order.
    pub fn entries_in_window_order(&self, u_1: &BigUint, u_2: &BigUint) -> Vec<Felt> {
        self.entries_for_indices(&selected_leaf_indices(u_1, u_2))
    }

    /// Returns only the sparse `MerkleStore` for the selected table entries.
    pub fn merkle_store_for_windows(&self, u_1: &BigUint, u_2: &BigUint) -> MerkleStore {
        self.merkle_store_for_indices(&selected_leaf_indices(u_1, u_2))
    }

    fn entries_for_indices(&self, indices: &[usize]) -> Vec<Felt> {
        let mut out = Vec::with_capacity(JOINT_WINDOW_POSITIONS * FELTS_PER_MERKLE_ENTRY);
        for &leaf_idx in indices {
            self.entry_for_leaf_index(leaf_idx).extend_padded_felts(&mut out);
        }
        debug_assert_eq!(out.len(), JOINT_WINDOW_POSITIONS * FELTS_PER_MERKLE_ENTRY);
        out
    }

    fn merkle_store_for_indices(&self, indices: &[usize]) -> MerkleStore {
        let paths = indices.iter().copied().map(|leaf_idx| {
            (leaf_idx as u64, self.leaf_hash(leaf_idx), self.authentication_path(leaf_idx))
        });

        let mut store = MerkleStore::new();
        store
            .add_merkle_paths(paths)
            .expect("cached Merkle levels are internally consistent");
        store
    }

    fn authentication_path(&self, leaf_idx: usize) -> MerklePath {
        let mut idx = leaf_idx;
        let mut path = Vec::with_capacity(MERKLE_TREE_DEPTH as usize);

        path.push(self.leaf_hash(idx ^ 1));
        idx >>= 1;

        for dropped_level in 0..STORED_INTERNAL_LEVEL_START {
            path.push(self.node_at_dropped_level(dropped_level, idx ^ 1));
            idx >>= 1;
        }

        for level in self
            .merkle_internal_levels
            .iter()
            .take(MERKLE_TREE_DEPTH as usize - 1 - STORED_INTERNAL_LEVEL_START)
        {
            path.push(level[idx ^ 1]);
            idx >>= 1;
        }
        MerklePath::new(path)
    }

    fn leaf_hash(&self, leaf_idx: usize) -> Word {
        if leaf_idx < MERKLE_LEAF_COUNT {
            self.entry_for_leaf_index(leaf_idx).leaf_hash()
        } else {
            empty_leaf_hash()
        }
    }

    fn entry_for_leaf_index(&self, leaf_idx: usize) -> CompactCombEntry {
        let block = leaf_idx / ENTRIES_PER_BLOCK;
        let in_block = leaf_idx % ENTRIES_PER_BLOCK;
        let i = in_block / ENTRIES_PER_AXIS;
        let j = in_block % ENTRIES_PER_AXIS;

        let axis_offset = block * ENTRIES_PER_AXIS;
        add_compact_entries(&self.axis_p1[axis_offset + i], &self.axis_p2[axis_offset + j])
    }

    fn node_at_dropped_level(&self, level: usize, idx: usize) -> Word {
        if level == 0 {
            let left = self.leaf_hash(idx * 2);
            let right = self.leaf_hash(idx * 2 + 1);
            Poseidon2::merge(&[left, right])
        } else {
            let left = self.node_at_dropped_level(level - 1, idx * 2);
            let right = self.node_at_dropped_level(level - 1, idx * 2 + 1);
            Poseidon2::merge(&[left, right])
        }
    }
}

fn comb_axes_and_leaf_parents(
    p1: &AffinePoint,
    p2: &AffinePoint,
) -> (Vec<CompactCombEntry>, Vec<CompactCombEntry>, Vec<Word>) {
    #[cfg(feature = "std")]
    {
        comb_axes_and_leaf_parents_parallel(p1, p2)
    }

    #[cfg(not(feature = "std"))]
    {
        comb_axes_and_leaf_parents_serial(p1, p2)
    }
}

#[cfg(not(feature = "std"))]
fn comb_axes_and_leaf_parents_serial(
    p1: &AffinePoint,
    p2: &AffinePoint,
) -> (Vec<CompactCombEntry>, Vec<CompactCombEntry>, Vec<Word>) {
    let mut axis_p1 = Vec::with_capacity(JOINT_WINDOW_POSITIONS * ENTRIES_PER_AXIS);
    let mut axis_p2 = Vec::with_capacity(JOINT_WINDOW_POSITIONS * ENTRIES_PER_AXIS);
    let mut leaf_parents = Vec::with_capacity(MERKLE_LEAF_COUNT / 2);
    let prime = base_prime();

    for (shift_p1, shift_p2) in joint_comb_shifts(p1, p2, &prime) {
        let mut small_p1 = Vec::with_capacity(ENTRIES_PER_AXIS);
        let mut small_p2 = Vec::with_capacity(ENTRIES_PER_AXIS);
        small_p1.push(AffinePoint::infinity());
        small_p2.push(AffinePoint::infinity());
        for k in 1..ENTRIES_PER_AXIS {
            small_p1.push(affine_add(&small_p1[k - 1], &shift_p1, &prime));
            small_p2.push(affine_add(&small_p2[k - 1], &shift_p2, &prime));
        }

        axis_p1.extend(small_p1.iter().map(CompactCombEntry::from_point));
        axis_p2.extend(small_p2.iter().map(CompactCombEntry::from_point));

        let entries = batch_affine_add_pairs(&small_p1, &small_p2, &prime);
        for pair in entries.chunks_exact(2) {
            let left = CompactCombEntry::from_point(&pair[0]).leaf_hash();
            let right = CompactCombEntry::from_point(&pair[1]).leaf_hash();
            leaf_parents.push(Poseidon2::merge(&[left, right]));
        }
    }

    (axis_p1, axis_p2, leaf_parents)
}

#[cfg(feature = "std")]
fn comb_axes_and_leaf_parents_parallel(
    p1: &AffinePoint,
    p2: &AffinePoint,
) -> (Vec<CompactCombEntry>, Vec<CompactCombEntry>, Vec<Word>) {
    let p1 = to_k256_projective(p1);
    let p2 = to_k256_projective(p2);
    let shifts = k256_joint_comb_shifts(p1, p2);
    let mut axis_p1 = vec![CompactCombEntry::default(); JOINT_WINDOW_POSITIONS * ENTRIES_PER_AXIS];
    let mut axis_p2 = vec![CompactCombEntry::default(); JOINT_WINDOW_POSITIONS * ENTRIES_PER_AXIS];
    let mut leaf_parents = vec![Word::new([Felt::ZERO; 4]); MERKLE_LEAF_COUNT / 2];

    axis_p1
        .par_chunks_mut(ENTRIES_PER_AXIS)
        .zip(axis_p2.par_chunks_mut(ENTRIES_PER_AXIS))
        .zip(leaf_parents.par_chunks_mut(ENTRIES_PER_BLOCK / 2))
        .zip(shifts.par_iter())
        .for_each(|(((axis_p1_chunk, axis_p2_chunk), parent_chunk), (shift_p1, shift_p2))| {
            fill_k256_comb_block(shift_p1, shift_p2, axis_p1_chunk, axis_p2_chunk, parent_chunk);
        });

    (axis_p1, axis_p2, leaf_parents)
}

#[cfg(feature = "std")]
fn to_k256_projective(point: &AffinePoint) -> K256ProjectivePoint {
    if point.is_infinity {
        return K256ProjectivePoint::IDENTITY;
    }

    let x = biguint_to_be32(&point.x);
    let y = biguint_to_be32(&point.y);
    let encoded = K256EncodedPoint::from_affine_coordinates(
        K256FieldBytes::from_slice(&x),
        K256FieldBytes::from_slice(&y),
        false,
    );
    let affine = Option::<K256AffinePoint>::from(K256AffinePoint::from_encoded_point(&encoded))
        .expect("point must lie on secp256k1");
    K256ProjectivePoint::from(affine)
}

#[cfg(feature = "std")]
fn k256_joint_comb_shifts(
    p1: K256ProjectivePoint,
    p2: K256ProjectivePoint,
) -> Vec<(K256ProjectivePoint, K256ProjectivePoint)> {
    let mut shifts = Vec::with_capacity(JOINT_WINDOW_POSITIONS);
    let mut shift_p1 = p1;
    let mut shift_p2 = p2;

    for _ in 0..JOINT_WINDOW_POSITIONS {
        shifts.push((shift_p1, shift_p2));
        for _ in 0..WINDOW_WIDTH {
            shift_p1 = shift_p1.double();
            shift_p2 = shift_p2.double();
        }
    }

    shifts
}

#[cfg(feature = "std")]
fn fill_k256_comb_block(
    shift_p1: &K256ProjectivePoint,
    shift_p2: &K256ProjectivePoint,
    axis_p1: &mut [CompactCombEntry],
    axis_p2: &mut [CompactCombEntry],
    leaf_parents: &mut [Word],
) {
    debug_assert_eq!(axis_p1.len(), ENTRIES_PER_AXIS);
    debug_assert_eq!(axis_p2.len(), ENTRIES_PER_AXIS);
    debug_assert_eq!(leaf_parents.len(), ENTRIES_PER_BLOCK / 2);

    let mut small_p1 = Vec::with_capacity(ENTRIES_PER_AXIS);
    let mut small_p2 = Vec::with_capacity(ENTRIES_PER_AXIS);
    small_p1.push(K256ProjectivePoint::IDENTITY);
    small_p2.push(K256ProjectivePoint::IDENTITY);
    for k in 1..ENTRIES_PER_AXIS {
        small_p1.push(small_p1[k - 1] + shift_p1);
        small_p2.push(small_p2[k - 1] + shift_p2);
    }

    let mut axis_affines = vec![K256AffinePoint::IDENTITY; ENTRIES_PER_AXIS];
    let mut axis_identity_mask = vec![false; ENTRIES_PER_AXIS];
    compact_from_k256_projective_batch_into(
        &mut small_p1,
        &mut axis_affines,
        axis_p1,
        &mut axis_identity_mask,
    );
    compact_from_k256_projective_batch_into(
        &mut small_p2,
        &mut axis_affines,
        axis_p2,
        &mut axis_identity_mask,
    );

    let mut points = Vec::with_capacity(ROWS_PER_BATCH_NORMALIZE * ENTRIES_PER_AXIS);
    let mut affines = vec![K256AffinePoint::IDENTITY; ROWS_PER_BATCH_NORMALIZE * ENTRIES_PER_AXIS];
    let mut compact =
        vec![CompactCombEntry::default(); ROWS_PER_BATCH_NORMALIZE * ENTRIES_PER_AXIS];
    let mut identity_mask = vec![false; ROWS_PER_BATCH_NORMALIZE * ENTRIES_PER_AXIS];
    for (row_batch, p1_rows) in small_p1.chunks(ROWS_PER_BATCH_NORMALIZE).enumerate() {
        points.clear();
        for p1 in p1_rows {
            for p2 in &small_p2 {
                points.push(*p1 + p2);
            }
        }

        let parent_offset = row_batch * ROWS_PER_BATCH_NORMALIZE * ENTRIES_PER_AXIS / 2;
        compact_from_k256_projective_batch_into(
            &mut points,
            &mut affines[..],
            &mut compact[..],
            &mut identity_mask[..],
        );
        for (idx, pair) in compact.chunks_exact(2).enumerate() {
            let left = pair[0].leaf_hash();
            let right = pair[1].leaf_hash();
            leaf_parents[parent_offset + idx] = Poseidon2::merge(&[left, right]);
        }
    }
}

#[cfg(feature = "std")]
fn compact_from_k256_projective_batch_into(
    points: &mut [K256ProjectivePoint],
    affines: &mut [K256AffinePoint],
    out: &mut [CompactCombEntry],
    identity_mask: &mut [bool],
) {
    assert_eq!(affines.len(), points.len());
    assert_eq!(out.len(), points.len());
    assert_eq!(identity_mask.len(), points.len());

    // Keep identity points out of batch normalization; the compact encoding restores them below.
    for (mask, point) in identity_mask.iter_mut().zip(points.iter()) {
        *mask = bool::from(point.is_identity());
    }
    for (point, is_identity) in points.iter_mut().zip(identity_mask.iter()) {
        if *is_identity {
            *point = K256ProjectivePoint::GENERATOR;
        }
    }

    <K256ProjectivePoint as Curve>::batch_normalize(&*points, affines);
    for (point, is_identity) in points.iter_mut().zip(identity_mask.iter()) {
        if *is_identity {
            *point = K256ProjectivePoint::IDENTITY;
        }
    }

    for ((slot, point), is_identity) in out.iter_mut().zip(affines.iter()).zip(identity_mask.iter())
    {
        *slot = if *is_identity {
            let mut limbs = [0u32; U32S_PER_COMPACT_ENTRY];
            limbs[16] = 1;
            CompactCombEntry { limbs }
        } else {
            compact_from_k256_affine(point)
        };
    }
}

#[cfg(feature = "std")]
fn add_compact_entries(a: &CompactCombEntry, b: &CompactCombEntry) -> CompactCombEntry {
    compact_from_k256_projective(
        to_k256_projective_from_compact(a) + to_k256_projective_from_compact(b),
    )
}

#[cfg(not(feature = "std"))]
fn add_compact_entries(a: &CompactCombEntry, b: &CompactCombEntry) -> CompactCombEntry {
    let prime = base_prime();
    CompactCombEntry::from_point(&affine_add(&a.to_affine_point(), &b.to_affine_point(), &prime))
}

#[cfg(feature = "std")]
fn compact_from_k256_projective(point: K256ProjectivePoint) -> CompactCombEntry {
    if bool::from(point.is_identity()) {
        let mut limbs = [0u32; U32S_PER_COMPACT_ENTRY];
        limbs[16] = 1;
        return CompactCombEntry { limbs };
    }

    let affines = <K256ProjectivePoint as BatchNormalize<_>>::batch_normalize(&[point]);
    compact_from_k256_affine(&affines[0])
}

#[cfg(feature = "std")]
fn to_k256_projective_from_compact(entry: &CompactCombEntry) -> K256ProjectivePoint {
    if entry.limbs[16] == 1 {
        return K256ProjectivePoint::IDENTITY;
    }

    let encoded = K256EncodedPoint::from_affine_coordinates(
        K256FieldBytes::from_slice(&u32_le_to_be32(&entry.limbs[..8])),
        K256FieldBytes::from_slice(&u32_le_to_be32(&entry.limbs[8..16])),
        false,
    );
    let affine = Option::<K256AffinePoint>::from(K256AffinePoint::from_encoded_point(&encoded))
        .expect("cached point must lie on secp256k1");
    K256ProjectivePoint::from(affine)
}

#[cfg(not(feature = "std"))]
impl CompactCombEntry {
    fn to_affine_point(self) -> AffinePoint {
        if self.limbs[16] == 1 {
            AffinePoint::infinity()
        } else {
            AffinePoint::finite(
                BigUint::from_slice(&self.limbs[..8]),
                BigUint::from_slice(&self.limbs[8..16]),
            )
        }
    }
}

#[cfg(feature = "std")]
fn compact_from_k256_affine(point: &K256AffinePoint) -> CompactCombEntry {
    if bool::from(point.is_identity()) {
        let mut limbs = [0u32; U32S_PER_COMPACT_ENTRY];
        limbs[16] = 1;
        return CompactCombEntry { limbs };
    }

    let encoded = point.to_encoded_point(false);
    match encoded.coordinates() {
        Coordinates::Uncompressed { x, y } => {
            let mut limbs = [0u32; U32S_PER_COMPACT_ENTRY];
            limbs[..8].copy_from_slice(&be32_to_u32_le(x));
            limbs[8..16].copy_from_slice(&be32_to_u32_le(y));
            CompactCombEntry { limbs }
        },
        _ => panic!("non-identity affine point must encode as uncompressed"),
    }
}

fn joint_comb_shifts(
    p1: &AffinePoint,
    p2: &AffinePoint,
    prime: &BigUint,
) -> Vec<(AffinePoint, AffinePoint)> {
    let mut shifts = Vec::with_capacity(JOINT_WINDOW_POSITIONS);
    let mut shift_p1 = p1.clone();
    let mut shift_p2 = p2.clone();

    for _ in 0..JOINT_WINDOW_POSITIONS {
        shifts.push((shift_p1.clone(), shift_p2.clone()));
        for _ in 0..WINDOW_WIDTH {
            shift_p1 = affine_double(&shift_p1, prime);
            shift_p2 = affine_double(&shift_p2, prime);
        }
    }

    shifts
}

fn for_each_joint_comb_entry(
    p1: &AffinePoint,
    p2: &AffinePoint,
    mut visit: impl FnMut(&AffinePoint),
) {
    let prime = base_prime();

    for (shift_p1, shift_p2) in joint_comb_shifts(p1, p2, &prime) {
        let mut small_p1 = Vec::with_capacity(ENTRIES_PER_AXIS);
        let mut small_p2 = Vec::with_capacity(ENTRIES_PER_AXIS);
        small_p1.push(AffinePoint::infinity());
        small_p2.push(AffinePoint::infinity());
        for k in 1..ENTRIES_PER_AXIS {
            small_p1.push(affine_add(&small_p1[k - 1], &shift_p1, &prime));
            small_p2.push(affine_add(&small_p2[k - 1], &shift_p2, &prime));
        }

        for entry in batch_affine_add_pairs(&small_p1, &small_p2, &prime) {
            visit(&entry);
        }
    }
}

/// Builds a 2D comb table for a pair of secp256k1 base points `(p1, p2)`, suitable for the
/// joint scalar mult `[u_1] * p1 + [u_2] * p2` over 256-bit scalars `u_1`, `u_2`. Layout:
/// `JOINT_WINDOW_POSITIONS` contiguous blocks of `ENTRIES_PER_BLOCK` entries; entry
/// `(i, j)` in block `b` is `[i * 2^(WINDOW_WIDTH*b)] * p1 +
/// [j * 2^(WINDOW_WIDTH*b)] * p2`.
///
/// The per-block cross-product step is computed with one Montgomery-batched modular
/// inversion instead of one Fermat inversion per entry.
///
/// This materializes the full joint table. Use [`PrecomputedK1PubKey`] for ECDSA witness
/// generation.
pub fn joint_comb_table(p1: &AffinePoint, p2: &AffinePoint) -> Vec<Felt> {
    let mut out = Vec::with_capacity(JOINT_TABLE_FELTS);
    for_each_joint_comb_entry(p1, p2, |entry| {
        CompactCombEntry::from_point(entry).extend_point_felts(&mut out);
    });
    debug_assert_eq!(out.len(), JOINT_TABLE_FELTS);
    out
}

/// Builds the joint comb table for `(p1, p2)` and reformats it as a flat sequence of
/// `MERKLE_LEAF_COUNT` entries, each `FELTS_PER_MERKLE_ENTRY` (= 24) felts. Each entry is
/// the 20-felt point representation followed by 4 zero pad felts.
///
/// Layout: entry at `(block, i, j)` lives at offset
/// `(block * ENTRIES_PER_BLOCK + i * ENTRIES_PER_AXIS + j) * FELTS_PER_MERKLE_ENTRY` in the
/// returned vector.
///
/// This materializes the full joint table. Use [`PrecomputedK1PubKey`] for ECDSA witness
/// generation.
pub fn joint_comb_padded_entries(p1: &AffinePoint, p2: &AffinePoint) -> Vec<Felt> {
    let mut out = Vec::with_capacity(MERKLE_LEAF_COUNT * FELTS_PER_MERKLE_ENTRY);
    for_each_joint_comb_entry(p1, p2, |entry| {
        CompactCombEntry::from_point(entry).extend_padded_felts(&mut out);
    });
    debug_assert_eq!(out.len(), MERKLE_LEAF_COUNT * FELTS_PER_MERKLE_ENTRY);
    out
}

/// Computes the per-leaf Poseidon2 hashes for the padded-entries vector returned by
/// `joint_comb_padded_entries`. Returns one `Word` per leaf in entry order.
pub fn merkle_leaf_hashes(padded_entries: &[Felt]) -> Vec<Word> {
    assert_eq!(
        padded_entries.len(),
        MERKLE_LEAF_COUNT * FELTS_PER_MERKLE_ENTRY,
        "padded_entries.len() = {} does not match MERKLE_LEAF_COUNT * FELTS_PER_MERKLE_ENTRY = {}",
        padded_entries.len(),
        MERKLE_LEAF_COUNT * FELTS_PER_MERKLE_ENTRY
    );
    (0..MERKLE_LEAF_COUNT)
        .map(|idx| {
            let base = idx * FELTS_PER_MERKLE_ENTRY;
            Poseidon2::hash_elements(&padded_entries[base..base + FELTS_PER_MERKLE_ENTRY])
        })
        .collect()
}

/// Builds the depth-`depth` Merkle tree witness for a *left-aligned* leaf list (real
/// leaves at indices `[0, real_leaves.len())`, empty padding at `[len, 2^depth)`).
///
/// Returns `(root, inner_nodes)`, where `root` matches what `MerkleTree::new(...)` of the
/// fully-padded leaves would produce, and `inner_nodes` is the minimal set of
/// [`InnerNodeInfo`]s needed to populate a [`MerkleStore`] that can serve any path in the
/// real range `[0, real_leaves.len())`.
///
/// The empty padding contributes only `depth` distinct subtree roots (one per level),
/// produced by repeated self-merge of `empty_leaf`; the builder reuses these instead of
/// re-hashing identical empty leaves through identical empty subtrees.
///
/// [`MerkleStore`]: miden_core::crypto::merkle::MerkleStore
pub fn build_left_aligned_padded_tree(
    real_leaves: &[Word],
    depth: u8,
    empty_leaf: Word,
) -> (Word, Vec<InnerNodeInfo>) {
    assert!(depth < 64, "depth = {} must be < 64 to fit tree capacity in u64", depth);
    let total = 1u64 << depth;
    assert!(
        real_leaves.len() as u64 <= total,
        "real_leaves.len() = {} exceeds tree capacity 2^{} = {}",
        real_leaves.len(),
        depth,
        total
    );

    // Precompute empty_subtree[h] = root of a height-h all-empty subtree.
    // empty_subtree[0] = empty_leaf, empty_subtree[depth] = root of fully-empty tree.
    let mut empty_subtree = Vec::with_capacity(depth as usize + 1);
    empty_subtree.push(empty_leaf);
    for _ in 0..depth as usize {
        let last = *empty_subtree.last().expect("non-empty");
        empty_subtree.push(Poseidon2::merge(&[last, last]));
    }

    // Empty-subtree inner nodes: one InnerNodeInfo per height. Registering each canonical
    // empty subtree root once is sufficient for the store; the same value can appear as a
    // sibling on many different paths.
    let mut inner_nodes: Vec<InnerNodeInfo> = (1..=depth as usize)
        .map(|h| {
            let child = empty_subtree[h - 1];
            let value = empty_subtree[h];
            InnerNodeInfo { value, left: child, right: child }
        })
        .collect();

    // Build the live + boundary portion of the tree, level by level. At each level, pair
    // adjacent live nodes; if the live count is odd, pair the rightmost one with the
    // empty subtree of the same height (the boundary case).
    let mut current: Vec<Word> = real_leaves.to_vec();
    for level_filler in empty_subtree.iter().take(depth as usize) {
        let n = current.len();
        let mut parents = Vec::with_capacity(n.div_ceil(2));
        let mut i = 0;
        while i + 1 < n {
            let left = current[i];
            let right = current[i + 1];
            let value = Poseidon2::merge(&[left, right]);
            inner_nodes.push(InnerNodeInfo { value, left, right });
            parents.push(value);
            i += 2;
        }
        if i < n {
            let left = current[i];
            let right = *level_filler;
            let value = Poseidon2::merge(&[left, right]);
            inner_nodes.push(InnerNodeInfo { value, left, right });
            parents.push(value);
        }
        current = parents;
    }

    let root = if real_leaves.is_empty() {
        empty_subtree[depth as usize]
    } else {
        debug_assert_eq!(current.len(), 1);
        current[0]
    };

    (root, inner_nodes)
}

fn build_internal_levels_from_leaf_parents(leaf_parents: Vec<Word>, depth: u8) -> Vec<Vec<Word>> {
    assert!(depth > 0, "depth must be non-zero");
    assert!(depth < usize::BITS as u8, "depth = {} is too large for usize", depth);
    assert!(
        STORED_INTERNAL_LEVEL_START < depth as usize,
        "at least the root level must be stored"
    );

    let expected = 1usize << (depth as usize - 1);
    assert_eq!(leaf_parents.len(), expected, "leaf parent count must match 2^(depth - 1)");

    let mut levels = Vec::with_capacity(depth as usize - STORED_INTERNAL_LEVEL_START);
    let mut current = leaf_parents;

    for level in 0..depth as usize {
        if level >= STORED_INTERNAL_LEVEL_START {
            levels.push(current);
            if level + 1 == depth as usize {
                break;
            }
            let stored_level_idx = levels.len() - 1;
            current = parent_level(&levels[stored_level_idx]);
        } else {
            current = parent_level(&current);
        }
    }

    debug_assert_eq!(levels.last().expect("root level").len(), 1);
    levels
}

#[cfg(feature = "std")]
fn parent_level(current: &[Word]) -> Vec<Word> {
    current
        .par_chunks_exact(2)
        .map(|pair| Poseidon2::merge(&[pair[0], pair[1]]))
        .collect()
}

#[cfg(not(feature = "std"))]
fn parent_level(current: &[Word]) -> Vec<Word> {
    let mut parents = Vec::with_capacity(current.len() / 2);
    for pair in current.chunks_exact(2) {
        parents.push(Poseidon2::merge(&[pair[0], pair[1]]));
    }
    parents
}

fn empty_leaf_hash() -> Word {
    Poseidon2::hash_elements(&[Felt::ZERO; FELTS_PER_MERKLE_ENTRY])
}

/// Selects the `JOINT_WINDOW_POSITIONS` entries the verifier will look up given the scalars
/// `(u_1, u_2)`, in window order, and concatenates them into a flat `Vec<Felt>` of
/// `JOINT_WINDOW_POSITIONS * FELTS_PER_MERKLE_ENTRY` felts ready to be
/// pushed onto the advice stack.
///
/// Both scalars must satisfy `u_x < 2^256` (canonical scalar bound). The verifier processes
/// 32 byte windows from the LSB end of each scalar; the host must mirror that order so the
/// verifier consumes the entry for the correct window.
pub fn entries_in_window_order(padded_entries: &[Felt], u_1: &BigUint, u_2: &BigUint) -> Vec<Felt> {
    assert_eq!(padded_entries.len(), MERKLE_LEAF_COUNT * FELTS_PER_MERKLE_ENTRY);
    assert!(u_1.bits() <= 256, "u_1 must satisfy u_1 < 2^256, got {} bits", u_1.bits());
    assert!(u_2.bits() <= 256, "u_2 must satisfy u_2 < 2^256, got {} bits", u_2.bits());
    let mut out = Vec::with_capacity(JOINT_WINDOW_POSITIONS * FELTS_PER_MERKLE_ENTRY);
    for leaf_idx in selected_leaf_indices(u_1, u_2) {
        let base = leaf_idx * FELTS_PER_MERKLE_ENTRY;
        out.extend_from_slice(&padded_entries[base..base + FELTS_PER_MERKLE_ENTRY]);
    }
    debug_assert_eq!(out.len(), JOINT_WINDOW_POSITIONS * FELTS_PER_MERKLE_ENTRY);
    out
}

fn selected_leaf_indices(u_1: &BigUint, u_2: &BigUint) -> Vec<usize> {
    assert!(u_1.bits() <= 256, "u_1 must satisfy u_1 < 2^256, got {} bits", u_1.bits());
    assert!(u_2.bits() <= 256, "u_2 must satisfy u_2 < 2^256, got {} bits", u_2.bits());

    let mut indices = Vec::with_capacity(JOINT_WINDOW_POSITIONS);
    let mask = BigUint::from((ENTRIES_PER_AXIS - 1) as u32);
    for p in 0..JOINT_WINDOW_POSITIONS {
        let shift = WINDOW_WIDTH * p;
        let i = window_digit(u_1, shift, &mask);
        let j = window_digit(u_2, shift, &mask);
        indices.push(p * ENTRIES_PER_BLOCK + i * ENTRIES_PER_AXIS + j);
    }
    indices
}

fn window_digit(scalar: &BigUint, shift: usize, mask: &BigUint) -> usize {
    ((scalar >> shift) & mask).to_u32_digits().first().copied().unwrap_or(0) as usize
}

// CURVE ARITHMETIC
// ================================================================================================

/// Affine point doubling on secp256k1. `Y^2 = X^3 + 7`, so `lambda = 3 * X^2 / (2 * Y)`.
fn affine_double(p: &AffinePoint, prime: &BigUint) -> AffinePoint {
    if p.is_infinity || p.y.is_zero() {
        return AffinePoint::infinity();
    }
    let three_x2 = (&p.x * &p.x * 3u32) % prime;
    let two_y = (&p.y * 2u32) % prime;
    let inv_two_y = modinv(&two_y, prime);
    let m = (&three_x2 * &inv_two_y) % prime;

    let m2 = (&m * &m) % prime;
    let two_x = (&p.x * 2u32) % prime;
    let x3 = sub_mod(&m2, &two_x, prime);

    let diff = sub_mod(&p.x, &x3, prime);
    let prod = (&m * &diff) % prime;
    let y3 = sub_mod(&prod, &p.y, prime);

    AffinePoint::finite(x3, y3)
}

/// Affine point addition with the standard +/-P / identity case handling.
fn affine_add(a: &AffinePoint, b: &AffinePoint, prime: &BigUint) -> AffinePoint {
    if a.is_infinity {
        return b.clone();
    }
    if b.is_infinity {
        return a.clone();
    }
    if a.x == b.x {
        if a.y == b.y {
            return affine_double(a, prime);
        }
        return AffinePoint::infinity();
    }
    let num = sub_mod(&b.y, &a.y, prime);
    let den = sub_mod(&b.x, &a.x, prime);
    let inv_den = modinv(&den, prime);
    let m = (num * inv_den) % prime;

    let m2 = (&m * &m) % prime;
    let x3 = sub_mod(&sub_mod(&m2, &a.x, prime), &b.x, prime);
    let diff = sub_mod(&a.x, &x3, prime);
    let prod = (&m * &diff) % prime;
    let y3 = sub_mod(&prod, &a.y, prime);
    AffinePoint::finite(x3, y3)
}

fn sub_mod(a: &BigUint, b: &BigUint, prime: &BigUint) -> BigUint {
    if a >= b {
        (a - b) % prime
    } else {
        (prime - ((b - a) % prime)) % prime
    }
}

/// Modular inverse via Fermat's little theorem. Asserts `a != 0`.
fn modinv(a: &BigUint, prime: &BigUint) -> BigUint {
    assert!(!a.is_zero(), "modular inverse of zero");
    a.modpow(&(prime - 2u32), prime)
}

/// Computes modular inverses of all input values via Montgomery's trick: one Fermat
/// inversion plus `3 * N` modular multiplications. All inputs must be non-zero.
fn batch_modinv(vals: &[BigUint], prime: &BigUint) -> Vec<BigUint> {
    let n = vals.len();
    if n == 0 {
        return Vec::new();
    }

    // Forward pass: prods[i] = vals[0] * ... * vals[i] mod p.
    let mut prods = Vec::with_capacity(n);
    prods.push(vals[0].clone());
    for v in &vals[1..] {
        let last = prods.last().expect("non-empty");
        prods.push((last * v) % prime);
    }

    // One Fermat inversion of the total product.
    let mut acc_inv = modinv(prods.last().expect("non-empty"), prime);

    // Backward pass: walk from the end, peeling off the latest val to recover its inverse.
    let mut inverses = vec![BigUint::zero(); n];
    for i in (1..n).rev() {
        inverses[i] = (&acc_inv * &prods[i - 1]) % prime;
        acc_inv = (&acc_inv * &vals[i]) % prime;
    }
    inverses[0] = acc_inv;

    inverses
}

/// Batched affine addition over the cross-product `small_p1[i] + small_p2[j]` for all
/// `(i, j)` pairs, returned in row-major order with `j` inner. Per-pair denominators are
/// inverted in a single batch via Montgomery's trick. Degenerate pairs (identity inputs,
/// equal points, opposite points) are handled per-pair without contributing to the batch.
fn batch_affine_add_pairs(
    small_p1: &[AffinePoint],
    small_p2: &[AffinePoint],
    prime: &BigUint,
) -> Vec<AffinePoint> {
    enum PairCase {
        AInfinity,
        BInfinity,
        Opposite,
        Equal,
        Generic { inv_idx: usize, num: BigUint },
    }

    let total = small_p1.len() * small_p2.len();
    let mut cases: Vec<PairCase> = Vec::with_capacity(total);
    let mut denominators: Vec<BigUint> = Vec::new();

    for a in small_p1 {
        for b in small_p2 {
            if a.is_infinity {
                cases.push(PairCase::AInfinity);
            } else if b.is_infinity {
                cases.push(PairCase::BInfinity);
            } else if a.x == b.x {
                if a.y == b.y {
                    cases.push(PairCase::Equal);
                } else {
                    cases.push(PairCase::Opposite);
                }
            } else {
                let num = sub_mod(&b.y, &a.y, prime);
                let den = sub_mod(&b.x, &a.x, prime);
                let inv_idx = denominators.len();
                denominators.push(den);
                cases.push(PairCase::Generic { inv_idx, num });
            }
        }
    }

    let inverses = batch_modinv(&denominators, prime);

    let n2 = small_p2.len();
    let mut results = Vec::with_capacity(total);
    for (idx, case) in cases.into_iter().enumerate() {
        let i = idx / n2;
        let j = idx % n2;
        let a = &small_p1[i];
        let b = &small_p2[j];
        let result = match case {
            PairCase::AInfinity => b.clone(),
            PairCase::BInfinity => a.clone(),
            PairCase::Opposite => AffinePoint::infinity(),
            PairCase::Equal => affine_double(a, prime),
            PairCase::Generic { inv_idx, num } => {
                let m = (num * &inverses[inv_idx]) % prime;
                let m2 = (&m * &m) % prime;
                let x3 = sub_mod(&sub_mod(&m2, &a.x, prime), &b.x, prime);
                let diff = sub_mod(&a.x, &x3, prime);
                let prod = (&m * &diff) % prime;
                let y3 = sub_mod(&prod, &a.y, prime);
                AffinePoint::finite(x3, y3)
            },
        };
        results.push(result);
    }

    results
}

// SERIALIZATION
// ================================================================================================

fn u256_to_u32_array(value: &BigUint) -> [u32; 8] {
    assert!(value.bits() <= 256, "value must fit in 256 bits, got {} bits", value.bits());
    let mut digits = value.to_u32_digits();
    digits.resize(8, 0);
    digits.try_into().expect("resized to 8 limbs")
}

#[cfg(feature = "std")]
fn biguint_to_be32(value: &BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    assert!(bytes.len() <= 32, "coordinate must fit in 32 bytes");
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

#[cfg(feature = "std")]
fn be32_to_u32_le(bytes: &[u8]) -> [u32; 8] {
    assert_eq!(bytes.len(), 32);
    let mut out = [0u32; 8];
    for (idx, slot) in out.iter_mut().enumerate() {
        let start = 32 - 4 * (idx + 1);
        *slot = u32::from_be_bytes(bytes[start..start + 4].try_into().unwrap());
    }
    out
}

#[cfg(feature = "std")]
fn u32_le_to_be32(limbs: &[u32]) -> [u8; 32] {
    assert_eq!(limbs.len(), 8);
    let mut out = [0u8; 32];
    for (idx, &limb) in limbs.iter().enumerate() {
        let start = 32 - 4 * (idx + 1);
        out[start..start + 4].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

// CONSTANT BIGNUMS
// ================================================================================================

fn base_prime() -> BigUint {
    BigUint::from_slice(&SECP256K1_BASE_PRIME_U32)
}

// UNIT TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn generator() -> AffinePoint {
        AffinePoint::finite(
            BigUint::parse_bytes(
                b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                16,
            )
            .unwrap(),
            BigUint::parse_bytes(
                b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
                16,
            )
            .unwrap(),
        )
    }

    fn scalar_mul(p: &AffinePoint, k: &BigUint, prime: &BigUint) -> AffinePoint {
        let mut acc = AffinePoint::infinity();
        for i in (0..k.bits()).rev() {
            acc = affine_double(&acc, prime);
            if k.bit(i) {
                acc = affine_add(&acc, p, prime);
            }
        }
        acc
    }

    fn read_point_at(felts: &[Felt], offset: usize) -> AffinePoint {
        let mut x_digits = [0u32; 8];
        let mut y_digits = [0u32; 8];
        for i in 0..8 {
            x_digits[i] = felts[offset + i].as_canonical_u64() as u32;
            y_digits[i] = felts[offset + 8 + i].as_canonical_u64() as u32;
        }
        let is_infinity = felts[offset + 16].as_canonical_u64() == 1;
        AffinePoint {
            x: BigUint::from_slice(&x_digits),
            y: BigUint::from_slice(&y_digits),
            is_infinity,
        }
    }

    /// The joint table has the expected total length.
    #[test]
    fn joint_table_has_correct_size() {
        let g = generator();
        let prime = base_prime();
        let q = scalar_mul(&g, &BigUint::from(7u32), &prime);
        let table = joint_comb_table(&g, &q);
        assert_eq!(table.len(), JOINT_TABLE_FELTS);
        assert_eq!(table.len(), JOINT_WINDOW_POSITIONS * ENTRIES_PER_BLOCK * FELTS_PER_ENTRY);
    }

    /// Reconstruct a full 256-bit-scalar joint mult `[u_1] * G + [u_2] * Q` by summing the
    /// per-window block entries and compare against direct scalar mult.
    #[test]
    fn joint_table_reconstructs_full_256_bit_mult() {
        let g = generator();
        let prime = base_prime();
        let q = scalar_mul(&g, &BigUint::from(7u32), &prime);

        let u_1 = BigUint::parse_bytes(
            b"5e3a1b3a8c00c5d6c0a4afde7f8e0c5b9a2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e",
            16,
        )
        .unwrap();
        let u_2 = BigUint::parse_bytes(
            b"7f8e9d0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8e9d0a1b2c3d4e5f6a7b8c",
            16,
        )
        .unwrap();
        let bound = BigUint::from(1u32) << 256;
        assert!(u_1 < bound && u_2 < bound);

        let table = joint_comb_table(&g, &q);
        let mask = BigUint::from((ENTRIES_PER_AXIS - 1) as u32);
        let mut acc = AffinePoint::infinity();
        for p in 0..JOINT_WINDOW_POSITIONS {
            let shift = WINDOW_WIDTH * p;
            let i =
                ((&u_1 >> shift) & &mask).to_u32_digits().first().copied().unwrap_or(0) as usize;
            let j =
                ((&u_2 >> shift) & &mask).to_u32_digits().first().copied().unwrap_or(0) as usize;
            let block_offset = p * ENTRIES_PER_BLOCK * FELTS_PER_ENTRY;
            let entry_offset = block_offset + (i * ENTRIES_PER_AXIS + j) * FELTS_PER_ENTRY;
            let entry = read_point_at(&table, entry_offset);
            acc = affine_add(&acc, &entry, &prime);
        }

        let direct_g = scalar_mul(&g, &u_1, &prime);
        let direct_q = scalar_mul(&q, &u_2, &prime);
        let expected = affine_add(&direct_g, &direct_q, &prime);
        assert_eq!(acc.x, expected.x);
        assert_eq!(acc.y, expected.y);
        assert!(!acc.is_infinity);
    }

    /// `build_left_aligned_padded_tree` agrees with the naive `MerkleTree::new` baseline
    /// for several `(depth, real_count)` configurations, including the fully-empty edge
    /// case. The naive baseline materializes all `2^depth` leaves and merges every level;
    /// the optimized builder skips the all-empty subtrees by reusing the precomputed
    /// `empty_subtree[h]` values.
    ///
    /// Checks both the root AND that the returned `inner_nodes`, when loaded into a
    /// `MerkleStore`, can actually serve every path in the real range -- so a builder bug
    /// that produced the right root with an incomplete inner-node set would still fail.
    #[test]
    fn empty_subtree_aware_builder_matches_naive_merkle_tree() {
        use miden_core::crypto::merkle::{MerkleStore, MerkleTree, NodeIndex};

        let empty_leaf = Poseidon2::hash_elements(&[Felt::from_u32(0); FELTS_PER_MERKLE_ENTRY]);

        // Stand-in real leaves that aren't equal to empty_leaf, so the optimized and naive
        // tree shapes differ in every bit position.
        let make_real_leaves = |n: usize| -> Vec<Word> {
            (0..n)
                .map(|i| {
                    let pad = [Felt::from_u32(i as u32 + 1); FELTS_PER_MERKLE_ENTRY];
                    Poseidon2::hash_elements(&pad)
                })
                .collect()
        };

        // Cover: empty (0 real), single real, perfectly-balanced left subtree, mid-tree
        // boundary, fully-populated. Depths kept small so the naive build stays cheap.
        let configs: &[(u8, usize)] = &[
            (4, 0),   // fully empty
            (4, 1),   // odd-pair-with-empty all the way up
            (4, 8),   // exact left-half subtree
            (4, 10),  // mid-boundary in the right half
            (4, 16),  // fully populated
            (6, 23),  // wider tree, asymmetric boundary
            (8, 100), // wider yet
        ];

        for &(depth, real_count) in configs {
            let real_leaves = make_real_leaves(real_count);

            // Naive baseline: pad to 2^depth with empty_leaf and call MerkleTree::new.
            let mut padded = real_leaves.clone();
            padded.resize(1usize << depth, empty_leaf);
            let baseline = MerkleTree::new(&padded).expect("padded leaves form a valid tree");

            let (root, nodes) = build_left_aligned_padded_tree(&real_leaves, depth, empty_leaf);

            assert_eq!(
                root,
                (*baseline.root()).into(),
                "root mismatch for depth={depth}, real_count={real_count}"
            );

            // Path-query check: the `inner_nodes` set should be sufficient to recover the
            // value of every leaf in the real range under the produced root.
            let mut store = MerkleStore::new();
            store.extend(nodes);
            for (leaf_idx, &expected) in real_leaves.iter().enumerate().take(real_count) {
                let value = store
                    .get_node(root, NodeIndex::new(depth, leaf_idx as u64).expect("valid index"))
                    .unwrap_or_else(|err| {
                        panic!(
                            "path query failed for depth={depth}, real_count={real_count}, \
                             leaf_idx={leaf_idx}: {err}"
                        )
                    });
                assert_eq!(
                    value, expected,
                    "wrong leaf value for depth={depth}, real_count={real_count}, \
                     leaf_idx={leaf_idx}"
                );
            }
        }
    }

    /// The empty-subtree root computed inside `build_left_aligned_padded_tree` (returned as
    /// `inner_nodes` entries) matches the iteratively-merged `empty_subtree[h]` value for
    /// every height. Sanity check that the canonical empty-tree root is what we think it is.
    #[test]
    fn empty_subtree_roots_match_iterative_self_merge() {
        let empty_leaf = Poseidon2::hash_elements(&[Felt::from_u32(0); FELTS_PER_MERKLE_ENTRY]);
        let depth = MERKLE_TREE_DEPTH;

        let mut expected = vec![empty_leaf];
        for _ in 0..depth as usize {
            let last = *expected.last().expect("non-empty");
            expected.push(Poseidon2::merge(&[last, last]));
        }

        let (root, nodes) = build_left_aligned_padded_tree(&[], depth, empty_leaf);
        assert_eq!(root, expected[depth as usize], "fully-empty tree root");

        // Each height should be present exactly once in the inner-node list, mapped to
        // its self-merge children.
        for h in 1..=depth as usize {
            let entry = nodes
                .iter()
                .find(|n| n.value == expected[h])
                .unwrap_or_else(|| panic!("missing empty-subtree inner node at height {h}"));
            assert_eq!(entry.left, expected[h - 1], "wrong left child at height {h}");
            assert_eq!(entry.right, expected[h - 1], "wrong right child at height {h}");
        }
    }

    #[test]
    fn precomputed_cache_matches_legacy_padded_entries() {
        use miden_core::crypto::merkle::{MerkleStore, NodeIndex};

        let g = generator();
        let prime = base_prime();
        let q = scalar_mul(&g, &BigUint::from(7u32), &prime);

        let cache = PrecomputedK1PubKey::new(&g, &q);

        let legacy_entries = joint_comb_padded_entries(&g, &q);
        let legacy_leaves = merkle_leaf_hashes(&legacy_entries);
        let empty_leaf = Poseidon2::hash_elements(&[Felt::ZERO; FELTS_PER_MERKLE_ENTRY]);
        let (legacy_root, _) =
            build_left_aligned_padded_tree(&legacy_leaves, MERKLE_TREE_DEPTH, empty_leaf);
        assert_eq!(Word::new(cache.merkle_root()), legacy_root);

        let u_1 = BigUint::parse_bytes(b"123456789abcdef123456789abcdef", 16).unwrap();
        let u_2 = BigUint::parse_bytes(b"fedcba9876543210fedcba9876543210", 16).unwrap();
        assert_eq!(
            cache.entries_in_window_order(&u_1, &u_2),
            entries_in_window_order(&legacy_entries, &u_1, &u_2)
        );

        let sparse_store = cache.merkle_store_for_windows(&u_1, &u_2);
        let full_store: MerkleStore =
            build_left_aligned_padded_tree(&legacy_leaves, MERKLE_TREE_DEPTH, empty_leaf)
                .1
                .into_iter()
                .collect();

        for leaf_idx in selected_leaf_indices(&u_1, &u_2) {
            let index = NodeIndex::new(MERKLE_TREE_DEPTH, leaf_idx as u64).expect("valid index");
            let sparse_leaf = sparse_store.get_node(legacy_root, index).expect("sparse path opens");
            let full_leaf = full_store.get_node(legacy_root, index).expect("full store opens");
            assert_eq!(sparse_leaf, full_leaf);
        }
    }

    /// Times the one-time per-PK cache build. Run with
    /// `cargo test --release ... full_per_pk_build_timing -- --ignored --nocapture`.
    #[test]
    #[ignore = "benchmark; run with --ignored to print timings"]
    fn full_per_pk_build_timing() {
        use std::{eprintln, time::Instant};

        let g = generator();
        let prime = base_prime();
        let q = scalar_mul(&g, &BigUint::from(0x9f2815b1u32), &prime);

        let t0 = Instant::now();
        let (axis_p1, axis_p2, leaf_parents) = comb_axes_and_leaf_parents(&g, &q);
        let t_comb = t0.elapsed();

        let merkle_internal_levels =
            build_internal_levels_from_leaf_parents(leaf_parents, MERKLE_TREE_DEPTH);
        let t_cache = t0.elapsed();

        let cache = PrecomputedK1PubKey { axis_p1, axis_p2, merkle_internal_levels };
        let u_1 = BigUint::parse_bytes(b"123456789abcdef123456789abcdef", 16).unwrap();
        let u_2 = BigUint::parse_bytes(b"fedcba9876543210fedcba9876543210", 16).unwrap();
        let t_advice = Instant::now();
        let _ = cache.advice_for_windows(&u_1, &u_2);
        let advice = t_advice.elapsed();

        eprintln!("per-PK build timing (release mode):");
        eprintln!("  comb + leaf parents      : {:?}", t_comb);
        eprintln!("  upper Merkle levels      : {:?}", t_cache - t_comb);
        eprintln!("  cache build total        : {:?}", t_cache);
        eprintln!("  advice for one signature : {:?}", advice);
        let axis_bytes = (cache.axis_p1.len() + cache.axis_p2.len())
            * U32S_PER_COMPACT_ENTRY
            * core::mem::size_of::<u32>();
        let internal_level_bytes = cache
            .merkle_internal_levels
            .iter()
            .map(|level| level.len() * core::mem::size_of::<Word>())
            .sum::<usize>();
        eprintln!("  compact axis tables (bytes): {axis_bytes}");
        eprintln!("  internal levels (bytes): {internal_level_bytes}");
        eprintln!("  persistent cache (bytes): {}", axis_bytes + internal_level_bytes);
    }
}
