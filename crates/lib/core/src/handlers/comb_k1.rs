//! Off-VM precomputation of the joint 2D comb-style scalar-mult lookup table for a pair of
//! secp256k1 points. Produces the data the host needs to populate `AdviceInputs` for the
//! precomputation-based ECDSA verifier (`ecdsa_k256_keccak::verify_prehash_native_precomp`):
//! the table itself, the per-leaf Poseidon2 hashes, the Merkle tree's `InnerNodeInfo`
//! records for the `MerkleStore`, and a per-signature selector that returns the 43 window
//! entries the verifier consumes off the advice stack.
//!
//! Intended lifecycle. The table and Merkle tree are expensive to build (~176K Poseidon2
//! hashes for the leaves plus the same order again for the internal nodes) but depend
//! only on the base points `(G, Q)`. They are meant to be built once per public key `Q`
//! and cached across every signature verified under that PK. Per signature, the only host
//! work is `entries_in_window_order` (43 indexed lookups into the cached padded-entries
//! vector) plus pushing the result onto the advice stack; the cached `MerkleStore` is
//! supplied as-is.
//!
//! Background: comb tables. A comb table is a precomputed lookup that lets a verifier
//! compute a scalar multiplication `k * P` without running the textbook 256-step double-
//! and-add. The scalar `k` is split into fixed-width windows -- here 43 windows of 6 bits
//! each -- and the table stores `[d * 2^(w*b)] * P` for every window position `b` and
//! every possible window digit `d` in `0..2^w`. At verification time, the driver reads
//! one table entry per window position and accumulates them; this replaces the 256
//! doublings of double-and-add with 43 host-supplied table lookups plus 43 additions.
//! The "comb" name comes from the per-window bit pattern resembling comb teeth across the
//! scalar.
//!
//! "Joint" extends the construction to two base points `(P_1, P_2)` that share the same
//! window schedule: a single entry at `(b, i, j)` holds
//!     [i * 64^b] * P_1 + [j * 64^b] * P_2
//! so a double scalar mult like ECDSA's `R = u_1*G + u_2*Q` reads one entry per window
//! instead of two and contributes one addition per window instead of two. Cost: the table
//! grows from `43 * 64 = 2,752` single-point entries to `43 * 4,096 = 176,128` joint
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
//! mechanic at the actual `w = 6` over 256-bit scalars gives 43 lookups + 43 adds with the
//! doubling chain absorbed entirely into the precomputed table.
//!
//! Layout. The table holds `JOINT_WINDOW_POSITIONS = 43` blocks at width `w = 6`. Block
//! `b` covers windows that select bits `[w*b, w*(b+1))` of the two 256-bit scalars; within
//! block `b`, the entry at index `(i, j)` for `i, j` in `0..2^w` stores
//!     `entry[b][i][j] = [i * 64^b] * P_1 + [j * 64^b] * P_2`
//! Each entry occupies 20 felts (`X[8]` + `Y[8]` + `is_infinity[1]` + 3 reserved zero felts). The
//! high block (`b = 42`) covers bits 252..258; for any canonical scalar `< 2^256` only the
//! low 4 bits of that block's index are reachable, so the unreachable 75% of block 42 is
//! materialized but never queried.

use alloc::{vec, vec::Vec};

use miden_core::{
    Felt, Word,
    crypto::{hash::Poseidon2, merkle::InnerNodeInfo},
};
use num::{Zero, bigint::BigUint};

use crate::handlers::secp256k1_constants::SECP256K1_BASE_PRIME_U32;

/// Comb window width. Each window selects 6 bits, so each block of the table is indexed by
/// a pair of 6-bit values, giving 4,096 entries per block.
pub const WINDOW_WIDTH: usize = 6;

/// `2^WINDOW_WIDTH`: the number of distinct values a single window can take.
pub const ENTRIES_PER_AXIS: usize = 1 << WINDOW_WIDTH;

/// Number of `(i, j)` pairs per block.
pub const ENTRIES_PER_BLOCK: usize = ENTRIES_PER_AXIS * ENTRIES_PER_AXIS;

/// Felt count for one stored point: 8 for X, 8 for Y, 1 for is_infinity, 3 reserved zeros.
pub const FELTS_PER_ENTRY: usize = 20;

/// Number of window blocks for a joint comb table over a pair of 256-bit scalars at width
/// `WINDOW_WIDTH`. Each scalar is 256 bits; `ceil(256 / 6) = 43` blocks cover all the bits
/// (the high block's index covers bits 252..258, with bits 256-258 implicitly zero for any
/// canonical scalar < 2^256).
pub const JOINT_WINDOW_POSITIONS: usize = 256_usize.div_ceil(WINDOW_WIDTH);

/// Total joint-table size in felts: 43 * 4096 * 20 = 3,522,560.
pub const JOINT_TABLE_FELTS: usize = JOINT_WINDOW_POSITIONS * ENTRIES_PER_BLOCK * FELTS_PER_ENTRY;

/// Felt count for one Merkle-tree leaf entry: the 20-felt point representation padded with
/// 4 zeros to align to 24 felts.
pub const FELTS_PER_MERKLE_ENTRY: usize = 24;

/// Number of leaves in the Merkle tree commitment over the joint comb table. One leaf per
/// table entry: 43 blocks * 4,096 entries = 176,128. Not a power of two; the host's tree
/// construction pads up to the next power of two (`2^MERKLE_TREE_DEPTH = 262,144`) with a
/// fixed empty-leaf digest.
pub const MERKLE_LEAF_COUNT: usize = JOINT_WINDOW_POSITIONS * ENTRIES_PER_BLOCK;

/// Depth of the Merkle tree committing to the comb table. `2^18 = 262,144` is the next
/// power of two strictly above `MERKLE_LEAF_COUNT = 176,128`.
pub const MERKLE_TREE_DEPTH: u8 = 18;

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

/// Builds a 2D comb table for a pair of secp256k1 base points `(p1, p2)`, suitable for the
/// joint scalar mult `[u_1] * p1 + [u_2] * p2` over 256-bit scalars `u_1`, `u_2`. Layout:
/// 43 contiguous blocks of 4,096 entries * 20 felts; entry `(i, j)` in block `b` is
/// `[i * 64^b] * p1 + [j * 64^b] * p2`.
///
/// The per-block cross-product step (4,096 affine additions) is computed with a single
/// Montgomery-batched modular inversion in place of 4,096 Fermat inversions.
pub fn joint_comb_table(p1: &AffinePoint, p2: &AffinePoint) -> Vec<Felt> {
    let prime = base_prime();

    let mut out = Vec::with_capacity(JOINT_TABLE_FELTS);

    let mut shift_p1 = p1.clone();
    let mut shift_p2 = p2.clone();

    for _pos in 0..JOINT_WINDOW_POSITIONS {
        let mut small_p1 = Vec::with_capacity(ENTRIES_PER_AXIS);
        let mut small_p2 = Vec::with_capacity(ENTRIES_PER_AXIS);
        small_p1.push(AffinePoint::infinity());
        small_p2.push(AffinePoint::infinity());
        for k in 1..ENTRIES_PER_AXIS {
            small_p1.push(affine_add(&small_p1[k - 1], &shift_p1, &prime));
            small_p2.push(affine_add(&small_p2[k - 1], &shift_p2, &prime));
        }

        for entry in batch_affine_add_pairs(&small_p1, &small_p2, &prime) {
            push_point_as_felts(&mut out, &entry);
        }

        for _ in 0..WINDOW_WIDTH {
            shift_p1 = affine_double(&shift_p1, &prime);
            shift_p2 = affine_double(&shift_p2, &prime);
        }
    }

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
pub fn joint_comb_padded_entries(p1: &AffinePoint, p2: &AffinePoint) -> Vec<Felt> {
    let table = joint_comb_table(p1, p2);
    let mut out = Vec::with_capacity(MERKLE_LEAF_COUNT * FELTS_PER_MERKLE_ENTRY);
    for entry_idx in 0..MERKLE_LEAF_COUNT {
        let base = entry_idx * FELTS_PER_ENTRY;
        out.extend_from_slice(&table[base..base + FELTS_PER_ENTRY]);
        for _ in FELTS_PER_ENTRY..FELTS_PER_MERKLE_ENTRY {
            out.push(Felt::from_u32(0));
        }
    }
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

/// Selects the `JOINT_WINDOW_POSITIONS` entries the verifier will look up given the scalars
/// `(u_1, u_2)`, in window order, and concatenates them into a flat `Vec<Felt>` of
/// `JOINT_WINDOW_POSITIONS * FELTS_PER_MERKLE_ENTRY = 43 * 24 = 1,032` felts ready to be
/// pushed onto the advice stack.
///
/// Both scalars must satisfy `u_x < 2^256` (canonical scalar bound). The on-VM driver
/// substitutes a synthetic zero limb when its next-limb index reaches 8, so non-canonical
/// scalars would desynchronise the host-side window selection from the verifier's. The
/// verifier processes windows from the LSB end of each scalar; the host must mirror that
/// order so each `adv_pushw` in the driver pulls the entry for the correct window.
pub fn entries_in_window_order(padded_entries: &[Felt], u_1: &BigUint, u_2: &BigUint) -> Vec<Felt> {
    assert_eq!(padded_entries.len(), MERKLE_LEAF_COUNT * FELTS_PER_MERKLE_ENTRY);
    assert!(u_1.bits() <= 256, "u_1 must satisfy u_1 < 2^256, got {} bits", u_1.bits());
    assert!(u_2.bits() <= 256, "u_2 must satisfy u_2 < 2^256, got {} bits", u_2.bits());
    let mut out = Vec::with_capacity(JOINT_WINDOW_POSITIONS * FELTS_PER_MERKLE_ENTRY);
    let mask = BigUint::from((ENTRIES_PER_AXIS - 1) as u32);
    for p in 0..JOINT_WINDOW_POSITIONS {
        let shift = WINDOW_WIDTH * p;
        let i = window_digit(u_1, shift, &mask);
        let j = window_digit(u_2, shift, &mask);
        let leaf_idx = p * ENTRIES_PER_BLOCK + i * ENTRIES_PER_AXIS + j;
        let base = leaf_idx * FELTS_PER_MERKLE_ENTRY;
        out.extend_from_slice(&padded_entries[base..base + FELTS_PER_MERKLE_ENTRY]);
    }
    debug_assert_eq!(out.len(), JOINT_WINDOW_POSITIONS * FELTS_PER_MERKLE_ENTRY);
    out
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

fn push_point_as_felts(out: &mut Vec<Felt>, p: &AffinePoint) {
    push_u256_as_felts(out, &p.x);
    push_u256_as_felts(out, &p.y);
    out.push(if p.is_infinity {
        Felt::from_u32(1)
    } else {
        Felt::from_u32(0)
    });
    // Three reserved zero felts to round to a 5-word boundary.
    out.push(Felt::from_u32(0));
    out.push(Felt::from_u32(0));
    out.push(Felt::from_u32(0));
}

fn push_u256_as_felts(out: &mut Vec<Felt>, value: &BigUint) {
    assert!(value.bits() <= 256, "value must fit in 256 bits, got {} bits", value.bits());
    let mut digits = value.to_u32_digits();
    digits.resize(8, 0);
    for d in digits {
        out.push(Felt::from_u32(d));
    }
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

    /// The joint table has the expected total length (43 blocks * 4,096 entries * 20 felts).
    #[test]
    fn joint_table_has_correct_size() {
        let g = generator();
        let prime = base_prime();
        let q = scalar_mul(&g, &BigUint::from(7u32), &prime);
        let table = joint_comb_table(&g, &q);
        assert_eq!(table.len(), JOINT_TABLE_FELTS);
        assert_eq!(table.len(), 43 * 4096 * 20);
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
            store.extend(nodes.into_iter());
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
        let depth = 18u8;

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

    /// Times the one-time per-PK build pipeline: comb table -> padded entries -> per-leaf
    /// Poseidon2 hashes -> left-aligned padded tree. Run with
    /// `cargo test --release ... full_per_pk_build_timing -- --ignored --nocapture`.
    #[test]
    #[ignore = "benchmark; run with --ignored to print timings"]
    fn full_per_pk_build_timing() {
        use std::{eprintln, time::Instant};

        let g = generator();
        let prime = base_prime();
        let q = scalar_mul(&g, &BigUint::from(0x9f2815b1u32), &prime);

        let t0 = Instant::now();
        let entries = joint_comb_padded_entries(&g, &q);
        let t_entries = t0.elapsed();

        let t1 = Instant::now();
        let leaves = merkle_leaf_hashes(&entries);
        let t_leaves = t1.elapsed();

        let t2 = Instant::now();
        let empty_leaf = Poseidon2::hash_elements(&[Felt::ZERO; FELTS_PER_MERKLE_ENTRY]);
        let (_root, _inner) =
            build_left_aligned_padded_tree(&leaves, MERKLE_TREE_DEPTH, empty_leaf);
        let t_tree = t2.elapsed();

        let total = t0.elapsed();
        eprintln!("per-PK build timing (release mode):");
        eprintln!("  joint_comb_padded_entries : {:?}", t_entries);
        eprintln!("  merkle_leaf_hashes        : {:?}", t_leaves);
        eprintln!("  build_left_aligned_tree   : {:?}", t_tree);
        eprintln!("  total                     : {:?}", total);
        eprintln!(
            "  padded-entries size (bytes)   : {}",
            entries.len() * core::mem::size_of::<Felt>()
        );
    }
}
