//! Tests for the Keccak-node chiplet.
//!
//! Layout / [`LiftedAir`] structural smoke checks +
//! trace-driven constraint checks across single- and multi-invocation
//! traces (verifying boundary anchors + per-namespace continuity).
//! Negative tests confirm `check_constraints` catches deliberate
//! corruption of the activity flag, boundary, and continuity edges.

use std::vec;

use miden_core::{
    Felt,
    deferred::{Digest, Node},
    field::{Field, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{BaseAir, LiftedAir};
use miden_precompiles::Keccak256Precompile;
use rand::{RngExt, SeedableRng, rngs::StdRng};

use crate::{
    hash::{
        chunk::trace::ChunkSeqId,
        keccak::{
            node::{
                COL_ABSORPTION_ID_CHUNKS, COL_ABSORPTION_ID_DIGEST_CHUNKS,
                COL_ABSORPTION_ID_KECCAK, COL_ACT, COL_CHUNK_SEQ_ID_HEAD, COL_D_BEGIN,
                COL_H_DIGEST_CHUNKS_BEGIN, COL_H_INPUT_CHUNKS_BEGIN, COL_H_KECCAK_BEGIN,
                COL_LAST_CHUNK_REM, COL_LEN_BYTES, COL_N_CHUNKS, COL_N_CHUNKS_INV,
                COL_N_SPONGE_PERMS, COL_SPONGE_SEQ_ID_HEAD, KeccakNodeAir, NUM_AUX_COLS, NUM_HASH,
                NUM_MAIN_COLS,
                trace::{KeccakNodeInvocation, generate_trace_from_invocations},
            },
            sponge::trace::SpongeSeqId,
        },
    },
    logup::{NUM_LOGUP_VALUES, NUM_PUBLIC_VALUES, NUM_RANDOMNESS},
    transcript::eidos::trace::testing::forged_absorption_id,
};

// HELPERS
// ================================================================================================

fn check_with_invocations(_seed: u64, invocations: &[KeccakNodeInvocation]) {
    let main = generate_trace_from_invocations(invocations);
    crate::tests::check_local(KeccakNodeAir, &main);
}

/// Build a single-invocation example anchored at the row-0 origin. The
/// concrete `d` / `h_input_chunks` values are arbitrary — `check_constraints`
/// runs the AIR's local constraints plus the centered LogUp recurrence, both of
/// which are agnostic to the digest bytes (cross-chiplet content
/// consistency lives at the integration-test layer).
fn anchored_inv(seed: u64, len_bytes: u32) -> KeccakNodeInvocation {
    let mut rng = StdRng::seed_from_u64(seed);
    KeccakNodeInvocation {
        len_bytes,
        d: core::array::from_fn(|_| rng.random()),
        h_input_chunks: core::array::from_fn(|_| rng.random::<Felt>()),
        chunk_seq_id_head: ChunkSeqId::forged(0),
        absorption_id_chunks: forged_absorption_id(0),
        absorption_id_digest_chunks: forged_absorption_id(100),
        absorption_id_keccak: forged_absorption_id(101),
        sponge_seq_id_head: SpongeSeqId::forged(0),
        out_mult: 1,
    }
}

/// Append a follow-on invocation whose head columns satisfy the
/// orchestrator's continuity equations against `prev`. Eidos digest-chunks /
/// keccak cycles are free witnesses (the orchestrator's continuity
/// doesn't constrain them); we just pick fresh cycles per invocation.
fn next_inv(prev: &KeccakNodeInvocation, seed: u64, len_bytes: u32) -> KeccakNodeInvocation {
    let mut rng = StdRng::seed_from_u64(seed);
    KeccakNodeInvocation {
        len_bytes,
        d: core::array::from_fn(|_| rng.random()),
        h_input_chunks: core::array::from_fn(|_| rng.random::<Felt>()),
        chunk_seq_id_head: ChunkSeqId::forged(
            prev.chunk_seq_id_head.seq() + prev.n_chunks() as u32,
        ),
        absorption_id_chunks: forged_absorption_id(
            prev.absorption_id_chunks.as_u32() + prev.n_chunks() as u32,
        ),
        absorption_id_digest_chunks: forged_absorption_id(
            prev.absorption_id_digest_chunks.as_u32() + 1000,
        ),
        absorption_id_keccak: forged_absorption_id(prev.absorption_id_keccak.as_u32() + 1000),
        sponge_seq_id_head: SpongeSeqId::forged(
            prev.sponge_seq_id_head.seq() + 32 * prev.n_sponge_perms() as u32,
        ),
        out_mult: 1,
    }
}

fn single_node_trace(len_bytes: u32) -> RowMajorMatrix<Felt> {
    let main = generate_trace_from_invocations(&[anchored_inv(0x11, len_bytes)]);
    crate::tests::check_local(KeccakNodeAir, &main);
    main
}

/// `is_empty = 32·(n_chunks − 1) + remainder + 1 − len_bytes` of a node row.
fn is_empty(row: &[Felt]) -> Felt {
    Felt::from(32u8) * (row[COL_N_CHUNKS] - Felt::ONE) + row[COL_LAST_CHUNK_REM] + Felt::ONE
        - row[COL_LEN_BYTES]
}

/// Set a node row's chunk count, its inverse (zero for a zero count), and last-chunk remainder.
fn set_chunk_count(row: &mut [Felt], n_chunks: Felt, remainder: Felt) {
    row[COL_N_CHUNKS] = n_chunks;
    row[COL_N_CHUNKS_INV] = n_chunks.try_inverse().unwrap_or(Felt::ZERO);
    row[COL_LAST_CHUNK_REM] = remainder;
}

/// Recast a 32-byte node row as two chunks with remainder −1, which satisfies the length
/// equation. Returns the `Xor` byte-pair tuple the row then consumes.
pub(super) fn forge_out_of_range_remainder(row: &mut [Felt]) -> [Felt; 3] {
    assert_eq!(row[COL_LEN_BYTES], Felt::from(32u8));
    let remainder = -Felt::ONE;
    set_chunk_count(row, Felt::from(2u8), remainder);
    assert_eq!(is_empty(row), Felt::ZERO);
    [remainder, Felt::from(31u8) - remainder, Felt::from(31u8)]
}

// LAYOUT / STRUCTURAL
// ================================================================================================

#[test]
fn main_column_layout_partitions_32_indices() {
    use crate::hash::keccak::node::COL_OUT_MULT;
    assert_eq!(COL_ACT, 0);
    assert_eq!(COL_SPONGE_SEQ_ID_HEAD, 1);
    assert_eq!(COL_N_SPONGE_PERMS, 2);
    assert_eq!(COL_CHUNK_SEQ_ID_HEAD, 3);
    assert_eq!(COL_N_CHUNKS, 4);
    assert_eq!(COL_ABSORPTION_ID_CHUNKS, 5);
    assert_eq!(COL_LEN_BYTES, 6);
    assert_eq!(COL_ABSORPTION_ID_DIGEST_CHUNKS, 7);
    assert_eq!(COL_ABSORPTION_ID_KECCAK, 8);
    assert_eq!(COL_D_BEGIN, 9);
    assert_eq!(COL_H_INPUT_CHUNKS_BEGIN, 17);
    assert_eq!(COL_H_DIGEST_CHUNKS_BEGIN, 21);
    assert_eq!(COL_H_KECCAK_BEGIN, 25);
    assert_eq!(COL_OUT_MULT, 29);
    assert_eq!(COL_LAST_CHUNK_REM, 30);
    assert_eq!(COL_N_CHUNKS_INV, 31);
    assert_eq!(NUM_MAIN_COLS, 32);
    assert_eq!(<KeccakNodeAir as BaseAir<Felt>>::width(&KeccakNodeAir), NUM_MAIN_COLS,);
}

#[test]
fn lifted_air_validates_and_layout_matches_spec() {
    let air = KeccakNodeAir;
    let layout = <KeccakNodeAir as LiftedAir<Felt, QuadFelt>>::air_layout(&air);
    assert_eq!(layout.preprocessed_width, 0);
    assert_eq!(layout.main_width, NUM_MAIN_COLS);
    assert_eq!(layout.num_public_values, NUM_PUBLIC_VALUES);
    assert_eq!(layout.permutation_width, NUM_AUX_COLS);
    assert_eq!(layout.num_permutation_challenges, NUM_RANDOMNESS);
    assert_eq!(layout.num_permutation_values, NUM_LOGUP_VALUES);
    assert_eq!(layout.num_periodic_columns, 0);
}

#[test]
fn log_quotient_degree_matches_design_target() {
    // The nine-column packing leaves columns 0 and 8 as singletons and pairs the other fractions.
    // Every closing constraint therefore stays at degree ≤ 3 → log_quotient_degree = 1.
    let air = KeccakNodeAir;
    assert_eq!(crate::tests::log_quotient_degree(&air), 1);
}

// HASH ORACLES
// ================================================================================================

#[test]
fn generated_row_uses_vm_chunk_and_keccak_node_digests() {
    let inv = anchored_inv(0x33, 200);
    let main = generate_trace_from_invocations(core::slice::from_ref(&inv));

    let d_felts: [Felt; 8] = inv.d.map(Felt::from);
    let h_digest_chunks = Node::chunks(vec![d_felts])
        .expect("Keccak digest chunks are non-empty")
        .digest()
        .into_elements();
    let h_keccak = Keccak256Precompile::assert_node(
        inv.len_bytes,
        Digest::new(inv.h_input_chunks),
        Digest::new(h_digest_chunks),
    )
    .digest()
    .into_elements();

    let row_h_digest_chunks: [Felt; NUM_HASH] =
        core::array::from_fn(|i| main.values[COL_H_DIGEST_CHUNKS_BEGIN + i]);
    let row_h_keccak: [Felt; NUM_HASH] =
        core::array::from_fn(|i| main.values[COL_H_KECCAK_BEGIN + i]);
    assert_eq!(row_h_digest_chunks, h_digest_chunks);
    assert_eq!(row_h_keccak, h_keccak);
}

// CONSTRAINT TESTS
// ================================================================================================

#[test]
fn constraints_hold_on_single_invocation() {
    check_with_invocations(0x01, &[anchored_inv(0x11, 50)]);
}

#[test]
fn chunk_count_accepts_empty_and_boundary_lengths() {
    for len_bytes in [0, 1, 31, 32, 33, 64] {
        check_with_invocations(0x11, &[anchored_inv(0x11, len_bytes)]);
    }
}

#[test]
fn final_node_cannot_redirect_chunk_tail() {
    let first = anchored_inv(0x11, 32);
    let last = next_inv(&first, 0x12, 32);
    let mut main = generate_trace_from_invocations(&[first, last]);
    crate::tests::check_local(KeccakNodeAir, &main);
    assert_eq!(main.values[NUM_MAIN_COLS + COL_ACT], Felt::ONE);
    assert_eq!(main.values[NUM_MAIN_COLS + COL_N_CHUNKS], Felt::ONE);

    main.values[NUM_MAIN_COLS + COL_N_CHUNKS] = Felt::from(2u8);
    main.values[NUM_MAIN_COLS + COL_N_CHUNKS_INV] = Felt::from(2u8).inverse();
    crate::tests::assert_local_rejects(KeccakNodeAir, &main);
}

#[test]
fn is_empty_must_be_binary() {
    // Empty input claimed as two chunks gives `is_empty = 33`. The tail read at
    // `perm_seq_id_chunks + 1` would bind `keccak("")` to a two-chunk commitment.
    let mut main = single_node_trace(0);
    let row = &mut main.values[..NUM_MAIN_COLS];
    set_chunk_count(row, Felt::from(2u8), Felt::ZERO);
    assert_eq!(is_empty(row), Felt::from(33u8));
    crate::tests::assert_local_rejects(KeccakNodeAir, &main);
}

#[test]
fn is_empty_cannot_cover_nonempty_input() {
    // Two chunks with remainder 0 describe 33 bytes; claiming 32 sets `is_empty = 1`. The claim
    // would bind the Keccak digest of 32 bytes to a two-chunk commitment.
    let mut main = single_node_trace(33);
    main.values[COL_LEN_BYTES] = Felt::from(32u8);
    assert_eq!(is_empty(&main.values[..NUM_MAIN_COLS]), Felt::ONE);
    crate::tests::assert_local_rejects(KeccakNodeAir, &main);
}

#[test]
fn is_empty_cannot_cover_a_remainder() {
    // Empty input with remainder 1 holds only for the field-wrapped `n_chunks = 1 − 1/32`.
    // This guard rules out that remainder locally, independent of the tail lookup.
    let mut main = single_node_trace(0);
    let row = &mut main.values[..NUM_MAIN_COLS];
    let remainder = Felt::ONE;
    set_chunk_count(row, Felt::ONE - remainder * Felt::from(32u8).inverse(), remainder);
    assert_eq!(is_empty(row), Felt::ONE);
    crate::tests::assert_local_rejects(KeccakNodeAir, &main);
}

#[test]
fn chunk_count_must_be_nonzero() {
    // Zero chunks with remainder 31 give `is_empty = 0` for empty input. The tail read would
    // target the Eidos compression cycle before this invocation's chunk-chain head.
    let mut main = single_node_trace(0);
    let row = &mut main.values[..NUM_MAIN_COLS];
    set_chunk_count(row, Felt::ZERO, Felt::from(31u8));
    assert_eq!(is_empty(row), Felt::ZERO);
    crate::tests::assert_local_rejects(KeccakNodeAir, &main);
}

#[test]
fn chunk_remainder_is_range_checked() {
    // 32 bytes as two chunks satisfy every local constraint with remainder −1; the row must then
    // request `Xor(−1, 32) = 31`, which the byte-pair table never provides.
    let mut main = single_node_trace(32);
    let tuple = forge_out_of_range_remainder(&mut main.values[..NUM_MAIN_COLS]);
    crate::tests::check_local(KeccakNodeAir, &main);
    crate::tests::bus_balance::assert_unprovidable_xor_lookup(&KeccakNodeAir, &main, tuple);
}

/// Set a node row's sponge permutation count and return the last-block remainder
/// `len_bytes − 136·(n_sponge_perms − 1)` that the row then range-checks.
pub(super) fn forge_sponge_perms(row: &mut [Felt], n_sponge_perms: Felt) -> Felt {
    row[COL_N_SPONGE_PERMS] = n_sponge_perms;
    row[COL_LEN_BYTES] - Felt::from(136u8) * (n_sponge_perms - Felt::ONE)
}

#[test]
fn final_node_sponge_perm_count_cannot_wrap() {
    // The final active row has no continuity successor. A count of −1 would place the digest read
    // two permutations before this invocation's first block, at another invocation's output.
    let mut main = single_node_trace(32);
    forge_sponge_perms(&mut main.values[..NUM_MAIN_COLS], -Felt::ONE);
    crate::tests::check_local(KeccakNodeAir, &main);
    crate::tests::bus_balance::assert_unprovidable_range16_lookup(
        &KeccakNodeAir,
        &main,
        -Felt::from(2u8),
    );
}

#[test]
fn sponge_perm_count_cannot_exceed_length() {
    // 32 bytes absorb in one permutation. Claiming two would read the digest from the permutation
    // after this invocation, and leaves the last-block remainder at 32 − 136.
    let mut main = single_node_trace(32);
    let remainder = forge_sponge_perms(&mut main.values[..NUM_MAIN_COLS], Felt::from(2u8));
    assert_eq!(remainder, -Felt::from(104u8));
    crate::tests::check_local(KeccakNodeAir, &main);
    crate::tests::bus_balance::assert_unprovidable_range16_lookup(&KeccakNodeAir, &main, remainder);
}

#[test]
fn sponge_perm_count_cannot_fall_short_of_length() {
    // 136 bytes need a second, padding-only permutation. Claiming one would read the first
    // block's output as the digest and leaves the remainder at 136.
    let mut main = single_node_trace(136);
    let remainder = forge_sponge_perms(&mut main.values[..NUM_MAIN_COLS], Felt::ONE);
    assert_eq!(remainder, Felt::from(136u8));
    crate::tests::check_local(KeccakNodeAir, &main);
    crate::tests::bus_balance::assert_unprovidable_range16_lookup(
        &KeccakNodeAir,
        &main,
        Felt::from(135u8) - remainder,
    );
}

#[test]
fn sponge_perm_count_must_be_integral() {
    // `n_sponge_perms = 1 + 10/136` gives the in-range remainder 0 for a 10-byte input; only the
    // range check on `n_sponge_perms − 1` excludes this field-fractional count.
    let mut main = single_node_trace(10);
    let fraction = Felt::from(10u8) * Felt::from(136u8).inverse();
    let remainder = forge_sponge_perms(&mut main.values[..NUM_MAIN_COLS], Felt::ONE + fraction);
    assert_eq!(remainder, Felt::ZERO);
    crate::tests::check_local(KeccakNodeAir, &main);
    crate::tests::bus_balance::assert_unprovidable_range16_lookup(&KeccakNodeAir, &main, fraction);
}

#[test]
fn constraints_hold_on_multi_invocation_with_continuity() {
    let inv0 = anchored_inv(0xa0, 50);
    let inv1 = next_inv(&inv0, 0xa1, 100);
    let inv2 = next_inv(&inv1, 0xa2, 200);
    check_with_invocations(0x02, &[inv0, inv1, inv2]);
}

#[test]
fn constraints_hold_on_empty_trace() {
    // No invocations — trace is padded out to height 1, all rows
    // inactive (act = 0 throughout, all witnesses zero). The boundary
    // pins on `sponge_seq_id_head` / `chunk_seq_id_head` reduce to
    // `0 = 0`, every transition is gated off by `act_next = 0`.
    check_with_invocations(0x03, &[]);
}

// NEGATIVE TESTS
// ================================================================================================

fn corrupt_and_check(
    _seed: u64,
    invocations: &[KeccakNodeInvocation],
    corruption: impl FnOnce(&mut RowMajorMatrix<Felt>),
) {
    let mut main = generate_trace_from_invocations(invocations);
    corruption(&mut main);
    crate::tests::check_local(KeccakNodeAir, &main);
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_non_binary_act() {
    corrupt_and_check(0xc0, &[anchored_inv(0x11, 50)], |main| {
        main.values[COL_ACT] = Felt::from(2u8);
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_sponge_seq_id_head_boundary() {
    // when_first_row · sponge_seq_id_head = 0 — non-zero at row 0
    // violates the boundary.
    corrupt_and_check(0xc1, &[anchored_inv(0x11, 50)], |main| {
        main.values[COL_SPONGE_SEQ_ID_HEAD] = Felt::from(7u8);
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_chunk_seq_id_head_boundary() {
    corrupt_and_check(0xc2, &[anchored_inv(0x11, 50)], |main| {
        main.values[COL_CHUNK_SEQ_ID_HEAD] = Felt::from(11u8);
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_sponge_continuity() {
    // Break the sponge-namespace continuity: bump invocation 1's
    // sponge_seq_id_head off the `+32·n_sponge_perms` step.
    let inv0 = anchored_inv(0xa0, 50);
    let inv1 = next_inv(&inv0, 0xa1, 100);
    corrupt_and_check(0xc3, &[inv0, inv1], |main| {
        main.values[NUM_MAIN_COLS + COL_SPONGE_SEQ_ID_HEAD] += Felt::ONE;
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_chunk_continuity() {
    let inv0 = anchored_inv(0xa0, 50);
    let inv1 = next_inv(&inv0, 0xa1, 100);
    corrupt_and_check(0xc4, &[inv0, inv1], |main| {
        main.values[NUM_MAIN_COLS + COL_CHUNK_SEQ_ID_HEAD] += Felt::ONE;
    });
}

// The `ChunkChain` bus pins `absorption_id_chunks` on each row instead of a local cross-row
// constraint. A single-cell corruption therefore unbalances that bus, and bus-balance falsification
// belongs in a cross-chiplet test, not here.

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_act_sticky_down_violated() {
    // Sticky-down `(1−act)·act_next = 0` forbids any 0→1 transition.
    // Generate a 2-invocation trace (height 2), then flip row 0
    // inactive — row 1 stays active, giving the forbidden 0→1.
    let inv0 = anchored_inv(0xa0, 50);
    let inv1 = next_inv(&inv0, 0xa1, 100);
    corrupt_and_check(0xc6, &[inv0, inv1], |main| {
        main.values[COL_ACT] = Felt::ZERO;
    });
}
