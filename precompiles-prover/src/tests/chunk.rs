//! Tests for the chunk chiplet.
//!
//! [`ChunkChainMsg`] encoding invariants, main-column-layout invariants,
//! [`LiftedAir`] structural smoke checks (validate, layout dims,
//! log-quotient-degree target), trace-driven constraint checks across the
//! canonical edge cases (single chunk, multi-chunk, block-aligned tails,
//! multi-invocation), and negative tests confirming `check_constraints`
//! catches corruption.

use miden_air::BaseAir;
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_lifted_air::LiftedAir;
use rand::{RngExt, SeedableRng, rngs::StdRng};

use crate::{
    hash::{
        chunk::{
            COL_ACT, COL_CHUNK_SEQ_ID, COL_F_BEGIN, COL_F_END, COL_IS_HEAD, COL_PERM_SEQ_ID,
            ChunkAir, ChunkChainMsg, NUM_AUX_COLS, NUM_MAIN_COLS,
            trace::{ChunkRequires, Invocation, generate_trace},
        },
        memory64::Memory64Msg,
    },
    logup::{Challenges, LookupMessage, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, NUM_SIGMA_VALUES},
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    transcript::poseidon2::trace::Poseidon2Requires,
};

fn build_chunk_requires(invocations: &[Invocation]) -> (ChunkRequires, Poseidon2Requires) {
    let mut p2 = Poseidon2Requires::new();
    let mut chunk = ChunkRequires::new();
    for inv in invocations {
        chunk.require(inv, &mut p2);
    }
    (chunk, p2)
}

fn check_with_seed(_seed: u64, invocations: &[Invocation]) {
    let (chunk_req, _p2) = build_chunk_requires(invocations);
    let main = generate_trace(chunk_req);
    crate::tests::check_local(ChunkAir, &main);
}

fn inv(len: usize, seed: u64) -> Invocation {
    let mut rng = StdRng::seed_from_u64(seed);
    Invocation {
        input: (0..len).map(|_| rng.random()).collect(),
    }
}

// MESSAGE ENCODING
// ================================================================================================

#[test]
fn chunk_chain_msg_encodes_with_chunk_chain_bus_prefix() {
    let alpha = QuadFelt::from_u64(31);
    let beta = QuadFelt::from_u64(37);
    let challenges = Challenges::<QuadFelt>::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);

    let chunk_seq_id_head = Felt::from(13u32);
    let perm_seq_id_head = Felt::from(17u32);
    let msg = ChunkChainMsg { chunk_seq_id_head, perm_seq_id_head };
    let enc = msg.encode(&challenges);

    // Expected: bus_prefix[ChunkChain] + β⁰·chunk_seq_id_head +
    // β¹·perm_seq_id_head.
    let bus_prefix = alpha
        + beta.exp_u64(MAX_MESSAGE_WIDTH as u64)
            * QuadFelt::from_u64((BusId::ChunkChain as u64) + 1);
    let expected =
        bus_prefix + QuadFelt::from(chunk_seq_id_head) + beta * QuadFelt::from(perm_seq_id_head);

    assert_eq!(enc, expected);
}

#[test]
fn chunk_chain_bus_has_disjoint_prefix() {
    // Same-arity payload on ChunkChain vs Memory64 must differ — they
    // share the 2-felt header shape, so only the bus prefix
    // distinguishes them. (Memory64 carries a third `hi` felt, which
    // we set to zero to make the bus-prefix the sole differentiator.)
    let alpha = QuadFelt::from_u64(2);
    let beta = QuadFelt::from_u64(3);
    let challenges = Challenges::<QuadFelt>::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);

    let a = Felt::from(5u32);
    let b = Felt::from(11u32);
    let enc_chunk_chain = ChunkChainMsg {
        chunk_seq_id_head: a,
        perm_seq_id_head: b,
    }
    .encode(&challenges);
    let enc_memory64 = Memory64Msg { addr: a, lo: b, hi: Felt::ZERO }.encode(&challenges);

    assert_ne!(enc_chunk_chain, enc_memory64);
}

// LAYOUT / STRUCTURAL
// ================================================================================================

#[test]
fn main_column_layout_partitions_12_indices() {
    assert_eq!(COL_CHUNK_SEQ_ID, 0);
    assert_eq!(COL_PERM_SEQ_ID, 1);
    assert_eq!(COL_ACT, 2);
    assert_eq!(COL_IS_HEAD, 3);
    assert_eq!(COL_F_BEGIN, 4);
    assert_eq!(COL_F_END, NUM_MAIN_COLS);
    assert_eq!(NUM_MAIN_COLS, 12);
    assert_eq!(<ChunkAir as BaseAir<Felt>>::width(&ChunkAir), NUM_MAIN_COLS);
}

#[test]
fn lifted_air_validates_and_layout_matches_spec() {
    let air = ChunkAir;
    let layout = <ChunkAir as LiftedAir<Felt, QuadFelt>>::air_layout(&air);
    assert_eq!(layout.preprocessed_width, 0);
    assert_eq!(layout.main_width, NUM_MAIN_COLS);
    assert_eq!(layout.num_public_values, NUM_PUBLIC_VALUES);
    assert_eq!(layout.permutation_width, NUM_AUX_COLS);
    assert_eq!(layout.num_permutation_challenges, NUM_RANDOMNESS);
    assert_eq!(layout.num_permutation_values, NUM_SIGMA_VALUES);
    // Period 1 — no periodic columns.
    assert_eq!(layout.num_periodic_columns, 0);
}

#[test]
fn log_quotient_degree_matches_design_target() {
    // The logup running-sum (ext field) tops out at symbolic degree 6 →
    // log_quotient_degree 3. The 2-aux batches put the *ungated* recurrence
    // `D₀·acc_next − …` at degree 5 (denominator product n=4 · acc + 1); the
    // natural last-row σ-closing then gates it with `when_transition`, whose
    // degree-1 `is_transition` selector adds the +1 to 6. (The old σ/n-cyclic
    // adapter kept this recurrence ungated at degree 5 → lqd 2, paid for with
    // an `inv_n` public input we dropped under 0.26's shared `air_inputs`.)
    // See `docs/airs/chunk.md`.
    let air = ChunkAir;
    assert_eq!(crate::tests::log_quotient_degree(&air), 3);
}

// CONSTRAINT TESTS
// ================================================================================================

#[test]
fn constraints_hold_on_single_chunk() {
    // len ≤ 32 → one chunk, is_head on row 0.
    check_with_seed(0x01, &[inv(1, 0x11)]);
    check_with_seed(0x07, &[inv(7, 0x77)]);
    check_with_seed(0x08, &[inv(8, 0x88)]);
    check_with_seed(0x20, &[inv(32, 0x20)]);
}

#[test]
fn constraints_hold_on_two_chunks() {
    // 33 bytes → chunk 0 full, chunk 1 has one real byte (full
    // emission with trailing zero lanes).
    check_with_seed(0x21, &[inv(33, 0x21)]);
}

#[test]
fn constraints_hold_on_block_aligned() {
    // 128 bytes → 4 full chunks.
    check_with_seed(0x80, &[inv(128, 0x80)]);
}

#[test]
fn constraints_hold_on_five_chunks() {
    // 129, 135 → 5 chunks each; all chunks emit four lanes (the chiplet
    // is hasher-agnostic — no block-fit awareness).
    check_with_seed(0x81, &[inv(129, 0x81)]);
    check_with_seed(0x87, &[inv(135, 0x87)]);
}

#[test]
fn constraints_hold_on_pad_block_tail() {
    // 136 → 5 chunks, last chunk one real lane (8 bytes) + zero lanes.
    // 200 → 7 chunks.
    check_with_seed(0x88, &[inv(136, 0x88)]);
    check_with_seed(0xc8, &[inv(200, 0xc8)]);
}

#[test]
fn constraints_hold_on_multiple_invocations() {
    // Back-to-back invocations: is_head fires on each first chunk;
    // the chunk_seq_id / perm_seq_id chains run across the seam.
    check_with_seed(0x5ea, &[inv(33, 0xa1), inv(40, 0xb2), inv(129, 0xc3)]);
}

#[test]
fn constraints_hold_with_perm_seq_id_jump_at_head() {
    // Exercise the within-chain `+1` relaxation: shift the second
    // invocation's perm_seq_id by a gap (modelling P2 cycles
    // interleaved with another caller). The jump lands on a chain
    // head (is_head_next = 1), so the chain gate vanishes and the
    // constraints still hold.
    let (chunk_req, _p2) = build_chunk_requires(&[inv(33, 0xa1), inv(40, 0xb2)]);
    let mut main = generate_trace(chunk_req);
    // inv0 = 2 chunks (rows 0,1), inv1 = 2 chunks (rows 2,3). Row 2 is
    // a head (is_head = 1). Bump perm_seq_id on rows 2,3 by a gap.
    let gap = Felt::from(7u8);
    for row in 2..4 {
        let cell = &mut main.values[row * NUM_MAIN_COLS + COL_PERM_SEQ_ID];
        *cell += gap;
    }
    crate::tests::check_local(ChunkAir, &main);
}

// NEGATIVE TESTS
// ================================================================================================

fn corrupt_and_check(
    _seed: u64,
    invocations: &[Invocation],
    corruption: impl FnOnce(&mut miden_core::utils::RowMajorMatrix<Felt>),
) {
    let (chunk_req, _p2) = build_chunk_requires(invocations);
    let mut main = generate_trace(chunk_req);
    corruption(&mut main);
    crate::tests::check_local(ChunkAir, &main);
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_non_binary_act() {
    corrupt_and_check(0xc0, &[inv(33, 0x21)], |main| {
        main.values[COL_ACT] = Felt::from(2u8);
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_non_binary_is_head() {
    corrupt_and_check(0xc1, &[inv(33, 0x21)], |main| {
        main.values[COL_IS_HEAD] = Felt::from(2u8);
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_chunk_seq_id_breaks_chain() {
    corrupt_and_check(0xc3, &[inv(200, 0xc8)], |main| {
        main.values[NUM_MAIN_COLS + COL_CHUNK_SEQ_ID] = Felt::from(7u8);
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_perm_seq_id_jump_mid_chain() {
    // 200 bytes → 7 chunks in one invocation (rows 0..7). Row 3 is
    // interior (is_head_next = 0 at the 2→3 and 3→4 transitions), so
    // bumping perm_seq_id there breaks the within-chain +1.
    corrupt_and_check(0xc4, &[inv(200, 0xc8)], |main| {
        let cell = &mut main.values[3 * NUM_MAIN_COLS + COL_PERM_SEQ_ID];
        *cell += Felt::from(5u8);
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_is_head_on_dead_row() {
    // 200 → 7 chunks → height 8; row 7 is a dead pad row (act = 0).
    // Setting is_head there violates is_head · (1 − act) = 0.
    corrupt_and_check(0xc5, &[inv(200, 0xc8)], |main| {
        main.values[7 * NUM_MAIN_COLS + COL_IS_HEAD] = Felt::ONE;
    });
}
