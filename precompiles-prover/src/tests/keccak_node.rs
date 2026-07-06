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
    field::QuadFelt,
};
use miden_lifted_air::{BaseAir, LiftedAir};
use miden_precompiles::Keccak256Precompile;
use rand::{Rng, SeedableRng, rngs::StdRng};

use crate::{
    hash::{
        chunk::trace::ChunkSeqId,
        keccak::{
            node::{
                COL_ACT, COL_CHUNK_SEQ_ID_HEAD, COL_D_BEGIN, COL_H_DIGEST_CHUNKS_BEGIN,
                COL_H_INPUT_CHUNKS_BEGIN, COL_H_KECCAK_BEGIN, COL_LEN_BYTES, COL_N_CHUNKS,
                COL_N_SPONGE_PERMS, COL_PERM_SEQ_ID_CHUNKS, COL_PERM_SEQ_ID_DIGEST_CHUNKS,
                COL_PERM_SEQ_ID_KECCAK, COL_SPONGE_SEQ_ID_HEAD, KeccakNodeAir, NUM_AUX_COLS,
                NUM_HASH, NUM_MAIN_COLS,
                trace::{KeccakNodeInvocation, generate_trace_from_invocations},
            },
            sponge::trace::SpongeSeqId,
        },
    },
    logup::{NUM_PUBLIC_VALUES, NUM_RANDOMNESS, NUM_SIGMA_VALUES},
    transcript::poseidon2::trace::PermSeqId,
};

// HELPERS
// ================================================================================================

fn check_with_invocations(_seed: u64, invocations: &[KeccakNodeInvocation]) {
    let main = generate_trace_from_invocations(invocations);
    crate::tests::check_local(KeccakNodeAir, &main);
}

/// Build a single-invocation example anchored at the row-0 origin. The
/// concrete `d` / `h_input_chunks` values are arbitrary — `check_constraints`
/// runs the AIR's local constraints + LogUp σ recurrence, both of
/// which are agnostic to the digest bytes (cross-chiplet content
/// consistency lives at the integration-test layer).
fn anchored_inv(seed: u64, len_bytes: u32) -> KeccakNodeInvocation {
    let mut rng = StdRng::seed_from_u64(seed);
    KeccakNodeInvocation {
        len_bytes,
        d: core::array::from_fn(|_| rng.random()),
        h_input_chunks: core::array::from_fn(|_| Felt::new(rng.random()).unwrap()),
        chunk_seq_id_head: ChunkSeqId::forged(0),
        perm_seq_id_chunks: PermSeqId::forged(0),
        perm_seq_id_digest_chunks: PermSeqId::forged(100),
        perm_seq_id_keccak: PermSeqId::forged(101),
        sponge_seq_id_head: SpongeSeqId::forged(0),
        out_mult: 1,
    }
}

/// Append a follow-on invocation whose head columns satisfy the
/// orchestrator's continuity equations against `prev`. P2 digest-chunks /
/// keccak cycles are free witnesses (the orchestrator's continuity
/// doesn't constrain them); we just pick fresh cycles per invocation.
fn next_inv(prev: &KeccakNodeInvocation, seed: u64, len_bytes: u32) -> KeccakNodeInvocation {
    let mut rng = StdRng::seed_from_u64(seed);
    KeccakNodeInvocation {
        len_bytes,
        d: core::array::from_fn(|_| rng.random()),
        h_input_chunks: core::array::from_fn(|_| Felt::new(rng.random()).unwrap()),
        chunk_seq_id_head: ChunkSeqId::forged(
            prev.chunk_seq_id_head.seq() + prev.n_chunks() as u32,
        ),
        perm_seq_id_chunks: PermSeqId::forged(
            prev.perm_seq_id_chunks.seq() + prev.n_chunks() as u32,
        ),
        perm_seq_id_digest_chunks: PermSeqId::forged(prev.perm_seq_id_digest_chunks.seq() + 1000),
        perm_seq_id_keccak: PermSeqId::forged(prev.perm_seq_id_keccak.seq() + 1000),
        sponge_seq_id_head: SpongeSeqId::forged(
            prev.sponge_seq_id_head.seq() + 32 * prev.n_sponge_perms() as u32,
        ),
        out_mult: 1,
    }
}

// LAYOUT / STRUCTURAL
// ================================================================================================

#[test]
fn main_column_layout_partitions_30_indices() {
    use crate::hash::keccak::node::COL_OUT_MULT;
    assert_eq!(COL_ACT, 0);
    assert_eq!(COL_SPONGE_SEQ_ID_HEAD, 1);
    assert_eq!(COL_N_SPONGE_PERMS, 2);
    assert_eq!(COL_CHUNK_SEQ_ID_HEAD, 3);
    assert_eq!(COL_N_CHUNKS, 4);
    assert_eq!(COL_PERM_SEQ_ID_CHUNKS, 5);
    assert_eq!(COL_LEN_BYTES, 6);
    assert_eq!(COL_PERM_SEQ_ID_DIGEST_CHUNKS, 7);
    assert_eq!(COL_PERM_SEQ_ID_KECCAK, 8);
    assert_eq!(COL_D_BEGIN, 9);
    assert_eq!(COL_H_INPUT_CHUNKS_BEGIN, 17);
    assert_eq!(COL_H_DIGEST_CHUNKS_BEGIN, 21);
    assert_eq!(COL_H_KECCAK_BEGIN, 25);
    assert_eq!(COL_OUT_MULT, 29);
    assert_eq!(NUM_MAIN_COLS, 30);
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
    assert_eq!(layout.num_permutation_values, NUM_SIGMA_VALUES);
    assert_eq!(layout.num_periodic_columns, 0);
}

#[test]
fn log_quotient_degree_matches_design_target() {
    // 4-aux-column product layout — batches n = 4 put the *ungated* logup
    // recurrence at degree 5 (denominator product · acc + 1). The natural
    // last-row σ-closing gates it with `when_transition` (degree-1
    // `is_transition` selector), tipping the ext-field constraint to degree
    // 6 → log_quotient_degree 3. (Old σ/n-cyclic form: ungated deg 5 → lqd 2,
    // at the cost of the now-dropped `inv_n` public input.)
    let air = KeccakNodeAir;
    assert_eq!(crate::tests::log_quotient_degree(&air), 3);
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
    corruption: impl FnOnce(&mut p3_matrix::dense::RowMajorMatrix<Felt>),
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

// `perm_seq_id_chunks` is no longer constrained for cross-row
// continuity (it's bus-pinned per row by `ChunkChain`); a single-cell
// corruption is caught by the `ChunkChain` bus going out of balance,
// not by a local AIR constraint, and bus-balance falsification
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
