//! Tests for the Keccak-node chiplet.
//!
//! Layout / [`LiftedAir`] structural smoke checks +
//! trace-driven constraint checks across single- and multi-invocation
//! traces (verifying boundary anchors + per-namespace continuity).
//! Negative tests confirm `check_constraints` catches deliberate
//! corruption of the activity flag, boundary, and continuity edges.

use std::{vec, vec::Vec};

use miden_air::lookup::Challenges;
use miden_core::{
    Felt,
    deferred::{Digest, Node, TRUE_DIGEST, deferred_chunks_frame},
    field::{Field, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};
use miden_lifted_air::{BaseAir, LiftedAir};
use miden_precompiles::Keccak256Precompile;
use rand::{RngExt, SeedableRng, rngs::StdRng};

use crate::{
    hash::{
        chunk::{
            self as chunk_cols,
            trace::{ChunkRequires, ChunkSeqId, generate_trace_padded_to as chunk_trace},
        },
        chunk_node::NODE_COL_OFFSET,
        chunk_node_sponge::{
            ChunkNodeSpongeAir, NUM_MAIN_COLS as CNS_COLS, SPONGE_COL_OFFSET,
            trace::generate_trace as cns_trace,
        },
        keccak::{
            node::{
                COL_ABSORPTION_ID_CHUNKS, COL_ABSORPTION_ID_DIGEST_CHUNKS,
                COL_ABSORPTION_ID_KECCAK, COL_ACT, COL_CHUNK_SEQ_ID_HEAD, COL_D_BEGIN, COL_D_END,
                COL_H_DIGEST_CHUNKS_BEGIN, COL_H_DIGEST_CHUNKS_END, COL_H_INPUT_CHUNKS_BEGIN,
                COL_H_INPUT_CHUNKS_END, COL_H_KECCAK_BEGIN, COL_H_KECCAK_END, COL_LAST_CHUNK_REM,
                COL_LEN_BYTES, COL_N_CHUNKS, COL_N_CHUNKS_INV, COL_N_SPONGE_PERMS, COL_OUT_MULT,
                COL_SPONGE_SEQ_ID_HEAD, KeccakNodeAir, NUM_AUX_COLS, NUM_HASH, NUM_MAIN_COLS,
                SPONGE_RATE_BYTES,
                trace::{
                    KeccakNodeInvocation, KeccakNodeRequires, generate_trace_from_invocations,
                },
            },
            round::{KeccakRoundAir, RoundRequires, generate_trace as round_trace},
            sponge::{
                self as sponge_cols,
                trace::{
                    Invocation as SpongeInvocation, SpongeOutput, SpongeRequires, SpongeSeqId,
                    generate_trace_padded_to as sponge_trace, keccak_oracle,
                },
            },
        },
    },
    logup::{LookupMessage, NUM_LOGUP_VALUES, NUM_PUBLIC_VALUES, NUM_RANDOMNESS},
    primitives::byte_pair_lut::{
        BytePairLutAir, BytePairLutRequires, BytePairOp, Range16Msg, generate_trace as bpl_trace,
    },
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    session::Session,
    tests::bus_balance::session_stack_residual_keyed,
    transcript::{
        eidos::{
            EidosCompressionAir, EidosDigest,
            trace::{
                AbsorptionOutput, EidosRequires, generate_trace_with_byte_lookups as eidos_trace,
                testing::forged_absorption_id,
            },
        },
        eval::{
            TranscriptEvalAir,
            trace::{TranscriptEvalRequires, generate_trace as eval_trace},
        },
    },
};

// HELPERS
// ================================================================================================

/// Deterministic stand-in for seeded random fixture data. The digest bytes and chunk-chain
/// digests are don't-care witnesses for these tests (the AIR's local constraints and LogUp
/// recurrence are agnostic to them), so they only need to be arbitrary-looking and
/// reproducible from source.
fn fixture_u32(i: usize, tag: u64) -> u32 {
    ((i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ tag) as u32
}

fn fixture_felt(i: usize, tag: u64) -> Felt {
    let mix = (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ tag.rotate_left(32);
    Felt::new_unchecked(mix % Felt::ORDER)
}

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
    KeccakNodeInvocation {
        len_bytes,
        d: core::array::from_fn(|i| fixture_u32(i, seed)),
        h_input_chunks: core::array::from_fn(|i| fixture_felt(i, seed)),
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
    KeccakNodeInvocation {
        len_bytes,
        d: core::array::from_fn(|i| fixture_u32(i, seed)),
        h_input_chunks: core::array::from_fn(|i| fixture_felt(i, seed)),
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
    // The eleven-column packing leaves columns 0, 8, and 10 as singletons and pairs the rest.
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

// MULTI-INVOCATION DIGEST FORGERY
// ================================================================================================

/// Attacker-chosen statement input: the digest of [`M_Y`] is claimed for it.
const M_X: &[u8] = b"pay 1 MIDEN to alice";
/// Message whose digest is misattributed to [`M_X`].
const M_Y: &[u8] = b"pay 1000000 MIDEN to mallory";
/// Dummy third invocation that lets the node rows visit the sponge out of physical order.
const M_Z: &[u8] = b"z";

/// `p − 1` in Goldilocks: the `n_sponge_perms` that steps the sponge head back by 32 rows, one
/// permutation.
const P_MINUS_ONE: u64 = 0xffff_ffff_0000_0000;

const CHUNK_W: usize = chunk_cols::NUM_MAIN_COLS;
const NODE_W: usize = NUM_MAIN_COLS;
const SPONGE_W: usize = sponge_cols::NUM_MAIN_COLS;

/// Indices of the Keccak-dependent chiplets in the session stack
/// ([`SessionTraces::mains`](crate::session::SessionTraces::mains) order).
const CNS: usize = 0;
const EIDOS: usize = 1;
const ROUND: usize = 2;
const BPL: usize = 3;
const EVAL: usize = 4;

/// The Keccak-dependent chiplet traces (merged chunk/node/sponge, Eidos, round, eval) plus the
/// byte-pair multiplicities those chiplets demand, and the transcript root.
struct KeccakSide {
    cns: RowMajorMatrix<Felt>,
    eidos: RowMajorMatrix<Felt>,
    round: RowMajorMatrix<Felt>,
    bpl: RowMajorMatrix<Felt>,
    eval: RowMajorMatrix<Felt>,
    root: EidosDigest,
}

fn len_u32(m: &[u8]) -> u32 {
    u32::try_from(m.len()).expect("message length fits u32")
}

fn keccak_felts(m: &[u8]) -> [Felt; 8] {
    keccak_oracle(m).to_felts()
}

/// The three `Range16` values a node row range-checks, mirroring `eval_sponge_perm_count`: the
/// full-block count `n_sponge_perms − 1`, the last block's remainder
/// `len_bytes − 136·(n_sponge_perms − 1)`, and the rate gap `135 − remainder`.
fn sponge_perm_range_checks(n_sponge_perms: Felt, len_bytes: Felt) -> [Felt; 3] {
    let full_blocks = n_sponge_perms - Felt::ONE;
    let remainder = len_bytes - Felt::from(SPONGE_RATE_BYTES) * full_blocks;
    let rate_gap = Felt::from(SPONGE_RATE_BYTES - 1) - remainder;
    [full_blocks, remainder, rate_gap]
}

/// The deferred root a VM program logs for
/// `AND(TRUE, Keccak256Assert(chunks(input), chunks(claimed_digest)))`.
fn deferred_root_for_claim(input: &[u8], claimed_digest: [Felt; 8]) -> EidosDigest {
    let input_chunks = Node::chunks_from_bytes(input).digest();
    let digest_chunks = Node::chunks(vec![claimed_digest])
        .expect("digest chunks are non-empty")
        .digest();
    let assertion =
        Keccak256Precompile::assert_node(len_u32(input), input_chunks, digest_chunks).digest();
    EidosDigest::from(Node::and(TRUE_DIGEST, assertion).digest())
}

/// Replay the Keccak side of a session with the same inputs. Reproducing the session's Keccak
/// chiplets bit for bit lets the test subtract their byte-pair demand and isolate the demand of
/// the other chiplets.
fn honest_keccak_side(msgs: &[&[u8]]) -> KeccakSide {
    let mut eidos = EidosRequires::new();
    let mut chunk = ChunkRequires::new();
    let mut round = RoundRequires::new();
    let mut bpl = BytePairLutRequires::new();
    let mut sponge = SpongeRequires::new();
    let mut node = KeccakNodeRequires::new();
    let mut eval = TranscriptEvalRequires::new();

    let claims: Vec<_> = msgs
        .iter()
        .map(|m| {
            let out = node.require(m, &mut sponge, &mut chunk, &mut round, &mut bpl, &mut eidos);
            eval.issue_keccak(out.h_keccak, out.node_row)
        })
        .collect();
    let mut root = eval.zero();
    for claim in claims {
        root = eval.record_and(root, claim, &mut eidos);
    }

    let root_hash = root.hash();
    let eval = eval_trace(eval, root);
    let cns = cns_trace(chunk, node, sponge);
    let eidos = eidos_trace(eidos, &mut bpl);
    let round = round_trace(round, &mut bpl);
    KeccakSide {
        cns,
        eidos,
        round,
        bpl: bpl_trace(bpl),
        eval,
        root: root_hash,
    }
}

/// One forged node row: the message whose input chunks it binds, the sponge invocation and chunk
/// chain it names, which invocation's digest it reads, and its `n_sponge_perms`.
struct ForgedRow {
    msg: usize,
    sponge_head: u32,
    chunk_head: u32,
    digest_of: usize,
    n_sponge_perms: Felt,
    out_mult: u32,
}

/// Build the Keccak side where node rows associate each input with another invocation's digest.
///
/// The sponge, round, and chunk bands stay honest in physical order X, Y, Z. The node rows run in
/// chunk order X, Z, Y at sponge heads 0, 64, 32 with `n_sponge_perms` 2, p − 1, 2, so the digest
/// address `100·sponge_seq_id_head + 3200·n_sponge_perms − 128 + j` lands on another invocation's
/// final-permutation output (row 0 reads D_Y, row 1 reads D_X, row 2 reads D_Z). The
/// head-continuity step `+ 32·n_sponge_perms` still holds across the three rows, so without the
/// sponge-permutation range checks every local constraint and every bus closes.
fn forged_keccak_side(msgs: [&[u8]; 3]) -> KeccakSide {
    let mut eidos = EidosRequires::new();
    let mut chunk = ChunkRequires::new();
    let mut round = RoundRequires::new();
    let mut bpl = BytePairLutRequires::new();
    let mut sponge = SpongeRequires::new();
    let mut eval = TranscriptEvalRequires::new();

    // Honest sponge, round, and chunk work in physical order X, Y, Z.
    let outs: Vec<SpongeOutput> = msgs
        .iter()
        .map(|m| {
            sponge.require(
                &SpongeInvocation { input: m.to_vec() },
                &mut chunk,
                &mut round,
                &mut bpl,
                &mut eidos,
            )
        })
        .collect();
    for (i, out) in outs.iter().enumerate() {
        assert_eq!(out.sponge_head.seq(), 32 * i as u32, "one permutation per message");
        assert_eq!(out.chunk_head.seq(), i as u32, "one chunk per message");
        assert_eq!(out.keccak_digest.to_felts(), keccak_felts(msgs[i]), "sponge stays honest");
        // Each node row reads its chunk-chain tail through EidosOut(H_input_chunks).
        let _ = eidos.require_digest(out.chunk_content_digest);
    }
    let digest_chunks: Vec<AbsorptionOutput> = outs
        .iter()
        .map(|out| {
            let d = out.keccak_digest.to_felts();
            let a = eidos.require_one_shot(
                deferred_chunks_frame(1),
                d[0..4].try_into().expect("block low"),
                d[4..8].try_into().expect("block high"),
            );
            let _ = eidos.require_digest(a.digest);
            a
        })
        .collect();

    // Node rows in chunk order X, Z, Y; sponge heads 0, 64, 32.
    let p_minus_one = Felt::new(P_MINUS_ONE).expect("p - 1 is canonical");
    let rows = [
        ForgedRow {
            msg: 0,
            sponge_head: 0,
            chunk_head: 0,
            digest_of: 1,
            n_sponge_perms: Felt::from(2u8),
            out_mult: 1,
        },
        ForgedRow {
            msg: 2,
            sponge_head: 64,
            chunk_head: 1,
            digest_of: 0,
            n_sponge_perms: p_minus_one,
            out_mult: 0,
        },
        ForgedRow {
            msg: 1,
            sponge_head: 32,
            chunk_head: 2,
            digest_of: 2,
            n_sponge_perms: Felt::from(2u8),
            out_mult: 0,
        },
    ];

    let mut node_rows: Vec<[Felt; NODE_W]> = Vec::new();
    let mut claimed_keccak = None;
    for row in &rows {
        let out = &outs[row.msg];
        let h_input = out.chunk_content_digest;
        let digest = &digest_chunks[row.digest_of];
        let len = len_u32(msgs[row.msg]);
        let keccak = eidos.require_one_shot(
            Keccak256Precompile::assert_frame(len),
            h_input.as_array(),
            digest.digest.as_array(),
        );
        let _ = eidos.require_digest(keccak.digest);
        if row.out_mult == 1 {
            claimed_keccak = Some(keccak.digest);
        }

        let mut cells = [Felt::ZERO; NODE_W];
        cells[COL_ACT] = Felt::ONE;
        cells[COL_SPONGE_SEQ_ID_HEAD] = Felt::from(row.sponge_head);
        cells[COL_N_SPONGE_PERMS] = row.n_sponge_perms;
        cells[COL_CHUNK_SEQ_ID_HEAD] = Felt::from(row.chunk_head);
        cells[COL_N_CHUNKS] = Felt::ONE;
        cells[COL_ABSORPTION_ID_CHUNKS] =
            Felt::from(out.chunk_content_absorption_span.head().as_u32());
        cells[COL_LEN_BYTES] = Felt::from(len);
        cells[COL_ABSORPTION_ID_DIGEST_CHUNKS] = Felt::from(digest.head().as_u32());
        cells[COL_ABSORPTION_ID_KECCAK] = Felt::from(keccak.head().as_u32());
        let d = outs[row.digest_of].keccak_digest.to_felts();
        cells[COL_D_BEGIN..COL_D_END].copy_from_slice(&d);
        cells[COL_H_INPUT_CHUNKS_BEGIN..COL_H_INPUT_CHUNKS_END]
            .copy_from_slice(&h_input.as_array());
        cells[COL_H_DIGEST_CHUNKS_BEGIN..COL_H_DIGEST_CHUNKS_END]
            .copy_from_slice(&digest.digest.as_array());
        cells[COL_H_KECCAK_BEGIN..COL_H_KECCAK_END].copy_from_slice(&keccak.digest.as_array());
        cells[COL_OUT_MULT] = Felt::from(row.out_mult);
        let remainder = (len.saturating_sub(1) % 32) as u8;
        cells[COL_LAST_CHUNK_REM] = Felt::from(remainder);
        cells[COL_N_CHUNKS_INV] = Felt::ONE;
        node_rows.push(cells);

        // The byte-pair LUT provides this row's chunk-remainder lookup and its in-range sponge
        // permutation checks; the out-of-range checks have no row to provide them.
        bpl.require(BytePairOp::Xor, remainder, 31 - remainder);
        for w in sponge_perm_range_checks(row.n_sponge_perms, Felt::from(len)) {
            if let Ok(w) = u16::try_from(w.as_canonical_u64()) {
                bpl.require_range16(w);
            }
        }
    }

    // Only row 0's binding enters the transcript.
    let claim = eval.issue_keccak(claimed_keccak.expect("row 0 provides its binding"), 0);
    let zero = eval.zero();
    let root = eval.record_and(zero, claim, &mut eidos);
    let root_hash = root.hash();

    let sponge_main = sponge_trace(sponge, 4);
    let height = sponge_main.height();
    let chunk_main = chunk_trace(chunk, height);
    assert_eq!(chunk_main.height(), height);

    let chunk_main = reorder_chunk_chains(chunk_main);
    let sponge_main = repin_sponge_chunk_ptrs(sponge_main);
    let cns = assemble_cns(&chunk_main, &node_rows, &sponge_main);

    let eval = eval_trace(eval, root);
    let round = round_trace(round, &mut bpl);
    let eidos = eidos_trace(eidos, &mut bpl);
    KeccakSide {
        cns,
        eidos,
        round,
        bpl: bpl_trace(bpl),
        eval,
        root: root_hash,
    }
}

/// Swap chunk rows 1 and 2 so the chunk band holds X, Z, Y, and continue the dead rows'
/// perm-cycle chain from the new last active row.
fn reorder_chunk_chains(mut m: RowMajorMatrix<Felt>) -> RowMajorMatrix<Felt> {
    for col in [chunk_cols::COL_ABSORPTION_ID]
        .into_iter()
        .chain(chunk_cols::COL_F_BEGIN..chunk_cols::COL_F_END)
    {
        m.values.swap(CHUNK_W + col, 2 * CHUNK_W + col);
    }
    for r in 0..3 {
        assert_eq!(m.values[r * CHUNK_W + chunk_cols::COL_IS_HEAD], Felt::ONE);
    }
    let last_active = m.values[2 * CHUNK_W + chunk_cols::COL_ABSORPTION_ID];
    for r in 3..m.height() {
        assert_eq!(m.values[r * CHUNK_W + chunk_cols::COL_ACT], Felt::ZERO);
        m.values[r * CHUNK_W + chunk_cols::COL_ABSORPTION_ID] =
            last_active + Felt::from((r - 2) as u32);
    }
    m
}

/// Re-pin each sponge invocation's chunk-tape base to the reordered chunk band: Y (rows 32..64)
/// reads chunk 2, Z (rows 64..) reads chunk 1. The chain is relaxed at both invocation seams.
fn repin_sponge_chunk_ptrs(mut m: RowMajorMatrix<Felt>) -> RowMajorMatrix<Felt> {
    let col = sponge_cols::COL_CHUNK_PTR;
    assert_eq!(m.values[32 * SPONGE_W + col], Felt::from(4u8));
    assert_eq!(m.values[64 * SPONGE_W + col], Felt::from(8u8));
    let four = Felt::from(4u8);
    for r in 32..64 {
        m.values[r * SPONGE_W + col] += four;
    }
    for r in 64..m.height() {
        m.values[r * SPONGE_W + col] -= four;
    }
    m
}

/// Interleave the chunk, forged node, and sponge bands into the merged chiplet's column layout.
fn assemble_cns(
    chunk: &RowMajorMatrix<Felt>,
    node_rows: &[[Felt; NODE_W]],
    sponge: &RowMajorMatrix<Felt>,
) -> RowMajorMatrix<Felt> {
    assert_eq!(NODE_COL_OFFSET, CHUNK_W);
    assert_eq!(SPONGE_COL_OFFSET, CHUNK_W + NODE_W);
    let height = sponge.height();
    let mut vals = Vec::with_capacity(height * CNS_COLS);
    for r in 0..height {
        vals.extend_from_slice(&chunk.values[r * CHUNK_W..(r + 1) * CHUNK_W]);
        match node_rows.get(r) {
            Some(cells) => vals.extend_from_slice(cells),
            None => vals.extend([Felt::ZERO; NODE_W]),
        }
        vals.extend_from_slice(&sponge.values[r * SPONGE_W..(r + 1) * SPONGE_W]);
    }
    RowMajorMatrix::new(vals, CNS_COLS)
}

fn node_cell(cns: &RowMajorMatrix<Felt>, row: usize, col: usize) -> Felt {
    cns.values[row * CNS_COLS + NODE_COL_OFFSET + col]
}

#[test]
fn multi_invocation_node_rows_cannot_read_another_invocations_digest() {
    let msgs = [M_X, M_Y, M_Z];

    // Honest session with the same three Keccak calls. It supplies every non-Keccak chiplet,
    // including the fixed uint and EC boundary state.
    let mut session = Session::new();
    let claims: Vec<_> = msgs.iter().map(|m| session.keccak(m).1).collect();
    let root = session.assert_and_fold(claims);
    let honest = session.finish(root);
    let s = honest.mains();

    // The replay reproduces the session's Keccak side bit for bit, so subtracting its byte-pair
    // demand isolates the demand of the other chiplets.
    let replay = honest_keccak_side(&msgs);
    assert_eq!(s[CNS].values, replay.cns.values, "replay chunk-node-sponge");
    assert_eq!(s[EIDOS].values, replay.eidos.values, "replay eidos");
    assert_eq!(s[ROUND].values, replay.round.values, "replay round");
    assert_eq!(s[EVAL].values, replay.eval.values, "replay eval");
    assert_eq!(honest.public_root(), replay.root, "replay root");

    let forged = forged_keccak_side(msgs);
    assert_eq!(forged.round.values, s[ROUND].values, "sponge and round work stays honest");

    // The byte-pair LUT provides the honest non-Keccak demand plus the forged Keccak side's demand,
    // every in-range check included, so only the out-of-range sponge-permutation checks stay
    // unprovided.
    let bpl_values: Vec<Felt> = s[BPL]
        .values
        .iter()
        .zip(&replay.bpl.values)
        .zip(&forged.bpl.values)
        .map(|((&total, &keccak_honest), &keccak_forged)| total - keccak_honest + keccak_forged)
        .collect();
    let bpl = RowMajorMatrix::new(bpl_values, s[BPL].width());

    // The statement is false: the transcript root is the deferred root of
    // `Keccak256Assert(M_X, keccak256(M_Y))`, and keccak256(M_X) != keccak256(M_Y).
    let d_x = keccak_felts(M_X);
    let d_y = keccak_felts(M_Y);
    assert_ne!(d_x, d_y);
    assert_eq!(forged.root, deferred_root_for_claim(M_X, d_y), "root asserts H(M_X) = H(M_Y)");
    assert_ne!(forged.root, deferred_root_for_claim(M_X, d_x), "root is not the honest claim");
    let d_row0: [Felt; 8] = core::array::from_fn(|i| node_cell(&forged.cns, 0, COL_D_BEGIN + i));
    assert_eq!(d_row0, d_y, "node row 0 binds M_X's chunks to D_Y");
    assert_eq!(node_cell(&forged.cns, 0, COL_LEN_BYTES), Felt::from(len_u32(M_X)));
    assert_eq!(node_cell(&forged.cns, 0, COL_OUT_MULT), Felt::ONE);
    assert_eq!(
        node_cell(&forged.cns, 1, COL_N_SPONGE_PERMS),
        Felt::new(P_MINUS_ONE).expect("p - 1 is canonical"),
    );

    // Without the sponge-permutation range checks this witness satisfies every local constraint of
    // every replaced chiplet.
    crate::tests::check_local(ChunkNodeSpongeAir, &forged.cns);
    crate::tests::check_local(EidosCompressionAir, &forged.eidos);
    crate::tests::check_local(KeccakRoundAir, &forged.round);
    crate::tests::check_local(BytePairLutAir, &bpl);
    crate::tests::check_local_inputs(
        TranscriptEvalAir,
        &forged.eval,
        forged.root.as_array().to_vec(),
    );

    // Control: the local check is not vacuous. The physical-order value n_sponge_perms = 1 on row 1
    // breaks the sponge-head continuity into row 2.
    let mut control = forged.cns.clone();
    control.values[CNS_COLS + NODE_COL_OFFSET + COL_N_SPONGE_PERMS] = Felt::ONE;
    crate::tests::assert_local_rejects(ChunkNodeSpongeAir, &control);

    // The out-of-range `Range16` values the forged rows request, predicted from their
    // `n_sponge_perms` and `len_bytes`.
    let forged_rows = [
        (Felt::from(2u8), Felt::from(len_u32(M_X))),
        (Felt::new(P_MINUS_ONE).expect("p - 1 is canonical"), Felt::from(len_u32(M_Z))),
        (Felt::from(2u8), Felt::from(len_u32(M_Y))),
    ];
    let mut expected_out_of_range: Vec<Felt> = Vec::new();
    for (n_sponge_perms, len_bytes) in forged_rows {
        for w in sponge_perm_range_checks(n_sponge_perms, len_bytes) {
            if u16::try_from(w.as_canonical_u64()).is_err() {
                expected_out_of_range.push(w);
            }
        }
    }
    assert_eq!(expected_out_of_range.len(), 4, "the forgery requests four out-of-range checks");

    // The full session stack closes except for those out-of-range `Range16` requests: nothing else
    // is left unbalanced.
    let replacements = [
        (CNS, &forged.cns),
        (EIDOS, &forged.eidos),
        (ROUND, &forged.round),
        (BPL, &bpl),
        (EVAL, &forged.eval),
    ];
    let mut rng = StdRng::seed_from_u64(0x3974);
    for _ in 0..3 {
        let challenges = Challenges::new(
            QuadFelt::new([Felt::from(rng.random::<u32>()), Felt::from(rng.random::<u32>())]),
            QuadFelt::new([Felt::from(rng.random::<u32>()), Felt::from(rng.random::<u32>())]),
            MAX_MESSAGE_WIDTH,
            NUM_BUS_IDS,
        );
        assert!(
            session_stack_residual_keyed(&s, &[], &challenges).is_empty(),
            "the honest stack balances",
        );
        let residual = session_stack_residual_keyed(&s, &replacements, &challenges);
        let expected: Vec<QuadFelt> = expected_out_of_range
            .iter()
            .map(|&w| Range16Msg { w }.encode(&challenges))
            .collect();
        assert_eq!(
            residual.len(),
            expected.len(),
            "only out-of-range range checks stay unbalanced: {residual:?}",
        );
        for (denom, mult, _) in &residual {
            assert!(
                expected.contains(denom),
                "every residual entry is a predicted Range16 message"
            );
            assert_eq!(*mult, Felt::ONE, "each out-of-range range check is requested once");
        }
    }
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
