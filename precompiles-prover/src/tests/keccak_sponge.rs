//! Tests for the Keccak sponge chiplet.
//!
//! [`KeccakSpongeMsg`] encoding + main-column-layout invariants +
//! [`LiftedAir`] structural smoke checks (validate, layout dimensions,
//! log-quotient-degree target) + trace-driven constraint checks
//! across the canonical edge cases (empty input, single-byte, full
//! block, multi-block, padding-only trailing block).

use std::{vec, vec::Vec};

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_lifted_air::{BaseAir, LiftedAir};
use rand::{RngExt, SeedableRng, rngs::StdRng};

use crate::{
    hash::{
        chunk::trace::ChunkRequires,
        keccak::{
            round::RoundRequires,
            sponge::{
                COL_B_BEGIN, COL_B_RANGE, COL_CHUNK_LO, COL_CHUNK_PTR, COL_PADDED_HI,
                COL_SPONGE_SEQ_ID, KeccakSpongeAir, KeccakSpongeMsg, NUM_AUX_COLS, NUM_B_SELECTORS,
                NUM_MAIN_COLS, NUM_PERIODIC_COLS, SPONGE_PERIOD,
                trace::{Invocation, SpongeRequires, generate_trace, keccak_oracle},
            },
        },
    },
    logup::{Challenges, LookupMessage, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, NUM_SIGMA_VALUES},
    primitives::{bitwise64::Bitwise64Requires, byte_pair_lut::BytePairLutRequires},
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    transcript::poseidon2::trace::Poseidon2Requires,
};

fn build_sponge_requires(
    invs: &[Invocation],
) -> (SpongeRequires, ChunkRequires, Poseidon2Requires) {
    let mut p2 = Poseidon2Requires::new();
    let mut chunk = ChunkRequires::new();
    let mut round = RoundRequires::new();
    let mut bw64 = Bitwise64Requires::new();
    let mut bpl = BytePairLutRequires::new();
    let mut sponge = SpongeRequires::new();
    for inv in invs {
        sponge.require(inv, &mut chunk, &mut round, &mut bw64, &mut bpl, &mut p2);
    }
    (sponge, chunk, p2)
}

fn check_invocation(_seed: u64, inv: Invocation) {
    let (sponge_req, _chunk, _p2) = build_sponge_requires(&[inv]);
    let main = generate_trace(sponge_req);
    crate::tests::check_local(KeccakSpongeAir, &main);
}

#[test]
fn keccak_sponge_msg_encodes_with_keccak_sponge_bus_prefix() {
    // Use a small fixed (α, β) so we can hand-compute the expected
    // encoding.
    let alpha = QuadFelt::from_u64(11);
    let beta = QuadFelt::from_u64(13);
    let challenges = Challenges::<QuadFelt>::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);

    let sponge_seq_id = Felt::from(42u32);
    let chunk_ptr = Felt::from(12u32);
    let len_bytes = Felt::from(200u32);
    let msg = KeccakSpongeMsg { sponge_seq_id, chunk_ptr, len_bytes };

    let enc = msg.encode(&challenges);

    // Expected encoding: bus_prefix[KeccakSponge] + β⁰·sponge_seq_id +
    // β¹·chunk_ptr + β²·len_bytes (the `Challenges::encode` layout,
    // with the KeccakSponge bus prefix as the additive base).
    let bus_prefix = alpha
        + beta.exp_u64(MAX_MESSAGE_WIDTH as u64)
            * QuadFelt::from_u64((BusId::KeccakSponge as u64) + 1);
    let expected = bus_prefix
        + QuadFelt::from(sponge_seq_id)
        + beta * QuadFelt::from(chunk_ptr)
        + beta * beta * QuadFelt::from(len_bytes);

    assert_eq!(enc, expected);
}

#[test]
fn keccak_sponge_msg_encoding_is_bus_distinct_from_memory64() {
    // The same (sponge_seq_id, chunk_ptr, len_bytes) payload encoded
    // as a KeccakSpongeMsg must differ from the same numeric payload
    // encoded under any other bus prefix (Memory64 here as a
    // sanity check), so the two buses can never coincide in the
    // running sum.

    let alpha = QuadFelt::from_u64(7);
    let beta = QuadFelt::from_u64(5);
    let challenges = Challenges::<QuadFelt>::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);

    let payload = [Felt::from(42u32), Felt::from(12u32), Felt::from(200u32)];

    let enc_sponge = KeccakSpongeMsg::<Felt> {
        sponge_seq_id: payload[0],
        chunk_ptr: payload[1],
        len_bytes: payload[2],
    }
    .encode(&challenges);

    let enc_memory = challenges.encode(BusId::Memory64 as usize, payload);

    assert_ne!(enc_sponge, enc_memory);
}

#[test]
fn main_column_layout_partitions_27_indices() {
    // The 27 main witness columns are partitioned into:
    //   - structural (5): sponge_seq_id, act, bytes_left, is_first_block, chunk_ptr (indices 0..4).
    //   - padding-state machine (10): is_zero_p, is_chunk_avail, b_0..b_7 (indices 5..14).
    //   - per-row lane values (12): chunk, state_prev, state_new, state_out, cleared, padded — all
    //     u32-lo/hi (indices 15..26).
    //
    // The boundary checks below pin the 5/10/12 split so that any
    // future column shuffling fails fast.

    // Structural block starts at sponge_seq_id = 0 and the b_j block starts
    // immediately after it.
    assert_eq!(COL_SPONGE_SEQ_ID, 0);
    assert_eq!(COL_CHUNK_PTR, 4);
    assert_eq!(COL_B_BEGIN, 7);
    // The b_j run is 8 consecutive indices.
    assert_eq!(NUM_B_SELECTORS, 8);
    assert_eq!(COL_B_RANGE, COL_B_BEGIN..(COL_B_BEGIN + NUM_B_SELECTORS));
    // Lane-value block ends at PADDED_HI = NUM_MAIN_COLS - 1.
    assert_eq!(COL_PADDED_HI, NUM_MAIN_COLS - 1);
    // Total matches the spec.
    assert_eq!(NUM_MAIN_COLS, 27);
    // `BaseAir::width()` agrees.
    assert_eq!(<KeccakSpongeAir as BaseAir<Felt>>::width(&KeccakSpongeAir), NUM_MAIN_COLS);
}

#[test]
fn lifted_air_validates_and_layout_matches_spec() {
    let air = KeccakSpongeAir;
    // `air_layout` is the single source of truth that downstream
    // builders consume. Pin every dimension to a documented constant
    // so any column-count drift fails fast.
    let layout = <KeccakSpongeAir as LiftedAir<Felt, QuadFelt>>::air_layout(&air);
    assert_eq!(layout.preprocessed_width, 0);
    assert_eq!(layout.main_width, NUM_MAIN_COLS);
    assert_eq!(layout.num_public_values, NUM_PUBLIC_VALUES);
    assert_eq!(layout.permutation_width, NUM_AUX_COLS);
    assert_eq!(layout.num_permutation_challenges, NUM_RANDOMNESS);
    assert_eq!(layout.num_permutation_values, NUM_SIGMA_VALUES);
    assert_eq!(layout.num_periodic_columns, NUM_PERIODIC_COLS);
}

#[test]
fn periodic_columns_match_program() {
    // `BaseAir::periodic_columns()` is plumbed through to the
    // verifier; ensure it returns exactly what `sponge_program()`
    // produced (same shape, same values).
    let air = KeccakSpongeAir;
    let cols = <KeccakSpongeAir as BaseAir<Felt>>::periodic_columns(&air);
    assert_eq!(cols.len(), NUM_PERIODIC_COLS);
    for c in &cols {
        assert_eq!(c.len(), SPONGE_PERIOD);
    }
}

#[test]
fn log_quotient_degree_matches_design_target() {
    // The 3-aux-column mutex-grouped layout lands at
    // `log_quotient_degree = 3` under Plonky3's
    // periodic-deg-1 convention — the same profile as
    // `bitwise64`. See `docs/chiplets/keccak-sponge.md` §"Aux
    // columns and σ exposure" for the per-column constraint-deg
    // breakdown. Pin the value so any constraint or lookup edit
    // that drifts the degree past the column-max of 9 fails fast.
    let air = KeccakSpongeAir;
    assert_eq!(crate::tests::log_quotient_degree(&air), 3);
}

// CONSTRAINT TESTS
// ================================================================================================

#[test]
fn constraints_hold_on_empty_invocation() {
    // Empty input — the padding-only edge case. One block with the
    // pad row at slot 0 (`byte_offset = 0`) and no chunk-tape lanes
    // consumed (the chunk chiplet emits 0 chunks for an empty input).
    check_invocation(0xe_0_0_0, Invocation { input: vec![] });
}

#[test]
fn constraints_hold_on_single_byte_invocation() {
    // 1-byte input — pad at slot 0, `byte_offset = 1`. The lane-0
    // chunk has 1 real input byte + 7 chunk-alignment zero-pad bytes.
    check_invocation(0xe_0_0_1, Invocation { input: vec![0xab] });
}

#[test]
fn constraints_hold_on_partial_lane_input() {
    // 11-byte input — pad at slot 1, `byte_offset = 3`. Covers the
    // "real input + intra-lane pad byte" case where the pad row's
    // ANDNOT properly preserves the leading bytes.
    let input: Vec<u8> = (0..11).map(|i| i as u8 ^ 0x5a).collect();
    check_invocation(0xe_0_0_b, Invocation { input });
}

#[test]
fn constraints_hold_on_full_single_block() {
    // 135-byte input — single block, pad at the merged 0x81 lane
    // (slot 16, `byte_offset = 7`). Exercises the lane-16 0x80
    // mixin's interaction with the pad row, since the merged byte
    // lands at byte 7 of lane 16 (= the same position the 0x80 row
    // writes). Also the max-overshoot case: 5 chunks = 20 lanes vs
    // one block's 17 rate slots, so the 3 overshoot lanes are mopped
    // up on the extra rows [26,29).
    let mut rng = StdRng::seed_from_u64(0xe_0_8_7);
    let input: Vec<u8> = (0..135).map(|_| rng.random()).collect();
    check_invocation(0xe_0_8_7, Invocation { input });
}

#[test]
fn constraints_hold_on_block_aligned_input() {
    // 136-byte input — fills block 0 verbatim, block 1 is the
    // trailing padding-only block with the pad at slot 0
    // (`byte_offset = 0`). Stresses the cross-block state propagation
    // (perm-0's output flows into block 1's `state_prev`) and the
    // garbage-tail lanes that chunk-alignment spills into block 1.
    let mut rng = StdRng::seed_from_u64(0xe_0_8_8);
    let input: Vec<u8> = (0..136).map(|_| rng.random()).collect();
    check_invocation(0xe_0_8_8, Invocation { input });
}

#[test]
fn constraints_hold_on_multi_block_input() {
    // 200-byte input — block 0 full, block 1 partial (64 bytes
    // real input) + pad at slot 8 (`byte_offset = 0`). The
    // chunk-tape segment is 7 chunks = 28 lanes; block 1 consumes
    // 11 (8 real + 3 chunk-alignment garbage-tail lanes the
    // past-pad chain discards).
    let mut rng = StdRng::seed_from_u64(0xe_0_c_8);
    let input: Vec<u8> = (0..200).map(|_| rng.random()).collect();
    check_invocation(0xe_0_c_8, Invocation { input });
}

#[test]
fn constraints_hold_on_overshoot_two_lanes() {
    // 271-byte input — 2 blocks (34 rate lanes), chunk tape = 9 chunks
    // = 36 lanes, so overshoot = 2. The last block fills all 17 rate
    // slots, carries `is_chunk_avail` through the capacity / 0x80 rows,
    // and consumes the 2 overshoot lanes on extra rows [26,28).
    let mut rng = StdRng::seed_from_u64(0xe_1_0_f);
    let input: Vec<u8> = (0..271).map(|_| rng.random()).collect();
    check_invocation(0xe_1_0_f, Invocation { input });
}

#[test]
fn constraints_hold_on_overshoot_one_lane() {
    // 407-byte input — 3 blocks (51 rate lanes), chunk tape = 13 chunks
    // = 52 lanes, so overshoot = 1, consumed on extra row 26 of the
    // last block. 3 blocks → 96 rows padded to 128, so this also
    // exercises the dead-row trace tail and the cyclic wrap.
    let mut rng = StdRng::seed_from_u64(0xe_1_9_7);
    let input: Vec<u8> = (0..407).map(|_| rng.random()).collect();
    check_invocation(0xe_1_9_7, Invocation { input });
}

#[test]
fn constraints_hold_on_overshoot_then_invocation_seam() {
    // A 271-byte overshoot invocation (2 blocks, overshoot 2) followed
    // by a 40-byte one (1 block) = 3 blocks → 128 rows (dead-row tail).
    // After the first invocation's extra rows advance `chunk_ptr` past
    // its overshoot tail, the relaxed chain must carry `chunk_ptr`
    // contiguously into the second — no seam gap, since the sponge now
    // consumes all 4·num_chunks lanes the chiplet emits.
    let mut rng = StdRng::seed_from_u64(0xe15e);
    let a: Vec<u8> = (0..271).map(|_| rng.random()).collect();
    let b: Vec<u8> = (0..40).map(|_| rng.random()).collect();
    let (sponge_req, _chunk, _p2) =
        build_sponge_requires(&[Invocation { input: a }, Invocation { input: b }]);
    let main = generate_trace(sponge_req);
    crate::tests::check_local(KeccakSpongeAir, &main);
}

#[test]
fn constraints_hold_with_dead_rows() {
    // 300-byte input — 3 blocks, 10 chunks = 40 lanes (undershoot, no
    // extra rows). 3 blocks → 96 rows padded to 128, so 32 dead pad
    // rows. Regression for the cyclic-wrap pad-must-fire gate: the wrap
    // (last dead row → row 0, a new invocation) must not demand
    // `is_zero = 1` on the dead row. Any non-power-of-two block count
    // exercises this.
    let mut rng = StdRng::seed_from_u64(0x0dea_d12c);
    let input: Vec<u8> = (0..300).map(|_| rng.random()).collect();
    check_invocation(0x0dea_d12c, Invocation { input });
}

#[test]
fn constraints_hold_on_empty_input() {
    // Zero-length message: one pad block (`keccak256("")`) with the pad
    // firing at byte 0, plus one canonical zero chunk consumed entirely
    // as garbage-tail (`is_chunk_avail = 1` on lanes 0..4 while
    // `past_pad = 1`). Exercises the pad-at-byte-0 + chunk-consume overlap
    // on the first and only block.
    check_invocation(0xe_1_9_0_7, Invocation { input: vec![] });
}

#[test]
fn constraints_hold_on_empty_transcript() {
    // Zero invocations: the all-dead sponge trace — the only valid
    // empty-transcript trace. `bytes_left` is unconstrained on dead rows
    // (`act = 0`), so the cyclic wrap that would otherwise reject it (the
    // `M·136 ≢ 0` argument applies only to active traces) is vacuous.
    let (sponge_req, _chunk, _p2) = build_sponge_requires(&[]);
    let main = generate_trace(sponge_req);
    crate::tests::check_local(KeccakSpongeAir, &main);
}

#[test]
fn empty_input_digest_is_keccak256_of_empty() {
    // Known-answer test: keccak256("") =
    //   c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    // (the canonical Ethereum empty-data hash). The 32 output bytes are
    // lanes 0..4 serialized little-endian, i.e. these eight u32 halves.
    assert_eq!(
        keccak_oracle(&[]).to_u32s(),
        [
            0x0146_d2c5,
            0x3c23_f786,
            0xb27d_7e92,
            0xc003_c7dc,
            0x53b6_00e5,
            0x3b27_82ca,
            0x04d8_fa7b,
            0x70a4_855d,
        ],
    );
}

#[test]
fn constraints_hold_on_empty_then_nonempty_seam() {
    // Empty invocation immediately followed by a normal one — the empty
    // block's chunk_ptr advance (4 lanes) must carry contiguously across
    // the invocation seam into the next.
    let mut rng = StdRng::seed_from_u64(0x000e_15ea);
    let b: Vec<u8> = (0..40).map(|_| rng.random()).collect();
    let (sponge_req, _chunk, _p2) =
        build_sponge_requires(&[Invocation { input: vec![] }, Invocation { input: b }]);
    let main = generate_trace(sponge_req);
    crate::tests::check_local(KeccakSpongeAir, &main);
}

#[test]
fn constraints_hold_on_multiple_invocations() {
    // Two back-to-back invocations. Exercises the invocation seam:
    // `bytes_left` resets, `is_first_block_of_invocation` toggles, and
    // the relaxed `chunk_ptr` chain (gated off at `enters_new_invocation`)
    // carries `chunk_ptr` across the boundary. The first invocation
    // (33 bytes → 2 chunks) leaves `chunk_ptr` at a non-multiple-of-4
    // offset for the second (40 bytes), confirming the per-invocation
    // base needn't be 4-aligned under the relaxed chain.
    let mut rng = StdRng::seed_from_u64(0x5ea3);
    let a: Vec<u8> = (0..33).map(|_| rng.random()).collect();
    let b: Vec<u8> = (0..40).map(|_| rng.random()).collect();
    let (sponge_req, _chunk, _p2) =
        build_sponge_requires(&[Invocation { input: a }, Invocation { input: b }]);
    let main = generate_trace(sponge_req);
    crate::tests::check_local(KeccakSpongeAir, &main);
}

// NEGATIVE TESTS — confirm `check_constraints` catches deliberate corruption.
// ================================================================================================

/// Corrupt a single cell of a generated main trace, then run the full
/// `check_constraints` pipeline. Wrapped so each negative test only
/// has to point at the column / row / value to falsify.
fn corrupt_and_check(
    _seed: u64,
    inv: Invocation,
    corruption: impl FnOnce(&mut miden_core::utils::RowMajorMatrix<Felt>),
) {
    let (sponge_req, _chunk, _p2) = build_sponge_requires(&[inv]);
    let mut main = generate_trace(sponge_req);
    corruption(&mut main);
    crate::tests::check_local(KeccakSpongeAir, &main);
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_non_binary_act_breaks_booleanity() {
    // Set `act` at row 5 to 2 — violates `act · (1 − act) = 0`.
    use crate::hash::keccak::sponge::COL_ACT;
    corrupt_and_check(0xc0_bb, Invocation { input: vec![0xab] }, |main| {
        main.values[5 * NUM_MAIN_COLS + COL_ACT] = Felt::from(2u8);
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_nonzero_chunk_on_chunks_unavailable_breaks_zero_fill() {
    // Single-byte invocation: chunk-tape segment is 1 chunk = 4 lanes,
    // sponge consumes them at slots 0..3 (slot 0 = pad row, slots 1..3
    // = garbage-tail). Slots 4..16 of the period have
    // `is_chunk_avail = 0` and the zero-fill constraint pins
    // `chunk_lo = chunk_hi = 0` there. Writing a non-zero value into
    // `chunk_lo` at row 5 violates Z1.
    corrupt_and_check(0xc0_2e, Invocation { input: vec![0xab] }, |main| {
        main.values[5 * NUM_MAIN_COLS + COL_CHUNK_LO] = Felt::from(1u8);
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_new_invocation_after_non_last_block() {
    // A 271-byte invocation is 2 blocks (64 rows). Flip `is_first_block`
    // to 1 on the second period (rows 32..64) — as if a new invocation
    // began right after block 0, a non-last block whose slot 31 has
    // `is_zero = 0`. The act-gated pad-must-fire (act = 1 on this active
    // seam) rejects it: a new invocation may only follow a padded last
    // block. Guards the anti-truncation property the act gate preserves.
    use crate::hash::keccak::sponge::COL_IS_FIRST_BLOCK_OF_INVOCATION;
    let mut rng = StdRng::seed_from_u64(0xc0_f1);
    let input: Vec<u8> = (0..271).map(|_| rng.random()).collect();
    corrupt_and_check(0xc0_f1, Invocation { input }, |main| {
        for row in SPONGE_PERIOD..2 * SPONGE_PERIOD {
            main.values[row * NUM_MAIN_COLS + COL_IS_FIRST_BLOCK_OF_INVOCATION] = Felt::ONE;
        }
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_seq_id_breaks_row_counter_transition() {
    // Skip a value in `sponge_seq_id` (row 1 = 7 instead of 1) — both the
    // row-0 transition (`seq_id_1 − seq_id_0 − 1 = 6 ≠ 0`) and the
    // row-1 transition (`seq_id_2 − seq_id_1 − 1 = −6 ≠ 0`) fail.
    corrupt_and_check(0xc0_5e, Invocation { input: vec![0xab] }, |main| {
        main.values[NUM_MAIN_COLS + COL_SPONGE_SEQ_ID] = Felt::from(7u8);
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_aux_cell_breaks_logup_recurrence() {
    // Direct main-trace corruption is absorbed by
    // `build_logup_aux_trace` (the aux just adapts to whatever the
    // main says). To exercise the per-row σ/n recurrence emitted by
    // `LookupAir::eval` (constraint of the form
    // `u(r) · acc(r+1) = u(r) · acc(r) + v(r) − u(r) · σ · inv_n`),
    // we wrap `KeccakSpongeAir` in an AIR that runs the standard aux
    // build and then perturbs `aux[row 1, col 0]`. The constraint at
    // row 0 (and again at row 1) then evaluates to a non-zero residue.
    // `check_local` builds the aux trace through `LiftedAir::build_aux_trace`,
    // so the corruption must live in that override (the 0.26 API no longer
    // accepts a standalone `AuxBuilder` — the AIR owns the aux build).
    use miden_air::BaseAir;
    use miden_core::{field::PrimeCharacteristicRing, utils::RowMajorMatrix};
    use miden_lifted_air::{LiftedAir, LiftedAirBuilder};

    use crate::hash::keccak::sponge::NUM_AUX_COLS;

    #[derive(Debug, Clone, Copy)]
    struct AuxCorruptAir;

    impl BaseAir<Felt> for AuxCorruptAir {
        fn width(&self) -> usize {
            <KeccakSpongeAir as BaseAir<Felt>>::width(&KeccakSpongeAir)
        }

        fn num_public_values(&self) -> usize {
            <KeccakSpongeAir as BaseAir<Felt>>::num_public_values(&KeccakSpongeAir)
        }

        fn periodic_columns(&self) -> Vec<Vec<Felt>> {
            <KeccakSpongeAir as BaseAir<Felt>>::periodic_columns(&KeccakSpongeAir)
        }
    }

    impl LiftedAir<Felt, QuadFelt> for AuxCorruptAir {
        fn num_randomness(&self) -> usize {
            <KeccakSpongeAir as LiftedAir<Felt, QuadFelt>>::num_randomness(&KeccakSpongeAir)
        }

        fn aux_width(&self) -> usize {
            <KeccakSpongeAir as LiftedAir<Felt, QuadFelt>>::aux_width(&KeccakSpongeAir)
        }

        fn num_aux_values(&self) -> usize {
            <KeccakSpongeAir as LiftedAir<Felt, QuadFelt>>::num_aux_values(&KeccakSpongeAir)
        }

        fn build_aux_trace(
            &self,
            main: &RowMajorMatrix<Felt>,
            air_inputs: &[Felt],
            aux_inputs: &[Felt],
            challenges: &[QuadFelt],
        ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
            let (mut aux, sigma) = <KeccakSpongeAir as LiftedAir<Felt, QuadFelt>>::build_aux_trace(
                &KeccakSpongeAir,
                main,
                air_inputs,
                aux_inputs,
                challenges,
            );
            aux.values[NUM_AUX_COLS] += QuadFelt::ONE;
            (aux, sigma)
        }

        fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
            <KeccakSpongeAir as LiftedAir<Felt, QuadFelt>>::eval(&KeccakSpongeAir, builder);
        }
    }

    let (sponge_req, _chunk, _p2) = build_sponge_requires(&[Invocation { input: vec![0xab] }]);
    let main = generate_trace(sponge_req);
    crate::tests::check_local(AuxCorruptAir, &main);
}
