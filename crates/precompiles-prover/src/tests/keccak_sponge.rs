//! Tests for the Keccak sponge chiplet.
//!
//! [`KeccakSpongeMsg`] encoding + main-column-layout invariants +
//! [`LiftedAir`] structural smoke checks (validate, layout dimensions,
//! log-quotient-degree target) + trace-driven constraint checks
//! across the canonical edge cases (empty input, single-byte, full
//! block, multi-block, padding-only trailing block).

use std::{borrow::Cow, vec, vec::Vec};

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_crypto::hash::keccak::Keccak256;
use miden_stark::{
    air::{BaseAir, ConstraintDegrees, LiftedAir},
    lookup::debug::{ValidateLayout, ValidateLookupAir},
};
use rand::{RngExt, SeedableRng, rngs::StdRng};

use crate::{
    hash::{
        chunk::trace::ChunkRequires,
        keccak::{
            round::RoundRequires,
            sponge::{
                CHUNK_BYTES_RANGE, COL_CHUNK_PTR, COL_IS_CHUNK_AVAIL, COL_IS_PAD_BLOCK,
                COL_OFFSET_PRODUCT, COL_PAD_HI, COL_PAD_LO, COL_SPONGE_SEQ_ID, COL_STATE_OUT_HI,
                COL_STATE_OUT_LO, KeccakSpongeAir, KeccakSpongeMsg, NUM_AUX_COLS, NUM_MAIN_COLS,
                NUM_PERIODIC_COLS, OFFSET_BITS_RANGE, SPONGE_PERIOD, STATE_NEW_BYTES_RANGE,
                STATE_PREV_BYTES_RANGE,
                trace::{Invocation, SpongeRequires, generate_trace, keccak_oracle},
            },
        },
    },
    logup::{Challenges, LookupMessage, NUM_LOGUP_VALUES, NUM_RANDOMNESS},
    primitives::byte_pair_lut::BytePairLutRequires,
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    session::{ChipletAir, Session},
    tests::bus_balance::session_stack_residual,
    transcript::eidos::trace::EidosRequires,
};

fn build_sponge_requires(invs: &[Invocation]) -> (SpongeRequires, ChunkRequires, EidosRequires) {
    let mut eidos = EidosRequires::new();
    let mut chunk = ChunkRequires::new();
    let mut round = RoundRequires::new();
    let mut bpl = BytePairLutRequires::new();
    let mut sponge = SpongeRequires::new();
    for inv in invs {
        sponge.require(inv, &mut chunk, &mut round, &mut bpl, &mut eidos);
    }
    (sponge, chunk, eidos)
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
fn main_column_layout_matches_sponge_band() {
    // The 40 main witness columns are partitioned into these half-open ranges:
    // - Structural (5): sponge_seq_id through chunk_ptr, 0..5.
    // - Padding state (9): flags, offset bits and their product, and suffix limbs, 5..14.
    // - Squeeze value (2): state_out as u32 lo/hi, 14..16.
    // - Byte lanes (24): chunk, state_prev, state_new, each eight little-endian bytes, 16..40.
    //
    // Pin these boundaries so a layout change cannot silently shift a neighboring group.
    assert_eq!(COL_SPONGE_SEQ_ID, 0);
    assert_eq!(COL_CHUNK_PTR, 4);
    assert_eq!(COL_IS_PAD_BLOCK, 7);
    assert_eq!(OFFSET_BITS_RANGE, 8..11);
    assert_eq!(COL_OFFSET_PRODUCT, 11);
    assert_eq!(COL_PAD_LO, 12);
    assert_eq!(COL_PAD_HI, 13);
    assert_eq!(COL_STATE_OUT_LO, 14);
    assert_eq!(COL_STATE_OUT_HI, 15);
    assert_eq!(CHUNK_BYTES_RANGE, 16..24);
    assert_eq!(STATE_PREV_BYTES_RANGE, 24..32);
    assert_eq!(STATE_NEW_BYTES_RANGE, 32..40);
    // Total matches the spec.
    assert_eq!(NUM_MAIN_COLS, 40);
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
    assert_eq!(layout.num_public_values, 0);
    assert_eq!(layout.permutation_width, NUM_AUX_COLS);
    assert_eq!(layout.num_permutation_challenges, NUM_RANDOMNESS);
    assert_eq!(layout.num_permutation_values, NUM_LOGUP_VALUES);
    assert_eq!(layout.num_periodic_columns, NUM_PERIODIC_COLS);
    assert_eq!(NUM_AUX_COLS, 5);
    assert_eq!(crate::tests::lookup_column_shape(&air), &[3, 3, 4, 4, 2]);

    assert_eq!(
        ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air),
        ConstraintDegrees { base: 5, ext: 5 },
    );
    ValidateLookupAir::validate(
        &air,
        ValidateLayout {
            preprocessed_width: air.preprocessed_width(),
            trace_width: air.width(),
            num_public_values: 0,
            num_periodic_columns: air.periodic_columns().len(),
            permutation_width: NUM_AUX_COLS,
            num_permutation_challenges: NUM_RANDOMNESS,
            num_permutation_values: NUM_LOGUP_VALUES,
        },
    )
    .unwrap_or_else(|err| panic!("KeccakSpongeAir lookup validation failed: {err}"));
}

#[test]
fn periodic_columns_match_program() {
    // `BaseAir::periodic_columns()` is plumbed through to the
    // verifier; ensure it returns exactly what `sponge_program()`
    // produced (same shape, same values).
    let air = KeccakSpongeAir;
    let cols = <KeccakSpongeAir as BaseAir<Felt>>::periodic_columns(&air);
    assert_eq!(cols.len(), NUM_PERIODIC_COLS);
    for c in cols.iter() {
        assert_eq!(c.len(), SPONGE_PERIOD);
    }
}

#[test]
fn log_quotient_degree_matches_design_target() {
    // Four XOR fractions share each byte column. The input-handshake/chunk column also closes
    // within degree five, preserving log_quotient_degree = 2.
    let air = KeccakSpongeAir;
    assert_eq!(crate::tests::log_quotient_degree(&air), 2);
}

// CONSTRAINT TESTS
// ================================================================================================

#[test]
fn constraints_hold_on_empty_invocation() {
    // Empty input has one padding block. Its pad row is at slot 0,
    // and the first four rate rows consume the canonical zero chunk.
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
    // 11-byte input — pad at slot 1, `byte_offset = 3`. Suffix insertion preserves the three
    // leading input bytes in the pad lane.
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
    // `is_chunk_avail = 0` and the zero-fill constraint pins the reconstructed
    // chunk halves to zero there. Writing a non-zero byte at row 5 violates it.
    corrupt_and_check(0xc0_2e, Invocation { input: vec![0xab] }, |main| {
        main.values[5 * NUM_MAIN_COLS + CHUNK_BYTES_RANGE.start] = Felt::from(1u8);
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_new_invocation_after_non_last_block() {
    // A 271-byte invocation needs two blocks. Starting a new invocation at the second block
    // would truncate the first one before padding. The active-successor constraint rejects it.
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
    // Rebuilding the auxiliary trace after main-trace corruption produces a consistent witness.
    // Perturbing the built accumulator instead directly exercises the centered recurrence.
    // `check_local` obtains the auxiliary trace through `LiftedAir::build_aux_trace`, so the test
    // wrapper overrides that method to inject the corruption.
    use miden_air::BaseAir;
    use miden_core::{field::PrimeCharacteristicRing, utils::RowMajorMatrix};
    use miden_stark::air::{LiftedAir, LiftedAirBuilder};

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

        fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
            Cow::Owned(
                <KeccakSpongeAir as BaseAir<Felt>>::periodic_columns(&KeccakSpongeAir).into_owned(),
            )
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
            let (mut aux, normalized_sum) =
                <KeccakSpongeAir as LiftedAir<Felt, QuadFelt>>::build_aux_trace(
                    &KeccakSpongeAir,
                    main,
                    air_inputs,
                    aux_inputs,
                    challenges,
                );
            aux.values[NUM_AUX_COLS] += QuadFelt::ONE;
            (aux, normalized_sum)
        }

        fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
            <KeccakSpongeAir as LiftedAir<Felt, QuadFelt>>::eval(&KeccakSpongeAir, builder);
        }
    }

    let (sponge_req, _chunk, _p2) = build_sponge_requires(&[Invocation { input: vec![0xab] }]);
    let main = generate_trace(sponge_req);
    crate::tests::check_local(AuxCorruptAir, &main);
}

#[test]
fn suffix_limbs_are_pinned_on_absorption_padding_and_lane16_rows() {
    // A 200-byte message pads at lane 8 of its second block; slot 25 applies the trailing 0x80.
    let honest = single_invocation_trace(vec![0x5a; 200]);
    crate::tests::check_local(KeccakSpongeAir, &honest);
    for row in [0, SPONGE_PERIOD + 8, SPONGE_PERIOD + 25] {
        for column in [COL_PAD_LO, COL_PAD_HI] {
            let mut main = honest.clone();
            main.values[row * NUM_MAIN_COLS + column] += Felt::ONE;
            crate::tests::assert_local_rejects(KeccakSpongeAir, &main);
        }
    }
}

#[test]
fn padding_covers_every_lane_offset_and_matches_independent_keccak() {
    // Cover every position in a rate block, the extra padding block, and overshoot seams.
    for len in (0..=137).chain([271, 272, 273, 407]) {
        let input: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
        let expected = Keccak256::hash(&input);
        let mut requires = SpongeRequires::new();
        let out = requires.require(
            &Invocation { input: input.clone() },
            &mut ChunkRequires::new(),
            &mut RoundRequires::new(),
            &mut BytePairLutRequires::new(),
            &mut EidosRequires::new(),
        );
        assert_eq!(
            out.keccak_digest.to_u32s(),
            core::array::from_fn(|i| {
                u32::from_le_bytes(expected.as_bytes()[4 * i..4 * i + 4].try_into().unwrap())
            }),
            "input length {len}",
        );
        let main = generate_trace(requires);
        let pad_row = (len / 136) * SPONGE_PERIOD + (len % 136) / 8;
        let offset = len % 8;
        for byte in 0..8 {
            let expected_byte = if byte < offset {
                input[len - offset + byte]
            } else {
                u8::from(byte == offset)
            };
            assert_eq!(
                main.values[pad_row * NUM_MAIN_COLS + CHUNK_BYTES_RANGE.start + byte],
                Felt::from(expected_byte),
                "input length {len}, byte {byte}",
            );
        }
        crate::tests::check_local(KeccakSpongeAir, &main);
    }
}

#[test]
fn padding_records_only_state_xor_requests() {
    for len in [0, 1, 7, 8, 134, 135, 136, 137, 271, 407] {
        let mut bpl = BytePairLutRequires::new();
        SpongeRequires::new().require(
            &Invocation { input: vec![0xa5; len] },
            &mut ChunkRequires::new(),
            &mut RoundRequires::new(),
            &mut bpl,
            &mut EidosRequires::new(),
        );
        let requests: u64 = (0..=u8::MAX)
            .flat_map(|a| (0..=u8::MAX).map(move |b| (a, b)))
            .map(|(a, b)| u64::from(bpl.multiplicity_canonical_xor(a, b)))
            .sum();
        // Full input lanes, the leading pad lane, and the final lane-16 suffix each use eight
        // canonical XOR requests. Local padding constraints reconstruct the raw input bytes.
        assert_eq!(requests, 8 * (len as u64 / 8 + 2), "input length {len}");
    }
}

#[test]
fn padding_suffix_and_tail_bytes_are_pinned_at_every_offset() {
    // Padding must reject these edits locally, even with auxiliary traces rebuilt from the
    // forged main trace; rejection must not depend on cross-chiplet lookup balance.
    for offset in 0..8 {
        let main = single_invocation_trace(vec![0xa5; offset]);
        crate::tests::check_local(KeccakSpongeAir, &main);
        for byte in offset..8 {
            let mut forged = main.clone();
            forged.values[CHUNK_BYTES_RANGE.start + byte] += Felt::ONE;
            crate::tests::assert_local_rejects(KeccakSpongeAir, &forged);
        }
    }
}

#[test]
fn compact_offset_bits_and_product_are_constrained() {
    let main = single_invocation_trace(vec![0x5a]);
    crate::tests::check_local(KeccakSpongeAir, &main);
    for column in OFFSET_BITS_RANGE.chain(core::iter::once(COL_OFFSET_PRODUCT)) {
        let mut forged = main.clone();
        for row in forged.values.as_chunks_mut::<NUM_MAIN_COLS>().0 {
            row[column] = Felt::from_u8(2);
        }
        crate::tests::assert_local_rejects(KeccakSpongeAir, &forged);
    }
}

#[test]
fn noncanonical_prefix_digits_preserving_packed_words_fail_global_byte_checks() {
    use crate::hash::chunk_node_sponge::{ChunkNodeSpongeAir, SPONGE_COL_OFFSET};

    let mut session = Session::new();
    let (_, claim) = session.keccak(&[0x5a; 7]);
    let root = session.assert_and_fold([claim]);
    let traces = session.finish(root);
    traces.check();
    let mains = traces.mains();
    let challenges = Challenges::new(
        QuadFelt::from_u32(7),
        QuadFelt::from_u32(13),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    let index = ChipletAir::all()
        .into_iter()
        .position(|air| air == ChipletAir::ChunkNodeSponge)
        .unwrap();
    assert!(session_stack_residual(&mains, &[], &challenges).is_empty());
    let start = SPONGE_COL_OFFSET + CHUNK_BYTES_RANGE.start;
    let expected = crate::utils::halves_le::<Felt, _>(&mains[index].values[start..start + 8], 256);
    for byte in 0..6 {
        let mut forged = mains[index].clone();
        forged.values[start + byte] += Felt::from_u16(256);
        if byte % 4 < 3 {
            forged.values[start + byte + 1] -= Felt::ONE;
        } else {
            forged.values[start + byte - 1] -= Felt::from_u32(65_536);
        }
        // These aliases lie before the suffix and preserve both u32 halves. The local padding
        // equations still hold, so the canonical XOR lookup must reject the forged digits.
        assert_eq!(
            crate::utils::halves_le::<Felt, _>(&forged.values[start..start + 8], 256),
            expected
        );
        crate::tests::check_local(ChunkNodeSpongeAir, &forged);
        assert!(!session_stack_residual(&mains, &[(index, &forged)], &challenges).is_empty());
    }
}

#[test]
fn dead_padding_state_remains_bus_inert() {
    use crate::hash::chunk_node_sponge::{ChunkNodeSpongeAir, SPONGE_COL_OFFSET};

    let mut session = Session::new();
    let (_, claim) = session.keccak(&[0x5a; 300]);
    let root = session.assert_and_fold([claim]);
    let traces = session.finish(root);
    traces.check();
    let mains = traces.mains();
    let index = ChipletAir::all()
        .into_iter()
        .position(|air| air == ChipletAir::ChunkNodeSponge)
        .unwrap();
    let mut decorated = mains[index].clone();
    let width = decorated.width;
    assert_eq!(decorated.values.len() / width, 128);
    for slot in 0..SPONGE_PERIOD {
        let start = (96 + slot) * width + SPONGE_COL_OFFSET;
        assert_eq!(decorated.values[start + crate::hash::keccak::sponge::COL_ACT], Felt::ZERO);
        for bit in OFFSET_BITS_RANGE {
            assert_eq!(decorated.values[start + bit], Felt::ZERO);
        }
    }
    // Unused digits can cancel in a packed zero lane. They must not create byte-table demands.
    let cell = 96 * width + SPONGE_COL_OFFSET + CHUNK_BYTES_RANGE.start;
    decorated.values[cell] = Felt::from_u16(256);
    decorated.values[cell + 1] = -Felt::ONE;
    crate::tests::check_local(ChunkNodeSpongeAir, &decorated);
    let challenges = Challenges::new(
        QuadFelt::from_u32(7),
        QuadFelt::from_u32(13),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    assert!(session_stack_residual(&mains, &[(index, &decorated)], &challenges).is_empty());
    let mut invalid_offset = decorated.clone();
    invalid_offset.values[96 * width + SPONGE_COL_OFFSET + OFFSET_BITS_RANGE.start] = Felt::ONE;
    crate::tests::assert_local_rejects(ChunkNodeSpongeAir, &invalid_offset);
    decorated.values[96 * width + SPONGE_COL_OFFSET + COL_IS_PAD_BLOCK] = Felt::ONE;
    crate::tests::assert_local_rejects(ChunkNodeSpongeAir, &decorated);
}

// TAPE CONSUMPTION
// ================================================================================================

fn single_invocation_trace(input: Vec<u8>) -> miden_core::utils::RowMajorMatrix<Felt> {
    let (sponge_req, _chunk, _p2) = build_sponge_requires(&[Invocation { input }]);
    let main = generate_trace(sponge_req);
    crate::tests::check_local(KeccakSpongeAir, &main);
    main
}

fn set_cell(main: &mut miden_core::utils::RowMajorMatrix<Felt>, row: usize, col: usize, v: Felt) {
    main.values[row * NUM_MAIN_COLS + col] = v;
}

#[test]
fn constraints_hold_when_pad_lane_has_no_message_bytes() {
    // Lengths that are multiples of 8 put the pad at byte 0 of its lane; for multiples of 32 the
    // tape has no lane there at all, so the pad row consumes nothing.
    let mut rng = StdRng::seed_from_u64(0x7a9e);
    for len in [8usize, 16, 24, 32, 64, 128, 136, 264] {
        let input: Vec<u8> = (0..len).map(|_| rng.random()).collect();
        check_invocation(0x7a9e, Invocation { input });
    }
}

#[test]
fn non_last_block_cannot_skip_tape_lanes() {
    // 136 zero bytes: two blocks, 20 tape lanes. Block 0 consumes no lane (absorbing zeros) and
    // the last block consumes all 20 past the pad, where they are ignored.
    let mut main = single_invocation_trace(vec![0u8; 136]);
    for row in 0..SPONGE_PERIOD {
        set_cell(&mut main, row, COL_IS_CHUNK_AVAIL, Felt::ZERO);
        set_cell(&mut main, row, COL_CHUNK_PTR, Felt::ZERO);
    }
    let mut consumed = 0u32;
    for slot in 0..SPONGE_PERIOD {
        let row = SPONGE_PERIOD + slot;
        set_cell(&mut main, row, COL_IS_CHUNK_AVAIL, Felt::from(u8::from(slot < 29)));
        set_cell(&mut main, row, COL_CHUNK_PTR, Felt::from(consumed));
        if slot < 17 || (26..29).contains(&slot) {
            consumed += 1;
        }
    }
    assert_eq!(consumed, 20);
    crate::tests::assert_local_rejects(KeccakSpongeAir, &main);
}

#[test]
fn pad_lane_with_message_bytes_must_be_consumed() {
    // 33 bytes: the pad sits at byte 1 of lane 4, which holds message byte 32 (zero here, so the
    // honest lane is zero too). Stopping consumption at the pad row would absorb that byte as 0
    // whatever the tape holds.
    let mut rng = StdRng::seed_from_u64(0x9ad0);
    let mut input: Vec<u8> = (0..33).map(|_| rng.random()).collect();
    input[32] = 0;
    let mut main = single_invocation_trace(input);
    for row in 4..SPONGE_PERIOD {
        set_cell(&mut main, row, COL_IS_CHUNK_AVAIL, Felt::ZERO);
        set_cell(&mut main, row, COL_CHUNK_PTR, Felt::from(4u8));
    }
    crate::tests::assert_local_rejects(KeccakSpongeAir, &main);
}

#[test]
fn tape_lane_past_the_pad_must_be_zero() {
    // 33 bytes: rows 5..8 consume the zero padding of the second chunk. A nonzero lane there
    // would commit to a preimage whose padding is not zero.
    let mut rng = StdRng::seed_from_u64(0x9ad1);
    let input: Vec<u8> = (0..33).map(|_| rng.random()).collect();
    let honest = single_invocation_trace(input);
    for half in 0..2 {
        let mut main = honest.clone();
        set_cell(&mut main, 6, CHUNK_BYTES_RANGE.start + 4 * half, Felt::ONE);
        crate::tests::assert_local_rejects(KeccakSpongeAir, &main);
    }
}

#[test]
fn pad_lane_bytes_after_the_message_must_be_zero() {
    // 33 bytes: the pad row's lane holds message byte 32 at byte 0; byte 1 onwards is padding.
    let mut rng = StdRng::seed_from_u64(0x9ad2);
    let input: Vec<u8> = (0..33).map(|_| rng.random()).collect();
    let honest = single_invocation_trace(input);
    // (half, byte within the lane): byte 1 is in the low half, byte 5 in the high half.
    for byte in [1usize, 5] {
        let mut main = honest.clone();
        set_cell(&mut main, 4, CHUNK_BYTES_RANGE.start + byte, Felt::from(0xabu8));
        crate::tests::assert_local_rejects(KeccakSpongeAir, &main);
    }
}
