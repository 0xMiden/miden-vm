//! Tests for the Poseidon2 permutation chiplet.
//!
//! Message encoding + main-column-layout invariants +
//! [`LiftedAir`] structural smoke checks + trace-driven constraint
//! checks across 1-shot perms, absorption chains, and interning.
//! Negative tests confirm `check_constraints` catches deliberate
//! corruption.

use std::{vec, vec::Vec};

use miden_air::BaseAir;
use miden_core::{
    Felt,
    chiplets::hasher::Hasher,
    deferred::Tag,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_lifted_air::LiftedAir;
use miden_precompiles::{CurvePrecompile, Keccak256Precompile};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

use crate::{
    logup::{Challenges, LookupMessage, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, NUM_SIGMA_VALUES},
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS, ProvideMult},
    transcript::poseidon2::{
        COL_IN_MULTIPLICITY, COL_IS_ABSORB, COL_OUT_MULTIPLICITY, COL_PERM_SEQ_ID, COL_STATE_BEGIN,
        NUM_AUX_COLS, NUM_MAIN_COLS, NUM_WITNESSES, P2Cap, P2Digest, POSEIDON2_IN_TAG_RATE0,
        Poseidon2Air, Poseidon2InMsg, Poseidon2OutMsg,
        math::STATE_WIDTH,
        program::{NUM_PERIODIC_COLS, PERIOD},
        trace::{AbsorptionOutput, Poseidon2Requires, generate_trace},
    },
};

// HELPERS
// ================================================================================================

fn random_chunk(rng: &mut impl Rng) -> [Felt; 4] {
    core::array::from_fn(|_| Felt::new(rng.random()).unwrap())
}

fn random_block(rng: &mut impl Rng) -> ([Felt; 4], [Felt; 4]) {
    (random_chunk(rng), random_chunk(rng))
}

/// Test-local mirror of the old caller-facing `Absorption` struct, used
/// so the test call sites stay readable. [`build_requires`] turns a
/// slice of these into a [`Poseidon2Requires`] by issuing
/// `require_absorption` `in_multiplicity` times (interning collapses
/// them to one record) and `require_digest` `out_multiplicity` times.
#[derive(Debug, Clone)]
struct Absorption {
    cap: [Felt; 4],
    blocks: Vec<([Felt; 4], [Felt; 4])>,
    in_multiplicity: ProvideMult,
    out_multiplicity: ProvideMult,
}

impl Absorption {
    fn one_shot(cap: [Felt; 4], rate0: [Felt; 4], rate1: [Felt; 4]) -> Self {
        Self {
            cap,
            blocks: vec![(rate0, rate1)],
            in_multiplicity: 1,
            out_multiplicity: 1,
        }
    }
}

fn build_requires(absorptions: &[Absorption]) -> (Poseidon2Requires, Vec<AbsorptionOutput>) {
    let mut p2 = Poseidon2Requires::new();
    let outputs: Vec<AbsorptionOutput> = absorptions
        .iter()
        .map(|abs| {
            assert!(abs.in_multiplicity > 0, "absorption needs in_multiplicity > 0");
            let mut last = None;
            for _ in 0..abs.in_multiplicity {
                last = Some(p2.require_absorption(P2Cap(abs.cap), abs.blocks.iter().copied()));
            }
            let out = last.unwrap();
            for _ in 0..abs.out_multiplicity {
                p2.require_digest(out.digest);
            }
            out
        })
        .collect();
    (p2, outputs)
}

fn check_absorptions(_seed: u64, absorptions: &[Absorption]) -> Vec<AbsorptionOutput> {
    let (p2, outputs) = build_requires(absorptions);
    let main = generate_trace(p2);
    crate::tests::check_local(Poseidon2Air, &main);
    outputs
}

/// Read the cycle's row-15 state (= perm output) from the generated trace.
fn read_row15_state(main: &RowMajorMatrix<Felt>, cycle: usize) -> [Felt; STATE_WIDTH] {
    let row_start = (cycle * PERIOD + 15) * NUM_MAIN_COLS;
    core::array::from_fn(|i| main.values[row_start + COL_STATE_BEGIN + i])
}

/// Compute the reference digest of an N-block absorption by chained
/// `Hasher::apply_permutation` calls.
fn reference_digest(absorption: &Absorption) -> [Felt; 4] {
    let mut state = [Felt::ZERO; STATE_WIDTH];
    let mut cap = absorption.cap;
    for &(rate0, rate1) in &absorption.blocks {
        state[0..4].copy_from_slice(&rate0);
        state[4..8].copy_from_slice(&rate1);
        state[8..12].copy_from_slice(&cap);
        Hasher::apply_permutation(&mut state);
        cap = state[8..12].try_into().unwrap();
    }
    state[0..4].try_into().unwrap()
}

// CAP CONSTRUCTORS
// ================================================================================================

#[test]
fn p2_caps_match_vm_sources() {
    let len_bytes = 136u32;

    assert_eq!(P2Cap::chunk().as_array(), Tag::CHUNKS.as_word());
    assert_eq!(P2Cap::and().as_array(), Tag::AND.as_word());
    assert_eq!(
        P2Cap::keccak256_assertion(len_bytes).as_array(),
        Keccak256Precompile::assert_tag(len_bytes).as_word(),
    );
    assert_eq!(
        P2Cap::ec_msm_iv().as_array(),
        [
            CurvePrecompile::id(),
            Felt::from_u32(CurvePrecompile::MSM_OP_ID as u32),
            Felt::ZERO,
            Felt::ZERO,
        ],
    );
}

// MESSAGE ENCODING
// ================================================================================================

#[test]
fn poseidon2_in_msg_encodes_with_in_bus_prefix() {
    let alpha = QuadFelt::from_u64(11);
    let beta = QuadFelt::from_u64(13);
    let challenges = Challenges::<QuadFelt>::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);

    let perm_seq_id = Felt::from(42u32);
    let chunk = [Felt::from(1u32), Felt::from(2u32), Felt::from(3u32), Felt::from(4u32)];
    let msg = Poseidon2InMsg::rate0(perm_seq_id, chunk);
    let enc = msg.encode(&challenges);

    // Expected: bus_prefix[Poseidon2In] + β⁰·perm_seq_id + β¹·tag +
    // β²·c0 + β³·c1 + β⁴·c2 + β⁵·c3.
    let bus_prefix = alpha
        + beta.exp_u64(MAX_MESSAGE_WIDTH as u64)
            * QuadFelt::from_u64((BusId::Poseidon2In as u64) + 1);
    let expected = bus_prefix
        + QuadFelt::from(perm_seq_id)
        + beta * QuadFelt::from(Felt::from(POSEIDON2_IN_TAG_RATE0))
        + beta.square() * QuadFelt::from(chunk[0])
        + beta.exp_u64(3) * QuadFelt::from(chunk[1])
        + beta.exp_u64(4) * QuadFelt::from(chunk[2])
        + beta.exp_u64(5) * QuadFelt::from(chunk[3]);

    assert_eq!(enc, expected);
}

#[test]
fn poseidon2_in_msg_tags_produce_distinct_encodings() {
    // Same (perm_seq_id, chunk) under three different tags must produce
    // three distinct encodings — otherwise a malicious prover could
    // pair rate0 with rate1 across cycles.
    let alpha = QuadFelt::from_u64(7);
    let beta = QuadFelt::from_u64(5);
    let challenges = Challenges::<QuadFelt>::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);

    let perm_seq_id = Felt::from(1u32);
    let chunk = [Felt::from(0u32), Felt::from(0u32), Felt::from(0u32), Felt::from(0u32)];

    let enc_r0 = Poseidon2InMsg::rate0(perm_seq_id, chunk).encode(&challenges);
    let enc_r1 = Poseidon2InMsg::rate1(perm_seq_id, chunk).encode(&challenges);
    let enc_c = Poseidon2InMsg::cap(perm_seq_id, chunk).encode(&challenges);

    assert_ne!(enc_r0, enc_r1);
    assert_ne!(enc_r0, enc_c);
    assert_ne!(enc_r1, enc_c);
}

#[test]
fn poseidon2_out_msg_encodes_with_out_bus_prefix() {
    let alpha = QuadFelt::from_u64(17);
    let beta = QuadFelt::from_u64(19);
    let challenges = Challenges::<QuadFelt>::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);

    let perm_seq_id = Felt::from(7u32);
    let digest = [Felt::from(100u32), Felt::from(200u32), Felt::from(300u32), Felt::from(400u32)];
    let msg = Poseidon2OutMsg { perm_seq_id, digest };
    let enc = msg.encode(&challenges);

    let bus_prefix = alpha
        + beta.exp_u64(MAX_MESSAGE_WIDTH as u64)
            * QuadFelt::from_u64((BusId::Poseidon2Out as u64) + 1);
    let expected = bus_prefix
        + QuadFelt::from(perm_seq_id)
        + beta * QuadFelt::from(digest[0])
        + beta.square() * QuadFelt::from(digest[1])
        + beta.exp_u64(3) * QuadFelt::from(digest[2])
        + beta.exp_u64(4) * QuadFelt::from(digest[3]);

    assert_eq!(enc, expected);
}

#[test]
fn poseidon2_in_and_out_buses_have_disjoint_prefixes() {
    let alpha = QuadFelt::from_u64(3);
    let beta = QuadFelt::from_u64(2);
    let challenges = Challenges::<QuadFelt>::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);

    let perm_seq_id = Felt::from(5u32);
    let chunk = [Felt::from(9u32), Felt::from(8u32), Felt::from(7u32), Felt::from(6u32)];

    let enc_in = Poseidon2InMsg::rate0(perm_seq_id, chunk).encode(&challenges);
    let enc_out = Poseidon2OutMsg { perm_seq_id, digest: chunk }.encode(&challenges);
    assert_ne!(enc_in, enc_out);
}

// LAYOUT INVARIANTS
// ================================================================================================

#[test]
fn main_column_layout_matches_spec() {
    assert_eq!(COL_PERM_SEQ_ID, 0);
    assert_eq!(COL_IN_MULTIPLICITY, 1);
    assert_eq!(COL_OUT_MULTIPLICITY, 2);
    assert_eq!(COL_IS_ABSORB, 3);
    assert_eq!(COL_STATE_BEGIN, 4);
    assert_eq!(NUM_WITNESSES, 3);
    assert_eq!(NUM_MAIN_COLS, 19);
    assert_eq!(<Poseidon2Air as BaseAir<Felt>>::width(&Poseidon2Air), NUM_MAIN_COLS,);
}

#[test]
fn lifted_air_validates_and_layout_matches_spec() {
    let air = Poseidon2Air;
    let layout = <Poseidon2Air as LiftedAir<Felt, QuadFelt>>::air_layout(&air);
    assert_eq!(layout.preprocessed_width, 0);
    assert_eq!(layout.main_width, NUM_MAIN_COLS);
    assert_eq!(layout.num_public_values, NUM_PUBLIC_VALUES);
    assert_eq!(layout.permutation_width, NUM_AUX_COLS);
    assert_eq!(layout.num_permutation_challenges, NUM_RANDOMNESS);
    assert_eq!(layout.num_permutation_values, NUM_SIGMA_VALUES);
    assert_eq!(layout.num_periodic_columns, NUM_PERIODIC_COLS);
}

#[test]
fn log_quotient_degree_matches_design_target() {
    let air = Poseidon2Air;
    assert_eq!(crate::tests::log_quotient_degree(&air), 3);
}

#[test]
fn periodic_columns_have_period_16() {
    let air = Poseidon2Air;
    let cols = <Poseidon2Air as BaseAir<Felt>>::periodic_columns(&air);
    assert_eq!(cols.len(), NUM_PERIODIC_COLS);
    for c in &cols {
        assert_eq!(c.len(), PERIOD);
    }
}

/// The `(head, tail)` cycle numbers of an absorption's span.
fn span_bounds(out: &AbsorptionOutput) -> (u32, u32) {
    (out.head().seq(), out.tail().seq())
}

// ORACLE: digest + perm span correctness
// ================================================================================================

#[test]
fn one_shot_digest_matches_reference_on_zero_input() {
    let absorption = Absorption::one_shot([Felt::ZERO; 4], [Felt::ZERO; 4], [Felt::ZERO; 4]);
    let (p2, outputs) = build_requires(std::slice::from_ref(&absorption));
    let main = generate_trace(p2);

    let expected_digest = P2Digest(reference_digest(&absorption));
    assert_eq!(outputs[0].digest, expected_digest);
    assert_eq!(span_bounds(&outputs[0]), (0, 0));

    // Row-15 state's first 4 felts also equal the digest.
    let state_out = read_row15_state(&main, 0);
    let digest_from_state = P2Digest(state_out[0..4].try_into().unwrap());
    assert_eq!(digest_from_state, expected_digest);
}

#[test]
fn one_shot_digest_matches_reference_on_random_input() {
    let mut rng = StdRng::seed_from_u64(0xc011_5eed);
    let cap = random_chunk(&mut rng);
    let (rate0, rate1) = random_block(&mut rng);
    let absorption = Absorption::one_shot(cap, rate0, rate1);

    let (_, outputs) = build_requires(std::slice::from_ref(&absorption));
    assert_eq!(outputs[0].digest, P2Digest(reference_digest(&absorption)));
}

#[test]
fn three_block_digest_matches_chained_reference_permutation() {
    let mut rng = StdRng::seed_from_u64(0x0c0a_1ced);
    let cap = random_chunk(&mut rng);
    let absorption = Absorption {
        cap,
        blocks: vec![random_block(&mut rng), random_block(&mut rng), random_block(&mut rng)],
        in_multiplicity: 1,
        out_multiplicity: 1,
    };

    let (_, outputs) = build_requires(std::slice::from_ref(&absorption));
    assert_eq!(outputs[0].digest, P2Digest(reference_digest(&absorption)));
    assert_eq!(span_bounds(&outputs[0]), (0, 2));
}

#[test]
fn multi_absorption_outputs_have_non_overlapping_perm_spans() {
    let mut rng = StdRng::seed_from_u64(0xdead_beef);
    let absorptions = vec![
        Absorption::one_shot(
            random_chunk(&mut rng),
            random_chunk(&mut rng),
            random_chunk(&mut rng),
        ),
        Absorption {
            cap: random_chunk(&mut rng),
            blocks: vec![random_block(&mut rng), random_block(&mut rng)],
            in_multiplicity: 1,
            out_multiplicity: 1,
        },
        Absorption::one_shot(
            random_chunk(&mut rng),
            random_chunk(&mut rng),
            random_chunk(&mut rng),
        ),
    ];

    let (_, outputs) = build_requires(&absorptions);

    // Expected ranges: 0..1, 1..3, 3..4 — contiguous + non-overlapping.
    assert_eq!(span_bounds(&outputs[0]), (0, 0));
    assert_eq!(span_bounds(&outputs[1]), (1, 2));
    assert_eq!(span_bounds(&outputs[2]), (3, 3));

    for (i, absorption) in absorptions.iter().enumerate() {
        assert_eq!(outputs[i].digest, P2Digest(reference_digest(absorption)));
    }
}

// CONSTRAINT TESTS (positive)
// ================================================================================================

#[test]
fn constraints_hold_on_one_shot_zero_input() {
    check_absorptions(
        0xa1_00,
        &[Absorption::one_shot([Felt::ZERO; 4], [Felt::ZERO; 4], [Felt::ZERO; 4])],
    );
}

#[test]
fn constraints_hold_on_one_shot_random_input() {
    let mut rng = StdRng::seed_from_u64(0xa1_01);
    let cap = random_chunk(&mut rng);
    let (rate0, rate1) = random_block(&mut rng);
    check_absorptions(0xa1_01, &[Absorption::one_shot(cap, rate0, rate1)]);
}

#[test]
fn constraints_hold_on_two_block_absorption() {
    let mut rng = StdRng::seed_from_u64(0xa2_00);
    let cap = random_chunk(&mut rng);
    let absorption = Absorption {
        cap,
        blocks: vec![random_block(&mut rng), random_block(&mut rng)],
        in_multiplicity: 1,
        out_multiplicity: 1,
    };
    check_absorptions(0xa2_00, &[absorption]);
}

#[test]
fn constraints_hold_on_three_block_absorption() {
    let mut rng = StdRng::seed_from_u64(0xa3_00);
    let cap = random_chunk(&mut rng);
    let absorption = Absorption {
        cap,
        blocks: vec![random_block(&mut rng), random_block(&mut rng), random_block(&mut rng)],
        in_multiplicity: 1,
        out_multiplicity: 1,
    };
    check_absorptions(0xa3_00, &[absorption]);
}

#[test]
fn constraints_hold_on_interned_absorption() {
    // Single absorption serving 7 identical caller requests.
    let mut rng = StdRng::seed_from_u64(0xa4_00);
    let cap = random_chunk(&mut rng);
    let (rate0, rate1) = random_block(&mut rng);
    check_absorptions(
        0xa4_00,
        &[Absorption {
            cap,
            blocks: vec![(rate0, rate1)],
            in_multiplicity: 7,
            out_multiplicity: 7,
        }],
    );
}

#[test]
fn constraints_hold_on_multiplicity_beyond_range16_cap() {
    // Regression for the retired Range16 mult cap. The provide
    // multiplicities used to be range-checked to 16 bits, so a count of
    // 2^16 forced a spill onto a fresh cycle; now they are unbounded
    // `usize` dedup counts pinned only by bus balance. A single record
    // carrying a mult *past* 2^16 must still close the trace — proof the
    // cell is no longer tied to a 16-bit range check.
    let over_cap = (1u32 << 16) + 1;
    let mut rng = StdRng::seed_from_u64(0xa4_ff);
    let cap = random_chunk(&mut rng);
    let (rate0, rate1) = random_block(&mut rng);
    check_absorptions(
        0xa4_ff,
        &[Absorption {
            cap,
            blocks: vec![(rate0, rate1)],
            in_multiplicity: over_cap,
            out_multiplicity: over_cap,
        }],
    );
}

#[test]
fn constraints_hold_on_asymmetric_multiplicities() {
    // Content-addressed-DAG pattern: 1 creator + 6 readers. The
    // chiplet provides 1 copy of the In-side tuples and 7 copies of
    // the Out-side tuple, all balancing against the caller-side
    // consumes.
    let mut rng = StdRng::seed_from_u64(0xda6_c0de);
    let cap = random_chunk(&mut rng);
    let (rate0, rate1) = random_block(&mut rng);
    check_absorptions(
        0xda6_c0de,
        &[Absorption {
            cap,
            blocks: vec![(rate0, rate1)],
            in_multiplicity: 1,
            out_multiplicity: 7,
        }],
    );
}

#[test]
fn constraints_hold_on_mixed_one_shot_and_chain() {
    // Two unrelated 1-shot absorptions followed by a 2-block chain.
    let mut rng = StdRng::seed_from_u64(0xa5_00);
    let one_shot_a = Absorption::one_shot(
        random_chunk(&mut rng),
        random_chunk(&mut rng),
        random_chunk(&mut rng),
    );
    let one_shot_b = Absorption::one_shot(
        random_chunk(&mut rng),
        random_chunk(&mut rng),
        random_chunk(&mut rng),
    );
    let chain = Absorption {
        cap: random_chunk(&mut rng),
        blocks: vec![random_block(&mut rng), random_block(&mut rng)],
        in_multiplicity: 1,
        out_multiplicity: 1,
    };
    check_absorptions(0xa5_00, &[one_shot_a, one_shot_b, chain]);
}

// NEGATIVE TESTS — confirm `check_constraints` catches deliberate corruption
// ================================================================================================

fn corrupt_and_check(
    _seed: u64,
    absorptions: &[Absorption],
    corruption: impl FnOnce(&mut RowMajorMatrix<Felt>),
) {
    let (p2, _outputs) = build_requires(absorptions);
    let mut main = generate_trace(p2);
    corruption(&mut main);
    crate::tests::check_local(Poseidon2Air, &main);
}

fn rng_one_shot(seed: u64) -> Absorption {
    let mut rng = StdRng::seed_from_u64(seed);
    Absorption::one_shot(random_chunk(&mut rng), random_chunk(&mut rng), random_chunk(&mut rng))
}

fn rng_two_block(seed: u64) -> Absorption {
    let mut rng = StdRng::seed_from_u64(seed);
    Absorption {
        cap: random_chunk(&mut rng),
        blocks: vec![random_block(&mut rng), random_block(&mut rng)],
        in_multiplicity: 1,
        out_multiplicity: 1,
    }
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_seq_id_breaks_row_counter() {
    // Skip a value in `perm_seq_id` — both the cycle-constancy and the
    // cycle-boundary increment constraints fail.
    corrupt_and_check(0xc0_5e, &[rng_one_shot(0xc0_5e)], |main| {
        main.values[NUM_MAIN_COLS + COL_PERM_SEQ_ID] = Felt::from(99u8);
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_non_binary_is_absorb_breaks_booleanity() {
    corrupt_and_check(0xc0_bb, &[rng_one_shot(0xc0_bb)], |main| {
        for r in 0..PERIOD {
            main.values[r * NUM_MAIN_COLS + COL_IS_ABSORB] = Felt::from(2u8);
        }
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_in_multiplicity_non_constant_breaks_constancy() {
    // in_multiplicity must be constant within a cycle.
    corrupt_and_check(0xc0_60, &[rng_one_shot(0xc0_60)], |main| {
        main.values[7 * NUM_MAIN_COLS + COL_IN_MULTIPLICITY] = Felt::from(2u8);
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_out_multiplicity_non_constant_breaks_constancy() {
    // out_multiplicity must also be constant within a cycle.
    corrupt_and_check(0xc0_61, &[rng_one_shot(0xc0_61)], |main| {
        main.values[7 * NUM_MAIN_COLS + COL_OUT_MULTIPLICITY] = Felt::from(2u8);
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_capacity_mismatch_in_chain_breaks_carry() {
    // Build a valid 2-block absorption, then perturb the tail's
    // row-0 capacity so it no longer matches the head's row-15
    // capacity. The chiplet auto-threads on trace gen, so the
    // capacity is correct out of the box; we have to break it
    // post-hoc.
    corrupt_and_check(0xc0_ca, &[rng_two_block(0xc0_ca)], |main| {
        // Row 0 of cycle 1 = trace row 16. Bump state[8] (first
        // capacity lane) by 1 — breaks the cap-carry constraint.
        let row_offset = PERIOD * NUM_MAIN_COLS;
        main.values[row_offset + COL_STATE_BEGIN + 8] += Felt::ONE;
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_is_absorb_non_constant_breaks_within_cycle() {
    corrupt_and_check(0xc0_ab, &[rng_two_block(0xc0_ab)], |main| {
        // Flip is_absorb on row 5 of cycle 1 (originally 1, now 0).
        let row_offset = (PERIOD + 5) * NUM_MAIN_COLS;
        main.values[row_offset + COL_IS_ABSORB] = Felt::ZERO;
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_state_at_step_breaks_transition() {
    corrupt_and_check(0xc0_57, &[rng_one_shot(0xc0_57)], |main| {
        // Perturb state[0] at row 5 (one of the packed-internal
        // rows). The packed-internal next-state constraint fires
        // and observes the inconsistency.
        main.values[5 * NUM_MAIN_COLS + COL_STATE_BEGIN] += Felt::ONE;
    });
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_is_absorb_at_row_0_breaks_boundary() {
    // is_absorb must be 0 at row 0: chains cannot wrap the trace.
    // Set is_absorb = 1 across every row of cycle 0 (matches
    // cycle-constancy + breaks the when_first_row boundary).
    corrupt_and_check(0xc0_ab_00, &[rng_one_shot(0xc0_ab_00)], |main| {
        for r in 0..PERIOD {
            main.values[r * NUM_MAIN_COLS + COL_IS_ABSORB] = Felt::ONE;
        }
    });
}
