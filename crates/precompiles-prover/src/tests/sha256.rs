use std::{
    collections::HashMap,
    panic::{AssertUnwindSafe, catch_unwind},
    vec,
    vec::Vec,
};

use miden_air::lookup::{Challenges, LookupAir, ProverLookupBuilder, build_lookup_fractions};
use miden_core::{
    Felt,
    field::{Field, PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};
use miden_crypto::hash::sha2::Sha256;
use miden_lifted_air::{BaseAir, LiftedAir};
use miden_precompiles_air::primitives::byte_pair_lut::eidos::Relation as EidosRelation;

use crate::{
    hash::sha256::compression::{
        COL_A_BEGIN, COL_ACT, COL_B_BEGIN, COL_BLOCK_ID, COL_CARRY, COL_R_BEGIN, COL_ROT_BEGIN,
        NUM_MAIN_COLS, Sha256CompressionAir, Sha256CompressionRequires, Sha256WordMsg,
        generate_trace, program,
    },
    logup::{LookupMessage, NUM_PUBLIC_VALUES},
    primitives::byte_pair_lut::{
        BytePairLutAir, BytePairLutRequires, NUM_MAIN_COLS as BPL_MAIN_COLS,
        generate_trace as bpl_trace,
    },
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
};

const COL_MULT_CANONICAL_XOR: usize = EidosRelation::CanonicalXor.index();
const COL_MULT_RANGE16: usize = BPL_MAIN_COLS - 1;

#[test]
fn sha256_program_has_the_frozen_shape() {
    let slots = program::slots();
    assert_eq!(slots.len(), program::COMPRESSION_PERIOD);
    assert_eq!(program::real_slot_count(&slots), 2354);
    assert_eq!(slots[0].dst_mult, 48);
    assert_eq!(slots[1].dst_mult, 48);
    let mut counts = [0usize; 7];
    for slot in slots.iter() {
        match slot.op {
            program::Op::Input => counts[0] += 1,
            program::Op::Const(_) => counts[1] += 1,
            program::Op::Rol(_) => counts[2] += 1,
            program::Op::And => counts[3] += 1,
            program::Op::Xor => counts[4] += 1,
            program::Op::Add => counts[5] += 1,
            program::Op::AndNot => counts[6] += 1,
            program::Op::Nop => {},
        }
    }
    assert_eq!(counts, [24, 66, 672, 288, 640, 600, 64]);
    assert_eq!(program::OUTPUT_SLOTS, [3232, 3233, 3234, 3235, 3236, 3237, 3238, 3239]);
    assert!(slots[3232..3240].iter().all(|slot| slot.op == program::Op::Add));
    assert_eq!(program::PHASE_BASES, [0, 32, 1056, 1184, 3232, 3264]);
    assert_eq!(program::PHASE_CYCLES, [1, 32, 4, 64, 1, 26]);
    assert!(slots.iter().enumerate().all(|(i, slot)| slot.sources_before_destination(i)));
    assert_eq!(<Sha256CompressionAir as BaseAir<Felt>>::width(&Sha256CompressionAir), 39);
    assert_eq!(Sha256CompressionAir.periodic_columns().len(), program::NUM_PERIODIC_COLS);
    assert_eq!(Sha256CompressionAir.periodic_columns()[0].len(), program::MAX_PERIODIC_LENGTH);
    assert_eq!(Sha256CompressionAir.aux_width(), 9);
}

#[test]
fn sha256_program_fanout_and_rotation_bounds_are_mechanical() {
    let slots = program::slots();
    let mut fanout = [0u32; program::COMPRESSION_PERIOD];
    for slot in slots.iter() {
        if !matches!(slot.op, program::Op::Input | program::Op::Const(_) | program::Op::Nop) {
            fanout[slot.src_a as usize] += 1;
        }
        if matches!(
            slot.op,
            program::Op::Xor | program::Op::And | program::Op::AndNot | program::Op::Add
        ) {
            fanout[slot.src_b as usize] += 1;
        }
        if let program::Op::Rol(shift) = slot.op {
            assert!((1..=30).contains(&shift), "invalid ROL shift {shift}");
        }
    }
    for output in program::OUTPUT_SLOTS {
        fanout[output as usize] += 1;
    }
    for (slot, expected) in slots.iter().zip(fanout) {
        assert_eq!(slot.dst_mult, expected, "fanout mismatch at slot");
    }
    // The metadata bus authenticates closed-form fanouts for the round-dependent outputs.
    // They must equal the fanouts the program builder derives from its source references.
    let metadata = program::round_metadata();
    for (t, m) in metadata.iter().enumerate().take(64) {
        assert_eq!(slots[32 + 16 * t + 15].dst_mult, m.w_mult, "W[{t}] fanout");
        assert_eq!(slots[1184 + 32 * t + 23].dst_mult, m.a_mult, "A[{t}] fanout");
        assert_eq!(slots[1184 + 32 * t + 24].dst_mult, m.e_mult, "E[{t}] fanout");
    }
    assert_eq!(slots[0].op, program::Op::Const(0x1fff_ffff));
    assert_eq!(slots[1].op, program::Op::Const(0x003f_ffff));
    assert!(slots.iter().any(|slot| slot.op == program::Op::Rol(29)));
    assert!(slots.iter().any(|slot| slot.op == program::Op::Rol(30)));
}

fn mutation_trace() -> RowMajorMatrix<Felt> {
    let state = [0, 1, 0xffff, 0x1_0000, u32::MAX - 1, u32::MAX, 7, 13];
    let block = core::array::from_fn(|i| match i % 8 {
        0 => 0,
        1 => u32::MAX,
        2 => 0xffff,
        3 => 0x1_0000,
        4 => 0xffff_0001,
        5 => 0x8000_0000,
        6 => 0x0123_4567,
        _ => 0x89ab_cdef,
    });
    let mut requires = Sha256CompressionRequires::new();
    requires.require(state, block);
    generate_trace(requires, &mut BytePairLutRequires::new())
}

fn first_slot(op: program::Op) -> usize {
    program::slots()
        .iter()
        .position(|slot| slot.op == op)
        .expect("program must contain requested operation")
}

fn pack_test_bytes(bytes: &[Felt]) -> Felt {
    bytes
        .iter()
        .enumerate()
        .fold(Felt::ZERO, |acc, (i, byte)| acc + *byte * Felt::from(1u32 << (8 * i)))
}

fn assert_local_rejects(mutator: impl FnOnce(&mut RowMajorMatrix<Felt>)) {
    let mut main = mutation_trace();
    mutator(&mut main);
    let result = catch_unwind(AssertUnwindSafe(|| {
        crate::tests::check_local(Sha256CompressionAir, &main);
    }));
    assert!(result.is_err(), "mutated trace unexpectedly satisfied local AIR");
}

fn assert_add_equation_holds(main: &RowMajorMatrix<Felt>, row_idx: usize) {
    let two32 = Felt::new(1u64 << 32).unwrap();
    let row = &main.values[row_idx * NUM_MAIN_COLS..(row_idx + 1) * NUM_MAIN_COLS];
    let a = pack_test_bytes(&row[COL_A_BEGIN..COL_A_BEGIN + 4]);
    let b = pack_test_bytes(&row[COL_B_BEGIN..COL_B_BEGIN + 4]);
    let r = pack_test_bytes(&row[COL_R_BEGIN..COL_R_BEGIN + 4]);
    assert_eq!(a + b, r + two32 * row[COL_CARRY]);
}

#[test]
#[should_panic]
fn sha256_rejects_non_boolean_activity() {
    let mut main = mutation_trace();
    main.values[COL_ACT] = Felt::from(2u8);
    crate::tests::check_local(Sha256CompressionAir, &main);
}

#[test]
fn sha256_rejects_non_boolean_carry() {
    let mut main = mutation_trace();
    let row = first_slot(program::Op::Add);
    let base = row * NUM_MAIN_COLS;
    // Shift one unit from the result into a fractional carry, preserving the ADD equation.
    let delta = -Felt::new(1u64 << 32).unwrap().inverse();
    main.values[base + COL_R_BEGIN] += Felt::ONE;
    main.values[base + COL_CARRY] += delta;
    assert_add_equation_holds(&main, row);
    let result = catch_unwind(AssertUnwindSafe(|| {
        crate::tests::check_local(Sha256CompressionAir, &main);
    }));
    assert!(result.is_err(), "non-Boolean carry unexpectedly passed");
}

#[test]
fn sha256_rejects_wrong_constant() {
    let row = first_slot(program::Op::Const(0x1fff_ffff));
    for offset in [0, 3] {
        assert_local_rejects(|main| {
            main.values[row * NUM_MAIN_COLS + COL_R_BEGIN + offset] += Felt::ONE;
        });
    }
}

#[test]
fn sha256_rejects_wrong_rotation_decomposition() {
    let row = first_slot(program::Op::Rol(30));
    for offset in [0, 2] {
        assert_local_rejects(|main| {
            main.values[row * NUM_MAIN_COLS + COL_ROT_BEGIN + offset] += Felt::ONE;
        });
    }
}

#[test]
fn sha256_rejects_wrong_add_result() {
    let row = first_slot(program::Op::Add);
    for offset in [0, 3] {
        assert_local_rejects(|main| {
            main.values[row * NUM_MAIN_COLS + COL_R_BEGIN + offset] += Felt::ONE;
        });
    }
}

#[test]
#[should_panic]
fn sha256_rejects_shifted_block_ids_via_first_row_anchor() {
    let mut requires = Sha256CompressionRequires::new();
    requires.require([0; 8], [0; 16]);
    requires.require([1; 8], [1; 16]);
    let mut main = crate::hash::sha256::compression::generate_trace_padded_to(
        requires,
        &mut BytePairLutRequires::new(),
        8192,
    );
    for row in main.values.as_chunks_mut::<{ NUM_MAIN_COLS }>().0 {
        row[COL_BLOCK_ID] += Felt::ONE;
    }
    crate::tests::check_local(Sha256CompressionAir, &main);
}

#[test]
#[should_panic]
fn sha256_rejects_reactivation_after_inactive_block() {
    let mut requires = Sha256CompressionRequires::new();
    requires.require([0; 8], [0; 16]);
    requires.require([1; 8], [1; 16]);
    let mut main = crate::hash::sha256::compression::generate_trace_padded_to(
        requires,
        &mut BytePairLutRequires::new(),
        8192,
    );
    for row in main.values[..program::COMPRESSION_PERIOD * NUM_MAIN_COLS]
        .as_chunks_mut::<{ NUM_MAIN_COLS }>()
        .0
    {
        row.fill(Felt::ZERO);
    }
    crate::tests::check_local(Sha256CompressionAir, &main);
}

#[test]
fn sha256_arithmetic_edges_cover_rotations_and_both_carries() {
    let words = [0, 1, 0x7fff_ffff, 0x8000_0000, 0x0000_ffff, 0xffff_0000, u32::MAX - 1, u32::MAX];
    let state = core::array::from_fn(|i| words[(i * 3) % words.len()]);
    let block = core::array::from_fn(|i| words[(i * 5 + 1) % words.len()]);
    let mut requires = Sha256CompressionRequires::new();
    requires.require(state, block);
    requires.require(core::array::from_fn(|i| words[(i * 7 + 2) % words.len()]), block);
    let main = generate_trace(requires, &mut BytePairLutRequires::new());
    let mut seen = 0u8;
    for row in main.values.as_chunks::<{ NUM_MAIN_COLS }>().0.iter() {
        if row[crate::hash::sha256::compression::COL_PROG_BEGIN + program::T_IS_ADD] == Felt::ONE {
            seen |= 1 << row[COL_CARRY].as_canonical_u64();
        }
    }
    assert_eq!(seen, 0b11, "both carry values must occur");
    crate::tests::check_local(Sha256CompressionAir, &main);
}

fn trace_word(main: &RowMajorMatrix<Felt>, row: usize, col_begin: usize) -> u32 {
    u32::from_le_bytes(core::array::from_fn(|i| {
        main.values[row * NUM_MAIN_COLS + col_begin + i].as_canonical_u64() as u8
    }))
}

#[test]
fn sha256_expansion_rotation_and_shift_slots_match_native_words() {
    let state = [u32::MAX, 0xffff_0001, 0x0123_4567, 7, 11, 13, 17, 19];
    let mut block = [0u32; 16];
    block[1] = u32::MAX - 0x1234;
    block[14] = 0x8765_4321;
    let mut requires = Sha256CompressionRequires::new();
    requires.require(state, block);
    let main = generate_trace(requires, &mut BytePairLutRequires::new());
    let slots = program::slots();
    let rotr7 = slots.iter().position(|s| s.op == program::Op::Rol(25)).unwrap();
    let w1 = trace_word(&main, 32 + 16 + 15, COL_R_BEGIN);
    // ROL stores its unrotated source in r; the consumer reads the rotated word.
    assert_eq!(trace_word(&main, rotr7, COL_R_BEGIN), w1);
    let rotr7_consumer = slots
        .iter()
        .position(|s| matches!(s.op, program::Op::Xor) && s.src_a == rotr7 as u32)
        .unwrap();
    assert_eq!(trace_word(&main, rotr7_consumer, COL_A_BEGIN), w1.rotate_right(7));
    let shr3 = slots.iter().position(|s| s.op == program::Op::And && s.src_b == 0).unwrap();
    assert_eq!(trace_word(&main, shr3, COL_R_BEGIN), w1 >> 3);
    let shr10 = slots.iter().position(|s| s.op == program::Op::And && s.src_b == 1).unwrap();
    let w14 = trace_word(&main, 32 + 16 * 14 + 15, COL_R_BEGIN);
    assert_eq!(trace_word(&main, shr10, COL_R_BEGIN), w14 >> 10);
    crate::tests::check_local(Sha256CompressionAir, &main);
}

#[test]
fn sha256_compression_trace_satisfies_local_air() {
    let mut requires = Sha256CompressionRequires::new();
    requires.require([0; 8], [0; 16]);
    let main = generate_trace(requires, &mut BytePairLutRequires::new());
    crate::tests::check_local(Sha256CompressionAir, &main);
}

fn digest_words(bytes: [u8; 32]) -> [u32; 8] {
    core::array::from_fn(|i| u32::from_be_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()))
}

#[test]
fn sha256_compression_matches_empty_message_oracle() {
    let mut block = [0u32; 16];
    block[0] = 0x8000_0000;
    let mut requires = Sha256CompressionRequires::new();
    let got = requires.require(sha256_iv(), block).state;
    assert_eq!(got, digest_words(<[u8; 32]>::from(Sha256::hash(b""))));

    let mut block = [0u32; 16];
    block[0] = 0x6162_6380;
    block[15] = 24;
    let got = requires.require(sha256_iv(), block).state;
    assert_eq!(got, digest_words(<[u8; 32]>::from(Sha256::hash(b"abc"))));
}

#[test]
fn sha256_compression_supports_multiple_blocks_and_requested_padding() {
    let mut requires = Sha256CompressionRequires::new();
    requires.require([0; 8], [0; 16]);
    requires.require([1; 8], [u32::MAX; 16]);
    assert_eq!(requires.trace_height(), Some(8192));
    let main = crate::hash::sha256::compression::generate_trace_padded_to(
        requires,
        &mut BytePairLutRequires::new(),
        12_000,
    );
    assert_eq!(main.height(), 16_384);
    crate::tests::check_local(Sha256CompressionAir, &main);
}

#[test]
fn sha256_compression_records_all_byte_pair_and_range16_demands() {
    let mut requires = Sha256CompressionRequires::new();
    requires.require([0x0123_4567; 8], [0x89ab_cdef; 16]);
    let mut bpl = BytePairLutRequires::new();
    let main = generate_trace(requires, &mut bpl);
    let bpl_main = bpl_trace(bpl);

    let mut counts = [0usize; BPL_MAIN_COLS];
    for row in bpl_main.values.as_chunks::<{ BPL_MAIN_COLS }>().0 {
        for (count, value) in counts.iter_mut().zip(row) {
            *count += usize::try_from(value.as_canonical_u64()).unwrap();
        }
    }
    // AND and ANDNOT consume the canonical XOR relation through their affine result encodings.
    assert_eq!(counts[COL_MULT_CANONICAL_XOR], (288 + 64 + 24 + 66 + 672 + 640 + 600) * 4);
    assert_eq!(counts[COL_MULT_RANGE16], 672 * 4);
    crate::tests::check_local(BytePairLutAir, &bpl_main);
    crate::tests::check_local(Sha256CompressionAir, &main);
}

#[test]
#[should_panic]
fn sha256_activity_cannot_restart_in_padded_tail() {
    let mut requires = Sha256CompressionRequires::new();
    requires.require([0; 8], [0; 16]);
    let mut main = crate::hash::sha256::compression::generate_trace_padded_to(
        requires,
        &mut BytePairLutRequires::new(),
        8192,
    );
    main.values[program::COMPRESSION_PERIOD * NUM_MAIN_COLS + COL_ACT] = Felt::ONE;
    crate::tests::check_local(Sha256CompressionAir, &main);
}

fn fold_lookup_balance<A>(
    air: &A,
    main: &RowMajorMatrix<Felt>,
    challenges: &Challenges<QuadFelt>,
    net: &mut HashMap<QuadFelt, Felt>,
) where
    A: LiftedAir<Felt, QuadFelt> + Sync,
    for<'a> A: LookupAir<ProverLookupBuilder<'a, Felt, QuadFelt>>,
{
    let periodic = air.periodic_columns();
    let preprocessed = air.preprocessed_trace();
    for &(multiplicity, denominator) in
        build_lookup_fractions(air, main, preprocessed.as_ref(), &periodic, challenges).fractions()
    {
        *net.entry(denominator).or_insert(Felt::ZERO) += multiplicity;
    }
}

fn word_msg(block_id: usize, addr: u32, value: u32) -> Sha256WordMsg<Felt> {
    Sha256WordMsg {
        block_id: Felt::from(block_id as u32),
        addr: Felt::from(addr),
        value: Felt::from(value),
    }
}

#[test]
fn sha256_and_bpl_buses_balance_with_input_and_output_boundaries() {
    let state = [0x0123_4567; 8];
    let block = [0x89ab_cdef; 16];
    let mut requires = Sha256CompressionRequires::new();
    let output = requires.require(state, block);
    let mut bpl = BytePairLutRequires::new();
    let sha_main = generate_trace(requires, &mut bpl);
    let bpl_main = bpl_trace(bpl);
    let challenges = Challenges::new(
        QuadFelt::from_u64(17),
        QuadFelt::from_u64(31),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    let mut net = HashMap::new();
    fold_lookup_balance(&Sha256CompressionAir, &sha_main, &challenges, &mut net);
    fold_lookup_balance(&BytePairLutAir, &bpl_main, &challenges, &mut net);

    let mut boundary = |addr: u32, value: u32, multiplicity: Felt| {
        *net.entry(word_msg(0, addr, value).encode(&challenges)).or_insert(Felt::ZERO) +=
            multiplicity;
    };
    for (i, &word) in block.iter().enumerate() {
        boundary(4096 + i as u32, word, -Felt::ONE);
    }
    for (i, &word) in state.iter().enumerate() {
        boundary(4112 + i as u32, word, -Felt::ONE);
    }
    for (i, &word) in output.state.iter().enumerate() {
        boundary(3232 + i as u32, word, Felt::ONE);
    }
    assert!(
        net.values().all(|multiplicity| *multiplicity == Felt::ZERO),
        "SHA-256 and BPL lookup buses must balance at every message"
    );
    assert_eq!(Sha256CompressionAir.num_public_values(), NUM_PUBLIC_VALUES);
}

fn two_block_bus_residual(mutator: impl FnOnce(&mut RowMajorMatrix<Felt>)) -> usize {
    let states = [[0x0123_4567; 8], [0xfedc_ba98; 8]];
    let blocks = [
        [0x89ab_cdef; 16],
        core::array::from_fn(|i| (i as u32).wrapping_mul(0x0102_0304)),
    ];
    let mut requires = Sha256CompressionRequires::new();
    let outputs = [requires.require(states[0], blocks[0]), requires.require(states[1], blocks[1])];
    let mut bpl = BytePairLutRequires::new();
    let mut sha_main = generate_trace(requires, &mut bpl);
    let bpl_main = bpl_trace(bpl);
    mutator(&mut sha_main);

    let challenges = Challenges::new(
        QuadFelt::from_u64(19),
        QuadFelt::from_u64(37),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    let mut net = HashMap::new();
    fold_lookup_balance(&Sha256CompressionAir, &sha_main, &challenges, &mut net);
    fold_lookup_balance(&BytePairLutAir, &bpl_main, &challenges, &mut net);
    let mut boundary = |block_id: usize, addr: u32, value: u32, multiplicity: Felt| {
        *net.entry(word_msg(block_id, addr, value).encode(&challenges))
            .or_insert(Felt::ZERO) += multiplicity;
    };
    for block_id in 0..2 {
        for (i, &word) in blocks[block_id].iter().enumerate() {
            boundary(block_id, 4096 + i as u32, word, -Felt::ONE);
        }
        for (i, &word) in states[block_id].iter().enumerate() {
            boundary(block_id, 4112 + i as u32, word, -Felt::ONE);
        }
        for (i, &word) in outputs[block_id].state.iter().enumerate() {
            boundary(block_id, 3232 + i as u32, word, Felt::ONE);
        }
    }
    net.values().filter(|multiplicity| **multiplicity != Felt::ZERO).count()
}

#[test]
fn sha256_two_block_bus_baseline_balances() {
    assert_eq!(two_block_bus_residual(|_| {}), 0);
}

#[test]
fn sha256_two_block_bus_rejects_wrong_xor() {
    let row = first_slot(program::Op::Xor);
    assert!(
        two_block_bus_residual(|main| {
            main.values[row * NUM_MAIN_COLS + COL_R_BEGIN] += Felt::ONE;
        }) > 0
    );
}

#[test]
fn sha256_two_block_bus_rejects_wrong_and() {
    let row = first_slot(program::Op::And);
    assert!(
        two_block_bus_residual(|main| {
            main.values[row * NUM_MAIN_COLS + COL_R_BEGIN] += Felt::ONE;
        }) > 0
    );
}

#[test]
fn sha256_two_block_bus_rejects_cross_block_word() {
    let row = program::COMPRESSION_PERIOD + first_slot(program::Op::Xor);
    assert!(
        two_block_bus_residual(|main| {
            main.values[row * NUM_MAIN_COLS + COL_BLOCK_ID] = Felt::ZERO;
        }) > 0
    );
}

#[test]
fn sha256_two_block_bus_rejects_wrong_output() {
    let row = program::COMPRESSION_PERIOD + program::OUTPUT_SLOTS[0] as usize;
    assert!(
        two_block_bus_residual(|main| {
            main.values[row * NUM_MAIN_COLS + COL_R_BEGIN] += Felt::ONE;
        }) > 0
    );
}

#[test]
fn sha256_two_block_bus_rejects_byte_256() {
    let row = first_slot(program::Op::Xor);
    assert!(
        two_block_bus_residual(|main| {
            main.values[row * NUM_MAIN_COLS + COL_A_BEGIN] = Felt::from(256u32);
        }) > 0
    );
}

#[test]
fn sha256_two_block_bus_binds_rotation_source_bytes() {
    let row = first_slot(program::Op::Rol(30));
    assert!(
        two_block_bus_residual(|main| {
            // ROL stores the unrotated source in r; XOR(a, 0, r) must enforce r == a.
            main.values[row * NUM_MAIN_COLS + COL_R_BEGIN] += Felt::ONE;
        }) > 0
    );
}

#[test]
fn sha256_two_block_bus_ranges_logic_inputs_and_add_outputs() {
    for (op, column) in [
        (program::Op::And, COL_A_BEGIN),
        (program::Op::AndNot, COL_A_BEGIN),
        (program::Op::Add, COL_R_BEGIN),
    ] {
        let offset = first_slot(op) * NUM_MAIN_COLS + column;
        assert!(
            two_block_bus_residual(|main| {
                // Keep the packed word unchanged so word lookups and ADD equations cannot
                // reject this non-byte representation; the byte-pair LUT must do so.
                let original = pack_test_bytes(&main.values[offset..offset + 4]);
                let two8 = Felt::from_u32(256);
                let compensation = (main.values[offset] - two8) * two8.inverse();
                main.values[offset + 1] += compensation;
                main.values[offset] = two8;
                assert_eq!(pack_test_bytes(&main.values[offset..offset + 4]), original);
                crate::tests::check_local(Sha256CompressionAir, main);
            }) > 0,
            "{op:?} must reject a non-byte digit"
        );
    }
}

#[test]
fn sha256_two_block_bus_rejects_range16_65536() {
    let row = first_slot(program::Op::Rol(30));
    assert!(
        two_block_bus_residual(|main| {
            main.values[row * NUM_MAIN_COLS + COL_ROT_BEGIN] = Felt::from(65_536u32);
        }) > 0
    );
}

fn sha256_iv() -> [u32; 8] {
    [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ]
}

fn padded_sha256_blocks(message: &[u8]) -> Vec<[u32; 16]> {
    let padded_len = (message.len() + 9).next_multiple_of(64);
    let mut bytes = vec![0u8; padded_len];
    bytes[..message.len()].copy_from_slice(message);
    bytes[message.len()] = 0x80;
    bytes[padded_len - 8..].copy_from_slice(&(message.len() as u64 * 8).to_be_bytes());
    bytes
        .as_chunks::<{ 4 * 16 }>()
        .0
        .iter()
        .map(|chunk| {
            core::array::from_fn(|i| {
                u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap())
            })
        })
        .collect()
}

fn sha256_digest_via_compression(message: &[u8]) -> [u32; 8] {
    let mut state = sha256_iv();
    let mut requires = Sha256CompressionRequires::new();
    for block in padded_sha256_blocks(message) {
        state = requires.require(state, block).state;
    }
    state
}

/// FIPS 180-4 §6.2.2, written independently of the program's round constants.
fn sha256_reference_compress(state: [u32; 8], block: [u32; 16]) -> [u32; 8] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut schedule = [0u32; 64];
    schedule[..16].copy_from_slice(&block);
    for t in 16..64 {
        let x = schedule[t - 15];
        let y = schedule[t - 2];
        let s0 = x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
        let s1 = y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10);
        schedule[t] =
            schedule[t - 16].wrapping_add(s0).wrapping_add(schedule[t - 7]).wrapping_add(s1);
    }
    let mut working = state;
    for (t, &word) in schedule.iter().enumerate() {
        let [a, b, c, d, e, f, g, h] = working;
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[t]).wrapping_add(word);
        let t2 = s0.wrapping_add(maj);
        working = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
    }
    core::array::from_fn(|i| state[i].wrapping_add(working[i]))
}

#[test]
fn sha256_compression_matches_fips_abc_vector() {
    let digest = sha256_digest_via_compression(b"abc");
    assert_eq!(
        digest,
        [
            0xba78_16bf,
            0x8f01_cfea,
            0x4141_40de,
            0x5dae_2223,
            0xb003_61a3,
            0x9617_7a9c,
            0xb410_ff61,
            0xf200_15ad,
        ]
    );
}

#[test]
fn sha256_padding_boundaries_match_oracle() {
    for len in [0usize, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 200] {
        let message: Vec<u8> =
            (0..len).map(|i| (i as u8).wrapping_mul(37).wrapping_add(11)).collect();
        let got = sha256_digest_via_compression(&message);
        let expected = digest_words(<[u8; 32]>::from(Sha256::hash(&message)));
        assert_eq!(got, expected, "message length {len}");
    }
}

#[test]
fn sha256_nonuniform_arbitrary_state_and_block_match_reference() {
    let state = [
        0x0123_4567,
        0xfedc_ba98,
        0x1111_2222,
        0xaaaa_bbbb,
        0x0f0e_0d0c,
        0x8877_6655,
        0x1357_9bdf,
        0x0bad_f00d,
    ];
    let block = [
        0x8000_0000,
        0x0102_0304,
        0x1112_1314,
        0x2122_2324,
        0x3132_3334,
        0x4142_4344,
        0x5152_5354,
        0x6162_6364,
        0x7172_7374,
        0x8182_8384,
        0x9192_9394,
        0xa1a2_a3a4,
        0xb1b2_b3b4,
        0xc1c2_c3c4,
        0xd1d2_d3d4,
        0xe1e2_e3e4,
    ];
    let mut requires = Sha256CompressionRequires::new();
    let got = requires.require(state, block).state;
    assert_eq!(got, sha256_reference_compress(state, block));
}

#[test]
fn sha256_short_templates_bind_all_program_fields() {
    use crate::hash::sha256::compression::{COL_PROG_BEGIN, COL_ROL_K};
    // Exercise each phase, initial inputs, expansion (including the idle lane 14), and late
    // rounds whose fanouts shrink.
    for row in [
        0, 1, 2, 32, 47, 288, 302, 543, 544, 559, 1054, 1055, 1056, 1079, 1176, 1184, 1207, 3111,
        3143, 3159, 3191, 3224, 3232, 3239, 3242, 4095,
    ] {
        for column in COL_PROG_BEGIN..=COL_ROL_K {
            assert_local_rejects(|main| main.values[row * NUM_MAIN_COLS + column] += Felt::ONE);
        }
    }
}

#[test]
fn sha256_controller_cannot_skip_repeat_or_truncate_phases() {
    use crate::hash::sha256::compression::{
        COL_CYCLE, COL_PHASE_BEGIN, COL_PHASE_END, COL_PHASE_INV,
    };
    for row in [0, 31, 32, 1055, 1056, 1183, 1184, 3231, 3232, 3263, 3264, 4095] {
        for column in COL_PHASE_BEGIN..=COL_PHASE_INV {
            // At a phase end delta is zero, so its inverse witness is unused.
            if column == COL_PHASE_INV
                && mutation_trace().values[row * NUM_MAIN_COLS + COL_PHASE_END] == Felt::ONE
            {
                continue;
            }
            assert_local_rejects(|main| main.values[row * NUM_MAIN_COLS + column] += Felt::ONE);
        }
    }
    for height in [128, 256, 512, 1024, 2048] {
        assert_local_rejects(|main| main.values.truncate(height * NUM_MAIN_COLS));
    }
    // A coordinated change to a cycle and its end witness cannot bypass the transition.
    assert_local_rejects(|main| {
        let row = &mut main.values[32 * NUM_MAIN_COLS..33 * NUM_MAIN_COLS];
        row[COL_CYCLE] = Felt::from(31u8);
        row[COL_PHASE_END] = Felt::ONE;
        row[COL_PHASE_INV] = Felt::ZERO;
    });
}

#[test]
fn sha256_metadata_is_held_through_each_round() {
    use crate::hash::sha256::compression::{COL_META_K, COL_META_T};
    for row in [32, 33, 47, 544, 559, 1184, 1185, 1215, 3231] {
        for column in COL_META_T..=COL_META_K {
            assert_local_rejects(|main| main.values[row * NUM_MAIN_COLS + column] += Felt::ONE);
        }
    }
}

#[test]
fn sha256_fixed_metadata_provider_authenticates_unused_tuple_fields() {
    use crate::hash::sha256::compression::{COL_META_A_MULT, COL_META_E_MULT, COL_META_K};
    for column in [COL_META_A_MULT, COL_META_E_MULT, COL_META_K] {
        assert!(
            two_block_bus_residual(|main| {
                // These fields do not affect a word-schedule instruction. Changing them for an
                // entire word preserves local constraints but must fail the fixed-table lookup.
                for row in main.values[544 * NUM_MAIN_COLS..560 * NUM_MAIN_COLS]
                    .as_chunks_mut::<{ NUM_MAIN_COLS }>()
                    .0
                {
                    row[column] += Felt::ONE;
                }
                crate::tests::check_local(Sha256CompressionAir, main);
            }) > 0
        );
    }
}

#[test]
fn sha256_empty_trace_needs_only_the_metadata_period() {
    let main = generate_trace(Sha256CompressionRequires::new(), &mut BytePairLutRequires::new());
    assert_eq!(main.height(), 128);
    crate::tests::check_local(Sha256CompressionAir, &main);
    assert!(Sha256CompressionAir.periodic_columns().iter().all(|column| column.len() <= 128));
    assert_eq!(crate::tests::log_quotient_degree(&Sha256CompressionAir), 2);
}

#[test]
fn sha256_materialized_program_matches_random_compressions() {
    let mut seed = 0x4d69_6465_6e53_4832u64;
    let mut random = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed >> 16) as u32
    };
    let mut requires = Sha256CompressionRequires::new();
    let expected: Vec<[u32; 8]> = (0..4)
        .map(|_| {
            let state = core::array::from_fn(|_| random());
            let block = core::array::from_fn(|_| random());
            requires.require(state, block);
            sha256_reference_compress(state, block)
        })
        .collect();
    let main = generate_trace(requires, &mut BytePairLutRequires::new());
    for (block, expected) in expected.iter().enumerate() {
        for (slot, expected) in program::OUTPUT_SLOTS.iter().zip(expected) {
            assert_eq!(
                trace_word(
                    &main,
                    block * program::COMPRESSION_PERIOD + *slot as usize,
                    COL_R_BEGIN
                ),
                *expected
            );
        }
    }
    crate::tests::check_local(Sha256CompressionAir, &main);
}
