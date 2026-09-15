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
use miden_crypto::hash::sha2::Sha512;
use miden_lifted_air::{BaseAir, LiftedAir};
use miden_precompiles_air::primitives::byte_pair_lut::eidos::Relation as EidosRelation;

use crate::{
    hash::sha512::compression::{
        COL_A_BEGIN, COL_ACT, COL_BLOCK_ID, COL_CARRY_HI, COL_CARRY_LO, COL_R_BEGIN, COL_ROT_BEGIN,
        NUM_MAIN_COLS, Sha512CompressionAir, Sha512CompressionRequires, Sha512WordMsg,
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
fn sha512_program_has_the_frozen_shape() {
    let slots = program::slots();
    assert_eq!(slots.len(), program::COMPRESSION_PERIOD);
    assert_eq!(program::real_slot_count(&slots), 3058);
    assert_eq!(slots[0].dst_mult, 64);
    assert_eq!(slots[1].dst_mult, 64);
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
    assert_eq!(counts, [24, 82, 928, 368, 816, 760, 80]);
    assert_eq!(program::OUTPUT_SLOTS, [4000, 4001, 4002, 4003, 4004, 4005, 4006, 4007]);
    assert!(slots.iter().enumerate().all(|(i, slot)| slot.sources_before_destination(i)));
    assert_eq!(<Sha512CompressionAir as BaseAir<Felt>>::width(&Sha512CompressionAir), 53);
    assert_eq!(Sha512CompressionAir.periodic_columns().len(), program::NUM_PERIODIC_COLS);
    assert_eq!(Sha512CompressionAir.periodic_columns()[0].len(), program::MAX_PERIODIC_LENGTH);
    assert_eq!(Sha512CompressionAir.aux_width(), 13);
}

#[test]
fn sha512_program_fanout_and_rotation_bounds_are_mechanical() {
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
            let reduced = shift % 32;
            assert!(reduced != 0 && reduced <= 30, "invalid reduced ROL shift {shift}");
        }
    }
    for output in program::OUTPUT_SLOTS {
        fanout[output as usize] += 1;
    }
    for (slot, expected) in slots.iter().zip(fanout) {
        assert_eq!(slot.dst_mult, expected, "fanout mismatch at slot");
    }
    assert_eq!(slots[0].op, program::Op::Const(0x03ff_ffff_ffff_ffff));
    assert_eq!(slots[1].op, program::Op::Const(0x01ff_ffff_ffff_ffff));
    assert!(slots.iter().any(|slot| slot.op == program::Op::Rol(30)));
    assert!(slots.iter().any(|slot| slot.op == program::Op::Rol(33)));
}

fn mutation_trace() -> RowMajorMatrix<Felt> {
    let state = [0, 1, 0xffff_ffff, 0x1_0000_0000, u64::MAX - 1, u64::MAX, 7, 13];
    let block = core::array::from_fn(|i| match i % 8 {
        0 => 0,
        1 => u64::MAX,
        2 => 0xffff_ffff,
        3 => 0x1_0000_0000,
        4 => 0xffff_ffff_0000_0001,
        5 => 0x8000_0000_0000_0000,
        6 => 0x0123_4567_89ab_cdef,
        _ => 0xfedc_ba98_7654_3210,
    });
    let mut requires = Sha512CompressionRequires::new();
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
        crate::tests::check_local(Sha512CompressionAir, &main);
    }));
    assert!(result.is_err(), "mutated trace unexpectedly satisfied local AIR");
}

fn assert_add_equations_hold(main: &RowMajorMatrix<Felt>, row_idx: usize) {
    let two32 = Felt::new(1u64 << 32).unwrap();
    let row = &main.values[row_idx * NUM_MAIN_COLS..(row_idx + 1) * NUM_MAIN_COLS];
    let a_lo = pack_test_bytes(&row[COL_A_BEGIN..COL_A_BEGIN + 4]);
    let a_hi = pack_test_bytes(&row[COL_A_BEGIN + 4..COL_A_BEGIN + 8]);
    let b_lo = pack_test_bytes(&row[COL_A_BEGIN + 8..COL_A_BEGIN + 12]);
    let b_hi = pack_test_bytes(&row[COL_A_BEGIN + 12..COL_A_BEGIN + 16]);
    let r_lo = pack_test_bytes(&row[COL_R_BEGIN..COL_R_BEGIN + 4]);
    let r_hi = pack_test_bytes(&row[COL_R_BEGIN + 4..COL_R_BEGIN + 8]);
    assert_eq!(a_lo + b_lo, r_lo + two32 * row[COL_CARRY_LO]);
    assert_eq!(a_hi + b_hi + row[COL_CARRY_LO], r_hi + two32 * row[COL_CARRY_HI]);
}

#[test]
#[should_panic]
fn sha512_rejects_non_boolean_activity() {
    let mut main = mutation_trace();
    main.values[COL_ACT] = Felt::from(2u8);
    crate::tests::check_local(Sha512CompressionAir, &main);
}

#[test]
fn sha512_rejects_non_boolean_carries_independently() {
    for high in [false, true] {
        let mut main = mutation_trace();
        let row = first_slot(program::Op::Add);
        let base = row * NUM_MAIN_COLS;
        let delta = -Felt::new(1u64 << 32).unwrap().inverse();
        if high {
            main.values[base + COL_R_BEGIN + 4] += Felt::ONE;
            main.values[base + COL_CARRY_HI] += delta;
        } else {
            main.values[base + COL_R_BEGIN] += Felt::ONE;
            main.values[base + COL_R_BEGIN + 4] += delta;
            main.values[base + COL_CARRY_LO] += delta;
        }
        assert_add_equations_hold(&main, row);
        let result = catch_unwind(AssertUnwindSafe(|| {
            crate::tests::check_local(Sha512CompressionAir, &main);
        }));
        assert!(result.is_err(), "carry {high:?} mutation unexpectedly passed");
    }
}

#[test]
fn sha512_rejects_wrong_constant_in_low_and_high_halves() {
    let row = first_slot(program::Op::Const(0x03ff_ffff_ffff_ffff));
    for offset in [0, 4] {
        assert_local_rejects(|main| {
            main.values[row * NUM_MAIN_COLS + COL_R_BEGIN + offset] += Felt::ONE;
        });
    }
}

#[test]
fn sha512_rejects_wrong_rotation_decomposition_in_low_and_high_limbs() {
    let row = first_slot(program::Op::Rol(30));
    for offset in [0, 4] {
        assert_local_rejects(|main| {
            main.values[row * NUM_MAIN_COLS + COL_ROT_BEGIN + offset] += Felt::ONE;
        });
    }
}

#[test]
fn sha512_rejects_wrong_add_result_in_low_and_high_halves() {
    let row = first_slot(program::Op::Add);
    for offset in [0, 4] {
        assert_local_rejects(|main| {
            main.values[row * NUM_MAIN_COLS + COL_R_BEGIN + offset] += Felt::ONE;
        });
    }
}

#[test]
#[should_panic]
fn sha512_rejects_shifted_block_ids_via_first_row_anchor() {
    let mut requires = Sha512CompressionRequires::new();
    requires.require([0; 8], [0; 16]);
    requires.require([1; 8], [1; 16]);
    let mut main = crate::hash::sha512::compression::generate_trace_padded_to(
        requires,
        &mut BytePairLutRequires::new(),
        8192,
    );
    for row in main.values.as_chunks_mut::<{ NUM_MAIN_COLS }>().0 {
        row[COL_BLOCK_ID] += Felt::ONE;
    }
    crate::tests::check_local(Sha512CompressionAir, &main);
}

#[test]
#[should_panic]
fn sha512_rejects_reactivation_after_inactive_block() {
    let mut requires = Sha512CompressionRequires::new();
    requires.require([0; 8], [0; 16]);
    requires.require([1; 8], [1; 16]);
    let mut main = crate::hash::sha512::compression::generate_trace_padded_to(
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
    crate::tests::check_local(Sha512CompressionAir, &main);
}

#[test]
fn sha512_arithmetic_edges_cover_rotations_and_all_carry_combinations() {
    let goldilocks = 0xffff_ffff_0000_0001u64;
    let words = [
        0,
        1,
        0xffff_ffff,
        0x1_0000_0000,
        goldilocks - 1,
        goldilocks,
        goldilocks + 1,
        u64::MAX - 1,
        u64::MAX,
    ];
    let state = core::array::from_fn(|i| words[(i * 3) % words.len()]);
    let block = core::array::from_fn(|i| words[(i * 5 + 1) % words.len()]);
    let mut requires = Sha512CompressionRequires::new();
    requires.require(state, block);
    requires.require(core::array::from_fn(|i| words[(i * 7 + 2) % words.len()]), block);
    let main = generate_trace(requires, &mut BytePairLutRequires::new());
    let mut seen = 0u8;
    for row in main.values.as_chunks::<{ NUM_MAIN_COLS }>().0.iter() {
        if row[crate::hash::sha512::compression::COL_PROG_BEGIN + 5] == Felt::ONE {
            let lo = row[COL_CARRY_LO].as_canonical_u64() as u8;
            let hi = row[COL_CARRY_HI].as_canonical_u64() as u8;
            seen |= 1 << (lo | (hi << 1));
        }
    }
    assert_eq!(seen, 0b1111, "all four carry combinations must occur");
    crate::tests::check_local(Sha512CompressionAir, &main);
}

fn trace_word(main: &RowMajorMatrix<Felt>, row: usize, col_begin: usize) -> u64 {
    u64::from_le_bytes(core::array::from_fn(|i| {
        main.values[row * NUM_MAIN_COLS + col_begin + i].as_canonical_u64() as u8
    }))
}

#[test]
fn sha512_expansion_rotation_and_shift_slots_match_native_words() {
    let goldilocks = 0xffff_ffff_0000_0001u64;
    let state = [u64::MAX, goldilocks, 0x0123_4567_89ab_cdef, 7, 11, 13, 17, 19];
    let mut block = [0u64; 16];
    block[1] = u64::MAX;
    block[14] = goldilocks;
    let mut requires = Sha512CompressionRequires::new();
    requires.require(state, block);
    let main = generate_trace(requires, &mut BytePairLutRequires::new());
    let slots = program::slots();
    let rotr1_first = slots.iter().position(|s| s.op == program::Op::Rol(30)).unwrap();
    let rotr1_second = rotr1_first + 1;
    assert_eq!(slots[rotr1_second].op, program::Op::Rol(33));
    let w1 = trace_word(&main, 32 + 16 + 15, COL_R_BEGIN);
    assert_eq!(trace_word(&main, rotr1_second, COL_R_BEGIN), w1.rotate_left(30));
    let rotr1_consumer = slots
        .iter()
        .position(|s| matches!(s.op, program::Op::Xor) && s.src_a == rotr1_second as u32)
        .unwrap();
    assert_eq!(trace_word(&main, rotr1_consumer, COL_A_BEGIN), w1.rotate_right(1));
    let shr7 = slots.iter().position(|s| s.op == program::Op::And && s.src_b == 1).unwrap();
    assert_eq!(trace_word(&main, shr7, COL_R_BEGIN), w1.rotate_right(7) & 0x01ff_ffff_ffff_ffff);
    let shr6 = slots.iter().position(|s| s.op == program::Op::And && s.src_b == 0).unwrap();
    let w14 = trace_word(&main, 32 + 16 * 14 + 15, COL_R_BEGIN);
    assert_eq!(
        trace_word(&main, shr6, COL_R_BEGIN),
        w14.rotate_right(6) & 0x03ff_ffff_ffff_ffff
    );
    crate::tests::check_local(Sha512CompressionAir, &main);
}

#[test]
fn sha512_compression_trace_satisfies_local_air() {
    let mut requires = Sha512CompressionRequires::new();
    requires.require([0; 8], [0; 16]);
    let main = generate_trace(requires, &mut BytePairLutRequires::new());
    crate::tests::check_local(Sha512CompressionAir, &main);
}

#[test]
fn sha512_compression_matches_empty_message_oracle() {
    let iv = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
    let mut block = [0u64; 16];
    block[0] = 0x8000_0000_0000_0000;
    let mut requires = Sha512CompressionRequires::new();
    let got = requires.require(iv, block).state;
    let expected_bytes = <[u8; 64]>::from(Sha512::hash(b""));
    let expected = core::array::from_fn(|i| {
        u64::from_be_bytes(expected_bytes[i * 8..i * 8 + 8].try_into().unwrap())
    });
    assert_eq!(got, expected);

    let mut block = [0u64; 16];
    block[0] = 0x6162_6380_0000_0000;
    block[15] = 24;
    let got = requires.require(iv, block).state;
    let expected_bytes = <[u8; 64]>::from(Sha512::hash(b"abc"));
    let expected = core::array::from_fn(|i| {
        u64::from_be_bytes(expected_bytes[i * 8..i * 8 + 8].try_into().unwrap())
    });
    assert_eq!(got, expected);
}

#[test]
fn sha512_compression_supports_multiple_blocks_and_requested_padding() {
    let mut requires = Sha512CompressionRequires::new();
    requires.require([0; 8], [0; 16]);
    requires.require([1; 8], [u64::MAX; 16]);
    assert_eq!(requires.trace_height(), Some(8192));
    let main = crate::hash::sha512::compression::generate_trace_padded_to(
        requires,
        &mut BytePairLutRequires::new(),
        12_000,
    );
    assert_eq!(main.height(), 16_384);
    crate::tests::check_local(Sha512CompressionAir, &main);
}

#[test]
fn sha512_compression_records_all_byte_pair_and_range16_demands() {
    let mut requires = Sha512CompressionRequires::new();
    requires.require([0x0123_4567_89ab_cdef; 8], [0x0fed_cba9_8765_4321; 16]);
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
    assert_eq!(counts[COL_MULT_CANONICAL_XOR], (368 + 80 + 24 + 82 + 928 + 816 + 760) * 8);
    assert_eq!(counts[COL_MULT_RANGE16], 928 * 8);
    crate::tests::check_local(BytePairLutAir, &bpl_main);
    crate::tests::check_local(Sha512CompressionAir, &main);
}

#[test]
#[should_panic]
fn sha512_activity_cannot_restart_in_padded_tail() {
    let mut requires = Sha512CompressionRequires::new();
    requires.require([0; 8], [0; 16]);
    let mut main = crate::hash::sha512::compression::generate_trace_padded_to(
        requires,
        &mut BytePairLutRequires::new(),
        8192,
    );
    main.values[program::COMPRESSION_PERIOD * NUM_MAIN_COLS + COL_ACT] = Felt::ONE;
    crate::tests::check_local(Sha512CompressionAir, &main);
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

#[test]
fn sha512_and_bpl_buses_balance_with_input_and_output_boundaries() {
    let state = [0x0123_4567_89ab_cdef; 8];
    let block = [0x0fed_cba9_8765_4321; 16];
    let mut requires = Sha512CompressionRequires::new();
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
    fold_lookup_balance(&Sha512CompressionAir, &sha_main, &challenges, &mut net);
    fold_lookup_balance(&BytePairLutAir, &bpl_main, &challenges, &mut net);

    let mut boundary = |addr: u32, value: u64, multiplicity: Felt| {
        let msg = Sha512WordMsg {
            block_id: Felt::ZERO,
            addr: Felt::from(addr),
            lo: Felt::from(value as u32),
            hi: Felt::from((value >> 32) as u32),
        };
        *net.entry(msg.encode(&challenges)).or_insert(Felt::ZERO) += multiplicity;
    };
    for (i, &word) in block.iter().enumerate() {
        boundary(4096 + i as u32, word, -Felt::ONE);
    }
    for (i, &word) in state.iter().enumerate() {
        boundary(4112 + i as u32, word, -Felt::ONE);
    }
    for (i, &word) in output.state.iter().enumerate() {
        boundary(4000 + i as u32, word, Felt::ONE);
    }
    assert!(
        net.values().all(|multiplicity| *multiplicity == Felt::ZERO),
        "SHA-512 and BPL lookup buses must balance at every message"
    );
    assert_eq!(Sha512CompressionAir.num_public_values(), NUM_PUBLIC_VALUES);
}

fn two_block_bus_residual(mutator: impl FnOnce(&mut RowMajorMatrix<Felt>)) -> usize {
    let states = [[0x0123_4567_89ab_cdef; 8], [0xfedc_ba98_7654_3210; 8]];
    let blocks = [
        [0x0fed_cba9_8765_4321; 16],
        core::array::from_fn(|i| (i as u64).wrapping_mul(0x0102_0304_0506_0708)),
    ];
    let mut requires = Sha512CompressionRequires::new();
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
    fold_lookup_balance(&Sha512CompressionAir, &sha_main, &challenges, &mut net);
    fold_lookup_balance(&BytePairLutAir, &bpl_main, &challenges, &mut net);
    let mut boundary = |block_id: usize, addr: u32, value: u64, multiplicity: Felt| {
        let msg = Sha512WordMsg {
            block_id: Felt::from(block_id as u32),
            addr: Felt::from(addr),
            lo: Felt::from(value as u32),
            hi: Felt::from((value >> 32) as u32),
        };
        *net.entry(msg.encode(&challenges)).or_insert(Felt::ZERO) += multiplicity;
    };
    for block_id in 0..2 {
        for (i, &word) in blocks[block_id].iter().enumerate() {
            boundary(block_id, 4096 + i as u32, word, -Felt::ONE);
        }
        for (i, &word) in states[block_id].iter().enumerate() {
            boundary(block_id, 4112 + i as u32, word, -Felt::ONE);
        }
        for (i, &word) in outputs[block_id].state.iter().enumerate() {
            boundary(block_id, 4000 + i as u32, word, Felt::ONE);
        }
    }
    net.values().filter(|multiplicity| **multiplicity != Felt::ZERO).count()
}

#[test]
fn sha512_two_block_bus_baseline_balances() {
    assert_eq!(two_block_bus_residual(|_| {}), 0);
}

#[test]
fn sha512_two_block_bus_rejects_wrong_xor() {
    let row = first_slot(program::Op::Xor);
    assert!(
        two_block_bus_residual(|main| {
            main.values[row * NUM_MAIN_COLS + COL_R_BEGIN] += Felt::ONE;
        }) > 0
    );
}

#[test]
fn sha512_two_block_bus_rejects_wrong_and() {
    let row = first_slot(program::Op::And);
    assert!(
        two_block_bus_residual(|main| {
            main.values[row * NUM_MAIN_COLS + COL_R_BEGIN] += Felt::ONE;
        }) > 0
    );
}

#[test]
fn sha512_two_block_bus_rejects_cross_block_word() {
    let row = program::COMPRESSION_PERIOD + first_slot(program::Op::Xor);
    assert!(
        two_block_bus_residual(|main| {
            main.values[row * NUM_MAIN_COLS + COL_BLOCK_ID] = Felt::ZERO;
        }) > 0
    );
}

#[test]
fn sha512_two_block_bus_rejects_wrong_output() {
    let row = program::COMPRESSION_PERIOD + program::OUTPUT_SLOTS[0] as usize;
    assert!(
        two_block_bus_residual(|main| {
            main.values[row * NUM_MAIN_COLS + COL_R_BEGIN] += Felt::ONE;
        }) > 0
    );
}

#[test]
fn sha512_two_block_bus_rejects_byte_256() {
    let row = first_slot(program::Op::Xor);
    assert!(
        two_block_bus_residual(|main| {
            main.values[row * NUM_MAIN_COLS + COL_A_BEGIN] = Felt::from(256u32);
        }) > 0
    );
}

#[test]
fn sha512_two_block_bus_binds_rotation_source_bytes() {
    let row = first_slot(program::Op::Rol(30));
    assert!(
        two_block_bus_residual(|main| {
            // ROL stores the unrotated source in r; XOR(a, 0, r) must enforce r == a.
            main.values[row * NUM_MAIN_COLS + COL_R_BEGIN] += Felt::ONE;
        }) > 0
    );
}

#[test]
fn sha512_two_block_bus_ranges_logic_inputs_and_add_outputs() {
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
                crate::tests::check_local(Sha512CompressionAir, main);
            }) > 0,
            "{op:?} must reject a non-byte digit"
        );
    }
}

#[test]
fn sha512_two_block_bus_rejects_range16_65536() {
    let row = first_slot(program::Op::Rol(30));
    assert!(
        two_block_bus_residual(|main| {
            main.values[row * NUM_MAIN_COLS + COL_ROT_BEGIN] = Felt::from(65_536u32);
        }) > 0
    );
}

fn sha512_iv() -> [u64; 8] {
    [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ]
}

fn padded_sha512_blocks(message: &[u8]) -> Vec<[u64; 16]> {
    let padded_len = (message.len() + 17).next_multiple_of(128);
    let mut bytes = vec![0u8; padded_len];
    bytes[..message.len()].copy_from_slice(message);
    bytes[message.len()] = 0x80;
    bytes[padded_len - 16..].copy_from_slice(&(message.len() as u128 * 8).to_be_bytes());
    bytes
        .as_chunks::<{ 8 * 16 }>()
        .0
        .iter()
        .map(|chunk| {
            core::array::from_fn(|i| {
                u64::from_be_bytes(chunk[i * 8..i * 8 + 8].try_into().unwrap())
            })
        })
        .collect()
}

fn sha512_digest_via_compression(message: &[u8]) -> [u64; 8] {
    let mut state = sha512_iv();
    let mut requires = Sha512CompressionRequires::new();
    for block in padded_sha512_blocks(message) {
        state = requires.require(state, block).state;
    }
    state
}

fn sha512_reference_compress(state: [u64; 8], block: [u64; 16]) -> [u64; 8] {
    let mut schedule = [0u64; 80];
    schedule[..16].copy_from_slice(&block);
    for t in 16..80 {
        let x = schedule[t - 15];
        let y = schedule[t - 2];
        let s0 =
            x.rotate_right(1) ^ x.rotate_right(8) ^ (x.rotate_right(7) & 0x01ff_ffff_ffff_ffff);
        let s1 =
            y.rotate_right(19) ^ y.rotate_right(61) ^ (y.rotate_right(6) & 0x03ff_ffff_ffff_ffff);
        schedule[t] =
            schedule[t - 16].wrapping_add(s0).wrapping_add(schedule[t - 7]).wrapping_add(s1);
    }
    let mut working = state;
    for (t, &word) in schedule.iter().enumerate() {
        let [a, b, c, d, e, f, g, h] = working;
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ ((!e) & g);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (c & (a ^ b));
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(program::K[t])
            .wrapping_add(word);
        let t2 = s0.wrapping_add(maj);
        working = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
    }
    core::array::from_fn(|i| state[i].wrapping_add(working[i]))
}

#[test]
fn sha512_padding_boundaries_match_oracle() {
    for len in [111usize, 112, 127, 128] {
        let message: Vec<u8> =
            (0..len).map(|i| (i as u8).wrapping_mul(37).wrapping_add(11)).collect();
        let got = sha512_digest_via_compression(&message);
        let expected_bytes = <[u8; 64]>::from(Sha512::hash(&message));
        let expected = core::array::from_fn(|i| {
            u64::from_be_bytes(expected_bytes[i * 8..i * 8 + 8].try_into().unwrap())
        });
        assert_eq!(got, expected, "message length {len}");
    }
}

#[test]
fn sha512_nonuniform_arbitrary_state_and_block_match_reference() {
    let state = [
        0x0123_4567_89ab_cdef,
        0xfedc_ba98_7654_3210,
        0x1111_2222_3333_4444,
        0xaaaa_bbbb_cccc_dddd,
        0x0f0e_0d0c_0b0a_0908,
        0x8877_6655_4433_2211,
        0x1357_9bdf_2468_ace0,
        0x0bad_f00d_dead_beef,
    ];
    let block = [
        0x8000_0000_0000_0000,
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
        0x2122_2324_2526_2728,
        0x3132_3334_3536_3738,
        0x4142_4344_4546_4748,
        0x5152_5354_5556_5758,
        0x6162_6364_6566_6768,
        0x7172_7374_7576_7778,
        0x8182_8384_8586_8788,
        0x9192_9394_9596_9798,
        0xa1a2_a3a4_a5a6_a7a8,
        0xb1b2_b3b4_b5b6_b7b8,
        0xc1c2_c3c4_c5c6_c7c8,
        0xd1d2_d3d4_d5d6_d7d8,
        0xe1e2_e3e4_e5e6_e7e8,
    ];
    let mut requires = Sha512CompressionRequires::new();
    let got = requires.require(state, block).state;
    assert_eq!(got, sha512_reference_compress(state, block));
}

#[test]
fn sha512_short_templates_bind_all_program_fields() {
    use crate::hash::sha512::compression::{COL_PROG_BEGIN, COL_SWAP};
    // Exercise each phase, initial inputs, expansion, and late rounds whose fanouts shrink.
    for row in [
        0, 1, 2, 32, 47, 288, 543, 544, 559, 1312, 1335, 1432, 1440, 1463, 3879, 3911, 3927, 3959,
        3992, 4000, 4007, 4010, 4095,
    ] {
        for column in COL_PROG_BEGIN..=COL_SWAP {
            assert_local_rejects(|main| main.values[row * NUM_MAIN_COLS + column] += Felt::ONE);
        }
    }
}

#[test]
fn sha512_controller_cannot_skip_repeat_or_truncate_phases() {
    use crate::hash::sha512::compression::{
        COL_CYCLE, COL_PHASE_BEGIN, COL_PHASE_END, COL_PHASE_INV,
    };
    for row in [0, 31, 32, 1311, 1312, 1439, 1440, 3999, 4000, 4031, 4032, 4095] {
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
        row[COL_CYCLE] = Felt::from(39u8);
        row[COL_PHASE_END] = Felt::ONE;
        row[COL_PHASE_INV] = Felt::ZERO;
    });
}

#[test]
fn sha512_metadata_is_held_through_each_round() {
    use crate::hash::sha512::compression::{COL_META_K_HI, COL_META_T};
    for row in [32, 33, 47, 544, 559, 1440, 1441, 1471, 3999] {
        for column in COL_META_T..=COL_META_K_HI {
            assert_local_rejects(|main| main.values[row * NUM_MAIN_COLS + column] += Felt::ONE);
        }
    }
}

#[test]
fn sha512_fixed_metadata_provider_authenticates_unused_tuple_fields() {
    use crate::hash::sha512::compression::{
        COL_META_A_MULT, COL_META_E_MULT, COL_META_K_HI, COL_META_K_LO,
    };
    for column in [COL_META_A_MULT, COL_META_E_MULT, COL_META_K_LO, COL_META_K_HI] {
        assert!(
            two_block_bus_residual(|main| {
                // These fields do not affect a word-schedule instruction. Changing them for an
                // entire cycle preserves local constraints but must fail the fixed-table lookup.
                for row in main.values[544 * NUM_MAIN_COLS..560 * NUM_MAIN_COLS]
                    .as_chunks_mut::<{ NUM_MAIN_COLS }>()
                    .0
                {
                    row[column] += Felt::ONE;
                }
                crate::tests::check_local(Sha512CompressionAir, main);
            }) > 0
        );
    }
}

#[test]
fn sha512_empty_trace_needs_only_the_metadata_period() {
    let main = generate_trace(Sha512CompressionRequires::new(), &mut BytePairLutRequires::new());
    assert_eq!(main.height(), 128);
    crate::tests::check_local(Sha512CompressionAir, &main);
    assert!(Sha512CompressionAir.periodic_columns().iter().all(|column| column.len() <= 128));
    assert_eq!(crate::tests::log_quotient_degree(&Sha512CompressionAir), 2);
}

#[test]
fn sha512_materialized_program_matches_random_compressions() {
    let mut seed = 0x4d69_6465_6e53_4841u64;
    let mut random = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut requires = Sha512CompressionRequires::new();
    let expected: Vec<[u64; 8]> = (0..4)
        .map(|_| {
            let state = core::array::from_fn(|_| random());
            let block = core::array::from_fn(|_| random());
            requires.require(state, block);
            sha512_reference_compress(state, block)
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
    crate::tests::check_local(Sha512CompressionAir, &main);
}
