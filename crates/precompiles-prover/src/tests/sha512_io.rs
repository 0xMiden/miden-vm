use std::{collections::HashMap, string::String, vec, vec::Vec};

use miden_air::lookup::Challenges;
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_crypto::hash::sha2::Sha512;

use crate::{
    hash::sha512::{
        compression::{self, Sha512CompressionAir, Sha512CompressionRequires, Sha512WordMsg},
        io::{self, Sha512IoAir, Sha512IoRequires, generate_trace},
    },
    logup::LookupMessage,
    primitives::byte_pair_lut::{self, BytePairLutAir, BytePairLutRequires, Range16Msg},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    tests::bus_balance::fold_balance,
    transcript::{
        binding::BindingMsg,
        eidos::{
            EidosCompressionAir,
            trace::{EidosRequires, generate_trace_with_byte_lookups as eidos_trace},
        },
    },
};

#[test]
fn sha512_io_padding_boundaries_match_all_eight_digest_words() {
    let mut io = Sha512IoRequires::new();
    let mut compression = Sha512CompressionRequires::new();
    let mut eidos = EidosRequires::new();
    for len in [
        0, 1, 3, 7, 8, 15, 16, 31, 32, 33, 63, 64, 95, 96, 111, 112, 113, 119, 120, 127, 128, 129,
        239, 240, 255, 256,
    ] {
        let input: Vec<u8> = (0..len).map(|i| [0, 0x80, 0xff, i as u8][i % 4]).collect();
        let output = io.require(&input, &mut compression, &mut eidos);
        assert_eq!(output.digest, <[u8; 64]>::from(Sha512::hash(&input)), "length {len}");
    }
    let trace = generate_trace(io, &mut BytePairLutRequires::new());
    crate::tests::check_local(Sha512IoAir, &trace);
}

#[test]
fn sha512_io_empty_accumulator_and_exact_final_row_are_valid() {
    crate::tests::check_local(
        Sha512IoAir,
        &generate_trace(Sha512IoRequires::new(), &mut BytePairLutRequires::new()),
    );
    let mut io = Sha512IoRequires::new();
    io.require(&[0xa5; 112], &mut Sha512CompressionRequires::new(), &mut EidosRequires::new());
    let main = generate_trace(io, &mut BytePairLutRequires::new());
    assert_eq!(main.values.len(), 32 * io::NUM_MAIN_COLS);
    crate::tests::check_local(Sha512IoAir, &main);
}

#[test]
fn sha512_io_rejects_noncanonical_padding_and_invocation_transitions() {
    let mut io = Sha512IoRequires::new();
    io.require(&[0xa5; 129], &mut Sha512CompressionRequires::new(), &mut EidosRequires::new());
    let main = io::generate_trace_padded_to(io, &mut BytePairLutRequires::new(), 64);
    crate::tests::check_local(Sha512IoAir, &main);
    // Each case changes a distinct part of the canonical message/padding layout. In particular,
    // the final digest pointer must be transported all the way into its row-15 EidosOut read.
    for (name, row, col, value) in [
        ("claimed length", 0, io::COL_LEN, Felt::from_u32(130)),
        ("negative countdown", 1, io::COL_LEFT, -Felt::ONE),
        ("countdown decomposition", 0, io::COL_LEFT_LO16, Felt::ZERO),
        ("message restarts after padding", 17, io::COL_MSG_BEGIN, Felt::ONE),
        ("nonzero raw zero tail", 17, io::COL_RAW_BEGIN, Felt::ONE),
        ("missing padding marker", 16, io::COL_WORD_HI, Felt::new_unchecked(0xa500_0000)),
        ("repeated padding marker", 17, io::COL_WORD_HI, Felt::new_unchecked(0x8000_0000)),
        ("nonzero upper bit length", 30, io::COL_WORD_LO, Felt::ONE),
        ("byte length instead of bit length", 31, io::COL_WORD_LO, Felt::from_u32(129)),
        ("nonstandard IV", 0, io::COL_STATE_LO, Felt::ZERO),
        ("wrong block id", 16, io::COL_BLOCK_ID, Felt::ZERO),
        ("activity changes within block", 1, io::COL_ACT, Felt::ZERO),
        ("activity reactivates", 48, io::COL_ACT, Felt::ONE),
        ("non-Boolean activity", 1, io::COL_ACT, Felt::from_u8(2)),
        ("extra raw zero chunk", 20, io::COL_CHUNK_ACTIVE, Felt::ONE),
        ("raw chunk skips a cycle", 4, io::COL_INPUT_EIDOS, Felt::ZERO),
        ("raw chain head drifts", 5, io::COL_INPUT_HEAD, Felt::ONE),
        ("raw chunk head not forwarded", 2, io::COL_CHUNK_HEAD_RAW, Felt::ONE),
        ("digest chunk head not forwarded", 18, io::COL_CHUNK_HEAD_DIGEST, Felt::ONE),
        ("final digest span substituted on row 15", 31, io::COL_DIGEST_EIDOS, Felt::ZERO),
        ("off-end Binding output", 1, io::COL_OUT_MULT, Felt::ONE),
    ] {
        let mut bad = main.clone();
        bad.values[row * io::NUM_MAIN_COLS + col] = value;
        assert!(
            std::panic::catch_unwind(|| crate::tests::check_local(Sha512IoAir, &bad)).is_err(),
            "{name}"
        );
    }
    for (name, block, final_flag) in [
        ("premature final block", 0, Felt::ONE),
        ("gratuitous extra block", 1, Felt::ZERO),
    ] {
        let mut bad = main.clone();
        for row in block * 16..(block + 1) * 16 {
            bad.values[row * io::NUM_MAIN_COLS + io::COL_FINAL_BLOCK] = final_flag;
        }
        assert!(
            std::panic::catch_unwind(|| crate::tests::check_local(Sha512IoAir, &bad)).is_err(),
            "{name}"
        );
    }
    // The one-/two-block padding boundary must reject either direction of a final-block flip.
    for len in [110, 111, 112, 127, 128] {
        let mut io = Sha512IoRequires::new();
        io.require(
            &vec![0xa5; len],
            &mut Sha512CompressionRequires::new(),
            &mut EidosRequires::new(),
        );
        let main = generate_trace(io, &mut BytePairLutRequires::new());
        crate::tests::check_local(Sha512IoAir, &main);
        for block in 0..(len + 17).div_ceil(128) {
            let mut bad = main.clone();
            for row in block * io::IO_PERIOD..(block + 1) * io::IO_PERIOD {
                let flag = &mut bad.values[row * io::NUM_MAIN_COLS + io::COL_FINAL_BLOCK];
                *flag = Felt::ONE - *flag;
            }
            assert!(
                std::panic::catch_unwind(|| crate::tests::check_local(Sha512IoAir, &bad)).is_err(),
                "length {len}, block {block}: changing the final block must fail"
            );
        }
    }
}

#[test]
fn sha512_io_binds_chained_blocks_full_digest_and_shared_eidos_multiplicities() {
    let mut io = Sha512IoRequires::new();
    let mut compression = Sha512CompressionRequires::new();
    let mut eidos = EidosRequires::new();
    let challenges = Challenges::new(
        QuadFelt::from_u64(17),
        QuadFelt::from_u64(31),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    let mut net: HashMap<QuadFelt, (Felt, String)> = HashMap::new();
    // Duplicate inputs reuse shared Eidos spans; [1] and [1,0] share raw chunks but differ in
    // length.
    for input in [vec![0xa5; 129], vec![1], vec![1, 0], vec![1], vec![]] {
        let output = io.require(&input, &mut compression, &mut eidos);
        assert_eq!(output.digest, <[u8; 64]>::from(Sha512::hash(&input)));
        let expected = BindingMsg::truth(output.h_sha512.0);
        net.entry(expected.encode(&challenges)).or_insert((Felt::ZERO, String::new())).0 +=
            Felt::ONE;
    }
    let mut bpl = BytePairLutRequires::new();
    let main = generate_trace(io, &mut bpl);
    let compression_main = compression::generate_trace(compression, &mut bpl);
    fold_balance(&Sha512CompressionAir, &compression_main, &challenges, &mut net);
    let eidos_main = eidos_trace(eidos, &mut bpl);
    fold_balance(&EidosCompressionAir, &eidos_main, &challenges, &mut net);
    fold_balance(&BytePairLutAir, &byte_pair_lut::generate_trace(bpl), &challenges, &mut net);
    let balanced = |trace: &RowMajorMatrix<Felt>| {
        let mut actual = net.clone();
        fold_balance(&Sha512IoAir, trace, &challenges, &mut actual);
        actual.values().all(|(mult, _)| *mult == Felt::ZERO)
    };
    assert!(
        balanced(&main),
        "honest SHA compression, IO, Eidos, and byte/range messages must balance"
    );
    for (name, row, col) in [
        ("borrowed chaining state", 16, io::COL_STATE_LO),
        ("digest low half", 16, io::COL_DIGEST_BEGIN),
        ("digest high half", 23, io::COL_DIGEST_BEGIN),
        ("reordered raw block", 2, io::COL_PREVIOUS_RAW),
        ("wrong raw chunk head", 2, io::COL_CHUNK_HEAD_RAW),
        ("reordered digest block", 18, io::COL_PREVIOUS_DIGEST),
        ("wrong digest chunk head", 22, io::COL_CHUNK_HEAD_DIGEST),
        ("wrong raw CHUNKS digest", 31, io::COL_H_INPUT),
        ("wrong full digest commitment", 31, io::COL_H_DIGEST),
        ("wrong SHA assertion hash", 31, io::H_SHA512_COLS[0]),
        ("wrong node Eidos chain", 31, io::COL_NODE_EIDOS),
        ("wrong raw chain head", 31, io::COL_INPUT_HEAD),
        ("wrong assertion length", 31, io::COL_LEN),
        ("missing duplicate Binding consume", 79, io::COL_OUT_MULT),
    ] {
        let mut bad = main.clone();
        bad.values[row * io::NUM_MAIN_COLS + col] += Felt::ONE;
        assert!(!balanced(&bad), "{name}");
    }
    // A full u64 equal to 8*n+p aliases the field equality for the bit length. Its high half
    // must still fail Range16; simply comparing a reconstructed u64 in the field is insufficient.
    let mut bad = main.clone();
    let alias = 129 * 8 + 0xffff_ffff_0000_0001u64;
    bad.values[31 * io::NUM_MAIN_COLS + io::COL_WORD_LO] = Felt::from_u32(alias as u32);
    bad.values[31 * io::NUM_MAIN_COLS + io::COL_WORD_HI] = Felt::from_u32((alias >> 32) as u32);
    crate::tests::check_local(Sha512IoAir, &bad);
    let mut alias_requests = HashMap::new();
    fold_balance(&Sha512IoAir, &bad, &challenges, &mut alias_requests);
    let invalid_high = Range16Msg { w: Felt::from_u32((alias >> 32) as u32) };
    assert_eq!(
        alias_requests[&invalid_high.encode(&challenges)].0,
        Felt::ONE,
        "the length alias must explicitly request the impossible high-half Range16 value"
    );
    assert!(
        !balanced(&bad),
        "noncanonical length alias must be rejected through lookup constraints"
    );
    // A legal high-half Range16 value can still hide a non-u32 low half in the field equality.
    // Only the compression band's byte-checked INPUT binds these halves to a real SHA word.
    let mut bad = main.clone();
    let bad_lo = Felt::from_u32(129 * 8) - Felt::new_unchecked(1u64 << 32);
    bad.values[31 * io::NUM_MAIN_COLS + io::COL_WORD_LO] = bad_lo;
    bad.values[31 * io::NUM_MAIN_COLS + io::COL_WORD_HI] = Felt::ONE;
    crate::tests::check_local(Sha512IoAir, &bad);
    let mut residual = net.clone();
    fold_balance(&Sha512IoAir, &bad, &challenges, &mut residual);
    // Supply the substituted (valid) Range16 value so the remaining rejection isolates Sha512Word.
    for (w, delta) in [(Felt::ZERO, Felt::ONE), (Felt::ONE, -Felt::ONE)] {
        residual.entry(Range16Msg { w }.encode(&challenges)).or_default().0 += delta;
    }
    let word_message = |lo, hi| {
        Sha512WordMsg {
            block_id: Felt::ONE,
            addr: Felt::from_u32(compression::INPUT_ADDR_BASE + 15),
            lo,
            hi,
        }
        .encode(&challenges)
    };
    assert_eq!(residual[&word_message(bad_lo, Felt::ONE)].0, -Felt::ONE);
    assert_eq!(residual[&word_message(Felt::from_u32(129 * 8), Felt::ZERO)].0, Felt::ONE);
    assert_eq!(residual.values().filter(|(mult, _)| *mult != Felt::ZERO).count(), 2);
    for col in [io::COL_RAW_BEGIN, io::COL_DIGEST_BEGIN] {
        let mut bad = main.clone();
        // Preserve the big-endian packed word using non-byte digits; the byte LUT must reject it.
        let row = if col == io::COL_RAW_BEGIN { 0 } else { 16 };
        bad.values[row * io::NUM_MAIN_COLS + col] -= Felt::ONE;
        bad.values[row * io::NUM_MAIN_COLS + col + 1] += Felt::from_u32(256);
        assert!(!balanced(&bad), "non-byte digits cannot change the endian interpretation");
    }
}
