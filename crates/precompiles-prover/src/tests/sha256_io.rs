use std::{collections::HashMap, string::String, vec, vec::Vec};

use miden_air::lookup::Challenges;
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_crypto::hash::sha2::Sha256;

use crate::{
    hash::sha256::{
        compression::{self, Sha256CompressionAir, Sha256CompressionRequires, Sha256WordMsg},
        io::{self, Sha256IoAir, Sha256IoRequires, generate_trace},
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
fn sha256_io_padding_boundaries_match_all_eight_digest_words() {
    let mut io = Sha256IoRequires::new();
    let mut compression = Sha256CompressionRequires::new();
    let mut eidos = EidosRequires::new();
    for len in [
        0, 1, 3, 7, 8, 15, 16, 31, 32, 33, 55, 56, 57, 63, 64, 65, 95, 96, 119, 120, 127, 128, 129,
    ] {
        let input: Vec<u8> = (0..len).map(|i| [0, 0x80, 0xff, i as u8][i % 4]).collect();
        let output = io.require(&input, &mut compression, &mut eidos);
        assert_eq!(output.digest, <[u8; 32]>::from(Sha256::hash(&input)), "length {len}");
    }
    let trace = generate_trace(io, &mut BytePairLutRequires::new());
    crate::tests::check_local(Sha256IoAir, &trace);
}

#[test]
fn sha256_io_empty_accumulator_and_exact_final_row_are_valid() {
    crate::tests::check_local(
        Sha256IoAir,
        &generate_trace(Sha256IoRequires::new(), &mut BytePairLutRequires::new()),
    );
    let mut io = Sha256IoRequires::new();
    io.require(&[0xa5; 56], &mut Sha256CompressionRequires::new(), &mut EidosRequires::new());
    let main = generate_trace(io, &mut BytePairLutRequires::new());
    assert_eq!(main.values.len(), 16 * io::NUM_MAIN_COLS);
    crate::tests::check_local(Sha256IoAir, &main);
}

#[test]
fn sha256_io_rejects_noncanonical_padding_and_invocation_transitions() {
    let mut io = Sha256IoRequires::new();
    io.require(&[0xa5; 65], &mut Sha256CompressionRequires::new(), &mut EidosRequires::new());
    let main = io::generate_trace_padded_to(io, &mut BytePairLutRequires::new(), 32);
    crate::tests::check_local(Sha256IoAir, &main);
    // Each case changes a distinct part of the canonical message/padding layout. In particular,
    // the final digest pointer must be transported all the way into its row-7 EidosOut read.
    for (name, row, col, value) in [
        ("claimed length", 0, io::COL_LEN, Felt::from_u32(66)),
        ("negative countdown", 1, io::COL_LEFT, -Felt::ONE),
        ("countdown decomposition", 0, io::COL_LEFT_LO16, Felt::ZERO),
        ("message restarts after padding", 9, io::COL_MSG_BEGIN, Felt::ONE),
        ("nonzero raw zero tail", 9, io::COL_RAW_BEGIN, Felt::ONE),
        ("missing padding marker", 8, io::COL_WORD_HI, Felt::new_unchecked(0xa500_0000)),
        ("repeated padding marker", 9, io::COL_WORD_HI, Felt::new_unchecked(0x8000_0000)),
        ("nonzero upper bit length", 15, io::COL_WORD_HI, Felt::ONE),
        ("byte length instead of bit length", 15, io::COL_WORD_LO, Felt::from_u32(65)),
        ("nonstandard IV", 0, io::COL_STATE_LO, Felt::ZERO),
        ("wrong block id", 8, io::COL_BLOCK_ID, Felt::ZERO),
        ("activity changes within block", 1, io::COL_ACT, Felt::ZERO),
        ("activity reactivates", 24, io::COL_ACT, Felt::ONE),
        ("non-Boolean activity", 1, io::COL_ACT, Felt::from_u8(2)),
        ("extra raw zero chunk", 12, io::COL_CHUNK_ACTIVE, Felt::ONE),
        ("raw chunk skips a cycle", 4, io::COL_INPUT_EIDOS, Felt::ZERO),
        ("raw chain head drifts", 5, io::COL_INPUT_HEAD, Felt::ONE),
        ("raw chunk head not forwarded", 2, io::COL_CHUNK_HEAD_RAW, Felt::ONE),
        ("digest chunk head not forwarded", 10, io::COL_CHUNK_HEAD_DIGEST, Felt::ONE),
        ("final digest span substituted on row 7", 15, io::COL_DIGEST_EIDOS, Felt::ZERO),
        ("off-end Binding output", 1, io::COL_OUT_MULT, Felt::ONE),
    ] {
        let mut bad = main.clone();
        bad.values[row * io::NUM_MAIN_COLS + col] = value;
        assert!(
            std::panic::catch_unwind(|| crate::tests::check_local(Sha256IoAir, &bad)).is_err(),
            "{name}"
        );
    }
    for (name, block, final_flag) in [
        ("premature final block", 0, Felt::ONE),
        ("gratuitous extra block", 1, Felt::ZERO),
    ] {
        let mut bad = main.clone();
        for row in block * io::IO_PERIOD..(block + 1) * io::IO_PERIOD {
            bad.values[row * io::NUM_MAIN_COLS + io::COL_FINAL_BLOCK] = final_flag;
        }
        assert!(
            std::panic::catch_unwind(|| crate::tests::check_local(Sha256IoAir, &bad)).is_err(),
            "{name}"
        );
    }
    // The one-/two-block padding boundary must reject either direction of a final-block flip.
    for len in [54, 55, 56, 63, 64] {
        let mut io = Sha256IoRequires::new();
        io.require(
            &vec![0xa5; len],
            &mut Sha256CompressionRequires::new(),
            &mut EidosRequires::new(),
        );
        let main = generate_trace(io, &mut BytePairLutRequires::new());
        crate::tests::check_local(Sha256IoAir, &main);
        for block in 0..(len + 9).div_ceil(64) {
            let mut bad = main.clone();
            for row in block * io::IO_PERIOD..(block + 1) * io::IO_PERIOD {
                let flag = &mut bad.values[row * io::NUM_MAIN_COLS + io::COL_FINAL_BLOCK];
                *flag = Felt::ONE - *flag;
            }
            assert!(
                std::panic::catch_unwind(|| crate::tests::check_local(Sha256IoAir, &bad)).is_err(),
                "length {len}, block {block}: changing the final block must fail"
            );
        }
    }
}

#[test]
fn sha256_io_marker_fit_rejects_length_row_forgeries() {
    let width = io::NUM_MAIN_COLS;
    let last_row = (io::IO_PERIOD - 1) * width;
    let honest = |len: usize| {
        let mut io = Sha256IoRequires::new();
        io.require(
            &vec![0xa5; len],
            &mut Sha256CompressionRequires::new(),
            &mut EidosRequires::new(),
        );
        generate_trace(io, &mut BytePairLutRequires::new()).values
    };

    // Fifty-six bytes fill rows 0..6, so the marker needs row 7 and SHA-256 pads a second block.
    // Declaring the first block final puts the length on row 7 and hashes the message without
    // its marker. Every other local equation accepts this forgery.
    let mut forged = honest(56)[..io::IO_PERIOD * width].to_vec();
    for row in forged.as_chunks_mut::<{ io::NUM_MAIN_COLS }>().0 {
        row[io::COL_FINAL_BLOCK] = Felt::ONE;
    }
    assert_eq!(forged[last_row + io::COL_BEFORE], Felt::ONE, "the marker is still pending");
    forged[last_row + io::COL_WORD_HI] = Felt::ZERO;
    forged[last_row + io::COL_WORD_LO] = Felt::from_u32(56 * 8);
    let forged = RowMajorMatrix::new(forged, width);
    assert!(
        std::panic::catch_unwind(|| crate::tests::check_local(Sha256IoAir, &forged)).is_err(),
        "a final block must end the message and marker before its length row"
    );

    // Conversely, three bytes fit one block. Declaring it non-final and appending an all-zero
    // block moves the length one block later, hashing a different padding.
    let honest = honest(3);
    let mut forged = honest.clone();
    for row in forged.as_chunks_mut::<{ io::NUM_MAIN_COLS }>().0 {
        row[io::COL_FINAL_BLOCK] = Felt::ZERO;
    }
    assert_eq!(forged[last_row + io::COL_BEFORE], Felt::ZERO, "the marker is already placed");
    forged[last_row + io::COL_WORD_LO] = Felt::ZERO;
    forged[last_row + io::COL_OUT_MULT] = Felt::ZERO;
    for i in 0..io::IO_PERIOD {
        let mut row = [Felt::ZERO; io::NUM_MAIN_COLS];
        for column in [
            io::COL_INPUT_EIDOS,
            io::COL_INPUT_HEAD,
            io::COL_DIGEST_EIDOS,
            io::COL_NODE_EIDOS,
        ] {
            row[column] = honest[last_row + column];
        }
        row[io::COL_ACT] = Felt::ONE;
        row[io::COL_BLOCK_ID] = Felt::ONE;
        row[io::COL_FINAL_BLOCK] = Felt::ONE;
        row[io::COL_LEN] = Felt::from_u32(3);
        if i == io::IO_PERIOD - 1 {
            row[io::COL_WORD_LO] = Felt::from_u32(3 * 8);
        }
        forged.extend_from_slice(&row);
    }
    let forged = RowMajorMatrix::new(forged, width);
    assert!(
        std::panic::catch_unwind(|| crate::tests::check_local(Sha256IoAir, &forged)).is_err(),
        "a non-final block must still carry the pending marker into its last row"
    );
}

#[test]
fn sha256_io_binds_chained_blocks_full_digest_and_shared_eidos_multiplicities() {
    let mut io = Sha256IoRequires::new();
    let mut compression = Sha256CompressionRequires::new();
    let mut eidos = EidosRequires::new();
    let challenges = Challenges::new(
        QuadFelt::from_u64(17),
        QuadFelt::from_u64(31),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    let mut net: HashMap<QuadFelt, (Felt, String)> = HashMap::new();
    // Duplicate inputs reuse shared Eidos spans; [1] and [1,0] share raw chunks but differ in
    // length. Extra consumers of the [1,0] claim reuse its hashing work and must raise its
    // Binding multiplicity instead.
    for (index, input) in
        [vec![0xa5; 65], vec![1], vec![1, 0], vec![1], vec![]].into_iter().enumerate()
    {
        let output = io.require(&input, &mut compression, &mut eidos);
        assert_eq!(output.digest, <[u8; 32]>::from(Sha256::hash(&input)));
        assert_eq!(output.invocation, index as u32);
        let consumers = if index == 2 { 3 } else { 1 };
        if consumers > 1 {
            io.add_consumers(output.invocation, consumers - 1);
        }
        let expected = BindingMsg::truth(output.h_sha256.0);
        net.entry(expected.encode(&challenges)).or_insert((Felt::ZERO, String::new())).0 +=
            Felt::from_u32(consumers);
    }
    let mut bpl = BytePairLutRequires::new();
    let main = generate_trace(io, &mut bpl);
    let compression_main = compression::generate_trace(compression, &mut bpl);
    fold_balance(&Sha256CompressionAir, &compression_main, &challenges, &mut net);
    let eidos_main = eidos_trace(eidos, &mut bpl);
    fold_balance(&EidosCompressionAir, &eidos_main, &challenges, &mut net);
    fold_balance(&BytePairLutAir, &byte_pair_lut::generate_trace(bpl), &challenges, &mut net);
    let balanced = |trace: &RowMajorMatrix<Felt>| {
        let mut actual = net.clone();
        fold_balance(&Sha256IoAir, trace, &challenges, &mut actual);
        actual.values().all(|(mult, _)| *mult == Felt::ZERO)
    };
    assert!(
        balanced(&main),
        "honest SHA compression, IO, Eidos, and byte/range messages must balance"
    );
    for (name, row, col) in [
        ("borrowed chaining state (high word)", 8, io::COL_STATE_HI),
        ("borrowed chaining state (low word)", 8, io::COL_STATE_LO),
        ("digest first word", 8, io::COL_DIGEST_BEGIN),
        ("digest second word", 8, io::COL_DIGEST_BEGIN + 4),
        ("digest last word", 11, io::COL_DIGEST_BEGIN + 7),
        ("reordered raw block", 2, io::COL_PREVIOUS_RAW),
        ("wrong raw chunk head", 2, io::COL_CHUNK_HEAD_RAW),
        ("reordered digest block", 10, io::COL_PREVIOUS_DIGEST),
        ("wrong digest chunk head", 10, io::COL_CHUNK_HEAD_DIGEST),
        ("wrong raw CHUNKS digest", 15, io::COL_H_INPUT),
        ("wrong full digest commitment", 15, io::COL_H_DIGEST),
        ("wrong SHA assertion hash", 15, io::H_SHA256_COLS[0]),
        ("wrong node Eidos chain", 15, io::COL_NODE_EIDOS),
        ("wrong raw chain head", 15, io::COL_INPUT_HEAD),
        ("wrong assertion length", 15, io::COL_LEN),
        ("unbound extra claim consumers", 31, io::COL_OUT_MULT),
        ("missing duplicate Binding consume", 39, io::COL_OUT_MULT),
    ] {
        let mut bad = main.clone();
        bad.values[row * io::NUM_MAIN_COLS + col] += Felt::ONE;
        assert!(!balanced(&bad), "{name}");
    }
    // A 64-bit length equal to 8*n+p aliases the field equality for the bit length. Its high word
    // must still fail Range16; simply comparing a reconstructed u64 in the field is insufficient.
    let mut bad = main.clone();
    let alias = 65 * 8 + 0xffff_ffff_0000_0001u64;
    bad.values[15 * io::NUM_MAIN_COLS + io::COL_WORD_LO] = Felt::from_u32(alias as u32);
    bad.values[15 * io::NUM_MAIN_COLS + io::COL_WORD_HI] = Felt::from_u32((alias >> 32) as u32);
    crate::tests::check_local(Sha256IoAir, &bad);
    let mut alias_requests = HashMap::new();
    fold_balance(&Sha256IoAir, &bad, &challenges, &mut alias_requests);
    let invalid_high = Range16Msg { w: Felt::from_u32((alias >> 32) as u32) };
    assert_eq!(
        alias_requests[&invalid_high.encode(&challenges)].0,
        Felt::ONE,
        "the length alias must explicitly request the impossible high-word Range16 value"
    );
    assert!(
        !balanced(&bad),
        "noncanonical length alias must be rejected through lookup constraints"
    );
    // A legal high-word Range16 value can still hide a non-u32 low word in the field equality.
    // Only the compression band's byte-checked INPUTs bind both words to real SHA words.
    let mut bad = main.clone();
    let bad_lo = Felt::from_u32(65 * 8) - Felt::new_unchecked(1u64 << 32);
    bad.values[15 * io::NUM_MAIN_COLS + io::COL_WORD_LO] = bad_lo;
    bad.values[15 * io::NUM_MAIN_COLS + io::COL_WORD_HI] = Felt::ONE;
    crate::tests::check_local(Sha256IoAir, &bad);
    let mut residual = net.clone();
    fold_balance(&Sha256IoAir, &bad, &challenges, &mut residual);
    // Supply the substituted (valid) Range16 value so the remaining rejection isolates Sha256Word.
    for (w, delta) in [(Felt::ZERO, Felt::ONE), (Felt::ONE, -Felt::ONE)] {
        residual.entry(Range16Msg { w }.encode(&challenges)).or_default().0 += delta;
    }
    let word_message = |addr: u32, value| {
        Sha256WordMsg {
            block_id: Felt::ONE,
            addr: Felt::from_u32(compression::INPUT_ADDR_BASE + addr),
            value,
        }
        .encode(&challenges)
    };
    assert_eq!(residual[&word_message(15, bad_lo)].0, -Felt::ONE);
    assert_eq!(residual[&word_message(15, Felt::from_u32(65 * 8))].0, Felt::ONE);
    assert_eq!(residual[&word_message(14, Felt::ONE)].0, -Felt::ONE);
    assert_eq!(residual[&word_message(14, Felt::ZERO)].0, Felt::ONE);
    assert_eq!(residual.values().filter(|(mult, _)| *mult != Felt::ZERO).count(), 4);
    for col in [io::COL_RAW_BEGIN, io::COL_DIGEST_BEGIN] {
        let mut bad = main.clone();
        // Preserve the big-endian packed word using non-byte digits; the byte LUT must reject it.
        let row = if col == io::COL_RAW_BEGIN { 0 } else { 8 };
        bad.values[row * io::NUM_MAIN_COLS + col] -= Felt::ONE;
        bad.values[row * io::NUM_MAIN_COLS + col + 1] += Felt::from_u32(256);
        assert!(!balanced(&bad), "non-byte digits cannot change the endian interpretation");
    }
}
