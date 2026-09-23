use std::{collections::HashMap, string::String, vec};

use miden_air::lookup::Challenges;
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};
use miden_lifted_air::{BaseAir, LiftedAir};
use miden_precompiles_air::hash::sha256::{
    COL_IO_ACT, IO_COLUMNS, IO_ROW_START, NUM_MAIN_COLS, Sha256IoContinuation,
};

use crate::{
    hash::sha256::{
        Sha256Air,
        compression::{self, Sha256CompressionAir, Sha256CompressionRequires},
        io::{self, Sha256IoAir, Sha256IoRequires},
        trace::generate_trace,
    },
    logup::LookupMessage,
    primitives::byte_pair_lut::{self, BytePairLutRequires},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    tests::{bus_balance::fold_balance, check_local},
    transcript::eidos::trace::EidosRequires,
};

fn challenges() -> Challenges<QuadFelt> {
    Challenges::new(QuadFelt::from_u64(17), QuadFelt::from_u64(31), MAX_MESSAGE_WIDTH, NUM_BUS_IDS)
}

fn requirements(lengths: &[usize]) -> (Sha256CompressionRequires, Sha256IoRequires) {
    let mut compression = Sha256CompressionRequires::new();
    let mut io = Sha256IoRequires::new();
    let mut eidos = EidosRequires::new();
    for &len in lengths {
        io.require(&vec![0xa5; len], &mut compression, &mut eidos);
    }
    (compression, io)
}

fn io_index(block: usize, lane: usize, column: usize) -> usize {
    (block * compression::COMPRESSION_PERIOD + IO_ROW_START + lane) * NUM_MAIN_COLS
        + IO_COLUMNS[column]
}

#[test]
fn sha256_reuses_compression_padding_for_io() {
    // IO needs only eight rows per block. It shares both witness and lookup columns with
    // compression instead of adding a mostly empty band to all 4096 rows.
    assert_eq!(Sha256Air.width(), 61);
    assert_eq!(Sha256Air.aux_width(), 18);
    assert_eq!(crate::tests::log_quotient_degree(&Sha256Air), 2);
    assert_eq!(crate::tests::log_quotient_degree(&Sha256IoAir), 2);
}

#[test]
fn sha256_multiplex_preserves_dense_lookup_demands_and_empty_heights() {
    // Cover no invocations, an empty message, an exact final row, a padded third block,
    // and multiple invocations with duplicate messages and shared Eidos spans.
    for lengths in [&[][..], &[0], &[56], &[128], &[65, 1, 2, 1, 0]] {
        let (compression, io) = requirements(lengths);
        let blocks = compression.num_blocks();
        let mut sparse_bpl = BytePairLutRequires::new();
        let sparse = generate_trace(compression.clone(), io.clone(), &mut sparse_bpl);
        assert_eq!(
            sparse.height(),
            (blocks * compression::COMPRESSION_PERIOD).max(128).next_power_of_two()
        );
        for (index, row) in sparse.values.as_chunks::<NUM_MAIN_COLS>().0.iter().enumerate() {
            let owns_io = index / compression::COMPRESSION_PERIOD < blocks
                && index % compression::COMPRESSION_PERIOD >= IO_ROW_START;
            assert_eq!(row[COL_IO_ACT], Felt::from_bool(owns_io));
        }
        check_local(Sha256Air, &sparse);

        let mut dense_bpl = BytePairLutRequires::new();
        let dense_comp = compression::generate_trace(compression, &mut dense_bpl);
        let dense_io = io::generate_trace(io, &mut dense_bpl);
        let challenges = challenges();
        let mut net = HashMap::new();
        fold_balance(&Sha256CompressionAir, &dense_comp, &challenges, &mut net);
        fold_balance(&Sha256IoAir, &dense_io, &challenges, &mut net);
        for (multiplicity, _) in net.values_mut() {
            *multiplicity = -*multiplicity;
        }
        fold_balance(&Sha256Air, &sparse, &challenges, &mut net);
        assert!(net.values().all(|(multiplicity, _)| *multiplicity == Felt::ZERO), "{lengths:?}");
        assert_eq!(
            byte_pair_lut::generate_trace(sparse_bpl).values,
            byte_pair_lut::generate_trace(dense_bpl).values,
            "sharing witness cells must preserve every byte and Range16 demand",
        );
    }
}

#[test]
fn sha256_multiplex_rejects_wrong_row_ownership_and_io_witnesses() {
    let (compression, io) = requirements(&[3]);
    let main = generate_trace(compression, io, &mut BytePairLutRequires::new());
    check_local(Sha256Air, &main);
    for (name, index, value) in [
        ("missing IO row", io_index(0, 7, io::COL_ACT), Felt::ZERO),
        (
            "IO outside its NOP rows",
            (IO_ROW_START - 1) * NUM_MAIN_COLS + COL_IO_ACT,
            Felt::ONE,
        ),
        ("non-Boolean IO activity", io_index(0, 0, io::COL_ACT), Felt::from_u8(2)),
        ("message restarts after padding", io_index(0, 1, io::COL_MSG_BEGIN), Felt::ONE),
        ("raw byte outside the message", io_index(0, 1, io::COL_RAW_BEGIN), Felt::ONE),
        ("non-Boolean first flag", io_index(0, 0, io::COL_FIRST_BLOCK), Felt::from_u8(2)),
        ("output before the final row", io_index(0, 1, io::COL_OUT_MULT), Felt::ONE),
    ] {
        let mut bad = main.clone();
        bad.values[index] = value;
        assert!(std::panic::catch_unwind(|| check_local(Sha256Air, &bad)).is_err(), "{name}");
    }
    // Claiming IO on a compression NOP outside the IO window switches off that row's program
    // checks. With zeroed IO cells on it and its successor, every IO equation holds, so only the
    // row-ownership definition rejects the claim.
    let mut bad = main.clone();
    let row = IO_ROW_START - io::IO_PERIOD;
    bad.values[row * NUM_MAIN_COLS + COL_IO_ACT] = Felt::ONE;
    for row in [row, row + 1] {
        for &column in &IO_COLUMNS[2..] {
            bad.values[row * NUM_MAIN_COLS + column] = Felt::ZERO;
        }
    }
    assert!(
        std::panic::catch_unwind(|| check_local(Sha256Air, &bad)).is_err(),
        "IO activity must be confined to the final eight padding rows",
    );
    let mut bad = main;
    bad.values[io_index(0, 7, io::COL_DIGEST_EIDOS)] += Felt::ONE;
    assert!(
        std::panic::catch_unwind(|| check_local(Sha256Air, &bad)).is_err(),
        "digest pointer must be held across IO row 6 -> 7",
    );
}

fn continuation(
    main: &RowMajorMatrix<Felt>,
    block: usize,
    provide: bool,
) -> Sha256IoContinuation<Felt> {
    let lane = if provide { io::IO_PERIOD - 1 } else { 0 };
    let v = |column| main.values[io_index(block, lane, column)];
    Sha256IoContinuation {
        block_id: v(io::COL_BLOCK_ID) + Felt::from_bool(provide),
        len: v(io::COL_LEN),
        left: v(io::COL_LEFT)
            - if provide {
                (0..8).map(|i| v(io::COL_MSG_BEGIN + i)).sum::<Felt>()
            } else {
                Felt::ZERO
            },
        before: v(if provide { io::COL_MSG_BEGIN + 7 } else { io::COL_BEFORE }),
        input_eidos: v(io::COL_INPUT_EIDOS)
            - if provide { Felt::ZERO } else { v(io::COL_CHUNK_ACTIVE) },
        input_head: v(io::COL_INPUT_HEAD),
    }
}

#[test]
fn sha256_multiplex_continuation_binds_every_transport_field() {
    let (compression, io) = requirements(&[128]);
    let main = generate_trace(compression, io, &mut BytePairLutRequires::new());
    let challenges = challenges();
    let original = continuation(&main, 0, true).encode(&challenges);
    assert_eq!(original, continuation(&main, 1, false).encode(&challenges));
    // Isolate this bus in the full lookup residual. Local equations alone cannot transport
    // a witness through the intervening compression rows.
    for column in [
        io::COL_BLOCK_ID,
        io::COL_LEN,
        io::COL_LEFT,
        io::COL_MSG_BEGIN + 7,
        io::COL_INPUT_EIDOS,
        io::COL_INPUT_HEAD,
    ] {
        let mut bad = main.clone();
        bad.values[io_index(0, io::IO_PERIOD - 1, column)] += Felt::ONE;
        let changed = continuation(&bad, 0, true).encode(&challenges);
        let mut net = HashMap::new();
        fold_balance(&Sha256Air, &bad, &challenges, &mut net);
        assert_eq!(net[&original].0, Felt::ONE, "unmatched consumer for column {column}");
        assert_eq!(net[&changed].0, -Felt::ONE, "unmatched provider for column {column}");
    }
}

#[test]
fn sha256_multiplex_endpoints_and_cross_gap_pointers_need_global_closure() {
    let (compression, io) = requirements(&[128]);
    let main = generate_trace(compression, io, &mut BytePairLutRequires::new());
    let challenges = challenges();
    let residual = |main: &RowMajorMatrix<Felt>| {
        let mut net: HashMap<QuadFelt, (Felt, String)> = HashMap::new();
        fold_balance(&Sha256Air, main, &challenges, &mut net);
        net
    };
    let mut bad = main.clone();
    for lane in 0..io::IO_PERIOD {
        bad.values[io_index(0, lane, io::COL_FIRST_BLOCK)] = Felt::ZERO;
    }
    check_local(Sha256Air, &bad);
    assert_eq!(
        residual(&bad)[&continuation(&bad, 0, false).encode(&challenges)].0,
        Felt::ONE,
        "block zero cannot consume a continuation from a nonexistent predecessor"
    );

    let mut bad = main.clone();
    for lane in 0..io::IO_PERIOD {
        bad.values[io_index(1, lane, io::COL_INPUT_EIDOS)] += Felt::ONE;
    }
    check_local(Sha256Air, &bad);
    assert_eq!(
        residual(&bad)[&continuation(&bad, 1, false).encode(&challenges)].0,
        Felt::ONE,
        "a coherent local pointer offset must still fail across the compression gap"
    );

    let mut bad = main.clone();
    // Replace the final block's IO with a locally valid non-final block. The shared controller
    // still fixes block id 2; no later block can consume its key-3 continuation.
    for lane in 0..io::IO_PERIOD {
        for column in 2..io::NUM_MAIN_COLS {
            bad.values[io_index(2, lane, column)] = main.values[io_index(0, lane, column)];
        }
        bad.values[io_index(2, lane, io::COL_FIRST_BLOCK)] = Felt::ZERO;
    }
    check_local(Sha256Air, &bad);
    assert_eq!(
        residual(&bad)[&continuation(&bad, 2, true).encode(&challenges)].0,
        -Felt::ONE,
        "the last active block must finish an invocation even before an inactive tail"
    );
}
