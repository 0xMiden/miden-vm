//! Tests for the composite chunk, Keccak-node, and Keccak-sponge chiplet.

use std::{vec, vec::Vec};

use miden_air::lookup::{
    LookupAir, ProverLookupBuilder,
    debug::{ValidateLayout, ValidateLookupAir},
};
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix, bytes_to_packed_u32_elements},
};
use miden_crypto::hash::keccak::Keccak256;
use miden_lifted_air::{BaseAir, ConstraintDegrees};
use rand::{RngExt, SeedableRng, rngs::StdRng};

use crate::{
    hash::{
        chunk::{
            self, ChunkAir,
            trace::{ChunkRequires, generate_trace_padded_to as chunk_trace},
        },
        chunk_node,
        chunk_node_sponge::{
            ChunkNodeSpongeAir, NUM_AUX_COLS, NUM_MAIN_COLS, trace::generate_trace,
        },
        keccak::{
            node::{
                self, KeccakNodeAir,
                trace::{KeccakNodeRequires, generate_trace as node_trace},
            },
            round::RoundRequires,
            sponge::{
                self, KeccakSpongeAir, NUM_AUX_COLS as SPONGE_NUM_AUX_COLS,
                trace::{SpongeRequires, generate_trace_padded_to as sponge_trace},
            },
        },
    },
    logup::{Challenges, NUM_LOGUP_VALUES, NUM_RANDOMNESS},
    primitives::byte_pair_lut::BytePairLutRequires,
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    session::Session,
    tests::{
        assert_same_rational_fold, log_quotient_degree, lookup_column_folds, lookup_fractions,
        sum_rational_folds,
    },
    transcript::eidos::trace::EidosRequires,
};

#[test]
fn all_suffix_offsets_match_keccak_and_close_the_chiplet_stack() {
    let mut session = Session::new();
    let mut claims = Vec::new();
    // Exercise each offset in the first rate lane, lane 16, and lane 16 after a full block.
    // The suffix and trailing 0x80 can share a byte; one session checks the invocation seams.
    for lane_start in [0, 128, 264] {
        for offset in 0..8 {
            let input = std::vec![0xa5; lane_start + offset];
            let (digest, claim) = session.keccak(&input);
            let expected = bytes_to_packed_u32_elements(Keccak256::hash(&input).as_ref());
            assert_eq!(digest.to_felts().as_slice(), expected.as_slice());
            claims.push(claim);
        }
    }
    let root = session.assert_and_fold(claims);
    session.finish(root).check();
}

#[test]
fn layout_and_lookup_shape_match_design() {
    assert_eq!(chunk_node::NUM_AUX_COLS, 2);
    let composite_shape = <ChunkNodeSpongeAir as LookupAir<
        ProverLookupBuilder<'_, Felt, QuadFelt>,
    >>::column_shape(&ChunkNodeSpongeAir);
    assert_eq!(&composite_shape[..chunk_node::NUM_AUX_COLS], [3, 3]);
    assert_eq!(NUM_MAIN_COLS, 47);
    assert_eq!(NUM_AUX_COLS, 7);
    assert_eq!(NUM_AUX_COLS, chunk_node::NUM_AUX_COLS + SPONGE_NUM_AUX_COLS);
    assert_eq!(<ChunkNodeSpongeAir as BaseAir<Felt>>::width(&ChunkNodeSpongeAir), NUM_MAIN_COLS);
    assert_eq!(
        ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&ChunkNodeSpongeAir),
        ConstraintDegrees { base: 5, ext: 5 },
    );
    assert_eq!(log_quotient_degree(&ChunkNodeSpongeAir), 2);

    ValidateLookupAir::validate(
        &ChunkNodeSpongeAir,
        ValidateLayout {
            preprocessed_width: ChunkNodeSpongeAir.preprocessed_width(),
            trace_width: ChunkNodeSpongeAir.width(),
            num_public_values: 0,
            num_periodic_columns: ChunkNodeSpongeAir.periodic_columns().len(),
            permutation_width: NUM_AUX_COLS,
            num_permutation_challenges: NUM_RANDOMNESS,
            num_permutation_values: NUM_LOGUP_VALUES,
        },
    )
    .unwrap_or_else(|err| panic!("ChunkNodeSpongeAir lookup validation failed: {err}"));
}

#[test]
fn serialized_records_fit_the_sponge_height_at_allocation_boundaries() {
    let mut node = KeccakNodeRequires::new();
    let mut sponge = SpongeRequires::new();
    let mut chunk = ChunkRequires::new();
    let mut round = RoundRequires::new();
    let mut bpl = BytePairLutRequires::new();
    let mut eidos = EidosRequires::new();

    // An empty session still needs one complete period for the periodic program.
    let empty = generate_trace(chunk.clone(), node.clone(), sponge.clone());
    assert_eq!(empty.height(), sponge::SPONGE_PERIOD);
    super::check_local(ChunkNodeSpongeAir, &empty);

    // Cross chunk, sponge-block, and padded-height boundaries, including empty input.
    for len in [0, 1, 31, 32, 33, 127, 128, 135, 136, 137, 159, 160, 271, 272, 273] {
        let input = vec![0xa5; len];
        node.require(&input, &mut sponge, &mut chunk, &mut round, &mut bpl, &mut eidos);
        let counts = (node.total_rows(), chunk.total_chunks(), sponge.total_active_rows());
        // Interning must precede allocation in every component.
        node.require(&input, &mut sponge, &mut chunk, &mut round, &mut bpl, &mut eidos);
        assert_eq!((node.total_rows(), chunk.total_chunks(), sponge.total_active_rows()), counts,);
        let periods = counts.2 as usize / sponge::SPONGE_PERIOD;
        assert!(counts.0 as usize <= periods);
        assert!(counts.1 as usize <= 5 * periods);
        let natural_height = sponge_trace(sponge.clone(), 0).height();
        let composite = generate_trace(chunk.clone(), node.clone(), sponge.clone());
        assert_eq!(composite.height(), natural_height, "input length {len}");
        super::check_local(ChunkNodeSpongeAir, &composite);
    }
}

#[test]
fn packed_lookup_columns_match_the_standalone_components() {
    let input: Vec<u8> = (0..200).map(|i| i as u8).collect();
    let mut node = KeccakNodeRequires::new();
    let mut sponge = SpongeRequires::new();
    let mut chunk = ChunkRequires::new();
    let mut round = RoundRequires::new();
    let mut bpl = BytePairLutRequires::new();
    let mut eidos = EidosRequires::new();
    node.require(&input, &mut sponge, &mut chunk, &mut round, &mut bpl, &mut eidos);
    let chunk_main = chunk_trace(chunk.clone(), 0);
    let node_main = node_trace(node.clone());
    let sponge_main = sponge_trace(sponge.clone(), 0);
    let composite_main = generate_trace(chunk, node, sponge);
    assert_eq!(composite_main.height(), sponge_main.height());

    let mut rng = StdRng::seed_from_u64(0x3524_c011);
    let challenges = Challenges::new(
        QuadFelt::new([Felt::from(rng.random::<u32>()), Felt::from(rng.random::<u32>())]),
        QuadFelt::new([Felt::from(rng.random::<u32>()), Felt::from(rng.random::<u32>())]),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    let composite_folds =
        lookup_column_folds(&lookup_fractions(&ChunkNodeSpongeAir, &composite_main, &challenges));
    let chunk_folds = lookup_column_folds(&lookup_fractions(&ChunkAir, &chunk_main, &challenges));
    let node_folds =
        lookup_column_folds(&lookup_fractions(&KeccakNodeAir, &node_main, &challenges));
    let sponge_folds =
        lookup_column_folds(&lookup_fractions(&KeccakSpongeAir, &sponge_main, &challenges));

    assert_same_rational_fold(
        sum_rational_folds(composite_folds.iter().flat_map(|row| row[..2].iter().copied())),
        sum_rational_folds(
            chunk_folds.iter().chain(&node_folds).flat_map(|row| row.iter().copied()),
        ),
        "serialization must preserve every chunk and node lookup",
    );
    for row in 0..composite_main.height() {
        for col in 0..SPONGE_NUM_AUX_COLS {
            assert_same_rational_fold(
                composite_folds[row][chunk_node::NUM_AUX_COLS + col],
                sponge_folds[row][col],
                "shared cells must not change sponge lookups",
            );
        }
    }

    for (name, folds) in [("chunk", &chunk_folds), ("node", &node_folds), ("sponge", &sponge_folds)]
    {
        for col in 0..folds[0].len() {
            assert!(
                folds.iter().any(|row| row[col].0 != QuadFelt::ZERO),
                "the fixture must activate {name} lookup column {col}",
            );
        }
    }
}

/// Map the standalone node record to all live copies in one composite period. Tests use
/// logical fields so a coordinated mutation reaches every consumer of that field.
fn node_locations(column: usize) -> (core::ops::Range<usize>, usize) {
    use chunk_node as c;
    match column {
        node::COL_ACT => (0..32, c::COL_NODE_ACT),
        node::COL_SPONGE_SEQ_ID_HEAD => (0..21, c::COL_SPONGE_HEAD),
        node::COL_CHUNK_SEQ_ID_HEAD => (0..24, c::COL_CHUNK_HEAD),
        node::COL_N_SPONGE_PERMS => (17..21, c::COL_NODE_PERMS),
        node::COL_N_CHUNKS => (17..24, c::COL_NODE_CHUNKS),
        node::COL_ABSORPTION_ID_CHUNKS => (17..22, c::COL_INPUT_ID),
        node::COL_LEN_BYTES => (17..23, c::COL_LEN),
        node::COL_ABSORPTION_ID_DIGEST_CHUNKS => (19..23, c::COL_DIGEST_ID),
        node::COL_ABSORPTION_ID_KECCAK => (21..24, c::COL_NODE_ID),
        node::COL_OUT_MULT => (23..24, c::COL_OUT_MULT),
        node::COL_LAST_CHUNK_REM => (17..18, c::COL_REMAINDER),
        node::COL_N_CHUNKS_INV => (17..18, c::COL_CHUNKS_INV),
        node::COL_D_BEGIN..node::COL_D_END => {
            let offset = column - node::COL_D_BEGIN;
            (19 + offset / 4..20 + offset / 4, c::PAYLOAD[offset % 4])
        },
        node::COL_H_INPUT_CHUNKS_BEGIN..node::COL_H_KECCAK_END => {
            let offset = column - node::COL_H_INPUT_CHUNKS_BEGIN;
            (21 + offset / 4..22 + offset / 4, c::PAYLOAD[offset % 4])
        },
        _ => panic!("unknown node column {column}"),
    }
}

pub(super) fn read_node(main: &RowMajorMatrix<Felt>, index: usize) -> [Felt; node::NUM_MAIN_COLS] {
    core::array::from_fn(|column| {
        let (rows, physical) = node_locations(column);
        main.values[(index * 32 + rows.start) * NUM_MAIN_COLS + physical]
    })
}

pub(super) fn write_node(
    main: &mut RowMajorMatrix<Felt>,
    index: usize,
    record: &[Felt; node::NUM_MAIN_COLS],
) {
    for (column, &value) in record.iter().enumerate() {
        let (rows, physical) = node_locations(column);
        for row in rows {
            main.values[(index * 32 + row) * NUM_MAIN_COLS + physical] = value;
        }
    }
    // The controller advances each namespace head after its final consumer in this period.
    for row in 21..32 {
        main.values[(index * 32 + row) * NUM_MAIN_COLS + chunk_node::COL_SPONGE_HEAD] = record
            [node::COL_SPONGE_SEQ_ID_HEAD]
            + Felt::from_u8(32) * record[node::COL_N_SPONGE_PERMS];
    }
    for row in 24..32 {
        main.values[(index * 32 + row) * NUM_MAIN_COLS + chunk_node::COL_CHUNK_HEAD] =
            record[node::COL_CHUNK_SEQ_ID_HEAD] + record[node::COL_N_CHUNKS];
    }
}

pub(super) fn chunk_cell(index: usize, column: usize) -> usize {
    let row = chunk_node::CHUNK_ROWS[index % 7];
    let columns = if row == 24 {
        chunk_node::CHUNK_CAPACITY_COLUMNS
    } else {
        chunk_node::CHUNK_LATE_COLUMNS
    };
    (index / 7 * 32 + row) * NUM_MAIN_COLS + columns[column]
}

/// Assemble independently forged standalone records without calling the production writer.
pub(super) fn assemble(
    chunk: &RowMajorMatrix<Felt>,
    records: &[[Felt; node::NUM_MAIN_COLS]],
    sponge: &RowMajorMatrix<Felt>,
) -> RowMajorMatrix<Felt> {
    let height = sponge.height();
    let mut values = vec![Felt::ZERO; height * NUM_MAIN_COLS];
    for row in 0..height {
        values[row * NUM_MAIN_COLS..row * NUM_MAIN_COLS + sponge::NUM_MAIN_COLS].copy_from_slice(
            &sponge.values[row * sponge::NUM_MAIN_COLS..(row + 1) * sponge::NUM_MAIN_COLS],
        );
    }
    let mut main = RowMajorMatrix::new(values, NUM_MAIN_COLS);
    let mut padding = [Felt::ZERO; node::NUM_MAIN_COLS];
    for index in 0..height / 32 {
        let record = records.get(index).unwrap_or(&padding);
        write_node(&mut main, index, record);
        let sponge_head = record[node::COL_SPONGE_SEQ_ID_HEAD]
            + Felt::from_u8(32) * record[node::COL_N_SPONGE_PERMS];
        let chunk_head = record[node::COL_CHUNK_SEQ_ID_HEAD] + record[node::COL_N_CHUNKS];
        padding[node::COL_SPONGE_SEQ_ID_HEAD] = sponge_head;
        padding[node::COL_CHUNK_SEQ_ID_HEAD] = chunk_head;
    }
    let mut sequence = 0;
    let mut id = chunk.values[chunk::COL_ABSORPTION_ID] - Felt::ONE;
    let mut act = chunk.values[chunk::COL_ACT];
    for row in 0..height {
        let is_chunk = chunk_node::CHUNK_ROWS.contains(&(row % 32));
        if is_chunk {
            for column in 0..chunk::NUM_MAIN_COLS {
                main.values[chunk_cell(sequence, column)] =
                    chunk.values[sequence * chunk::NUM_MAIN_COLS + column];
            }
            id = chunk.values[sequence * chunk::NUM_MAIN_COLS + chunk::COL_ABSORPTION_ID];
            act = chunk.values[sequence * chunk::NUM_MAIN_COLS + chunk::COL_ACT];
        }
        main.values[row * NUM_MAIN_COLS + chunk_node::COL_CHUNK_SEQ] = Felt::from_usize(sequence);
        main.values[row * NUM_MAIN_COLS + chunk_node::COL_CHUNK_ID] = id;
        main.values[row * NUM_MAIN_COLS + chunk_node::COL_CHUNK_ACT] = act;
        if is_chunk {
            sequence += 1;
        }
    }
    main
}

#[test]
fn serialized_controllers_reject_transport_and_period_seam_corruption() {
    let mut session = Session::new();
    let claims = [vec![0x51; 135], vec![0x52; 137]].map(|input| session.keccak(&input).1);
    let root = session.assert_and_fold(claims);
    let traces = session.finish(root);
    traces.check();
    let main = traces.mains()[0];
    use chunk_node as c;
    for (row, column) in [
        (18, c::COL_LEN),
        (20, c::COL_DIGEST_ID),
        (22, c::COL_NODE_ID),
        (31, c::COL_SPONGE_HEAD),
        (32, c::COL_CHUNK_HEAD),
        (25, c::COL_CHUNK_ID),
        (32, c::COL_CHUNK_SEQ),
        (18, c::COL_NODE_ACT),
    ] {
        let mut forged = main.clone();
        forged.values[row * NUM_MAIN_COLS + column] += Felt::ONE;
        crate::tests::assert_local_rejects(ChunkNodeSpongeAir, &forged);
    }
}

#[test]
fn next_row_node_payloads_are_authenticated_by_their_consumers() {
    let mut session = Session::new();
    let (_, claim) = session.keccak(&[0x51; 135]);
    let root = session.assert_and_fold([claim]);
    let traces = session.finish(root);
    let mains = traces.mains();
    let challenges = Challenges::new(
        QuadFelt::from_u64(101),
        QuadFelt::from_u64(103),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    // The digest and node blocks each borrow four cells from the following phase.
    for phase in [20, 22] {
        let mut forged = mains[0].clone();
        forged.values[phase * NUM_MAIN_COLS + chunk_node::PAYLOAD[0]] += Felt::ONE;
        crate::tests::check_local(ChunkNodeSpongeAir, &forged);
        assert!(
            !super::bus_balance::session_stack_residual(&mains, &[(0, &forged)], &challenges)
                .is_empty()
        );
    }
}
