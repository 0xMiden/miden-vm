//! Tests for the composite chunk, Keccak-node, and Keccak-sponge chiplet.

use std::vec::Vec;

use miden_air::lookup::debug::{ValidateLayout, ValidateLookupAir, collect_column_oracle_folds};
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::Matrix,
};
use miden_lifted_air::{BaseAir, ConstraintDegrees};
use rand::{RngExt, SeedableRng, rngs::StdRng};

use crate::{
    composite::extract_band,
    hash::{
        chunk::{self, ChunkAir, trace::ChunkRequires},
        chunk_node::{self, COLUMN_SHAPE as CHUNK_NODE_COLUMN_SHAPE},
        chunk_node_sponge::{
            ChunkNodeSpongeAir, NUM_AUX_COLS, NUM_MAIN_COLS, SPONGE_COL_OFFSET,
            trace::generate_trace,
        },
        keccak::{
            node::{KeccakNodeAir, trace::KeccakNodeRequires},
            round::RoundRequires,
            sponge::{KeccakSpongeAir, NUM_AUX_COLS as SPONGE_NUM_AUX_COLS, trace::SpongeRequires},
        },
    },
    logup::{Challenges, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, NUM_SIGMA_VALUES},
    primitives::byte_pair_lut::BytePairLutRequires,
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    tests::{assert_same_rational_fold, log_quotient_degree, sum_rational_folds},
    transcript::eidos::trace::EidosRequires,
};

#[test]
fn layout_and_lookup_shape_match_design() {
    assert_eq!(chunk_node::NUM_AUX_COLS, 6);
    assert_eq!(CHUNK_NODE_COLUMN_SHAPE, [3; chunk_node::NUM_AUX_COLS]);
    assert_eq!(NUM_MAIN_COLS, 99);
    assert_eq!(NUM_AUX_COLS, 24);
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
            num_public_values: NUM_PUBLIC_VALUES,
            num_periodic_columns: ChunkNodeSpongeAir.periodic_columns().len(),
            permutation_width: NUM_AUX_COLS,
            num_permutation_challenges: NUM_RANDOMNESS,
            num_permutation_values: NUM_SIGMA_VALUES,
        },
    )
    .unwrap_or_else(|err| panic!("ChunkNodeSpongeAir lookup validation failed: {err}"));
}

#[test]
fn packed_lookup_columns_match_the_standalone_components() {
    const COMPOSITE_CHUNK_MEMORY_COL: usize = 0;
    const COMPOSITE_CHUNK_TAIL_COL: usize = 1;
    const COMPOSITE_NODE_HANDSHAKE_COL: usize = 2;
    const COMPOSITE_NODE_INPUT_COL: usize = 3;
    const COMPOSITE_NODE_TAIL_COLS: [usize; 2] = [4, 5];

    const CHUNK_MEMORY_COLS: [usize; 2] = [0, 1];
    const CHUNK_TAIL_COLS: [usize; 2] = [2, 3];
    const NODE_HANDSHAKE_COLS: [usize; 2] = [0, 1];
    const NODE_INPUT_COLS: [usize; 2] = [2, 3];
    const NODE_TAIL_COLS: [usize; 3] = [4, 5, 6];

    let input: Vec<u8> = (0..200).map(|i| i as u8).collect();
    let mut node = KeccakNodeRequires::new();
    let mut sponge = SpongeRequires::new();
    let mut chunk = ChunkRequires::new();
    let mut round = RoundRequires::new();
    let mut bpl = BytePairLutRequires::new();
    let mut eidos = EidosRequires::new();
    node.require(&input, &mut sponge, &mut chunk, &mut round, &mut bpl, &mut eidos);
    let composite_main = generate_trace(chunk, node, sponge);

    let chunk_main = extract_band(&composite_main, 0..chunk::NUM_MAIN_COLS);
    let node_main =
        extract_band(&composite_main, chunk_node::NODE_COL_OFFSET..chunk_node::NUM_MAIN_COLS);
    let sponge_main = extract_band(&composite_main, SPONGE_COL_OFFSET..NUM_MAIN_COLS);
    assert_eq!(chunk_main.height(), composite_main.height());
    assert_eq!(node_main.height(), composite_main.height());
    assert_eq!(sponge_main.height(), composite_main.height());

    let mut rng = StdRng::seed_from_u64(0x3524_c011);
    let challenges = Challenges::new(
        QuadFelt::new([Felt::from(rng.random::<u32>()), Felt::from(rng.random::<u32>())]),
        QuadFelt::new([Felt::from(rng.random::<u32>()), Felt::from(rng.random::<u32>())]),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    let public_values = [Felt::ZERO; NUM_PUBLIC_VALUES];

    let composite_folds = collect_column_oracle_folds(
        &ChunkNodeSpongeAir,
        &composite_main,
        &ChunkNodeSpongeAir.periodic_columns(),
        &public_values,
        &challenges,
    );
    let chunk_folds = collect_column_oracle_folds(
        &ChunkAir,
        &chunk_main,
        &ChunkAir.periodic_columns(),
        &public_values,
        &challenges,
    );
    let node_folds = collect_column_oracle_folds(
        &KeccakNodeAir,
        &node_main,
        &KeccakNodeAir.periodic_columns(),
        &public_values,
        &challenges,
    );
    let sponge_folds = collect_column_oracle_folds(
        &KeccakSpongeAir,
        &sponge_main,
        &KeccakSpongeAir.periodic_columns(),
        &public_values,
        &challenges,
    );

    for row in 0..composite_main.height() {
        assert_same_rational_fold(
            composite_folds[row][COMPOSITE_CHUNK_MEMORY_COL],
            sum_rational_folds(CHUNK_MEMORY_COLS.map(|col| chunk_folds[row][col])),
            "packed chunk Memory64 column must preserve both standalone columns",
        );
        assert_same_rational_fold(
            composite_folds[row][COMPOSITE_CHUNK_TAIL_COL],
            sum_rational_folds(CHUNK_TAIL_COLS.map(|col| chunk_folds[row][col])),
            "packed chunk tail column must preserve both standalone columns",
        );
        assert_same_rational_fold(
            composite_folds[row][COMPOSITE_NODE_HANDSHAKE_COL],
            sum_rational_folds(NODE_HANDSHAKE_COLS.map(|col| node_folds[row][col])),
            "packed node handshake column must preserve both standalone columns",
        );
        assert_same_rational_fold(
            composite_folds[row][COMPOSITE_NODE_INPUT_COL],
            sum_rational_folds(NODE_INPUT_COLS.map(|col| node_folds[row][col])),
            "packed node input/D-limb column must preserve both standalone columns",
        );
        assert_same_rational_fold(
            sum_rational_folds(COMPOSITE_NODE_TAIL_COLS.map(|col| composite_folds[row][col])),
            sum_rational_folds(NODE_TAIL_COLS.map(|col| node_folds[row][col])),
            "packed node D-limb/Eidos columns must preserve all standalone columns",
        );

        // The same Sponge evaluator runs at two main/aux offsets. This
        // comparison pins the composite offset plumbing; the independent
        // multi-block session-balance test covers its bus semantics.
        for col in 0..SPONGE_NUM_AUX_COLS {
            assert_same_rational_fold(
                composite_folds[row][chunk_node::NUM_AUX_COLS + col],
                sponge_folds[row][col],
                "the composite Sponge offset must match the standalone evaluator",
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
