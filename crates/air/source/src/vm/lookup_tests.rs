//! VM lookup integration checks for the shared LogUp framework.

use miden_core::{
    field::{PrimeCharacteristicRing, QuadFelt},
    operations::opcodes,
};
use miden_stark::{
    air::{AuxTraceInputs, LiftedAir, ProverAir},
    lookup::{self, Challenges, accumulate_slow},
};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    shared::{WitnessError, eidos::EidosWitnessError},
    vm::{
        Felt, MidenAir,
        constraints::{
            columns::{NUM_CHIPLETS_COLS, NUM_CORE_COLS},
            op_flags::generate_test_row,
        },
        logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
    },
};

fn assert_witness_matches_slow(
    air: MidenAir,
    main: &RowMajorMatrix<Felt>,
    preprocessed: Option<&RowMajorMatrix<Felt>>,
) {
    let spec = air.spec();
    let public_values = vec![Felt::ZERO; spec.num_public_values];
    let challenges = [QuadFelt::new([Felt::from_u32(7), Felt::ONE]), QuadFelt::from_u32(13)];
    let lookup_challenges =
        Challenges::new(challenges[0], challenges[1], MIDEN_MAX_MESSAGE_WIDTH, BusId::COUNT);
    let fractions = lookup::build_lookup_fractions(
        &air,
        main,
        preprocessed,
        &spec.periodic_columns,
        &lookup_challenges,
    );
    let (expected, sigma) = accumulate_slow(&fractions);
    let actual = air
        .build_aux_trace(AuxTraceInputs {
            main,
            preprocessed,
            public_values: &public_values,
            statement: &[],
            challenges: &challenges,
        })
        .unwrap();
    assert_eq!(actual.exports, [sigma], "{air:?}");
    assert_eq!(actual.columns.height(), main.height(), "{air:?}");
    assert_eq!(actual.columns.width(), expected.len(), "{air:?}");
    for (row, values) in actual.columns.values.chunks_exact(actual.columns.width()).enumerate() {
        for (column, value) in values.iter().enumerate() {
            assert_eq!(*value, expected[column][row], "{air:?}, row {row}, column {column}");
        }
    }
}

#[test]
fn vm_lookup_witnesses_match_slow_accumulation() {
    let mut current = generate_test_row(opcodes::PUSH.into());
    let mut next = generate_test_row(opcodes::END.into());
    current.system.clk = Felt::from_u32(19);
    next.system.clk = Felt::from_u32(41);
    let main = RowMajorMatrix::new(
        current.as_slice().iter().chain(next.as_slice()).copied().collect(),
        NUM_CORE_COLS,
    );
    assert_witness_matches_slow(MidenAir::Core, &main, None);

    let main = RowMajorMatrix::new(
        (0..8)
            .flat_map(|row| {
                let mut values = [Felt::ZERO; NUM_CHIPLETS_COLS];
                values[23] = Felt::from_usize(row + 1);
                values
            })
            .collect(),
        NUM_CHIPLETS_COLS,
    );
    assert_witness_matches_slow(MidenAir::Chiplets, &main, None);
}

#[test]
fn chunked_driver_matches_slow_accumulation_with_preprocessed_window() {
    let air = MidenAir::AND8_LOOKUP;
    let preprocessed = air.build_preprocessed_trace().expect("And8 declares a fixed table");
    let num_rows = preprocessed.height();
    let width = air.spec().main_width;
    let mut main = RowMajorMatrix::new(
        (0..num_rows * width).map(|i| Felt::from_usize(i % 17 + 1)).collect(),
        width,
    );
    // Cross several accumulation chunks and leave a live row at the cyclic closing edge.
    main.values[512 * width..(num_rows - 1) * width].fill(Felt::ZERO);
    assert_witness_matches_slow(air, &main, Some(&preprocessed));
}

#[test]
fn native_logup_allocates_the_full_declared_width_with_a_zero_suffix() {
    let air = MidenAir::EIDOS_COMPRESSION;
    let spec = air.spec();
    let main = RowMajorMatrix::new(Felt::zero_vec(32 * spec.main_width), spec.main_width);
    let challenges = [QuadFelt::from_u32(7), QuadFelt::from_u32(13)];
    let lookup_width = air.column_shape().len();
    assert_eq!(spec.aux_width, lookup_width + 1);
    let auxiliary = lookup::build_logup_aux_trace(
        &air,
        AuxTraceInputs {
            main: &main,
            preprocessed: None,
            public_values: &[],
            statement: &[],
            challenges: &challenges,
        },
    )
    .unwrap();
    assert_eq!(auxiliary.columns.width(), spec.aux_width);
    assert_eq!(auxiliary.columns.height(), 32);
    assert_eq!(auxiliary.exports.len(), spec.num_exports);
    for row in auxiliary.columns.values.chunks_exact(spec.aux_width) {
        assert!(row[lookup_width..].iter().all(|value| *value == QuadFelt::ZERO));
    }
}

#[test]
fn borrowed_logup_rejects_missing_or_malformed_setup_windows() {
    let air = MidenAir::AND8_LOOKUP;
    let main =
        RowMajorMatrix::new(Felt::zero_vec(8 * air.spec().main_width), air.spec().main_width);
    let width = air.spec().preprocessed_width();
    let challenges = [QuadFelt::from_u32(7), QuadFelt::from_u32(13)];
    let witness_error = |air: MidenAir,
                         main: &RowMajorMatrix<Felt>,
                         preprocessed: Option<&RowMajorMatrix<Felt>>| {
        air.build_aux_trace(AuxTraceInputs {
            main,
            preprocessed,
            public_values: &[],
            statement: &[],
            challenges: &challenges,
        })
        .expect_err("invalid setup must fail before fraction accumulation")
    };
    for preprocessed in [
        None,
        Some(RowMajorMatrix::new(Felt::zero_vec(8 * (width + 1)), width + 1)),
        Some(RowMajorMatrix::new(Felt::zero_vec(4 * width), width)),
    ] {
        assert_eq!(
            witness_error(air, &main, preprocessed.as_ref()),
            WitnessError::Lookup(lookup::LookupError::PreprocessedShape)
        );
    }
    let no_table_air = MidenAir::EIDOS_COMPRESSION;
    let main = RowMajorMatrix::new(
        Felt::zero_vec(32 * no_table_air.spec().main_width),
        no_table_air.spec().main_width,
    );
    let unexpected = RowMajorMatrix::new(Felt::zero_vec(32), 1);
    assert_eq!(
        witness_error(no_table_air, &main, Some(&unexpected)),
        WitnessError::Eidos(EidosWitnessError::Lookup(lookup::LookupError::PreprocessedShape))
    );
}
