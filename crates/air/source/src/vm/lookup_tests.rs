//! VM lookup integration checks for the shared LogUp framework.

use miden_core::field::{PrimeCharacteristicRing, QuadFelt};
use miden_stark::{
    air::native::{AuxTraceInputs, LiftedAir, ProverAir},
    lookup::{Challenges, accumulate_slow, native as native_lookup},
};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::vm::Felt;

/// The chunked driver, over an AIR whose lookup reads a separate preprocessed window, matches
/// slow accumulation of the same fractions. The And8 lookup's 2^16-row trace spans many
/// accumulation chunks; a zero-multiplicity middle block and a live final row cover chunk
/// boundaries and the cyclic closing edge.
#[test]
fn chunked_driver_matches_slow_accumulation_with_preprocessed_window() {
    use miden_stark::lookup::native::build_lookup_fractions;

    use crate::vm::{
        MidenAir,
        logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
    };

    let air = MidenAir::AND8_LOOKUP;
    let preprocessed =
        air.build_preprocessed_trace().expect("And8 lookup has a preprocessed table");
    let num_rows = preprocessed.height();
    let spec = air.spec();
    let width = spec.main_width;
    let mut main = RowMajorMatrix::new(
        (0..num_rows * width).map(|i| Felt::from_usize(i % 17 + 1)).collect(),
        width,
    );
    main.values[512 * width..(num_rows - 1) * width].fill(Felt::ZERO);
    let challenges = [QuadFelt::new([Felt::from_u32(7), Felt::ONE]), QuadFelt::from_u32(13)];
    let lookup_challenges =
        Challenges::new(challenges[0], challenges[1], MIDEN_MAX_MESSAGE_WIDTH, BusId::COUNT);
    let fractions = build_lookup_fractions(
        &air,
        &main,
        Some(&preprocessed),
        &spec.periodic_columns,
        &lookup_challenges,
    );
    let (expected, sigma_prime) = accumulate_slow(&fractions);
    let inputs = AuxTraceInputs {
        main: &main,
        preprocessed: Some(&preprocessed),
        public_values: &[],
        statement: &[],
        challenges: &challenges,
    };
    let actual = native_lookup::build_logup_aux_trace(&air, inputs).unwrap();
    let borrowed = ProverAir::build_aux_trace(&air, inputs).unwrap();
    assert_eq!(borrowed.columns.values, actual.columns.values);
    assert_eq!(borrowed.exports, actual.exports);
    assert_eq!(actual.exports, [sigma_prime]);
    assert_eq!(actual.columns.height(), num_rows);
    assert_eq!(actual.columns.width(), expected.len());
    for (row_idx, row) in actual.columns.values.chunks_exact(actual.columns.width()).enumerate() {
        for (column, &value) in row.iter().enumerate() {
            assert_eq!(value, expected[column][row_idx], "row {row_idx}, column {column}");
        }
    }
}

#[test]
fn native_logup_allocates_the_full_declared_width_with_a_zero_suffix() {
    let air = crate::vm::MidenAir::EIDOS_COMPRESSION;
    let spec = air.spec();
    let main = RowMajorMatrix::new(Felt::zero_vec(32 * spec.main_width), spec.main_width);
    let challenges = [QuadFelt::from_u32(7), QuadFelt::from_u32(13)];
    let lookup_width = air.column_shape().len();
    assert_eq!(spec.aux_width, lookup_width + 1);
    let auxiliary = native_lookup::build_logup_aux_trace(
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
    let air = crate::vm::MidenAir::AND8_LOOKUP;
    let main =
        RowMajorMatrix::new(Felt::zero_vec(8 * air.spec().main_width), air.spec().main_width);
    let width = air.spec().preprocessed_width();
    let challenges = [QuadFelt::from_u32(7), QuadFelt::from_u32(13)];
    let assert_rejected = |air: crate::vm::MidenAir,
                           main: &RowMajorMatrix<Felt>,
                           preprocessed: Option<&RowMajorMatrix<Felt>>| {
        let result = native_lookup::build_logup_aux_trace(
            &air,
            AuxTraceInputs {
                main,
                preprocessed,
                public_values: &[],
                statement: &[],
                challenges: &challenges,
            },
        );
        assert!(
            matches!(result, Err(native_lookup::LookupError::PreprocessedShape)),
            "invalid setup must fail before fraction accumulation"
        );
    };
    for preprocessed in [
        None,
        Some(RowMajorMatrix::new(Felt::zero_vec(8 * (width + 1)), width + 1)),
        Some(RowMajorMatrix::new(Felt::zero_vec(4 * width), width)),
    ] {
        assert_rejected(air, &main, preprocessed.as_ref());
    }
    let no_table_air = crate::vm::MidenAir::EIDOS_COMPRESSION;
    let main = RowMajorMatrix::new(
        Felt::zero_vec(32 * no_table_air.spec().main_width),
        no_table_air.spec().main_width,
    );
    let unexpected = RowMajorMatrix::new(Felt::zero_vec(32), 1);
    assert_rejected(no_table_air, &main, Some(&unexpected));
}
