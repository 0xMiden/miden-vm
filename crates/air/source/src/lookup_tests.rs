//! VM lookup integration checks for the shared LogUp framework.

use miden_core::field::{PrimeCharacteristicRing, QuadFelt};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    Felt, LiftedAir,
    lookup::{Challenges, accumulate_slow, build_logup_aux_trace},
};

/// The chunked driver, over an AIR whose lookup reads a separate preprocessed window, matches
/// slow accumulation of the same fractions. The And8 lookup's 2^16-row trace spans many
/// accumulation chunks; a zero-multiplicity middle block and a live final row cover chunk
/// boundaries and the cyclic closing edge.
#[test]
fn chunked_driver_matches_slow_accumulation_with_preprocessed_window() {
    use crate::{
        BaseAir, MidenAir,
        logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
        lookup::build_lookup_fractions,
    };

    let air = MidenAir::AND8_LOOKUP;
    let preprocessed = air.preprocessed_trace().expect("And8 lookup has a preprocessed table");
    let num_rows = preprocessed.height();
    let width = air.width();
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
        &air.periodic_columns(),
        &lookup_challenges,
    );
    let (expected, sigma_prime) = accumulate_slow(&fractions);
    let (actual, aux_values) = build_logup_aux_trace(&air, &main, &challenges);
    let borrowed =
        air.build_aux_trace_with_preprocessed(&main, Some(&preprocessed), &[], &[], &challenges);
    assert_eq!(borrowed.0.values, actual.values);
    assert_eq!(borrowed.1, aux_values);
    assert_eq!(aux_values, [sigma_prime]);
    assert_eq!(actual.height(), num_rows);
    assert_eq!(actual.width(), expected.len());
    for (row_idx, row) in actual.values.chunks_exact(actual.width()).enumerate() {
        for (column, &value) in row.iter().enumerate() {
            assert_eq!(value, expected[column][row_idx], "row {row_idx}, column {column}");
        }
    }
}

#[test]
fn borrowed_logup_rejects_missing_or_malformed_setup_windows() {
    use crate::BaseAir;

    let air = crate::MidenAir::AND8_LOOKUP;
    let main = RowMajorMatrix::new(Felt::zero_vec(8 * air.width()), air.width());
    let width = air.preprocessed_width();
    let challenges = [QuadFelt::from_u32(7), QuadFelt::from_u32(13)];
    let assert_rejected = |air: crate::MidenAir,
                           main: &RowMajorMatrix<Felt>,
                           preprocessed: Option<&RowMajorMatrix<Felt>>,
                           expected: &str| {
        let error = std::panic::catch_unwind(|| {
            air.build_aux_trace_with_preprocessed(main, preprocessed, &[], &[], &challenges)
        })
        .expect_err("invalid setup must fail before fraction accumulation");
        let message = error
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| {
                error.downcast_ref::<std::string::String>().map(std::string::String::as_str)
            })
            .expect("validation panic must have a message");
        assert!(message.contains(expected), "expected {expected:?}, got {message:?}");
    };
    for (expected, preprocessed) in [
        ("LogUp preprocessed presence", None),
        (
            "LogUp preprocessed width mismatch",
            Some(RowMajorMatrix::new(Felt::zero_vec(8 * (width + 1)), width + 1)),
        ),
        (
            "LogUp preprocessed height mismatch",
            Some(RowMajorMatrix::new(Felt::zero_vec(4 * width), width)),
        ),
    ] {
        assert_rejected(air, &main, preprocessed.as_ref(), expected);
    }
    let no_table_air = crate::MidenAir::EIDOS_COMPRESSION;
    let main = RowMajorMatrix::new(Felt::zero_vec(32 * no_table_air.width()), no_table_air.width());
    let unexpected = RowMajorMatrix::new(Felt::zero_vec(32), 1);
    assert_rejected(no_table_air, &main, Some(&unexpected), "LogUp preprocessed presence");
}
