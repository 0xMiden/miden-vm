//! Debug-only structural checks for AIRs. These panic on contract violation and
//! are meant for tests / setup; the prover and verifier hot paths assume AIRs
//! are well-formed.
//!
//! # When to use what
//!
//! - [`assert_multi_air_valid`]: verify a [`MultiAir`] satisfies the structural contract assumed by
//!   the rest of the protocol — non-empty AIR collection, positive auxiliary width, and
//!   power-of-two periodic columns. This also cross-checks the overridable
//!   [`LiftedAir::max_periodic_length`] against the raw periodic columns.
//! - [`check_builder_shape`]: verify a concrete builder's accessor dimensions match an AIR before
//!   calling [`LiftedAir::eval`]. Used as a `cfg(debug_assertions)` belt-and-suspenders inside the
//!   prover and verifier loops.
//!
//! Runtime checks on caller-supplied data live on the constructors
//! [`Statement::new`](crate::air::Statement::new) /
//! [`ProverStatement::new`](crate::air::ProverStatement::new).

use p3_field::{ExtensionField, Field};
use p3_matrix::Matrix;

use crate::air::{LiftedAir, LiftedAirBuilder, MultiAir, WindowAccess};

/// Assert a [`MultiAir`] is structurally well-formed.
///
/// This checks the structural invariants that prover/verifier hot paths trust:
/// - [`MultiAir::airs`] is non-empty.
/// - Each AIR has positive auxiliary width.
/// - Each AIR's [`crate::air::BaseAir::preprocessed_width`] agrees with
///   [`crate::air::BaseAir::preprocessed_trace`] presence and width.
/// - Each periodic column is non-empty and has power-of-two length.
/// - [`LiftedAir::max_periodic_length`] agrees with the raw periodic columns.
///
/// Panics on any violation. An empty [`MultiAir`] is a malformed trusted AIR
/// definition, not a typed [`Statement::new`](crate::air::Statement::new) error.
pub fn assert_multi_air_valid<F, EF, MA>(multi_air: &MA)
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    let airs = multi_air.airs();
    assert!(!airs.is_empty(), "MultiAir::airs() must be non-empty");

    for (idx, air) in airs.iter().enumerate() {
        check_one_air::<F, EF, _>(idx, air);
    }
}

/// Assert one AIR satisfies the structural contract.
fn check_one_air<F, EF, A>(idx: usize, air: &A)
where
    F: Field,
    A: LiftedAir<F, EF>,
{
    assert!(air.aux_width() > 0, "AIR {idx}: aux_width must be positive");

    let preprocessed_width = air.preprocessed_width();
    match air.preprocessed_trace() {
        Some(trace) => {
            assert!(
                preprocessed_width > 0,
                "AIR {idx}: preprocessed_trace returned Some but preprocessed_width() is 0",
            );
            assert_eq!(
                trace.width(),
                preprocessed_width,
                "AIR {idx}: preprocessed_trace width disagrees with preprocessed_width()",
            );
            assert!(
                trace.height().is_power_of_two(),
                "AIR {idx}: preprocessed_trace height must be a positive power of two, got {height}",
                height = trace.height(),
            );
        },
        None => {
            assert_eq!(
                preprocessed_width, 0,
                "AIR {idx}: preprocessed_width() is {preprocessed_width} but preprocessed_trace returned None",
            );
        },
    }

    // Derive the max period from the raw columns (asserting positive-power-of-two)
    // and confirm the overridable `max_periodic_length` agrees.
    let mut max_period = 0;
    for (i, col) in air.periodic_columns().iter().enumerate() {
        assert!(
            !col.is_empty() && col.len().is_power_of_two(),
            "AIR {idx}: periodic column {i}: length must be a positive power of two, \
             got {len}",
            len = col.len(),
        );
        max_period = max_period.max(col.len());
    }
    assert!(
        air.max_periodic_length() == max_period,
        "AIR {idx}: max_periodic_length() = {} disagrees with periodic_columns() max = {max_period}",
        air.max_periodic_length(),
    );
}

/// Assert a concrete builder's accessor dimensions match `air` — preprocessed,
/// main and aux trace, public values, randomness, aux values, and periodic values.
///
/// Guards the invariant that makes [`LiftedAir::eval`] panic-free: if symbolic
/// evaluation in `constraint_degree` succeeds and this check passes, `eval()`
/// cannot panic from out-of-bounds accessor access.
pub fn check_builder_shape<F, EF, A, AB>(air: &A, builder: &AB)
where
    F: Field,
    A: LiftedAir<F, EF>,
    AB: LiftedAirBuilder<F = F>,
{
    let check = |part: &str, expected: usize, actual: usize| {
        assert!(
            actual == expected,
            "{part} dimension mismatch: expected {expected}, got {actual}"
        );
    };

    let preprocessed = builder.preprocessed();
    check(
        "preprocessed (current)",
        air.preprocessed_width(),
        preprocessed.current_slice().len(),
    );
    check("preprocessed (next)", air.preprocessed_width(), preprocessed.next_slice().len());

    let main = builder.main();
    check("main (current)", air.width(), main.current_slice().len());
    check("main (next)", air.width(), main.next_slice().len());

    let perm = builder.permutation();
    check("aux (current)", air.aux_width(), perm.current_slice().len());
    check("aux (next)", air.aux_width(), perm.next_slice().len());

    check("public values", air.num_public_values(), builder.public_values().len());
    check("randomness", air.num_randomness(), builder.permutation_randomness().len());
    check("aux values", air.num_aux_values(), builder.permutation_values().len());
    check("periodic values", air.periodic_columns().len(), builder.periodic_values().len());
}
