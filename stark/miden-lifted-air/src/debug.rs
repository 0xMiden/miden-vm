//! Debug-only structural checks for AIRs.
//!
//! These helpers panic on contract violation. They are intended to be called
//! from tests / setup code; the prover and verifier hot paths assume AIRs
//! are well-formed.
//!
//! # When to use what
//!
//! - [`assert_multi_air_valid`]: verify a [`MultiAir`] satisfies the structural contract assumed by
//!   the rest of the protocol — per AIR no preprocessed trace, positive auxiliary width,
//!   power-of-two periodic columns; across AIRs a shared `num_public_values`. This also
//!   cross-checks the overridable [`MultiAir::num_air_inputs`] / [`LiftedAir::max_periodic_length`]
//!   against the raw AIR data, so an override that lies about either is caught here.
//! - [`check_builder_shape`]: verify a concrete builder's accessor dimensions match an AIR before
//!   calling [`LiftedAir::eval`]. Used as a `cfg(debug_assertions)` belt-and-suspenders inside the
//!   prover and verifier loops.
//!
//! Runtime checks on caller-supplied data live on the constructors
//! [`Statement::new`](crate::Statement::new) /
//! [`ProverStatement::new`](crate::ProverStatement::new), which return
//! [`InstanceError`](crate::InstanceError).

use p3_field::{ExtensionField, Field};

use crate::{BaseAir, LiftedAir, LiftedAirBuilder, MultiAir, WindowAccess};

/// Assert a [`MultiAir`] is structurally well-formed.
///
/// Per AIR: no preprocessed trace, positive auxiliary width, and periodic
/// columns whose lengths are positive powers of two. Across AIRs: every AIR
/// declares the same `num_public_values` (via [`MultiAir::num_air_inputs`]).
///
/// The overridable [`MultiAir::num_air_inputs`] and
/// [`LiftedAir::max_periodic_length`] are cross-checked against the raw AIR
/// data here, so an override that disagrees with `periodic_columns` /
/// `num_public_values` is caught rather than trusted.
///
/// Panics on an empty `airs()` (a meaningless statement) and on any violation.
/// A degenerate AIR whose constraints all vanish under `Z_H` (combined degree
/// `< 2`) is *supported*, not rejected: the prover and verifier clamp the
/// quotient degree to `D = 2` and proceed normally.
pub fn assert_multi_air_valid<F, EF, MA>(multi_air: &MA)
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    let airs = multi_air.airs();

    // Independently derive the shared public-input count from the raw AIRs
    // (panics on empty `airs()`), assert agreement, then confirm the
    // overridable `num_air_inputs` matches — so an override that lies is caught
    // rather than trusted.
    let num_air_inputs = airs[0].num_public_values();
    assert!(
        airs.iter().all(|air| air.num_public_values() == num_air_inputs),
        "AIRs disagree on num_public_values",
    );
    assert!(
        multi_air.num_air_inputs() == num_air_inputs,
        "num_air_inputs() = {} disagrees with per-AIR num_public_values() = {num_air_inputs}",
        multi_air.num_air_inputs(),
    );

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
    assert!(
        air.preprocessed_trace().is_none(),
        "AIR {idx}: preprocessed traces are not supported"
    );
    assert!(air.aux_width() > 0, "AIR {idx}: aux_width must be positive");

    // Independently derive the max period from the raw columns — asserting the
    // positive-power-of-two contract — then confirm the (overridable)
    // `max_periodic_length` agrees. This holds even if an AIR overrides
    // `max_periodic_length` to skip the default's own checks.
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

/// Assert a concrete builder's accessor dimensions match `air`.
///
/// Verifies every data-carrying accessor on [`LiftedAirBuilder`]: main
/// trace, aux trace, public values, randomness, aux values, and periodic
/// values. Guards the invariant that makes [`LiftedAir::eval`] panic-free:
/// if the symbolic evaluation in `constraint_degree` succeeds and this
/// check passes, then `eval()` cannot panic from out-of-bounds access on
/// the builder's accessors.
pub fn check_builder_shape<F, EF, A, AB>(idx: usize, air: &A, builder: &AB)
where
    F: Field,
    A: LiftedAir<F, EF>,
    AB: LiftedAirBuilder<F = F>,
{
    let check = |part: &str, expected: usize, actual: usize| {
        assert!(
            actual == expected,
            "AIR {idx}: {part} dimension mismatch: expected {expected}, got {actual}"
        );
    };

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
