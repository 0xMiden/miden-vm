//! Debug-only structural checks for AIRs. These panic on contract violation and
//! are meant for tests / setup; the prover and verifier hot paths assume AIRs
//! are well-formed.
//!
//! Runtime checks on caller-supplied data live instead on
//! [`Statement::new`](crate::Statement::new) /
//! [`ProverStatement::new`](crate::ProverStatement::new).

use p3_field::{ExtensionField, Field};

use crate::{BaseAir, LiftedAir, LiftedAirBuilder, MultiAir, WindowAccess};

/// Assert a [`MultiAir`] is structurally well-formed: per AIR no preprocessed
/// trace, positive auxiliary width, and positive-power-of-two periodic columns;
/// across AIRs a shared `num_public_values`. The overridable
/// [`MultiAir::num_air_inputs`] / [`LiftedAir::max_periodic_length`] are
/// cross-checked against the raw AIR data, so a lying override is caught here.
///
/// Panics on an empty `airs()` or any violation. A degenerate AIR whose
/// constraints all vanish under `Z_H` is supported, not rejected — the
/// prover/verifier clamp the quotient degree to `D = 2`.
pub fn assert_multi_air_valid<F, EF, MA>(multi_air: &MA)
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    let airs = multi_air.airs();

    // Derive the shared count from the raw AIRs (panics on empty `airs()`) and
    // confirm the overridable `num_air_inputs` agrees.
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

/// Assert a concrete builder's accessor dimensions match `air` — main and aux
/// trace, public values, randomness, aux values, and periodic values.
///
/// Guards the invariant that makes [`LiftedAir::eval`] panic-free: if symbolic
/// evaluation in `constraint_degree` succeeds and this check passes, `eval()`
/// cannot panic from out-of-bounds accessor access.
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
