//! Debug-only structural checks for AIRs.
//!
//! These helpers panic on contract violation. They are intended to be called
//! from tests / setup code; the prover and verifier hot paths assume AIRs
//! are well-formed.
//!
//! # When to use what
//!
//! - [`assert_airs_valid`] / [`check_air_structure`] / [`check_one_air`]: verify an AIR (or AIR
//!   list) satisfies the structural contract assumed by the rest of the protocol — no preprocessed
//!   trace, positive auxiliary width, power-of-two periodic columns.
//! - [`assert_valid`] / [`assert_prover_valid`]: structural contract plus the runtime contract
//!   baked into [`Statement`] / [`ProverStatement`].
//! - [`check_builder_shape`]: verify a concrete builder's accessor dimensions match an AIR before
//!   calling [`LiftedAir::eval`]. Used as a `cfg(debug_assertions)` belt-and-suspenders inside the
//!   prover and verifier loops.

use p3_field::{ExtensionField, Field};

use crate::{
    LiftedAir, LiftedAirBuilder, MultiAir, ProverStatement, Statement, WindowAccess,
    validate::{validate_inputs, validate_prover_traces},
};

/// Assert every AIR in `airs` satisfies the structural contract.
///
/// Convenience entry point: equivalent to [`check_air_structure`].
pub fn assert_airs_valid<F, EF, A>(airs: &[A])
where
    F: Field,
    A: LiftedAir<F, EF>,
{
    check_air_structure::<F, EF, A>(airs);
}

/// Assert a statement is fully valid: the runtime inputs contract plus the
/// AIR structural contract.
pub fn assert_valid<F, EF, MA>(statement: &Statement<F, EF, MA>)
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    validate_inputs::<F, EF, MA>(
        statement.multi_air(),
        statement.air_inputs(),
        statement.aux_inputs(),
    )
    .expect("BUG: statement invalid (debug)");
    check_air_structure::<F, EF, MA::Air>(statement.airs());
}

/// Prover-side analogue of [`assert_valid`]: validates trace shape too via
/// [`validate_prover_traces`].
pub fn assert_prover_valid<F, EF, MA>(prover_statement: &ProverStatement<F, EF, MA>)
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    let statement = prover_statement.statement();
    validate_inputs::<F, EF, MA>(
        statement.multi_air(),
        statement.air_inputs(),
        statement.aux_inputs(),
    )
    .expect("BUG: statement invalid (debug)");
    validate_prover_traces::<F, EF, MA>(statement, prover_statement.traces())
        .expect("BUG: prover traces invalid (debug)");
    check_air_structure::<F, EF, MA::Air>(statement.airs());
}

/// Assert every AIR in `airs` is structurally well-formed.
///
/// Loops [`check_one_air`] over the list. The list-level invariant that
/// every AIR declares the same `num_public_values` is *not* checked here;
/// the runtime [`validate_inputs`](crate::validate::validate_inputs)
/// enforces the stronger per-AIR equality
/// `num_public_values == air_inputs.len()`.
pub fn check_air_structure<F, EF, A>(airs: &[A])
where
    F: Field,
    A: LiftedAir<F, EF>,
{
    for (idx, air) in airs.iter().enumerate() {
        check_one_air::<F, EF, _>(idx, air);
    }
}

/// Assert one AIR satisfies the structural contract.
///
/// Checked properties:
/// - **No preprocessed trace** — lifted AIRs forbid preprocessed columns.
/// - **Positive auxiliary width** — `aux_width() > 0`.
/// - **Well-formed periodic columns** — each column non-empty and a power of two in length.
///
/// A degenerate AIR whose constraints all vanish under `Z_H` (combined
/// degree `< 2`) is *supported*, not rejected: the prover and verifier
/// clamp the quotient degree to `D = 2` and proceed normally.
pub fn check_one_air<F, EF, A>(idx: usize, air: &A)
where
    F: Field,
    A: LiftedAir<F, EF>,
{
    assert!(
        air.preprocessed_trace().is_none(),
        "BUG: AIR {idx}: preprocessed traces are not supported"
    );
    assert!(air.aux_width() > 0, "BUG: AIR {idx}: aux_width must be positive");
    for (i, col) in air.periodic_columns().iter().enumerate() {
        assert!(
            !col.is_empty() && col.len().is_power_of_two(),
            "BUG: AIR {idx}: periodic column {i}: length must be positive power of two, \
             got {len}",
            len = col.len(),
        );
    }
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
            "BUG: AIR {idx}: {part} dimension mismatch: expected {expected}, got {actual}"
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
