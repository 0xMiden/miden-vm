//! Drift tests: the generated constraint evaluators must be exactly equivalent
//! to the hand-written definitions they were derived from.
//!
//! Two oracles with different failure modes:
//!
//! - **Structural equality (modulo commutative operand order)**: both evaluators captured into one
//!   shared, hash-consing builder produce identical canonical per-constraint roots — the constraint
//!   expressions are the same, deterministically, not just equal at sampled points. Commutative
//!   operand order is quotiented away (any `Add`/`Mul` swap — value-neutral in a field); the
//!   emitter's mixed-class flip, which lets the extension side drive the efficient impl, is the one
//!   difference that exercises the quotient. This also pins the constraint order
//!   (`ConstraintLayout`, and hence alpha assignment and all proof artifacts).
//! - **Polynomial identity testing**: independently captured graphs evaluate to identical
//!   per-constraint values on pseudorandom leaf assignments (4 seeds). Unlike the structural check,
//!   this does not rely on shared-builder id canonicalization or the commutative-sort pass.
//!
//! If these fail after an intentional constraint change, the artifact is stale:
//! `cargo run -p miden-core-lib --features constraints-tools --bin
//! regenerate-evaluator -- --write`

use miden_air::{AIRS, HandwrittenMidenAir};
use miden_constraint_compiler::testing::{
    assert_distinct_captures, assert_evaluations_match, assert_structurally_equivalent,
};

#[test]
fn generated_evaluators_match_handwritten_structurally() {
    for air in AIRS {
        assert_structurally_equivalent(&HandwrittenMidenAir(air), &air);
    }
}

#[test]
fn generated_evaluators_match_handwritten_values() {
    for air in AIRS {
        assert_evaluations_match(&HandwrittenMidenAir(air), &air);
    }
}

/// Guards `miden-constraint-compiler` crate invariant 1: capture must read the
/// hand-written definitions. The emitter flips mixed-class commutative
/// operands, so honest routing yields raw (pre-canonicalization) root ids that
/// differ from the handwritten capture's for every AIR. If
/// `HandwrittenMidenAir` and `MidenAir` ever route to the same evaluator for
/// even one AIR, both drift oracles silently compare the generated path against
/// itself for that AIR — and this test fails instead.
#[test]
fn handwritten_and_generated_are_distinct_captures() {
    for air in AIRS {
        assert_distinct_captures(&HandwrittenMidenAir(air), &air);
    }
}
