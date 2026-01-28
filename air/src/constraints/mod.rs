//! Miden VM Constraints
//!
//! This module contains the constraint functions for the Miden VM processor.
//! Constraints are organized by component:
//! - System-level constraints (clock)
//! - Range checker constraints
//! - (Future: decoder, stack, chiplets)

// Allow some clippy warnings for semi-generated code
#![allow(clippy::useless_conversion, clippy::clone_on_copy)]

use core::borrow::Borrow;

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use crate::{MainTraceRow, NUM_PERIODIC_VALUES};

#[rustfmt::skip]
pub mod chiplets;
pub mod range;

/// Enforces all MidenVM constraints
pub fn enforce_constraints<AB>(builder: &mut AB)
where
    AB: MidenAirBuilder,
{
    use p3_matrix::Matrix;

    use crate::constraints;

    let main = builder.main();

    // Access the two rows: current (local) and next
    let local = main.row_slice(0).expect("Matrix should have at least 1 row");
    let next = main.row_slice(1).expect("Matrix should have at least 2 rows");

    // Use structured column access via MainTraceCols
    let local: &MainTraceRow<AB::Var> = (*local).borrow();
    let next: &MainTraceRow<AB::Var> = (*next).borrow();

    let periodic_values: [_; NUM_PERIODIC_VALUES] =
        builder.periodic_evals().try_into().expect("Wrong number of periodic values");

    // SYSTEM CONSTRAINTS
    constraints::enforce_clock_constraint(builder, local, next);

    // STACK CONSTRAINTS
    //constraints::stack::enforce_stack_boundary_constraints(builder, local);
    //constraints::stack::enforce_stack_transition_constraint(builder, local, next);
    //constraints::stack::enforce_stack_bus_constraint(builder, local);

    // RANGE CHECKER CONSTRAINTS
    constraints::range::enforce_range_boundary_constraints(builder, local);
    constraints::range::enforce_range_transition_constraint(builder, local, next);
    constraints::range::enforce_range_bus_constraint(builder, local);

    // CHIPLETS CONSTRAINTS
    constraints::chiplets::enforce_chiplets_transition_constraint(
        builder,
        local,
        next,
        &periodic_values,
    );
    constraints::chiplets::enforce_chiplets_bus_constraint(builder, local);
}

/// Enforces the clock constraint: clk' = clk + 1
///
/// The clock must increment by 1 at each step, ensuring proper sequencing of operations.
pub fn enforce_clock_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    // Clock boundary constraint: clk[0] = 0
    builder.when_first_row().assert_zero(local.clk.clone());

    // Clock transition constraint: clk' = clk + 1
    let one_expr: AB::Expr = AB::F::ONE.into();
    builder
        .when_transition()
        .assert_eq(next.clk.clone(), local.clk.clone() + one_expr);
}
