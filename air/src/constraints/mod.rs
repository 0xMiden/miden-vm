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

use miden_crypto::stark::air::MidenAirBuilder;
use p3_matrix::Matrix;

use crate::{MainTraceRow, NUM_PERIODIC_VALUES};

#[rustfmt::skip]
pub mod chiplets;
pub mod range;
pub mod system;

/// Enforces all MidenVM constraints
pub fn enforce_constraints<AB>(builder: &mut AB)
where
    AB: MidenAirBuilder,
{
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
    system::enforce_system_constraints(builder, local, next);

    // STACK CONSTRAINTS
    // For now, decoder and stack constraints are not included in the generated constraints
    // They will be added in the future.
    //stack::enforce_stack_constraints(builder, local, next);

    // RANGE CHECKER CONSTRAINTS
    range::enforce_range_constraints(builder, local, next);

    // CHIPLETS CONSTRAINTS
    chiplets::enforce_chiplets_constraints(builder, local, next, &periodic_values);
}
