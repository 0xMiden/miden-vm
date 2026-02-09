//! Miden VM Constraints
//!
//! This module contains the constraint functions for the Miden VM processor.
//! Constraints are organized by component:
//! - System-level constraints (clock)
//! - Range checker constraints
//! - (Future: decoder, stack, chiplets)

// Allow some clippy warnings for semi-generated code
#![allow(clippy::useless_conversion, clippy::clone_on_copy)]
// Temporarily allow unused code until feature flags are stabilized
#![allow(unused_imports, dead_code, unused_variables)]

use core::borrow::Borrow;

use miden_core::utils::Matrix;
use miden_crypto::stark::air::MidenAirBuilder;

use crate::{MainTraceRow, NUM_PERIODIC_VALUES};

#[rustfmt::skip]
pub mod chiplets;
#[cfg(feature = "decoder_constraints")]
pub mod decoder;
#[cfg(feature = "range_constraints")]
pub mod range;
#[cfg(feature = "stack_constraints")]
pub mod stack;
#[cfg(feature = "system_constraints")]
pub mod system;

/// Enforces all MidenVM constraints on the main trace
pub fn enforce_main_constraints<AB>(builder: &mut AB)
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

    // SYSTEM MAIN CONSTRAINTS
    #[cfg(feature = "system_constraints")]
    system::enforce_main_system_constraints(builder, local, next);

    // TODO: STACK MAIN CONSTRAINTS
    #[cfg(feature = "stack_constraints")]
    stack::enforce_main_stack_constraints(builder, local, next);

    // TODO: DECODER MAIN CONSTRAINTS
    #[cfg(feature = "decoder_constraints")]
    decoder::enforce_main_decoder_constraints(builder, local, next);

    // RANGE CHECKER MAIN CONSTRAINTS
    #[cfg(feature = "range_constraints")]
    range::enforce_main_range_constraints(builder, local, next);

    // CHIPLETS MAIN CONSTRAINTS
    #[cfg(feature = "chiplets_constraints")]
    chiplets::enforce_main_chiplets_constraints(builder, local, next, &periodic_values);
}

/// Enforces all bus MidenVM constraints
pub fn enforce_bus_constraints<AB>(builder: &mut AB)
where
    AB: MidenAirBuilder,
{
    let main = builder.main();

    // Access the two rows: current (local) and next
    let local = main.row_slice(0).expect("Matrix should have at least 1 row");
    let next = main.row_slice(1).expect("Matrix should have at least 2 rows");

    // Use structured column access via MainTraceCols
    let local: &MainTraceRow<AB::Var> = (*local).borrow();
    let _next: &MainTraceRow<AB::Var> = (*next).borrow();

    let _periodic_values: [_; NUM_PERIODIC_VALUES] =
        builder.periodic_evals().try_into().expect("Wrong number of periodic values");

    // For now, decoder and stack constraints are not included in the generated constraints
    // They will be added in the future.

    // TODO: STACK BUS CONSTRAINTS
    #[cfg(feature = "stack_constraints")]
    stack::bus::enforce_stack_bus_constraints(builder, local);

    // TODO: DECODER BUS CONSTRAINTS
    #[cfg(feature = "decoder_constraints")]
    decoder::bus::enforce_decoder_bus_constraints(builder, local);

    // RANGE CHECKER BUS CONSTRAINTS
    #[cfg(feature = "range_constraints")]
    range::bus::enforce_range_bus_constraints(builder, local);

    // CHIPLETS BUS CONSTRAINTS
    #[cfg(feature = "chiplets_constraints")]
    chiplets::bus::enforce_chiplets_bus_constraints(builder, local);
}
