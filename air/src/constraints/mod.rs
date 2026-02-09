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

use miden_core::field::PrimeCharacteristicRing;
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

    // STACK MAIN CONSTRAINTS
    #[cfg(feature = "stack_constraints")]
    stack::enforce_main_stack_constraints(builder, local, next);

    // DECODER MAIN CONSTRAINTS
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
    let next: &MainTraceRow<AB::Var> = (*next).borrow();

    let periodic_values: [_; NUM_PERIODIC_VALUES] =
        builder.periodic_evals().try_into().expect("Wrong number of periodic values");

    // FIXME: move these constants to a more appropriate place, and ensure they are consistent across all constraints modules
    const MAX_BETA_CHALLENGE_POWER: usize = 15;
    const AUX_WIDTH: usize = 8;

    let (&alpha, beta_challenges) = builder.permutation_randomness().split_first().expect("Wrong number of randomness");
    let beta_challenges: [_; MAX_BETA_CHALLENGE_POWER] = beta_challenges.try_into().expect("Wrong number of randomness");
    let aux_bus_boundary_values: [_; AUX_WIDTH] = builder.aux_bus_boundary_values().try_into().expect("Wrong number of aux bus boundary values");
    let aux = builder.permutation();
    let (aux_current, aux_next) = (
        aux.row_slice(0).unwrap(),
        aux.row_slice(1).unwrap(),
    );

    // STACK BUS CONSTRAINTS
    #[cfg(feature = "stack_constraints")]
    stack::bus::enforce_stack_bus_constraints(builder, alpha, &beta_challenges, &aux_current, &aux_next, local, next, &periodic_values);

    // DECODER BUS CONSTRAINTS
    #[cfg(feature = "decoder_constraints")]
    decoder::bus::enforce_decoder_bus_constraints(builder, alpha, &beta_challenges, &aux_current, &aux_next, local, next);

    // RANGE CHECKER BUS CONSTRAINTS
    #[cfg(feature = "range_constraints")]
    range::bus::enforce_range_bus_constraints(builder, alpha, &beta_challenges, &aux_current, &aux_next, local, next);

    // CHIPLETS BUS CONSTRAINTS
    #[cfg(feature = "chiplets_constraints")]
    chiplets::bus::enforce_chiplets_bus_constraints(builder, alpha, &beta_challenges, &aux_current, &aux_next, local, next, &periodic_values);
}
