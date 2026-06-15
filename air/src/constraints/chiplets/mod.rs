//! Chiplets constraints module.
//!
//! Currently we implement:
//! - chiplet selector constraints (including hasher internal selectors)
//! - controller sub-chiplet main-trace constraints
//! - bitwise chiplet main-trace constraints
//! - memory chiplet main-trace constraints
//! - ACE chiplet main-trace constraints
//!
//! Chiplet LogUp lookup-argument constraints are emitted by
//! [`crate::constraints::lookup::chiplet_air::emit_chiplet_lookup_columns`] and wired
//! through [`crate::ChipletsAir`]'s `LookupAir` impl from `ChipletsAir::eval`.

pub mod ace;
pub mod aead_stream;
pub mod bitwise;
pub mod columns;
pub mod hasher_control;
pub mod memory;
pub mod selectors;

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::AirBuilder;
use selectors::ChipletSelectors;

use crate::{ChipletCols, MidenAirBuilder};

// ENTRY POINTS
// ================================================================================================

/// Enforces chiplets main-trace constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &ChipletCols<AB::Var>,
    next: &ChipletCols<AB::Var>,
    selectors: &ChipletSelectors<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // Selector constraints (including hasher internal selectors) are enforced in
    // build_chiplet_selectors (called from lib.rs).

    // Chiplet-trace row counter `chip_clk`: starts at 1 and increments by 1 each row.
    builder.when_first_row().assert_eq(local.chip_clk, AB::Expr::ONE);
    builder
        .when_transition()
        .assert_eq(next.chip_clk.into(), local.chip_clk.into() + AB::Expr::ONE);

    hasher_control::enforce_controller_constraints(builder, local, next, &selectors.controller);

    aead_stream::enforce_aead_stream_constraints(builder, local, next, selectors);
    bitwise::enforce_bitwise_constraints(
        builder,
        local,
        next,
        selectors.stream_mode.normal_bitwise.clone(),
    );
    memory::enforce_memory_constraints(builder, local, next, &selectors.memory);
    ace::enforce_ace_constraints_all_rows(builder, local, next, &selectors.ace);
}
