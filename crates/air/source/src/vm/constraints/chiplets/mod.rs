//! Chiplets trace constraints.
//!
//! This module enforces:
//! - chiplet selector constraints
//! - controller sub-chiplet main-trace constraints
//! - AEAD stream main-trace constraints
//! - bitwise chiplet main-trace constraints
//! - memory chiplet main-trace constraints
//! - ACE chiplet main-trace constraints
//!
//! Eidos compression constraints are enforced by the separate
//! [`crate::vm::EidosCompressionAir`], with byte-table relations supplied by
//! [`crate::vm::And8LookupAir`].
//!
//! Chiplet LogUp lookup-argument constraints are emitted by
//! [`crate::vm::constraints::lookup::chiplet_air::emit_chiplet_lookup_columns`] and wired
//! through [`crate::vm::ChipletsAir`]'s `LookupAir` impl from `ChipletsAir::eval`.

pub mod ace;
pub mod aead_stream;
pub mod bitwise;
pub mod columns;
pub mod hasher_control;
pub mod memory;
pub mod selectors;

use selectors::ChipletSelectors;

use crate::vm::{ChipletCols, MidenAirBuilder};

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
    // Each evaluator sees its own payload and the gates derived from the shared selectors.
    let controller = local.controller_cols();
    let controller_next = next.controller_cols();
    hasher_control::enforce_controller_constraints(builder, controller, controller_next, selectors);

    aead_stream::enforce_aead_stream_constraints(
        builder,
        local.aead_stream_cols(),
        next.aead_stream_cols(),
        selectors,
    );
    bitwise::enforce_bitwise_constraints(builder, local.bitwise_cols(), selectors);
    memory::enforce_memory_constraints(builder, local.memory_cols(), next.memory_cols(), selectors);
    ace::enforce_ace_constraints_all_rows(builder, local.ace_cols(), next.ace_cols(), selectors);
    hasher_control::enforce_merkle_level_constraints(builder, controller, controller_next);
}
