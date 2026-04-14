//! Miden VM Constraints
//!
//! This module contains the constraint functions for the Miden VM processor.
//!
//! ## Organization
//!
//! - **Main trace constraints** are evaluated by [`enforce_main`] and cover system /
//!   range / stack / decoder / chiplets transitions.
//! - **LogUp lookup-argument constraints** are evaluated separately through the
//!   closure-based [`lookup::MidenLookupAir`], wired in from `ProcessorAir::eval` via
//!   [`lookup::ConstraintLookupBuilder`].
//!
//! The legacy multiset bus subtree (`bus.rs`, `decoder/bus.rs`, `stack/bus.rs`,
//! `range/bus.rs`, `chiplets/bus/`) was removed in Milestone B alongside the
//! stateless `MidenLookupAuxBuilder` integration.

use chiplets::selectors::ChipletSelectors;

use crate::{MainCols, MidenAirBuilder};

pub mod chiplets;
pub mod columns;
pub mod constants;
pub mod decoder;
mod degree_audit;
pub mod ext_field;
pub mod logup_msg;
pub mod lookup;
pub(crate) mod op_flags;
pub mod public_inputs;
pub mod range;
pub mod stack;
pub mod system;
pub mod utils;

// ENTRY POINTS
// ================================================================================================

/// Enforces all main trace constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    selectors: &ChipletSelectors<AB::Expr>,
    op_flags: &op_flags::OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    system::enforce_main(builder, local, next, op_flags);
    range::enforce_main(builder, local, next);
    stack::enforce_main(builder, local, next, op_flags);
    decoder::enforce_main(builder, local, next, op_flags);
    chiplets::enforce_main(builder, local, next, selectors);
}
