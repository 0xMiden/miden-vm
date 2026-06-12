//! Miden VM Constraints
//!
//! This module contains the constraint functions for the Miden VM processor.
//!
//! ## Organization
//!
//! - **Main trace constraints** are evaluated by [`enforce_main`] and cover system / range / stack
//!   / decoder / chiplets transitions.
//! - **LogUp lookup-argument constraints** are evaluated separately through the closure-based
//!   `LookupAir` impls on [`crate::CoreAir`] and [`crate::ChipletsAir`], wired in from each AIR's
//!   `eval` via [`crate::lookup::ConstraintLookupBuilder`].

use chiplets::selectors::ChipletSelectors;

use crate::{ChipletCols, CoreCols, MidenAirBuilder};

pub mod and8_lookup;
pub mod chiplets;
pub mod columns;
pub mod constants;
pub mod decoder;
pub mod ext_field;
pub mod lookup;
pub(crate) mod op_flags;
pub mod poseidon2_permutation;
pub mod public_inputs;
pub mod range;
pub mod stack;
pub mod system;
pub mod utils;

// ENTRY POINTS
// ================================================================================================
//
// Main trace constraints are partitioned by AIR: `enforce_core` runs the Core half (system,
// range, stack, decoder) and `enforce_chiplets` runs the Chiplets half. The per-AIR
// `LiftedAir` impls (`CoreAir`, `ChipletsAir`) each call only their share.

/// Enforces the Core-trace main constraints: system, range, stack, decoder.
///
/// Public-input boundary constraints ([`public_inputs::enforce_main`]) are owned by Core too
/// but live on a separate entry point because they don't read `next` or `op_flags`.
pub fn enforce_core<AB>(
    builder: &mut AB,
    local: &CoreCols<AB::Var>,
    next: &CoreCols<AB::Var>,
    op_flags: &op_flags::OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    system::enforce_main(builder, local, next, op_flags);
    range::enforce_main(builder, local, next);
    stack::enforce_main(builder, local, next, op_flags);
    decoder::enforce_main(builder, local, next, op_flags);
}

/// Enforces the Chiplets-trace main constraints (hasher controller, bitwise, memory, ACE).
/// Selector validity is enforced separately via
/// [`chiplets::selectors::build_chiplet_selectors`].
pub fn enforce_chiplets<AB>(
    builder: &mut AB,
    local: &ChipletCols<AB::Var>,
    next: &ChipletCols<AB::Var>,
    selectors: &ChipletSelectors<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    chiplets::enforce_main(builder, local, next, selectors);
}
