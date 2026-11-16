//! Miden VM Constraints
//!
//! This module contains the constraint functions for the Miden VM processor.
//!
//! ## Organization
//!
//! - **Main trace constraints** use [`enforce_core`] and [`enforce_chiplets`], covering system,
//!   stack, decoder, and chiplet transitions.
//! - **LogUp lookup-argument constraints** use the declarations selected by [`crate::vm::MidenAir`]
//!   and are wired into each AIR's `eval` through [`miden_stark::lookup::ConstraintLookupBuilder`].

use chiplets::selectors::ChipletSelectors;
use miden_stark::air::Frame;

use crate::vm::{ChipletCols, CoreCols, NativeMidenAirBuilder};

pub mod and8_lookup;
pub mod chiplets;
pub mod columns;
pub mod constants;
pub mod decoder;
pub mod eidos_compression;
pub mod ext_field;
pub mod lookup;
pub(crate) mod op_flags;
pub mod public_inputs;
pub mod stack;
pub mod system;
pub mod utils;

#[cfg(test)]
mod test_utils;

// ENTRY POINTS
// ================================================================================================
//
// Main trace constraints are partitioned by AIR: `enforce_core` runs the Core half (system, stack,
// decoder) and `enforce_chiplets` runs the Chiplets half. The per-AIR
// `LiftedAir` impls (`CoreAir`, `ChipletsAir`) each call only their share.

/// Enforces the Core-trace main constraints: system, stack, decoder.
///
/// Public-input boundary constraints ([`public_inputs::enforce_main`]) are owned by Core too
/// but live on a separate entry point because they don't read `next` or `op_flags`.
pub fn enforce_core<AB>(
    frame: &Frame<'_, AB>,
    builder: &mut AB,
    local: &CoreCols<AB::Expr>,
    next: &CoreCols<AB::Expr>,
    op_flags: &op_flags::OpFlags<AB::Expr>,
) where
    AB: NativeMidenAirBuilder,
{
    system::enforce_main(frame, builder, local, next, op_flags);
    stack::enforce_main(frame, builder, local, next, op_flags);
    decoder::enforce_main(frame, builder, local, next, op_flags);
}

/// Enforces the Chiplets-trace main constraints (hasher controller, bitwise, memory, ACE).
/// Selector validity is enforced separately via
/// [`chiplets::selectors::build_chiplet_selectors`].
pub fn enforce_chiplets<AB>(
    frame: &Frame<'_, AB>,
    builder: &mut AB,
    local: &ChipletCols<AB::Expr>,
    next: &ChipletCols<AB::Expr>,
    selectors: &ChipletSelectors<AB::Expr>,
) where
    AB: NativeMidenAirBuilder,
{
    chiplets::enforce_main(frame, builder, local, next, selectors);
}
