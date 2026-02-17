//! Miden VM Constraints
//!
//! This module contains the constraint functions for the Miden VM processor.
//!
//! ## Organization
//!
//! Constraints are separated into two categories:
//!
//! ### Main Trace Constraints
//! - system: clock, ctx, fn_hash transitions
//! - range: range checker V column transitions
//! - chiplets, stack, decoder (future)
//!
//! ### Bus Constraints (Auxiliary Trace)
//! - range::bus (LogUp multiset checks)

use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

pub mod range;
pub mod system;

// ENTRY POINTS
// ================================================================================================

/// Enforces all main trace constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    system::enforce_main(builder, local, next);
    range::enforce_main(builder, local, next);
}

/// Enforces all auxiliary (bus) constraints.
pub fn enforce_bus<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    _next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    range::bus::enforce_bus(builder, local);
}
