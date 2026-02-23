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
//! - decoder: op bits, batch flags, control flow
//! - range: range checker V column transitions
//! - chiplets: hasher, bitwise, memory, ACE, kernel ROM
//! - stack: op flags, overflow, field ops, etc.
//!
//! ### Bus Constraints (Auxiliary Trace)
//! - decoder::bus, stack::bus, range::bus, chiplets::bus
//! - bus: shared auxiliary trace indices and utils
//!
//! Bus constraints access the auxiliary trace via `builder.permutation()` and use
//! random challenges from `builder.permutation_randomness()` for multiset/LogUp verification.
//!
//! ## Kernel Verification
//!
//! The chiplets bus uses aux_finals for kernel verification:
//! - First row: b_chiplets[0] = 1 (AIR boundary constraint)
//! - Last row: b_chiplets[last] = reduced_kernel_digests (verified via aux_finals)

use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

mod op_flags;
pub mod range;
pub mod system;
pub mod tagging;

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
