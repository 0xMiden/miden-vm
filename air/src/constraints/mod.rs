//! Miden VM Constraints
//!
//! This module contains the constraint functions for the Miden VM processor.
//!
//! ## Organization
//!
//! Constraints are separated into two categories:
//!
//! ### Main Trace Constraints
//! - [`system`]: Clock, ctx, fn_hash transitions
//! - [`decoder`]: Op bits, batch flags, control flow
//! - [`range`]: Range checker V column transitions
//! - [`chiplets`]: Hasher, bitwise, memory, ACE, kernel ROM
//! - [`stack`]: Op flags, overflow, field ops, etc.
//!
//! ### Bus Constraints (Auxiliary Trace)
//! - [`decoder::bus`], [`stack::bus`], [`range::bus`], [`chiplets::bus`]
//! - [`bus`]: shared auxiliary trace indices and documentation
//!
//! Bus constraints access the auxiliary trace via `builder.permutation()` and use
//! random challenges from `builder.permutation_randomness()` for Multiset/LogUp verification.
//!
//! ## Kernel Verification
//!
//! The chiplets bus uses aux_finals for kernel verification:
//! - First row: b_chiplets[0] = 1 (AIR boundary constraint)
//! - Last row: b_chiplets[last] = reduced_kernel_digests (verified via aux_finals)
//!
//! See [`bus`] module documentation for details.

use miden_crypto::stark::air::MidenAirBuilder;

use crate::{Felt, MainTraceRow};

pub mod bus;
pub mod chiplets;
pub mod decoder;
pub mod range;
pub mod stack;
pub mod system;

// Re-export OpFlags for convenience
pub use stack::op_flags::{ExprDecoderAccess, OpFlags};

// ENTRY POINTS
// ================================================================================================

/// Enforces all main trace constraints (system, decoder, stack, range, chiplets).
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    system::enforce_main(builder, local, next, op_flags);
    decoder::enforce_main(builder, local, next, op_flags);
    stack::enforce_main(builder, local, next, op_flags);
    range::enforce_main(builder, local, next);
    chiplets::enforce_main(builder, local, next);
}

/// Enforces all auxiliary (bus) constraints.
pub fn enforce_bus<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // Decoder virtual tables (p1, p2, p3).
    decoder::bus::enforce_bus(builder, local, next, op_flags);

    // Stack overflow bus (s_aux).
    stack::bus::enforce_bus(builder, local, next, op_flags);

    // Range checker bus (b_range).
    range::bus::enforce_bus(builder, local);

    // Chiplets buses (b_chiplets, b_hash_kernel) and ACE wiring (v_wiring).
    chiplets::bus::enforce_bus(builder, local, next, op_flags);
}
