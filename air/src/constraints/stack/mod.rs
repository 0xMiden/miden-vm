//! Stack constraints module.
//!
//! This module contains constraints for the operand stack in the Miden VM.
//!
//! The stack constraints are organized into:
//! - [`op_flags`]: Operation flag computation from decoder op bits
//! - [`overflow`]: Stack overflow table bookkeeping constraints
//! - [`general`]: General stack transition constraints (16 positions)
//! - [`field_ops`]: Field operation constraints (ADD, MUL, INV, etc.)
//! - [`crypto_ops`]: Crypto operation constraints (CRYPTOSTREAM, HORNERBASE, HORNEREXT, FRIE2F4)
//! - [`io_ops`]: Input/output operation constraints (SDEPTH)
//! - [`system_ops`]: System operation constraints (ASSERT)
//! - [`u32_ops`]: U32 arithmetic operation constraints (U32SPLIT, U32ADD, etc.)
//! - [`stack_ops`]: Stack manipulation constraints (PAD, DUP, CLK, SWAP, MOV*, CSWAP, ...)
//! - [`bus`]: Stack overflow bus constraints (s_aux)

pub mod bus;
pub mod crypto_ops;
pub mod field_ops;
pub mod general;
pub mod io_ops;
pub mod op_flags;
pub mod overflow;
pub mod stack_ops;
pub mod system_ops;
pub mod u32_ops;

use miden_crypto::stark::air::MidenAirBuilder;

use self::op_flags::OpFlags;
use crate::MainTraceRow;

// ENTRY POINTS
// ================================================================================================

/// Enforces stack main-trace constraints (entry point).
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    overflow::enforce_main(builder, local, next, op_flags);
    general::enforce_main(builder, local, next, op_flags);
    field_ops::enforce_main(builder, local, next, op_flags);
    crypto_ops::enforce_main(builder, local, next, op_flags);
    io_ops::enforce_main(builder, local, next, op_flags);
    system_ops::enforce_main(builder, local, next, op_flags);
    u32_ops::enforce_main(builder, local, next, op_flags);
    stack_ops::enforce_main(builder, local, next, op_flags);
}
