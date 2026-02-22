//! Chiplets constraints module (partial).
//!
//! Currently we implement:
//! - chiplet selector constraints
//! - hasher chiplet main-trace constraints
//! - bitwise chiplet main-trace constraints
//! - memory chiplet main-trace constraints
//! - ACE chiplet main-trace constraints
//! - ACE wiring bus constraint
//!
//! Other chiplets (kernel ROM) and chiplet buses are added later.

pub mod ace;
pub mod bitwise;
pub mod bus;
pub mod hasher;
pub mod memory;
pub mod selectors;

use miden_crypto::stark::air::MidenAirBuilder;

use crate::{Felt, MainTraceRow};

// ENTRY POINTS
// ================================================================================================

/// Enforces chiplets main-trace constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    selectors::enforce_chiplet_selectors(builder, local, next);
    hasher::enforce_hasher_constraints(builder, local, next);
    bitwise::enforce_bitwise_constraints(builder, local, next);
    memory::enforce_memory_constraints(builder, local, next);
    ace::enforce_ace_constraints(builder, local, next);
}
