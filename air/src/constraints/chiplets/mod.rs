//! Chiplets constraints module (partial).
//!
//! Currently we implement:
//! - chiplet selector constraints
//! - hasher chiplet main-trace constraints
//! - bitwise chiplet main-trace constraints
//!
//! Other chiplets (memory/ACE/kernel ROM) and chiplet buses are added later.

pub mod bitwise;
pub mod hasher;
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
}
