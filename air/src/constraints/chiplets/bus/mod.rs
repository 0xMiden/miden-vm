//! Chiplets bus constraints.
//!
//! This module groups auxiliary (bus) constraints associated with chiplets.
//! Currently implemented:
//! - v_wiring: ACE wiring bus

pub mod wiring;

use miden_crypto::stark::air::MidenAirBuilder;

use crate::{Felt, MainTraceRow};

/// Enforces chiplets bus constraints.
pub fn enforce_bus<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    wiring::enforce_wiring_bus_constraint(builder, local, next);
}
