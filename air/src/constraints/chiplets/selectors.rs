//! Chiplet selector system constraints.
//!
//! This module implements the hierarchical chiplet selector system that determines
//! which chiplet is active at any given row.
//!
//! ## Selector Hierarchy
//!
//! The chiplet system uses 5 selector columns `s[0..4]` to identify active chiplets:
//!
//! | Chiplet     | Active when                    | Selector pattern |
//! |-------------|--------------------------------|------------------|
//! | Hasher      | `!s0`                          | `(0, *, *, *, *)` |
//! | Bitwise     | `s0 * !s1`                     | `(1, 0, *, *, *)` |
//! | Memory      | `s0 * s1 * !s2`                | `(1, 1, 0, *, *)` |
//! | ACE         | `s0 * s1 * s2 * !s3`           | `(1, 1, 1, 0, *)` |
//! | Kernel ROM  | `s0 * s1 * s2 * s3 * !s4`      | `(1, 1, 1, 1, 0)` |
//!
//! ## Constraints
//!
//! 1. **Binary constraints**: Each selector is binary when it could be active
//! 2. **Stability constraints**: Once a selector becomes 1, it stays 1 (no 1→0 transitions)

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use crate::{Felt, MainTraceRow};

// ENTRY POINTS
// ================================================================================================

/// Enforce chiplet selector constraints.
///
/// This enforces:
/// 1. Binary constraints for each selector level
/// 2. Stability constraints (no 1→0 transitions)
pub fn enforce_chiplet_selectors<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // Load selector columns (chiplets[0..5] are the selectors)
    let s0: AB::Expr = local.chiplets[0].clone().into();
    let s1: AB::Expr = local.chiplets[1].clone().into();
    let s2: AB::Expr = local.chiplets[2].clone().into();
    let s3: AB::Expr = local.chiplets[3].clone().into();
    let s4: AB::Expr = local.chiplets[4].clone().into();

    let s0_next: AB::Expr = next.chiplets[0].clone().into();
    let s1_next: AB::Expr = next.chiplets[1].clone().into();
    let s2_next: AB::Expr = next.chiplets[2].clone().into();
    let s3_next: AB::Expr = next.chiplets[3].clone().into();
    let s4_next: AB::Expr = next.chiplets[4].clone().into();

    let one: AB::Expr = AB::Expr::ONE;

    // ==========================================================================
    // BINARY CONSTRAINTS
    // ==========================================================================
    // Each selector is binary when it could be active

    // s0 is always binary
    builder.assert_zero(s0.clone() * (s0.clone() - one.clone()));

    // s1 is binary when s0 = 1 (bitwise, memory, ACE, or kernel ROM could be active)
    builder.assert_zero(s0.clone() * s1.clone() * (s1.clone() - one.clone()));

    // s2 is binary when s0 = 1 and s1 = 1 (memory, ACE, or kernel ROM could be active)
    builder.assert_zero(s0.clone() * s1.clone() * s2.clone() * (s2.clone() - one.clone()));

    // s3 is binary when s0 = s1 = s2 = 1 (ACE or kernel ROM could be active)
    builder.assert_zero(
        s0.clone() * s1.clone() * s2.clone() * s3.clone() * (s3.clone() - one.clone()),
    );

    // s4 is binary when s0 = s1 = s2 = s3 = 1 (kernel ROM could be active)
    builder.assert_zero(
        s0.clone() * s1.clone() * s2.clone() * s3.clone() * s4.clone() * (s4.clone() - one.clone()),
    );

    // ==========================================================================
    // STABILITY CONSTRAINTS (transition only)
    // ==========================================================================
    // Once a selector becomes 1, it must stay 1 (forbids 1→0 transitions)

    let is_transition: AB::Expr = builder.is_transition();

    // s0' = s0 when s0 = 1
    builder.assert_zero(is_transition.clone() * s0.clone() * (s0_next.clone() - s0.clone()));

    // s1' = s1 when s0 = 1 and s1 = 1
    builder.assert_zero(
        is_transition.clone() * s0.clone() * s1.clone() * (s1_next.clone() - s1.clone()),
    );

    // s2' = s2 when s0 = s1 = s2 = 1
    builder.assert_zero(
        is_transition.clone()
            * s0.clone()
            * s1.clone()
            * s2.clone()
            * (s2_next.clone() - s2.clone()),
    );

    // s3' = s3 when s0 = s1 = s2 = s3 = 1
    builder.assert_zero(
        is_transition.clone()
            * s0.clone()
            * s1.clone()
            * s2.clone()
            * s3.clone()
            * (s3_next.clone() - s3.clone()),
    );

    // s4' = s4 when s0 = s1 = s2 = s3 = s4 = 1
    builder.assert_zero(is_transition * s0 * s1 * s2 * s3 * s4.clone() * (s4_next - s4));
}

// INTERNAL HELPERS
// ================================================================================================

/// Hasher chiplet active flag: `!s0`
#[inline]
#[allow(dead_code)]
pub fn hasher_chiplet_flag<E: PrimeCharacteristicRing>(s0: E) -> E {
    E::ONE - s0
}

/// Bitwise chiplet active flag: `s0 * !s1`
#[inline]
pub fn bitwise_chiplet_flag<E: PrimeCharacteristicRing>(s0: E, s1: E) -> E {
    s0 * (E::ONE - s1)
}

/// Memory chiplet active flag: `s0 * s1 * !s2`
#[inline]
pub fn memory_chiplet_flag<E: PrimeCharacteristicRing>(s0: E, s1: E, s2: E) -> E {
    s0 * s1 * (E::ONE - s2)
}

/// ACE chiplet active flag: `s0 * s1 * s2 * !s3`
#[inline]
pub fn ace_chiplet_flag<E: PrimeCharacteristicRing>(s0: E, s1: E, s2: E, s3: E) -> E {
    s0 * s1 * s2 * (E::ONE - s3)
}

/// Kernel ROM chiplet active flag: `s0 * s1 * s2 * s3 * !s4`
#[inline]
pub fn kernel_rom_chiplet_flag<E: PrimeCharacteristicRing>(s0: E, s1: E, s2: E, s3: E, s4: E) -> E {
    s0 * s1 * s2 * s3 * (E::ONE - s4)
}
