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
use miden_crypto::stark::air::AirBuilder;

use crate::{MainTraceRow, MidenAirBuilder, constraints::utils::BoolNot};

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
    AB: MidenAirBuilder,
{
    // Load selector columns (chiplets[0..5] are the selectors)
    let s0 = local.chiplets[0];
    let s1 = local.chiplets[1];
    let s2 = local.chiplets[2];
    let s3 = local.chiplets[3];
    let s4 = local.chiplets[4];

    let s0_next = next.chiplets[0];
    let s1_next = next.chiplets[1];
    let s2_next = next.chiplets[2];
    let s3_next = next.chiplets[3];
    let s4_next = next.chiplets[4];

    // ==========================================================================
    // BINARY CONSTRAINTS
    // ==========================================================================
    // Each selector is binary when it could be active

    // s0 is always binary
    builder.assert_bool(s0);

    // s1 is binary when s0 = 1 (bitwise, memory, ACE, or kernel ROM could be active)
    builder.when(s0).assert_bool(s1);

    // s2 is binary when s0 = 1 and s1 = 1 (memory, ACE, or kernel ROM could be active)
    builder.when(s0).when(s1).assert_bool(s2);

    // s3 is binary when s0 = s1 = s2 = 1 (ACE or kernel ROM could be active)
    builder.when(s0).when(s1).when(s2).assert_bool(s3);

    // s4 is binary when s0 = s1 = s2 = s3 = 1 (kernel ROM could be active)
    builder.when(s0).when(s1).when(s2).when(s3).assert_bool(s4);

    // ==========================================================================
    // STABILITY CONSTRAINTS (transition only)
    // ==========================================================================
    // Once a selector becomes 1, it must stay 1 (forbids 1→0 transitions)

    // s0' = s0 when s0 = 1
    builder.when_transition().when(s0).assert_eq(s0_next, s0);

    // s1' = s1 when s0 = 1 and s1 = 1
    builder.when_transition().when(s0).when(s1).assert_eq(s1_next, s1);

    // s2' = s2 when s0 = s1 = s2 = 1
    builder.when_transition().when(s0).when(s1).when(s2).assert_eq(s2_next, s2);

    // s3' = s3 when s0 = s1 = s2 = s3 = 1
    builder
        .when_transition()
        .when(s0)
        .when(s1)
        .when(s2)
        .when(s3)
        .assert_eq(s3_next, s3);

    // s4' = s4 when s0 = s1 = s2 = s3 = s4 = 1
    builder
        .when_transition()
        .when(s0)
        .when(s1)
        .when(s2)
        .when(s3)
        .when(s4)
        .assert_eq(s4_next, s4);
}

// INTERNAL HELPERS
// ================================================================================================

/// Bitwise chiplet active flag: `s0 * !s1`.
#[inline]
pub fn bitwise_chiplet_flag<E: PrimeCharacteristicRing>(s0: E, s1: E) -> E {
    s0 * s1.not()
}

/// Memory chiplet active flag: `s0 * s1 * !s2`.
#[inline]
pub fn memory_chiplet_flag<E: PrimeCharacteristicRing>(s0: E, s1: E, s2: E) -> E {
    s0 * s1 * s2.not()
}

/// ACE chiplet active flag: `s0 * s1 * s2 * !s3`.
#[inline]
pub fn ace_chiplet_flag<E: PrimeCharacteristicRing>(s0: E, s1: E, s2: E, s3: E) -> E {
    s0 * s1 * s2 * s3.not()
}

/// Kernel ROM chiplet active flag: `s0 * s1 * s2 * s3 * !s4`.
#[inline]
pub fn kernel_rom_chiplet_flag<E: PrimeCharacteristicRing>(s0: E, s1: E, s2: E, s3: E, s4: E) -> E {
    s0 * s1 * s2 * s3 * s4.not()
}
