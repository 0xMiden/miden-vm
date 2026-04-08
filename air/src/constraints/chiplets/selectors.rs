//! Chiplet selector system constraints and precomputed flags.
//!
//! This module implements the hierarchical chiplet selector system that determines
//! which chiplet is active at any given row, and provides precomputed flags for
//! gating chiplet-specific constraints.
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
//! ## Precomputed Flags
//!
//! Each chiplet gets a [`ChipletFlags`] struct with four flags:
//! - `is_active`: 1 when this chiplet owns the current row
//! - `is_transition`: `is_transition() * prefix * (1 - s_n')` — active and not on last row
//! - `is_last`: `is_active * s_n'` — last row of this chiplet's section
//! - `next_is_first`: `is_last[n-1] * (1 - s_n')` — next row is first of this chiplet
//!
//! ## Constraints
//!
//! 1. **Binary constraints**: Each selector is binary when it could be active
//! 2. **Stability constraints**: Once a selector becomes 1, it stays 1 (no 1→0 transitions)
//! 3. **Last-row invariant**: All selectors must be 1 in the last row
//!
//! The last-row invariant (s0 = s1 = s2 = s3 = s4 = 1 on the final row) guarantees
//! that every chiplet's `is_active` flag is zero on the last row. Combined with the
//! `(1 - s_n')` factor in the precomputed flags, this makes chiplet-gated constraints
//! automatically vanish on the last row without needing explicit `when_transition()`
//! guards.

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::AirBuilder;

use crate::{MainCols, MidenAirBuilder, constraints::utils::BoolNot};

// CHIPLET FLAGS
// ================================================================================================

/// Precomputed flags for a single chiplet.
#[derive(Clone)]
pub struct ChipletFlags<E> {
    /// 1 when this chiplet owns the current row.
    pub is_active: E,
    /// `is_transition() * prefix * (1 - s_n')` — bakes in the transition flag.
    pub is_transition: E,
    /// `is_active * s_n'` — last row of this chiplet's section.
    pub is_last: E,
    /// `is_last[n-1] * (1 - s_n')` — next row is the first row of this chiplet.
    pub next_is_first: E,
}

/// Precomputed flags for all chiplets.
#[derive(Clone)]
pub struct ChipletSelectors<E> {
    // TODO: hasher constraints currently compute their own flag instead of using this.
    // Will be wired up during the bus constraint refactor.
    pub _hasher: ChipletFlags<E>,
    pub bitwise: ChipletFlags<E>,
    pub memory: ChipletFlags<E>,
    pub ace: ChipletFlags<E>,
    pub kernel_rom: ChipletFlags<E>,
}

// ENTRY POINTS
// ================================================================================================

/// Enforce chiplet selector constraints and build precomputed flags.
///
/// This enforces:
/// 1. Binary constraints for each selector level
/// 2. Stability constraints (no 1→0 transitions)
///
/// Returns [`ChipletSelectors`] with precomputed flags for gating chiplet constraints.
pub fn build_chiplet_selectors<AB>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
) -> ChipletSelectors<AB::Expr>
where
    AB: MidenAirBuilder,
{
    // Load selector columns via typed accessor
    let sel = local.chiplet_selectors();
    let sel_next = next.chiplet_selectors();

    let s0: AB::Expr = sel[0].into();
    let s1: AB::Expr = sel[1].into();
    let s2: AB::Expr = sel[2].into();
    let s3: AB::Expr = sel[3].into();
    let s4: AB::Expr = sel[4].into();

    let s0_next: AB::Expr = sel_next[0].into();
    let s1_next: AB::Expr = sel_next[1].into();
    let s2_next: AB::Expr = sel_next[2].into();
    let s3_next: AB::Expr = sel_next[3].into();
    let s4_next: AB::Expr = sel_next[4].into();

    // ==========================================================================
    // BINARY CONSTRAINTS
    // ==========================================================================

    // s0 is always binary
    builder.assert_bool(sel[0]);

    // s1..s4 are binary when their prefix selectors are all 1.
    // Cumulative products gate each selector on its prefix being active.
    let s01 = s0.clone() * s1.clone();
    let s012 = s01.clone() * s2.clone();
    let s0123 = s012.clone() * s3.clone();

    builder.when(sel[0]).assert_bool(sel[1]);
    builder.when(s01.clone()).assert_bool(sel[2]);
    builder.when(s012.clone()).assert_bool(sel[3]);
    builder.when(s0123.clone()).assert_bool(sel[4]);

    // ==========================================================================
    // STABILITY CONSTRAINTS (transition only)
    // ==========================================================================
    // Once a selector becomes 1, it must stay 1 (forbids 1→0 transitions).
    // Each selector's next value must equal its current value when its prefix is active.

    let s01234 = s0123.clone() * s4.clone();

    // Selectors are stable: once set to 1, they remain 1.
    {
        let builder = &mut builder.when_transition();
        builder.when(s0.clone()).assert_eq(sel_next[0], sel[0]);
        builder.when(s01.clone()).assert_eq(sel_next[1], sel[1]);
        builder.when(s012.clone()).assert_eq(sel_next[2], sel[2]);
        builder.when(s0123.clone()).assert_eq(sel_next[3], sel[3]);
        builder.when(s01234.clone()).assert_eq(sel_next[4], sel[4]);
    }

    // ==========================================================================
    // LAST-ROW INVARIANT
    // ==========================================================================
    // All selectors must be 1 in the last row. This ensures every chiplet's
    // is_active flag is zero on the last row, making chiplet-gated constraints
    // vanish without explicit when_transition() guards.
    {
        let builder = &mut builder.when_last_row();
        builder.assert_one(sel[0]);
        builder.assert_one(sel[1]);
        builder.assert_one(sel[2]);
        builder.assert_one(sel[3]);
        builder.assert_one(sel[4]);
    }

    // ==========================================================================
    // PRECOMPUTE FLAGS
    // ==========================================================================

    let not_s0_next = s0_next.not();
    let not_s1_next = s1_next.not();
    let not_s2_next = s2_next.not();
    let not_s3_next = s3_next.not();
    let not_s4_next = s4_next.not();

    let is_transition_flag: AB::Expr = builder.is_transition();

    // 1. Active flags (subtraction trick: prefix - prefix * s_n)
    let is_hasher = s0.not();
    let is_bitwise = s0.clone() - s01.clone();
    let is_memory = s01.clone() - s012.clone();
    let is_ace = s012.clone() - s0123.clone();
    let is_kernel_rom = s0123.clone() - s01234;

    // 2. Last-row flags: is_active * s_n'
    let is_hasher_last = is_hasher.clone() * s0_next;
    let is_bitwise_last = is_bitwise.clone() * s1_next;
    let is_memory_last = is_memory.clone() * s2_next;
    let is_ace_last = is_ace.clone() * s3_next;
    let is_kernel_rom_last = is_kernel_rom.clone() * s4_next;

    // 3. Next-is-first flags: is_last[n-1] * (1 - s_n')
    let next_is_hasher_first = AB::Expr::ZERO;
    let next_is_bitwise_first = is_hasher_last.clone() * not_s1_next.clone();
    let next_is_memory_first = is_bitwise_last.clone() * not_s2_next.clone();
    let next_is_ace_first = is_memory_last.clone() * not_s3_next.clone();
    let next_is_kernel_rom_first = is_ace_last.clone() * not_s4_next.clone();

    // 4. Transition flags: is_transition * prefix * (1 - s_n')
    let hasher_transition = is_transition_flag.clone() * not_s0_next;
    let bitwise_transition = is_transition_flag.clone() * s0 * not_s1_next;
    let memory_transition = is_transition_flag.clone() * s01 * not_s2_next;
    let ace_transition = is_transition_flag.clone() * s012 * not_s3_next;
    let kernel_rom_transition = is_transition_flag * s0123 * not_s4_next;

    ChipletSelectors {
        _hasher: ChipletFlags {
            is_active: is_hasher,
            is_transition: hasher_transition,
            is_last: is_hasher_last,
            next_is_first: next_is_hasher_first,
        },
        bitwise: ChipletFlags {
            is_active: is_bitwise,
            is_transition: bitwise_transition,
            is_last: is_bitwise_last,
            next_is_first: next_is_bitwise_first,
        },
        memory: ChipletFlags {
            is_active: is_memory,
            is_transition: memory_transition,
            is_last: is_memory_last,
            next_is_first: next_is_memory_first,
        },
        ace: ChipletFlags {
            is_active: is_ace,
            is_transition: ace_transition,
            is_last: is_ace_last,
            next_is_first: next_is_ace_first,
        },
        kernel_rom: ChipletFlags {
            is_active: is_kernel_rom,
            is_transition: kernel_rom_transition,
            is_last: is_kernel_rom_last,
            next_is_first: next_is_kernel_rom_first,
        },
    }
}
