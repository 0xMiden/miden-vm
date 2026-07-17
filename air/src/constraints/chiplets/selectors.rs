//! Chiplet selector system constraints and precomputed flags.
//!
//! This module implements the chiplet selector system that determines which chiplet is
//! active at any given row, and provides precomputed flags for gating chiplet-specific
//! constraints.
//!
//! ## Selector Hierarchy
//!
//! The chiplet system uses a prefix selector chain `s0..s4`. The hasher controller is active
//! when `s0 = 0`; the remaining chiplets are selected by the first zero after an active prefix.
//!
//! Each chiplet is gated by a named *activation flag* `f_<chiplet>`, defined once in terms of
//! the raw selectors below. Main-trace constraints use the flags returned by this module; LogUp
//! uses [`ChipletActiveFlags`], which mirrors the same algebra and also includes kernel ROM.
//!
//! [`ChipletActiveFlags`]: crate::constraints::lookup::buses::ChipletActiveFlags
//!
//! | Chiplet     | Flag          | Active when                    |
//! |-------------|---------------|--------------------------------|
//! | Controller  | `f_ctrl`      | `!s0`                          |
//! | Bitwise     | `f_bitwise`   | `s0 * !s1`                     |
//! | Memory      | `f_memory`    | `s0 * s1 * !s2`                |
//! | ACE         | `f_ace`       | `s0 * s1 * s2 * !s3`           |
//! | Kernel ROM  | `f_kernel_rom`| `s0 * s1 * s2 * s3 * !s4`      |
//!
//! ## Selector Transition Rules
//!
//! - `s0` is boolean
//! - `s0 = 1 -> s0' = 1` (once outside the controller region, stay there)
//!
//! This makes controller rows a prefix of the chiplets trace.
//!
//! ## Main-Constraint Flags
//!
//! The chiplets with main-trace constraints get a [`ChipletFlags`] struct with four flags:
//! - `is_active`: 1 when this chiplet owns the current row
//! - `is_transition`: active on both current and next row, including `is_transition()`
//! - `is_last`: current row belongs to this chiplet and the next row has advanced past it
//! - `next_is_first`: the next row is the first row of this chiplet's section (equivalently, the
//!   current row is the last row before that section). This flag is derived from the section
//!   boundary itself, so it still fires when the preceding chiplet section is empty.
//!
//! For each non-controller chiplet, `is_active` is `prefix * (1 - selector)`, where
//! `selector` is the column that ends that chiplet's section. The code writes this as
//! `prefix - prefix * selector`. The controller has an empty prefix and uses `1 - s0`.
//!
//! ## Constraints
//!
//! 1. **Partition**: `s0` is boolean
//! 2. **Transition rules**: once `s0` becomes 1, it remains 1
//! 3. **Binary constraints**: `s1..s4` are binary when their prefix is active
//! 4. **Stability constraints**: once `s1..s4` become 1, they stay 1
//! 5. **Last-row invariant**: `s0 = s1 = s2 = s3 = s4 = 1` on the final row
//!
//! The last-row invariant ensures every chiplet's `is_active` flag is zero on the last
//! row. The precomputed flags also check that the next row has not advanced past the
//! selected chiplet, so chiplet-gated constraints automatically vanish on the last row without
//! needing explicit `when_transition()` guards.

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::AirBuilder;

use crate::{ChipletCols, MidenAirBuilder, constraints::utils::BoolNot};

// CHIPLET FLAGS
// ================================================================================================

/// Precomputed flags for a single chiplet.
#[derive(Clone)]
pub struct ChipletFlags<E> {
    /// 1 when this chiplet owns the current row.
    pub is_active: E,
    /// 1 on transitions where both the current row and next row belong to this chiplet.
    pub is_transition: E,
    /// 1 on the last row of this chiplet's section.
    pub is_last: E,
    /// 1 when the next row is the first row of this chiplet's section.
    pub next_is_first: E,
}

/// Precomputed flags for chiplets with main-trace constraints.
///
/// Kernel ROM is enforced through lookup-bus constraints, so its active flag lives in
/// `ChipletActiveFlags` instead.
#[derive(Clone)]
pub struct ChipletSelectors<E> {
    pub controller: ChipletFlags<E>,
    pub bitwise: ChipletFlags<E>,
    pub memory: ChipletFlags<E>,
    pub ace: ChipletFlags<E>,
}

// ENTRY POINT
// ================================================================================================

/// Enforce chiplet selector constraints and build precomputed flags.
///
/// This enforces:
/// 1. Partition constraints for `s0`
/// 2. Transition rule: once `s0` becomes 1, it remains 1
/// 3. Binary and stability constraints for `s1..s4` under `s0`
/// 4. Last-row invariant (`s0..s4 = 1`)
///
/// Returns [`ChipletSelectors`] with precomputed flags for gating chiplet constraints.
pub fn build_chiplet_selectors<AB>(
    builder: &mut AB,
    local: &ChipletCols<AB::Var>,
    next: &ChipletCols<AB::Var>,
) -> ChipletSelectors<AB::Expr>
where
    AB: MidenAirBuilder,
{
    // =========================================================================
    // LOAD SELECTOR COLUMNS
    // =========================================================================

    // [s0, s1, s2, s3, s4]
    let sel = local.chiplet_selectors();
    let sel_next = next.chiplet_selectors();

    // Top-level chiplet selectors.
    let s0: AB::Expr = sel[0].into();
    let s0_next: AB::Expr = sel_next[0].into();

    let s1: AB::Expr = sel[1].into();
    let s2: AB::Expr = sel[2].into();
    let s3: AB::Expr = sel[3].into();
    let s4: AB::Expr = sel[4].into();

    let s1_next: AB::Expr = sel_next[1].into();
    let s2_next: AB::Expr = sel_next[2].into();
    let s3_next: AB::Expr = sel_next[3].into();
    let s4_next: AB::Expr = sel_next[4].into();

    // =========================================================================
    // TOP-LEVEL SELECTOR CONSTRAINTS
    // =========================================================================

    builder.assert_bool(s0.clone());

    // Once s0 becomes 1, it stays 1; controller rows form a prefix of the trace.
    {
        let builder = &mut builder.when_transition();

        // Once outside the controller region, controller rows cannot appear again.
        builder.when(s0.clone()).assert_one(s0_next.clone());
    }

    // =========================================================================
    // REMAINING CHIPLET SELECTOR CONSTRAINTS (s1..s4 under s0)
    // =========================================================================

    // Cumulative products gate each selector on its prefix being active.
    let s01 = s0.clone() * s1.clone();
    let s012 = s01.clone() * s2.clone();
    let s0123 = s012.clone() * s3.clone();

    // s1..s4 booleanity, gated by their prefix under s0.
    builder.when(s0.clone()).assert_bool(s1.clone());
    builder.when(s01.clone()).assert_bool(s2.clone());
    builder.when(s012.clone()).assert_bool(s3.clone());
    builder.when(s0123.clone()).assert_bool(s4.clone());

    // s1..s4 stability: once set to 1, they stay 1 (forbids 1 -> 0 transitions).
    // Gated by the cumulative product including the target selector, so the gate
    // is only active when the selector is already 1, permitting the 0 -> 1
    // transition at section boundaries while forbidding 1 -> 0.
    let s01234 = s0123.clone() * s4.clone();
    {
        let builder = &mut builder.when_transition();
        builder.when(s01.clone()).assert_eq(s1_next.clone(), s1.clone());
        builder.when(s012.clone()).assert_eq(s2_next.clone(), s2.clone());
        builder.when(s0123.clone()).assert_eq(s3_next.clone(), s3.clone());
        builder.when(s01234).assert_eq(s4_next, s4.clone());
    }

    // =========================================================================
    // LAST-ROW INVARIANT
    // =========================================================================
    // On the last row: s0 = s1 = s2 = s3 = s4 = 1 (padding section).
    // This ensures every chiplet's is_active flag is zero on the last row.
    // The precomputed flags also check that the next row has not advanced past the selected
    // chiplet, so chiplet-gated constraints vanish without explicit when_transition() guards.
    {
        let builder = &mut builder.when_last_row();
        builder.assert_one(s0.clone());
        builder.assert_one(s1);
        builder.assert_one(s2);
        builder.assert_one(s3);
        builder.assert_one(s4);
    }

    // =========================================================================
    // PRECOMPUTE FLAGS
    // =========================================================================

    let not_s1_next = s1_next.not();
    let not_s2_next = s2_next.not();
    let not_s3_next = s3_next.not();

    let is_transition_flag: AB::Expr = builder.is_transition();

    let not_s0 = s0.not();
    let not_s0_next = s0_next.not();

    // --- Controller flags ---
    // is_active = 1 - s0
    // is_transition = is_transition_flag * (1 - s0) * (1 - s0')
    // is_last = (1 - s0) * s0'
    let ctrl_is_active = not_s0.clone();
    let ctrl_is_transition = is_transition_flag.clone() * not_s0.clone() * not_s0_next;
    let ctrl_is_last = not_s0 * s0_next;
    let ctrl_next_is_first = AB::Expr::ZERO; // controller is first section

    // --- Non-controller active flags ---
    let is_bitwise = s0.clone() - s01.clone();
    let is_memory = s01.clone() - s012.clone();
    let is_ace = s012.clone() - s0123;

    // --- Non-controller last-row flags ---
    // A section ends when the current row is active and the next selector advances past it.
    let is_bitwise_last = is_bitwise.clone() * s1_next;
    let is_memory_last = is_memory.clone() * s2_next;
    let is_ace_last = is_ace.clone() * s3_next;

    // --- Non-controller next-is-first flags ---
    //
    // Each `next_is_first` flag marks the row that immediately precedes a chiplet section's first
    // row, and it gates that section's first-row initialization. Because any chiplet section other
    // than the controller can be empty, these flags must be derived from the section boundary
    // itself rather than from "the previous chiplet's last row". A predecessor-based definition
    // silently fails when the predecessor is empty: it has no last row, so the flag never fires and
    // the initialization is skipped. For the memory chiplet, that initialization is the "values not
    // being written must be zero" reset, and skipping it would let a malicious prover forge a read
    // of never-written memory.
    //
    // The bitwise flag is the exception that needs no boundary rewrite. Bitwise is preceded only by
    // the controller, and the controller is always non-empty because a boundary constraint pins the
    // first trace row to a controller row. (Even a hypothetical empty controller would be safe:
    // bitwise would then begin at row 0, where the periodic `k_first` column already performs the
    // reset.)
    let next_is_bitwise_first = ctrl_is_last.clone() * not_s1_next.clone();

    let s0_next_raw: AB::Expr = sel_next[0].into();
    let s1_next_raw: AB::Expr = sel_next[1].into();
    let s2_next_raw: AB::Expr = sel_next[2].into();

    // The memory section is entered from the last bitwise row (when bitwise is non-empty) or
    // from the last controller row (when bitwise is empty). `s1' = 1` with `s2' = 0` confirms
    // the next row is the first memory row; `is_bitwise` selects the last bitwise row (via that
    // same `s1'` factor) and `ctrl_is_last` selects the last controller row, covering both paths.
    let precedes_first_memory_row = is_bitwise.clone() + ctrl_is_last.clone();
    let next_is_memory_first =
        precedes_first_memory_row * s1_next_raw.clone() * not_s2_next.clone();

    // The ACE section is entered from the memory section, or from an earlier section when the
    // sections in between are empty. Instead of enumerating those cases, we detect the boundary
    // directly: the next row is the first ACE row (`s0' = s1' = s2' = 1` and `s3' = 0`) while the
    // current row has not yet reached the ACE section or beyond (`s0 * s1 * s2 = 0`).
    //
    // Direct detection is affordable here because the ACE first-row constraint gates only a single
    // column, so even this degree-7 flag stays within the AIR's degree-9 cap. The memory boundary
    // above cannot afford it: its first-row init is degree-heavy, so the degree-5 direct form would
    // overflow the cap, which is why memory uses the lower-degree two-term form instead.
    let next_row_is_ace = s0_next_raw * s1_next_raw * s2_next_raw * not_s3_next.clone();
    let current_row_before_ace = AB::Expr::ONE - s012.clone();
    let next_is_ace_first = next_row_is_ace * current_row_before_ace;

    // --- Non-controller transition flags ---
    // Each non-controller chiplet fires its transition flag when the current row is in that
    // chiplet's section (the prefix product) and the next row hasn't yet advanced
    // past that chiplet's selector. The top-level transition rule enforces
    // `s0 = 1 -> s0' = 1`, so no separate `s0'` factor is needed.
    let bitwise_transition = is_transition_flag.clone() * s0 * not_s1_next;
    let memory_transition = is_transition_flag.clone() * s01 * not_s2_next;
    let ace_transition = is_transition_flag * s012 * not_s3_next;

    ChipletSelectors {
        controller: ChipletFlags {
            is_active: ctrl_is_active,
            is_transition: ctrl_is_transition,
            is_last: ctrl_is_last,
            next_is_first: ctrl_next_is_first,
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
    }
}
