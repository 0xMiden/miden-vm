//! Chiplet selector system constraints and precomputed flags.
//!
//! This module implements the chiplet selector system that determines which chiplet is
//! active at any given row, and provides precomputed flags for gating chiplet-specific
//! constraints.
//!
//! [`ChipletCols`] exposes typed row overlays, [`ChipletSelectors`] names the gates used by main
//! constraints, and [`ChipletActiveFlags`] decodes single-row membership for lookup buses and
//! native trace readers. The packed selector encoding is owned by this module.
//!
//! ## Packed Encoding
//!
//! Read the selector prefix from column zero. After the prefix, each section can use the
//! remaining columns for its payload. The trace producer writes the prefixes in this order.
//!
//! | Section     | Prefix  |
//! |-------------|---------|
//! | Controller  | `0`     |
//! | AEAD stream | `100`   |
//! | Bitwise     | `101`   |
//! | Memory      | `110`   |
//! | ACE         | `1110`  |
//! | Kernel ROM  | `11110` |
//! | Padding     | `11111` |
//!
//! A leading run of ones can only grow as the trace advances. This leaves the third bit free
//! under the `10` prefix, where the AIR permits switching between AEAD and bitwise at complete
//! AEAD cycle boundaries.
//!
//! The final row has prefix `11111`, so every chiplet's current-row activity is zero
//! on the last row. Gates that include current-row activity therefore vanish there. Next-row
//! activity is raw membership and can be nonzero on the cyclic last-to-first opening.

use miden_core::field::{Algebra, PrimeCharacteristicRing};
use miden_stark::air::AirBuilder;

use crate::vm::{ChipletCols, Felt, MidenAirBuilder, constraints::utils::BoolNot};

// CHIPLET FLAGS
// ================================================================================================

/// Precomputed flags for chiplets with main-trace constraints.
///
/// Kernel ROM is enforced through lookup-bus constraints, so its active flag lives in
/// [`ChipletActiveFlags`] instead.
#[derive(Clone)]
pub struct ChipletSelectors<E> {
    /// 1 on controller rows.
    pub controller_active: E,
    /// 1 when the next row belongs to the controller, without a transition gate.
    pub controller_next_active: E,
    /// Controller-to-controller transitions, including the trace transition selector.
    pub controller_transition: E,
    /// 1 on AEAD stream rows.
    pub aead_stream_active: E,
    /// 1 when the next row belongs to AEAD, without a transition gate.
    pub aead_stream_next_active: E,
    /// 1 on bitwise AND/XOR rows.
    pub bitwise_active: E,
    /// 1 on memory rows.
    pub memory_active: E,
    /// Memory-to-memory transitions, including the trace transition selector.
    pub memory_transition: E,
    /// 1 when the next row starts memory, including when preceding sections are empty.
    /// Evaluated on the row immediately before the memory section.
    pub memory_entry_next: E,
    /// 1 on ACE rows.
    pub ace_active: E,
    /// ACE-to-ACE transitions, including the trace transition selector.
    pub ace_transition: E,
    /// 1 when the current row ends the ACE section.
    pub ace_last: E,
    /// 1 when the next row starts ACE, including when preceding sections are empty.
    /// Evaluated on the row immediately before the ACE section.
    pub ace_entry_next: E,
}

// SINGLE-ROW CHIPLET ACTIVITY
// ================================================================================================

/// Semantic chiplet membership for a single row.
///
/// Main constraints and lookup buses share the polynomial decoder. Native trace readers use
/// exact selector-value comparisons through [`Self::from_trace_row`]. Main constraints also
/// use transition, exit, and section-entry gates from their two-row selector context.
///
/// Both constructors are pure: neither emits selector constraints.
pub struct ChipletActiveFlags<E> {
    /// Controller rows.
    pub controller: E,
    /// AEAD stream rows.
    pub aead_stream: E,
    /// Bitwise AND/XOR rows.
    pub bitwise: E,
    /// Memory rows.
    pub memory: E,
    /// ACE rows.
    pub ace: E,
    /// Kernel ROM rows.
    pub kernel_rom: E,
}

impl<E> ChipletActiveFlags<E>
where
    E: PrimeCharacteristicRing + Clone,
{
    /// Builds the polynomial chiplet membership expressions from a typed shared row.
    pub fn from_chiplet_cols<V>(local: &ChipletCols<V>) -> Self
    where
        V: Copy,
        E: Algebra<V>,
    {
        let s0: E = local.chiplets[0].into();
        let s1: E = local.chiplets[1].into();
        let s2: E = local.chiplets[2].into();
        let s3: E = local.chiplets[3].into();
        let s4: E = local.chiplets[4].into();

        let s01 = s0.clone() * s1;
        let s012 = s01.clone() * s2.clone();
        let s0123 = s012.clone() * s3;
        let s01234 = s0123.clone() * s4;

        // For prefix p and selector s, the 0 branch is p - p * s and the 1 branch is p * s.
        let bitwise_region = s0.clone() - s01.clone();
        let bitwise = bitwise_region.clone() * s2;

        Self {
            controller: E::ONE - s0,
            aead_stream: bitwise_region - bitwise.clone(),
            bitwise,
            memory: s01 - s012.clone(),
            ace: s012 - s0123.clone(),
            kernel_rom: s0123 - s01234,
        }
    }
}

impl ChipletActiveFlags<bool> {
    /// Classifies a native trace row using exact selector-prefix comparisons.
    pub fn from_trace_row(local: &ChipletCols<Felt>) -> Self {
        let s0 = local.chiplets[0];
        let s1 = local.chiplets[1];
        let s2 = local.chiplets[2];
        let s3 = local.chiplets[3];
        let s4 = local.chiplets[4];

        let non_controller = s0 == Felt::ONE;
        let bitwise_region = non_controller && s1 == Felt::ZERO;
        let memory_prefix = non_controller && s1 == Felt::ONE;
        let ace_prefix = memory_prefix && s2 == Felt::ONE;

        Self {
            controller: s0 == Felt::ZERO,
            aead_stream: bitwise_region && s2 == Felt::ZERO,
            bitwise: bitwise_region && s2 == Felt::ONE,
            memory: memory_prefix && s2 == Felt::ZERO,
            ace: ace_prefix && s3 == Felt::ZERO,
            kernel_rom: ace_prefix && s3 == Felt::ONE && s4 == Felt::ZERO,
        }
    }
}

// ENTRY POINT
// ================================================================================================

/// Enforces the selector prefixes and section order and builds the chiplet gates.
pub fn build_chiplet_selectors<AB>(
    builder: &mut AB,
    local: &ChipletCols<AB::Var>,
    next: &ChipletCols<AB::Var>,
) -> ChipletSelectors<AB::Expr>
where
    AB: MidenAirBuilder,
{
    let s0: AB::Expr = local.chiplets[0].into();
    let s1: AB::Expr = local.chiplets[1].into();
    let s2: AB::Expr = local.chiplets[2].into();
    let s3: AB::Expr = local.chiplets[3].into();
    let s4: AB::Expr = local.chiplets[4].into();

    let s0_next: AB::Expr = next.chiplets[0].into();
    let s1_next: AB::Expr = next.chiplets[1].into();
    let s2_next: AB::Expr = next.chiplets[2].into();
    let s3_next: AB::Expr = next.chiplets[3].into();
    let s4_next: AB::Expr = next.chiplets[4].into();

    let s01 = s0.clone() * s1.clone();
    let s012 = s01.clone() * s2.clone();
    let s0123 = s012.clone() * s3.clone();
    let s01234 = s0123.clone() * s4.clone();

    // A column is binary whenever it is part of the row's selector prefix.
    builder.assert_bool(s0.clone());
    builder.when(s0.clone()).assert_bools([s1.clone(), s2.clone()]);
    builder.when(s012.clone()).assert_bool(s3.clone());
    builder.when(s0123.clone()).assert_bool(s4.clone());

    // Once the trace reaches an all-ones prefix, subsequent rows retain it. This leaves s2
    // free to distinguish AEAD and bitwise under `10`.
    {
        let builder = &mut builder.when_transition();
        builder.when(s0.clone()).assert_one(s0_next.clone());
        builder.when(s01.clone()).assert_one(s1_next.clone());
        builder.when(s012.clone()).assert_one(s2_next.clone());
        builder.when(s0123).assert_one(s3_next.clone());
        builder.when(s01234).assert_one(s4_next);
    }

    // Padding on the last row makes all current-row chiplet activity vanish.
    {
        let builder = &mut builder.when_last_row();
        builder.assert_one(s0.clone());
        builder.assert_one(s1);
        builder.assert_one(s2);
        builder.assert_one(s3);
        builder.assert_one(s4);
    }

    let not_s2_next = s2_next.not();
    let not_s3_next = s3_next.not();

    let is_transition_flag: AB::Expr = builder.is_transition();
    let active = ChipletActiveFlags::<AB::Expr>::from_chiplet_cols(local);
    let controller_next_active = s0_next.not();
    let controller_transition =
        is_transition_flag.clone() * active.controller.clone() * controller_next_active.clone();
    let controller_last = active.controller.clone() * s0_next.clone();
    let aead_stream_next_active = s0_next.clone() * s1_next.not() * not_s2_next.clone();

    // Entry gates cover skipped sections. Memory initialization must still zero values that
    // have never been written when the trace goes directly from controller to memory.
    // Both predecessors already imply s0' = 1, so the entry gate can omit that factor and stay
    // within the degree budget.
    let bitwise_region_active = s0 - s01.clone();
    let precedes_first_memory_row = bitwise_region_active + controller_last;
    let memory_entry_next = precedes_first_memory_row * s1_next.clone() * not_s2_next.clone();

    // ACE initialization is linear, so it can use a degree-7 gate that directly detects the
    // boundary. The next row is ACE while the current row is before the `111` prefix.
    let next_row_is_ace = s0_next * s1_next * s2_next * not_s3_next.clone();
    let current_row_before_ace = AB::Expr::ONE - s012.clone();
    let ace_entry_next = next_row_is_ace * current_row_before_ace;

    // A stable prefix and a zero in the next split bit imply both rows are in the same section.
    let memory_transition = is_transition_flag.clone() * s01 * not_s2_next;
    let ace_transition = is_transition_flag * s012 * not_s3_next;
    let ace_last = active.ace.clone() * s3_next;

    ChipletSelectors {
        controller_active: active.controller,
        controller_next_active,
        controller_transition,
        aead_stream_active: active.aead_stream,
        aead_stream_next_active,
        bitwise_active: active.bitwise,
        memory_active: active.memory,
        memory_transition,
        memory_entry_next,
        ace_active: active.ace,
        ace_transition,
        ace_last,
        ace_entry_next,
    }
}
