//! Per-bus emitters for the Miden VM's LogUp argument.
//!
//! The Miden VM's LogUp buses are emitted per AIR: 4 columns for Core, 3 for Chiplets, and 1 for
//! Poseidon2Permutation. Most columns host a single bus, but several host two or more
//! linearly-independent buses sharing one running accumulator via distinct `bus_prefix[bus]`
//! additive bases (see per-bus module docs for the merges).
//! Each emitter is a crate-private `pub(in crate::constraints::lookup) fn emit_*` that
//! opens a single [`super::LookupBuilder::column`] closure and describes the bus's
//! interactions via [`super::LookupColumn::group`] or
//! [`super::LookupColumn::group_with_cached_encoding`].
//!
//! The emitters are routed per-AIR:
//! - [`super::main_air::MainLookupAir`] for the main-trace columns, driven by [`crate::CoreAir`]'s
//!   `LookupAir` impl.
//! - [`super::chiplet_air::emit_chiplet_lookup_columns`] for the chiplet-trace columns, driven by
//!   [`crate::ChipletsAir`]'s `LookupAir` impl.
//! - [`super::poseidon2_permutation_air::emit_poseidon2_permutation_lookup_columns`] for the
//!   Poseidon2-permutation trace column, driven by [`crate::Poseidon2PermutationAir`]'s
//!   `LookupAir` impl.
//!
//! ## Shared precompute contexts
//!
//! The main-trace and chiplet-trace contexts live next to their respective LookupAirs:
//! - [`super::main_air::MainBusContext`] — two-row window plus the shared
//!   [`crate::constraints::op_flags::OpFlags`] instance consumed by the 4 main-trace emitters.
//! - [`super::chiplet_air::ChipletBusContext`] — two-row window plus the shared
//!   [`ChipletActiveFlags`] snapshot consumed by the 3 chiplet-trace emitters.
//!
//! Each context is built once per `eval` through an extension-trait hook
//! ([`super::main_air::MainLookupBuilder::build_op_flags`] /
//! [`super::chiplet_air::ChipletLookupBuilder::build_chiplet_active`]). Prover-side
//! implementations can override those hooks with boolean fast paths without changing
//! emitter code. [`ChipletActiveFlags`] lives in this module because it is the pure
//! helper used by the default chiplet hook and by optimized implementations.

use miden_core::field::{Algebra, PrimeCharacteristicRing};

use crate::ChipletCols;

pub(in crate::constraints::lookup) mod block_hash_and_op_group;
pub(in crate::constraints::lookup) mod block_stack_and_range_logcap;
pub(in crate::constraints::lookup) mod chiplet_requests;
pub(in crate::constraints::lookup) mod chiplet_responses;
pub(in crate::constraints::lookup) mod hash_kernel;
pub(in crate::constraints::lookup) mod lookup_op_flags;
pub(in crate::constraints::lookup) mod stack_overflow;
pub(in crate::constraints::lookup) mod wiring;

pub(in crate::constraints::lookup) use lookup_op_flags::LookupOpFlags;

// CHIPLET ACTIVE FLAGS
// ================================================================================================

/// Per-chiplet `is_active` expressions, mirroring the active-flag block of
/// [`build_chiplet_selectors`](super::super::chiplets::selectors::build_chiplet_selectors).
///
/// These are the only chiplet-flag flavors the LogUp buses consume —
/// `is_transition` / `is_last` / `next_is_first` are used only by the constraint-path
/// chiplet code, not by the LogUp argument — so this type carries no other variants.
///
/// The constructor is a pure compute function: it builds the same algebra as
/// `build_chiplet_selectors` but does NOT emit any `when` / `assert_*` calls, so it is
/// safe to run in parallel with the constraint-path chiplet selector pass.
pub(crate) struct ChipletActiveFlags<E> {
    /// `is_active` for the hasher controller sub-chiplet (= `s_ctrl`).
    pub controller: E,
    /// `is_active` for the bitwise chiplet (= `s0 - s01`).
    pub bitwise: E,
    /// `is_active` for the memory chiplet (= `s01 - s012`).
    pub memory: E,
    /// `is_active` for the ACE chiplet (= `s012 - s0123`).
    pub ace: E,
    /// `is_active` for the kernel ROM chiplet (= `s0123 - s01234`).
    pub kernel_rom: E,
}

impl<E> ChipletActiveFlags<E>
where
    E: PrimeCharacteristicRing + Clone,
{
    /// Build the chiplet active-flag snapshot from a `ChipletCols` borrow.
    ///
    /// Mirrors the active-flag block of
    /// [`build_chiplet_selectors`](super::super::chiplets::selectors::build_chiplet_selectors):
    /// - `s_ctrl = chiplets[0]`
    /// - virtual `s0 = 1 - s_ctrl`
    /// - prefix chain `s01 / s012 / s0123 / s01234`
    /// - `is_bitwise = s0 - s01`, `is_memory = s01 - s012`, `is_ace = s012 - s0123`, `is_kernel_rom
    ///   = s0123 - s01234`
    pub fn from_chiplet_cols<V>(local: &ChipletCols<V>) -> Self
    where
        V: Copy,
        E: Algebra<V>,
    {
        let s_ctrl: E = local.chiplets[0].into();
        let s1: E = local.chiplets[1].into();
        let s2: E = local.chiplets[2].into();
        let s3: E = local.chiplets[3].into();
        let s4: E = local.chiplets[4].into();

        // Virtual non-controller selector and prefix products.
        let s0 = E::ONE - s_ctrl.clone();
        let s01 = s0.clone() * s1;
        let s012 = s01.clone() * s2;
        let s0123 = s012.clone() * s3;
        let s01234 = s0123.clone() * s4;

        // Active flags are prefix * (1 - section_selector).
        let bitwise = s0 - s01.clone();
        let memory = s01 - s012.clone();
        let ace = s012 - s0123.clone();
        let kernel_rom = s0123 - s01234;

        Self {
            controller: s_ctrl,
            bitwise,
            memory,
            ace,
            kernel_rom,
        }
    }
}
