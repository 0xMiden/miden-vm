//! Per-bus emitters for the Miden VM's [`super::MidenLookupAir`].
//!
//! Splits the Miden VM's 8 LogUp buses into one file each. Each emitter is a crate-private
//! `pub(in crate::constraints::lookup) fn emit_*` that opens a single
//! [`super::super::LookupBuilder::column`] closure and describes the bus's interactions via
//! [`super::super::LookupColumn::group`] or
//! [`super::super::LookupColumn::group_with_cached_encoding`]. The emitters are routed
//! through [`super::MidenLookupAir::eval`] in the order M1..M5, C1..C3 so the column indices
//! line up with the legacy `enforce_main` / `enforce_chiplet` layout.
//!
//! ## Shared precompute contexts
//!
//! The 4 main-trace emitters (M1, M_2+5, M3, M4) share [`MainTraceContext`], which holds
//! the two-row `MainCols` window plus a single [`OpFlags`] instance built once per
//! `eval`. The 3 chiplet-trace emitters (C1, C2, C3) share [`ChipletTraceContext`], which
//! holds the same two-row window plus [`ChipletActiveFlags`] — a pure-compute snapshot of
//! the per-chiplet `is_active` expressions produced by
//! [`super::super::super::chiplets::selectors::build_chiplet_selectors`]'s active-flag
//! block. Both contexts are built at the top of [`super::MidenLookupAir::eval`] and passed
//! by reference to the matching emitters so each expensive precompute runs exactly once.
//!
//! ## Dead-code suppression
//!
//! Until Task #8 wires `ProcessorAir::eval` into `MidenLookupAir::eval`, the only live
//! consumer of these emitters is the `miden_lookup_air_degree_within_budget` test in
//! [`super::miden_air`]. The per-bus `emit_*` functions are kept discoverable from
//! [`super::MidenLookupAir::eval`] so they are reached transitively from that test even in
//! lib-only builds.

use miden_core::field::{Algebra, PrimeCharacteristicRing};

use super::LookupBuilder;
use crate::{Felt, MainCols, constraints::op_flags::OpFlags};

pub(in crate::constraints::lookup) mod block_hash_and_op_group;
pub(in crate::constraints::lookup) mod block_stack;
pub(in crate::constraints::lookup) mod chiplet_requests;
pub(in crate::constraints::lookup) mod chiplet_responses;
pub(in crate::constraints::lookup) mod hash_kernel;
pub(in crate::constraints::lookup) mod range_logcap;
pub(in crate::constraints::lookup) mod wiring;

// MAIN TRACE CONTEXT
// ================================================================================================

/// Shared context for the main-trace LogUp bus emitters (M1, M_2+5, M3, M4).
///
/// Built once at the top of [`super::MidenLookupAir::eval`] so every emitter reads the same
/// row window and the same [`OpFlags`] instance. Before this split, each of the four
/// main-trace emitters rebuilt [`OpFlags`] independently — this type collapses those into a
/// single `OpFlags::new(...)` call per `eval`.
///
/// `LB::Var` is `Copy`, so borrowing the row slices through this context carries no
/// additional cost beyond a pair of references.
pub(in crate::constraints::lookup) struct MainTraceContext<'a, LB>
where
    LB: LookupBuilder<F = Felt>,
{
    /// Typed view of the current row.
    pub local: &'a MainCols<LB::Var>,
    /// Typed view of the next row.
    pub next: &'a MainCols<LB::Var>,
    /// Operation flags computed from `(local.decoder, local.stack, next.decoder)`.
    pub op_flags: OpFlags<LB::Expr>,
}

impl<'a, LB> MainTraceContext<'a, LB>
where
    LB: LookupBuilder<F = Felt>,
{
    /// Build the shared main-trace context for one `eval` call.
    pub fn new(local: &'a MainCols<LB::Var>, next: &'a MainCols<LB::Var>) -> Self {
        let op_flags = OpFlags::<LB::Expr>::new(&local.decoder, &local.stack, &next.decoder);
        Self { local, next, op_flags }
    }
}

// CHIPLET TRACE CONTEXT
// ================================================================================================

/// Shared context for the chiplet-trace LogUp bus emitters (C1, C2, C3).
///
/// Holds the same two-row window as [`MainTraceContext`] together with a snapshot of the
/// per-chiplet `is_active` expressions. Before this split, each chiplet-trace emitter
/// rebuilt `s_ctrl`, `s_perm`, `virtual_s0 = 1 - s_ctrl - s_perm`, and the `s01/s012/
/// s0123/s01234` prefix chain manually — this type collapses those into a single
/// [`ChipletActiveFlags`] instance per `eval`. `s_ctrl` and `s_perm` now only appear
/// inside the [`ChipletActiveFlags::from_main_cols`] constructor, matching the style rule
/// that selector columns must not leak into individual chiplet constraint code.
pub(in crate::constraints::lookup) struct ChipletTraceContext<'a, LB>
where
    LB: LookupBuilder<F = Felt>,
{
    /// Typed view of the current row.
    pub local: &'a MainCols<LB::Var>,
    /// Typed view of the next row.
    pub next: &'a MainCols<LB::Var>,
    /// Per-chiplet `is_active` flags, computed from `local`'s selector columns.
    pub chiplet_active: ChipletActiveFlags<LB::Expr>,
}

impl<'a, LB> ChipletTraceContext<'a, LB>
where
    LB: LookupBuilder<F = Felt>,
{
    /// Build the shared chiplet-trace context for one `eval` call.
    pub fn new(local: &'a MainCols<LB::Var>, next: &'a MainCols<LB::Var>) -> Self {
        let chiplet_active = ChipletActiveFlags::<LB::Expr>::from_main_cols::<LB::Var>(local);
        Self { local, next, chiplet_active }
    }
}

// CHIPLET ACTIVE FLAGS
// ================================================================================================

/// Per-chiplet `is_active` expressions, mirroring the active-flag block of
/// [`build_chiplet_selectors`](super::super::super::chiplets::selectors::build_chiplet_selectors).
///
/// These are the only chiplet-flag flavors the LogUp buses consume —
/// `is_transition` / `is_last` / `next_is_first` are used only by the constraint-path
/// chiplet code, not by the LogUp argument — so this type carries no other variants.
///
/// The constructor is a pure compute function: it builds the same algebra as
/// `build_chiplet_selectors` but does NOT emit any `when` / `assert_*` calls, so it is
/// safe to run in parallel with the constraint-path chiplet selector pass.
pub(in crate::constraints::lookup) struct ChipletActiveFlags<E> {
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
    /// Build the chiplet active-flag snapshot from a `MainCols` borrow.
    ///
    /// Mirrors the active-flag block of
    /// [`build_chiplet_selectors`](super::super::super::chiplets::selectors::build_chiplet_selectors):
    /// - `s_ctrl = chiplets[0]`, `s_perm = perm_seg`
    /// - virtual `s0 = 1 - s_ctrl - s_perm`
    /// - prefix chain `s01 / s012 / s0123 / s01234`
    /// - `is_bitwise = s0 - s01`, `is_memory = s01 - s012`, `is_ace = s012 - s0123`, `is_kernel_rom
    ///   = s0123 - s01234`
    pub fn from_main_cols<V>(local: &MainCols<V>) -> Self
    where
        V: Copy,
        E: Algebra<V>,
    {
        let s_ctrl: E = local.chiplets[0].into();
        let s_perm: E = local.perm_seg.into();
        let s1: E = local.chiplets[1].into();
        let s2: E = local.chiplets[2].into();
        let s3: E = local.chiplets[3].into();
        let s4: E = local.chiplets[4].into();

        // Virtual non-hasher selector and prefix products.
        let s0 = E::ONE - s_ctrl.clone() - s_perm;
        let s01 = s0.clone() * s1;
        let s012 = s01.clone() * s2;
        let s0123 = s012.clone() * s3;
        let s01234 = s0123.clone() * s4;

        // Active flags via the subtraction trick.
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
