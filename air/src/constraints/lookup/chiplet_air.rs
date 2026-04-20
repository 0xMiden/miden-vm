//! Chiplet-trace LogUp lookup AIR.
//!
//! Owns the chiplet-trace side of the Miden VM's LogUp argument: the three permutation
//! columns C1, C2, C3. Each column is described by one of the `emit_*` functions in
//! [`super::buses`]; this module wires them together via a single [`ChipletBusContext`]
//! that carries the two-row window plus a shared [`ChipletActiveFlags`] snapshot.
//!
//! The [`ChipletLookupBuilder`] extension trait mirrors [`super::main_air::MainLookupBuilder`]:
//! it exposes a single construction hook so the prover path can eventually skip the dead
//! polynomial products in [`ChipletActiveFlags::from_main_cols`]. For now the default body
//! is the polynomial path and every adapter picks it up via an empty `impl` block.

use core::borrow::Borrow;

use miden_crypto::stark::air::WindowAccess;

use super::{
    bus_id::NUM_BUS_IDS,
    buses::{
        ChipletActiveFlags,
        chiplet_responses::{self, emit_chiplet_responses},
        hash_kernel::{self, emit_hash_kernel_table},
        wiring::{self, emit_v_wiring},
    },
};
use crate::{
    Felt, MainCols,
    lookup::{LookupAir, LookupBuilder},
};

// CHIPLET LOOKUP BUILDER
// ================================================================================================

/// Extension trait the chiplet-trace [`LookupAir`] requires from its [`LookupBuilder`].
///
/// Carries a single hook, [`build_chiplet_active`](Self::build_chiplet_active), for
/// constructing the shared [`ChipletActiveFlags`] snapshot consumed by the three
/// chiplet-trace bus emitters. Symmetric to [`super::main_air::MainLookupBuilder`]; see its
/// docs for the rationale behind the explicit-impl-no-blanket pattern.
pub(crate) trait ChipletLookupBuilder: LookupBuilder<F = Felt> {
    /// Build the shared [`ChipletActiveFlags`] snapshot for one `eval` call.
    ///
    /// Default body calls [`ChipletActiveFlags::from_main_cols`], matching the pre-split
    /// behavior of `ChipletTraceContext::new`. Adapters override this when a cheaper
    /// construction path is available (e.g. the prover path, where the selector columns
    /// are concrete 0/1 and the active-flag subtractions can short-circuit).
    fn build_chiplet_active(&self, local: &MainCols<Self::Var>) -> ChipletActiveFlags<Self::Expr> {
        ChipletActiveFlags::from_main_cols(local)
    }
}

// CHIPLET BUS CONTEXT
// ================================================================================================

/// Shared context for the three chiplet-trace bus emitters.
///
/// Holds the two-row window plus a single [`ChipletActiveFlags`] snapshot built once per
/// `eval` through [`ChipletLookupBuilder::build_chiplet_active`]. Every emitter reads
/// `ctx.local`, `ctx.next`, and
/// `ctx.chiplet_active.{controller,permutation,bitwise,memory,ace,kernel_rom}` directly —
/// field access, no method indirection.
pub(crate) struct ChipletBusContext<'a, LB>
where
    LB: LookupBuilder<F = Felt>,
{
    /// Typed view of the current row.
    pub local: &'a MainCols<LB::Var>,
    /// Typed view of the next row.
    pub next: &'a MainCols<LB::Var>,
    /// Per-chiplet `is_active` flags, computed from `local`'s selector columns via the
    /// builder-provided hook.
    pub chiplet_active: ChipletActiveFlags<LB::Expr>,
}

impl<'a, LB> ChipletBusContext<'a, LB>
where
    LB: ChipletLookupBuilder,
{
    /// Build the shared chiplet-trace context for one `eval` call.
    pub fn new(builder: &LB, local: &'a MainCols<LB::Var>, next: &'a MainCols<LB::Var>) -> Self {
        let chiplet_active = builder.build_chiplet_active(local);
        Self { local, next, chiplet_active }
    }
}

// CHIPLET LOOKUP AIR
// ================================================================================================

/// LogUp lookup argument over the chiplet trace.
///
/// Zero-sized. Emits three permutation columns in the order C1, C2, C3 — matching the
/// layout the legacy `enforce_chiplet` held and the aggregator
/// [`super::miden_air::MidenLookupAir`] still holds. The main-trace half of the argument
/// lives in [`super::main_air::MainLookupAir`].
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct ChipletLookupAir;

/// Per-column fraction stride: [C1, C2, C3].
pub(crate) const CHIPLET_COLUMN_SHAPE: [usize; 3] = [
    chiplet_responses::MAX_INTERACTIONS_PER_ROW,
    hash_kernel::MAX_INTERACTIONS_PER_ROW,
    wiring::MAX_INTERACTIONS_PER_ROW,
];

impl<LB> LookupAir<LB> for ChipletLookupAir
where
    LB: ChipletLookupBuilder,
{
    fn num_columns(&self) -> usize {
        // C1 (chiplet responses), C2 (hash-kernel virtual table),
        // C3 (`v_wiring`: ACE wiring + hasher perm-link).
        3
    }

    fn column_shape(&self) -> &[usize] {
        &CHIPLET_COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        // `HasherMsg::State` on the C1 chiplet-responses column carries the widest payload:
        // label@β⁰, addr@β¹, node_index@β², state[0..12]@β³..β¹⁴ — 15 slots total. Matches
        // the aggregator's `MidenLookupAir::max_message_width`.
        15
    }

    fn num_bus_ids(&self) -> usize {
        // Chiplet-trace emitters touch BUS_CHIPLETS, BUS_SIBLING_TABLE, BUS_RANGE_CHECK,
        // BUS_ACE_WIRING, and BUS_HASHER_PERM_LINK. The adapter's bus-prefix table is shared
        // across every LookupAir it runs, so returning `NUM_BUS_IDS` (the total bus-type
        // count) is the safe upper bound.
        NUM_BUS_IDS
    }

    fn eval(&self, builder: &mut LB) {
        let main = builder.main();
        let local: &MainCols<_> = main.current_slice().borrow();
        let next: &MainCols<_> = main.next_slice().borrow();

        let ctx = ChipletBusContext::new(&*builder, local, next);

        emit_chiplet_responses::<LB>(builder, &ctx);
        emit_hash_kernel_table::<LB>(builder, &ctx);
        emit_v_wiring::<LB>(builder, &ctx);
    }
}
