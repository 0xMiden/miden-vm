//! Chiplet-trace LogUp lookup AIR.
//!
//! Owns the chiplet-trace side of the Miden VM's LogUp argument: three permutation
//! columns, one per `emit_*` function in [`super::buses`]. This module wires them together
//! via a single [`ChipletBusContext`] that carries the two-row window plus a shared
//! [`ChipletActiveFlags`] snapshot.
//!
//! Columns (in emission order):
//! - chiplet responses (memory / bitwise / hasher replies).
//! - hash-kernel virtual table.
//! - shared wiring column: ACE wiring + hasher perm-link (the legacy `v_wiring`).
//!
//! The [`ChipletLookupBuilder`] extension trait mirrors [`super::main_air::MainLookupBuilder`]:
//! it exposes a single construction hook so the prover path can eventually skip the dead
//! polynomial products in [`ChipletActiveFlags::from_main_cols`]. For now the default body
//! is the polynomial path and every adapter picks it up via an empty `impl` block.

use core::borrow::Borrow;

use miden_crypto::stark::air::WindowAccess;

use super::{
    BusId,
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
/// Zero-sized. Emits three permutation columns (see module docs for per-column contents),
/// matching the aggregated `LookupAir` impl on [`crate::ProcessorAir`]. The main-trace half
/// of the argument lives in [`super::main_air::MainLookupAir`].
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct ChipletLookupAir;

/// Per-column fraction stride, in emission order (see [`ChipletLookupAir`] docs).
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
        CHIPLET_COLUMN_SHAPE.len()
    }

    fn column_shape(&self) -> &[usize] {
        &CHIPLET_COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        // Must match `ProcessorAir::max_message_width` since this sub-AIR shares the
        // aggregator's bus-prefix table. The widest chiplet-trace payload is
        // `HasherMsg::State` on the responses column at 15 slots, but the aggregator's
        // `MIDEN_MAX_MESSAGE_WIDTH = 16` is kept for MASM transcript alignment.
        super::messages::MIDEN_MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        // Chiplet-trace emitters touch the shared chiplet responses column plus
        // `BusId::{SiblingTable, RangeCheck, AceWiring, HasherPermLinkInput,
        // HasherPermLinkOutput}`. The adapter's bus-prefix table is shared
        // across every LookupAir it runs, so returning `BusId::COUNT` (the total bus-type
        // count) is the safe upper bound.
        BusId::COUNT
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
