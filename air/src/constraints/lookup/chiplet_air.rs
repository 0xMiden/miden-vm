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
//! - shared wiring column: ACE wiring + hasher perm-link.
//!
//! The [`ChipletLookupBuilder`] extension trait mirrors [`super::main_air::MainLookupBuilder`]:
//! it exposes a single construction hook so the prover path can eventually skip the dead
//! polynomial products in [`ChipletActiveFlags::from_chiplet_cols`]. For now the default
//! body is the polynomial path and every adapter picks it up via an empty `impl` block.

use core::borrow::Borrow;

use miden_core::field::PrimeCharacteristicRing;
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
    ChipletCols, Felt, MainCols,
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
    /// Default body calls [`ChipletActiveFlags::from_chiplet_cols`] against the multi-AIR
    /// `ChipletCols` view. Adapters override this when a cheaper construction path is
    /// available (e.g. the prover path, where the selector columns are concrete 0/1 and the
    /// active-flag subtractions can short-circuit).
    fn build_chiplet_active(
        &self,
        local: &ChipletCols<Self::Var>,
    ) -> ChipletActiveFlags<Self::Expr> {
        ChipletActiveFlags::from_chiplet_cols(local)
    }
}

// CHIPLET BUS CONTEXT
// ================================================================================================

/// Shared context for the three chiplet-trace bus emitters.
///
/// Holds the two-row window plus a single [`ChipletActiveFlags`] snapshot built once per
/// `eval` through [`ChipletLookupBuilder::build_chiplet_active`]. Every emitter reads
/// `ctx.local`, `ctx.next`, `ctx.chiplet_active.*`, and `ctx.clk_plus_one` directly — field
/// access, no method indirection.
///
/// `clk_plus_one` is the chiplet-side response address used by every hasher response variant
/// (linear-hash init, RESPAN, MR-update legs, HOUT, SOUT). Today it is derived from
/// `local.system.clk + 1` at construction time — the only cross-trace read in the chiplet
/// half of the LogUp argument, concentrated here so a future migration to a chiplet-side
/// row counter only changes one line (see `MULTI_AIR_TODO.md` M1.5).
pub(crate) struct ChipletBusContext<'a, LB>
where
    LB: LookupBuilder<F = Felt>,
{
    /// Typed view of the current row (Chiplets half of the trace).
    pub local: &'a ChipletCols<LB::Var>,
    /// Typed view of the next row (Chiplets half of the trace).
    pub next: &'a ChipletCols<LB::Var>,
    /// Per-chiplet `is_active` flags, computed from `local`'s selector columns via the
    /// builder-provided hook.
    pub chiplet_active: ChipletActiveFlags<LB::Expr>,
    /// Hasher response address: `local.system.clk + 1`. Sourced from the Core trace for
    /// now via the constructor's `MainCols` parameter; this is the last cross-trace read in
    /// the chiplet half and will be replaced by a chiplet-side row counter once the
    /// multi-AIR addressing scheme is finalized (see `MULTI_AIR_TODO.md` M1.5).
    pub clk_plus_one: LB::Expr,
}

impl<'a, LB> ChipletBusContext<'a, LB>
where
    LB: ChipletLookupBuilder,
{
    /// Build the shared chiplet-trace context for one `eval` call.
    ///
    /// Takes a `&MainCols` because the responder address is currently derived from
    /// `local.system.clk + 1` (a Core-trace column). Bridges through
    /// [`MainCols::as_chiplet_cols`] for the per-row chiplet view so emitters operate on the
    /// multi-AIR `ChipletCols` type.
    pub fn new(builder: &LB, local: &'a MainCols<LB::Var>, next: &'a MainCols<LB::Var>) -> Self {
        let local_chiplet = local.as_chiplet_cols();
        let next_chiplet = next.as_chiplet_cols();
        let chiplet_active = builder.build_chiplet_active(local_chiplet);
        let clk_plus_one: LB::Expr = local.system.clk.into() + LB::Expr::ONE;
        Self {
            local: local_chiplet,
            next: next_chiplet,
            chiplet_active,
            clk_plus_one,
        }
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
