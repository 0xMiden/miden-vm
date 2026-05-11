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
/// (linear-hash init, RESPAN, MR-update legs, HOUT, SOUT). Both callers (the legacy
/// [`ChipletLookupAir`] aggregator and the standalone `ChipletsAir`) source it from the
/// chiplet-trace `chip_clk` column.
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
    /// Hasher response address, sourced from the chiplet-trace `chip_clk` column.
    pub clk_plus_one: LB::Expr,
}

impl<'a, LB> ChipletBusContext<'a, LB>
where
    LB: ChipletLookupBuilder,
{
    /// Build the shared chiplet-trace context for one `eval` call.
    ///
    /// Takes per-row `&ChipletCols` views and an externally-supplied `clk_plus_one` value
    /// (the chiplet-trace `chip_clk` column).
    pub fn new(
        builder: &LB,
        local: &'a ChipletCols<LB::Var>,
        next: &'a ChipletCols<LB::Var>,
        clk_plus_one: LB::Expr,
    ) -> Self {
        let chiplet_active = builder.build_chiplet_active(local);
        Self {
            local,
            next,
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
        // Borrow the row buffer as `MainCols` (legacy 72-col aggregator path) and bridge to
        // `ChipletCols`. Source the responder address from the chiplet-side `chip_clk`
        // column — no cross-trace dependency.
        let main = builder.main();
        let local_main: &MainCols<_> = main.current_slice().borrow();
        let next_main: &MainCols<_> = main.next_slice().borrow();
        let local_chiplet = local_main.as_chiplet_cols();
        let next_chiplet = next_main.as_chiplet_cols();

        let clk_plus_one: LB::Expr = local_chiplet.chip_clk.into();

        emit_chiplet_lookup_columns(builder, local_chiplet, next_chiplet, clk_plus_one);
    }
}

/// Emit the three chiplet-trace LogUp columns (responses, hash-kernel virtual table,
/// wiring) using a caller-supplied responder address.
///
/// Shared between [`ChipletLookupAir`]'s [`LookupAir`] impl and `ChipletsAir`'s
/// [`LookupAir`] impl. Both source `clk_plus_one` from the chiplet-trace `chip_clk` column;
/// centralizing the three-emitter sequence keeps the two AIR types in lockstep.
pub(crate) fn emit_chiplet_lookup_columns<LB: ChipletLookupBuilder>(
    builder: &mut LB,
    local: &ChipletCols<LB::Var>,
    next: &ChipletCols<LB::Var>,
    clk_plus_one: LB::Expr,
) {
    let ctx = ChipletBusContext::new(&*builder, local, next, clk_plus_one);
    emit_chiplet_responses::<LB>(builder, &ctx);
    emit_hash_kernel_table::<LB>(builder, &ctx);
    emit_v_wiring::<LB>(builder, &ctx);
}
