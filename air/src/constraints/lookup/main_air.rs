//! Main-trace LogUp lookup AIR.
//!
//! Owns the main-trace side of the Miden VM's LogUp argument: four permutation columns, one
//! per `emit_*` function in [`super::buses`]. This module wires them together via a single
//! [`MainBusContext`] that carries the two-row window plus a shared [`OpFlags`] instance.
//!
//! Columns (in emission order):
//! - block-stack table + u32 range checks + log-precompile capacity + range-table response (merged
//!   — see [`super::buses::block_stack_and_range_logcap`]).
//! - block-hash queue + op-group table.
//! - chiplet requests from the decoder.
//! - stack overflow table.
//!
//! The [`MainLookupBuilder`] extension trait exists so the `OpFlags` construction can diverge
//! between the constraint path (polynomial, today's default) and the prover path (boolean
//! fast path, planned). For now every adapter picks up the default polynomial body via an
//! empty `impl MainLookupBuilder for …` block — the structural split is the sole purpose of
//! this module today.

use core::borrow::Borrow;

use miden_crypto::stark::air::WindowAccess;

use super::{
    BusId,
    buses::{
        LookupOpFlags,
        block_hash_and_op_group::{self, emit_block_hash_and_op_group},
        block_stack_and_range_logcap::{self, emit_block_stack_and_range_logcap},
        chiplet_requests::{self, emit_chiplet_requests},
        stack_overflow::{self, emit_stack_overflow},
    },
};
use crate::{
    Felt, MainCols,
    lookup::{LookupAir, LookupBuilder},
};

// MAIN LOOKUP BUILDER
// ================================================================================================

/// Extension trait the main-trace [`LookupAir`] requires from its [`LookupBuilder`].
///
/// Carries a single hook, [`build_op_flags`](Self::build_op_flags), for constructing the
/// shared [`LookupOpFlags`] instance that the four main-trace bus emitters consume. The
/// default body uses the polynomial path (today's behavior for both the constraint-path and
/// the prover-path adapters). A future prover-side optimization will override this method on
/// the prover adapter to skip the dead polynomial products that come from decoder bits
/// already being concrete 0/1 values; no other code moves.
///
/// There is intentionally **no** blanket `impl<LB: LookupBuilder> MainLookupBuilder for LB`
/// — Rust coherence would then forbid the prover adapter from overriding the default body.
/// Each adapter implements this trait explicitly with an empty `impl` block that picks up
/// the default.
pub(crate) trait MainLookupBuilder: LookupBuilder<F = Felt> {
    /// Build the shared [`LookupOpFlags`] instance for one `eval` call.
    ///
    /// Default body calls [`LookupOpFlags::from_main_cols`], the polynomial path. Adapters
    /// override this when a cheaper construction path is available (e.g. the prover path,
    /// where decoder bits are concrete 0/1).
    fn build_op_flags(
        &self,
        local: &MainCols<Self::Var>,
        next: &MainCols<Self::Var>,
    ) -> LookupOpFlags<Self::Expr> {
        LookupOpFlags::from_main_cols(&local.decoder, &local.stack, &next.decoder)
    }
}

// MAIN BUS CONTEXT
// ================================================================================================

/// Shared context for the four main-trace bus emitters.
///
/// Holds the two-row window plus a single [`LookupOpFlags`] instance built once per `eval`
/// through [`MainLookupBuilder::build_op_flags`]. Every emitter reads `ctx.local`,
/// `ctx.next`, and `ctx.op_flags.<accessor>()` directly — no method indirection beyond the
/// single clone each accessor performs.
pub(crate) struct MainBusContext<'a, LB>
where
    LB: LookupBuilder<F = Felt>,
{
    /// Typed view of the current row.
    pub local: &'a MainCols<LB::Var>,
    /// Typed view of the next row.
    pub next: &'a MainCols<LB::Var>,
    /// Operation flags computed from `(local.decoder, local.stack, next.decoder)` via the
    /// builder-provided hook.
    pub op_flags: LookupOpFlags<LB::Expr>,
}

impl<'a, LB> MainBusContext<'a, LB>
where
    LB: MainLookupBuilder,
{
    /// Build the shared main-trace context for one `eval` call.
    ///
    /// Delegates the `LookupOpFlags` construction to the builder's
    /// [`MainLookupBuilder::build_op_flags`] hook so the constraint-path and prover-path
    /// adapters can diverge on construction cost without the emitters noticing.
    pub fn new(builder: &LB, local: &'a MainCols<LB::Var>, next: &'a MainCols<LB::Var>) -> Self {
        let op_flags = builder.build_op_flags(local, next);
        Self { local, next, op_flags }
    }
}

// MAIN LOOKUP AIR
// ================================================================================================

/// LogUp lookup argument over the main trace.
///
/// Zero-sized. Emits four permutation columns: the first packs block-stack + u32 range
/// checks + log-precompile capacity + range-table response; the second unions block-hash
/// queue and op-group table; the third hosts the decoder's chiplet requests; the fourth
/// hosts the stack overflow table. The chiplet-trace half of the argument lives in
/// [`super::chiplet_air::ChipletLookupAir`].
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct MainLookupAir;

/// Per-column fraction stride, in emission order (see [`MainLookupAir`] docs).
pub(crate) const MAIN_COLUMN_SHAPE: [usize; 4] = [
    block_stack_and_range_logcap::MAX_INTERACTIONS_PER_ROW,
    block_hash_and_op_group::MAX_INTERACTIONS_PER_ROW,
    chiplet_requests::MAX_INTERACTIONS_PER_ROW,
    stack_overflow::MAX_INTERACTIONS_PER_ROW,
];

impl<LB> LookupAir<LB> for MainLookupAir
where
    LB: MainLookupBuilder,
{
    fn num_columns(&self) -> usize {
        MAIN_COLUMN_SHAPE.len()
    }

    fn column_shape(&self) -> &[usize] {
        &MAIN_COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        // Must match `ProcessorAir::max_message_width` since this sub-AIR shares the
        // aggregator's bus-prefix table. The widest main-trace payload is
        // `HasherMsg::State` (linear_hash_init / return_state) at 15 slots, but the
        // aggregator's `MIDEN_MAX_MESSAGE_WIDTH = 16` is kept for MASM transcript alignment.
        super::messages::MIDEN_MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        // Main-trace emitters touch `BusId::{BlockStackTable, BlockHashTable, OpGroupTable,
        // RangeCheck, LogPrecompileTranscript}` plus the shared chiplet-requests column.
        // The adapter's bus-prefix table is shared across every LookupAir it runs, so
        // returning `BusId::COUNT` (the total bus-type count) is the safe upper bound.
        BusId::COUNT
    }

    fn eval(&self, builder: &mut LB) {
        let main = builder.main();
        let local: &MainCols<_> = main.current_slice().borrow();
        let next: &MainCols<_> = main.next_slice().borrow();

        let ctx = MainBusContext::new(&*builder, local, next);

        emit_block_stack_and_range_logcap::<LB>(builder, &ctx);
        emit_block_hash_and_op_group::<LB>(builder, &ctx);
        emit_chiplet_requests::<LB>(builder, &ctx);
        emit_stack_overflow::<LB>(builder, &ctx);
    }
}
