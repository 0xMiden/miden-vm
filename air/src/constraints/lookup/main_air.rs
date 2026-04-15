//! Main-trace LogUp lookup AIR.
//!
//! Owns the main-trace side of the Miden VM's LogUp argument: the five permutation columns
//! M1, M_2+5, M3, M4, M5. Each column is described by one of the `emit_*` functions in
//! [`super::buses`]; this module wires them together via a single [`MainBusContext`] that
//! carries the two-row window plus a shared [`OpFlags`] instance.
//!
//! The [`MainLookupBuilder`] extension trait exists so the `OpFlags` construction can diverge
//! between the constraint path (polynomial, today's default) and the prover path (boolean
//! fast path, planned). For now every adapter picks up the default polynomial body via an
//! empty `impl MainLookupBuilder for …` block — the structural split is the sole purpose of
//! this module today.

use core::borrow::Borrow;

use miden_crypto::stark::air::WindowAccess;

use super::{
    LookupAir, LookupBuilder,
    bus_id::NUM_BUS_IDS,
    buses::{
        block_hash_and_op_group::{self as block_hash_and_op_group, emit_block_hash_and_op_group},
        block_stack::{self, emit_block_stack_and_range_table},
        chiplet_requests::{self, emit_chiplet_requests},
        range_logcap::{self, emit_range_stack_and_log_capacity},
        stack_overflow::{self, emit_stack_overflow},
    },
};
use crate::{Felt, MainCols, constraints::op_flags::OpFlags};

// MAIN LOOKUP BUILDER
// ================================================================================================

/// Extension trait the main-trace [`LookupAir`] requires from its [`LookupBuilder`].
///
/// Carries a single hook, [`build_op_flags`](Self::build_op_flags), for constructing the
/// shared [`OpFlags`] instance that the four main-trace bus emitters consume. The default
/// body uses the polynomial path (today's behavior for both the constraint-path and the
/// prover-path adapters). A future prover-side optimization will override this method on
/// the prover adapter to skip the dead polynomial products that come from decoder bits
/// already being concrete 0/1 values; no other code moves.
///
/// There is intentionally **no** blanket `impl<LB: LookupBuilder> MainLookupBuilder for LB`
/// — Rust coherence would then forbid the prover adapter from overriding the default body.
/// Each adapter implements this trait explicitly with an empty `impl` block that picks up
/// the default.
pub(crate) trait MainLookupBuilder: LookupBuilder<F = Felt> {
    /// Build the shared [`OpFlags`] instance for one `eval` call.
    ///
    /// Default body calls [`OpFlags::new`], matching the pre-split behavior of
    /// `MainTraceContext::new`. Adapters override this when a cheaper construction path is
    /// available (e.g. the prover path, where decoder bits are concrete 0/1).
    fn build_op_flags(
        &self,
        local: &MainCols<Self::Var>,
        next: &MainCols<Self::Var>,
    ) -> OpFlags<Self::Expr> {
        OpFlags::new(&local.decoder, &local.stack, &next.decoder)
    }
}

// MAIN BUS CONTEXT
// ================================================================================================

/// Shared context for the four main-trace bus emitters.
///
/// Holds the two-row window plus a single [`OpFlags`] instance built once per `eval`
/// through [`MainLookupBuilder::build_op_flags`]. Every emitter reads `ctx.local`,
/// `ctx.next`, and `ctx.op_flags.f_*` directly — field access, no method indirection.
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
    pub op_flags: OpFlags<LB::Expr>,
}

impl<'a, LB> MainBusContext<'a, LB>
where
    LB: MainLookupBuilder,
{
    /// Build the shared main-trace context for one `eval` call.
    ///
    /// Delegates the `OpFlags` construction to the builder's
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
/// Zero-sized. Emits five permutation columns in the order M1, M_2+5, M3, M4, M5 — matching
/// the layout the legacy `enforce_main` held and the aggregator
/// [`super::miden_air::MidenLookupAir`] still holds. The chiplet-trace half of the argument
/// lives in [`super::chiplet_air::ChipletLookupAir`].
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct MainLookupAir;

/// Per-column fraction stride: [M1, M_2+5, M3, M4, M5].
pub(crate) const MAIN_COLUMN_SHAPE: [usize; 5] = [
    block_stack::MAX_INTERACTIONS_PER_ROW,
    block_hash_and_op_group::MAX_INTERACTIONS_PER_ROW,
    chiplet_requests::MAX_INTERACTIONS_PER_ROW,
    range_logcap::MAX_INTERACTIONS_PER_ROW,
    stack_overflow::MAX_INTERACTIONS_PER_ROW,
];

impl<LB> LookupAir<LB> for MainLookupAir
where
    LB: MainLookupBuilder,
{
    fn num_columns(&self) -> usize {
        // M1 (block-stack + range-table response), M_2+5 (block-hash queue ∪ op-group table),
        // M3 (chiplet requests), M4 (range-stack + logpre capacity), M5 (stack overflow table).
        5
    }

    fn column_shape(&self) -> &[usize] {
        &MAIN_COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        // The main-trace M3 column emits `HasherMsg::State` variants (linear_hash_init /
        // return_state) in the HPERM and LOGPRECOMPILE paths. That's the widest payload any
        // main-trace message carries: label@β⁰, addr@β¹, node_index@β², state[0..12]@β³..β¹⁴
        // — 15 slots total. Matches the aggregator's `MidenLookupAir::max_message_width`.
        15
    }

    fn num_bus_ids(&self) -> usize {
        // Main-trace emitters touch BUS_BLOCK_STACK_TABLE, BUS_BLOCK_HASH_TABLE,
        // BUS_OP_GROUP_TABLE, BUS_RANGE_CHECK, BUS_LOG_PRECOMPILE_TRANSCRIPT, and BUS_CHIPLETS.
        // The adapter's bus-prefix table is shared across every LookupAir it runs, so returning
        // `NUM_BUS_IDS` (the total bus-type count) is the safe upper bound.
        NUM_BUS_IDS
    }

    fn eval(&self, builder: &mut LB) {
        // Hold the `MainWindow` as an owned value so its borrow on the underlying builder is
        // released by the time we grab the `&mut builder` for the per-column emitters. Same
        // pattern as the pre-split `MidenLookupAir::eval`.
        let main = builder.main();
        let local: &MainCols<_> = main.current_slice().borrow();
        let next: &MainCols<_> = main.next_slice().borrow();

        // Build the shared main-trace context once per `eval`. `&*builder` is an immutable
        // reborrow of the mutable parameter; it's alive only for the duration of the
        // constructor call and is released before the emitters take their own `&mut builder`.
        let ctx = MainBusContext::new(&*builder, local, next);

        emit_block_stack_and_range_table::<LB>(builder, &ctx);
        emit_block_hash_and_op_group::<LB>(builder, &ctx);
        emit_chiplet_requests::<LB>(builder, &ctx);
        emit_range_stack_and_log_capacity::<LB>(builder, &ctx);
        emit_stack_overflow::<LB>(builder, &ctx);
    }
}
