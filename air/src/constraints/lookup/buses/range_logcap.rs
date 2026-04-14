//! Range stack + log-precompile capacity bus (M4 / `BUS_RANGE_CHECK` +
//! `BUS_LOG_PRECOMPILE_TRANSCRIPT` on the same column).
//!
//! Four simultaneous range-check lookups (gated by the u32-rangecheck op) and a
//! log-precompile transcript add/remove pair.

use core::array;

use crate::{
    Felt,
    constraints::{
        logup_msg::{LogCapacityMsg, RangeMsg},
        lookup::{LookupBatch, LookupBuilder, LookupColumn, LookupGroup, buses::MainTraceContext},
    },
    trace::log_precompile::{HELPER_CAP_PREV_RANGE, STACK_CAP_NEXT_RANGE},
};

/// Emit the range stack + log-precompile capacity bus (M4).
pub(in crate::constraints::lookup) fn emit_range_stack_and_log_capacity<LB>(
    builder: &mut LB,
    ctx: &MainTraceContext<LB>,
) where
    LB: LookupBuilder<F = Felt>,
{
    let local = ctx.local;
    let next = ctx.next;
    let op_flags = &ctx.op_flags;

    let dec = &local.decoder;
    let stk_next = &next.stack;
    let user_helpers = dec.user_op_helpers();

    // u32-rangecheck gate and log-precompile gate come straight from the shared `OpFlags`.
    let f_u32rc = op_flags.u32_rc_op();
    let f_log_precompile = op_flags.log_precompile();

    // U32RC helpers: first 4 of the 6 user_op_helpers. Kept as `[Var; 4]` (Copy) so the
    // batch closure captures them without cloning.
    let helpers: [LB::Var; 4] = array::from_fn(|i| user_helpers[i]);

    // LOGPRECOMPILE capacity add/remove payloads — also raw `[Var; 4]`.
    let cap_prev: [LB::Var; 4] = array::from_fn(|i| user_helpers[HELPER_CAP_PREV_RANGE.start + i]);
    let cap_next: [LB::Var; 4] = array::from_fn(|i| stk_next.get(STACK_CAP_NEXT_RANGE.start + i));

    builder.column(|col| {
        col.group(|g| {
            // U32RC: four simultaneous range-check removals under the u32rc flag.
            g.batch(f_u32rc, |b| {
                for helper in helpers {
                    b.remove(RangeMsg { value: helper.into() });
                }
            });

            // LOGPRECOMPILE: remove the old capacity, add the new one.
            g.batch(f_log_precompile, |b| {
                b.remove(LogCapacityMsg { capacity: cap_prev.map(Into::into) });
                b.add(LogCapacityMsg { capacity: cap_next.map(Into::into) });
            });
        });
    });
}
