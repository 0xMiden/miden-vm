//! Range stack + log-precompile capacity bus (M4 / `BUS_RANGE_CHECK` +
//! `BUS_LOG_PRECOMPILE_TRANSCRIPT` on the same column).
//!
//! Four simultaneous range-check lookups (gated by the u32-rangecheck op) and a
//! log-precompile transcript add/remove pair.

use core::array;

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    Felt, MainTraceRow,
    constraints::{
        logup_msg::{LogCapacityMsg, RangeMsg},
        lookup::{LookupBatch, LookupBuilder, LookupColumn, LookupGroup},
        op_flags::{ExprDecoderAccess, OpFlags},
    },
    trace::{
        decoder::{OP_BITS_RANGE, USER_OP_HELPERS_OFFSET},
        log_precompile::{HELPER_CAP_PREV_RANGE, STACK_CAP_NEXT_RANGE},
    },
};

/// Emit the range stack + log-precompile capacity bus (M4).
pub(in crate::constraints::lookup) fn emit_range_stack_and_log_capacity<LB>(
    builder: &mut LB,
    local: &MainTraceRow<LB::Var>,
    next: &MainTraceRow<LB::Var>,
) where
    LB: LookupBuilder<F = Felt>,
{
    let dec = &local.decoder;
    let stk_next = &next.stack;

    // U32RC flag: op_bit6 · (1-op_bit5) · (1-op_bit4) — matches the legacy expression.
    let op_bit4: LB::Expr = dec[OP_BITS_RANGE.start + 4].into();
    let op_bit5: LB::Expr = dec[OP_BITS_RANGE.start + 5].into();
    let op_bit6: LB::Expr = dec[OP_BITS_RANGE.start + 6].into();
    let f_u32rc: LB::Expr = op_bit6 * (LB::Expr::ONE - op_bit5) * (LB::Expr::ONE - op_bit4);

    let helpers: [LB::Var; 4] = array::from_fn(|i| dec[USER_OP_HELPERS_OFFSET + i]);

    // log_precompile capacity add/remove pair.
    let op_flags = OpFlags::new(ExprDecoderAccess::<LB::Var, LB::Expr>::new(local));
    let f_log_precompile = op_flags.log_precompile();
    let cap_prev: [LB::Var; 4] =
        array::from_fn(|i| dec[USER_OP_HELPERS_OFFSET + HELPER_CAP_PREV_RANGE.start + i]);
    let cap_next: [LB::Var; 4] = array::from_fn(|i| stk_next[STACK_CAP_NEXT_RANGE.start + i]);

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
