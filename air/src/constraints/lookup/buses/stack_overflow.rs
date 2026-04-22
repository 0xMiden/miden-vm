//! Stack overflow table bus (M4, `BusId::StackOverflowTable`).
//!
//! Three mutually exclusive interactions:
//!
//! - **Right shift** (add): when an item is pushed past stack[15], record `(clk, s15, b1)` — the
//!   cycle, the spilled value, and the link to the previous overflow row.
//! - **Left shift ∧ non-empty overflow** (remove): when an item is popped back from the overflow
//!   table, consume the matching `(b1, s15', b1')` row.
//! - **DYNCALL ∧ non-empty overflow** (remove): DYNCALL is excluded from the `left_shift`
//!   aggregate; it consumes `(b1, s15', hasher_state[5])` because the new overflow pointer after a
//!   DYNCALL is staged in the decoder hasher state, not in `b1'` (which is reset).

use crate::{
    constraints::lookup::{
        main_air::{MainBusContext, MainLookupBuilder},
        messages::StackOverflowMsg,
    },
    lookup::{Deg, LookupColumn, LookupGroup},
};

/// Upper bound on fractions this emitter pushes into its column per row.
///
/// All three interactions gate on mutually exclusive opcode flags (right_shift, left_shift,
/// dyncall — DYNCALL is excluded from the `left_shift` aggregate by construction), so at
/// most one fires per row.
pub(in crate::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 1;

/// Emit the stack overflow table bus (M4).
pub(in crate::constraints::lookup) fn emit_stack_overflow<LB>(
    builder: &mut LB,
    ctx: &MainBusContext<LB>,
) where
    LB: MainLookupBuilder,
{
    let local = ctx.local;
    let next = ctx.next;
    let op_flags = &ctx.op_flags;

    let clk = local.system.clk;
    let s15 = local.stack.get(15);
    let s15_next = next.stack.get(15);
    let b1 = local.stack.b1;
    let b1_next = next.stack.b1;
    let h5 = local.decoder.hasher_state[5];

    // `op_flags.overflow() = (b0 - 16) * h0`, degree 2. Aliased once so each remove site
    // does not re-clone the underlying expression.
    let f_overflow = op_flags.overflow();
    let f_left_overflow = op_flags.left_shift() * f_overflow.clone();
    let f_dyncall_overflow = op_flags.dyncall() * f_overflow;

    builder.next_column(
        |col| {
            col.group(
                "overflow_interactions",
                |g| {
                    // Right shift: push `(clk, s15, b1)` onto the overflow table.
                    g.add(
                        "right_shift",
                        op_flags.right_shift(),
                        || StackOverflowMsg {
                            clk: clk.into(),
                            val: s15.into(),
                            prev: b1.into(),
                        },
                        Deg { n: 6, d: 7 },
                    );

                    // Left shift with non-empty overflow: pop `(b1, s15', b1')` off the overflow
                    // table.
                    g.remove(
                        "left_shift",
                        f_left_overflow,
                        || StackOverflowMsg {
                            clk: b1.into(),
                            val: s15_next.into(),
                            prev: b1_next.into(),
                        },
                        Deg { n: 7, d: 8 },
                    );

                    // DYNCALL with non-empty overflow: pop `(b1, s15', h5)`. The new overflow
                    // pointer lives in `hasher_state[5]` after a DYNCALL, since
                    // `b1'` is reset by the call.
                    g.remove(
                        "dyncall",
                        f_dyncall_overflow,
                        || StackOverflowMsg {
                            clk: b1.into(),
                            val: s15_next.into(),
                            prev: h5.into(),
                        },
                        Deg { n: 7, d: 8 },
                    );
                },
                Deg { n: 7, d: 8 },
            );
        },
        Deg { n: 7, d: 8 },
    );
}
