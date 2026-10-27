//! Stack overflow table bus (`BusId::StackOverflowTable`).
//!
//! Stack-overflow table interactions share this column with the low three limbs of the Merkle
//! canonical-index witness. The opcode families are row-disjoint: MPVERIFY and MRUPDATE are
//! no-shift operations, so neither can activate a stack-overflow add/remove.
//!
//! - **Right shift** (add): when an item is pushed past `stack[15]`, record `(clk, s15, b1)` — the
//!   cycle, spilled value, and link to the previous overflow row.
//! - **Left shift ∧ non-empty overflow** (remove): consume the matching `(b1, s15', b1')` row.
//! - **DYNCALL ∧ non-empty overflow** (remove): DYNCALL is excluded from `left_shift`; it consumes
//!   `(b1, s15', hasher_state[5])` because the caller's post-pop overflow pointer is staged in h5
//!   while `b1'` is reset.

use p3_field::Dup;

use super::super::operations::merkle;
use crate::{
    constraints::lookup::{
        main_air::{MainBusContext, MainLookupBuilder},
        messages::StackOverflowMsg,
    },
    lookup::{Deg, LookupColumn, LookupGroup},
};

/// Upper bound on fractions this emitter pushes into its column per row.
///
/// Stack-overflow interactions contribute one fraction; MPVERIFY/MRUPDATE contribute the three
/// low canonical-index limbs. The branches are opcode-disjoint, so at most three fire per row.
pub(in crate::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 3;

/// Emit the stack overflow table bus.
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

    // `op_flags.overflow() = (b0 - 16) * h0`, degree 2. Aliased once so each removal can cheaply
    // duplicate the expression.
    let f_overflow = op_flags.overflow();
    let f_left_shift_overflow = op_flags.left_shift() * f_overflow.dup();
    let f_dyncall_overflow = op_flags.dyncall() * f_overflow;

    builder.next_column(
        |col| {
            col.group(
                "overflow_interactions",
                |g| {
                    // Right shift: add `(clk, s15, b1)` to the overflow table.
                    g.add(
                        "right_shift",
                        op_flags.right_shift(),
                        || StackOverflowMsg {
                            clk: clk.into(),
                            val: s15.into(),
                            prev: b1.into(),
                        },
                        Deg { v: 6, u: 7 },
                    );

                    // Left shift with non-empty overflow: remove `(b1, s15', b1')`.
                    g.remove(
                        "left_shift",
                        f_left_shift_overflow,
                        || StackOverflowMsg {
                            clk: b1.into(),
                            val: s15_next.into(),
                            prev: b1_next.into(),
                        },
                        Deg { v: 7, u: 8 },
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
                        Deg { v: 7, u: 8 },
                    );

                    merkle::emit_core_index_limbs::<LB, _>(g, ctx);
                },
                Deg { v: 7, u: 8 },
            );
        },
        Deg { v: 7, u: 8 },
    );
}
