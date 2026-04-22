//! Merged main-trace column: block-stack table, u32 range checks, log-precompile capacity,
//! and range-table response (`BusId::BlockStackTable` + `BusId::RangeCheck` +
//! `BusId::LogPrecompileTranscript` on one column).
//!
//! Packs what used to be two separate columns (block-stack and range_logcap) into one,
//! saving an aux column. Soundness of the merge relies on the three buses using distinct
//! `bus_prefix[bus]` bases (so their rationals remain linearly independent in the
//! extension field) and on all opcode-gated interactions being mutually exclusive in the
//! main group.
//!
//! # Structure
//!
//! One [`super::super::LookupBuilder::column`] call with two sibling
//! [`super::super::LookupColumn::group`] calls:
//!
//! - **Main group** (opcode-gated, mutually exclusive by opcode):
//!   - Block-stack table: JOIN/SPLIT/SPAN/DYN, LOOP, DYNCALL, CALL/SYSCALL, two END cases, RESPAN
//!     batch (7 branches, mutually exclusive via decoder opcode flags).
//!   - u32 range-check batch: 4 removes gated by `u32_rc_op`.
//!   - Log-precompile capacity batch: 1 remove + 1 add gated by `log_precompile`.
//! - **Sibling group** (always on):
//!   - Range-table response: a single insert with runtime multiplicity `range_m`, gated by `ONE` so
//!     it fires on every row. Lives in its own group because it overlaps (row-wise) with every
//!     opcode-gated interaction above and would break the simple-group mutual-exclusion invariant.
//!
//! # Mutual exclusivity
//!
//! The main group is sound under simple-group accumulation because all its gates are
//! mutually exclusive decoder-opcode flags. The three bus families live in disjoint
//! opcode sets:
//!
//! - Block-stack: {JOIN, SPLIT, SPAN, DYN, LOOP, DYNCALL, CALL, SYSCALL, END, RESPAN}
//! - u32: {U32SPLIT, U32ASSERT2, U32ADD, U32SUB, U32MUL, U32DIV, U32MOD, U32AND, U32XOR, U32ADD3,
//!   U32MADD, …} — prefix_100 in the opcode encoding.
//! - LOGPRECOMPILE: {LOGPRECOMPILE} — a single opcode.
//!
//! No row can fire two of these simultaneously. The END-simple / END-call/syscall split
//! inside block-stack is mutually exclusive via the `is_call + is_syscall ≤ 1` end-flag
//! invariant.
//!
//! # Degree budget
//!
//! Main group contribution table:
//!
//! | Interaction | Gate deg | Payload | U contrib | V contrib |
//! |---|---|---|---|---|
//! | JOIN/SPLIT/SPAN/DYN simple add | 5 | Simple, denom 1 | 6 | 5 |
//! | LOOP simple add | 5 | Simple, denom 1 | 6 | 5 |
//! | DYNCALL simple add (Full msg) | 5 | Full, denom 1 | 6 | 5 |
//! | CALL/SYSCALL simple add (Full msg) | 4 | Full, denom 1 | 5 | 4 |
//! | END simple remove | 5 | Simple, denom 1 | 6 | 5 |
//! | END call/syscall remove (Full msg) | 5 | Full, denom 1 | 6 | 5 |
//! | RESPAN batch (k=2, f=respan deg 4) | — | Simple | 6 | 5 |
//! | u32rc batch (k=4, f=u32_rc_op deg 3) | — | Range, denom 1 | **7** | **6** |
//! | logpre batch (k=2, f=log_precompile deg 5) | — | LogCap, denom 1 | **7** | **6** |
//!
//! Main group max: `U_g = 7, V_g = 6`.
//!
//! Sibling range-table group: `g.insert(ONE, range_m, RangeMsg)` — gate deg 0, mult deg 1,
//! denom deg 1. `U_g = 1, V_g = 1`.
//!
//! Column fold (cross-mul rule `U_col = ∏ U_gi`, `V_col = Σᵢ V_gi · ∏_{j≠i} U_gj`):
//!
//! - `deg(U_col) = 7 + 1 = 8`
//! - `deg(V_col) = max(6 + 1, 1 + 7) = 8`
//! - **Transition = `max(1 + 8, 8) = 9`**, 0 headroom.

use core::array;

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    constraints::lookup::{
        main_air::{MainBusContext, MainLookupBuilder},
        messages::{BlockStackMsg, LogCapacityMsg, RangeMsg},
    },
    lookup::{Deg, LookupBatch, LookupColumn, LookupGroup},
    trace::log_precompile::{HELPER_CAP_PREV_RANGE, STACK_CAP_NEXT_RANGE},
};

/// Upper bound on fractions this emitter pushes into its column per row.
///
/// Main group per-row max is `max(1, 1, 1, 1, 1, 1, 2 (RESPAN), 4 (u32rc), 2 (logpre)) = 4`
/// — the u32rc 4-remove batch is the dominant branch.
/// Sibling range-table group always contributes 1 fraction.
/// Both groups run unconditionally (the main group fires at most one branch per row but
/// the per-column accumulator allocates the worst-case slot budget), so the per-row max is
/// the sum: `4 + 1 = 5`.
pub(in crate::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 5;

/// Emit the merged block-stack + u32rc + logpre + range-table column.
#[allow(clippy::too_many_lines)]
pub(in crate::constraints::lookup) fn emit_block_stack_and_range_logcap<LB>(
    builder: &mut LB,
    ctx: &MainBusContext<LB>,
) where
    LB: MainLookupBuilder,
{
    let local = ctx.local;
    let next = ctx.next;
    let op_flags = &ctx.op_flags;

    let dec = &local.decoder;
    let dec_next = &next.decoder;
    let stk = &local.stack;
    let stk_next = &next.stack;

    // ---- Block-stack captures (from block_stack.rs) ----
    //
    // `dec.hasher_state` holds `[h0..h7]` with `h[4..8]` doubling as the end-block flags
    // (see `end_block_flags()`). DYNCALL reads `h[4]`/`h[5]` as `fmp`/`depth`; the END
    // variants read `is_loop`/`is_call`/`is_syscall` through the typed `EndBlockFlags`
    // overlay.
    let addr = dec.addr;
    let addr_next = dec_next.addr;
    let h4 = dec.hasher_state[4];
    let h5 = dec.hasher_state[5];
    let h1_next = dec_next.hasher_state[1];
    let end_flags = dec.end_block_flags();

    let s0 = stk.get(0);
    let b0 = stk.b0;
    let b1 = stk.b1;
    let b0_next = stk_next.b0;
    let b1_next = stk_next.b1;

    let sys_ctx = local.system.ctx;
    let sys_ctx_next = next.system.ctx;

    // `fn_hash` is used twice (DYNCALL, CALL/SYSCALL) and `fn_hash_next` once (END-after-
    // CALL/SYSCALL); keep them as `[Var; 4]` and convert inside each closure.
    let fn_hash = local.system.fn_hash;
    let fn_hash_next = next.system.fn_hash;

    let range_m = local.range.multiplicity;
    let range_v = local.range.value;

    // ---- u32rc + logpre captures (from range_logcap.rs) ----

    let user_helpers = dec.user_op_helpers();
    let f_u32rc = op_flags.u32_rc_op();
    let f_log_precompile = op_flags.log_precompile();

    // u32rc helpers: first 4 of the 6 user_op_helpers. Kept as `[Var; 4]` (Copy) so the
    // batch closure captures them without cloning.
    let u32rc_helpers: [LB::Var; 4] = array::from_fn(|i| user_helpers[i]);

    // LOGPRECOMPILE capacity add/remove payloads — also raw `[Var; 4]`.
    let cap_prev: [LB::Var; 4] = array::from_fn(|i| user_helpers[HELPER_CAP_PREV_RANGE.start + i]);
    let cap_next: [LB::Var; 4] = array::from_fn(|i| stk_next.get(STACK_CAP_NEXT_RANGE.start + i));

    builder.next_column(
        |col| {
            // ──────────── Main group: all opcode-gated interactions ────────────
            col.group(
                "main_interactions",
                |g| {
                    // ---- Block-stack table (BusId::BlockStackTable) ----

                    // JOIN/SPLIT/SPAN/DYN: simple push with `is_loop = 0`.
                    let f =
                        op_flags.join() + op_flags.split() + op_flags.span() + op_flags.dyn_op();
                    g.add(
                        "join_split_span_dyn",
                        f,
                        || {
                            let block_id = addr_next.into();
                            let parent_id = addr.into();
                            let is_loop = LB::Expr::ZERO;
                            BlockStackMsg::Simple { block_id, parent_id, is_loop }
                        },
                        Deg { n: 5, d: 6 },
                    );

                    // LOOP: push with is_loop = s0.
                    g.add(
                        "loop",
                        op_flags.loop_op(),
                        || {
                            let block_id = addr_next.into();
                            let parent_id = addr.into();
                            let is_loop = s0.into();
                            BlockStackMsg::Simple { block_id, parent_id, is_loop }
                        },
                        Deg { n: 5, d: 6 },
                    );

                    // DYNCALL: full push with h[4]/h[5] as fmp/depth.
                    g.add(
                        "dyncall",
                        op_flags.dyncall(),
                        || {
                            let block_id = addr_next.into();
                            let parent_id = addr.into();
                            let is_loop = LB::Expr::ZERO;
                            let ctx = sys_ctx.into();
                            let fmp = h4.into();
                            let depth = h5.into();
                            let fn_hash = fn_hash.map(LB::Expr::from);
                            BlockStackMsg::Full {
                                block_id,
                                parent_id,
                                is_loop,
                                ctx,
                                fmp,
                                depth,
                                fn_hash,
                            }
                        },
                        Deg { n: 5, d: 6 },
                    );

                    // CALL/SYSCALL: full push saving the caller context.
                    let f = op_flags.call() + op_flags.syscall();
                    g.add(
                        "call_syscall",
                        f,
                        || {
                            let block_id = addr_next.into();
                            let parent_id = addr.into();
                            let is_loop = LB::Expr::ZERO;
                            let ctx = sys_ctx.into();
                            let fmp = b0.into();
                            let depth = b1.into();
                            let fn_hash = fn_hash.map(LB::Expr::from);
                            BlockStackMsg::Full {
                                block_id,
                                parent_id,
                                is_loop,
                                ctx,
                                fmp,
                                depth,
                                fn_hash,
                            }
                        },
                        Deg { n: 4, d: 5 },
                    );

                    // END (simple blocks): pop with the stored is_loop.
                    let f = op_flags.end()
                        * (LB::Expr::ONE - end_flags.is_call.into() - end_flags.is_syscall.into());
                    g.remove(
                        "end_simple",
                        f,
                        || {
                            let block_id = addr.into();
                            let parent_id = addr_next.into();
                            let is_loop = end_flags.is_loop.into();
                            BlockStackMsg::Simple { block_id, parent_id, is_loop }
                        },
                        Deg { n: 5, d: 6 },
                    );

                    // END (after CALL/SYSCALL): pop with restored caller context.
                    let f =
                        op_flags.end() * (end_flags.is_call.into() + end_flags.is_syscall.into());
                    g.remove(
                        "end_call_syscall",
                        f,
                        || {
                            let block_id = addr.into();
                            let parent_id = addr_next.into();
                            let is_loop = end_flags.is_loop.into();
                            let ctx = sys_ctx_next.into();
                            let fmp = b0_next.into();
                            let depth = b1_next.into();
                            let fn_hash = fn_hash_next.map(LB::Expr::from);
                            BlockStackMsg::Full {
                                block_id,
                                parent_id,
                                is_loop,
                                ctx,
                                fmp,
                                depth,
                                fn_hash,
                            }
                        },
                        Deg { n: 5, d: 6 },
                    );

                    // RESPAN: simultaneous push + pop — one batch under the RESPAN flag.
                    g.batch(
                        "respan",
                        op_flags.respan(),
                        |b| {
                            let block_id_add = addr_next.into();
                            let parent_id_add = h1_next.into();
                            let is_loop_add = LB::Expr::ZERO;
                            b.add(
                                "respan_add",
                                BlockStackMsg::Simple {
                                    block_id: block_id_add,
                                    parent_id: parent_id_add,
                                    is_loop: is_loop_add,
                                },
                                Deg { n: 4, d: 5 },
                            );
                            let block_id_rem = addr.into();
                            let parent_id_rem = h1_next.into();
                            let is_loop_rem = LB::Expr::ZERO;
                            b.remove(
                                "respan_remove",
                                BlockStackMsg::Simple {
                                    block_id: block_id_rem,
                                    parent_id: parent_id_rem,
                                    is_loop: is_loop_rem,
                                },
                                Deg { n: 4, d: 5 },
                            );
                        },
                        Deg { n: 1, d: 2 },
                    );

                    // ---- u32 range-check removes (BusId::RangeCheck) ----
                    // Four simultaneous range-check removals under the u32rc flag. Mutually
                    // exclusive with all block-stack branches (u32 ops are disjoint from
                    // control-flow ops) and with logpre (disjoint from LOGPRECOMPILE).
                    g.batch(
                        "u32_range_check",
                        f_u32rc,
                        move |b| {
                            for helper in u32rc_helpers {
                                let value = helper.into();
                                b.remove("u32rc_remove", RangeMsg { value }, Deg { n: 3, d: 4 });
                            }
                        },
                        Deg { n: 3, d: 4 },
                    );

                    // ---- Log-precompile capacity update (BusId::LogPrecompileTranscript) ----
                    // Remove the previous capacity, add the next. Mutually exclusive with all
                    // block-stack branches and with u32rc.
                    g.batch(
                        "log_precompile_capacity",
                        f_log_precompile,
                        move |b| {
                            let capacity_prev = cap_prev.map(LB::Expr::from);
                            b.remove(
                                "logpre_cap_remove",
                                LogCapacityMsg { capacity: capacity_prev },
                                Deg { n: 5, d: 6 },
                            );
                            let capacity_next = cap_next.map(LB::Expr::from);
                            b.add(
                                "logpre_cap_add",
                                LogCapacityMsg { capacity: capacity_next },
                                Deg { n: 5, d: 6 },
                            );
                        },
                        Deg { n: 1, d: 2 },
                    );
                },
                Deg { n: 6, d: 7 },
            );

            // ──────────── Sibling group: range-table response (BusId::RangeCheck) ────────────
            //
            // Always-active insertion with multiplicity `range_m`. Lives in its own group
            // because its gate (`ONE`) makes it fire on every row, overlapping with every
            // opcode-gated interaction in the main group — which would break the simple-group
            // mutual-exclusion invariant if they shared a group.
            col.group(
                "range_table",
                |g| {
                    g.insert(
                        "range_response",
                        LB::Expr::ONE,
                        range_m.into(),
                        || {
                            let value = range_v.into();
                            RangeMsg { value }
                        },
                        Deg { n: 1, d: 1 },
                    );
                },
                Deg { n: 1, d: 1 },
            );
        },
        Deg { n: 8, d: 8 },
    );
}
