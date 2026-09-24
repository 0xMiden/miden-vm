//! Packs three bus families onto one main-trace lookup column:
//!
//! - Block-stack table: control-flow block nesting.
//! - u32 and Merkle-depth range-check removes: gated by u32 or Merkle opcodes.
//! - Log-deferred transcript-state: gated by the log deferred opcode.
//!
//! Soundness of the merge relies on the bus families using distinct `bus_prefix[bus]` bases
//! (so their rationals remain linearly independent in the extension field) and on all
//! interactions being mutually exclusive by opcode.
//!
//! # Structure
//!
//! One [`crate::lookup::LookupBuilder::next_column`] call with one opcode-gated group:
//!
//! - Block-stack table: JOIN/SPLIT/SPAN/DYN, LOOP, DYNCALL, CALL/SYSCALL, two END cases, RESPAN
//!   batch (7 branches, mutually exclusive via decoder opcode flags).
//! - u32 range-check batch: 4 removes gated by `u32_rc_op`.
//! - Merkle range-check batches: depth bounds plus part of the canonical-index witness, gated by
//!   MPVERIFY / MRUPDATE.
//! - Log-deferred transcript-state batch: 1 remove + 1 add gated by `log_deferred`.
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
//! - Merkle: {MPVERIFY, MRUPDATE}.
//! - LOGDEFERRED: {LOGDEFERRED} — a single opcode.
//!
//! No row can fire two of these simultaneously. The continuation / caller-frame END split
//! inside block-stack is mutually exclusive because the caller-frame restoration selector is
//! asserted boolean on END rows (decoder/mod.rs) — the group's single-reciprocal accumulation is
//! only well-formed under that, and nothing else establishes it. The two END branches also use
//! an explicit entry-kind field in the same relation, so neither can be substituted for the
//! other.
//!
//! # Degree budget
//!
//! Main group contribution table:
//!
//! |Interaction                                  |Gate deg|Payload              |U degree|V degree|
//! |---------------------------------------------|--------|---------------------|--------|--------|
//! |JOIN/SPLIT/SPAN/DYN continuation add         |5       |Continuation, denom 1|6       |5       |
//! |LOOP continuation add                        |5       |Continuation, denom 1|6       |5       |
//! |DYNCALL caller-frame add                     |5       |CallerFrame, denom 1 |6       |5       |
//! |CALL/SYSCALL caller-frame add                |4       |CallerFrame, denom 1 |5       |4       |
//! |END continuation remove                      |5       |Continuation, denom 1|6       |5       |
//! |END caller-frame remove                      |5       |CallerFrame, denom 1 |6       |5       |
//! |RESPAN batch (k=2, f=respan deg 4)           |—       |Continuation         |6       |5       |
//! |u32rc batch (k=4, f=u32_rc_op deg 3)         |—       |Range, denom 1       |**7**   |**6**   |
//! |MPVERIFY Merkle batch (k=3, f=mpverify deg 5)|—       |Range, denom 1       |**8**   |**7**   |
//! |MRUPDATE Merkle batch (k=4, f=mrupdate deg 4)|—       |Range, denom 1       |**8**   |**7**   |
//! |logpre batch (k=2, f=log_deferred deg 5)     |—       |LogDeferred, denom 1 |**7**   |**6**   |
//!
//! Column max: `U = 8, V = 7`; transition degree is `max(1 + 8, 7) = 9`.

use super::super::operations::merkle;

use core::array;

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    constraints::{
        lookup::{
            main_air::{MainBusContext, MainLookupBuilder},
            messages::{BlockStackMsg, LogDeferredMsg, RangeMsg},
        },
        utils::BoolNot,
    },
    lookup::{Deg, LookupBatch, LookupColumn, LookupGroup},
    trace::log_deferred::{HELPER_STATE_PREV_RANGE, STACK_STATE_NEW_RANGE},
};

/// Upper bound on fractions this emitter pushes into its column per row.
///
/// `max(1, 1, 1, 1, 1, 1, 2 (RESPAN), 4 (u32rc), 3 (MPVERIFY), 4 (MRUPDATE),
/// 2 (logpre)) = 4`.
pub(in crate::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 4;

/// Emit the merged block-stack + u32/Merkle-depth range-check + logpre column.
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
    // (see `end_block_flags()`). DYNCALL reads `h[4]`/`h[5]` as the caller stack depth and
    // caller overflow address; END reads its semantic flags through the typed `EndBlockFlags`
    // overlay.
    let addr = dec.addr;
    let addr_next = dec_next.addr;
    let h4 = dec.hasher_state[4];
    let h5 = dec.hasher_state[5];
    let h1_next = dec_next.hasher_state[1];
    let end_flags = dec.end_block_flags();

    let b0 = stk.b0;
    let b1 = stk.b1;
    let b0_next = stk_next.b0;
    let b1_next = stk_next.b1;

    let sys_ctx = local.system.ctx;
    let sys_ctx_next = next.system.ctx;

    // `fn_hash` is used by caller-frame additions (DYNCALL, CALL, SYSCALL), and `fn_hash_next`
    // is used by caller-frame END removals.
    let fn_hash = local.system.fn_hash;
    let fn_hash_next = next.system.fn_hash;

    // ---- u32 and Merkle-depth range-check + logpre captures (from range_logcap.rs) ----

    let user_helpers = dec.user_op_helpers();
    let f_u32rc = op_flags.u32_rc_op();
    let f_log_deferred = op_flags.log_deferred();

    // u32rc helpers: first 4 of the 6 user_op_helpers.
    let u32rc_helpers: [LB::Var; 4] = array::from_fn(|i| user_helpers[i]);

    // LOGDEFERRED transcript-state add/remove payloads.
    let state_prev: [LB::Var; 4] =
        array::from_fn(|i| user_helpers[HELPER_STATE_PREV_RANGE.start + i]);
    let state_new: [LB::Var; 4] = array::from_fn(|i| stk_next.get(STACK_STATE_NEW_RANGE.start + i));

    builder.next_column(
        |col| {
            // ──────────── Main group: all opcode-gated interactions ────────────
            col.group(
                "main_interactions",
                |g| {
                    // ---- Block-stack relation (Continuation / CallerFrame tagged entries) ----

                    // JOIN/SPLIT/SPAN/DYN: continuation push with `is_loop = 0`.
                    let f =
                        op_flags.join() + op_flags.split() + op_flags.span() + op_flags.dyn_op();
                    g.add(
                        "join_split_span_dyn",
                        f,
                        || {
                            let block_id = addr_next.into();
                            let parent_id = addr.into();
                            let is_loop = LB::Expr::ZERO;
                            BlockStackMsg::Continuation { block_id, parent_id, is_loop }
                        },
                        Deg { v: 5, u: 6 },
                    );

                    // LOOP: push with `is_loop = 1`. Under do-while semantics LOOP reads no
                    // stack input, as it unconditionally enters the loop.
                    g.add(
                        "loop",
                        op_flags.loop_op(),
                        || {
                            let block_id = addr_next.into();
                            let parent_id = addr.into();
                            let is_loop = LB::Expr::ONE;
                            BlockStackMsg::Continuation { block_id, parent_id, is_loop }
                        },
                        Deg { v: 5, u: 6 },
                    );

                    // DYNCALL: caller-frame push with h[4]/h[5] carrying the caller stack depth
                    // and overflow address.
                    g.add(
                        "dyncall",
                        op_flags.dyncall(),
                        || {
                            let block_id = addr_next.into();
                            let parent_id = addr.into();
                            let caller_ctx = sys_ctx.into();
                            let caller_stack_depth = h4.into();
                            let caller_overflow_addr = h5.into();
                            let caller_fn_hash = fn_hash.map(LB::Expr::from);
                            BlockStackMsg::CallerFrame {
                                block_id,
                                parent_id,
                                caller_ctx,
                                caller_stack_depth,
                                caller_overflow_addr,
                                caller_fn_hash,
                            }
                        },
                        Deg { v: 5, u: 6 },
                    );

                    // CALL/SYSCALL: caller-frame push saving the caller state.
                    let f = op_flags.call() + op_flags.syscall();
                    g.add(
                        "call_syscall",
                        f,
                        || {
                            let block_id = addr_next.into();
                            let parent_id = addr.into();
                            let caller_ctx = sys_ctx.into();
                            let caller_stack_depth = b0.into();
                            let caller_overflow_addr = b1.into();
                            let caller_fn_hash = fn_hash.map(LB::Expr::from);
                            BlockStackMsg::CallerFrame {
                                block_id,
                                parent_id,
                                caller_ctx,
                                caller_stack_depth,
                                caller_overflow_addr,
                                caller_fn_hash,
                            }
                        },
                        Deg { v: 4, u: 5 },
                    );

                    // END of a continuation: pop with the stored is_loop.
                    let restores_caller_frame: LB::Expr = end_flags.restores_caller_frame.into();
                    let f = op_flags.end() * restores_caller_frame.not();
                    g.remove(
                        "end_continuation",
                        f,
                        || {
                            let block_id = addr.into();
                            let parent_id = addr_next.into();
                            let is_loop = end_flags.is_loop.into();
                            BlockStackMsg::Continuation { block_id, parent_id, is_loop }
                        },
                        Deg { v: 5, u: 6 },
                    );

                    // END of a caller frame: pop with restored caller state.
                    let f = op_flags.end() * restores_caller_frame;
                    g.remove(
                        "end_caller_frame",
                        f,
                        || {
                            let block_id = addr.into();
                            let parent_id = addr_next.into();
                            let caller_ctx = sys_ctx_next.into();
                            let caller_stack_depth = b0_next.into();
                            let caller_overflow_addr = b1_next.into();
                            let caller_fn_hash = fn_hash_next.map(LB::Expr::from);
                            BlockStackMsg::CallerFrame {
                                block_id,
                                parent_id,
                                caller_ctx,
                                caller_stack_depth,
                                caller_overflow_addr,
                                caller_fn_hash,
                            }
                        },
                        Deg { v: 5, u: 6 },
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
                                BlockStackMsg::Continuation {
                                    block_id: block_id_add,
                                    parent_id: parent_id_add,
                                    is_loop: is_loop_add,
                                },
                                Deg { v: 4, u: 5 },
                            );
                            let block_id_rem = addr.into();
                            let parent_id_rem = h1_next.into();
                            let is_loop_rem = LB::Expr::ZERO;
                            b.remove(
                                "respan_remove",
                                BlockStackMsg::Continuation {
                                    block_id: block_id_rem,
                                    parent_id: parent_id_rem,
                                    is_loop: is_loop_rem,
                                },
                                Deg { v: 4, u: 5 },
                            );
                        },
                        Deg { v: 5, u: 6 }, // (V, U) = (1 + 4, 2 + 4)
                    );

                    // ---- u32 range-check removes (BusId::RangeCheck) ----
                    // Four simultaneous range-check removals under the u32rc flag. Mutually
                    // exclusive with all block-stack branches (u32 ops are disjoint from
                    // control-flow ops) and with logpre (disjoint from LOGDEFERRED).
                    g.batch(
                        "u32_range_check",
                        f_u32rc,
                        move |b| {
                            for helper in u32rc_helpers {
                                let value = helper.into();
                                b.remove("u32rc_remove", RangeMsg { value }, Deg { v: 3, u: 4 });
                            }
                        },
                        Deg { v: 6, u: 7 }, // (V, U) = (3 + 3, 4 + 3)
                    );

                    merkle::emit_core_range_checks::<LB, _>(g, ctx);

                    // ---- Log-deferred root update (BusId::LogDeferredRoot) ----
                    // Remove the previous deferred root, add the next. Mutually exclusive with all
                    // block-stack branches and with the u32 and Merkle-depth range checks.
                    g.batch(
                        "log_deferred_state",
                        f_log_deferred,
                        move |b| {
                            let state_prev_expr = state_prev.map(LB::Expr::from);
                            b.remove(
                                "logpre_state_remove",
                                LogDeferredMsg { state: state_prev_expr },
                                Deg { v: 5, u: 6 },
                            );
                            let state_new_expr = state_new.map(LB::Expr::from);
                            b.add(
                                "logpre_state_add",
                                LogDeferredMsg { state: state_new_expr },
                                Deg { v: 5, u: 6 },
                            );
                        },
                        Deg { v: 6, u: 7 }, // (V, U) = (1 + 5, 2 + 5)
                    );
                },
                Deg { v: 7, u: 8 },
            );
        },
        Deg { v: 7, u: 8 },
    );
}
