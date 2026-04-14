//! Chiplet requests bus (M3 / `BUS_CHIPLETS`).
//!
//! Decoder-side requests into the hasher, bitwise, memory, ACE init, and kernel ROM chiplets.
//!
//! Every interaction is folded into a single
//! [`super::super::LookupColumn::group`] call. The cached-encoding variant was dropped in
//! the Task #7 cleanup in favor of a flat inline body matching the `block_hash_and_op_group`
//! pattern ("dropping the cached path is the simpler option" — see that bus's module doc
//! for the rationale). The cached-encoding optimization can be reintroduced later if
//! symbolic expression growth becomes a bottleneck.

use core::array;

use miden_core::{FMP_ADDR, FMP_INIT_VALUE, field::PrimeCharacteristicRing, operations::opcodes};

use crate::{
    Felt,
    constraints::{
        logup_msg::{AceInitMsg, BitwiseMsg, HasherMsg, KernelRomMsg, MemoryHeader},
        lookup::{LookupBatch, LookupBuilder, LookupColumn, LookupGroup, buses::MainTraceContext},
    },
    trace::{
        chiplets::hasher::HASH_CYCLE_LEN,
        log_precompile::{
            HELPER_ADDR_IDX, HELPER_CAP_PREV_RANGE, STACK_CAP_NEXT_RANGE, STACK_COMM_RANGE,
            STACK_R0_RANGE, STACK_R1_RANGE, STACK_TAG_RANGE,
        },
    },
};

/// Emit the chiplet requests bus (M3).
#[allow(clippy::too_many_lines)]
pub(in crate::constraints::lookup) fn emit_chiplet_requests<LB>(
    builder: &mut LB,
    main_ctx: &MainTraceContext<LB>,
) where
    LB: LookupBuilder<F = Felt>,
{
    let local = main_ctx.local;
    let next = main_ctx.next;
    let op_flags = &main_ctx.op_flags;

    let dec = &local.decoder;
    let stk = &local.stack;
    let stk_next = &next.stack;
    let user_helpers = dec.user_op_helpers();

    // Raw Vars (Copy — captured by value and converted at point of use).
    let addr = dec.addr;
    let addr_next = next.decoder.addr;
    let h = dec.hasher_state; // [Var; 8]
    let helper0 = user_helpers[0];
    let clk = local.system.clk;
    let sys_ctx = local.system.ctx;
    let sys_ctx_next = next.system.ctx;
    let s0 = stk.get(0);
    let s1 = stk.get(1);
    let stk_next_0 = stk_next.get(0);
    let log_addr = user_helpers[HELPER_ADDR_IDX];

    // Constants reused across HPERM / MPVERIFY / MRUPDATE / END / LOGPRECOMPILE.
    let last_off: LB::Expr = LB::Expr::from_u16((HASH_CYCLE_LEN - 1) as u16);
    let cycle_len: LB::Expr = LB::Expr::from_u16(HASH_CYCLE_LEN as u16);

    // Shared memory header for MLOAD / MSTORE / MLOADW / MSTOREW (ctx / s0 / clk).
    let mem_header = MemoryHeader {
        ctx: sys_ctx.into(),
        addr: s0.into(),
        clk: clk.into(),
    };

    builder.column(|col| {
        col.group(|g| {
            // --- Control-block removes (JOIN / SPLIT / LOOP / SPAN / CALL / SYSCALL) ---
            // `h` is a `[Var; 8]` captured by copy; each closure materializes a fresh
            // `[Expr; 8]` via `.map(Into::into)` at call time.
            g.remove(op_flags.join(), move || {
                HasherMsg::control_block(addr_next.into(), &h.map(Into::into), opcodes::JOIN)
            });
            g.remove(op_flags.split(), move || {
                HasherMsg::control_block(addr_next.into(), &h.map(Into::into), opcodes::SPLIT)
            });
            g.remove(op_flags.loop_op(), move || {
                HasherMsg::control_block(addr_next.into(), &h.map(Into::into), opcodes::LOOP)
            });
            g.remove(op_flags.span(), move || {
                // SPAN is encoded with opcode 0 at the `β¹²` slot.
                HasherMsg::control_block(addr_next.into(), &h.map(Into::into), 0)
            });

            // CALL: control-block remove + FMP write under a fresh header (ctx_next / FMP_ADDR /
            // clk).
            g.batch(op_flags.call(), move |b| {
                b.remove(HasherMsg::control_block(
                    addr_next.into(),
                    &h.map(Into::into),
                    opcodes::CALL,
                ));
                b.remove(
                    MemoryHeader {
                        ctx: sys_ctx_next.into(),
                        addr: FMP_ADDR.into(),
                        clk: clk.into(),
                    }
                    .write_element(FMP_INIT_VALUE.into()),
                );
            });

            // SYSCALL: control-block remove + kernel-ROM call with the h[0..4] digest.
            g.batch(op_flags.syscall(), move |b| {
                b.remove(HasherMsg::control_block(
                    addr_next.into(),
                    &h.map(Into::into),
                    opcodes::SYSCALL,
                ));
                b.remove(KernelRomMsg::call(array::from_fn(|i| h[i].into())));
            });

            // --- RESPAN ---
            g.remove(op_flags.respan(), move || {
                HasherMsg::absorption(
                    Into::<LB::Expr>::into(addr_next) - LB::Expr::ONE,
                    h.map(Into::into),
                )
            });

            // --- END ---
            {
                let last_off = last_off.clone();
                g.remove(op_flags.end(), move || {
                    HasherMsg::return_hash(
                        Into::<LB::Expr>::into(addr) + last_off,
                        array::from_fn(|i| h[i].into()),
                    )
                });
            }

            // --- DYN ---
            {
                let mem_header = mem_header.clone();
                g.batch(op_flags.dyn_op(), move |b| {
                    let zeros8: [LB::Expr; 8] = array::from_fn(|_| LB::Expr::ZERO);
                    b.remove(HasherMsg::control_block(addr_next.into(), &zeros8, opcodes::DYN));
                    b.remove(mem_header.read_word(array::from_fn(|i| h[i].into())));
                });
            }

            // --- DYNCALL ---
            {
                let mem_header = mem_header.clone();
                g.batch(op_flags.dyncall(), move |b| {
                    let zeros8: [LB::Expr; 8] = array::from_fn(|_| LB::Expr::ZERO);
                    b.remove(HasherMsg::control_block(addr_next.into(), &zeros8, opcodes::DYNCALL));
                    b.remove(mem_header.read_word(array::from_fn(|i| h[i].into())));
                    b.remove(
                        MemoryHeader {
                            ctx: sys_ctx_next.into(),
                            addr: FMP_ADDR.into(),
                            clk: clk.into(),
                        }
                        .write_element(FMP_INIT_VALUE.into()),
                    );
                });
            }

            // --- HPERM ---
            {
                let last_off = last_off.clone();
                g.batch(op_flags.hperm(), move |b| {
                    let stk_state: [LB::Expr; 12] = array::from_fn(|i| stk.get(i).into());
                    let stk_next_state: [LB::Expr; 12] = array::from_fn(|i| stk_next.get(i).into());
                    let helper0_e: LB::Expr = helper0.into();
                    b.remove(HasherMsg::linear_hash_init(helper0_e.clone(), stk_state));
                    b.remove(HasherMsg::return_state(helper0_e + last_off, stk_next_state));
                });
            }

            // --- MPVERIFY ---
            {
                let cycle_len = cycle_len.clone();
                g.batch(op_flags.mpverify(), move |b| {
                    let helper0_e: LB::Expr = helper0.into();
                    let mp_index: LB::Expr = stk.get(5).into();
                    let mp_depth: LB::Expr = stk.get(4).into();
                    let stk_word_0: [LB::Expr; 4] = array::from_fn(|i| stk.get(i).into());
                    let old_root: [LB::Expr; 4] = array::from_fn(|i| stk.get(6 + i).into());
                    b.remove(HasherMsg::merkle_verify_init(
                        helper0_e.clone(),
                        mp_index,
                        stk_word_0,
                    ));
                    b.remove(HasherMsg::return_hash(
                        helper0_e + mp_depth * cycle_len - LB::Expr::ONE,
                        old_root,
                    ));
                });
            }

            // --- MRUPDATE ---
            {
                let cycle_len = cycle_len.clone();
                g.batch(op_flags.mrupdate(), move |b| {
                    let helper0_e: LB::Expr = helper0.into();
                    let mr_index: LB::Expr = stk.get(5).into();
                    let mr_depth: LB::Expr = stk.get(4).into();
                    let stk_word_0: [LB::Expr; 4] = array::from_fn(|i| stk.get(i).into());
                    let stk_next_word_0: [LB::Expr; 4] = array::from_fn(|i| stk_next.get(i).into());
                    let old_root: [LB::Expr; 4] = array::from_fn(|i| stk.get(6 + i).into());
                    let new_node: [LB::Expr; 4] = array::from_fn(|i| stk.get(10 + i).into());
                    b.remove(HasherMsg::merkle_old_init(
                        helper0_e.clone(),
                        mr_index.clone(),
                        stk_word_0,
                    ));
                    b.remove(HasherMsg::return_hash(
                        helper0_e.clone() + mr_depth.clone() * cycle_len.clone() - LB::Expr::ONE,
                        old_root.clone(),
                    ));
                    b.remove(HasherMsg::merkle_new_init(
                        helper0_e.clone() + mr_depth.clone() * cycle_len.clone(),
                        mr_index,
                        new_node,
                    ));
                    b.remove(HasherMsg::return_hash(
                        helper0_e + mr_depth * (cycle_len.clone() + cycle_len) - LB::Expr::ONE,
                        stk_next_word_0,
                    ));
                });
            }

            // --- MLOAD / MSTORE / MLOADW / MSTOREW (shared mem_header) ---
            {
                let mem_header = mem_header.clone();
                g.remove(op_flags.mload(), move || mem_header.read_element(stk_next_0.into()));
            }
            {
                let mem_header = mem_header.clone();
                g.remove(op_flags.mstore(), move || mem_header.write_element(s1.into()));
            }
            {
                let mem_header = mem_header.clone();
                g.remove(op_flags.mloadw(), move || {
                    mem_header.read_word(array::from_fn(|i| stk_next.get(i).into()))
                });
            }
            {
                let mem_header = mem_header;
                g.remove(op_flags.mstorew(), move || {
                    mem_header.write_word([
                        s1.into(),
                        stk.get(2).into(),
                        stk.get(3).into(),
                        stk.get(4).into(),
                    ])
                });
            }

            // --- U32AND / U32XOR ---
            g.remove(op_flags.u32and(), move || {
                BitwiseMsg::and(s0.into(), s1.into(), stk_next_0.into())
            });
            g.remove(op_flags.u32xor(), move || {
                BitwiseMsg::xor(s0.into(), s1.into(), stk_next_0.into())
            });

            // --- EVALCIRCUIT ---
            g.remove(op_flags.evalcircuit(), move || AceInitMsg {
                clk: clk.into(),
                ctx: sys_ctx.into(),
                ptr: s0.into(),
                num_read: s1.into(),
                num_eval: stk.get(2).into(),
            });

            // --- LOGPRECOMPILE ---
            g.batch(op_flags.log_precompile(), move |b| {
                let logpre_in: [LB::Expr; 12] = [
                    stk.get(STACK_COMM_RANGE.start).into(),
                    stk.get(STACK_COMM_RANGE.start + 1).into(),
                    stk.get(STACK_COMM_RANGE.start + 2).into(),
                    stk.get(STACK_COMM_RANGE.start + 3).into(),
                    stk.get(STACK_TAG_RANGE.start).into(),
                    stk.get(STACK_TAG_RANGE.start + 1).into(),
                    stk.get(STACK_TAG_RANGE.start + 2).into(),
                    stk.get(STACK_TAG_RANGE.start + 3).into(),
                    user_helpers[HELPER_CAP_PREV_RANGE.start].into(),
                    user_helpers[HELPER_CAP_PREV_RANGE.start + 1].into(),
                    user_helpers[HELPER_CAP_PREV_RANGE.start + 2].into(),
                    user_helpers[HELPER_CAP_PREV_RANGE.start + 3].into(),
                ];
                let logpre_out: [LB::Expr; 12] = [
                    stk_next.get(STACK_R0_RANGE.start).into(),
                    stk_next.get(STACK_R0_RANGE.start + 1).into(),
                    stk_next.get(STACK_R0_RANGE.start + 2).into(),
                    stk_next.get(STACK_R0_RANGE.start + 3).into(),
                    stk_next.get(STACK_R1_RANGE.start).into(),
                    stk_next.get(STACK_R1_RANGE.start + 1).into(),
                    stk_next.get(STACK_R1_RANGE.start + 2).into(),
                    stk_next.get(STACK_R1_RANGE.start + 3).into(),
                    stk_next.get(STACK_CAP_NEXT_RANGE.start).into(),
                    stk_next.get(STACK_CAP_NEXT_RANGE.start + 1).into(),
                    stk_next.get(STACK_CAP_NEXT_RANGE.start + 2).into(),
                    stk_next.get(STACK_CAP_NEXT_RANGE.start + 3).into(),
                ];
                b.remove(HasherMsg::linear_hash_init(log_addr.into(), logpre_in));
                b.remove(HasherMsg::return_state(
                    Into::<LB::Expr>::into(log_addr) + last_off,
                    logpre_out,
                ));
            });
        });
    });
}
