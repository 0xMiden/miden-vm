//! Chiplet requests bus ([`BusId::Chiplets`]).
//!
//! Decoder-side requests into the hasher, bitwise, memory, ACE init, and kernel ROM chiplets.
//!
//! Every interaction is folded into a single [`super::super::LookupColumn::group`] call.
//! The emitter uses ordinary lookup batches; cached encoding is unnecessary for this column today.

use core::array;

use miden_core::{
    FMP_ADDR, FMP_INIT_VALUE, chiplets::blakeg, field::PrimeCharacteristicRing, operations::opcodes,
};

use crate::{
    constraints::lookup::{
        main_air::{MainBusContext, MainLookupBuilder},
        messages::{
            AceInitMsg, AeadBlakeGInputMsg, AeadStreamRequestMsg, BitwiseMsg, HasherMsg,
            KernelRomMsg, MemoryMsg,
        },
    },
    lookup::{Deg, LookupBatch, LookupColumn, LookupGroup},
    trace::{
        chiplets::hasher::CONTROLLER_ROWS_PER_HASHER_OP,
        log_precompile::{
            HELPER_ADDR_IDX, HELPER_STATE_PREV_RANGE, STACK_STATE_NEW_RANGE, STACK_STMNT_RANGE,
        },
    },
};

/// Upper bound on fractions this emitter pushes into its column per row.
///
/// Every branch here is gated by one mutually exclusive decoder-opcode flag. The heaviest
/// branch is MRUPDATE, whose batch emits 4 removes (merkle_old_init + return_hash +
/// merkle_new_init + return_hash). No other single branch exceeds 4.
pub(in crate::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 4;

/// Emit the chiplet requests bus.
pub(in crate::constraints::lookup) fn emit_chiplet_requests<LB>(
    builder: &mut LB,
    main_ctx: &MainBusContext<LB>,
) where
    LB: MainLookupBuilder,
{
    let local = main_ctx.local;
    let next = main_ctx.next;
    let op_flags = &main_ctx.op_flags;

    let dec = &local.decoder;
    let stk = &local.stack;
    let stk_next = &next.stack;
    let user_helpers = dec.user_op_helpers();

    let addr = dec.addr;
    let addr_next = next.decoder.addr;
    let h = dec.hasher_state;
    let group_count = dec.group_count;
    let helper0 = user_helpers[0];
    let clk = local.system.clk;
    let sys_ctx = local.system.ctx;
    let sys_ctx_next = next.system.ctx;
    let s0 = stk.get(0);
    let s1 = stk.get(1);
    let stk_next_0 = stk_next.get(0);
    let log_addr = user_helpers[HELPER_ADDR_IDX];

    // Constants reused across BCOMPRESS / MPVERIFY / MRUPDATE / END / LOGPRECOMPILE.
    // Strides are measured in controller-trace rows.
    let last_off: LB::Expr = LB::Expr::from_u16((CONTROLLER_ROWS_PER_HASHER_OP - 1) as u16);
    let cycle_len: LB::Expr = LB::Expr::from_u16(CONTROLLER_ROWS_PER_HASHER_OP as u16);

    // Shared (ctx, addr, clk) triple for MLOAD / MSTORE / MLOADW / MSTOREW: all read from
    // `s0` with the current system context and clock.
    let mem_ctx: LB::Expr = sys_ctx.into();
    let mem_clk: LB::Expr = clk.into();
    let mem_addr: LB::Expr = s0.into();

    builder.next_column(
        |col| {
            col.group(
                "decoder_requests",
                |g| {
                    // --- Control-block removes (JOIN / SPLIT / LOOP / SPAN; CALL / SYSCALL
                    // share the payload but live in batches below). SPAN encodes opcode 0
                    // at the beta^12 slot.
                    let mut control_remove = |name, flag, opcode: u8| {
                        g.remove(
                            name,
                            flag,
                            move || {
                                let parent = addr_next.into();
                                let h = h.map(LB::Expr::from);
                                HasherMsg::control_block(parent, &h, opcode)
                            },
                            Deg { v: 5, u: 6 },
                        );
                    };
                    control_remove("join", op_flags.join(), opcodes::JOIN);
                    control_remove("split", op_flags.split(), opcodes::SPLIT);
                    control_remove("loop", op_flags.loop_op(), opcodes::LOOP);
                    g.remove(
                        "span",
                        op_flags.span(),
                        move || {
                            let parent = addr_next.into();
                            let h = h.map(LB::Expr::from);
                            HasherMsg::basic_block_init(parent, &h, group_count.into())
                        },
                        Deg { v: 5, u: 6 },
                    );

                    // CALL: control-block remove + FMP write under a fresh header (ctx_next /
                    // FMP_ADDR / clk).
                    g.batch(
                        "call",
                        op_flags.call(),
                        move |b| {
                            let parent = addr_next.into();
                            let h = h.map(LB::Expr::from);
                            b.remove(
                                "call_ctrl_block",
                                HasherMsg::control_block(parent, &h, opcodes::CALL),
                                Deg { v: 4, u: 5 },
                            );
                            b.remove(
                                "call_fmp_write",
                                MemoryMsg::write_element(
                                    sys_ctx_next.into(),
                                    FMP_ADDR.into(),
                                    clk.into(),
                                    FMP_INIT_VALUE.into(),
                                ),
                                Deg { v: 4, u: 5 },
                            );
                        },
                        Deg { v: 5, u: 6 }, // (V, U) = (1 + 4, 2 + 4)
                    );

                    // SYSCALL: control-block remove + kernel-ROM call with the h[0..4] digest.
                    g.batch(
                        "syscall",
                        op_flags.syscall(),
                        move |b| {
                            let parent = addr_next.into();
                            let digest = array::from_fn(|i| h[i].into());
                            let h = h.map(LB::Expr::from);
                            b.remove(
                                "syscall_ctrl_block",
                                HasherMsg::control_block(parent, &h, opcodes::SYSCALL),
                                Deg { v: 4, u: 5 },
                            );
                            b.remove(
                                "syscall_kernel_rom",
                                KernelRomMsg::call(digest),
                                Deg { v: 4, u: 5 },
                            );
                        },
                        Deg { v: 5, u: 6 }, // (V, U) = (1 + 4, 2 + 4)
                    );

                    // --- RESPAN ---
                    // Uses `addr_next` directly: the next row's decoder `addr` already points at
                    // the continuation controller row, so no offset is needed.
                    g.remove(
                        "respan",
                        op_flags.respan(),
                        move || {
                            let parent = addr_next.into();
                            let h = h.map(LB::Expr::from);
                            HasherMsg::absorption(parent, h)
                        },
                        Deg { v: 4, u: 5 },
                    );

                    // --- END ---
                    {
                        let last_off = last_off.clone();
                        g.remove(
                            "end",
                            op_flags.end(),
                            move || {
                                let addr: LB::Expr = addr.into();
                                let parent = addr + last_off;
                                let h = array::from_fn(|i| h[i].into());
                                HasherMsg::return_hash(parent, h)
                            },
                            Deg { v: 4, u: 5 },
                        );
                    }

                    // --- DYN ---
                    {
                        let mem_ctx = mem_ctx.clone();
                        let mem_clk = mem_clk.clone();
                        let mem_addr = mem_addr.clone();
                        g.batch(
                            "dyn",
                            op_flags.dyn_op(),
                            move |b| {
                                let parent = addr_next.into();
                                let zeros8: [LB::Expr; 8] = array::from_fn(|_| LB::Expr::ZERO);
                                b.remove(
                                    "dyn_ctrl_block",
                                    HasherMsg::control_block(parent, &zeros8, opcodes::DYN),
                                    Deg { v: 5, u: 6 },
                                );
                                let word = array::from_fn(|i| h[i].into());
                                b.remove(
                                    "dyn_mem_read",
                                    MemoryMsg::read_word(mem_ctx, mem_addr, mem_clk, word),
                                    Deg { v: 5, u: 6 },
                                );
                            },
                            Deg { v: 6, u: 7 }, // (V, U) = (1 + 5, 2 + 5)
                        );
                    }

                    // --- DYNCALL ---
                    {
                        let mem_ctx = mem_ctx.clone();
                        let mem_clk = mem_clk.clone();
                        let mem_addr = mem_addr.clone();
                        g.batch(
                            "dyncall",
                            op_flags.dyncall(),
                            move |b| {
                                let parent = addr_next.into();
                                let zeros8: [LB::Expr; 8] = array::from_fn(|_| LB::Expr::ZERO);
                                b.remove(
                                    "dyncall_ctrl_block",
                                    HasherMsg::control_block(parent, &zeros8, opcodes::DYNCALL),
                                    Deg { v: 5, u: 6 },
                                );
                                let word = array::from_fn(|i| h[i].into());
                                b.remove(
                                    "dyncall_mem_read",
                                    MemoryMsg::read_word(mem_ctx, mem_addr, mem_clk.clone(), word),
                                    Deg { v: 5, u: 6 },
                                );
                                b.remove(
                                    "dyncall_fmp_write",
                                    MemoryMsg::write_element(
                                        sys_ctx_next.into(),
                                        FMP_ADDR.into(),
                                        mem_clk,
                                        FMP_INIT_VALUE.into(),
                                    ),
                                    Deg { v: 5, u: 6 },
                                );
                            },
                            Deg { v: 7, u: 8 }, // (V, U) = (2 + 5, 3 + 5)
                        );
                    }

                    // --- BCOMPRESS ---
                    {
                        let last_off = last_off.clone();
                        g.batch(
                            "bcompress",
                            op_flags.bcompress(),
                            move |b| {
                                let helper0: LB::Expr = helper0.into();
                                let stk_state = array::from_fn(|i| stk.get(i).into());
                                let cv_next = array::from_fn(|i| stk_next.get(8 + i).into());
                                b.remove(
                                    "bcompress_init",
                                    HasherMsg::linear_hash_init(helper0.clone(), stk_state),
                                    Deg { v: 5, u: 6 },
                                );
                                let return_addr = helper0 + last_off;
                                b.remove(
                                    "bcompress_return",
                                    HasherMsg::return_hash(return_addr, cv_next),
                                    Deg { v: 5, u: 6 },
                                );
                            },
                            Deg { v: 6, u: 7 }, // (V, U) = (1 + 5, 2 + 5)
                        );
                    }

                    // --- MPVERIFY ---
                    {
                        let cycle_len = cycle_len.clone();
                        g.batch(
                            "mpverify",
                            op_flags.mpverify(),
                            move |b| {
                                let helper0: LB::Expr = helper0.into();
                                let mp_index = stk.get(5).into();
                                let mp_depth: LB::Expr = stk.get(4).into();
                                let stk_word_0 = array::from_fn(|i| stk.get(i).into());
                                let old_root = array::from_fn(|i| stk.get(6 + i).into());
                                b.remove(
                                    "mpverify_init",
                                    HasherMsg::merkle_verify_init(
                                        helper0.clone(),
                                        mp_index,
                                        stk_word_0,
                                    ),
                                    Deg { v: 5, u: 6 },
                                );
                                let return_addr = helper0 + mp_depth * cycle_len - LB::Expr::ONE;
                                b.remove(
                                    "mpverify_return",
                                    HasherMsg::return_hash(return_addr, old_root),
                                    Deg { v: 5, u: 6 },
                                );
                            },
                            Deg { v: 6, u: 7 }, // (V, U) = (1 + 5, 2 + 5)
                        );
                    }

                    // --- MRUPDATE ---
                    {
                        let cycle_len = cycle_len.clone();
                        g.batch(
                            "mrupdate",
                            op_flags.mrupdate(),
                            move |b| {
                                let helper0: LB::Expr = helper0.into();
                                let mr_index: LB::Expr = stk.get(5).into();
                                let mr_depth: LB::Expr = stk.get(4).into();
                                let stk_word_0 = array::from_fn(|i| stk.get(i).into());
                                let stk_next_word_0 = array::from_fn(|i| stk_next.get(i).into());
                                let old_root = array::from_fn(|i| stk.get(6 + i).into());
                                let new_node = array::from_fn(|i| stk.get(10 + i).into());
                                b.remove(
                                    "mrupdate_old_init",
                                    HasherMsg::merkle_old_init(
                                        helper0.clone(),
                                        mr_index.clone(),
                                        stk_word_0,
                                    ),
                                    Deg { v: 4, u: 5 },
                                );
                                let old_return_addr = helper0.clone()
                                    + mr_depth.clone() * cycle_len.clone()
                                    - LB::Expr::ONE;
                                b.remove(
                                    "mrupdate_old_return",
                                    HasherMsg::return_hash(old_return_addr, old_root),
                                    Deg { v: 4, u: 5 },
                                );
                                let new_init_addr =
                                    helper0.clone() + mr_depth.clone() * cycle_len.clone();
                                b.remove(
                                    "mrupdate_new_init",
                                    HasherMsg::merkle_new_init(new_init_addr, mr_index, new_node),
                                    Deg { v: 4, u: 5 },
                                );
                                let new_return_addr = helper0
                                    + mr_depth * (cycle_len.clone() + cycle_len)
                                    - LB::Expr::ONE;
                                b.remove(
                                    "mrupdate_new_return",
                                    HasherMsg::return_hash(new_return_addr, stk_next_word_0),
                                    Deg { v: 4, u: 5 },
                                );
                            },
                            Deg { v: 7, u: 8 }, // (V, U) = (3 + 4, 4 + 4)
                        );
                    }

                    // --- MLOAD / MSTORE / MLOADW / MSTOREW ---
                    // Shared (ctx, addr, clk) triple: reads the current system context, s0,
                    // and clk.
                    {
                        let (c, a, k) = (mem_ctx.clone(), mem_addr.clone(), mem_clk.clone());
                        g.remove(
                            "mload",
                            op_flags.mload(),
                            move || MemoryMsg::read_element(c, a, k, stk_next_0.into()),
                            Deg { v: 7, u: 8 },
                        );
                    }
                    {
                        let (c, a, k) = (mem_ctx.clone(), mem_addr.clone(), mem_clk.clone());
                        g.remove(
                            "mstore",
                            op_flags.mstore(),
                            move || MemoryMsg::write_element(c, a, k, s1.into()),
                            Deg { v: 7, u: 8 },
                        );
                    }
                    {
                        let (c, a, k) = (mem_ctx.clone(), mem_addr.clone(), mem_clk.clone());
                        g.remove(
                            "mloadw",
                            op_flags.mloadw(),
                            move || {
                                let word = array::from_fn(|i| stk_next.get(i).into());
                                MemoryMsg::read_word(c, a, k, word)
                            },
                            Deg { v: 7, u: 8 },
                        );
                    }
                    g.remove(
                        "mstorew",
                        op_flags.mstorew(),
                        move || {
                            let word = [
                                s1.into(),
                                stk.get(2).into(),
                                stk.get(3).into(),
                                stk.get(4).into(),
                            ];
                            MemoryMsg::write_word(mem_ctx, mem_addr, mem_clk, word)
                        },
                        Deg { v: 7, u: 8 },
                    );

                    // --- MSTREAM / PIPE ---
                    // Two-word memory ops. Address `stack[12]` holds the word-addressable target;
                    // the two words live at `addr` and `addr + 4`.
                    //
                    // MSTREAM reads 8 elements from memory into `next.stack[0..8]`
                    // (MEMORY_READ_WORD). PIPE writes 8 elements from
                    // `next.stack[0..8]` into memory (MEMORY_WRITE_WORD).
                    let stream_addr = stk.get(12);
                    g.batch(
                        "mstream",
                        op_flags.mstream(),
                        move |b| {
                            let addr0: LB::Expr = stream_addr.into();
                            let addr1: LB::Expr = addr0.clone() + LB::Expr::from_u16(4);
                            let word0: [LB::Expr; 4] = array::from_fn(|i| stk_next.get(i).into());
                            let word1: [LB::Expr; 4] =
                                array::from_fn(|i| stk_next.get(4 + i).into());
                            b.remove(
                                "mstream_word0",
                                MemoryMsg::read_word(sys_ctx.into(), addr0, clk.into(), word0),
                                Deg { v: 5, u: 6 },
                            );
                            b.remove(
                                "mstream_word1",
                                MemoryMsg::read_word(sys_ctx.into(), addr1, clk.into(), word1),
                                Deg { v: 5, u: 6 },
                            );
                        },
                        Deg { v: 6, u: 7 }, // (V, U) = (1 + 5, 2 + 5)
                    );
                    g.batch(
                        "pipe",
                        op_flags.pipe(),
                        move |b| {
                            let addr0: LB::Expr = stream_addr.into();
                            let addr1: LB::Expr = addr0.clone() + LB::Expr::from_u16(4);
                            let word0: [LB::Expr; 4] = array::from_fn(|i| stk_next.get(i).into());
                            let word1: [LB::Expr; 4] =
                                array::from_fn(|i| stk_next.get(4 + i).into());
                            b.remove(
                                "pipe_word0",
                                MemoryMsg::write_word(sys_ctx.into(), addr0, clk.into(), word0),
                                Deg { v: 5, u: 6 },
                            );
                            b.remove(
                                "pipe_word1",
                                MemoryMsg::write_word(sys_ctx.into(), addr1, clk.into(), word1),
                                Deg { v: 5, u: 6 },
                            );
                        },
                        Deg { v: 6, u: 7 }, // (V, U) = (1 + 5, 2 + 5)
                    );

                    // --- AEAD STREAM ---
                    let src_ptr = stk.get(5);
                    let dst_ptr = stk.get(6);
                    g.batch(
                        "aead_stream",
                        op_flags.aead_stream(),
                        move |b| {
                            let state = core::array::from_fn(|i| {
                                if i == 0 {
                                    stk.get(4).into()
                                } else if i < 8 {
                                    LB::Expr::ZERO
                                } else {
                                    stk.get(i - 8).into()
                                }
                            });
                            b.insert(
                                "aead_blakeg_input",
                                LB::Expr::ONE,
                                AeadBlakeGInputMsg { clk: clk.into(), state },
                                Deg { v: 4, u: 5 },
                            );
                            for (name, src_offset, dst_offset, lane_base) in
                                [("aead_stream_low", 0, 0, 0), ("aead_stream_high", 4, 8, 8)]
                            {
                                // The stream side emits the same request from both 4-row halves
                                // of one 8-row entry, so Core supplies multiplicity -2.
                                b.insert(
                                    name,
                                    -LB::Expr::from_u16(2),
                                    AeadStreamRequestMsg {
                                        ctx: sys_ctx.into(),
                                        clk: clk.into(),
                                        src_ptr: Into::<LB::Expr>::into(src_ptr)
                                            + LB::Expr::from_u16(src_offset),
                                        dst_ptr: Into::<LB::Expr>::into(dst_ptr)
                                            + LB::Expr::from_u16(dst_offset),
                                        lane_base: LB::Expr::from_u16(lane_base),
                                    },
                                    Deg { v: 4, u: 5 },
                                );
                            }
                        },
                        Deg { v: 7, u: 8 }, // (V, U) = (3 + 4, 4 + 4)
                    );

                    // --- HORNERBASE / HORNEREXT ---
                    // Both ops read the evaluation point alpha from memory at `stack[13]`.
                    // HORNERBASE reads two base-field elements (`alpha_0` at `addr`,
                    // `alpha_1` at `addr + 1`); HORNEREXT reads a single word
                    // `[alpha_0, alpha_1, k_0, k_1]` at `addr`. The point is held in
                    // helpers[0..2] for both ops; HORNEREXT also stores `k_0`, `k_1` in
                    // helpers[2..4].
                    let alpha_ptr = stk.get(13);
                    g.batch(
                        "hornerbase",
                        op_flags.hornerbase(),
                        move |b| {
                            let addr0: LB::Expr = alpha_ptr.into();
                            let addr1: LB::Expr = addr0.clone() + LB::Expr::from_u16(1);
                            let eval0: LB::Expr = user_helpers[0].into();
                            let eval1: LB::Expr = user_helpers[1].into();
                            b.remove(
                                "hornerbase_alpha0",
                                MemoryMsg::read_element(sys_ctx.into(), addr0, clk.into(), eval0),
                                Deg { v: 5, u: 6 },
                            );
                            b.remove(
                                "hornerbase_alpha1",
                                MemoryMsg::read_element(sys_ctx.into(), addr1, clk.into(), eval1),
                                Deg { v: 5, u: 6 },
                            );
                        },
                        Deg { v: 6, u: 7 }, // (V, U) = (1 + 5, 2 + 5)
                    );
                    g.remove(
                        "hornerext",
                        op_flags.hornerext(),
                        move || {
                            let addr: LB::Expr = alpha_ptr.into();
                            let word: [LB::Expr; 4] = [
                                user_helpers[0].into(),
                                user_helpers[1].into(),
                                user_helpers[2].into(),
                                user_helpers[3].into(),
                            ];
                            MemoryMsg::read_word(sys_ctx.into(), addr, clk.into(), word)
                        },
                        Deg { v: 5, u: 6 },
                    );

                    // --- U32AND / U32XOR ---
                    g.remove(
                        "u32and",
                        op_flags.u32and(),
                        move || {
                            let a = s0.into();
                            let b = s1.into();
                            let c = stk_next_0.into();
                            BitwiseMsg::and(a, b, c)
                        },
                        Deg { v: 7, u: 8 },
                    );
                    g.remove(
                        "u32xor",
                        op_flags.u32xor(),
                        move || {
                            let a = s0.into();
                            let b = s1.into();
                            let c = stk_next_0.into();
                            BitwiseMsg::xor(a, b, c)
                        },
                        Deg { v: 7, u: 8 },
                    );

                    // --- EVALCIRCUIT ---
                    g.remove(
                        "evalcircuit",
                        op_flags.evalcircuit(),
                        move || {
                            let clk = clk.into();
                            let ctx = sys_ctx.into();
                            let ptr = s0.into();
                            let num_read = s1.into();
                            let num_eval = stk.get(2).into();
                            AceInitMsg { clk, ctx, ptr, num_read, num_eval }
                        },
                        Deg { v: 5, u: 6 },
                    );

                    // --- LOGPRECOMPILE ---
                    //
                    // Hasher input: `[STATE_PREV (helpers), STMNT (stack[4..8]), CV]`.
                    // The response returns only the new transcript state.
                    g.batch(
                        "logprecompile",
                        op_flags.log_precompile(),
                        move |b| {
                            let log_addr: LB::Expr = log_addr.into();
                            let logpre_cv = blakeg::two_to_one_chaining_word(0);
                            let logpre_in: [LB::Expr; 12] = array::from_fn(|i| {
                                if i < 4 {
                                    user_helpers[HELPER_STATE_PREV_RANGE.start + i].into()
                                } else if i < 8 {
                                    stk.get(STACK_STMNT_RANGE.start + (i - 4)).into()
                                } else {
                                    LB::Expr::from(logpre_cv[i - 8])
                                }
                            });
                            let state_new: [LB::Expr; 4] = array::from_fn(|i| {
                                stk_next.get(STACK_STATE_NEW_RANGE.start + i).into()
                            });
                            b.remove(
                                "logprecompile_init",
                                HasherMsg::linear_hash_init(log_addr.clone(), logpre_in),
                                Deg { v: 5, u: 6 },
                            );
                            let return_addr = log_addr + last_off;
                            b.remove(
                                "logprecompile_return",
                                HasherMsg::return_hash(return_addr, state_new),
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
