//! Chiplet requests bus ([`BusId::Chiplets`]).
//!
//! Decoder-side requests into the hasher, bitwise, memory, ACE init, and kernel ROM chiplets.
//!
//! Every interaction is folded into a single [`super::super::LookupColumn::group`] call.
//! The cached-encoding optimization can be reintroduced later if symbolic expression growth
//! becomes a bottleneck.

use core::array;

use miden_core::{FMP_ADDR, FMP_INIT_VALUE, field::PrimeCharacteristicRing, operations::opcodes};

use crate::{
    constraints::lookup::{
        main_air::{MainBusContext, MainLookupBuilder},
        messages::{AceInitMsg, BitwiseMsg, HasherMsg, KernelRomMsg, MemoryHeader},
    },
    lookup::{Deg, LookupBatch, LookupColumn, LookupGroup},
    trace::{
        chiplets::hasher::CONTROLLER_ROWS_PER_PERMUTATION,
        log_precompile::{
            HELPER_ADDR_IDX, HELPER_CAP_PREV_RANGE, STACK_CAP_NEXT_RANGE, STACK_COMM_RANGE,
            STACK_R0_RANGE, STACK_R1_RANGE, STACK_TAG_RANGE,
        },
    },
};

/// Upper bound on fractions this emitter pushes into its column per row.
///
/// Every branch here is gated by one mutually exclusive decoder-opcode flag. The heaviest
/// branch is MRUPDATE, whose batch emits 4 removes (merkle_old_init + return_hash +
/// merkle_new_init + return_hash). No other single branch exceeds 4.
pub(in crate::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 4;

/// Emit the chiplet requests bus (M3).
#[allow(clippy::too_many_lines)]
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
    // Strides are measured in controller-trace rows (2 per permutation), not physical
    // hasher sub-chiplet rows — the address must cancel against `clk + 1` on the hasher
    // controller output row.
    let last_off: LB::Expr = LB::Expr::from_u16((CONTROLLER_ROWS_PER_PERMUTATION - 1) as u16);
    let cycle_len: LB::Expr = LB::Expr::from_u16(CONTROLLER_ROWS_PER_PERMUTATION as u16);

    // Shared memory header for MLOAD / MSTORE / MLOADW / MSTOREW (ctx / s0 / clk).
    let mem_header = MemoryHeader {
        ctx: sys_ctx.into(),
        addr: s0.into(),
        clk: clk.into(),
    };

    builder.next_column(
        |col| {
            col.group(
                "decoder_requests",
                |g| {
                    // --- Control-block removes (JOIN / SPLIT / LOOP / SPAN / CALL / SYSCALL) ---
                    // `h` is a `[Var; 8]` captured by copy; each closure shadows it with a fresh
                    // `[Expr; 8]` via `.map(LB::Expr::from)` at call time.
                    g.remove(
                        "join",
                        op_flags.join(),
                        move || {
                            let parent = addr_next.into();
                            let h = h.map(LB::Expr::from);
                            HasherMsg::control_block(parent, &h, opcodes::JOIN)
                        },
                        Deg { n: 5, d: 6 },
                    );
                    g.remove(
                        "split",
                        op_flags.split(),
                        move || {
                            let parent = addr_next.into();
                            let h = h.map(LB::Expr::from);
                            HasherMsg::control_block(parent, &h, opcodes::SPLIT)
                        },
                        Deg { n: 5, d: 6 },
                    );
                    g.remove(
                        "loop",
                        op_flags.loop_op(),
                        move || {
                            let parent = addr_next.into();
                            let h = h.map(LB::Expr::from);
                            HasherMsg::control_block(parent, &h, opcodes::LOOP)
                        },
                        Deg { n: 5, d: 6 },
                    );
                    g.remove(
                        "span",
                        op_flags.span(),
                        move || {
                            // SPAN is encoded with opcode 0 at the `β¹²` slot.
                            let parent = addr_next.into();
                            let h = h.map(LB::Expr::from);
                            HasherMsg::control_block(parent, &h, 0)
                        },
                        Deg { n: 5, d: 6 },
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
                                Deg { n: 4, d: 5 },
                            );
                            let fmp_header = MemoryHeader {
                                ctx: sys_ctx_next.into(),
                                addr: FMP_ADDR.into(),
                                clk: clk.into(),
                            };
                            b.remove(
                                "call_fmp_write",
                                fmp_header.write_element(FMP_INIT_VALUE.into()),
                                Deg { n: 4, d: 5 },
                            );
                        },
                        Deg { n: 1, d: 2 },
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
                                Deg { n: 4, d: 5 },
                            );
                            b.remove(
                                "syscall_kernel_rom",
                                KernelRomMsg::call(digest),
                                Deg { n: 4, d: 5 },
                            );
                        },
                        Deg { n: 1, d: 2 },
                    );

                    // --- RESPAN ---
                    // Uses `addr_next` directly: in the controller/perm split, the next row's
                    // decoder `addr` already points at the continuation input
                    // row, so no offset is needed.
                    g.remove(
                        "respan",
                        op_flags.respan(),
                        move || {
                            let parent = addr_next.into();
                            let h = h.map(LB::Expr::from);
                            HasherMsg::absorption(parent, h)
                        },
                        Deg { n: 4, d: 5 },
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
                            Deg { n: 4, d: 5 },
                        );
                    }

                    // --- DYN ---
                    {
                        let mem_header = mem_header.clone();
                        g.batch(
                            "dyn",
                            op_flags.dyn_op(),
                            move |b| {
                                let parent = addr_next.into();
                                let zeros8: [LB::Expr; 8] = array::from_fn(|_| LB::Expr::ZERO);
                                b.remove(
                                    "dyn_ctrl_block",
                                    HasherMsg::control_block(parent, &zeros8, opcodes::DYN),
                                    Deg { n: 5, d: 6 },
                                );
                                let word = array::from_fn(|i| h[i].into());
                                b.remove(
                                    "dyn_mem_read",
                                    mem_header.read_word(word),
                                    Deg { n: 5, d: 6 },
                                );
                            },
                            Deg { n: 1, d: 2 },
                        );
                    }

                    // --- DYNCALL ---
                    {
                        let mem_header = mem_header.clone();
                        g.batch(
                            "dyncall",
                            op_flags.dyncall(),
                            move |b| {
                                let parent = addr_next.into();
                                let zeros8: [LB::Expr; 8] = array::from_fn(|_| LB::Expr::ZERO);
                                b.remove(
                                    "dyncall_ctrl_block",
                                    HasherMsg::control_block(parent, &zeros8, opcodes::DYNCALL),
                                    Deg { n: 5, d: 6 },
                                );
                                let word = array::from_fn(|i| h[i].into());
                                b.remove(
                                    "dyncall_mem_read",
                                    mem_header.read_word(word),
                                    Deg { n: 5, d: 6 },
                                );
                                let fmp_header = MemoryHeader {
                                    ctx: sys_ctx_next.into(),
                                    addr: FMP_ADDR.into(),
                                    clk: clk.into(),
                                };
                                b.remove(
                                    "dyncall_fmp_write",
                                    fmp_header.write_element(FMP_INIT_VALUE.into()),
                                    Deg { n: 5, d: 6 },
                                );
                            },
                            Deg { n: 2, d: 3 },
                        );
                    }

                    // --- HPERM ---
                    {
                        let last_off = last_off.clone();
                        g.batch(
                            "hperm",
                            op_flags.hperm(),
                            move |b| {
                                let helper0: LB::Expr = helper0.into();
                                let stk_state = array::from_fn(|i| stk.get(i).into());
                                let stk_next_state = array::from_fn(|i| stk_next.get(i).into());
                                b.remove(
                                    "hperm_init",
                                    HasherMsg::linear_hash_init(helper0.clone(), stk_state),
                                    Deg { n: 5, d: 6 },
                                );
                                let return_addr = helper0 + last_off;
                                b.remove(
                                    "hperm_return",
                                    HasherMsg::return_state(return_addr, stk_next_state),
                                    Deg { n: 5, d: 6 },
                                );
                            },
                            Deg { n: 1, d: 2 },
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
                                    Deg { n: 5, d: 6 },
                                );
                                let return_addr = helper0 + mp_depth * cycle_len - LB::Expr::ONE;
                                b.remove(
                                    "mpverify_return",
                                    HasherMsg::return_hash(return_addr, old_root),
                                    Deg { n: 5, d: 6 },
                                );
                            },
                            Deg { n: 1, d: 2 },
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
                                    Deg { n: 4, d: 5 },
                                );
                                let old_return_addr = helper0.clone()
                                    + mr_depth.clone() * cycle_len.clone()
                                    - LB::Expr::ONE;
                                b.remove(
                                    "mrupdate_old_return",
                                    HasherMsg::return_hash(old_return_addr, old_root),
                                    Deg { n: 4, d: 5 },
                                );
                                let new_init_addr =
                                    helper0.clone() + mr_depth.clone() * cycle_len.clone();
                                b.remove(
                                    "mrupdate_new_init",
                                    HasherMsg::merkle_new_init(new_init_addr, mr_index, new_node),
                                    Deg { n: 4, d: 5 },
                                );
                                let new_return_addr = helper0
                                    + mr_depth * (cycle_len.clone() + cycle_len)
                                    - LB::Expr::ONE;
                                b.remove(
                                    "mrupdate_new_return",
                                    HasherMsg::return_hash(new_return_addr, stk_next_word_0),
                                    Deg { n: 4, d: 5 },
                                );
                            },
                            Deg { n: 3, d: 4 },
                        );
                    }

                    // --- MLOAD / MSTORE / MLOADW / MSTOREW (shared mem_header) ---
                    {
                        let mem_header = mem_header.clone();
                        g.remove(
                            "mload",
                            op_flags.mload(),
                            move || {
                                let value = stk_next_0.into();
                                mem_header.read_element(value)
                            },
                            Deg { n: 7, d: 8 },
                        );
                    }
                    {
                        let mem_header = mem_header.clone();
                        g.remove(
                            "mstore",
                            op_flags.mstore(),
                            move || {
                                let value = s1.into();
                                mem_header.write_element(value)
                            },
                            Deg { n: 7, d: 8 },
                        );
                    }
                    {
                        let mem_header = mem_header.clone();
                        g.remove(
                            "mloadw",
                            op_flags.mloadw(),
                            move || {
                                let word = array::from_fn(|i| stk_next.get(i).into());
                                mem_header.read_word(word)
                            },
                            Deg { n: 7, d: 8 },
                        );
                    }
                    {
                        let mem_header = mem_header;
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
                                mem_header.write_word(word)
                            },
                            Deg { n: 7, d: 8 },
                        );
                    }

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
                            let header0 = MemoryHeader {
                                ctx: sys_ctx.into(),
                                addr: addr0,
                                clk: clk.into(),
                            };
                            let header1 = MemoryHeader {
                                ctx: sys_ctx.into(),
                                addr: addr1,
                                clk: clk.into(),
                            };
                            b.remove("mstream_word0", header0.read_word(word0), Deg { n: 5, d: 6 });
                            b.remove("mstream_word1", header1.read_word(word1), Deg { n: 5, d: 6 });
                        },
                        Deg { n: 1, d: 2 },
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
                            let header0 = MemoryHeader {
                                ctx: sys_ctx.into(),
                                addr: addr0,
                                clk: clk.into(),
                            };
                            let header1 = MemoryHeader {
                                ctx: sys_ctx.into(),
                                addr: addr1,
                                clk: clk.into(),
                            };
                            b.remove("pipe_word0", header0.write_word(word0), Deg { n: 5, d: 6 });
                            b.remove("pipe_word1", header1.write_word(word1), Deg { n: 5, d: 6 });
                        },
                        Deg { n: 1, d: 2 },
                    );

                    // --- CRYPTOSTREAM ---
                    // Two word reads (plaintext from src_ptr, src_ptr + 4) followed by two word
                    // writes (ciphertext to dst_ptr, dst_ptr + 4). The rate lives on
                    // `local.stack[0..8]`, and the ciphertext on `next.stack[0..8]`; the
                    // plaintext is recovered algebraically as `cipher - rate`.
                    let src_ptr = stk.get(12);
                    let dst_ptr = stk.get(13);
                    g.batch(
                        "cryptostream",
                        op_flags.cryptostream(),
                        move |b| {
                            let src0: LB::Expr = src_ptr.into();
                            let src1: LB::Expr = src0.clone() + LB::Expr::from_u16(4);
                            let dst0: LB::Expr = dst_ptr.into();
                            let dst1: LB::Expr = dst0.clone() + LB::Expr::from_u16(4);
                            let rate: [LB::Expr; 8] = array::from_fn(|i| stk.get(i).into());
                            let cipher: [LB::Expr; 8] = array::from_fn(|i| stk_next.get(i).into());
                            let plain: [LB::Expr; 8] =
                                array::from_fn(|i| cipher[i].clone() - rate[i].clone());
                            let plain_word0: [LB::Expr; 4] = array::from_fn(|i| plain[i].clone());
                            let plain_word1: [LB::Expr; 4] =
                                array::from_fn(|i| plain[4 + i].clone());
                            let cipher_word0: [LB::Expr; 4] = array::from_fn(|i| cipher[i].clone());
                            let cipher_word1: [LB::Expr; 4] =
                                array::from_fn(|i| cipher[4 + i].clone());
                            let read_header0 = MemoryHeader {
                                ctx: sys_ctx.into(),
                                addr: src0,
                                clk: clk.into(),
                            };
                            let read_header1 = MemoryHeader {
                                ctx: sys_ctx.into(),
                                addr: src1,
                                clk: clk.into(),
                            };
                            let write_header0 = MemoryHeader {
                                ctx: sys_ctx.into(),
                                addr: dst0,
                                clk: clk.into(),
                            };
                            let write_header1 = MemoryHeader {
                                ctx: sys_ctx.into(),
                                addr: dst1,
                                clk: clk.into(),
                            };
                            b.remove(
                                "cryptostream_read0",
                                read_header0.read_word(plain_word0),
                                Deg { n: 4, d: 5 },
                            );
                            b.remove(
                                "cryptostream_read1",
                                read_header1.read_word(plain_word1),
                                Deg { n: 4, d: 5 },
                            );
                            b.remove(
                                "cryptostream_write0",
                                write_header0.write_word(cipher_word0),
                                Deg { n: 4, d: 5 },
                            );
                            b.remove(
                                "cryptostream_write1",
                                write_header1.write_word(cipher_word1),
                                Deg { n: 4, d: 5 },
                            );
                        },
                        Deg { n: 3, d: 4 },
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
                        Deg { n: 7, d: 8 },
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
                        Deg { n: 7, d: 8 },
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
                        Deg { n: 5, d: 6 },
                    );

                    // --- LOGPRECOMPILE ---
                    g.batch(
                        "logprecompile",
                        op_flags.log_precompile(),
                        move |b| {
                            let log_addr: LB::Expr = log_addr.into();
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
                            b.remove(
                                "logprecompile_init",
                                HasherMsg::linear_hash_init(log_addr.clone(), logpre_in),
                                Deg { n: 5, d: 6 },
                            );
                            let return_addr = log_addr + last_off;
                            b.remove(
                                "logprecompile_return",
                                HasherMsg::return_state(return_addr, logpre_out),
                                Deg { n: 5, d: 6 },
                            );
                        },
                        Deg { n: 1, d: 2 },
                    );
                },
                Deg { n: 7, d: 8 },
            );
        },
        Deg { n: 7, d: 8 },
    );
}
