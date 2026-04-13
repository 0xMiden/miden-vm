//! Chiplet requests bus (M3 / `BUS_CHIPLETS`).
//!
//! Decoder-side requests into the hasher, bitwise, memory, ACE init, and kernel ROM chiplets.
//!
//! Every interaction (cached and uncached) is folded into one column via a single
//! [`super::super::LookupColumn::group_with_cached_encoding`] call: the control-block variants
//! use the cached path (shared `prefix + LINEAR_HASH_LABEL + addr_next·β¹ + h[0..8]·β³..β¹⁰`
//! fragment with the opcode spliced at β¹²), and every remaining interaction rides through
//! `add` / `remove` / `batch` / `insert` on the same group handle. The canonical and encoded
//! closures share the non-cached tail through a private [`CreqCtx`] struct whose
//! [`CreqCtx::emit_non_cached`] method is generic over `G: LookupGroup`.

use core::array;

use miden_core::{FMP_ADDR, FMP_INIT_VALUE, field::PrimeCharacteristicRing, operations::opcodes};

use crate::{
    Felt, MainTraceRow,
    constraints::{
        logup_msg::*,
        lookup::{
            EncodedLookupGroup, LookupBatch, LookupBuilder, LookupColumn, LookupGroup,
            bus_id::BUS_CHIPLETS,
        },
        op_flags::{ExprDecoderAccess, OpFlags},
    },
    trace::{
        chiplets::hasher::{HASH_CYCLE_LEN, LINEAR_HASH_LABEL},
        decoder::{ADDR_COL_IDX, HASHER_STATE_RANGE, USER_OP_HELPERS_OFFSET},
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
    local: &MainTraceRow<LB::Var>,
    next: &MainTraceRow<LB::Var>,
) where
    LB: LookupBuilder<F = Felt>,
{
    let ctx = CreqCtx::<LB>::new(local, next);

    let f_join = ctx.op_flags.join();
    let f_split = ctx.op_flags.split();
    let f_loop = ctx.op_flags.loop_op();
    let f_span = ctx.op_flags.span();
    let f_call = ctx.op_flags.call();
    let f_syscall = ctx.op_flags.syscall();
    let call_fmp_msg = ctx.call_fmp_msg.clone();
    let syscall_krom_msg = ctx.syscall_krom_msg.clone();

    builder.column(|col| {
        col.group_with_cached_encoding(
            // CANONICAL (prover-path) — six individual control-block removes + the non-cached
            // tail. Mirrors the legacy `fold` closure in `g_creq::set.add_group_with(...)`.
            |g| {
                let he = ctx.he.clone();
                let addr_next_e = ctx.addr_next_e.clone();
                g.remove(f_join.clone(), || {
                    HasherMsg::control_block(addr_next_e.clone(), &he, opcodes::JOIN)
                });
                let he2 = ctx.he.clone();
                let addr_next_e2 = ctx.addr_next_e.clone();
                g.remove(f_split.clone(), || {
                    HasherMsg::control_block(addr_next_e2, &he2, opcodes::SPLIT)
                });
                let he3 = ctx.he.clone();
                let addr_next_e3 = ctx.addr_next_e.clone();
                g.remove(f_loop.clone(), || {
                    HasherMsg::control_block(addr_next_e3, &he3, opcodes::LOOP)
                });
                let he4 = ctx.he.clone();
                let addr_next_e4 = ctx.addr_next_e.clone();
                g.remove(f_span.clone(), || HasherMsg::control_block(addr_next_e4, &he4, 0));
                g.batch(f_call.clone(), |b| {
                    b.remove(HasherMsg::control_block(
                        ctx.addr_next_e.clone(),
                        &ctx.he,
                        opcodes::CALL,
                    ));
                    b.remove(call_fmp_msg.clone());
                });
                g.batch(f_syscall.clone(), |b| {
                    b.remove(HasherMsg::control_block(
                        ctx.addr_next_e.clone(),
                        &ctx.he,
                        opcodes::SYSCALL,
                    ));
                    b.remove(syscall_krom_msg.clone());
                });

                ctx.emit_non_cached(g);
            },
            // ENCODED (constraint-path) — cached control-block base + per-opcode β¹² splice;
            // the non-cached tail reuses the same generic helper.
            |ge| {
                let (ctrl_base, beta12) = {
                    let bp = ge.beta_powers();
                    let prefix = ge.bus_prefix(BUS_CHIPLETS);
                    // Label `LINEAR_HASH_LABEL + 16` at β⁰.
                    let mut base =
                        prefix + bp[0].clone() * LB::Expr::from_u16(LINEAR_HASH_LABEL as u16 + 16);
                    // addr at β¹.
                    base += bp[1].clone() * ctx.addr_next_e.clone();
                    // node_index = 0 at β² is elided.
                    // state[0..8] at β³..β¹⁰.
                    for (i, hi) in ctx.he.iter().enumerate() {
                        base += bp[3 + i].clone() * hi.clone();
                    }
                    // state[8..12] = 0 are elided.
                    (base, bp[12].clone())
                };
                let v = |opcode: u8| -> LB::ExprEF {
                    ctrl_base.clone() + beta12.clone() * LB::Expr::from_u16(opcode as u16)
                };

                let v_join = v(opcodes::JOIN);
                ge.insert_encoded(f_join.clone(), LB::Expr::NEG_ONE, || v_join);
                let v_split = v(opcodes::SPLIT);
                ge.insert_encoded(f_split.clone(), LB::Expr::NEG_ONE, || v_split);
                let v_loop = v(opcodes::LOOP);
                ge.insert_encoded(f_loop.clone(), LB::Expr::NEG_ONE, || v_loop);
                let v_span = v(0);
                ge.insert_encoded(f_span.clone(), LB::Expr::NEG_ONE, || v_span);

                let call_v = v(opcodes::CALL);
                ge.batch(f_call.clone(), |b| {
                    b.insert_encoded(LB::Expr::NEG_ONE, || call_v);
                    b.remove(call_fmp_msg.clone());
                });
                let syscall_v = v(opcodes::SYSCALL);
                ge.batch(f_syscall.clone(), |b| {
                    b.insert_encoded(LB::Expr::NEG_ONE, || syscall_v);
                    b.remove(syscall_krom_msg.clone());
                });

                ctx.emit_non_cached(ge);
            },
        );
    });
}

/// Pre-computed context for [`emit_chiplet_requests`].
///
/// Holds every row-derived value the canonical and encoded closures share, plus a generic
/// [`Self::emit_non_cached`] method that writes every non-control-block interaction against an
/// arbitrary [`LookupGroup`]. The simple `ConstraintGroup` (prover path) and encoded
/// `ConstraintGroupEncoded` (constraint path) both implement `LookupGroup`, so both closures
/// call the same helper and the bus body duplicates only the cached control-block section.
struct CreqCtx<LB: LookupBuilder<F = Felt>> {
    addr_e: LB::Expr,
    addr_next_e: LB::Expr,
    helper0_e: LB::Expr,
    last_off: LB::Expr,
    cycle_len: LB::Expr,
    he: [LB::Expr; 8],
    h_first: [LB::Expr; 4],
    zeros8: [LB::Expr; 8],
    mem: MemoryHeader<LB::Expr>,
    ctx_next_var: LB::Var,
    clk_var: LB::Var,
    s0: LB::Var,
    s1: LB::Var,
    stk_4: LB::Var,
    stk_5: LB::Var,
    stk_2: LB::Var,
    stk_3: LB::Var,
    stk_next_0: LB::Var,
    stk_state: [LB::Expr; 12],
    stk_next_state: [LB::Expr; 12],
    stk_words_0: [LB::Expr; 4],
    stk_next_words_0: [LB::Expr; 4],
    old_root: [LB::Expr; 4],
    new_node: [LB::Expr; 4],
    log_addr: LB::Var,
    logpre_in: [LB::Expr; 12],
    logpre_out: [LB::Expr; 12],
    ctx_local_e: LB::Expr,
    call_fmp_msg: MemoryMsg<LB::Expr>,
    syscall_krom_msg: KernelRomMsg<LB::Expr>,
    op_flags: OpFlags<LB::Expr>,
}

impl<LB> CreqCtx<LB>
where
    LB: LookupBuilder<F = Felt>,
{
    #[allow(clippy::too_many_lines)]
    fn new(local: &MainTraceRow<LB::Var>, next: &MainTraceRow<LB::Var>) -> Self {
        let dec = &local.decoder;
        let dec_next = &next.decoder;
        let stk = &local.stack;
        let stk_next = &next.stack;

        let addr = dec[ADDR_COL_IDX];
        let addr_next = dec_next[ADDR_COL_IDX];
        let h: [LB::Var; 8] = array::from_fn(|i| dec[HASHER_STATE_RANGE.start + i]);
        let helper0 = dec[USER_OP_HELPERS_OFFSET];

        let s0 = stk[0];
        let s1 = stk[1];
        let clk = local.clk;
        let ctx = local.ctx;
        let ctx_next = next.ctx;

        let he: [LB::Expr; 8] = h.map(Into::into);
        let h_first: [LB::Expr; 4] = array::from_fn(|i| he[i].clone());
        let stk_words_0: [LB::Expr; 4] = array::from_fn(|i| stk[i].into());
        let stk_next_words_0: [LB::Expr; 4] = array::from_fn(|i| stk_next[i].into());
        let stk_state: [LB::Expr; 12] = array::from_fn(|i| stk[i].into());
        let stk_next_state: [LB::Expr; 12] = array::from_fn(|i| stk_next[i].into());
        let old_root: [LB::Expr; 4] = array::from_fn(|i| stk[6 + i].into());
        let new_node: [LB::Expr; 4] = array::from_fn(|i| stk[10 + i].into());

        let addr_e: LB::Expr = addr.into();
        let addr_next_e: LB::Expr = addr_next.into();
        let helper0_e: LB::Expr = helper0.into();
        let last_off: LB::Expr = LB::Expr::from_u16((HASH_CYCLE_LEN - 1) as u16);
        let cycle_len: LB::Expr = LB::Expr::from_u16(HASH_CYCLE_LEN as u16);
        let zeros8: [LB::Expr; 8] = array::from_fn(|_| LB::Expr::ZERO);
        let ctx_local_e: LB::Expr = ctx.into();

        let mem = MemoryHeader {
            ctx: ctx_local_e.clone(),
            addr: s0.into(),
            clk: clk.into(),
        };

        // LOGPRECOMPILE input/output payloads.
        let log_addr: LB::Var = dec[USER_OP_HELPERS_OFFSET + HELPER_ADDR_IDX];
        let cap_prev: [LB::Var; 4] =
            array::from_fn(|i| dec[USER_OP_HELPERS_OFFSET + HELPER_CAP_PREV_RANGE.start + i]);
        let cap_next: [LB::Var; 4] = array::from_fn(|i| stk_next[STACK_CAP_NEXT_RANGE.start + i]);
        let logpre_in: [LB::Expr; 12] = [
            stk[STACK_COMM_RANGE.start].into(),
            stk[STACK_COMM_RANGE.start + 1].into(),
            stk[STACK_COMM_RANGE.start + 2].into(),
            stk[STACK_COMM_RANGE.start + 3].into(),
            stk[STACK_TAG_RANGE.start].into(),
            stk[STACK_TAG_RANGE.start + 1].into(),
            stk[STACK_TAG_RANGE.start + 2].into(),
            stk[STACK_TAG_RANGE.start + 3].into(),
            cap_prev[0].into(),
            cap_prev[1].into(),
            cap_prev[2].into(),
            cap_prev[3].into(),
        ];
        let logpre_out: [LB::Expr; 12] = [
            stk_next[STACK_R0_RANGE.start].into(),
            stk_next[STACK_R0_RANGE.start + 1].into(),
            stk_next[STACK_R0_RANGE.start + 2].into(),
            stk_next[STACK_R0_RANGE.start + 3].into(),
            stk_next[STACK_R1_RANGE.start].into(),
            stk_next[STACK_R1_RANGE.start + 1].into(),
            stk_next[STACK_R1_RANGE.start + 2].into(),
            stk_next[STACK_R1_RANGE.start + 3].into(),
            cap_next[0].into(),
            cap_next[1].into(),
            cap_next[2].into(),
            cap_next[3].into(),
        ];

        // CALL pushes an FMP write under a fresh MemoryHeader (ctx_next / FMP_ADDR / clk).
        let call_fmp_hdr = MemoryHeader {
            ctx: ctx_next.into(),
            addr: FMP_ADDR.into(),
            clk: clk.into(),
        };
        let call_fmp_msg = call_fmp_hdr.write_element(FMP_INIT_VALUE.into());

        // SYSCALL requests a kernel-ROM call with the h[0..4] digest.
        let syscall_krom_msg = KernelRomMsg::call(h_first.clone());

        let op_flags = OpFlags::new(ExprDecoderAccess::<LB::Var, LB::Expr>::new(local));

        Self {
            addr_e,
            addr_next_e,
            helper0_e,
            last_off,
            cycle_len,
            he,
            h_first,
            zeros8,
            mem,
            ctx_next_var: ctx_next,
            clk_var: clk,
            s0,
            s1,
            stk_2: stk[2],
            stk_3: stk[3],
            stk_4: stk[4],
            stk_5: stk[5],
            stk_next_0: stk_next[0],
            stk_state,
            stk_next_state,
            stk_words_0,
            stk_next_words_0,
            old_root,
            new_node,
            log_addr,
            logpre_in,
            logpre_out,
            ctx_local_e,
            call_fmp_msg,
            syscall_krom_msg,
            op_flags,
        }
    }

    /// Emit every chiplet-request interaction that is **not** a control-block variant.
    ///
    /// Identical algebra in both the prover (canonical) and constraint (encoded) closures of
    /// [`emit_chiplet_requests`]; shared here so the bus body duplicates only the cached
    /// control-block section.
    #[allow(clippy::too_many_lines)]
    fn emit_non_cached<G>(&self, g: &mut G)
    where
        G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
    {
        // RESPAN
        {
            let he = self.he.clone();
            let addr_next_e = self.addr_next_e.clone();
            g.remove(self.op_flags.respan(), move || {
                HasherMsg::absorption(addr_next_e - LB::Expr::ONE, he)
            });
        }

        // END
        {
            let h_first = self.h_first.clone();
            let addr_e = self.addr_e.clone();
            let last_off = self.last_off.clone();
            g.remove(self.op_flags.end(), move || {
                HasherMsg::return_hash(addr_e + last_off, h_first)
            });
        }

        // DYN
        g.batch(self.op_flags.dyn_op(), |b| {
            b.remove(HasherMsg::control_block(
                self.addr_next_e.clone(),
                &self.zeros8,
                opcodes::DYN,
            ));
            b.remove(self.mem.read_word(self.h_first.clone()));
        });

        // DYNCALL
        g.batch(self.op_flags.dyncall(), |b| {
            b.remove(HasherMsg::control_block(
                self.addr_next_e.clone(),
                &self.zeros8,
                opcodes::DYNCALL,
            ));
            b.remove(self.mem.read_word(self.h_first.clone()));
            let fmp_hdr = MemoryHeader {
                ctx: self.ctx_next_var.into(),
                addr: FMP_ADDR.into(),
                clk: self.clk_var.into(),
            };
            b.remove(fmp_hdr.write_element(FMP_INIT_VALUE.into()));
        });

        // HPERM
        g.batch(self.op_flags.hperm(), |b| {
            b.remove(HasherMsg::linear_hash_init(self.helper0_e.clone(), self.stk_state.clone()));
            b.remove(HasherMsg::return_state(
                self.helper0_e.clone() + self.last_off.clone(),
                self.stk_next_state.clone(),
            ));
        });

        // MPVERIFY
        let mp_index: LB::Expr = self.stk_5.into();
        let mp_depth: LB::Expr = self.stk_4.into();
        g.batch(self.op_flags.mpverify(), |b| {
            b.remove(HasherMsg::merkle_verify_init(
                self.helper0_e.clone(),
                mp_index.clone(),
                self.stk_words_0.clone(),
            ));
            b.remove(HasherMsg::return_hash(
                self.helper0_e.clone() + mp_depth * self.cycle_len.clone() - LB::Expr::ONE,
                self.old_root.clone(),
            ));
        });

        // MRUPDATE
        let mr_depth: LB::Expr = self.stk_4.into();
        let mr_index: LB::Expr = self.stk_5.into();
        g.batch(self.op_flags.mrupdate(), |b| {
            b.remove(HasherMsg::merkle_old_init(
                self.helper0_e.clone(),
                mr_index.clone(),
                self.stk_words_0.clone(),
            ));
            b.remove(HasherMsg::return_hash(
                self.helper0_e.clone() + mr_depth.clone() * self.cycle_len.clone() - LB::Expr::ONE,
                self.old_root.clone(),
            ));
            b.remove(HasherMsg::merkle_new_init(
                self.helper0_e.clone() + mr_depth.clone() * self.cycle_len.clone(),
                mr_index,
                self.new_node.clone(),
            ));
            b.remove(HasherMsg::return_hash(
                self.helper0_e.clone()
                    + mr_depth * (self.cycle_len.clone() + self.cycle_len.clone())
                    - LB::Expr::ONE,
                self.stk_next_words_0.clone(),
            ));
        });

        // MLOAD
        {
            let mem = self.mem.clone();
            let e: LB::Expr = self.stk_next_0.into();
            g.remove(self.op_flags.mload(), move || mem.read_element(e));
        }

        // MSTORE
        {
            let mem = self.mem.clone();
            let e: LB::Expr = self.s1.into();
            g.remove(self.op_flags.mstore(), move || mem.write_element(e));
        }

        // MLOADW
        {
            let mem = self.mem.clone();
            let word = self.stk_next_words_0.clone();
            g.remove(self.op_flags.mloadw(), move || mem.read_word(word));
        }

        // MSTOREW
        {
            let mem = self.mem.clone();
            let word: [LB::Expr; 4] =
                [self.s1.into(), self.stk_2.into(), self.stk_3.into(), self.stk_4.into()];
            g.remove(self.op_flags.mstorew(), move || mem.write_word(word));
        }

        // U32AND
        {
            let s0 = self.s0;
            let s1 = self.s1;
            let sn0 = self.stk_next_0;
            g.remove(self.op_flags.u32and(), move || {
                BitwiseMsg::and(s0.into(), s1.into(), sn0.into())
            });
        }

        // U32XOR
        {
            let s0 = self.s0;
            let s1 = self.s1;
            let sn0 = self.stk_next_0;
            g.remove(self.op_flags.u32xor(), move || {
                BitwiseMsg::xor(s0.into(), s1.into(), sn0.into())
            });
        }

        // EVALCIRCUIT
        {
            let clk: LB::Expr = self.clk_var.into();
            let ctx = self.ctx_local_e.clone();
            let ptr: LB::Expr = self.s0.into();
            let num_read: LB::Expr = self.s1.into();
            let num_eval: LB::Expr = self.stk_2.into();
            g.remove(self.op_flags.evalcircuit(), move || AceInitMsg {
                clk,
                ctx,
                ptr,
                num_read,
                num_eval,
            });
        }

        // LOGPRECOMPILE
        {
            let logpre_in = self.logpre_in.clone();
            let logpre_out = self.logpre_out.clone();
            let last_off = self.last_off.clone();
            let log_addr = self.log_addr;
            g.batch(self.op_flags.log_precompile(), move |b| {
                b.remove(HasherMsg::linear_hash_init(log_addr.into(), logpre_in));
                b.remove(HasherMsg::return_state(log_addr.into() + last_off, logpre_out));
            });
        }
    }
}
