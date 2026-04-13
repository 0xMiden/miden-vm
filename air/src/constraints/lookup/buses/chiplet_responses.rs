//! Chiplet responses bus (C1 / `BUS_CHIPLETS`).
//!
//! Chiplet-side responses from the hasher, bitwise, memory, ACE init, and kernel ROM
//! chiplets, all sharing one column.
//!
//! The hasher emits 7 independent hash-response variants whose encoding shares a big
//! `prefix + hasher_addr·β¹ + node_index·β²` fragment; the cached-encoding path precomputes
//! three shared β-weighted sums (`h[0..4]`, `h[0..12]`, `leaf[0..4]`, and the next-row
//! `rate[0..8]`) and splices per-variant label + payload tails on top.
//!
//! The bitwise / memory / kernel ROM responses sit in the same group as the hasher variants.
//! Each of them uses a runtime `label: E` expression muxed from chiplet columns. The
//! `LookupMessage<E, EF>` impls on `MemoryResponseMsg` / `BitwiseResponseMsg` /
//! `KernelRomResponseMsg` in `logup_msg.rs` keep the runtime-muxed encoding so the C1
//! transition stays at degree 8 (a per-variant split would bump it to 9).

use core::array;

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    Felt, MainTraceRow,
    constraints::{
        chiplets::{bitwise::P_BITWISE_K_TRANSITION, hasher},
        logup_msg::{
            AceInitMsg, BitwiseResponseMsg, HasherMsg, KernelRomResponseMsg, MemoryResponseMsg,
        },
        lookup::{
            EncodedLookupGroup, LookupBuilder, LookupColumn, LookupGroup, bus_id::BUS_CHIPLETS,
        },
    },
    trace::{
        CHIPLETS_OFFSET,
        chiplets::{
            HASHER_NODE_INDEX_COL_IDX, HASHER_SELECTOR_COL_RANGE, HASHER_STATE_COL_RANGE,
            NUM_ACE_SELECTORS, NUM_BITWISE_SELECTORS, NUM_KERNEL_ROM_SELECTORS,
            NUM_MEMORY_SELECTORS,
            ace::{CLK_IDX, CTX_IDX, ID_0_IDX, PTR_IDX, READ_NUM_EVAL_IDX, SELECTOR_START_IDX},
            bitwise::{self, BITWISE_AND_LABEL, BITWISE_XOR_LABEL},
            hasher::{
                LINEAR_HASH_LABEL, MP_VERIFY_LABEL, MR_UPDATE_NEW_LABEL, MR_UPDATE_OLD_LABEL,
                RETURN_HASH_LABEL, RETURN_STATE_LABEL,
            },
            kernel_rom::{KERNEL_PROC_CALL_LABEL, KERNEL_PROC_INIT_LABEL},
            memory::{
                self, MEMORY_READ_ELEMENT_LABEL, MEMORY_READ_WORD_LABEL,
                MEMORY_WRITE_ELEMENT_LABEL, MEMORY_WRITE_WORD_LABEL,
            },
        },
    },
};

// Chiplet-local column offsets (relative to `local.chiplets[]`).
const S_START: usize = HASHER_SELECTOR_COL_RANGE.start - CHIPLETS_OFFSET;
const H_START: usize = HASHER_STATE_COL_RANGE.start - CHIPLETS_OFFSET;
const IDX_COL: usize = HASHER_NODE_INDEX_COL_IDX - CHIPLETS_OFFSET;

/// Pre-computed context for [`emit_chiplet_responses`]. Holds every row-derived value the
/// canonical and encoded closures share and exposes helper methods that write against a
/// generic [`LookupGroup`].
///
/// The bitwise / memory / kernel ROM response interactions deliberately mirror the legacy
/// runtime-muxed encoding instead of splitting into per-label ME variants: the plan's R2/R3/R4
/// suggestion would have emitted 4 + 2 + 2 = 8 extra flag products, and the resulting `V_g`
/// contribution degree bumped C1's transition from 8 → 9. Using the legacy
/// [`MemoryResponseMsg`] / [`BitwiseResponseMsg`] / [`KernelRomResponseMsg`] structs
/// (through their new `LookupMessage<E, EF>` impls) keeps the C1 transition degree at 8,
/// matching the old `enforce_chiplet` output bit-for-bit.
struct CrespCtx<LB: LookupBuilder<F = Felt>> {
    hasher_addr: LB::Expr,
    node_index: LB::Expr,
    h: [LB::Expr; 12],
    h_next: [LB::Expr; 12],
    leaf: [LB::Expr; 4],
    // Hasher flags (7 ME variants).
    f_bp: LB::Expr,
    f_mp: LB::Expr,
    f_mv: LB::Expr,
    f_mu: LB::Expr,
    f_hout: LB::Expr,
    f_sout: LB::Expr,
    f_abp: LB::Expr,
    // Bitwise (single interaction with runtime-muxed label).
    is_bitwise_responding: LB::Expr,
    bw_label: LB::Expr,
    bw_a: LB::Expr,
    bw_b: LB::Expr,
    bw_z: LB::Expr,
    // Memory (single interaction with runtime-muxed label + is_word).
    is_memory: LB::Expr,
    mem_label: LB::Expr,
    mem_ctx: LB::Expr,
    mem_addr: LB::Expr,
    mem_clk: LB::Expr,
    mem_is_word: LB::Expr,
    mem_element: LB::Expr,
    mem_word: [LB::Expr; 4],
    // ACE init.
    is_ace: LB::Expr,
    ace_clk: LB::Expr,
    ace_ctx: LB::Expr,
    ace_ptr: LB::Expr,
    ace_num_read_rows: LB::Expr,
    ace_num_eval_rows: LB::Expr,
    // Kernel ROM (single interaction with runtime-muxed label).
    is_kernel_rom: LB::Expr,
    krom_label: LB::Expr,
    krom_digest: [LB::Expr; 4],
}

impl<LB> CrespCtx<LB>
where
    LB: LookupBuilder<F = Felt>,
{
    #[allow(clippy::too_many_lines)]
    fn new(
        local: &MainTraceRow<LB::Var>,
        next: &MainTraceRow<LB::Var>,
        cycle_row_0: LB::Expr,
        cycle_row_31: LB::Expr,
        k_transition: LB::Expr,
    ) -> Self {
        // Chiplet selector flags.
        let s0: LB::Expr = local.chiplets[0].into();
        let s1: LB::Expr = local.chiplets[1].into();
        let s2: LB::Expr = local.chiplets[2].into();
        let s3: LB::Expr = local.chiplets[3].into();
        let s4: LB::Expr = local.chiplets[4].into();

        let is_hasher: LB::Expr = LB::Expr::ONE - s0.clone();

        // Hasher internal selectors.
        let hs0: LB::Expr = local.chiplets[S_START].into();
        let hs1: LB::Expr = local.chiplets[S_START + 1].into();
        let hs2: LB::Expr = local.chiplets[S_START + 2].into();

        // Hasher state and node index.
        let h: [LB::Expr; 12] = array::from_fn(|i| local.chiplets[H_START + i].into());
        let h_next: [LB::Expr; 12] = array::from_fn(|i| next.chiplets[H_START + i].into());
        let node_index: LB::Expr = local.chiplets[IDX_COL].into();
        let node_index_next: LB::Expr = next.chiplets[IDX_COL].into();

        // hasher_addr = clk + 1.
        let clk_e: LB::Expr = local.clk.into();
        let hasher_addr: LB::Expr = clk_e + LB::Expr::ONE;

        // bit = node_index - 2·node_index_next.
        let bit: LB::Expr = node_index.clone() - node_index_next.double();
        let leaf: [LB::Expr; 4] = array::from_fn(|i| {
            (LB::Expr::ONE - bit.clone()) * h[i].clone() + bit.clone() * h[i + 4].clone()
        });

        // Hasher response flags.
        let f_bp = is_hasher.clone()
            * hasher::flags::f_bp(cycle_row_0.clone(), hs0.clone(), hs1.clone(), hs2.clone());
        let f_mp = is_hasher.clone()
            * hasher::flags::f_mp(cycle_row_0.clone(), hs0.clone(), hs1.clone(), hs2.clone());
        let f_mv = is_hasher.clone()
            * hasher::flags::f_mv(cycle_row_0.clone(), hs0.clone(), hs1.clone(), hs2.clone());
        let f_mu = is_hasher.clone()
            * hasher::flags::f_mu(cycle_row_0, hs0.clone(), hs1.clone(), hs2.clone());
        let f_hout = is_hasher.clone()
            * hasher::flags::f_hout(cycle_row_31.clone(), hs0.clone(), hs1.clone(), hs2.clone());
        let f_sout = is_hasher.clone()
            * hasher::flags::f_sout(cycle_row_31.clone(), hs0.clone(), hs1.clone(), hs2.clone());
        let f_abp = is_hasher * hasher::flags::f_abp(cycle_row_31, hs0, hs1, hs2);

        // Bitwise (runtime-muxed sel → label).
        let is_bitwise_responding: LB::Expr =
            s0.clone() * (LB::Expr::ONE - s1.clone()) * (LB::Expr::ONE - k_transition);
        let bw_offset = NUM_BITWISE_SELECTORS;
        let bw_sel: LB::Expr = local.chiplets[bw_offset].into();
        let bw_label: LB::Expr = (LB::Expr::ONE - bw_sel.clone())
            * LB::Expr::from(BITWISE_AND_LABEL)
            + bw_sel * LB::Expr::from(BITWISE_XOR_LABEL);
        let bw_a: LB::Expr = local.chiplets[bw_offset + bitwise::A_COL_IDX].into();
        let bw_b: LB::Expr = local.chiplets[bw_offset + bitwise::B_COL_IDX].into();
        let bw_z: LB::Expr = local.chiplets[bw_offset + bitwise::OUTPUT_COL_IDX].into();

        // Memory — keep the legacy runtime (is_read, is_word) mux so the C1 transition
        // degree stays at 8 (matches old `enforce_chiplet`).
        let is_memory: LB::Expr = s0.clone() * s1.clone() * (LB::Expr::ONE - s2.clone());
        let mem_offset = NUM_MEMORY_SELECTORS;
        let is_read: LB::Expr = local.chiplets[mem_offset + memory::IS_READ_COL_IDX].into();
        let is_word: LB::Expr = local.chiplets[mem_offset + memory::IS_WORD_ACCESS_COL_IDX].into();
        let mem_ctx: LB::Expr = local.chiplets[mem_offset + memory::CTX_COL_IDX].into();
        let mem_word_col: LB::Expr = local.chiplets[mem_offset + memory::WORD_COL_IDX].into();
        let mem_idx0: LB::Expr = local.chiplets[mem_offset + memory::IDX0_COL_IDX].into();
        let mem_idx1: LB::Expr = local.chiplets[mem_offset + memory::IDX1_COL_IDX].into();
        let mem_clk: LB::Expr = local.chiplets[mem_offset + memory::CLK_COL_IDX].into();
        let mem_addr: LB::Expr =
            mem_word_col + mem_idx1.clone() * LB::Expr::from_u16(2) + mem_idx0.clone();

        // Runtime-muxed label: (1-is_read)*write_label + is_read*read_label, each of which is
        // itself (1-is_word)*..._ELEMENT_LABEL + is_word*..._WORD_LABEL.
        let write_element = LB::Expr::from_u16(MEMORY_WRITE_ELEMENT_LABEL as u16);
        let write_word = LB::Expr::from_u16(MEMORY_WRITE_WORD_LABEL as u16);
        let read_element = LB::Expr::from_u16(MEMORY_READ_ELEMENT_LABEL as u16);
        let read_word = LB::Expr::from_u16(MEMORY_READ_WORD_LABEL as u16);
        let write_label =
            (LB::Expr::ONE - is_word.clone()) * write_element + is_word.clone() * write_word;
        let read_label =
            (LB::Expr::ONE - is_word.clone()) * read_element + is_word.clone() * read_word;
        let mem_label: LB::Expr =
            (LB::Expr::ONE - is_read.clone()) * write_label + is_read * read_label;

        let v0: LB::Expr = local.chiplets[mem_offset + memory::V_COL_RANGE.start].into();
        let v1: LB::Expr = local.chiplets[mem_offset + memory::V_COL_RANGE.start + 1].into();
        let v2: LB::Expr = local.chiplets[mem_offset + memory::V_COL_RANGE.start + 2].into();
        let v3: LB::Expr = local.chiplets[mem_offset + memory::V_COL_RANGE.start + 3].into();
        let mem_element: LB::Expr =
            v0.clone() * (LB::Expr::ONE - mem_idx0.clone()) * (LB::Expr::ONE - mem_idx1.clone())
                + v1.clone() * mem_idx0.clone() * (LB::Expr::ONE - mem_idx1.clone())
                + v2.clone() * (LB::Expr::ONE - mem_idx0.clone()) * mem_idx1.clone()
                + v3.clone() * mem_idx0 * mem_idx1;
        let mem_word = [v0, v1, v2, v3];

        // ACE init.
        let ace_start: LB::Expr = local.chiplets[NUM_ACE_SELECTORS + SELECTOR_START_IDX].into();
        let is_ace: LB::Expr =
            s0.clone() * s1.clone() * s2.clone() * (LB::Expr::ONE - s3.clone()) * ace_start;
        let ace_clk: LB::Expr = local.chiplets[NUM_ACE_SELECTORS + CLK_IDX].into();
        let ace_ctx: LB::Expr = local.chiplets[NUM_ACE_SELECTORS + CTX_IDX].into();
        let ace_ptr: LB::Expr = local.chiplets[NUM_ACE_SELECTORS + PTR_IDX].into();
        let ace_read_num_eval: LB::Expr =
            local.chiplets[NUM_ACE_SELECTORS + READ_NUM_EVAL_IDX].into();
        let ace_num_eval_rows: LB::Expr = ace_read_num_eval + LB::Expr::ONE;
        let ace_id_0: LB::Expr = local.chiplets[NUM_ACE_SELECTORS + ID_0_IDX].into();
        let ace_num_read_rows: LB::Expr = ace_id_0 + LB::Expr::ONE - ace_num_eval_rows.clone();

        // Kernel ROM (runtime-muxed s_first → label).
        let is_kernel_rom: LB::Expr = s0 * s1 * s2 * s3 * (LB::Expr::ONE - s4);
        let s_first: LB::Expr = local.chiplets[NUM_KERNEL_ROM_SELECTORS].into();
        let init_label: LB::Expr = LB::Expr::from(KERNEL_PROC_INIT_LABEL);
        let call_label: LB::Expr = LB::Expr::from(KERNEL_PROC_CALL_LABEL);
        let krom_label: LB::Expr =
            s_first.clone() * init_label + (LB::Expr::ONE - s_first) * call_label;
        let krom_digest: [LB::Expr; 4] =
            array::from_fn(|i| local.chiplets[NUM_KERNEL_ROM_SELECTORS + 1 + i].into());

        Self {
            hasher_addr,
            node_index,
            h,
            h_next,
            leaf,
            f_bp,
            f_mp,
            f_mv,
            f_mu,
            f_hout,
            f_sout,
            f_abp,
            is_bitwise_responding,
            bw_label,
            bw_a,
            bw_b,
            bw_z,
            is_memory,
            mem_label,
            mem_ctx,
            mem_addr,
            mem_clk,
            mem_is_word: is_word,
            mem_element,
            mem_word,
            is_ace,
            ace_clk,
            ace_ctx,
            ace_ptr,
            ace_num_read_rows,
            ace_num_eval_rows,
            is_kernel_rom,
            krom_label,
            krom_digest,
        }
    }

    /// Emit every non-hasher interaction (bitwise / memory / ACE / kernel ROM) into the
    /// given group. Shared between the canonical and encoded closures.
    ///
    /// Each interaction uses the legacy runtime-muxed encoding through the
    /// `LookupMessage<E, EF>` impl on [`BitwiseResponseMsg`] / [`MemoryResponseMsg`] /
    /// [`KernelRomResponseMsg`] — see `logup_msg.rs`. This preserves the C1 transition
    /// degree at 8.
    fn emit_non_hasher<G>(&self, g: &mut G)
    where
        G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
    {
        // Bitwise: single interaction with a runtime-muxed label.
        {
            let label = self.bw_label.clone();
            let a = self.bw_a.clone();
            let b = self.bw_b.clone();
            let z = self.bw_z.clone();
            g.add(self.is_bitwise_responding.clone(), move || BitwiseResponseMsg {
                label,
                a,
                b,
                z,
            });
        }

        // Memory: single interaction with runtime-muxed label + is_word mux between the
        // element and word encodings inside `MemoryResponseMsg::encode`.
        {
            let label = self.mem_label.clone();
            let ctx = self.mem_ctx.clone();
            let addr = self.mem_addr.clone();
            let clk = self.mem_clk.clone();
            let is_word = self.mem_is_word.clone();
            let element = self.mem_element.clone();
            let word = self.mem_word.clone();
            g.add(self.is_memory.clone(), move || MemoryResponseMsg {
                label,
                ctx,
                addr,
                clk,
                is_word,
                element,
                word,
            });
        }

        // ACE init.
        {
            let clk = self.ace_clk.clone();
            let ctx = self.ace_ctx.clone();
            let ptr = self.ace_ptr.clone();
            let num_read = self.ace_num_read_rows.clone();
            let num_eval = self.ace_num_eval_rows.clone();
            g.add(self.is_ace.clone(), move || AceInitMsg { clk, ctx, ptr, num_read, num_eval });
        }

        // Kernel ROM: single interaction with a runtime-muxed label.
        {
            let label = self.krom_label.clone();
            let digest = self.krom_digest.clone();
            g.add(self.is_kernel_rom.clone(), move || KernelRomResponseMsg { label, digest });
        }
    }

    /// Emit the 7 hasher response variants through the simple `add` surface (prover path).
    #[allow(clippy::too_many_lines)]
    fn emit_hasher_canonical<G>(&self, g: &mut G)
    where
        G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
    {
        {
            let addr = self.hasher_addr.clone();
            let ni = self.node_index.clone();
            let st = self.h.clone();
            g.add(self.f_bp.clone(), move || HasherMsg::State {
                label_value: LINEAR_HASH_LABEL as u16 + 16,
                addr,
                node_index: ni,
                state: st,
            });
        }
        {
            let addr = self.hasher_addr.clone();
            let ni = self.node_index.clone();
            let word = self.leaf.clone();
            g.add(self.f_mp.clone(), move || HasherMsg::Word {
                label_value: MP_VERIFY_LABEL as u16 + 16,
                addr,
                node_index: ni,
                word,
            });
        }
        {
            let addr = self.hasher_addr.clone();
            let ni = self.node_index.clone();
            let word = self.leaf.clone();
            g.add(self.f_mv.clone(), move || HasherMsg::Word {
                label_value: MR_UPDATE_OLD_LABEL as u16 + 16,
                addr,
                node_index: ni,
                word,
            });
        }
        {
            let addr = self.hasher_addr.clone();
            let ni = self.node_index.clone();
            let word = self.leaf.clone();
            g.add(self.f_mu.clone(), move || HasherMsg::Word {
                label_value: MR_UPDATE_NEW_LABEL as u16 + 16,
                addr,
                node_index: ni,
                word,
            });
        }
        {
            let addr = self.hasher_addr.clone();
            let ni = self.node_index.clone();
            let word = [self.h[0].clone(), self.h[1].clone(), self.h[2].clone(), self.h[3].clone()];
            g.add(self.f_hout.clone(), move || HasherMsg::Word {
                label_value: RETURN_HASH_LABEL as u16 + 32,
                addr,
                node_index: ni,
                word,
            });
        }
        {
            let addr = self.hasher_addr.clone();
            let ni = self.node_index.clone();
            let st = self.h.clone();
            g.add(self.f_sout.clone(), move || HasherMsg::State {
                label_value: RETURN_STATE_LABEL as u16 + 32,
                addr,
                node_index: ni,
                state: st,
            });
        }
        {
            let addr = self.hasher_addr.clone();
            let ni = self.node_index.clone();
            let rate: [LB::Expr; 8] = array::from_fn(|i| self.h_next[i].clone());
            g.add(self.f_abp.clone(), move || HasherMsg::Rate {
                label_value: LINEAR_HASH_LABEL as u16 + 32,
                addr,
                node_index: ni,
                rate,
            });
        }
    }

    /// Emit the 7 hasher response variants through the cached-encoding path (constraint
    /// path). Mirrors the legacy `fold_constraints` closure — precomputes `base` + the
    /// three shared β-weighted payload sums and splices the per-variant label + tail.
    fn emit_hasher_encoded<GE>(&self, ge: &mut GE)
    where
        GE: EncodedLookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
    {
        let (base, h4, h12, leaf4, rate8) = {
            let bp = ge.beta_powers();
            let prefix = ge.bus_prefix(BUS_CHIPLETS);
            let base = prefix
                + bp[1].clone() * self.hasher_addr.clone()
                + bp[2].clone() * self.node_index.clone();
            let mut h4 = LB::ExprEF::ZERO;
            for (i, hi) in self.h.iter().take(4).enumerate() {
                h4 += bp[3 + i].clone() * hi.clone();
            }
            let mut h12 = h4.clone();
            for (i, hi) in self.h.iter().enumerate().skip(4) {
                h12 += bp[3 + i].clone() * hi.clone();
            }
            let mut leaf4 = LB::ExprEF::ZERO;
            for (i, li) in self.leaf.iter().enumerate() {
                leaf4 += bp[3 + i].clone() * li.clone();
            }
            let mut rate8 = LB::ExprEF::ZERO;
            for (i, hi) in self.h_next.iter().take(8).enumerate() {
                rate8 += bp[3 + i].clone() * hi.clone();
            }
            (base, h4, h12, leaf4, rate8)
        };
        let bp0 = ge.beta_powers()[0].clone();

        let v = |label: u16, suffix: &LB::ExprEF| -> LB::ExprEF {
            base.clone() + bp0.clone() * LB::Expr::from_u16(label) + suffix.clone()
        };

        let v_bp = v(LINEAR_HASH_LABEL as u16 + 16, &h12);
        ge.insert_encoded(self.f_bp.clone(), LB::Expr::ONE, || v_bp);
        let v_mp = v(MP_VERIFY_LABEL as u16 + 16, &leaf4);
        ge.insert_encoded(self.f_mp.clone(), LB::Expr::ONE, || v_mp);
        let v_mv = v(MR_UPDATE_OLD_LABEL as u16 + 16, &leaf4);
        ge.insert_encoded(self.f_mv.clone(), LB::Expr::ONE, || v_mv);
        let v_mu = v(MR_UPDATE_NEW_LABEL as u16 + 16, &leaf4);
        ge.insert_encoded(self.f_mu.clone(), LB::Expr::ONE, || v_mu);
        let v_hout = v(RETURN_HASH_LABEL as u16 + 32, &h4);
        ge.insert_encoded(self.f_hout.clone(), LB::Expr::ONE, || v_hout);
        let v_sout = v(RETURN_STATE_LABEL as u16 + 32, &h12);
        ge.insert_encoded(self.f_sout.clone(), LB::Expr::ONE, || v_sout);
        let v_abp = v(LINEAR_HASH_LABEL as u16 + 32, &rate8);
        ge.insert_encoded(self.f_abp.clone(), LB::Expr::ONE, || v_abp);
    }
}

/// Emit the chiplet responses bus (C1).
pub(in crate::constraints::lookup) fn emit_chiplet_responses<LB>(
    builder: &mut LB,
    local: &MainTraceRow<LB::Var>,
    next: &MainTraceRow<LB::Var>,
) where
    LB: LookupBuilder<F = Felt>,
{
    // Periodic values (matches `enforce_chiplet` index scheme).
    let (cycle_row_0, cycle_row_31, k_transition) = {
        let p = builder.periodic_values();
        let cycle_row_0: LB::Expr = p[hasher::periodic::P_CYCLE_ROW_0].into();
        let cycle_row_31: LB::Expr = p[hasher::periodic::P_CYCLE_ROW_31].into();
        let k_transition: LB::Expr = p[P_BITWISE_K_TRANSITION].into();
        (cycle_row_0, cycle_row_31, k_transition)
    };

    let ctx = CrespCtx::<LB>::new(local, next, cycle_row_0, cycle_row_31, k_transition);

    builder.column(|col| {
        col.group_with_cached_encoding(
            |g| {
                ctx.emit_hasher_canonical(g);
                ctx.emit_non_hasher(g);
            },
            |ge| {
                ctx.emit_hasher_encoded(ge);
                ctx.emit_non_hasher(ge);
            },
        );
    });
}
