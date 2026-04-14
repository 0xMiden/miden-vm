//! Chiplet responses bus (C1 / `BUS_CHIPLETS`).
//!
//! Chiplet-side responses from the hasher, bitwise, memory, ACE, and kernel ROM chiplets,
//! all sharing one LogUp column.
//!
//! The 7 hasher response variants are gated on hasher controller rows (`s_ctrl = 1`) via
//! the per-variant `(s0, s1, s2, is_boundary)` combinations that mirror 2856's running
//! product `compute_hasher_response`. Non-hasher variants (bitwise / memory / ACE init /
//! kernel ROM) are gated on their respective chiplet sections under virtual
//! `s0 = 1 − s_ctrl − s_perm`.
//!
//! Memory uses the runtime-muxed [`MemoryResponseMsg`] encoding (label + is_word mux)
//! instead of splitting into 4 per-label variants — this keeps the C1 transition degree
//! at 8 (a per-variant split would bump it to 9), matching the 2856 running-product shape.

use core::{array, borrow::Borrow};

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    Felt, MainCols,
    constraints::{
        chiplets::columns::PeriodicCols,
        logup_msg::{
            AceInitMsg, BitwiseResponseMsg, HasherMsg, KernelRomResponseMsg, MemoryResponseMsg,
        },
        lookup::{LookupBuilder, LookupColumn, LookupGroup},
    },
    trace::{
        CHIPLETS_OFFSET,
        chiplets::{
            HASHER_IS_BOUNDARY_COL_IDX, HASHER_NODE_INDEX_COL_IDX, HASHER_SELECTOR_COL_RANGE,
            HASHER_STATE_COL_RANGE, NUM_ACE_SELECTORS, NUM_BITWISE_SELECTORS,
            NUM_KERNEL_ROM_SELECTORS, NUM_MEMORY_SELECTORS,
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

// Label offsets matching 2856's running product.
const INPUT_LABEL_OFFSET: u16 = 16;
const OUTPUT_LABEL_OFFSET: u16 = 32;

// Chiplet-local column offsets (relative to `local.chiplets[]`).
const S_START: usize = HASHER_SELECTOR_COL_RANGE.start - CHIPLETS_OFFSET;
const H_START: usize = HASHER_STATE_COL_RANGE.start - CHIPLETS_OFFSET;
const IDX_COL: usize = HASHER_NODE_INDEX_COL_IDX - CHIPLETS_OFFSET;
const IS_BOUNDARY_COL: usize = HASHER_IS_BOUNDARY_COL_IDX - CHIPLETS_OFFSET;

/// Emit the chiplet responses bus (C1).
#[allow(clippy::too_many_lines)]
pub(in crate::constraints::lookup) fn emit_chiplet_responses<LB>(
    builder: &mut LB,
    local: &MainCols<LB::Var>,
    next: &MainCols<LB::Var>,
) where
    LB: LookupBuilder<F = Felt>,
{
    // Read the typed periodic column view (used for bitwise k_transition).
    let k_transition: LB::Expr = {
        let periodic: &PeriodicCols<LB::PeriodicVar> = builder.periodic_values().borrow();
        periodic.bitwise.k_transition.into()
    };

    // Chiplet-level selectors.
    let s_ctrl: LB::Expr = local.chiplets[0].into();
    let s_perm: LB::Expr = local.perm_seg.into();
    let virtual_s0: LB::Expr = LB::Expr::ONE - s_ctrl.clone() - s_perm;
    let s1: LB::Expr = local.chiplets[1].into();
    let s2: LB::Expr = local.chiplets[2].into();
    let s3: LB::Expr = local.chiplets[3].into();
    let s4: LB::Expr = local.chiplets[4].into();

    // Precomputed chiplet-active flags (matches `build_chiplet_selectors`).
    let s01: LB::Expr = virtual_s0.clone() * s1.clone();
    let s012: LB::Expr = s01.clone() * s2.clone();
    let s0123: LB::Expr = s012.clone() * s3.clone();
    let s01234: LB::Expr = s0123.clone() * s4;

    let is_bitwise: LB::Expr = virtual_s0 - s01.clone();
    let is_memory: LB::Expr = s01 - s012.clone();
    let is_ace: LB::Expr = s012 - s0123.clone();
    let is_kernel_rom: LB::Expr = s0123 - s01234;

    // Hasher-internal sub-selectors and state (valid on controller rows, where s_ctrl = 1).
    let hs0: LB::Expr = local.chiplets[S_START].into();
    let hs1: LB::Expr = local.chiplets[S_START + 1].into();
    let hs2: LB::Expr = local.chiplets[S_START + 2].into();
    let is_boundary: LB::Expr = local.chiplets[IS_BOUNDARY_COL].into();

    let h: [LB::Expr; 12] = array::from_fn(|i| local.chiplets[H_START + i].into());
    let h_next: [LB::Expr; 12] = array::from_fn(|i| next.chiplets[H_START + i].into());
    let node_index: LB::Expr = local.chiplets[IDX_COL].into();
    let node_index_next: LB::Expr = next.chiplets[IDX_COL].into();

    // Address consistent with 2856: `addr_next = clk + 1`.
    let addr_next: LB::Expr = Into::<LB::Expr>::into(local.system.clk) + LB::Expr::ONE;

    // Merkle direction bit and leaf word. `leaf = (1-bit)·h[0..4] + bit·h[4..8]`.
    let bit: LB::Expr = node_index.clone() - node_index_next.double();
    let one_minus_bit = LB::Expr::ONE - bit.clone();
    let leaf: [LB::Expr; 4] =
        array::from_fn(|i| one_minus_bit.clone() * h[i].clone() + bit.clone() * h[i + 4].clone());

    // --- Hasher response flags ---
    // All gated by `controller_flag = s_ctrl`; composed with the per-row-type
    // `(s0, s1, s2, is_boundary)` combinations from 2856's `compute_hasher_response`.

    let not_hs0 = LB::Expr::ONE - hs0.clone();
    let not_hs1 = LB::Expr::ONE - hs1.clone();
    let not_hs2 = LB::Expr::ONE - hs2.clone();

    // Sponge start: input (hs0=1), hs1=hs2=0, is_boundary=1. Full 12-lane state.
    let f_sponge_start: LB::Expr =
        s_ctrl.clone() * hs0.clone() * not_hs1.clone() * not_hs2.clone() * is_boundary.clone();

    // Sponge RESPAN: input, hs1=hs2=0, is_boundary=0. Rate-only 8 lanes.
    let f_sponge_respan: LB::Expr = s_ctrl.clone()
        * hs0.clone()
        * not_hs1.clone()
        * not_hs2.clone()
        * (LB::Expr::ONE - is_boundary.clone());

    // Merkle tree input rows (is_boundary=1):
    //   f_mp = ctrl · hs0 · (1-hs1) · hs2 · is_boundary
    //   f_mv = ctrl · hs0 · hs1 · (1-hs2) · is_boundary
    //   f_mu = ctrl · hs0 · hs1 · hs2 · is_boundary
    let f_mp: LB::Expr =
        s_ctrl.clone() * hs0.clone() * not_hs1.clone() * hs2.clone() * is_boundary.clone();
    let f_mv: LB::Expr =
        s_ctrl.clone() * hs0.clone() * hs1.clone() * not_hs2.clone() * is_boundary.clone();
    let f_mu: LB::Expr = s_ctrl.clone() * hs0 * hs1.clone() * hs2.clone() * is_boundary.clone();

    // HOUT output: hs0=hs1=hs2=0 (always responds on digest). Degree 4 (no is_boundary).
    let f_hout: LB::Expr = s_ctrl.clone() * not_hs0.clone() * not_hs1.clone() * not_hs2.clone();

    // SOUT output with is_boundary=1 only (HPERM return).
    let f_sout: LB::Expr = s_ctrl * not_hs0 * not_hs1 * hs2 * is_boundary;

    // --- Non-hasher flags/payloads ---

    // Bitwise: responds only on the last row of the 8-row cycle (k_transition = 0).
    let is_bitwise_responding: LB::Expr = is_bitwise * (LB::Expr::ONE - k_transition);
    let bw_sel: LB::Expr = local.chiplets[NUM_BITWISE_SELECTORS].into();
    let bw_label: LB::Expr = (LB::Expr::ONE - bw_sel.clone()) * LB::Expr::from(BITWISE_AND_LABEL)
        + bw_sel * LB::Expr::from(BITWISE_XOR_LABEL);
    let bw_a: LB::Expr = local.chiplets[NUM_BITWISE_SELECTORS + bitwise::A_COL_IDX].into();
    let bw_b: LB::Expr = local.chiplets[NUM_BITWISE_SELECTORS + bitwise::B_COL_IDX].into();
    let bw_z: LB::Expr = local.chiplets[NUM_BITWISE_SELECTORS + bitwise::OUTPUT_COL_IDX].into();

    // Memory: runtime-muxed label + is_word mux keeps C1 transition at 8.
    let mem_offset = NUM_MEMORY_SELECTORS;
    let mem_is_read: LB::Expr = local.chiplets[mem_offset + memory::IS_READ_COL_IDX].into();
    let mem_is_word: LB::Expr = local.chiplets[mem_offset + memory::IS_WORD_ACCESS_COL_IDX].into();
    let mem_ctx: LB::Expr = local.chiplets[mem_offset + memory::CTX_COL_IDX].into();
    let mem_word_col: LB::Expr = local.chiplets[mem_offset + memory::WORD_COL_IDX].into();
    let mem_idx0: LB::Expr = local.chiplets[mem_offset + memory::IDX0_COL_IDX].into();
    let mem_idx1: LB::Expr = local.chiplets[mem_offset + memory::IDX1_COL_IDX].into();
    let mem_clk: LB::Expr = local.chiplets[mem_offset + memory::CLK_COL_IDX].into();
    let mem_addr: LB::Expr =
        mem_word_col + mem_idx1.clone() * LB::Expr::from_u16(2) + mem_idx0.clone();

    // Runtime label: `(1-is_read)*write_label + is_read*read_label`, each itself
    // `(1-is_word)*_ELEMENT + is_word*_WORD`.
    let one = LB::Expr::ONE;
    let write_elem = LB::Expr::from_u16(MEMORY_WRITE_ELEMENT_LABEL as u16);
    let write_word = LB::Expr::from_u16(MEMORY_WRITE_WORD_LABEL as u16);
    let read_elem = LB::Expr::from_u16(MEMORY_READ_ELEMENT_LABEL as u16);
    let read_word = LB::Expr::from_u16(MEMORY_READ_WORD_LABEL as u16);
    let write_label =
        (one.clone() - mem_is_word.clone()) * write_elem + mem_is_word.clone() * write_word;
    let read_label =
        (one.clone() - mem_is_word.clone()) * read_elem + mem_is_word.clone() * read_word;
    let mem_label: LB::Expr =
        (one.clone() - mem_is_read.clone()) * write_label + mem_is_read * read_label;

    let v0: LB::Expr = local.chiplets[mem_offset + memory::V_COL_RANGE.start].into();
    let v1: LB::Expr = local.chiplets[mem_offset + memory::V_COL_RANGE.start + 1].into();
    let v2: LB::Expr = local.chiplets[mem_offset + memory::V_COL_RANGE.start + 2].into();
    let v3: LB::Expr = local.chiplets[mem_offset + memory::V_COL_RANGE.start + 3].into();
    let mem_element: LB::Expr =
        v0.clone() * (one.clone() - mem_idx0.clone()) * (one.clone() - mem_idx1.clone())
            + v1.clone() * mem_idx0.clone() * (one.clone() - mem_idx1.clone())
            + v2.clone() * (one - mem_idx0.clone()) * mem_idx1.clone()
            + v3.clone() * mem_idx0 * mem_idx1;
    let mem_word = [v0, v1, v2, v3];

    // ACE init: responds only on ACE start rows.
    let ace_start: LB::Expr = local.chiplets[NUM_ACE_SELECTORS + SELECTOR_START_IDX].into();
    let is_ace_init: LB::Expr = is_ace * ace_start;
    let ace_clk: LB::Expr = local.chiplets[NUM_ACE_SELECTORS + CLK_IDX].into();
    let ace_ctx: LB::Expr = local.chiplets[NUM_ACE_SELECTORS + CTX_IDX].into();
    let ace_ptr: LB::Expr = local.chiplets[NUM_ACE_SELECTORS + PTR_IDX].into();
    let ace_read_num_eval: LB::Expr = local.chiplets[NUM_ACE_SELECTORS + READ_NUM_EVAL_IDX].into();
    let ace_num_eval_rows: LB::Expr = ace_read_num_eval + LB::Expr::ONE;
    let ace_id_0: LB::Expr = local.chiplets[NUM_ACE_SELECTORS + ID_0_IDX].into();
    let ace_num_read_rows: LB::Expr = ace_id_0 + LB::Expr::ONE - ace_num_eval_rows.clone();

    // Kernel ROM: runtime-muxed s_first → label.
    let krom_s_first: LB::Expr = local.chiplets[NUM_KERNEL_ROM_SELECTORS].into();
    let init_label: LB::Expr = LB::Expr::from(KERNEL_PROC_INIT_LABEL);
    let call_label: LB::Expr = LB::Expr::from(KERNEL_PROC_CALL_LABEL);
    let krom_label: LB::Expr =
        krom_s_first.clone() * init_label + (LB::Expr::ONE - krom_s_first) * call_label;
    let krom_digest: [LB::Expr; 4] =
        array::from_fn(|i| local.chiplets[NUM_KERNEL_ROM_SELECTORS + 1 + i].into());

    // --- Emit everything into a single LogUp column ---

    builder.column(|col| {
        col.group(|g| {
            // Sponge start: full 12-lane state, node_index = 0.
            {
                let addr = addr_next.clone();
                let state = h.clone();
                g.add(f_sponge_start, move || HasherMsg::State {
                    label_value: LINEAR_HASH_LABEL as u16 + INPUT_LABEL_OFFSET,
                    addr,
                    node_index: LB::Expr::ZERO,
                    state,
                });
            }

            // Sponge RESPAN: rate-only 8 lanes, node_index = 0.
            {
                let addr = addr_next.clone();
                let rate: [LB::Expr; 8] = array::from_fn(|i| h[i].clone());
                g.add(f_sponge_respan, move || HasherMsg::Rate {
                    label_value: LINEAR_HASH_LABEL as u16 + OUTPUT_LABEL_OFFSET,
                    addr,
                    node_index: LB::Expr::ZERO,
                    rate,
                });
            }

            // MP_VERIFY input: leaf word.
            {
                let addr = addr_next.clone();
                let ni = node_index.clone();
                let word = leaf.clone();
                g.add(f_mp, move || HasherMsg::Word {
                    label_value: MP_VERIFY_LABEL as u16 + INPUT_LABEL_OFFSET,
                    addr,
                    node_index: ni,
                    word,
                });
            }

            // MR_UPDATE_OLD input: leaf word.
            {
                let addr = addr_next.clone();
                let ni = node_index.clone();
                let word = leaf.clone();
                g.add(f_mv, move || HasherMsg::Word {
                    label_value: MR_UPDATE_OLD_LABEL as u16 + INPUT_LABEL_OFFSET,
                    addr,
                    node_index: ni,
                    word,
                });
            }

            // MR_UPDATE_NEW input: leaf word.
            {
                let addr = addr_next.clone();
                let ni = node_index.clone();
                let word = leaf;
                g.add(f_mu, move || HasherMsg::Word {
                    label_value: MR_UPDATE_NEW_LABEL as u16 + INPUT_LABEL_OFFSET,
                    addr,
                    node_index: ni,
                    word,
                });
            }

            // HOUT: digest = h[0..4].
            {
                let addr = addr_next.clone();
                let ni = node_index.clone();
                let word: [LB::Expr; 4] = [h[0].clone(), h[1].clone(), h[2].clone(), h[3].clone()];
                g.add(f_hout, move || HasherMsg::Word {
                    label_value: RETURN_HASH_LABEL as u16 + OUTPUT_LABEL_OFFSET,
                    addr,
                    node_index: ni,
                    word,
                });
            }

            // SOUT: full 12-lane state (HPERM return), node_index = 0.
            {
                let addr = addr_next.clone();
                let state = h;
                g.add(f_sout, move || HasherMsg::State {
                    label_value: RETURN_STATE_LABEL as u16 + OUTPUT_LABEL_OFFSET,
                    addr,
                    node_index: LB::Expr::ZERO,
                    state,
                });
            }

            // Bitwise: runtime-muxed label.
            {
                let label = bw_label;
                let a = bw_a;
                let b = bw_b;
                let z = bw_z;
                g.add(is_bitwise_responding, move || BitwiseResponseMsg { label, a, b, z });
            }

            // Memory: runtime-muxed label + is_word mux.
            {
                let label = mem_label;
                let ctx = mem_ctx;
                let addr = mem_addr;
                let clk = mem_clk;
                let is_word = mem_is_word;
                let element = mem_element;
                let word = mem_word;
                g.add(is_memory, move || MemoryResponseMsg {
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
                let clk = ace_clk;
                let ctx = ace_ctx;
                let ptr = ace_ptr;
                let num_read = ace_num_read_rows;
                let num_eval = ace_num_eval_rows;
                g.add(is_ace_init, move || AceInitMsg { clk, ctx, ptr, num_read, num_eval });
            }

            // Kernel ROM: runtime-muxed label.
            {
                let label = krom_label;
                let digest = krom_digest;
                g.add(is_kernel_rom, move || KernelRomResponseMsg { label, digest });
            }

            // Suppress the `next`/`h_next` unused warning while the next-row hasher state
            // is held only for future cached-encoding use.
            let _ = (next, h_next);
        });
    });
}
