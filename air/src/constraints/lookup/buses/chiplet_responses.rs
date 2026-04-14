//! Chiplet responses bus (C1 / `BUS_CHIPLETS`).
//!
//! Chiplet-side responses from the hasher, bitwise, memory, ACE, and kernel ROM chiplets,
//! all sharing one LogUp column.
//!
//! The 7 hasher response variants are gated on hasher controller rows
//! (`chiplet_active.controller = 1`) via the per-variant `(s0, s1, s2, is_boundary)`
//! combinations that mirror 2856's running product `compute_hasher_response`. Non-hasher
//! variants (bitwise / memory / ACE init / kernel ROM) are gated by the matching
//! `chiplet_active.{bitwise, memory, ace, kernel_rom}` flag.
//!
//! Memory uses the runtime-muxed [`MemoryResponseMsg`] encoding (label + is_word mux)
//! instead of splitting into 4 per-label variants — this keeps the C1 transition degree
//! at 8 (a per-variant split would bump it to 9), matching the 2856 running-product shape.

use core::{array, borrow::Borrow};

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    Felt,
    constraints::{
        chiplets::columns::PeriodicCols,
        logup_msg::{
            AceInitMsg, BitwiseResponseMsg, HasherMsg, KernelRomResponseMsg, MemoryResponseMsg,
        },
        lookup::{LookupBuilder, LookupColumn, LookupGroup, buses::ChipletTraceContext},
        utils::BoolNot,
    },
    trace::chiplets::{
        bitwise::{BITWISE_AND_LABEL, BITWISE_XOR_LABEL},
        hasher::{
            LINEAR_HASH_LABEL, MP_VERIFY_LABEL, MR_UPDATE_NEW_LABEL, MR_UPDATE_OLD_LABEL,
            RETURN_HASH_LABEL, RETURN_STATE_LABEL,
        },
        kernel_rom::{KERNEL_PROC_CALL_LABEL, KERNEL_PROC_INIT_LABEL},
        memory::{
            MEMORY_READ_ELEMENT_LABEL, MEMORY_READ_WORD_LABEL, MEMORY_WRITE_ELEMENT_LABEL,
            MEMORY_WRITE_WORD_LABEL,
        },
    },
};

// Label offsets matching 2856's running product.
const INPUT_LABEL_OFFSET: u16 = 16;
const OUTPUT_LABEL_OFFSET: u16 = 32;

/// Emit the chiplet responses bus (C1).
#[allow(clippy::too_many_lines)]
pub(in crate::constraints::lookup) fn emit_chiplet_responses<LB>(
    builder: &mut LB,
    ctx: &ChipletTraceContext<LB>,
) where
    LB: LookupBuilder<F = Felt>,
{
    let local = ctx.local;
    let next = ctx.next;

    // Read the typed periodic column view (used for bitwise k_transition).
    let k_transition: LB::Expr = {
        let periodic: &PeriodicCols<LB::PeriodicVar> = builder.periodic_values().borrow();
        periodic.bitwise.k_transition.into()
    };

    // Typed chiplet-data overlays.
    let ctrl = local.controller();
    let ctrl_next = next.controller();
    let bw = local.bitwise();
    let mem = local.memory();
    let ace = local.ace();
    let krom = local.kernel_rom();

    // Hasher-internal sub-selectors (valid on controller rows). Used many times below
    // via their negated siblings, so kept as named expressions.
    let hs0: LB::Expr = ctrl.s0.into();
    let hs1: LB::Expr = ctrl.s1.into();
    let hs2: LB::Expr = ctrl.s2.into();
    let is_boundary: LB::Expr = ctrl.is_boundary.into();
    let not_hs0 = hs0.not();
    let not_hs1 = hs1.not();
    let not_hs2 = hs2.not();

    // Address consistent with 2856: `addr_next = clk + 1`.
    let addr_next: LB::Expr = Into::<LB::Expr>::into(local.system.clk) + LB::Expr::ONE;

    // Hasher state as a 12-lane Expr array (used in 7 hasher variants + leaf derivation).
    let h: [LB::Expr; 12] = ctrl.state.map(Into::into);

    // Merkle direction bit and leaf word. `leaf = (1-bit)·h[0..4] + bit·h[4..8]`.
    let node_index: LB::Expr = ctrl.node_index.into();
    let node_index_next: LB::Expr = ctrl_next.node_index.into();
    let bit: LB::Expr = node_index.clone() - node_index_next.double();
    let one_minus_bit = bit.not();
    let leaf: [LB::Expr; 4] =
        array::from_fn(|i| one_minus_bit.clone() * h[i].clone() + bit.clone() * h[i + 4].clone());

    // --- Hasher response flags ---
    // All gated by `chiplet_active.controller`; composed with the per-row-type
    // `(s0, s1, s2, is_boundary)` combinations from 2856's `compute_hasher_response`.
    let controller_flag = ctx.chiplet_active.controller.clone();

    // Sponge start: input (hs0=1), hs1=hs2=0, is_boundary=1. Full 12-lane state.
    let f_sponge_start: LB::Expr = controller_flag.clone()
        * hs0.clone()
        * not_hs1.clone()
        * not_hs2.clone()
        * is_boundary.clone();

    // Sponge RESPAN: input, hs1=hs2=0, is_boundary=0. Rate-only 8 lanes.
    let f_sponge_respan: LB::Expr = controller_flag.clone()
        * hs0.clone()
        * not_hs1.clone()
        * not_hs2.clone()
        * is_boundary.not();

    // Merkle tree input rows (is_boundary=1):
    //   f_mp = ctrl · hs0 · (1-hs1) · hs2 · is_boundary
    //   f_mv = ctrl · hs0 · hs1 · (1-hs2) · is_boundary
    //   f_mu = ctrl · hs0 · hs1 · hs2 · is_boundary
    let f_mp: LB::Expr =
        controller_flag.clone() * hs0.clone() * not_hs1.clone() * hs2.clone() * is_boundary.clone();
    let f_mv: LB::Expr =
        controller_flag.clone() * hs0.clone() * hs1.clone() * not_hs2.clone() * is_boundary.clone();
    let f_mu: LB::Expr =
        controller_flag.clone() * hs0 * hs1.clone() * hs2.clone() * is_boundary.clone();

    // HOUT output: hs0=hs1=hs2=0 (always responds on digest). Degree 4 (no is_boundary).
    let f_hout: LB::Expr =
        controller_flag.clone() * not_hs0.clone() * not_hs1.clone() * not_hs2.clone();

    // SOUT output with is_boundary=1 only (HPERM return).
    let f_sout: LB::Expr = controller_flag * not_hs0 * not_hs1 * hs2 * is_boundary;

    // --- Non-hasher flags/payloads ---

    // Bitwise: responds only on the last row of the 8-row cycle (k_transition = 0).
    let is_bitwise_responding: LB::Expr = ctx.chiplet_active.bitwise.clone() * k_transition.not();
    let bw_op: LB::Expr = bw.op_flag.into();
    let bw_label: LB::Expr =
        bw_op.not() * LB::Expr::from(BITWISE_AND_LABEL) + bw_op * LB::Expr::from(BITWISE_XOR_LABEL);
    let bw_a: LB::Expr = bw.a.into();
    let bw_b: LB::Expr = bw.b.into();
    let bw_z: LB::Expr = bw.output.into();

    // Memory: runtime-muxed label + is_word mux keeps C1 transition at 8.
    let mem_is_read: LB::Expr = mem.is_read.into();
    let mem_is_word: LB::Expr = mem.is_word.into();
    let mem_ctx: LB::Expr = mem.ctx.into();
    let mem_clk: LB::Expr = mem.clk.into();
    let mem_idx0: LB::Expr = mem.idx0.into();
    let mem_idx1: LB::Expr = mem.idx1.into();
    let mem_addr: LB::Expr = Into::<LB::Expr>::into(mem.word_addr)
        + mem_idx1.clone() * LB::Expr::from_u16(2)
        + mem_idx0.clone();

    // Runtime label: `(1-is_read)*write_label + is_read*read_label`, each itself
    // `(1-is_word)*_ELEMENT + is_word*_WORD`.
    let write_label = mem_is_word.not() * LB::Expr::from_u16(MEMORY_WRITE_ELEMENT_LABEL as u16)
        + mem_is_word.clone() * LB::Expr::from_u16(MEMORY_WRITE_WORD_LABEL as u16);
    let read_label = mem_is_word.not() * LB::Expr::from_u16(MEMORY_READ_ELEMENT_LABEL as u16)
        + mem_is_word.clone() * LB::Expr::from_u16(MEMORY_READ_WORD_LABEL as u16);
    let mem_label: LB::Expr = mem_is_read.not() * write_label + mem_is_read * read_label;

    let mem_values: [LB::Expr; 4] = mem.values.map(Into::into);
    let mem_element: LB::Expr = mem_values[0].clone() * mem_idx0.not() * mem_idx1.not()
        + mem_values[1].clone() * mem_idx0.clone() * mem_idx1.not()
        + mem_values[2].clone() * mem_idx0.not() * mem_idx1.clone()
        + mem_values[3].clone() * mem_idx0 * mem_idx1;

    // ACE init: responds only on ACE start rows.
    let is_ace_init: LB::Expr =
        ctx.chiplet_active.ace.clone() * Into::<LB::Expr>::into(ace.s_start);
    let ace_clk: LB::Expr = ace.clk.into();
    let ace_ctx: LB::Expr = ace.ctx.into();
    let ace_ptr: LB::Expr = ace.ptr.into();
    let ace_num_eval_rows: LB::Expr = Into::<LB::Expr>::into(ace.read().num_eval) + LB::Expr::ONE;
    let ace_num_read_rows: LB::Expr =
        Into::<LB::Expr>::into(ace.id_0) + LB::Expr::ONE - ace_num_eval_rows.clone();

    // Kernel ROM: runtime-muxed s_first → label.
    let krom_s_first: LB::Expr = krom.s_first.into();
    let krom_label: LB::Expr = krom_s_first.clone() * LB::Expr::from(KERNEL_PROC_INIT_LABEL)
        + krom_s_first.not() * LB::Expr::from(KERNEL_PROC_CALL_LABEL);
    let krom_digest: [LB::Expr; 4] = krom.root.map(Into::into);

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
                let ni = node_index;
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
                let addr = addr_next;
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
                let sys_ctx = mem_ctx;
                let addr = mem_addr;
                let clk = mem_clk;
                let is_word = mem_is_word;
                let element = mem_element;
                let word = mem_values;
                g.add(ctx.chiplet_active.memory.clone(), move || MemoryResponseMsg {
                    label,
                    ctx: sys_ctx,
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
                let sys_ctx = ace_ctx;
                let ptr = ace_ptr;
                let num_read = ace_num_read_rows;
                let num_eval = ace_num_eval_rows;
                g.add(is_ace_init, move || AceInitMsg {
                    clk,
                    ctx: sys_ctx,
                    ptr,
                    num_read,
                    num_eval,
                });
            }

            // Kernel ROM: runtime-muxed label.
            {
                let label = krom_label;
                let digest = krom_digest;
                g.add(ctx.chiplet_active.kernel_rom.clone(), move || KernelRomResponseMsg {
                    label,
                    digest,
                });
            }
        });
    });
}
