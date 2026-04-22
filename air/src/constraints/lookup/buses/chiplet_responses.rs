//! Chiplet responses bus ([`BusId::Chiplets`]).
//!
//! Chiplet-side responses from the hasher, bitwise, memory, ACE, and kernel ROM chiplets,
//! all sharing one LogUp column.
//!
//! The 7 hasher response variants are gated on hasher controller rows
//! (`chiplet_active.controller = 1`) via the per-variant `(s0, s1, s2, is_boundary)`
//! combinations. Non-hasher variants (bitwise / memory / ACE init / kernel ROM) are gated
//! by the matching `chiplet_active.{bitwise, memory, ace, kernel_rom}` flag.
//!
//! Memory uses the runtime-muxed [`MemoryResponseMsg`] encoding (label + is_word mux)
//! rather than splitting into 4 per-label variants — this keeps the response-column
//! transition degree at 8 (a per-variant split would bump it to 9).

use core::{array, borrow::Borrow};

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    constraints::{
        chiplets::columns::PeriodicCols,
        lookup::{
            chiplet_air::{ChipletBusContext, ChipletLookupBuilder},
            messages::{
                AceInitMsg, BitwiseResponseMsg, BusId, HasherMsg, KernelRomMsg, MemoryResponseMsg,
            },
        },
        utils::BoolNot,
    },
    lookup::{Deg, LookupBatch, LookupColumn, LookupGroup},
};

/// Upper bound on fractions this emitter pushes into its column per row.
///
/// All adds gate on per-chiplet `chiplet_active.*` flags which are mutually exclusive (at
/// most one chiplet runs per row). Within the hasher branch, the 7 variants are gated by
/// mutually exclusive `(s0, s1, s2, is_boundary)` combinations. The kernel-ROM branch
/// emits two fractions per active row: an INIT-labeled remove (multiplicity 1) plus a
/// CALL-labeled add with multiplicity equal to the row's `multiplicity` column. Every
/// other chiplet emits exactly one fraction when active. Per-row max: 2.
pub(in crate::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 2;

/// Emit the chiplet responses bus (C1).
#[allow(clippy::too_many_lines)]
pub(in crate::constraints::lookup) fn emit_chiplet_responses<LB>(
    builder: &mut LB,
    ctx: &ChipletBusContext<LB>,
) where
    LB: ChipletLookupBuilder,
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

    // Hasher state split by convention: [rate_0 (4), rate_1 (4), cap (4)]. Kept as Var
    // arrays (Copy) so each closure can convert to `LB::Expr` as needed.
    let rate_0: [LB::Var; 4] = array::from_fn(|i| ctrl.state[i]);
    let rate_1: [LB::Var; 4] = array::from_fn(|i| ctrl.state[4 + i]);
    let cap: [LB::Var; 4] = array::from_fn(|i| ctrl.state[8 + i]);

    // --- Hasher response flags ---
    // All gated by `chiplet_active.controller`; composed with the per-row-type
    // `(s0, s1, s2, is_boundary)` combinations.
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
    let f_mu: LB::Expr = controller_flag.clone() * hs0 * hs1 * hs2.clone() * is_boundary.clone();

    // HOUT output: hs0=hs1=hs2=0 (always responds on digest). Degree 4 (no is_boundary).
    let f_hout: LB::Expr = controller_flag.clone() * not_hs0.clone() * not_hs1.clone() * not_hs2;

    // SOUT output with is_boundary=1 only (HPERM return).
    let f_sout: LB::Expr = controller_flag * not_hs0 * not_hs1 * hs2 * is_boundary;

    // --- Non-hasher flags ---

    // Bitwise: responds only on the last row of the 8-row cycle (k_transition = 0).
    let is_bitwise_responding: LB::Expr = ctx.chiplet_active.bitwise.clone() * k_transition.not();

    // ACE init: responds only on ACE start rows.
    let is_ace_init: LB::Expr = ctx.chiplet_active.ace.clone() * ace.s_start.into();

    // --- Emit everything into a single LogUp column ---

    // All hasher response variants encode their row at `clk + 1` (so they cancel against
    // the matching request at `clk`).
    let clk_plus_one: LB::Expr = local.system.clk.into() + LB::Expr::ONE;

    builder.next_column(
        |col| {
            col.group(
                "chiplet_responses",
                |g| {
                    // Sponge start: full 12-lane state, node_index = 0.
                    g.add(
                        "sponge_start",
                        f_sponge_start,
                        || {
                            let addr = clk_plus_one.clone();
                            let state: [LB::Expr; 12] = array::from_fn(|i| {
                                if i < 4 {
                                    rate_0[i].into()
                                } else if i < 8 {
                                    rate_1[i - 4].into()
                                } else {
                                    cap[i - 8].into()
                                }
                            });
                            HasherMsg::State {
                                kind: BusId::HasherLinearHashInit,
                                addr,
                                node_index: LB::Expr::ZERO,
                                state,
                            }
                        },
                        Deg { n: 5, d: 6 },
                    );

                    // Sponge RESPAN: rate-only 8 lanes, node_index = 0.
                    g.add(
                        "sponge_respan",
                        f_sponge_respan,
                        || {
                            let addr = clk_plus_one.clone();
                            let rate: [LB::Expr; 8] = array::from_fn(|i| {
                                if i < 4 { rate_0[i].into() } else { rate_1[i - 4].into() }
                            });
                            HasherMsg::Rate {
                                kind: BusId::HasherAbsorption,
                                addr,
                                node_index: LB::Expr::ZERO,
                                rate,
                            }
                        },
                        Deg { n: 5, d: 6 },
                    );

                    // Merkle leaf-word inputs for MP_VERIFY / MR_UPDATE_OLD / MR_UPDATE_NEW.
                    // Each fires on its own controller flag; all three encode
                    // `leaf = (1-bit)·rate_0 + bit·rate_1` with `bit = node_index -
                    // 2·node_index_next` (the current Merkle direction bit).
                    for (name, flag, kind) in [
                        ("mp_verify_input", f_mp, BusId::HasherMerkleVerifyInit),
                        ("mr_update_old_input", f_mv, BusId::HasherMerkleOldInit),
                        ("mr_update_new_input", f_mu, BusId::HasherMerkleNewInit),
                    ] {
                        g.add(
                            name,
                            flag,
                            || {
                                let addr = clk_plus_one.clone();
                                let node_index: LB::Expr = ctrl.node_index.into();
                                let bit: LB::Expr =
                                    node_index.clone() - ctrl_next.node_index.into().double();
                                let one_minus_bit = bit.not();
                                let word: [LB::Expr; 4] = array::from_fn(|i| {
                                    one_minus_bit.clone() * rate_0[i].into()
                                        + bit.clone() * rate_1[i].into()
                                });
                                HasherMsg::Word { kind, addr, node_index, word }
                            },
                            Deg { n: 5, d: 7 },
                        );
                    }

                    // HOUT: digest = rate_0.
                    g.add(
                        "hout",
                        f_hout,
                        || {
                            let addr = clk_plus_one.clone();
                            let node_index: LB::Expr = ctrl.node_index.into();
                            let word: [LB::Expr; 4] = rate_0.map(LB::Expr::from);
                            HasherMsg::Word {
                                kind: BusId::HasherReturnHash,
                                addr,
                                node_index,
                                word,
                            }
                        },
                        Deg { n: 4, d: 5 },
                    );

                    // SOUT: full 12-lane state (HPERM return), node_index = 0.
                    g.add(
                        "sout",
                        f_sout,
                        || {
                            let addr = clk_plus_one.clone();
                            let state: [LB::Expr; 12] = array::from_fn(|i| {
                                if i < 4 {
                                    rate_0[i].into()
                                } else if i < 8 {
                                    rate_1[i - 4].into()
                                } else {
                                    cap[i - 8].into()
                                }
                            });
                            HasherMsg::State {
                                kind: BusId::HasherReturnState,
                                addr,
                                node_index: LB::Expr::ZERO,
                                state,
                            }
                        },
                        Deg { n: 5, d: 6 },
                    );

                    // Bitwise: runtime op selector bit.
                    g.add(
                        "bitwise",
                        is_bitwise_responding,
                        || {
                            let bw_op: LB::Expr = bw.op_flag.into();
                            BitwiseResponseMsg {
                                op: bw_op,
                                a: bw.a.into(),
                                b: bw.b.into(),
                                z: bw.output.into(),
                            }
                        },
                        Deg { n: 3, d: 4 },
                    );

                    // Memory response: runtime (is_read, is_word) mux keeps C1 transition at 8.
                    g.add(
                        "memory",
                        ctx.chiplet_active.memory.clone(),
                        || {
                            let mem_is_read: LB::Expr = mem.is_read.into();
                            let is_word: LB::Expr = mem.is_word.into();
                            let mem_idx0: LB::Expr = mem.idx0.into();
                            let mem_idx1: LB::Expr = mem.idx1.into();

                            let addr = mem.word_addr.into()
                                + mem_idx1.clone() * LB::Expr::from_u16(2)
                                + mem_idx0.clone();

                            let word: [LB::Expr; 4] = mem.values.map(LB::Expr::from);
                            let element = word[0].clone() * mem_idx0.not() * mem_idx1.not()
                                + word[1].clone() * mem_idx0.clone() * mem_idx1.not()
                                + word[2].clone() * mem_idx0.not() * mem_idx1.clone()
                                + word[3].clone() * mem_idx0 * mem_idx1;

                            MemoryResponseMsg {
                                is_read: mem_is_read,
                                ctx: mem.ctx.into(),
                                addr,
                                clk: mem.clk.into(),
                                is_word,
                                element,
                                word,
                            }
                        },
                        Deg { n: 3, d: 7 },
                    );

                    // ACE init.
                    g.add(
                        "ace_init",
                        is_ace_init,
                        || {
                            let num_eval = ace.read().num_eval.into() + LB::Expr::ONE;
                            let num_read = ace.id_0.into() + LB::Expr::ONE - num_eval.clone();
                            AceInitMsg {
                                clk: ace.clk.into(),
                                ctx: ace.ctx.into(),
                                ptr: ace.ptr.into(),
                                num_read,
                                num_eval,
                            }
                        },
                        Deg { n: 5, d: 6 },
                    );

                    // Kernel ROM: two fractions per active row.
                    // INIT remove (multiplicity 1) is balanced by the boundary correction.
                    // CALL add carries the syscall multiplicity.
                    let kernel_gate = ctx.chiplet_active.kernel_rom.clone();
                    g.batch(
                        "kernel_rom",
                        kernel_gate,
                        |b| {
                            let krom_mult: LB::Expr = krom.multiplicity.into();
                            let digest: [LB::Expr; 4] = krom.root.map(LB::Expr::from);

                            b.remove(
                                "kernel_rom_init",
                                KernelRomMsg::init(digest.clone()),
                                Deg { n: 5, d: 6 },
                            );
                            b.insert(
                                "kernel_rom_call",
                                krom_mult,
                                KernelRomMsg::call(digest),
                                Deg { n: 6, d: 6 },
                            );
                        },
                        Deg { n: 2, d: 2 },
                    );
                },
                Deg { n: 7, d: 7 },
            );
        },
        Deg { n: 7, d: 7 },
    );
}
