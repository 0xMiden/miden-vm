//! `v_wiring` shared bus column.
//!
//! ACE wiring, hasher compression links, and AEAD stream output/request traffic live in one
//! [`super::super::LookupColumn::group`] call. Their row selectors are mutually exclusive at the
//! chiplet level, so the simple-group composition is sound and the column degree is the maximum
//! of the active branch degrees.
//!
//! ## ACE wiring (`BusId::AceWiring`)
//!
//! Two READ/EVAL wire interactions gated by the ACE chiplet selector + its per-row block
//! selector, folded into a single `ace_flag`-gated batch with `sblock`-muxed multiplicities:
//! `wire_0` fires with the same multiplicity `m_0` on both READ and EVAL rows, so it
//! factors out; `wire_1` and `wire_2` get `sblock`-parameterized multiplicities that recover
//! the original rational at every row. This drops the outer selector from degree 5
//! (`is_read`/`is_eval`) to degree 4 (`ace_flag`), bringing the batch's contribution to
//! `(deg(U_g), deg(V_g)) = (7, 8)`.
//!
//! Algebraic equivalence:
//!
//! ```text
//!   is_read * (m_0/wire_0 + m_1/wire_1)
//! + is_eval * (m_0/wire_0 - 1/wire_1 - 1/wire_2)
//!   = ace_flag * [ m_0/wire_0
//!                + ((1 - sblock) * m_1 - sblock)/wire_1
//!                + (-sblock)/wire_2 ]
//! ```
//!
//! The `wire_2` payload reads the physical columns shared with the READ overlay's `m_1`
//! slot: under `sblock = 1` (EVAL) they hold `v_2`, and under `sblock = 0` (READ) the
//! `wire_2` interaction is fully suppressed via the `-sblock` multiplicity, so the
//! interpretation collapses to the READ-mode one.
//!
//! ## Hasher compression link (`BusId::HasherCompressionLink`)
//!
//! Binds hasher controller rows to the standalone BlakeG compression AIR. Without this bus a
//! malicious prover could pair any controller `(state_in, state_out)` with any compression
//! execution (or skip the cycle entirely). The controller side emits one interaction per
//! compression row:
//!
//! - **Hash compression** (`s_ctrl * !controller_merkle_or_padding`, multiplicity `+1`):
//!   `[block(8), cv_in(4), cv_out(4)]`.
//! - **Merkle compression** (`s_ctrl * controller_merkle_or_padding * s0`, multiplicity `+1`):
//!   `[block(8), fixed_merkle_cv(4), cv_out(4)]`.
//!
//! The BlakeG compression AIR emits the matching receive on its interface row.
//!
//! The compression-link gate has degree `(5, 6)`, below the ACE batch's `(8, 7)`.
//! Merging into the same group therefore leaves the column's transition at `(8, 7)`.
//!
//! ## AEAD stream
//!
//! AEAD stream rows emit paired BlakeG-XOF output limbs. The first limb comes from the
//! current stream row; the second comes from the next row, whose phase is constrained by the
//! stream-row transition constraints. Request messages fire on phases 2 and 6.

use core::{array, borrow::Borrow};

use miden_core::{chiplets::blakeg, field::PrimeCharacteristicRing};

use crate::{
    constraints::{
        chiplets::columns::{AeadStreamCols, PeriodicCols},
        lookup::{
            chiplet_air::{ChipletBusContext, ChipletLookupBuilder},
            messages::{
                AceWireMsg, AeadBlakeGOutputPairMsg, AeadStreamRequestMsg, HasherCompressionLinkMsg,
            },
        },
        utils::{BoolNot, pack_u32_bytes_le},
    },
    lookup::{Deg, LookupBatch, LookupColumn, LookupGroup},
};

/// Upper bound on fractions this emitter pushes into its column per row.
///
/// Single group hosts all wiring buses. Active branches are pairwise mutually
/// exclusive, so on any given row only one of:
/// - **ACE wiring batch** on ACE rows: 3 fractions (wire_0 / wire_1 / wire_2 push unconditionally
///   when the outer `ace_flag` fires).
/// - **Hasher compression link** on controller rows: 1 fraction.
/// - **AEAD stream** rows: at most 2 fractions.
///
/// Per-row max is therefore `max(3, 1, 2) = 3`.
pub(in crate::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 3;

/// Emit the `v_wiring` shared column.
pub(in crate::constraints::lookup) fn emit_v_wiring<LB>(
    builder: &mut LB,
    ctx: &ChipletBusContext<LB>,
) where
    LB: ChipletLookupBuilder,
{
    let local = ctx.local;
    let next = ctx.next;
    let aead_phase: [LB::Expr; 8] = {
        let periodic: &PeriodicCols<LB::PeriodicVar> = builder.periodic_values().borrow();
        [
            periodic.aead_stream.r0.into(),
            periodic.aead_stream.r1.into(),
            periodic.aead_stream.r2.into(),
            periodic.aead_stream.r3.into(),
            periodic.aead_stream.r4.into(),
            periodic.aead_stream.r5.into(),
            periodic.aead_stream.r6.into(),
            periodic.aead_stream.r7.into(),
        ]
    };

    // ---- ACE wiring captures (Group 1) ----
    let ace_flag = ctx.chiplet_active.ace.clone();

    // Typed ACE chiplet overlay. `read()` exposes `m_0` / `m_1`, `eval()` exposes `v_2`;
    // wiring uses both overlays because its `sblock`-muxed multiplicities combine the
    // READ and EVAL row interpretations onto one column.
    let ace = local.ace();
    let ace_read = ace.read();
    let ace_eval = ace.eval();

    // Prefixed with `ace_` where the shorter name would clash with the outer function
    // parameter `ctx`.
    let ace_clk = ace.clk;
    let ace_ctx = ace.ctx;
    let id_0 = ace.id_0;
    let id_1 = ace.id_1;
    let id_2 = ace_eval.id_2;
    let v_0 = ace.v_0;
    let v_1 = ace.v_1;
    let v_2 = ace_eval.v_2;
    let m_0 = ace_read.m_0;
    let m_1 = ace_read.m_1;

    // `sblock` mixes into the wire_1 / wire_2 multiplicities; keep it as an `LB::Expr`
    // since the `wire_1_mult` expression needs arithmetic against the already-converted
    // `m_1`.
    let sblock: LB::Expr = ace.s_block.into();

    // Controller rows emit one compression-link tuple except padding rows.
    let ctrl = local.controller();
    let controller_flag = ctx.chiplet_active.controller.clone();
    let merkle_or_padding: LB::Expr = local.controller_merkle_or_padding().into();
    let ctrl_s0: LB::Expr = ctrl.s0.into();
    let f_hash_compression = controller_flag.clone() * merkle_or_padding.not();
    let f_merkle_compression = controller_flag * merkle_or_padding * ctrl_s0;

    let ctrl_state: [LB::Var; 12] = array::from_fn(|i| ctrl.state[i]);
    let ctrl_row_data: [LB::Var; 4] = ctrl.hash_digest();
    let merkle_cv = blakeg::two_to_one_chaining_word(0);
    let stream = local.aead_stream();
    let stream_next = next.aead_stream();
    let stream_gate = ctx.chiplet_active.aead_stream.clone();

    builder.next_column(
        |col| {
            // Single group hosts both buses. ACE rows (`chiplet_active.ace`) and controller rows
            // (`chiplet_active.controller`) are pairwise mutually exclusive, so the simple-group
            // composition is sound. Merging into one group takes MAX over per-interaction
            // degrees instead of multiplying sibling `(V_g, U_g)` pairs, critical for keeping
            // this column's transition inside the degree-9 budget.
            col.group(
                "ace_compression_link",
                |g| {
                    // ---- ACE wiring (BusId::AceWiring) ----
                    //
                    // Single `ace_flag`-gated batch with `sblock`-muxed multiplicities for wire_1
                    // and wire_2. `wire_0`'s `m_0` is invariant across the READ/EVAL split, so it
                    // lives in the batch as a plain trace-column multiplicity.
                    g.batch(
                        "ace_wiring",
                        ace_flag,
                        move |b| {
                            let m_0: LB::Expr = m_0.into();
                            let m_1: LB::Expr = m_1.into();
                            let wire_1_mult = sblock.not() * m_1 - sblock.clone();
                            let wire_2_mult = -sblock;

                            let wire_0 = AceWireMsg {
                                clk: ace_clk.into(),
                                ctx: ace_ctx.into(),
                                id: id_0.into(),
                                v0: v_0.0.into(),
                                v1: v_0.1.into(),
                            };
                            b.insert("wire_0", m_0, wire_0, Deg { v: 5, u: 5 });

                            let wire_1 = AceWireMsg {
                                clk: ace_clk.into(),
                                ctx: ace_ctx.into(),
                                id: id_1.into(),
                                v0: v_1.0.into(),
                                v1: v_1.1.into(),
                            };
                            b.insert("wire_1", wire_1_mult, wire_1, Deg { v: 6, u: 5 });

                            let wire_2 = AceWireMsg {
                                clk: ace_clk.into(),
                                ctx: ace_ctx.into(),
                                id: id_2.into(),
                                v0: v_2.0.into(),
                                v1: v_2.1.into(),
                            };
                            b.insert("wire_2", wire_2_mult, wire_2, Deg { v: 5, u: 5 });
                        },
                        Deg { v: 8, u: 7 }, // (V, U) = (4 + 4, 3 + 4); ace_flag deg 4
                    );

                    // ---- Hasher compression link (BusId::HasherCompressionLink) ----

                    // Hash compression: +1 / encode(block, cv_in, cv_out).
                    g.add(
                        "hash_compression",
                        f_hash_compression,
                        move || {
                            let block = array::from_fn(|i| ctrl_state[i].into());
                            let cv_in = array::from_fn(|i| ctrl_state[8 + i].into());
                            let cv_out = array::from_fn(|i| ctrl_row_data[i].into());
                            HasherCompressionLinkMsg { block, cv_in, cv_out }
                        },
                        Deg { v: 5, u: 6 },
                    );

                    // Merkle compression: +1 / encode(block, fixed_cv, cv_out).
                    g.add(
                        "merkle_compression",
                        f_merkle_compression,
                        move || {
                            let block = array::from_fn(|i| ctrl_state[i].into());
                            let cv_in = array::from_fn(|i| LB::Expr::from(merkle_cv[i]));
                            let cv_out = array::from_fn(|i| ctrl_state[8 + i].into());
                            HasherCompressionLinkMsg { block, cv_in, cv_out }
                        },
                        Deg { v: 5, u: 6 },
                    );

                    let mut add_stream_pair =
                        |name: &'static str, phase_idx: usize, first_lane_offset: u16| {
                            g.add(
                                name,
                                stream_gate.clone() * aead_phase[phase_idx].clone(),
                                || {
                                    aead_stream_pair_msg::<LB>(
                                        stream,
                                        stream_next,
                                        phase_idx,
                                        first_lane_offset,
                                    )
                                },
                                Deg { v: 3, u: 4 },
                            );
                        };
                    add_stream_pair("aead_stream_pair0", 0, 0);
                    add_stream_pair("aead_stream_pair2", 4, 0);

                    g.batch(
                        "aead_stream_pair1_request",
                        stream_gate.clone() * aead_phase[2].clone(),
                        |b| {
                            b.add(
                                "aead_stream_pair1",
                                aead_stream_pair_msg::<LB>(stream, stream_next, 2, 2),
                                Deg { v: 3, u: 4 },
                            );
                            b.add(
                                "aead_stream_request",
                                aead_stream_request_msg::<LB>(stream, 0),
                                Deg { v: 3, u: 4 },
                            );
                        },
                        Deg { v: 4, u: 7 },
                    );

                    g.batch(
                        "aead_stream_pair3_request",
                        stream_gate.clone() * aead_phase[6].clone(),
                        |b| {
                            b.add(
                                "aead_stream_pair3",
                                aead_stream_pair_msg::<LB>(stream, stream_next, 6, 2),
                                Deg { v: 3, u: 4 },
                            );
                            b.add(
                                "aead_stream_request",
                                aead_stream_request_msg::<LB>(stream, 4),
                                Deg { v: 3, u: 4 },
                            );
                        },
                        Deg { v: 4, u: 7 },
                    );
                },
                Deg { v: 8, u: 7 },
            );
        },
        Deg { v: 8, u: 7 },
    );
}

fn aead_stream_pair_msg<LB>(
    stream: &AeadStreamCols<LB::Var>,
    stream_next: &AeadStreamCols<LB::Var>,
    phase_idx: usize,
    first_lane_offset: u16,
) -> AeadBlakeGOutputPairMsg<LB::Expr>
where
    LB: ChipletLookupBuilder,
{
    let (clk, lane_base, value0, value1) = match phase_idx % 4 {
        0 => {
            let row = stream.read();
            let next = stream_next.high_first();
            (
                row.clk.into(),
                row.lane_base.into(),
                stream_b_limb::<LB>(row.bytes),
                stream_b_limb::<LB>(next.bytes),
            )
        },
        2 => {
            let row = stream.low_second();
            let next = stream_next.high_second();
            (
                row.clk.into(),
                row.lane_base.into(),
                stream_b_limb::<LB>(row.bytes),
                stream_b_limb::<LB>(next.bytes),
            )
        },
        _ => unreachable!(),
    };
    AeadBlakeGOutputPairMsg {
        clk,
        first_lane_idx: lane_base + LB::Expr::from_u16(first_lane_offset),
        value0,
        value1,
    }
}

fn aead_stream_request_msg<LB>(
    stream: &AeadStreamCols<LB::Var>,
    second_half_offset: u16,
) -> AeadStreamRequestMsg<LB::Expr>
where
    LB: ChipletLookupBuilder,
{
    let row = stream.low_second();
    let dst_ptr: LB::Expr = row.dst_ptr.into();
    let lane_base: LB::Expr = row.lane_base.into();
    let offset = LB::Expr::from_u16(second_half_offset);
    AeadStreamRequestMsg {
        ctx: row.ctx.into(),
        clk: row.clk.into(),
        src_ptr: row.src_ptr.into(),
        dst_ptr: dst_ptr - offset.clone(),
        lane_base: lane_base - offset,
    }
}

fn stream_b_limb<LB>(bytes: [LB::Var; 12]) -> LB::Expr
where
    LB: ChipletLookupBuilder,
{
    pack_u32::<LB>([bytes[4], bytes[5], bytes[6], bytes[7]])
}

fn pack_u32<LB>(bytes: [LB::Var; 4]) -> LB::Expr
where
    LB: ChipletLookupBuilder,
{
    pack_u32_bytes_le::<_, LB::Expr>(bytes)
}
