//! Chiplet responses bus ([`BusId::Chiplets`]).
//!
//! Chiplet-side responses from the hasher, bitwise, memory, ACE, and kernel ROM chiplets,
//! all sharing one LogUp column.
//!
//! Hasher operation-init responses are gated on the single-row controller selector encoding.
//! Final hasher digest returns live in a dedicated lookup column, because a final controller row
//! may emit both an init response and a return response.
//!
//! Memory uses the runtime-muxed [`MemoryResponseMsg`] encoding (label + is_word mux)
//! rather than splitting into four per-label variants. This keeps the response-column
//! transition degree at 8; a per-variant split would bump it to 9.

use core::{array, borrow::Borrow};

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    constraints::{
        chiplets::columns::PeriodicCols,
        lookup::{
            chiplet_air::{ChipletBusContext, ChipletLookupBuilder},
            messages::{
                AceInitMsg, And8Msg, BitwiseMsg, BusId, HasherMsg, HasherPayload, KernelRomMsg,
                MemoryResponseMsg,
            },
        },
        utils::{BoolNot, pack_u32_bytes_le},
    },
    lookup::{Deg, LookupBatch, LookupColumn, LookupGroup},
};

/// Upper bound on fractions this emitter pushes into its column per row.
///
/// All adds gate on per-chiplet `chiplet_active.*` flags which are mutually exclusive (at
/// most one chiplet runs per row). Within the hasher branch, init variants are gated by
/// mutually exclusive selector/start combinations. The kernel-ROM branch
/// emits two fractions per active row: an INIT-labeled remove (multiplicity 1) plus a
/// CALL-labeled add with multiplicity equal to the row's `multiplicity` column. Every
/// other chiplet emits exactly one fraction when active. AEAD stream rows emit four
/// byte-pair removals. Per-row max: 4.
pub(in crate::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 4;

/// Declared degree of the chiplet-responses lookup column.
pub(in crate::constraints::lookup) const COLUMN_DEG: Deg = Deg { v: 7, u: 8 };

/// Emit the chiplet responses bus.
pub(in crate::constraints::lookup) fn emit_chiplet_responses<LB>(
    builder: &mut LB,
    ctx: &ChipletBusContext<LB>,
) where
    LB: ChipletLookupBuilder,
{
    let local = ctx.local;
    // Read the typed periodic column view used by AEAD stream rows.
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

    // Typed chiplet-data overlays.
    let ctrl = local.controller();
    let bw = local.bitwise();
    let stream = local.aead_stream();
    let mem = local.memory();
    let ace = local.ace();
    let krom = local.kernel_rom();

    // Hasher-internal sub-selectors (valid on controller rows). Used many times below via their
    // negated siblings, so kept as named expressions.
    let hs0: LB::Expr = ctrl.s0.into();
    let hs1: LB::Expr = ctrl.s1.into();
    let hs2: LB::Expr = ctrl.s2.into();
    let not_hs0 = hs0.not();
    let not_hs1 = hs1.not();
    let not_hs2 = hs2.not();
    let merkle_or_padding: LB::Expr = local.controller_merkle_or_padding().into();
    let hash_gate = ctx.chiplet_active.controller.clone() * merkle_or_padding.not();
    // The controller skeleton makes `merkle_or_padding * s0` zero off controller rows. Keeping
    // this gate narrow avoids a higher-degree controller-selector factor.
    let merkle_gate = merkle_or_padding * hs0.clone();
    let merkle_start: LB::Expr = ctrl.merkle_is_start().into();

    let state: [LB::Var; 12] = ctrl.state;
    let rate_0: [LB::Var; 4] = array::from_fn(|i| ctrl.state[i]);
    let rate_1: [LB::Var; 4] = array::from_fn(|i| ctrl.state[4 + i]);

    // --- Hasher response flags ---
    let f_sponge_start: LB::Expr = hash_gate.clone() * hs0;
    let f_sponge_respan: LB::Expr = hash_gate * not_hs0;
    let f_mp: LB::Expr = merkle_gate.clone() * not_hs1 * hs2.clone() * merkle_start.clone();
    let f_mv: LB::Expr = merkle_gate.clone() * hs1.clone() * not_hs2 * merkle_start.clone();
    let f_mu: LB::Expr = merkle_gate * hs1 * hs2 * merkle_start;

    // --- Non-hasher flags ---

    // Normal bitwise rows use one row per operation.
    let is_bitwise_responding: LB::Expr = ctx.chiplet_active.bitwise.clone();

    // ACE init: responds only on ACE start rows.
    let is_ace_init: LB::Expr = ctx.chiplet_active.ace.clone() * ace.s_start.into();

    // --- Emit everything into a single LogUp column ---

    // All hasher response variants encode their row at the chiplet-trace row counter
    // (`chip_clk`) so they cancel against the matching request.
    let row_addr: LB::Expr = local.chip_clk.into();

    // Local helpers: convert the copied Var arrays into Expr arrays.
    let full_state = || -> [LB::Expr; 12] { state.map(Into::into) };
    let full_rate = || -> [LB::Expr; 8] {
        array::from_fn(|i| if i < 4 { rate_0[i].into() } else { rate_1[i - 4].into() })
    };

    builder.next_column(
        |col| {
            col.group(
                "chiplet_responses",
                |g| {
                    // Sponge start: full 12-lane state, node_index = 0.
                    g.add(
                        "sponge_start",
                        f_sponge_start,
                        || HasherMsg {
                            kind: BusId::HasherLinearHashInit,
                            addr: row_addr.clone(),
                            node_index: LB::Expr::ZERO,
                            payload: HasherPayload::State(full_state()),
                        },
                        Deg { v: 5, u: 6 },
                    );

                    // Sponge RESPAN: rate-only 8 lanes, node_index = 0.
                    g.add(
                        "sponge_respan",
                        f_sponge_respan,
                        || HasherMsg {
                            kind: BusId::HasherAbsorption,
                            addr: row_addr.clone(),
                            node_index: LB::Expr::ZERO,
                            payload: HasherPayload::Rate(full_rate()),
                        },
                        Deg { v: 5, u: 6 },
                    );

                    // Merkle leaf-word inputs for MP_VERIFY / MR_UPDATE_OLD / MR_UPDATE_NEW.
                    // Each fires only on the first row of the corresponding Merkle path.
                    for (name, flag, kind) in [
                        ("mp_verify_input", f_mp, BusId::HasherMerkleVerifyInit),
                        ("mr_update_old_input", f_mv, BusId::HasherMerkleOldInit),
                        ("mr_update_new_input", f_mu, BusId::HasherMerkleNewInit),
                    ] {
                        g.add(
                            name,
                            flag,
                            || {
                                let addr = row_addr.clone();
                                let node_index: LB::Expr = ctrl.merkle_node_index().into();
                                let bit: LB::Expr = node_index.clone()
                                    - Into::<LB::Expr>::into(ctrl.merkle_node_index_next())
                                        .double();
                                let one_minus_bit = bit.not();
                                let word: [LB::Expr; 4] = array::from_fn(|i| {
                                    one_minus_bit.clone() * rate_0[i].into()
                                        + bit.clone() * rate_1[i].into()
                                });
                                HasherMsg {
                                    kind,
                                    addr,
                                    node_index,
                                    payload: HasherPayload::Word(word),
                                }
                            },
                            Deg { v: 5, u: 7 },
                        );
                    }

                    // Bitwise: runtime op selector bit.
                    g.add(
                        "bitwise",
                        is_bitwise_responding,
                        || {
                            let bw_op: LB::Expr = bw.op_flag.into();
                            let a = pack_u32_bytes_le::<_, LB::Expr>(bw.a_bytes);
                            let b = pack_u32_bytes_le::<_, LB::Expr>(bw.b_bytes);
                            let and = pack_u32_bytes_le::<_, LB::Expr>(bw.and_bytes);
                            let xor = a.clone() + b.clone() - and.double();
                            let result = and.clone() + bw_op.clone() * (xor - and);
                            BitwiseMsg { op: bw_op, a, b, result }
                        },
                        Deg { v: 3, u: 5 },
                    );

                    let mut remove_stream_row = |name: &'static str, phase_idx: usize| {
                        let gate =
                            ctx.chiplet_active.aead_stream.clone() * aead_phase[phase_idx].clone();
                        g.batch(
                            name,
                            gate,
                            |b| {
                                let bytes = match phase_idx % 4 {
                                    0 => stream.read().bytes,
                                    1 => stream.high_first().bytes,
                                    2 => stream.low_second().bytes,
                                    3 => stream.high_second().bytes,
                                    _ => unreachable!(),
                                };
                                for idx in 0..4 {
                                    b.remove(
                                        "aead_stream_byte",
                                        And8Msg::new(
                                            bytes[idx].into(),
                                            bytes[4 + idx].into(),
                                            bytes[8 + idx].into(),
                                        ),
                                        Deg { v: 2, u: 3 },
                                    );
                                }
                            },
                            Deg { v: 3, u: 4 },
                        );
                    };
                    remove_stream_row("aead_stream_row0", 0);
                    remove_stream_row("aead_stream_row1", 1);
                    remove_stream_row("aead_stream_row2", 2);
                    remove_stream_row("aead_stream_row3", 3);
                    remove_stream_row("aead_stream_row4", 4);
                    remove_stream_row("aead_stream_row5", 5);
                    remove_stream_row("aead_stream_row6", 6);
                    remove_stream_row("aead_stream_row7", 7);

                    // Memory response: runtime (is_read, is_word) mux keeps column transition at 8.
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
                        Deg { v: 3, u: 7 },
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
                        Deg { v: 5, u: 6 },
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
                                Deg { v: 5, u: 6 },
                            );
                            b.insert(
                                "kernel_rom_call",
                                krom_mult,
                                KernelRomMsg::call(digest),
                                Deg { v: 6, u: 6 },
                            );
                        },
                        Deg { v: 7, u: 7 }, // (V, U) = (2 + 5, 2 + 5); kernel_rom flag deg 5
                    );
                },
                COLUMN_DEG,
            );
        },
        COLUMN_DEG,
    );
}
