//! Chiplet responses lookup column.
//!
//! Chiplet-side responses from the hasher, bitwise, memory, ACE, and kernel ROM chiplets,
//! all sharing one LogUp column.
//!
//! Hasher operation-init responses are gated on the single-row controller selector encoding.
//! Four-Felt hasher returns live in a dedicated lookup column, because a final controller row may
//! emit both an init response and a return response. Those returns are completed digests for framed
//! hashes and updated chaining values for raw compression.
//!
//! Memory uses the runtime-muxed [`MemoryResponseMsg`] encoding (label + is_word mux)
//! rather than splitting into four per-label variants. This keeps the response-column
//! transition degree at 8; a per-variant split would bump it to 9.

use super::super::operations::{aead_stream, merkle};

use core::{array, borrow::Borrow};

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    constraints::{
        chiplets::columns::PeriodicCols,
        lookup::{
            chiplet_air::{ChipletBusContext, ChipletLookupBuilder},
            messages::{
                AceInitMsg, BitwiseMsg, BusId, HasherMsg, HasherPayload, KernelRomMsg,
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
    let periodic: &PeriodicCols<LB::PeriodicVar> = builder.periodic_values().borrow();
    let aead_phase: [LB::Expr; 8] = periodic.aead_stream.phases.map(Into::into);

    // Typed chiplet-data overlays.
    let ctrl = local.controller();
    let bw = local.bitwise();
    let mem = local.memory();
    let ace = local.ace();
    let krom = local.kernel_rom();

    // Hash-start and continuation flags on controller rows.
    let hs0: LB::Expr = ctrl.s0.into();
    let not_hs0 = hs0.not();
    let merkle_or_padding: LB::Expr = local.controller_merkle_or_padding().into();
    let hash_gate = ctx.chiplet_active.controller.clone() * merkle_or_padding.not();

    let state: [LB::Var; 12] = ctrl.state;
    let block_lo: [LB::Var; 4] = array::from_fn(|i| ctrl.state[i]);
    let block_hi: [LB::Var; 4] = array::from_fn(|i| ctrl.state[4 + i]);

    // --- Hasher response flags ---
    let f_hash_start: LB::Expr = hash_gate.clone() * hs0;
    let f_hash_continue: LB::Expr = hash_gate * not_hs0;

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
    let full_block = || -> [LB::Expr; 8] {
        array::from_fn(|i| {
            if i < 4 {
                block_lo[i].into()
            } else {
                block_hi[i - 4].into()
            }
        })
    };

    builder.next_column(
        |col| {
            col.group(
                "chiplet_responses",
                |g| {
                    // Hash start: full 12-Felt compression state, node_index = 0.
                    g.add(
                        "hash_start",
                        f_hash_start,
                        || HasherMsg {
                            kind: BusId::HasherLinearHashInit,
                            addr: row_addr.clone(),
                            node_index: LB::Expr::ZERO,
                            payload: HasherPayload::State(full_state()),
                        },
                        Deg { v: 5, u: 6 },
                    );

                    // Hash continuation: next 8-Felt block, node_index = 0.
                    g.add(
                        "hash_continue",
                        f_hash_continue,
                        || HasherMsg {
                            kind: BusId::HasherAbsorption,
                            addr: row_addr.clone(),
                            node_index: LB::Expr::ZERO,
                            payload: HasherPayload::Block(full_block()),
                        },
                        Deg { v: 5, u: 6 },
                    );

                    merkle::emit_chiplet_inits::<LB, _>(g, ctx);

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

                    aead_stream::emit_byte_checks::<LB, _>(g, ctx, &aead_phase);

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
