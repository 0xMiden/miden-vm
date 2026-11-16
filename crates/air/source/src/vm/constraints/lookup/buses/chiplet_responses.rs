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

use core::array;

use miden_core::field::PrimeCharacteristicRing;
use miden_stark::lookup::{Deg, LookupBatch, LookupColumn, LookupGroup};
use p3_field::Dup;

use super::super::operations::{aead_stream, merkle};
use crate::vm::constraints::{
    lookup::{
        chiplet_air::{ChipletBusContext, NativeChipletLookupBuilder},
        messages::{
            AceInitMsg, BitwiseMsg, BusId, HasherMsg, HasherPayload, KernelRomMsg,
            MemoryResponseMsg,
        },
    },
    utils::{BoolNot, pack_u32_bytes_le},
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
pub(in crate::vm::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 4;

/// Declared degree of the chiplet-responses lookup column.
pub(in crate::vm::constraints::lookup) const COLUMN_DEG: Deg = Deg { v: 7, u: 8 };

/// Emit the chiplet responses bus.
pub(in crate::vm::constraints::lookup) fn emit_chiplet_responses<LB>(
    builder: &mut LB,
    ctx: &ChipletBusContext<'_, LB::Expr>,
) where
    LB: NativeChipletLookupBuilder,
{
    let local = ctx.local;
    // Read the typed periodic column view used by AEAD stream rows.
    let aead_phase = ctx.periodic.aead_stream.phases.clone();

    // Typed chiplet-data overlays.
    let ctrl = local.controller_cols();
    let bw = local.bitwise_cols();
    let mem = local.memory_cols();
    let ace = local.ace_cols();
    let krom = local.kernel_rom_cols();

    // Hash-start and continuation flags on controller rows.
    let hs0: LB::Expr = ctrl.s0.dup();
    let not_hs0 = hs0.not();
    let merkle_or_padding: LB::Expr = ctrl.merkle_or_padding.dup();
    let hash_gate = ctx.chiplet_active.controller.clone() * merkle_or_padding.not();

    let state: [LB::Expr; 12] = ctrl.state.clone();
    let block_lo: [LB::Expr; 4] = array::from_fn(|i| ctrl.state[i].dup());
    let block_hi: [LB::Expr; 4] = array::from_fn(|i| ctrl.state[4 + i].dup());

    // --- Hasher response flags ---
    let f_hash_start: LB::Expr = hash_gate.clone() * hs0;
    let f_hash_continue: LB::Expr = hash_gate * not_hs0;

    // --- Non-hasher flags ---

    // Normal bitwise rows use one row per operation.
    let is_bitwise_responding: LB::Expr = ctx.chiplet_active.bitwise.clone();

    // ACE init: responds only on ACE start rows.
    let is_ace_init: LB::Expr = ctx.chiplet_active.ace.clone() * ace.s_start.dup();

    // --- Emit everything into a single LogUp column ---

    // All hasher response variants use the controller row address so they cancel against
    // the matching request.
    let row_addr: LB::Expr = ctrl.addr.dup();

    // Duplicate expression arrays for synchronous message construction.
    let full_state = || -> [LB::Expr; 12] { state.clone() };
    let full_block = || -> [LB::Expr; 8] {
        array::from_fn(|i| {
            if i < 4 {
                block_lo[i].dup()
            } else {
                block_hi[i - 4].dup()
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
                            let bw_op: LB::Expr = bw.op_flag.dup();
                            let a = pack_u32_bytes_le::<_, LB::Expr>(bw.a_bytes.clone());
                            let b = pack_u32_bytes_le::<_, LB::Expr>(bw.b_bytes.clone());
                            let and = pack_u32_bytes_le::<_, LB::Expr>(bw.and_bytes.clone());
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
                            let mem_is_read: LB::Expr = mem.is_read.dup();
                            let is_word: LB::Expr = mem.is_word.dup();
                            let mem_idx0: LB::Expr = mem.idx0.dup();
                            let mem_idx1: LB::Expr = mem.idx1.dup();

                            let addr = mem.word_addr.dup() + mem_idx1.double() + mem_idx0.dup();

                            let word: [LB::Expr; 4] = mem.values.each_ref().map(Dup::dup);
                            let lower_pair =
                                word[0].dup() + mem_idx0.dup() * (word[1].dup() - word[0].dup());
                            let upper_pair =
                                word[2].dup() + mem_idx0 * (word[3].dup() - word[2].dup());
                            let element = lower_pair.dup() + mem_idx1 * (upper_pair - lower_pair);

                            MemoryResponseMsg {
                                is_read: mem_is_read,
                                ctx: mem.ctx.dup(),
                                addr,
                                clk: mem.clk.dup(),
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
                            let num_eval = ace.read().num_eval.dup() + LB::Expr::ONE;
                            let num_read = ace.id_0.dup() + LB::Expr::ONE - num_eval.clone();
                            AceInitMsg {
                                clk: ace.clk.dup(),
                                ctx: ace.ctx.dup(),
                                ptr: ace.ptr.dup(),
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
                            let krom_mult: LB::Expr = krom.multiplicity.dup();
                            let digest: [LB::Expr; 4] = krom.root.clone();

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
