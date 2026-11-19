//! AEAD stream lookup interactions across Core and Chiplets columns.
//!
//! Core requests one Eidos compression and two stream halves. The Chiplets response column
//! checks four byte pairs on each stream row; the hash-kernel column binds plaintext reads on
//! phases 0/4 and ciphertext writes on phases 3/7; the wiring column adds output pairs on
//! phases 0/2/4/6 and repeats the stream requests on phases 2/6. Each function emits into an
//! existing column group, whose row-disjointness and degree budget are declared by that column.

use core::array;

use miden_core::field::PrimeCharacteristicRing;
use miden_stark::lookup::{Deg, LookupBatch, LookupGroup};
use p3_field::Dup;

use crate::vm::constraints::{
    chiplets::columns::AeadStreamCols,
    lookup::{
        chiplet_air::{ChipletBusContext, NativeChipletLookupBuilder},
        main_air::{MainBusContext, NativeMainLookupBuilder},
        messages::{
            AeadEidosCompressionInputMsg, AeadEidosCompressionOutputPairMsg, AeadStreamRequestMsg,
            BytePairLookupMsg, MemoryMsg,
        },
    },
    utils::{pack_u32_bytes_le, pack_u32_xor_bytes_le},
};

pub(in crate::vm::constraints::lookup) fn emit_core_requests<LB, G>(
    g: &mut G,
    main_ctx: &MainBusContext<'_, LB::Expr>,
) where
    LB: NativeMainLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let stk = &main_ctx.local.stack;
    let clk = main_ctx.local.system.clk.dup();
    let sys_ctx = main_ctx.local.system.ctx.dup();
    let op_flags = &main_ctx.op_flags;
    let src_ptr = stk.get(5);
    let dst_ptr = stk.get(6);
    g.batch(
        "aead_stream",
        op_flags.cryptostream(),
        |b| {
            let state = array::from_fn(|i| {
                if i == 0 {
                    stk.get(4)
                } else if i < 8 {
                    LB::Expr::ZERO
                } else {
                    stk.get(i - 8)
                }
            });
            b.insert(
                "aead_eidos_input",
                LB::Expr::ONE,
                AeadEidosCompressionInputMsg { clk: clk.dup(), state },
                Deg { v: 4, u: 5 },
            );
            for (name, src_offset, dst_offset, lane_base) in
                [("aead_stream_low", 0, 0, 0), ("aead_stream_high", 4, 8, 8)]
            {
                // The stream side emits the same request from both 4-row halves
                // of one 8-row entry, so Core supplies multiplicity -2.
                b.insert(
                    name,
                    -LB::Expr::from_u16(2),
                    AeadStreamRequestMsg {
                        ctx: sys_ctx.dup(),
                        clk: clk.dup(),
                        src_ptr: src_ptr.dup() + LB::Expr::from_u16(src_offset),
                        dst_ptr: dst_ptr.dup() + LB::Expr::from_u16(dst_offset),
                        lane_base: LB::Expr::from_u16(lane_base),
                    },
                    Deg { v: 4, u: 5 },
                );
            }
        },
        Deg { v: 7, u: 8 }, // (V, U) = (3 + 4, 4 + 4)
    );
}

pub(in crate::vm::constraints::lookup) fn emit_byte_checks<LB, G>(
    g: &mut G,
    ctx: &ChipletBusContext<'_, LB::Expr>,
    aead_phase: &[LB::Expr; 8],
) where
    LB: NativeChipletLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let stream = ctx.local.aead_stream_cols();
    let mut remove_stream_row = |name: &'static str, phase_idx: usize| {
        let gate = ctx.chiplet_active.aead_stream.clone() * aead_phase[phase_idx].clone();
        g.batch(
            name,
            gate,
            |b| {
                let bytes = match phase_idx % 4 {
                    0 => &stream.read().bytes,
                    1 => &stream.high_first().bytes,
                    2 => &stream.low_second().bytes,
                    3 => &stream.high_second().bytes,
                    _ => unreachable!(),
                };
                for idx in 0..4 {
                    b.remove(
                        "aead_stream_byte",
                        BytePairLookupMsg::from_and(
                            bytes[idx].dup(),
                            bytes[4 + idx].dup(),
                            bytes[8 + idx].dup(),
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
}

pub(in crate::vm::constraints::lookup) fn emit_memory_io<LB, G>(
    g: &mut G,
    ctx: &ChipletBusContext<'_, LB::Expr>,
    aead_phase: &[LB::Expr; 8],
) where
    LB: NativeChipletLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let stream = ctx.local.aead_stream_cols();
    let stream_gate = ctx.chiplet_active.aead_stream.clone();
    // Both 4-row halves read the same plaintext word, so each half is bound to the
    // memory chiplet. Phases 3 and 7 write the two ciphertext words.
    let mut remove_stream_read = |name: &'static str, phase_idx: usize| {
        let gate = stream_gate.clone() * aead_phase[phase_idx].clone();
        g.remove(
            name,
            gate,
            || {
                let row = stream.read();
                let word = row.plaintext.clone();
                MemoryMsg::read_word(row.ctx.dup(), row.src_ptr.dup(), row.clk.dup(), word)
            },
            Deg { v: 4, u: 5 },
        );
    };
    remove_stream_read("aead_stream_read0", 0);
    remove_stream_read("aead_stream_read1", 4);

    let mut remove_stream_write = |name: &'static str, phase_idx: usize| {
        let gate = stream_gate.clone() * aead_phase[phase_idx].clone();
        g.remove(
            name,
            gate,
            || {
                let row = stream.high_second();
                let word = [
                    row.c_prev0.dup(),
                    row.c_prev1.dup(),
                    row.c_prev2.dup(),
                    pack_u32_xor_bytes_le::<_, LB::Expr>(row.bytes.clone()),
                ];
                MemoryMsg::write_word(row.ctx.dup(), row.dst_ptr.dup(), row.clk.dup(), word)
            },
            Deg { v: 4, u: 5 },
        );
    };
    remove_stream_write("aead_stream_write0", 3);
    remove_stream_write("aead_stream_write1", 7);
}

pub(in crate::vm::constraints::lookup) fn emit_wiring<LB, G>(
    g: &mut G,
    ctx: &ChipletBusContext<'_, LB::Expr>,
    aead_phase: &[LB::Expr; 8],
) where
    LB: NativeChipletLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let stream = ctx.local.aead_stream_cols();
    let stream_next = ctx.next.aead_stream_cols();
    let stream_gate = ctx.chiplet_active.aead_stream.clone();
    let mut add_stream_pair = |name: &'static str, phase_idx: usize, first_lane_offset: u16| {
        g.add(
            name,
            stream_gate.clone() * aead_phase[phase_idx].clone(),
            || aead_stream_pair_msg::<LB>(stream, stream_next, phase_idx, first_lane_offset),
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
}

fn aead_stream_pair_msg<LB>(
    stream: &AeadStreamCols<LB::Expr>,
    stream_next: &AeadStreamCols<LB::Expr>,
    phase_idx: usize,
    first_lane_offset: u16,
) -> AeadEidosCompressionOutputPairMsg<LB::Expr>
where
    LB: NativeChipletLookupBuilder,
{
    let (clk, lane_base, value0, value1) = match phase_idx % 4 {
        0 => {
            let row = stream.read();
            let next = stream_next.high_first();
            (
                row.clk.dup(),
                row.lane_base.dup(),
                stream_b_limb::<LB>(&row.bytes),
                stream_b_limb::<LB>(&next.bytes),
            )
        },
        2 => {
            let row = stream.low_second();
            let next = stream_next.high_second();
            (
                row.clk.dup(),
                row.lane_base.dup(),
                stream_b_limb::<LB>(&row.bytes),
                stream_b_limb::<LB>(&next.bytes),
            )
        },
        _ => unreachable!(),
    };
    AeadEidosCompressionOutputPairMsg {
        clk,
        first_lane_idx: lane_base + LB::Expr::from_u16(first_lane_offset),
        value0,
        value1,
    }
}

fn aead_stream_request_msg<LB>(
    stream: &AeadStreamCols<LB::Expr>,
    second_half_offset: u16,
) -> AeadStreamRequestMsg<LB::Expr>
where
    LB: NativeChipletLookupBuilder,
{
    let row = stream.low_second();
    let dst_ptr: LB::Expr = row.dst_ptr.dup();
    let lane_base: LB::Expr = row.lane_base.dup();
    let offset = LB::Expr::from_u16(second_half_offset);
    AeadStreamRequestMsg {
        ctx: row.ctx.dup(),
        clk: row.clk.dup(),
        src_ptr: row.src_ptr.dup(),
        dst_ptr: dst_ptr - offset.clone(),
        lane_base: lane_base - offset,
    }
}

fn stream_b_limb<LB>(bytes: &[LB::Expr; 12]) -> LB::Expr
where
    LB: NativeChipletLookupBuilder,
{
    pack_u32_bytes_le::<_, LB::Expr>(core::array::from_fn(|i| bytes[4 + i].dup()))
}
