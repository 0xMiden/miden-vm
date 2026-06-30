//! Hash-kernel virtual table bus.
//!
//! Combines five row-disjoint interaction families on a single LogUp column:
//!
//! 1. **Sibling table** (`BusId::SiblingTable`) - Merkle update siblings. On Merkle controller rows
//!    with `s0 * s1 = 1`, `s2` distinguishes MU (new path, removes siblings) from MV (old path,
//!    adds siblings). The direction bit `b = node_index - 2 * node_index_next` selects which half
//!    of `rate = [rate_0, rate_1]` holds the sibling, giving four gated interactions (two add, two
//!    remove).
//! 2. **ACE memory reads** - on ACE chiplet rows, the block selector distinguishes word reads
//!    (`f_ace_read`) from element reads used by EVAL rows (`f_ace_eval`). Both are removed from the
//!    chiplets bus.
//! 3. **AEAD stream memory I/O** (`BusId::{MemoryReadWord, MemoryWriteWord}`) - on stream rows,
//!    phases 0 and 4 remove the duplicated plaintext reads, and the two terminal phases remove
//!    ciphertext writes.
//! 4. **Normal bitwise AND8 checks** (`BusId::And8Lookup`) - on normal bitwise rows, four removes
//!    bind the bytewise `a & b` witnesses to the shared AND8 lookup table.
//! 5. **Memory-side range checks** (`BusId::RangeCheck`) - on memory chiplet rows, a five-remove
//!    batch consumes the two delta limbs `d0`/`d1` and the three word-address decomposition values
//!    `w0`, `w1`, and `4 * w1`. Together these enforce `d0, d1, w0, w1 in [0, 2^16)` plus `w1 in
//!    [0, 2^14)` (via the `4 * w1` check), which bounds `word_addr = 4 * (w0 + 2^16 * w1)` to the
//!    32-bit memory address space.
//!
//! Per-chiplet gating flows through [`ChipletBusContext::chiplet_active`]: the controller
//! gate is `chiplet_active.controller`, the ACE row gate is `chiplet_active.ace`, stream rows
//! use the derived AEAD stream flag, and the memory row gate is `chiplet_active.memory`. Hasher
//! sub-selectors, hasher state, `node_index`, and `mrupdate_id` come from the typed
//! [`local.controller()`](crate::constraints::columns::ChipletCols::controller) overlay;
//! memory delta limbs come from
//! [`local.memory()`](crate::constraints::columns::ChipletCols::memory).
//! `w0` / `w1` are not in the typed `MemoryCols` view (their physical columns live in
//! `chiplets[18..20]`, past the end of the memory overlay, shared with the ACE chiplet
//! column space), so they are read directly from the raw chiplet slice.

use core::{array, borrow::Borrow};

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    constraints::{
        chiplets::columns::PeriodicCols,
        lookup::{
            chiplet_air::{ChipletBusContext, ChipletLookupBuilder},
            messages::{And8Msg, MemoryMsg, RangeMsg, SiblingBit, SiblingMsg},
        },
        utils::{BoolNot, pack_u32_bytes_le},
    },
    lookup::{Deg, LookupBatch, LookupColumn, LookupGroup},
    trace::chiplets::ace::{ACE_INSTRUCTION_ID1_OFFSET, ACE_INSTRUCTION_ID2_OFFSET},
};

/// Upper bound on fractions this emitter pushes into its column per row.
///
/// Three row-type-disjoint interaction sets, mutually exclusive via chiplet active flags:
/// - **Sibling-table** on hasher controller rows (`chiplet_active.controller`): the MV/MU split is
///   mutually exclusive (`s2` vs `1-s2`) and the direction bit cuts within each side, so at most
///   one of the four fires per row -> 1 fraction.
/// - **ACE memory reads** on ACE rows (`chiplet_active.ace`): `f_ace_read` / `f_ace_eval` are
///   mutually exclusive via `block_sel` -> 1 fraction.
/// - **AEAD stream memory I/O** on stream rows: one memory interaction on each of phases 0, 3, 4,
///   and 7, so this contributes at most 1 fraction per row.
/// - **Normal bitwise AND8 checks** on normal bitwise rows: a 4-remove batch fires once per one-row
///   bitwise operation -> 4 fractions.
/// - **Memory-side range checks** on memory rows (`chiplet_active.memory`): a 5-remove batch (`d0`,
///   `d1`, `w0`, `w1`, `4 * w1`) fires unconditionally when the outer batch flag is active -> 5
///   fractions.
///
/// Row-type disjointness means only one set fires per row, so the per-row max is
/// `max(1, 1, 1, 4, 5) = 5`.
pub(in crate::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 5;

/// Emit the hash-kernel virtual table bus.
pub(in crate::constraints::lookup) fn emit_hash_kernel_table<LB>(
    builder: &mut LB,
    ctx: &ChipletBusContext<LB>,
) where
    LB: ChipletLookupBuilder,
{
    let local = ctx.local;
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

    // --- Sibling-table setup ---

    // Typed hasher-controller overlay: sub-selectors `s0/s1/s2`, state lanes, Merkle index data,
    // and carried MRUPDATE id.
    let ctrl = local.controller();

    let hs0: LB::Expr = ctrl.s0.into();
    let hs1: LB::Expr = ctrl.s1.into();
    let hs2: LB::Expr = ctrl.s2.into();

    // MU/MV controller-row flags for sibling-table participation. Both share `s0 * s1 = 1`;
    // they differ on `s2` (MU: `s2 = 1`, MV: `s2 = 0`) and fire at each Merkle path step.
    let controller_flag = ctx.chiplet_active.controller.clone();
    let f_mu_all: LB::Expr = controller_flag.clone() * hs0.clone() * hs1.clone() * hs2.clone();
    let f_mv_all: LB::Expr = controller_flag * hs0 * hs1 * hs2.not();

    // Hasher state is split by convention into `rate_0 (4), rate_1 (4), cap (4)` -
    // sibling messages only use the rate halves.
    let rate_0: [LB::Var; 4] = array::from_fn(|i| ctrl.state[i]);
    let rate_1: [LB::Var; 4] = array::from_fn(|i| ctrl.state[4 + i]);
    let mrupdate_id = local.controller_mrupdate_id();
    let node_index = ctrl.merkle_node_index();

    // Direction bit `b = node_index - 2 * node_index_next`. The bit / one_minus_bit combine
    // multiplicatively into the sibling flags below - they're computed once and cloned into
    // each `g.add` / `g.remove` flag argument.
    let node_index_next: LB::Expr = ctrl.merkle_node_index_next().into();
    let bit: LB::Expr = node_index.into() - node_index_next.double();
    let one_minus_bit: LB::Expr = bit.not();

    // --- ACE memory-read setup ---

    // Typed ACE chiplet overlay.
    let ace = local.ace();
    let block_sel: LB::Expr = ace.s_block.into();

    // ACE row gate comes from the shared `chiplet_active` snapshot; per-mode split by
    // `block_sel`.
    let is_ace_row = ctx.chiplet_active.ace.clone();
    let f_ace_read: LB::Expr = is_ace_row.clone() * block_sel.not();
    let f_ace_eval: LB::Expr = is_ace_row * block_sel;

    let ace_clk = ace.clk;
    let ace_ctx = ace.ctx;
    let ace_ptr = ace.ptr;
    let ace_v0 = ace.v_0;
    let ace_v1 = ace.v_1;
    let ace_id_1 = ace.id_1;
    let ace_id_2 = ace.eval().id_2;
    let ace_eval_op = ace.eval_op;
    let stream = local.aead_stream();
    let stream_gate = ctx.chiplet_active.aead_stream.clone();
    let bitwise = local.bitwise();
    let normal_bitwise_gate = ctx.chiplet_active.bitwise.clone();

    // --- Memory-side range-check setup ---

    let mem_active = ctx.chiplet_active.memory.clone();
    let mem = local.memory();
    let mem_d0 = mem.d0;
    let mem_d1 = mem.d1;
    let mem_w0 = local.memory_word_addr_lo();
    let mem_w1 = local.memory_word_addr_hi();

    builder.next_column(
        |col| {
            col.group(
                "sibling_ace_memory",
                |g| {
                    // --- SIBLING TABLE ---
                    // MV adds (old path), MU removes (new path); each splits on the Merkle
                    // direction bit into a BitZero (sibling at rate_1) and BitOne (sibling
                    // at rate_0) branch. Four mutually exclusive interactions total.
                    for (op_name, is_add, f_all, bit_tag, bit_gate) in [
                        (
                            "sibling_mv_b0",
                            true,
                            f_mv_all.clone(),
                            SiblingBit::Zero,
                            one_minus_bit.clone(),
                        ),
                        ("sibling_mv_b1", true, f_mv_all, SiblingBit::One, bit.clone()),
                        ("sibling_mu_b0", false, f_mu_all.clone(), SiblingBit::Zero, one_minus_bit),
                        ("sibling_mu_b1", false, f_mu_all, SiblingBit::One, bit),
                    ] {
                        let gate = f_all * bit_gate;
                        let build = move || {
                            let mrupdate_id: LB::Expr = mrupdate_id.into();
                            let node_index: LB::Expr = node_index.into();
                            let h = match bit_tag {
                                SiblingBit::Zero => array::from_fn(|i| rate_1[i].into()),
                                SiblingBit::One => array::from_fn(|i| rate_0[i].into()),
                            };
                            SiblingMsg { bit: bit_tag, mrupdate_id, node_index, h }
                        };
                        if is_add {
                            g.add(op_name, gate, build, Deg { v: 5, u: 6 });
                        } else {
                            g.remove(op_name, gate, build, Deg { v: 5, u: 6 });
                        }
                    }

                    // --- ACE MEMORY READS (chiplet-responses column) ---
                    // Word read on READ rows.
                    g.remove(
                        "ace_mem_read_word",
                        f_ace_read,
                        move || {
                            let clk = ace_clk.into();
                            let ctx = ace_ctx.into();
                            let addr = ace_ptr.into();
                            let word = [
                                ace_v0.0.into(),
                                ace_v0.1.into(),
                                ace_v1.0.into(),
                                ace_v1.1.into(),
                            ];
                            MemoryMsg::read_word(ctx, addr, clk, word)
                        },
                        Deg { v: 5, u: 6 },
                    );

                    // Element read on EVAL rows.
                    g.remove(
                        "ace_mem_eval_element",
                        f_ace_eval,
                        move || {
                            let clk = ace_clk.into();
                            let ctx = ace_ctx.into();
                            let addr = ace_ptr.into();
                            let id_1: LB::Expr = ace_id_1.into();
                            let id_2: LB::Expr = ace_id_2.into();
                            let eval_op: LB::Expr = ace_eval_op.into();
                            let element = id_1
                                + id_2 * LB::Expr::from(ACE_INSTRUCTION_ID1_OFFSET)
                                + (eval_op + LB::Expr::ONE)
                                    * LB::Expr::from(ACE_INSTRUCTION_ID2_OFFSET);
                            MemoryMsg::read_element(ctx, addr, clk, element)
                        },
                        Deg { v: 5, u: 6 },
                    );

                    // --- AEAD STREAM MEMORY I/O (chiplet rows) ---
                    // One 8-row stream entry reads one plaintext word and writes two ciphertext
                    // words. Both 4-row halves read the same source word, so each half is bound
                    // directly to the memory chiplet.
                    let mut remove_stream_read = |name: &'static str, phase_idx: usize| {
                        let gate = stream_gate.clone() * aead_phase[phase_idx].clone();
                        g.remove(
                            name,
                            gate,
                            || {
                                let row = stream.read();
                                let word = row.plaintext.map(Into::into);
                                MemoryMsg::read_word(
                                    row.ctx.into(),
                                    row.src_ptr.into(),
                                    row.clk.into(),
                                    word,
                                )
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
                                    row.c_prev0.into(),
                                    row.c_prev1.into(),
                                    row.c_prev2.into(),
                                    stream_xor_limb::<LB>(row.bytes),
                                ];
                                MemoryMsg::write_word(
                                    row.ctx.into(),
                                    row.dst_ptr.into(),
                                    row.clk.into(),
                                    word,
                                )
                            },
                            Deg { v: 4, u: 5 },
                        );
                    };
                    remove_stream_write("aead_stream_write0", 3);
                    remove_stream_write("aead_stream_write1", 7);

                    // --- NORMAL BITWISE AND8 CHECKS (BusId::And8Lookup) ---
                    //
                    // The response column emits `BitwiseMsg`. This column carries the four AND8
                    // removals, reusing row-disjoint capacity instead of widening the chiplet
                    // lookup shape.
                    g.batch(
                        "bitwise_and8_lookups",
                        normal_bitwise_gate,
                        |b| {
                            for idx in 0..4 {
                                b.remove(
                                    "bitwise_and8_byte",
                                    And8Msg::new(
                                        bitwise.a_bytes[idx].into(),
                                        bitwise.b_bytes[idx].into(),
                                        bitwise.and_bytes[idx].into(),
                                    ),
                                    Deg { v: 2, u: 3 },
                                );
                            }
                        },
                        Deg { v: 5, u: 6 },
                    );

                    // --- MEMORY-SIDE RANGE CHECKS (BusId::RangeCheck) ---
                    // Five removes per memory-active row:
                    // - `d0`, `d1` - the two 16-bit delta limbs used by the memory chiplet's
                    //   sorted-access constraints.
                    // - `w0`, `w1`, `4 * w1` - the word-address decomposition limbs. The `4 * w1`
                    //   check additionally enforces `w1 in [0, 2^14)`, which bounds `word_addr = 4
                    //   * (w0 + 2^16 * w1) < 2^32`.
                    g.batch(
                        "memory_range_checks",
                        mem_active,
                        move |b| {
                            b.remove(
                                "mem_d0",
                                RangeMsg { value: mem_d0.into() },
                                Deg { v: 3, u: 4 },
                            );
                            b.remove(
                                "mem_d1",
                                RangeMsg { value: mem_d1.into() },
                                Deg { v: 3, u: 4 },
                            );
                            let w0: LB::Expr = mem_w0.into();
                            let w1: LB::Expr = mem_w1.into();
                            let w1_mul4 = w1.clone() * LB::Expr::from_u16(4);
                            b.remove("mem_w0", RangeMsg { value: w0 }, Deg { v: 3, u: 4 });
                            b.remove("mem_w1", RangeMsg { value: w1 }, Deg { v: 3, u: 4 });
                            b.remove(
                                "mem_w1_mul4",
                                RangeMsg { value: w1_mul4 },
                                Deg { v: 3, u: 4 },
                            );
                        },
                        Deg { v: 7, u: 8 }, // (V, U) = (4 + 3, 5 + 3); mem_active flag deg 3
                    );
                },
                Deg { v: 7, u: 8 },
            );
        },
        Deg { v: 7, u: 8 },
    );
}

fn stream_xor_limb<LB>(bytes: [LB::Var; 12]) -> LB::Expr
where
    LB: ChipletLookupBuilder,
{
    let two = LB::Expr::from_u8(2);
    let xor_bytes = [
        Into::<LB::Expr>::into(bytes[0]) + Into::<LB::Expr>::into(bytes[4])
            - two.clone() * Into::<LB::Expr>::into(bytes[8]),
        Into::<LB::Expr>::into(bytes[1]) + Into::<LB::Expr>::into(bytes[5])
            - two.clone() * Into::<LB::Expr>::into(bytes[9]),
        Into::<LB::Expr>::into(bytes[2]) + Into::<LB::Expr>::into(bytes[6])
            - two.clone() * Into::<LB::Expr>::into(bytes[10]),
        Into::<LB::Expr>::into(bytes[3]) + Into::<LB::Expr>::into(bytes[7])
            - two * Into::<LB::Expr>::into(bytes[11]),
    ];
    pack_u32_bytes_le::<_, LB::Expr>(xor_bytes)
}
