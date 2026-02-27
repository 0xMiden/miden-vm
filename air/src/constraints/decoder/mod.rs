//! Decoder constraints module.
//!
//! This module contains constraints for the decoder component of the Miden VM.
//! The decoder handles instruction decoding, control flow, and basic block management.
//!
//! ## Constraint Categories
//!
//! 1. **Op Bit Constraints**: Ensure operation bits are binary
//! 2. **Op Bits Extra Columns**: Ensure degree reduction columns are correctly computed
//! 3. **Batch Flag Constraints**: Ensure batch flags are binary and properly set
//! 4. **In-Span Constraints**: Ensure in-span flag transitions correctly
//! 5. **Group Count Constraints**: Ensure group count transitions correctly
//!
//! ## Mental Model
//!
//! The decoder trace is the control-flow spine of the VM. Each row is either:
//! - **inside a basic block** (sp = 1) where ops execute and counters advance, or
//! - **a control-flow row** (sp = 0) that starts/ends/reshapes a block.
//!
//! The constraints below enforce three linked ideas:
//! 1. **Opcode decoding is well-formed** (op bits and degree-reduction columns are consistent).
//! 2. **Span state is coherent** (sp, group_count, op_index evolve exactly as control-flow allows).
//! 3. **Hasher lanes match batch semantics** (batch flags and h0..h7 encode the pending groups).
//!
//! Read the sections in that order: first the binary/format checks, then the span state machine,
//! then the counters and packing rules that make group decoding deterministic.
//!
//! ## Decoder Trace Layout
//!
//! The decoder trace consists of the following columns:
//! - `addr`: Block address (row address in hasher table)
//! - `b0-b6`: 7 operation bits encoding the opcode
//! - `h0-h7`: 8 hasher state columns (shared between decoding and program hashing)
//! - `sp`: In-span flag (1 when inside basic block, 0 otherwise)
//! - `gc`: Group count (remaining operation groups in current span)
//! - `ox`: Operation index (position within current operation group, 0-8)
//! - `c0, c1, c2`: Batch flags (encode number of groups in current batch)
//! - `e0, e1`: Extra columns for degree reduction

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use crate::{
    MainTraceRow,
    constraints::{
        op_flags::{ExprDecoderAccess, OpFlags},
        tagging::{TaggingAirBuilderExt, ids::TAG_DECODER_BASE},
    },
    trace::decoder as decoder_cols,
};

pub mod bus;
#[cfg(test)]
pub mod tests;

// CONSTANTS
// ================================================================================================

/// Index offset for block address column within decoder (column 0).
const ADDR_OFFSET: usize = 0;

/// Index offsets within the decoder array for op bits (b0-b6).
/// Op bits start at index 1 in the decoder (after addr at index 0).
const OP_BITS_OFFSET: usize = 1;

/// Hash cycle length for Poseidon2 (32 rows per permutation).
const HASH_CYCLE_LEN: u64 = 32;

/// Number of operation bits.
const NUM_OP_BITS: usize = 7;

/// Index offset for in-span column within decoder.
const IN_SPAN_OFFSET: usize = 16;

/// Index offset for group count column within decoder.
const GROUP_COUNT_OFFSET: usize = 17;

/// Index offset for operation index column within decoder.
const OP_INDEX_OFFSET: usize = 18;

/// Index offset for batch flags within decoder.
const BATCH_FLAGS_OFFSET: usize = 19;

/// Number of batch flag columns.
const NUM_BATCH_FLAGS: usize = 3;

/// Index offset for extra columns (e0, e1) within decoder.
const EXTRA_COLS_OFFSET: usize = 22;

/// Number of decoder constraints, in the order of `DECODER_NAMES`.
/// - 7 op bits binary constraints
/// - 2 extra columns constraints (e0, e1)
/// - 3 op-bit group constraints (u32 b0, very-high b0/b1)
/// - 3 batch flags binary constraints
/// - 14 general constraints
/// - 1 in-span boundary constraint (first row sp = 0)
/// - 1 in-span binary constraint
/// - 2 in-span transition constraints (after SPAN/RESPAN, sp' = 1)
/// - 5 group count constraints
/// - 2 op group decoding constraints
/// - 4 op index constraints
/// - 9 op batch flag constraints
/// - 3 block address constraints
/// - 1 control flow constraint (1 - sp - f_ctrl = 0)
#[allow(dead_code)]
pub const NUM_CONSTRAINTS: usize = 57;

/// Base ID for decoder constraints (inclusive).
const DECODER_BASE_ID: usize = TAG_DECODER_BASE;

/// Decoder constraint namespaces in assertion order.
const DECODER_NAMES: [&str; NUM_CONSTRAINTS] = [
    // in-span constraints (boundary first, then transition rules)
    "decoder.in_span.first_row",
    "decoder.in_span.binary",
    "decoder.in_span.span",
    "decoder.in_span.respan",
    // op bits binary (b0..b6)
    "decoder.op_bits.b0.binary",
    "decoder.op_bits.b1.binary",
    "decoder.op_bits.b2.binary",
    "decoder.op_bits.b3.binary",
    "decoder.op_bits.b4.binary",
    "decoder.op_bits.b5.binary",
    "decoder.op_bits.b6.binary",
    // extra columns (e0, e1)
    "decoder.extra.e0",
    "decoder.extra.e1",
    // op-bit group constraints
    "decoder.op_bits.u32_prefix.b0",
    "decoder.op_bits.very_high.b0",
    "decoder.op_bits.very_high.b1",
    // batch flags binary (c0..c2)
    "decoder.batch_flags.c0.binary",
    "decoder.batch_flags.c1.binary",
    "decoder.batch_flags.c2.binary",
    // general constraints
    "decoder.general.split_loop.s0.binary",
    "decoder.general.dyn.h4.zero",
    "decoder.general.dyn.h5.zero",
    "decoder.general.dyn.h6.zero",
    "decoder.general.dyn.h7.zero",
    "decoder.general.repeat.s0.one",
    "decoder.general.repeat.h4.one",
    "decoder.general.end.loop.s0.zero",
    "decoder.general.end_repeat.h0.carry",
    "decoder.general.end_repeat.h1.carry",
    "decoder.general.end_repeat.h2.carry",
    "decoder.general.end_repeat.h3.carry",
    "decoder.general.end_repeat.h4.carry",
    "decoder.general.halt.next",
    // group count constraints
    "decoder.group_count.delta.binary",
    "decoder.group_count.decrement.h0_or_imm",
    "decoder.group_count.span_decrement",
    "decoder.group_count.end_or_respan.hold",
    "decoder.group_count.end.zero",
    // op group decoding constraints
    "decoder.op_group.shift",
    "decoder.op_group.end_or_respan.h0.zero",
    // op index constraints
    "decoder.op_index.span_respan.reset",
    "decoder.op_index.new_group.reset",
    "decoder.op_index.increment",
    "decoder.op_index.range",
    // batch flag constraints and zeroing rules
    "decoder.batch_flags.span_sum",
    "decoder.batch_flags.zero_when_not_span",
    "decoder.batch_flags.h4.zero",
    "decoder.batch_flags.h5.zero",
    "decoder.batch_flags.h6.zero",
    "decoder.batch_flags.h7.zero",
    "decoder.batch_flags.h2.zero",
    "decoder.batch_flags.h3.zero",
    "decoder.batch_flags.h1.zero",
    // block address constraints
    "decoder.addr.hold_in_span",
    "decoder.addr.respan.increment",
    "decoder.addr.halt.zero",
    // control flow constraint
    "decoder.control_flow.sp_complement",
];

// Relative offsets into DECODER_NAMES by constraint group.
const IN_SPAN_BASE: usize = 0;
const OP_BITS_BASE: usize = IN_SPAN_BASE + 4;
const EXTRA_BASE: usize = OP_BITS_BASE + NUM_OP_BITS;
const OP_BIT_GROUP_BASE: usize = EXTRA_BASE + 2;
const BATCH_FLAGS_BINARY_BASE: usize = OP_BIT_GROUP_BASE + 3;
const GENERAL_BASE: usize = BATCH_FLAGS_BINARY_BASE + NUM_BATCH_FLAGS;
const GROUP_COUNT_BASE: usize = GENERAL_BASE + 14;
const OP_GROUP_DECODING_BASE: usize = GROUP_COUNT_BASE + 5;
const OP_INDEX_BASE: usize = OP_GROUP_DECODING_BASE + 2;
const BATCH_FLAGS_BASE: usize = OP_INDEX_BASE + 4;
const ADDR_BASE: usize = BATCH_FLAGS_BASE + 9;
const CONTROL_FLOW_BASE: usize = ADDR_BASE + 3;

// Global tag base IDs by constraint group (decoder IDs are contiguous from TAG_DECODER_BASE).
const OP_BITS_BASE_ID: usize = DECODER_BASE_ID + OP_BITS_BASE;
const EXTRA_BASE_ID: usize = DECODER_BASE_ID + EXTRA_BASE;
const OP_BIT_GROUP_BASE_ID: usize = DECODER_BASE_ID + OP_BIT_GROUP_BASE;
const BATCH_FLAGS_BINARY_BASE_ID: usize = DECODER_BASE_ID + BATCH_FLAGS_BINARY_BASE;
const GENERAL_BASE_ID: usize = DECODER_BASE_ID + GENERAL_BASE;
const IN_SPAN_BASE_ID: usize = DECODER_BASE_ID + IN_SPAN_BASE;
const GROUP_COUNT_BASE_ID: usize = DECODER_BASE_ID + GROUP_COUNT_BASE;
const OP_GROUP_DECODING_BASE_ID: usize = DECODER_BASE_ID + OP_GROUP_DECODING_BASE;
const OP_INDEX_BASE_ID: usize = DECODER_BASE_ID + OP_INDEX_BASE;
const BATCH_FLAGS_BASE_ID: usize = DECODER_BASE_ID + BATCH_FLAGS_BASE;
const ADDR_BASE_ID: usize = DECODER_BASE_ID + ADDR_BASE;
const CONTROL_FLOW_BASE_ID: usize = DECODER_BASE_ID + CONTROL_FLOW_BASE;

/// The degrees of the decoder constraints.
#[allow(dead_code)]
pub const CONSTRAINT_DEGREES: [usize; NUM_CONSTRAINTS] = [
    2, 2, 2, 2, 2, 2, 2, // op bits binary (degree 2)
    4, 3, // e0 (degree 4), e1 (degree 3)
    4, 3, 3, // u32 b0, very-high b0/b1
    2, 2, 2, // batch flags binary (degree 2)
    7, 6, 6, 6, 6, // general: split/loop top binary, dyn h4..h7 = 0
    5, 5, // general: repeat top=1, repeat in-loop
    6, // general: end + is_loop + s0
    9, 9, 9, 9, 9, // general: end + repeat' copies h0..h4
    8, // general: halt -> halt'
    1, // sp first row (degree 1)
    2, // sp binary (degree 2)
    6, 5, // sp transition for SPAN (deg 5+1=6), RESPAN (deg 4+1=5)
    3, // gc delta bounded (degree 3: sp * delta * (delta - 1))
    8, // gc decrement implies (h0=0 or is_push=1)
    6, // gc decrement on SPAN/RESPAN/PUSH
    5, // gc stays when next is END or RESPAN
    5, // gc zero at END
    6, // op group decoding: h0 shift by op'
    6, // op group decoding: h0 must be 0 before END/RESPAN
    6, // ox reset on SPAN/RESPAN (degree 6)
    6, // ox reset on new group (degree 6: sp * ng * ox')
    7, // ox increment inside basic block (degree 7)
    9, // ox range [0,8] (degree 9)
    5, // batch flags sum (span/respan -> one of g1/g2/g4/g8)
    6, // batch flags zero when not span/respan
    4, 4, 4, 4, // h4..h7 zero when <=4 groups
    4, 4, // h2..h3 zero when <=2 groups
    4, // h1 zero when <=1 group
    2, // addr unchanged inside basic block (degree 2)
    5, // addr increment on RESPAN (degree 5)
    5, // addr zero at HALT (degree 5)
    5, // control flow: 1 - sp - f_ctrl = 0
];

// SMALL HELPERS
// ================================================================================================

/// Asserts a value is binary (0 or 1): `x * (x - 1) = 0`.
fn assert_binary<AB>(builder: &mut AB, id: usize, name: &'static str, value: AB::Expr)
where
    AB: MidenAirBuilder,
{
    builder.tagged(id, name, |builder| {
        builder.assert_zero(value.clone() * (value - AB::Expr::ONE));
    });
}

/// Computes the opcode value from op bits: `b0 + 2*b1 + ... + 64*b6`.
fn op_bits_to_value<AB>(bits: &[AB::Expr; NUM_OP_BITS]) -> AB::Expr
where
    AB: MidenAirBuilder,
{
    bits.iter().enumerate().fold(AB::Expr::ZERO, |acc, (i, bit)| {
        acc + bit.clone() * AB::Expr::from_u16(1u16 << i)
    })
}

// ENTRY POINTS
// ================================================================================================

/// Enforces decoder main-trace constraints (entry point).
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // Load decoder columns using typed struct
    let cols: DecoderColumns<AB::Expr> = DecoderColumns::from_row::<AB>(local);
    let cols_next: DecoderColumns<AB::Expr> = DecoderColumns::from_row::<AB>(next);
    let op_flags_next = OpFlags::new(ExprDecoderAccess::<AB::Var, AB::Expr>::new(next));

    enforce_in_span_constraints(builder, &cols, &cols_next, op_flags);
    enforce_op_bits_binary(builder, &cols);
    enforce_extra_columns(builder, &cols);
    enforce_op_bit_group_constraints(builder, &cols);
    enforce_batch_flags_binary(builder, &cols);
    enforce_general_constraints(builder, local, next, op_flags, &op_flags_next);
    enforce_group_count_constraints(builder, &cols, &cols_next, local, op_flags, &op_flags_next);
    enforce_op_group_decoding_constraints(
        builder,
        &cols,
        &cols_next,
        local,
        next,
        op_flags,
        &op_flags_next,
    );
    enforce_op_index_constraints(builder, &cols, &cols_next, op_flags);
    enforce_batch_flags_constraints(builder, &cols, local, op_flags);
    enforce_block_address_constraints(builder, &cols, &cols_next, op_flags);
    enforce_control_flow_constraints(builder, &cols, op_flags);
}

// INTERNAL HELPERS
// ================================================================================================

/// Typed access to decoder columns.
///
/// This struct provides named access to decoder columns, eliminating error-prone
/// index arithmetic. Created from a `MainTraceRow` reference.
///
/// ## Layout
/// - `addr`: Block address (row address in hasher table)
/// - `op_bits[0..7]`: Operation bits b0-b6 encoding the opcode
/// - `in_span`: In-span flag (sp) - 1 when inside basic block
/// - `group_count`: Group count (gc) - remaining operation groups
/// - `op_index`: Operation index (ox) - position within group (0-8)
/// - `batch_flags[0..3]`: Batch flags c0, c1, c2
/// - `extra[0..2]`: Extra columns e0, e1 for degree reduction
///
/// Note: the 8 decoder hasher-state lanes live in the decoder trace but are not included here.
/// Constraints which depend on these lanes access them directly via `MainTraceRow` accessors.
pub struct DecoderColumns<E> {
    /// Block address (row address in hasher table)
    pub addr: E,
    /// Operation bits b0-b6 (7 bits encoding the opcode)
    pub op_bits: [E; NUM_OP_BITS],
    /// In-span flag (1 when inside basic block, 0 otherwise)
    pub in_span: E,
    /// Group count (remaining operation groups in current span)
    pub group_count: E,
    /// Operation index (position within current operation group, 0-8)
    pub op_index: E,
    /// Batch flags c0, c1, c2 (encode number of groups in current batch)
    pub batch_flags: [E; NUM_BATCH_FLAGS],
    /// Extra columns e0, e1 for degree reduction
    pub extra: [E; 2],
}

impl<E: Clone> DecoderColumns<E> {
    /// Extract decoder columns from a main trace row.
    pub fn from_row<AB>(row: &MainTraceRow<AB::Var>) -> Self
    where
        AB: MidenAirBuilder,
        AB::Var: Into<E> + Clone,
    {
        DecoderColumns {
            addr: row.decoder[ADDR_OFFSET].clone().into(),
            op_bits: core::array::from_fn(|i| row.decoder[OP_BITS_OFFSET + i].clone().into()),
            in_span: row.decoder[IN_SPAN_OFFSET].clone().into(),
            group_count: row.decoder[GROUP_COUNT_OFFSET].clone().into(),
            op_index: row.decoder[OP_INDEX_OFFSET].clone().into(),
            batch_flags: core::array::from_fn(|i| {
                row.decoder[BATCH_FLAGS_OFFSET + i].clone().into()
            }),
            extra: core::array::from_fn(|i| row.decoder[EXTRA_COLS_OFFSET + i].clone().into()),
        }
    }
}

// CONSTRAINT HELPERS
// ================================================================================================

/// Enforces that all operation bits (b0-b6) are binary (0 or 1).
///
/// For each bit bi: bi * (bi - 1) = 0
fn enforce_op_bits_binary<AB>(builder: &mut AB, cols: &DecoderColumns<AB::Expr>)
where
    AB: MidenAirBuilder,
{
    for i in 0..NUM_OP_BITS {
        let id = OP_BITS_BASE_ID + i;
        let namespace = DECODER_NAMES[OP_BITS_BASE + i];
        // Each opcode bit must be 0 or 1 to make decoding deterministic.
        assert_binary(builder, id, namespace, cols.op_bits[i].clone());
    }
}

/// Enforces that the extra columns (e0, e1) are correctly computed from op bits.
///
/// These columns are used for degree reduction in operation flag computation:
/// - e0 = b6 * (1 - b5) * b4
/// - e1 = b6 * b5
fn enforce_extra_columns<AB>(builder: &mut AB, cols: &DecoderColumns<AB::Expr>)
where
    AB: MidenAirBuilder,
{
    let b4 = cols.op_bits[4].clone();
    let b5 = cols.op_bits[5].clone();
    let b6 = cols.op_bits[6].clone();

    let e0 = cols.extra[0].clone();
    let e1 = cols.extra[1].clone();

    // e0 = b6 * (1 - b5) * b4.
    // This extra register exists to reduce the degree of op-flag selectors for the
    // `101...` opcode group (see docs/src/design/stack/op_constraints.md).
    let expected_e0 = b6.clone() * (AB::Expr::ONE - b5.clone()) * b4;
    builder.tagged(EXTRA_BASE_ID, DECODER_NAMES[EXTRA_BASE], |builder| {
        builder.assert_zero(e0 - expected_e0);
    });

    // e1 = b6 * b5.
    // This extra register exists to reduce the degree of op-flag selectors for the
    // `11...` opcode group (see docs/src/design/stack/op_constraints.md).
    let expected_e1 = b6 * b5;
    builder.tagged(EXTRA_BASE_ID + 1, DECODER_NAMES[EXTRA_BASE + 1], |builder| {
        builder.assert_zero(e1 - expected_e1);
    });
}

/// Enforces opcode-bit constraints for grouped opcode families.
///
/// - U32 ops (prefix `100`) must have b0 = 0.
/// - Very-high-degree ops (prefix `11`) must have b0 = b1 = 0.
fn enforce_op_bit_group_constraints<AB>(builder: &mut AB, cols: &DecoderColumns<AB::Expr>)
where
    AB: MidenAirBuilder,
{
    let b0 = cols.op_bits[0].clone();
    let b1 = cols.op_bits[1].clone();
    let b4 = cols.op_bits[4].clone();
    let b5 = cols.op_bits[5].clone();
    let b6 = cols.op_bits[6].clone();

    // U32 prefix pattern: b6=1, b5=0, b4=0. Under this prefix, b0 must be 0 to
    // eliminate invalid opcodes in the U32 opcode subset.
    let u32_prefix = b6.clone() * (AB::Expr::ONE - b5.clone()) * (AB::Expr::ONE - b4);
    builder.tagged(OP_BIT_GROUP_BASE_ID, DECODER_NAMES[OP_BIT_GROUP_BASE], |builder| {
        builder.assert_zero(u32_prefix * b0.clone());
    });

    // Very-high prefix pattern: b6=1, b5=1. Under this prefix, b0 and b1 must be 0
    // to eliminate invalid opcodes in the very-high opcode subset.
    let very_high_prefix = b6 * b5;
    builder.tagged(OP_BIT_GROUP_BASE_ID + 1, DECODER_NAMES[OP_BIT_GROUP_BASE + 1], |builder| {
        builder.assert_zero(very_high_prefix.clone() * b0);
    });
    builder.tagged(OP_BIT_GROUP_BASE_ID + 2, DECODER_NAMES[OP_BIT_GROUP_BASE + 2], |builder| {
        builder.assert_zero(very_high_prefix * b1);
    });
}

/// Enforces that batch flags (c0, c1, c2) are binary.
///
/// For each flag ci: ci * (ci - 1) = 0
fn enforce_batch_flags_binary<AB>(builder: &mut AB, cols: &DecoderColumns<AB::Expr>)
where
    AB: MidenAirBuilder,
{
    for i in 0..NUM_BATCH_FLAGS {
        let id = BATCH_FLAGS_BINARY_BASE_ID + i;
        let namespace = DECODER_NAMES[BATCH_FLAGS_BINARY_BASE + i];
        // Batch flags are selectors; they must be boolean.
        assert_binary(builder, id, namespace, cols.batch_flags[i].clone());
    }
}

/// Enforces in-span (sp) constraints.
///
/// The in-span flag indicates whether we're inside a basic block:
/// - sp = 1 when executing operations inside a basic block
/// - sp = 0 for SPAN, RESPAN, END, and control-flow operations
///
/// This is the entry point to the decoder state machine. Once sp is set by SPAN/RESPAN,
/// the rest of the decoder constraints (gc, ox, batch flags) are interpreted relative to
/// being inside that span.
///
/// Constraints:
/// 1. sp is binary: sp * (sp - 1) = 0
/// 2. After SPAN operation, sp' = 1: span_flag * (1 - sp') = 0
/// 3. After RESPAN operation, sp' = 1: respan_flag * (1 - sp') = 0
fn enforce_in_span_constraints<AB>(
    builder: &mut AB,
    cols: &DecoderColumns<AB::Expr>,
    cols_next: &DecoderColumns<AB::Expr>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let sp = cols.in_span.clone();
    let sp_next = cols_next.in_span.clone();

    // Boundary: execution starts outside any basic block.
    builder.tagged(IN_SPAN_BASE_ID, DECODER_NAMES[IN_SPAN_BASE], |builder| {
        builder.when_first_row().assert_zero(sp.clone());
    });

    // Constraint 1: sp is binary, so span state is well-formed.
    let sp_binary = sp.clone() * (sp - AB::Expr::ONE);
    builder.tagged(IN_SPAN_BASE_ID + 1, DECODER_NAMES[IN_SPAN_BASE + 1], |builder| {
        builder.assert_zero(sp_binary);
    });

    // Constraint 2: After SPAN, the next row must be inside a span.
    // span_flag * (1 - sp') = 0
    let span_flag = op_flags.span();
    builder.tagged(IN_SPAN_BASE_ID + 2, DECODER_NAMES[IN_SPAN_BASE + 2], |builder| {
        builder
            .when_transition()
            .assert_zero(span_flag * (AB::Expr::ONE - sp_next.clone()));
    });

    // Constraint 3: After RESPAN, the next row must be inside a span.
    // respan_flag * (1 - sp') = 0
    let respan_flag = op_flags.respan();
    builder.tagged(IN_SPAN_BASE_ID + 3, DECODER_NAMES[IN_SPAN_BASE + 3], |builder| {
        builder.when_transition().assert_zero(respan_flag * (AB::Expr::ONE - sp_next));
    });
}

/// Enforces group count (gc) constraints.
///
/// The group count tracks remaining operation groups in the current basic block:
/// - gc starts at the total number of groups when SPAN/RESPAN is executed
/// - gc decrements by 1 when processing SPAN, RESPAN, or completing a group
/// - gc must be 0 when END is executed
///
/// Intuition:
/// - `delta_gc = gc - gc'` is the number of groups consumed on this row.
/// - Inside a span, delta_gc can only be 0 or 1.
/// - SPAN/RESPAN/PUSH must consume a group immediately, so delta_gc must be 1.
///
/// Constraints:
/// 1. Inside basic block, gc can only stay same or decrement by 1: sp * delta_gc * (delta_gc - 1) =
///    0  (where delta_gc = gc - gc')
/// 2. When END is executed, gc must be 0: end_flag * gc = 0
/// 3. During SPAN/RESPAN, gc must decrement by 1: (span_flag + respan_flag) * (1 - delta_gc) = 0
fn enforce_group_count_constraints<AB>(
    builder: &mut AB,
    cols: &DecoderColumns<AB::Expr>,
    cols_next: &DecoderColumns<AB::Expr>,
    local: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    op_flags_next: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let sp = cols.in_span.clone();
    let gc = cols.group_count.clone();
    let gc_next = cols_next.group_count.clone();
    let h0: AB::Expr = local.decoder[decoder_cols::HASHER_STATE_OFFSET].clone().into();

    // delta_gc = gc - gc' (how much gc decrements; expected to be 0 or 1)
    let delta_gc = gc.clone() - gc_next;

    // is_push = push flag (PUSH is the only operation with immediate value)
    let is_push = op_flags.push();

    // Constraint 1: Inside a span, gc can only stay the same or decrement by 1.
    // sp * delta_gc * (delta_gc - 1) = 0
    // This ensures: if sp=1 and delta_gc != 0, then delta_gc must equal 1
    builder.tagged(GROUP_COUNT_BASE_ID, DECODER_NAMES[GROUP_COUNT_BASE], |builder| {
        builder
            .when_transition()
            .assert_zero(sp.clone() * delta_gc.clone() * (delta_gc.clone() - AB::Expr::ONE));
    });

    // Constraint 2: If gc decrements and this is not a PUSH-immediate row,
    // then h0 must be zero (no immediate value packed into the group).
    // sp * delta_gc * (1 - is_push) * h0 = 0
    builder.tagged(GROUP_COUNT_BASE_ID + 1, DECODER_NAMES[GROUP_COUNT_BASE + 1], |builder| {
        builder
            .when_transition()
            .assert_zero(sp.clone() * delta_gc.clone() * (AB::Expr::ONE - is_push.clone()) * h0);
    });

    // Constraint 3: SPAN/RESPAN/PUSH must consume a group immediately.
    // (span_flag + respan_flag + is_push) * (delta_gc - 1) = 0
    let span_flag = op_flags.span();
    let respan_flag = op_flags.respan();
    builder.tagged(GROUP_COUNT_BASE_ID + 2, DECODER_NAMES[GROUP_COUNT_BASE + 2], |builder| {
        builder
            .when_transition()
            .assert_zero((span_flag + respan_flag + is_push) * (delta_gc.clone() - AB::Expr::ONE));
    });

    // Constraint 4: If the next op is END or RESPAN, gc cannot decrement on this row.
    // delta_gc * (end' + respan') = 0
    let end_next = op_flags_next.end();
    let respan_next = op_flags_next.respan();
    builder.tagged(GROUP_COUNT_BASE_ID + 3, DECODER_NAMES[GROUP_COUNT_BASE + 3], |builder| {
        builder
            .when_transition()
            .assert_zero(delta_gc.clone() * (end_next + respan_next));
    });

    // Constraint 5: END closes the span, so gc must be 0.
    // end_flag * gc = 0
    let end_flag = op_flags.end();
    builder.tagged(GROUP_COUNT_BASE_ID + 4, DECODER_NAMES[GROUP_COUNT_BASE + 4], |builder| {
        builder.assert_zero(end_flag * gc);
    });
}

/// Enforces op index (ox) constraints.
///
/// The op index tracks the position of the current operation within its operation group:
/// - ox ranges from 0 to 8 (9 operations per group)
/// - ox resets to 0 when entering a new group (SPAN, RESPAN, or group boundary)
/// - ox increments by 1 for each operation within a group
///
/// Intuition:
/// - `ng = delta_gc - is_push` is 1 when a new group starts (excluding PUSH-immediate rows).
/// - When a new group starts, ox' must be 0.
/// - Otherwise, ox increments by 1 while sp stays 1.
///
/// Constraints:
/// 1. After SPAN/RESPAN, ox' = 0: (span_flag + respan_flag) * ox' = 0
/// 2. When starting new group inside basic block (gc decrements), ox' = 0: sp * delta_gc * ox' = 0
/// 3. When inside basic block and not starting new group, ox increments by 1: sp * sp' * (1 -
///    delta_gc) * (ox' - ox - 1) = 0
/// 4. Op index must be in range [0, 8]: ox * (ox-1) * (ox-2) * (ox-3) * (ox-4) * (ox-5) * (ox-6) *
///    (ox-7) * (ox-8) = 0
fn enforce_op_index_constraints<AB>(
    builder: &mut AB,
    cols: &DecoderColumns<AB::Expr>,
    cols_next: &DecoderColumns<AB::Expr>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let sp = cols.in_span.clone();
    let sp_next = cols_next.in_span.clone();
    let gc = cols.group_count.clone();
    let gc_next = cols_next.group_count.clone();
    let ox = cols.op_index.clone();
    let ox_next = cols_next.op_index.clone();

    // delta_gc = gc - gc' (how much gc decrements; 1 when entering new group)
    let delta_gc = gc.clone() - gc_next;

    // is_push = push flag (PUSH is the only operation with immediate value)
    let is_push = op_flags.push();

    // ng = delta_gc - is_push
    // This equals 1 when we're starting a new operation group (not due to immediate op)
    let ng = delta_gc - is_push;

    let span_flag = op_flags.span();
    let respan_flag = op_flags.respan();

    // Constraint 1: SPAN/RESPAN start a fresh group, so ox' = 0.
    // (span_flag + respan_flag) * ox' = 0
    builder.tagged(OP_INDEX_BASE_ID, DECODER_NAMES[OP_INDEX_BASE], |builder| {
        builder
            .when_transition()
            .assert_zero((span_flag + respan_flag) * ox_next.clone());
    });

    // Constraint 2: When a new group starts inside a span, ox' = 0.
    // sp * ng * ox' = 0
    builder.tagged(OP_INDEX_BASE_ID + 1, DECODER_NAMES[OP_INDEX_BASE + 1], |builder| {
        builder.when_transition().assert_zero(sp.clone() * ng.clone() * ox_next.clone());
    });

    // Constraint 3: When staying in the same group, ox increments by 1.
    // sp * sp' * (1 - ng) * (ox' - ox - 1) = 0
    let delta_ox = ox_next - ox.clone() - AB::Expr::ONE;
    builder.tagged(OP_INDEX_BASE_ID + 2, DECODER_NAMES[OP_INDEX_BASE + 2], |builder| {
        builder
            .when_transition()
            .assert_zero(sp * sp_next * (AB::Expr::ONE - ng) * delta_ox);
    });

    // Constraint 4: ox must be in range [0, 8] (9 ops per group).
    // ∏_{i=0}^{8}(ox - i) = 0
    let mut range_check = ox.clone();
    for i in 1..=8u64 {
        range_check *= ox.clone() - AB::Expr::from_u16(i as u16);
    }
    builder.tagged(OP_INDEX_BASE_ID + 3, DECODER_NAMES[OP_INDEX_BASE + 3], |builder| {
        builder.assert_zero(range_check);
    });
}

/// Enforces block address (addr) constraints.
///
/// The block address identifies the current code block in the hasher table:
/// - addr stays constant inside a basic block (sp = 1)
/// - addr increments by HASH_CYCLE_LEN (32) after RESPAN
/// - addr must be 0 when HALT is executed
///
/// This ties the span state to the hasher table position.
///
/// Constraints:
/// 1. Inside basic block, address unchanged: sp * (addr' - addr) = 0
/// 2. RESPAN increments address by HASH_CYCLE_LEN: respan_flag * (addr' - addr - HASH_CYCLE_LEN) =
///    0
/// 3. HALT has addr = 0: halt_flag * addr = 0
fn enforce_block_address_constraints<AB>(
    builder: &mut AB,
    cols: &DecoderColumns<AB::Expr>,
    cols_next: &DecoderColumns<AB::Expr>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let sp = cols.in_span.clone();
    let addr = cols.addr.clone();
    let addr_next = cols_next.addr.clone();

    // Constraint 1: Inside a span, address must stay the same.
    // sp * (addr' - addr) = 0
    builder.tagged(ADDR_BASE_ID, DECODER_NAMES[ADDR_BASE], |builder| {
        builder.when_transition().assert_zero(sp * (addr_next.clone() - addr.clone()));
    });

    // Constraint 2: RESPAN moves to the next hash block (Poseidon2 = 32 rows).
    // respan_flag * (addr' - addr - HASH_CYCLE_LEN) = 0
    let hash_cycle_len: AB::Expr = AB::Expr::from_u16(HASH_CYCLE_LEN as u16);
    let respan_flag = op_flags.respan();
    builder.tagged(ADDR_BASE_ID + 1, DECODER_NAMES[ADDR_BASE + 1], |builder| {
        builder
            .when_transition()
            .assert_zero(respan_flag * (addr_next - addr.clone() - hash_cycle_len));
    });

    // Constraint 3: HALT forces addr = 0.
    // halt_flag * addr = 0
    let halt_flag = op_flags.halt();
    builder.tagged(ADDR_BASE_ID + 2, DECODER_NAMES[ADDR_BASE + 2], |builder| {
        builder.assert_zero(halt_flag * addr);
    });
}

/// Enforces control flow constraints.
///
/// When outside a basic block (sp = 0), only control flow operations can execute.
/// This is expressed as: fctrl = 1 - sp, or equivalently: (1 - sp) * (1 - fctrl) = 0
///
/// Control flow operations include:
/// - SPAN, JOIN, SPLIT, LOOP (block start operations)
/// - END, REPEAT, RESPAN, HALT (block transition operations)
/// - DYN, DYNCALL, CALL, SYSCALL (procedure invocations)
///
/// Constraints:
/// 1. When sp = 0, control_flow must be 1: (1 - sp) * (1 - fctrl) = 0
fn enforce_control_flow_constraints<AB>(
    builder: &mut AB,
    cols: &DecoderColumns<AB::Expr>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let sp = cols.in_span.clone();

    // Constraint: sp and control_flow must be complementary.
    // 1 - sp - fctrl = 0
    let ctrl_flag = op_flags.control_flow();
    builder.tagged(CONTROL_FLOW_BASE_ID, DECODER_NAMES[CONTROL_FLOW_BASE], |builder| {
        builder.assert_zero(AB::Expr::ONE - sp - ctrl_flag);
    });
}

/// Enforces general decoder constraints derived from opcode semantics.
///
/// These are the opcode-specific rules that aren't captured by the generic counters:
/// - SPLIT/LOOP: s0 must be binary (branch selector)
/// - DYN: upper hasher lanes are zero (callee hash lives in lower half)
/// - REPEAT: must be inside loop body and s0 = 1
/// - END + REPEAT': carry hasher state forward
/// - HALT: absorbing
fn enforce_general_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    op_flags_next: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let s0: AB::Expr = local.stack[0].clone().into();

    // SPLIT/LOOP: top stack value must be binary (branch selector).
    let split_or_loop = op_flags.split() + op_flags.loop_op();
    let s0_binary = s0.clone() * (s0.clone() - AB::Expr::ONE);
    builder.tagged(GENERAL_BASE_ID, DECODER_NAMES[GENERAL_BASE], |builder| {
        builder.assert_zero(split_or_loop * s0_binary);
    });

    // DYN: the first half holds the callee digest; the second half must be zero.
    let f_dyn = op_flags.dyn_op();
    for i in 0..4 {
        let hi: AB::Expr = local.decoder[decoder_cols::HASHER_STATE_OFFSET + 4 + i].clone().into();
        let id = GENERAL_BASE_ID + 1 + i;
        let namespace = DECODER_NAMES[GENERAL_BASE + 1 + i];
        builder.tagged(id, namespace, |builder| {
            builder.assert_zero(f_dyn.clone() * hi);
        });
    }

    // REPEAT: top stack must be 1 and we must be in a loop body (h4=1).
    let f_repeat = op_flags.repeat();
    let h4: AB::Expr = local.decoder[decoder_cols::IS_LOOP_BODY_FLAG_COL_IDX].clone().into();
    builder.tagged(GENERAL_BASE_ID + 5, DECODER_NAMES[GENERAL_BASE + 5], |builder| {
        builder.assert_zero(f_repeat.clone() * (AB::Expr::ONE - s0.clone()));
    });
    builder.tagged(GENERAL_BASE_ID + 6, DECODER_NAMES[GENERAL_BASE + 6], |builder| {
        builder.assert_zero(f_repeat * (AB::Expr::ONE - h4));
    });

    // END inside a loop: if is_loop flag is set, top stack must be 0.
    let f_end = op_flags.end();
    let h5: AB::Expr = local.decoder[decoder_cols::IS_LOOP_FLAG_COL_IDX].clone().into();
    builder.tagged(GENERAL_BASE_ID + 7, DECODER_NAMES[GENERAL_BASE + 7], |builder| {
        builder.assert_zero(f_end.clone() * h5 * s0);
    });

    // END followed by REPEAT: carry h0..h4 into the next row.
    let f_repeat_next = op_flags_next.repeat();
    for i in 0..5 {
        let hi: AB::Expr = local.decoder[decoder_cols::HASHER_STATE_OFFSET + i].clone().into();
        let hi_next: AB::Expr = next.decoder[decoder_cols::HASHER_STATE_OFFSET + i].clone().into();
        let id = GENERAL_BASE_ID + 8 + i;
        let namespace = DECODER_NAMES[GENERAL_BASE + 8 + i];
        builder.tagged(id, namespace, |builder| {
            builder
                .when_transition()
                .assert_zero(f_end.clone() * f_repeat_next.clone() * (hi_next - hi));
        });
    }

    // HALT is absorbing: it can only be followed by HALT.
    let f_halt = op_flags.halt();
    let f_halt_next = op_flags_next.halt();
    builder.tagged(GENERAL_BASE_ID + 13, DECODER_NAMES[GENERAL_BASE + 13], |builder| {
        builder.when_transition().assert_zero(f_halt * (AB::Expr::ONE - f_halt_next));
    });
}

/// Enforces op group decoding constraints for the `h0` register.
///
/// `h0` is a packed buffer of pending op groups. When a group is started or continued,
/// the next opcode is shifted into `h0` (base 2^7, because opcodes fit in 7 bits).
/// When the next op is END or RESPAN, the buffer must be empty (h0 = 0).
fn enforce_op_group_decoding_constraints<AB>(
    builder: &mut AB,
    cols: &DecoderColumns<AB::Expr>,
    cols_next: &DecoderColumns<AB::Expr>,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    op_flags_next: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let sp = cols.in_span.clone();
    let sp_next = cols_next.in_span.clone();

    let gc = cols.group_count.clone();
    let gc_next = cols_next.group_count.clone();
    let delta_gc = gc - gc_next;

    let f_span = op_flags.span();
    let f_respan = op_flags.respan();
    let is_push = op_flags.push();

    // f_sgc is set when gc stays the same inside a basic block.
    let f_sgc = sp.clone() * sp_next * (AB::Expr::ONE - delta_gc.clone());

    let h0: AB::Expr = local.decoder[decoder_cols::HASHER_STATE_OFFSET].clone().into();
    let h0_next: AB::Expr = next.decoder[decoder_cols::HASHER_STATE_OFFSET].clone().into();

    // Compute op' from next-row op bits (b0' + 2*b1' + ... + 64*b6').
    let op_next = op_bits_to_value::<AB>(&cols_next.op_bits);

    // When SPAN/RESPAN/PUSH or when gc doesn't change, shift h0 by op'.
    // (h0 - h0' * 2^7 - op') = 0 under the combined flag.
    let op_group_base = AB::Expr::from_u16(1u16 << 7);
    let h0_shift = h0.clone() - h0_next * op_group_base - op_next;
    builder.tagged(OP_GROUP_DECODING_BASE_ID, DECODER_NAMES[OP_GROUP_DECODING_BASE], |builder| {
        builder
            .when_transition()
            .assert_zero((f_span + f_respan + is_push + f_sgc) * h0_shift);
    });

    // If the next op is END or RESPAN, the current h0 must be 0 (no pending group).
    let end_next = op_flags_next.end();
    let respan_next = op_flags_next.respan();
    builder.tagged(
        OP_GROUP_DECODING_BASE_ID + 1,
        DECODER_NAMES[OP_GROUP_DECODING_BASE + 1],
        |builder| {
            builder.when_transition().assert_zero(sp * (end_next + respan_next) * h0);
        },
    );
}

/// Enforces op batch flag constraints and associated hasher-state zeroing rules.
///
/// Batch flags encode how many groups were emitted by SPAN/RESPAN:
/// - g8, g4, g2, g1 correspond to batches of 8, 4, 2, or 1 groups. The hasher lanes h1..h7 store
///   the group values; unused lanes must be zeroed.
fn enforce_batch_flags_constraints<AB>(
    builder: &mut AB,
    cols: &DecoderColumns<AB::Expr>,
    local: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let bc0 = cols.batch_flags[0].clone();
    let bc1 = cols.batch_flags[1].clone();
    let bc2 = cols.batch_flags[2].clone();

    // Batch flag decoding matches trace::decoder batch encodings.
    let f_g8 = bc0.clone();
    let f_g4 = (AB::Expr::ONE - bc0.clone()) * bc1.clone() * (AB::Expr::ONE - bc2.clone());
    let f_g2 = (AB::Expr::ONE - bc0.clone()) * (AB::Expr::ONE - bc1.clone()) * bc2.clone();
    let f_g1 = (AB::Expr::ONE - bc0) * bc1 * bc2;

    let f_span = op_flags.span();
    let f_respan = op_flags.respan();
    let span_or_respan = f_span + f_respan;

    // When SPAN or RESPAN, exactly one batch flag must be set.
    builder.tagged(BATCH_FLAGS_BASE_ID, DECODER_NAMES[BATCH_FLAGS_BASE], |builder| {
        builder.assert_zero(
            span_or_respan.clone() - (f_g1.clone() + f_g2.clone() + f_g4.clone() + f_g8),
        );
    });

    // When not SPAN/RESPAN, all batch flags must be zero.
    builder.tagged(BATCH_FLAGS_BASE_ID + 1, DECODER_NAMES[BATCH_FLAGS_BASE + 1], |builder| {
        builder.assert_zero(
            (AB::Expr::ONE - span_or_respan)
                * (cols.batch_flags[0].clone()
                    + cols.batch_flags[1].clone()
                    + cols.batch_flags[2].clone()),
        );
    });

    // When batch has <=4 groups, h4..h7 must be zero (unused lanes).
    let small_batch = f_g1.clone() + f_g2.clone() + f_g4.clone();
    for i in 0..4 {
        let hi: AB::Expr = local.decoder[decoder_cols::HASHER_STATE_OFFSET + 4 + i].clone().into();
        let id = BATCH_FLAGS_BASE_ID + 2 + i;
        let namespace = DECODER_NAMES[BATCH_FLAGS_BASE + 2 + i];
        builder.tagged(id, namespace, |builder| {
            builder.assert_zero(small_batch.clone() * hi);
        });
    }

    // When batch has <=2 groups, h2..h3 must be zero (unused lanes).
    let tiny_batch = f_g1.clone() + f_g2.clone();
    for i in 0..2 {
        let hi: AB::Expr = local.decoder[decoder_cols::HASHER_STATE_OFFSET + 2 + i].clone().into();
        let id = BATCH_FLAGS_BASE_ID + 6 + i;
        let namespace = DECODER_NAMES[BATCH_FLAGS_BASE + 6 + i];
        builder.tagged(id, namespace, |builder| {
            builder.assert_zero(tiny_batch.clone() * hi);
        });
    }

    // When batch has 1 group, h1 must be zero (unused lane).
    let h1: AB::Expr = local.decoder[decoder_cols::HASHER_STATE_OFFSET + 1].clone().into();
    builder.tagged(BATCH_FLAGS_BASE_ID + 8, DECODER_NAMES[BATCH_FLAGS_BASE + 8], |builder| {
        builder.assert_zero(f_g1 * h1);
    });
}
