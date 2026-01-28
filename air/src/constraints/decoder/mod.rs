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
    constraints::stack::op_flags::{ExprDecoderAccess, OpFlags},
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

/// Number of decoder constraints.
/// - 7 op bits binary constraints
/// - 2 extra columns constraints (e0, e1)
/// - 3 op-bit group constraints (u32 b0, very-high b0/b1)
/// - 3 batch flags binary constraints
/// - 14 general constraints
/// - 1 in-span binary constraint
/// - 2 in-span transition constraints (after SPAN/RESPAN, sp' = 1)
/// - 5 group count constraints
/// - 2 op group decoding constraints
/// - 4 op index constraints
/// - 9 op batch flag constraints
/// - 3 block address constraints
/// - 1 control flow constraint (1 - sp - f_ctrl = 0)
#[allow(dead_code)]
pub const NUM_CONSTRAINTS: usize = 56;

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
    2, // sp binary (degree 2)
    6, 5, // sp transition for SPAN (deg 5+1=6), RESPAN (deg 4+1=5)
    3, // gc delta bounded (degree 3: sp * delta * (delta - 1))
    8, // gc decrement implies (h0=0 or f_imm=1)
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

    enforce_op_bits_binary(builder, &cols);
    enforce_extra_columns(builder, &cols);
    enforce_op_bit_group_constraints(builder, &cols);
    enforce_batch_flags_binary(builder, &cols);
    enforce_general_constraints(builder, local, next, op_flags, &op_flags_next);
    enforce_in_span_constraints(builder, &cols, &cols_next, op_flags);
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
    builder.assert_zeros(core::array::from_fn::<_, NUM_OP_BITS, _>(|i| {
        let bit = cols.op_bits[i].clone();
        bit.clone() * (bit - AB::Expr::ONE)
    }));
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

    // e0 = b6 * (1 - b5) * b4
    let expected_e0 = b6.clone() * (AB::Expr::ONE - b5.clone()) * b4;
    builder.assert_zero(e0 - expected_e0);

    // e1 = b6 * b5
    let expected_e1 = b6 * b5;
    builder.assert_zero(e1 - expected_e1);
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

    // U32 prefix: b6=1, b5=0, b4=0.
    let u32_prefix = b6.clone() * (AB::Expr::ONE - b5.clone()) * (AB::Expr::ONE - b4);
    builder.assert_zero(u32_prefix * b0.clone());

    // Very-high-degree prefix: b6=1, b5=1.
    let very_high_prefix = b6 * b5;
    builder.assert_zero(very_high_prefix.clone() * b0);
    builder.assert_zero(very_high_prefix * b1);
}

/// Enforces that batch flags (c0, c1, c2) are binary.
///
/// For each flag ci: ci * (ci - 1) = 0
fn enforce_batch_flags_binary<AB>(builder: &mut AB, cols: &DecoderColumns<AB::Expr>)
where
    AB: MidenAirBuilder,
{
    builder.assert_zeros(core::array::from_fn::<_, NUM_BATCH_FLAGS, _>(|i| {
        let flag = cols.batch_flags[i].clone();
        flag.clone() * (flag - AB::Expr::ONE)
    }));
}

/// Enforces in-span (sp) constraints.
///
/// The in-span flag indicates whether we're inside a basic block:
/// - sp = 1 when executing operations inside a basic block
/// - sp = 0 for SPAN, RESPAN, END, and control flow operations
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
    builder.when_first_row().assert_zero(sp.clone());

    // Constraint 1: sp is binary
    let sp_binary = sp.clone() * (sp - AB::Expr::ONE);
    builder.assert_zero(sp_binary);

    // Constraint 2: After SPAN, sp' = 1
    // span_flag * (1 - sp') = 0
    let span_flag = op_flags.span();
    builder
        .when_transition()
        .assert_zero(span_flag * (AB::Expr::ONE - sp_next.clone()));

    // Constraint 3: After RESPAN, sp' = 1
    // respan_flag * (1 - sp') = 0
    let respan_flag = op_flags.respan();
    builder.when_transition().assert_zero(respan_flag * (AB::Expr::ONE - sp_next));
}

/// Enforces group count (gc) constraints.
///
/// The group count tracks remaining operation groups in the current basic block:
/// - gc starts at the total number of groups when SPAN/RESPAN is executed
/// - gc decrements by 1 when processing SPAN, RESPAN, or completing a group
/// - gc must be 0 when END is executed
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

    // f_imm = push flag (PUSH is the only operation with immediate value)
    let f_imm = op_flags.push();

    // Constraint 1: Inside basic block, gc can only stay same or decrement by 1
    // sp * delta_gc * (delta_gc - 1) = 0
    // This ensures: if sp=1 and delta_gc != 0, then delta_gc must equal 1
    builder
        .when_transition()
        .assert_zero(sp.clone() * delta_gc.clone() * (delta_gc.clone() - AB::Expr::ONE));

    // Constraint 2: If gc decremented inside a span, then either h0=0 or op has immediate.
    // sp * delta_gc * (1 - f_imm) * h0 = 0
    builder
        .when_transition()
        .assert_zero(sp.clone() * delta_gc.clone() * (AB::Expr::ONE - f_imm.clone()) * h0);

    // Constraint 3: During SPAN/RESPAN/PUSH, gc must decrement by 1
    // (span_flag + respan_flag + f_imm) * (delta_gc - 1) = 0
    let span_flag = op_flags.span();
    let respan_flag = op_flags.respan();
    builder
        .when_transition()
        .assert_zero((span_flag + respan_flag + f_imm) * (delta_gc.clone() - AB::Expr::ONE));

    // Constraint 4: If next op is END or RESPAN, gc must stay the same.
    // delta_gc * (end' + respan') = 0
    let end_next = op_flags_next.end();
    let respan_next = op_flags_next.respan();
    builder
        .when_transition()
        .assert_zero(delta_gc.clone() * (end_next + respan_next));

    // Constraint 5: When END is executed, gc must be 0
    // end_flag * gc = 0
    let end_flag = op_flags.end();
    builder.assert_zero(end_flag * gc);
}

/// Enforces op index (ox) constraints.
///
/// The op index tracks the position of the current operation within its operation group:
/// - ox ranges from 0 to 8 (9 operations per group)
/// - ox resets to 0 when entering a new group (SPAN, RESPAN, or group boundary)
/// - ox increments by 1 for each operation within a group
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

    // f_imm = push flag (PUSH is the only operation with immediate value)
    let f_imm = op_flags.push();

    // ng = delta_gc - f_imm
    // This equals 1 when we're starting a new operation group (not due to immediate op)
    let ng = delta_gc - f_imm;

    let span_flag = op_flags.span();
    let respan_flag = op_flags.respan();

    // Constraint 1: After SPAN/RESPAN, ox' = 0
    // (span_flag + respan_flag) * ox' = 0
    builder
        .when_transition()
        .assert_zero((span_flag + respan_flag) * ox_next.clone());

    // Constraint 2: When starting a new operation group inside a basic block, ox' = 0
    // sp * ng * ox' = 0
    builder.when_transition().assert_zero(sp.clone() * ng.clone() * ox_next.clone());

    // Constraint 3: When inside basic block but not starting new group, ox increments by 1
    // sp * sp' * (1 - ng) * (ox' - ox - 1) = 0
    let delta_ox = ox_next - ox.clone() - AB::Expr::ONE;
    builder
        .when_transition()
        .assert_zero(sp * sp_next * (AB::Expr::ONE - ng) * delta_ox);

    // Constraint 4: ox must be in range [0, 8]
    // ∏_{i=0}^{8}(ox - i) = 0
    let mut range_check = ox.clone();
    for i in 1..=8u64 {
        range_check *= ox.clone() - AB::Expr::from_u16(i as u16);
    }
    builder.assert_zero(range_check);
}

/// Enforces block address (addr) constraints.
///
/// The block address identifies the current code block in the hasher table:
/// - addr stays constant inside a basic block (sp = 1)
/// - addr increments by HASH_CYCLE_LEN (32) after RESPAN
/// - addr must be 0 when HALT is executed
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

    // Constraint 1: Inside basic block, address must stay the same
    // sp * (addr' - addr) = 0
    builder.when_transition().assert_zero(sp * (addr_next.clone() - addr.clone()));

    // Constraint 2: RESPAN increments address by HASH_CYCLE_LEN (Poseidon2 = 32)
    // respan_flag * (addr' - addr - HASH_CYCLE_LEN) = 0
    let hash_cycle_len: AB::Expr = AB::Expr::from_u16(HASH_CYCLE_LEN as u16);
    let respan_flag = op_flags.respan();
    builder
        .when_transition()
        .assert_zero(respan_flag * (addr_next - addr.clone() - hash_cycle_len));

    // Constraint 3: HALT has addr = 0
    // halt_flag * addr = 0
    let halt_flag = op_flags.halt();
    builder.assert_zero(halt_flag * addr);
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
    builder.assert_zero(AB::Expr::ONE - sp - ctrl_flag);
}

/// Enforces general decoder constraints derived from opcode semantics.
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

    // SPLIT/LOOP: top stack value must be binary.
    let split_or_loop = op_flags.split() + op_flags.loop_op();
    let s0_binary = s0.clone() * (s0.clone() - AB::Expr::ONE);
    builder.assert_zero(split_or_loop * s0_binary);

    // DYN: the first half holds the callee digest; the second half must be zero.
    let f_dyn = op_flags.dyn_op();
    builder.assert_zeros(core::array::from_fn::<_, 4, _>(|i| {
        let hi: AB::Expr = local.decoder[decoder_cols::HASHER_STATE_OFFSET + 4 + i].clone().into();
        f_dyn.clone() * hi
    }));

    // REPEAT: top stack must be 1 and we must be in a loop body (h4=1).
    let f_repeat = op_flags.repeat();
    let h4: AB::Expr = local.decoder[decoder_cols::IS_LOOP_BODY_FLAG_COL_IDX].clone().into();
    builder.assert_zero(f_repeat.clone() * (AB::Expr::ONE - s0.clone()));
    builder.assert_zero(f_repeat * (AB::Expr::ONE - h4));

    // END inside a loop: if is_loop flag is set, top stack must be 0.
    let f_end = op_flags.end();
    let h5: AB::Expr = local.decoder[decoder_cols::IS_LOOP_FLAG_COL_IDX].clone().into();
    builder.assert_zero(f_end.clone() * h5 * s0);

    // END followed by REPEAT: carry h0..h4 into the next row.
    let f_repeat_next = op_flags_next.repeat();
    builder.when_transition().assert_zeros(core::array::from_fn::<_, 5, _>(|i| {
        let hi: AB::Expr = local.decoder[decoder_cols::HASHER_STATE_OFFSET + i].clone().into();
        let hi_next: AB::Expr = next.decoder[decoder_cols::HASHER_STATE_OFFSET + i].clone().into();
        f_end.clone() * f_repeat_next.clone() * (hi_next - hi)
    }));

    // HALT can only be followed by HALT.
    let f_halt = op_flags.halt();
    let f_halt_next = op_flags_next.halt();
    builder.when_transition().assert_zero(f_halt * (AB::Expr::ONE - f_halt_next));
}

/// Enforces op group decoding constraints for the `h0` register.
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
    let f_imm = op_flags.push();

    // f_sgc is set when gc stays the same inside a basic block.
    let f_sgc = sp.clone() * sp_next * (AB::Expr::ONE - delta_gc.clone());

    let h0: AB::Expr = local.decoder[decoder_cols::HASHER_STATE_OFFSET].clone().into();
    let h0_next: AB::Expr = next.decoder[decoder_cols::HASHER_STATE_OFFSET].clone().into();

    // Compute op' from next-row op bits (b0' + 2*b1' + ... + 64*b6').
    let op_next = cols_next.op_bits.iter().enumerate().fold(AB::Expr::ZERO, |acc, (i, bit)| {
        acc + bit.clone() * AB::Expr::from_u16(1u16 << i)
    });

    // When SPAN/RESPAN/PUSH or when gc doesn't change, shift h0 by op'.
    // (h0 - h0' * 2^7 - op') = 0 under the combined flag.
    let op_group_base = AB::Expr::from_u16(1u16 << 7);
    let h0_shift = h0.clone() - h0_next * op_group_base - op_next;
    builder
        .when_transition()
        .assert_zero((f_span + f_respan + f_imm + f_sgc) * h0_shift);

    // If the next op is END or RESPAN, the current h0 must be 0.
    let end_next = op_flags_next.end();
    let respan_next = op_flags_next.respan();
    builder.when_transition().assert_zero(sp * (end_next + respan_next) * h0);
}

/// Enforces op batch flag constraints and associated hasher-state zeroing rules.
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
    builder
        .assert_zero(span_or_respan.clone() - (f_g1.clone() + f_g2.clone() + f_g4.clone() + f_g8));

    // When not SPAN/RESPAN, all batch flags must be zero.
    builder.assert_zero(
        (AB::Expr::ONE - span_or_respan)
            * (cols.batch_flags[0].clone()
                + cols.batch_flags[1].clone()
                + cols.batch_flags[2].clone()),
    );

    // When batch has <=4 groups, h4..h7 must be zero.
    let small_batch = f_g1.clone() + f_g2.clone() + f_g4.clone();
    builder.assert_zeros(core::array::from_fn::<_, 4, _>(|i| {
        let hi: AB::Expr = local.decoder[decoder_cols::HASHER_STATE_OFFSET + 4 + i].clone().into();
        small_batch.clone() * hi
    }));

    // When batch has <=2 groups, h2..h3 must be zero.
    let tiny_batch = f_g1.clone() + f_g2.clone();
    builder.assert_zeros(core::array::from_fn::<_, 2, _>(|i| {
        let hi: AB::Expr = local.decoder[decoder_cols::HASHER_STATE_OFFSET + 2 + i].clone().into();
        tiny_batch.clone() * hi
    }));

    // When batch has 1 group, h1 must be zero.
    let h1: AB::Expr = local.decoder[decoder_cols::HASHER_STATE_OFFSET + 1].clone().into();
    builder.assert_zero(f_g1 * h1);
}
