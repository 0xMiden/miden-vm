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
use miden_crypto::stark::air::AirBuilder;

use crate::{
    Felt, MainTraceRow, MidenAirBuilder,
    constraints::{
        constants::{F_1, F_128, HASH_CYCLE_LEN_FELT},
        op_flags::OpFlags,
        utils::BoolNot,
    },
    trace::DecoderCols,
};

pub mod bus;

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
    let dec = &local.decoder;
    let dec_next = &next.decoder;

    enforce_in_span_constraints(builder, dec, dec_next, op_flags);

    // Op bits must be binary
    builder.assert_bools(dec.op_bits);

    enforce_extra_columns(builder, dec);
    enforce_op_bit_group_constraints(builder, dec);

    // Batch flags must be binary
    builder.assert_bools(dec.batch_flags);

    enforce_general_constraints(builder, local, next, op_flags);
    enforce_group_count_constraints(builder, dec, dec_next, op_flags);
    enforce_op_group_decoding_constraints(builder, dec, dec_next, op_flags);
    enforce_op_index_constraints(builder, dec, dec_next, op_flags);
    enforce_batch_flags_constraints(builder, dec, op_flags);
    enforce_block_address_constraints(builder, dec, dec_next, op_flags);

    // When outside a basic block (sp=0), only control flow ops can execute: sp + fctrl = 1
    builder.assert_one(dec.in_span.into() + op_flags.control_flow());
}

// CONSTRAINT HELPERS
// ================================================================================================

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
    dec: &DecoderCols<AB::Var>,
    dec_next: &DecoderCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let sp = dec.in_span;
    let sp_next: AB::Expr = dec_next.in_span.into();

    // Boundary: execution starts outside any basic block.
    builder.when_first_row().assert_zero(sp);

    // Constraint 1: sp is binary, so span state is well-formed.
    builder.assert_bool(sp);

    // Constraint 2: span_flag * (1 - sp') = 0
    let span_flag = op_flags.span();
    builder.when_transition().when(span_flag).assert_one(sp_next.clone());

    // Constraint 3: respan_flag * (1 - sp') = 0
    let respan_flag = op_flags.respan();
    builder.when_transition().when(respan_flag).assert_one(sp_next);
}

/// Enforces that the extra columns (e0, e1) are correctly computed from op bits.
///
/// These columns are used for degree reduction in operation flag computation:
/// - e0 = b6 * (1 - b5) * b4
/// - e1 = b6 * b5
fn enforce_extra_columns<AB>(builder: &mut AB, dec: &DecoderCols<AB::Var>)
where
    AB: MidenAirBuilder,
{
    let b4: AB::Expr = dec.op_bits[4].into();
    let b5: AB::Expr = dec.op_bits[5].into();
    let b6: AB::Expr = dec.op_bits[6].into();

    // e0 = b6 * (1 - b5) * b4.
    let expected_e0 = b6.clone() * b5.clone().not() * b4;
    builder.assert_eq(dec.extra[0], expected_e0);

    // e1 = b6 * b5.
    let expected_e1 = b6 * b5;
    builder.assert_eq(dec.extra[1], expected_e1);
}

/// Enforces opcode-bit constraints for grouped opcode families.
///
/// - U32 ops (prefix `100`) must have b0 = 0.
/// - Very-high-degree ops (prefix `11`) must have b0 = b1 = 0.
fn enforce_op_bit_group_constraints<AB>(builder: &mut AB, dec: &DecoderCols<AB::Var>)
where
    AB: MidenAirBuilder,
{
    let b0: AB::Expr = dec.op_bits[0].into();
    let b1: AB::Expr = dec.op_bits[1].into();
    let b4: AB::Expr = dec.op_bits[4].into();
    let b5: AB::Expr = dec.op_bits[5].into();
    let b6: AB::Expr = dec.op_bits[6].into();

    // U32 prefix pattern: b6=1, b5=0, b4=0. Under this prefix, b0 must be 0.
    let u32_prefix = b6.clone() * b5.clone().not() * b4.not();
    builder.when(u32_prefix).assert_zero(b0.clone());

    // Very-high prefix pattern: b6=1, b5=1. Under this prefix, b0 and b1 must be 0.
    let very_high_prefix = b6 * b5;
    // When very-high prefix is active, both b0 and b1 must be zero.
    {
        let builder = &mut builder.when(very_high_prefix);
        builder.assert_zero(b0);
        builder.assert_zero(b1);
    }
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
) where
    AB: MidenAirBuilder,
{
    let dec = &local.decoder;
    let dec_next = &next.decoder;
    let s0 = local.stack[0];

    // SPLIT/LOOP: top stack value must be binary (branch selector).
    let split_or_loop = op_flags.split() + op_flags.loop_op();
    builder.when(split_or_loop).assert_bool(s0);

    // DYN: the first half holds the callee digest; the second half must be zero.
    // When DYN is active, h4..h7 must be zeroed.
    {
        let builder = &mut builder.when(op_flags.dyn_op());
        for i in 0..4 {
            builder.assert_zero(dec.hasher_state[4 + i]);
        }
    }

    // REPEAT: top stack must be 1 and we must be in a loop body (h4=1).
    let end_flags = dec.end_block_flags();
    // When REPEAT is active, s0 and loop-body flag must both be 1.
    {
        let builder = &mut builder.when(op_flags.repeat());
        builder.assert_one(s0);
        builder.assert_one(end_flags.is_loop_body);
    }

    // END inside a loop: if is_loop flag is set, top stack must be 0.
    let f_end = op_flags.end();
    builder.when(f_end.clone()).when(end_flags.is_loop).assert_zero(s0);

    // END followed by REPEAT: carry h0..h4 into the next row.
    {
        let gate = builder.is_transition() * f_end.clone() * op_flags.repeat_next();
        let builder = &mut builder.when(gate);
        for i in 0..5 {
            builder.assert_eq(dec_next.hasher_state[i], dec.hasher_state[i]);
        }
    }

    // HALT is absorbing: it can only be followed by HALT.
    let f_halt = op_flags.halt();
    let f_halt_next = op_flags.halt_next();
    builder.when_transition().when(f_halt).assert_one(f_halt_next);
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
    dec: &DecoderCols<AB::Var>,
    dec_next: &DecoderCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let sp: AB::Expr = dec.in_span.into();
    let gc: AB::Expr = dec.group_count.into();
    let gc_next: AB::Expr = dec_next.group_count.into();
    let h0 = dec.hasher_state[0];

    // delta_gc = gc - gc' (how much gc decrements; expected to be 0 or 1)
    let delta_gc = gc.clone() - gc_next;

    // is_push = push flag (PUSH is the only operation with immediate value)
    let is_push = op_flags.push();

    // Constraint 1: Inside a span, gc can only stay the same or decrement by 1.
    // sp * delta_gc * (delta_gc - 1) = 0
    // This ensures: if sp=1 and delta_gc != 0, then delta_gc must equal 1
    // Constraint 2: If gc decrements and this is not a PUSH-immediate row,
    // then h0 must be zero (no immediate value packed into the group).
    // sp * delta_gc * (1 - is_push) * h0 = 0
    // When inside a span (transition), gc delta is boolean and non-push decrements clear h0.
    {
        let gate = builder.is_transition() * sp.clone();
        let builder = &mut builder.when(gate);
        builder.assert_bool(delta_gc.clone());
        builder.when(delta_gc.clone()).when(is_push.not()).assert_zero(h0);
    }

    // Constraint 3: SPAN/RESPAN/PUSH must consume a group immediately.
    // (span_flag + respan_flag + is_push) * (delta_gc - 1) = 0
    let span_flag = op_flags.span();
    let respan_flag = op_flags.respan();
    builder
        .when_transition()
        .when(span_flag + respan_flag + is_push)
        .assert_one(delta_gc.clone());

    // Constraint 4: If the next op is END or RESPAN, gc cannot decrement on this row.
    // delta_gc * (end' + respan') = 0
    let end_next = op_flags.end_next();
    let respan_next = op_flags.respan_next();
    builder.when_transition().when(delta_gc).assert_zero(end_next + respan_next);

    // Constraint 5: END closes the span, so gc must be 0.
    // end_flag * gc = 0
    let end_flag = op_flags.end();
    builder.when(end_flag).assert_zero(gc);
}

/// Enforces op group decoding constraints for the `h0` register.
///
/// `h0` is a packed buffer of pending op groups. When a group is started or continued,
/// the next opcode is shifted into `h0` (base 2^7, because opcodes fit in 7 bits).
/// When the next op is END or RESPAN, the buffer must be empty (h0 = 0).
fn enforce_op_group_decoding_constraints<AB>(
    builder: &mut AB,
    dec: &DecoderCols<AB::Var>,
    dec_next: &DecoderCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let sp: AB::Expr = dec.in_span.into();
    let sp_next: AB::Expr = dec_next.in_span.into();

    let gc: AB::Expr = dec.group_count.into();
    let gc_next: AB::Expr = dec_next.group_count.into();
    let delta_gc = gc - gc_next;

    let f_span = op_flags.span();
    let f_respan = op_flags.respan();
    let is_push = op_flags.push();

    // f_sgc is set when gc stays the same inside a basic block.
    let f_sgc = sp.clone() * sp_next * delta_gc.clone().not();

    let h0 = dec.hasher_state[0];
    let h0_next = dec_next.hasher_state[0];

    // Compute op' from next-row op bits (b0' + 2*b1' + ... + 64*b6').
    let op_next = dec_next
        .op_bits
        .iter()
        .enumerate()
        .fold(AB::Expr::ZERO, |acc, (i, &bit)| acc + bit * AB::F::from_u16(1u16 << i));

    // When SPAN/RESPAN/PUSH or when gc doesn't change, shift h0 by op'.
    // (h0 - h0' * 2^7 - op') = 0 under the combined flag.
    let h0_shift = h0 - h0_next * F_128 - op_next;
    builder
        .when_transition()
        .when(f_span + f_respan + is_push + f_sgc)
        .assert_zero(h0_shift);

    // If the next op is END or RESPAN, the current h0 must be 0 (no pending group).
    let end_next = op_flags.end_next();
    let respan_next = op_flags.respan_next();
    builder.when_transition().when(sp).when(end_next + respan_next).assert_zero(h0);
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
    dec: &DecoderCols<AB::Var>,
    dec_next: &DecoderCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let sp: AB::Expr = dec.in_span.into();
    let sp_next: AB::Expr = dec_next.in_span.into();
    let gc: AB::Expr = dec.group_count.into();
    let gc_next: AB::Expr = dec_next.group_count.into();
    let ox: AB::Expr = dec.op_index.into();
    let ox_next: AB::Expr = dec_next.op_index.into();

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
    builder
        .when_transition()
        .when(span_flag + respan_flag)
        .assert_zero(ox_next.clone());

    // Constraint 2: When a new group starts inside a span, ox' = 0.
    // sp * ng * ox' = 0
    builder
        .when_transition()
        .when(sp.clone())
        .when(ng.clone())
        .assert_zero(ox_next.clone());

    // Constraint 3: When staying in the same group, ox increments by 1.
    // sp * sp' * (1 - ng) * (ox' - ox - 1) = 0
    builder
        .when_transition()
        .when(sp)
        .when(sp_next)
        .when(ng.not())
        .assert_eq(ox_next, ox.clone() + F_1);

    // Constraint 4: ox must be in range [0, 8] (9 ops per group).
    // ∏_{i=0}^{8}(ox - i) = 0
    let mut range_check = ox.clone();
    for i in 1..=8u64 {
        range_check *= ox.clone() - Felt::new(i);
    }
    builder.assert_zero(range_check);
}

/// Enforces op batch flag constraints and associated hasher-state zeroing rules.
///
/// Batch flags encode how many groups were emitted by SPAN/RESPAN:
/// - g8, g4, g2, g1 correspond to batches of 8, 4, 2, or 1 groups. The hasher lanes h1..h7 store
///   the group values; unused lanes must be zeroed.
fn enforce_batch_flags_constraints<AB>(
    builder: &mut AB,
    dec: &DecoderCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let bc0: AB::Expr = dec.batch_flags[0].into();
    let bc1: AB::Expr = dec.batch_flags[1].into();
    let bc2: AB::Expr = dec.batch_flags[2].into();

    // Batch flag decoding matches trace::decoder batch encodings.
    let f_g8 = bc0.clone();
    let not_bc0 = bc0.not();
    let f_g4 = not_bc0.clone() * bc1.clone() * bc2.clone().not();
    let f_g2 = not_bc0.clone() * bc1.clone().not() * bc2.clone();
    let f_g1 = not_bc0 * bc1 * bc2;

    let f_span = op_flags.span();
    let f_respan = op_flags.respan();
    let span_or_respan = f_span + f_respan;

    // When SPAN or RESPAN, exactly one batch flag must be set.
    builder.assert_eq(span_or_respan.clone(), f_g1.clone() + f_g2.clone() + f_g4.clone() + f_g8);

    // When not SPAN/RESPAN, all batch flags must be zero.
    builder.when(span_or_respan.not()).assert_zero(
        dec.batch_flags[0].into() + dec.batch_flags[1].into() + dec.batch_flags[2].into(),
    );

    // When batch has <=4 groups, h4..h7 must be zero (unused lanes).
    // Zero the upper hasher lanes for batches with at most 4 groups.
    {
        let builder = &mut builder.when(f_g1.clone() + f_g2.clone() + f_g4.clone());
        for i in 0..4 {
            builder.assert_zero(dec.hasher_state[4 + i]);
        }
    }

    // When batch has <=2 groups, h2..h3 must be zero (unused lanes).
    // Zero h2..h3 for batches with at most 2 groups.
    {
        let builder = &mut builder.when(f_g1.clone() + f_g2.clone());
        for i in 0..2 {
            builder.assert_zero(dec.hasher_state[2 + i]);
        }
    }

    // When batch has 1 group, h1 must be zero (unused lane).
    builder.when(f_g1).assert_zero(dec.hasher_state[1]);
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
    dec: &DecoderCols<AB::Var>,
    dec_next: &DecoderCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let sp: AB::Expr = dec.in_span.into();
    let addr: AB::Expr = dec.addr.into();
    let addr_next: AB::Expr = dec_next.addr.into();

    // Constraint 1: Inside a span, address must stay the same.
    // sp * (addr' - addr) = 0
    builder.when_transition().when(sp).assert_eq(addr_next.clone(), addr.clone());

    // Constraint 2: RESPAN moves to the next hash block (Poseidon2 = 32 rows).
    // respan_flag * (addr' - addr - HASH_CYCLE_LEN) = 0
    let respan_flag = op_flags.respan();
    builder
        .when_transition()
        .when(respan_flag)
        .assert_eq(addr_next, addr.clone() + HASH_CYCLE_LEN_FELT);

    // Constraint 3: HALT forces addr = 0.
    // halt_flag * addr = 0
    let halt_flag = op_flags.halt();
    builder.when(halt_flag).assert_zero(addr);
}
