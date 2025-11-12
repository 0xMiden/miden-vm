//! Tests documenting the values of trace layout constants.
//!
//! This module uses `insta` snapshot testing to document the actual computed values of constants
//! that are defined programmatically. This makes it easy to understand the trace structure without
//! needing to manually compute values or rely on IDE evaluation.
//!
//! The documentation can reference this test when explaining the VM's trace structure.

use std::vec::Vec;

use crate::trace::{
    chiplets::{
        ace, bitwise, hasher, kernel_rom, memory,
        BITWISE_A_COL_IDX, BITWISE_A_COL_RANGE, BITWISE_B_COL_IDX, BITWISE_B_COL_RANGE,
        BITWISE_OUTPUT_COL_IDX, BITWISE_PREV_OUTPUT_COL_IDX, BITWISE_SELECTOR_COL_IDX,
        BITWISE_TRACE_OFFSET, BITWISE_TRACE_RANGE, HASHER_CAPACITY_COL_RANGE,
        HASHER_NODE_INDEX_COL_IDX, HASHER_RATE_COL_RANGE, HASHER_SELECTOR_COL_RANGE,
        HASHER_STATE_COL_RANGE, HASHER_TRACE_OFFSET, MEMORY_CLK_COL_IDX, MEMORY_CTX_COL_IDX,
        MEMORY_D0_COL_IDX, MEMORY_D1_COL_IDX, MEMORY_D_INV_COL_IDX,
        MEMORY_FLAG_SAME_CONTEXT_AND_WORD, MEMORY_IDX0_COL_IDX, MEMORY_IDX1_COL_IDX,
        MEMORY_IS_READ_COL_IDX, MEMORY_IS_WORD_ACCESS_COL_IDX, MEMORY_TRACE_OFFSET,
        MEMORY_V_COL_RANGE, MEMORY_WORD_COL_IDX, NUM_ACE_SELECTORS, NUM_BITWISE_SELECTORS,
        NUM_HASHER_SELECTORS, NUM_KERNEL_ROM_SELECTORS, NUM_MEMORY_SELECTORS,
    },
    decoder::{
        GROUP_COUNT_COL_IDX, HASHER_STATE_OFFSET, HASHER_STATE_RANGE, IN_SPAN_COL_IDX,
        IS_CALL_FLAG_COL_IDX, IS_LOOP_BODY_FLAG_COL_IDX, IS_LOOP_FLAG_COL_IDX,
        IS_SYSCALL_FLAG_COL_IDX, NUM_HASHER_COLUMNS, NUM_OP_BATCH_FLAGS, NUM_OP_BITS,
        NUM_OP_BITS_EXTRA_COLS, NUM_USER_OP_HELPERS, OP_BATCH_FLAGS_OFFSET, OP_BATCH_FLAGS_RANGE,
        OP_BITS_EXTRA_COLS_OFFSET, OP_BITS_EXTRA_COLS_RANGE, OP_BITS_OFFSET, OP_BITS_RANGE,
        OP_INDEX_COL_IDX, USER_OP_HELPERS_OFFSET,
    },
    stack::{B0_COL_IDX, B1_COL_IDX, H0_COL_IDX, NUM_STACK_HELPER_COLS, STACK_TOP_OFFSET},
    ACE_CHIPLET_WIRING_BUS_OFFSET, ACE_CHIPLET_WIRING_BUS_RANGE, ACE_CHIPLET_WIRING_BUS_WIDTH,
    AUX_TRACE_RAND_ELEMENTS, AUX_TRACE_WIDTH, CHIPLETS_BUS_AUX_TRACE_OFFSET,
    CHIPLETS_BUS_AUX_TRACE_RANGE, CHIPLETS_BUS_AUX_TRACE_WIDTH, CHIPLETS_OFFSET,
    CHIPLETS_RANGE, CHIPLETS_WIDTH, CLK_COL_IDX, CTX_COL_IDX, DECODER_AUX_TRACE_OFFSET,
    DECODER_AUX_TRACE_RANGE, DECODER_AUX_TRACE_WIDTH, DECODER_TRACE_OFFSET,
    DECODER_TRACE_RANGE, DECODER_TRACE_WIDTH, FN_HASH_OFFSET, FN_HASH_RANGE,
    HASHER_AUX_TRACE_RANGE, HASHER_AUX_TRACE_WIDTH, HASH_KERNEL_VTABLE_AUX_TRACE_OFFSET,
    MIN_TRACE_LEN, PADDED_TRACE_WIDTH, RANGE_CHECK_AUX_TRACE_OFFSET,
    RANGE_CHECK_AUX_TRACE_RANGE, RANGE_CHECK_AUX_TRACE_WIDTH, RANGE_CHECK_TRACE_OFFSET,
    RANGE_CHECK_TRACE_RANGE, RANGE_CHECK_TRACE_WIDTH, STACK_AUX_TRACE_OFFSET,
    STACK_AUX_TRACE_RANGE, STACK_AUX_TRACE_WIDTH, STACK_TRACE_OFFSET, STACK_TRACE_RANGE,
    STACK_TRACE_WIDTH, SYS_TRACE_OFFSET, SYS_TRACE_RANGE, SYS_TRACE_WIDTH, TRACE_WIDTH,
};

/// Documents all trace widths and offsets for the main execution trace.
///
/// This test captures the computed values of all trace segment widths and their offsets,
/// making it easy to understand the overall trace layout.
#[test]
fn document_main_trace_layout() {
    let layout = format!(
        r#"MAIN TRACE LAYOUT
===================

Minimum trace length: {MIN_TRACE_LEN}

System Trace:
  Offset: {SYS_TRACE_OFFSET}
  Width: {SYS_TRACE_WIDTH}
  Range: {SYS_TRACE_RANGE:?}
  - Clock column index: {CLK_COL_IDX}
  - Context column index: {CTX_COL_IDX}
  - Function hash offset: {FN_HASH_OFFSET}
  - Function hash range: {FN_HASH_RANGE:?}

Decoder Trace:
  Offset: {DECODER_TRACE_OFFSET}
  Width: {DECODER_TRACE_WIDTH}
  Range: {DECODER_TRACE_RANGE:?}

Stack Trace:
  Offset: {STACK_TRACE_OFFSET}
  Width: {STACK_TRACE_WIDTH}
  Range: {STACK_TRACE_RANGE:?}

Range Check Trace:
  Offset: {RANGE_CHECK_TRACE_OFFSET}
  Width: {RANGE_CHECK_TRACE_WIDTH}
  Range: {RANGE_CHECK_TRACE_RANGE:?}

Chiplets Trace:
  Offset: {CHIPLETS_OFFSET}
  Width: {CHIPLETS_WIDTH}
  Range: {CHIPLETS_RANGE:?}

Total Trace Width: {TRACE_WIDTH}
Padded Trace Width: {PADDED_TRACE_WIDTH}
"#
    );

    insta::assert_snapshot!("main_trace_layout", layout);
}

/// Documents all auxiliary trace widths and offsets.
///
/// This test captures the computed values of all auxiliary trace segment widths and their offsets.
#[test]
fn document_aux_trace_layout() {
    let layout = format!(
        r#"AUXILIARY TRACE LAYOUT
==========================

Decoder Auxiliary Trace:
  Offset: {DECODER_AUX_TRACE_OFFSET}
  Width: {DECODER_AUX_TRACE_WIDTH}
  Range: {DECODER_AUX_TRACE_RANGE:?}

Stack Auxiliary Trace:
  Offset: {STACK_AUX_TRACE_OFFSET}
  Width: {STACK_AUX_TRACE_WIDTH}
  Range: {STACK_AUX_TRACE_RANGE:?}

Range Check Auxiliary Trace:
  Offset: {RANGE_CHECK_AUX_TRACE_OFFSET}
  Width: {RANGE_CHECK_AUX_TRACE_WIDTH}
  Range: {RANGE_CHECK_AUX_TRACE_RANGE:?}

Hasher/Kernel ROM Virtual Table Auxiliary Trace:
  Offset: {HASH_KERNEL_VTABLE_AUX_TRACE_OFFSET}
  Width: {HASHER_AUX_TRACE_WIDTH}
  Range: {HASHER_AUX_TRACE_RANGE:?}

Chiplets Bus Auxiliary Trace:
  Offset: {CHIPLETS_BUS_AUX_TRACE_OFFSET}
  Width: {CHIPLETS_BUS_AUX_TRACE_WIDTH}
  Range: {CHIPLETS_BUS_AUX_TRACE_RANGE:?}

ACE Chiplet Wiring Bus:
  Offset: {ACE_CHIPLET_WIRING_BUS_OFFSET}
  Width: {ACE_CHIPLET_WIRING_BUS_WIDTH}
  Range: {ACE_CHIPLET_WIRING_BUS_RANGE:?}

Total Auxiliary Trace Width: {AUX_TRACE_WIDTH}
Auxiliary Trace Random Elements: {AUX_TRACE_RAND_ELEMENTS}
"#
    );

    insta::assert_snapshot!("aux_trace_layout", layout);
}

/// Documents decoder trace column ranges and offsets.
///
/// This test captures the computed values of decoder-specific column indices and ranges.
#[test]
fn document_decoder_trace_layout() {
    let layout = format!(
        r#"DECODER TRACE LAYOUT
======================

Hasher State:
  Offset: {HASHER_STATE_OFFSET}
  Number of columns: {NUM_HASHER_COLUMNS}
  Range: {HASHER_STATE_RANGE:?}

Operation Bits:
  Offset: {OP_BITS_OFFSET}
  Number of bits: {NUM_OP_BITS}
  Range: {OP_BITS_RANGE:?}

Operation Bits Extra Columns (for degree reduction):
  Offset: {OP_BITS_EXTRA_COLS_OFFSET}
  Number of columns: {NUM_OP_BITS_EXTRA_COLS}
  Range: {OP_BITS_EXTRA_COLS_RANGE:?}

User Operation Helpers:
  Offset: {USER_OP_HELPERS_OFFSET}
  Number of helpers: {NUM_USER_OP_HELPERS}

Operation Batch Flags:
  Offset: {OP_BATCH_FLAGS_OFFSET}
  Number of flags: {NUM_OP_BATCH_FLAGS}
  Range: {OP_BATCH_FLAGS_RANGE:?}

Column Indices (ordered by index):
  - {IS_LOOP_BODY_FLAG_COL_IDX}: Is loop body flag
  - {IS_LOOP_FLAG_COL_IDX}: Is loop flag
  - {IS_CALL_FLAG_COL_IDX}: Is call flag
  - {IS_SYSCALL_FLAG_COL_IDX}: Is syscall flag
  - {IN_SPAN_COL_IDX}: In span column
  - {GROUP_COUNT_COL_IDX}: Group count column
  - {OP_INDEX_COL_IDX}: Operation index column
"#
    );

    insta::assert_snapshot!("decoder_trace_layout", layout);
}

/// Documents stack trace column ranges and offsets.
///
/// This test captures the computed values of stack-specific column indices.
#[test]
fn document_stack_trace_layout() {
    let layout = format!(
        r#"STACK TRACE LAYOUT
====================

Stack Top:
  Offset: {STACK_TOP_OFFSET}

Helper Columns:
  Number of helper columns: {NUM_STACK_HELPER_COLS}
  - b0 column (stack depth): {B0_COL_IDX}
  - b1 column (overflow table address): {B1_COL_IDX}
  - h0 column (1 / (b0 - 16)): {H0_COL_IDX}
"#
    );

    insta::assert_snapshot!("stack_trace_layout", layout);
}

/// Documents hasher chiplet column ranges, especially the capacity portion of RPO.
///
/// This test captures the computed values of hasher chiplet column indices and ranges,
/// with special focus on the capacity portion of the Rescue Prime Optimized (RPO) state
/// inside the hasher chiplet, as this is specifically mentioned in the issue.
#[test]
fn document_hasher_chiplet_layout() {
    let layout = format!(
        r#"HASHER CHIPLET LAYOUT
==========================

Chiplet Selectors:
  Number of hasher selectors: {NUM_HASHER_SELECTORS}
  Trace offset: {HASHER_TRACE_OFFSET}
  Selector column range: {HASHER_SELECTOR_COL_RANGE:?}

Hasher State:
  State width: {}
  State column range: {HASHER_STATE_COL_RANGE:?}

Capacity Portion (RPO):
  Capacity length: {}
  Capacity column range: {HASHER_CAPACITY_COL_RANGE:?}
  Capacity domain index: {}

Rate Portion (RPO):
  Rate length: {}
  Rate column range: {HASHER_RATE_COL_RANGE:?}

Other Constants:
  Digest length: {}
  Number of rounds: {}
  Hash cycle length: {}
  Number of selectors: {}
  Hasher trace width: {}
  Node index column: {HASHER_NODE_INDEX_COL_IDX}
"#,
        hasher::STATE_WIDTH,
        hasher::CAPACITY_LEN,
        hasher::CAPACITY_DOMAIN_IDX,
        hasher::RATE_LEN,
        hasher::DIGEST_LEN,
        hasher::NUM_ROUNDS,
        hasher::HASH_CYCLE_LEN,
        hasher::NUM_SELECTORS,
        hasher::TRACE_WIDTH
    );

    insta::assert_snapshot!("hasher_chiplet_layout", layout);
}

/// Documents bitwise chiplet column ranges and offsets.
#[test]
fn document_bitwise_chiplet_layout() {
    let layout = format!(
        r#"BITWISE CHIPLET LAYOUT
===========================

Chiplet Selectors:
  Number of bitwise selectors: {NUM_BITWISE_SELECTORS}
  Trace offset: {BITWISE_TRACE_OFFSET}
  Selector column index: {BITWISE_SELECTOR_COL_IDX}

Input Columns:
  Input A column index: {BITWISE_A_COL_IDX}
  Input B column index: {BITWISE_B_COL_IDX}
  Input A bit decomposition range: {BITWISE_A_COL_RANGE:?}
  Input B bit decomposition range: {BITWISE_B_COL_RANGE:?}

Output Columns:
  Previous output column index: {BITWISE_PREV_OUTPUT_COL_IDX}
  Output column index: {BITWISE_OUTPUT_COL_IDX}

Trace Range:
  Bitwise trace range: {BITWISE_TRACE_RANGE:?}

Other Constants:
  Number of selectors: {}
  Trace width: {}
  Operation cycle length: {}
  Number of decomposed bits per row: {}
"#,
        bitwise::NUM_SELECTORS,
        bitwise::TRACE_WIDTH,
        bitwise::OP_CYCLE_LEN,
        bitwise::NUM_DECOMP_BITS
    );

    insta::assert_snapshot!("bitwise_chiplet_layout", layout);
}

/// Documents memory chiplet column ranges and offsets.
#[test]
fn document_memory_chiplet_layout() {
    let layout = format!(
        r#"MEMORY CHIPLET LAYOUT
==========================

Chiplet Selectors:
  Number of memory selectors: {NUM_MEMORY_SELECTORS}
  Trace offset: {MEMORY_TRACE_OFFSET}
  Trace width: {}

Column Indices (ordered by index):
  - {MEMORY_IS_READ_COL_IDX}: Is read column
  - {MEMORY_IS_WORD_ACCESS_COL_IDX}: Is word access column
  - {MEMORY_CTX_COL_IDX}: Context column
  - {MEMORY_WORD_COL_IDX}: Word column
  - {MEMORY_IDX0_COL_IDX}: Index 0 column
  - {MEMORY_IDX1_COL_IDX}: Index 1 column
  - {MEMORY_CLK_COL_IDX}: Clock column
  - {MEMORY_V_COL_RANGE:?}: Value columns
  - {MEMORY_D0_COL_IDX}: Delta 0 column
  - {MEMORY_D1_COL_IDX}: Delta 1 column
  - {MEMORY_D_INV_COL_IDX}: Delta inverse column
  - {MEMORY_FLAG_SAME_CONTEXT_AND_WORD}: Same context and word flag
"#,
        memory::TRACE_WIDTH
    );

    insta::assert_snapshot!("memory_chiplet_layout", layout);
}

/// Documents ACE chiplet column ranges and offsets.
#[test]
fn document_ace_chiplet_layout() {
    // Collect all column indices with their labels, sorted by index
    let mut columns = vec![
        (ace::SELECTOR_START_IDX, "Selector start"),
        (ace::SELECTOR_BLOCK_IDX, "Selector block"),
        (ace::CTX_IDX, "Context"),
        (ace::PTR_IDX, "Pointer"),
        (ace::CLK_IDX, "Clock"),
        (ace::EVAL_OP_IDX, "Eval operation"),
        (ace::ID_0_IDX, "ID 0"),
        (ace::V_0_0_IDX, "Value 0_0"),
        (ace::V_0_1_IDX, "Value 0_1"),
        (ace::ID_1_IDX, "ID 1"),
        (ace::V_1_0_IDX, "Value 1_0"),
        (ace::V_1_1_IDX, "Value 1_1"),
        (ace::ID_2_IDX, "ID 2"),
        (ace::READ_NUM_EVAL_IDX, "Read num eval"),
        (ace::V_2_0_IDX, "Value 2_0"),
        (ace::V_2_1_IDX, "Value 2_1"),
        (ace::M_1_IDX, "Multiplicity 1"),
        (ace::M_0_IDX, "Multiplicity 0"),
    ];
    columns.sort_by_key(|(idx, _)| *idx);

    let column_list = columns
        .iter()
        .map(|(idx, label)| format!("  - {}: {}", idx, label))
        .collect::<Vec<_>>()
        .join("\n");

    let layout = format!(
        r#"ACE CHIPLET LAYOUT
=====================

Chiplet Selectors:
  Number of ACE selectors: {NUM_ACE_SELECTORS}

Column Indices (ordered by index):
{column_list}

Other Constants:
  Number of columns: {}
  ACE init label: {}
  Instruction ID2 offset: {}
"#,
        ace::ACE_CHIPLET_NUM_COLS,
        ace::ACE_INIT_LABEL.as_int(),
        ace::ACE_INSTRUCTION_ID2_OFFSET.as_int()
    );

    insta::assert_snapshot!("ace_chiplet_layout", layout);
}

/// Documents kernel ROM chiplet constants.
#[test]
fn document_kernel_rom_chiplet_layout() {
    let layout = format!(
        r#"KERNEL ROM CHIPLET LAYOUT
================================

Chiplet Selectors:
  Number of kernel ROM selectors: {NUM_KERNEL_ROM_SELECTORS}

Other Constants:
  Trace width: {}
  Kernel procedure call label: 0b001111 + 1 ({})
  Kernel procedure init label: 0b101111 + 1 ({})
"#,
        kernel_rom::TRACE_WIDTH,
        kernel_rom::KERNEL_PROC_CALL_LABEL.as_int(),
        kernel_rom::KERNEL_PROC_INIT_LABEL.as_int()
    );

    insta::assert_snapshot!("kernel_rom_chiplet_layout", layout);
}

/// Documents all chiplet column ranges in a single comprehensive view.
///
/// This test provides a complete overview of all chiplet column ranges, making it easy
/// to understand how chiplets are laid out within the main trace.
#[test]
fn document_all_chiplet_column_ranges() {
    let hasher_selector_width = HASHER_SELECTOR_COL_RANGE.end - HASHER_SELECTOR_COL_RANGE.start;
    let hasher_state_width = HASHER_STATE_COL_RANGE.end - HASHER_STATE_COL_RANGE.start;
    let hasher_capacity_width = HASHER_CAPACITY_COL_RANGE.end - HASHER_CAPACITY_COL_RANGE.start;
    let hasher_rate_width = HASHER_RATE_COL_RANGE.end - HASHER_RATE_COL_RANGE.start;
    let bitwise_a_width = BITWISE_A_COL_RANGE.end - BITWISE_A_COL_RANGE.start;
    let bitwise_b_width = BITWISE_B_COL_RANGE.end - BITWISE_B_COL_RANGE.start;
    let bitwise_trace_width = BITWISE_TRACE_RANGE.end - BITWISE_TRACE_RANGE.start;
    let memory_v_width = MEMORY_V_COL_RANGE.end - MEMORY_V_COL_RANGE.start;

    let layout = format!(
        r#"ALL CHIPLET COLUMN RANGES
================================

Chiplet Selector Counts:
  - Hasher selectors: {NUM_HASHER_SELECTORS}
  - Bitwise selectors: {NUM_BITWISE_SELECTORS}
  - Memory selectors: {NUM_MEMORY_SELECTORS}
  - ACE selectors: {NUM_ACE_SELECTORS}
  - Kernel ROM selectors: {NUM_KERNEL_ROM_SELECTORS}

Hasher Chiplet:
  Trace offset: {HASHER_TRACE_OFFSET}
  Selector range: {HASHER_SELECTOR_COL_RANGE:?} (width {hasher_selector_width})
  State range: {HASHER_STATE_COL_RANGE:?} (width {hasher_state_width})
  Capacity range: {HASHER_CAPACITY_COL_RANGE:?} (width {hasher_capacity_width})
  Rate range: {HASHER_RATE_COL_RANGE:?} (width {hasher_rate_width})
  Node index: {HASHER_NODE_INDEX_COL_IDX}

Bitwise Chiplet:
  Trace offset: {BITWISE_TRACE_OFFSET}
  Selector index: {BITWISE_SELECTOR_COL_IDX}
  Input A range: {BITWISE_A_COL_RANGE:?} (width {bitwise_a_width})
  Input B range: {BITWISE_B_COL_RANGE:?} (width {bitwise_b_width})
  Trace range: {BITWISE_TRACE_RANGE:?} (width {bitwise_trace_width})

Memory Chiplet:
  Trace offset: {MEMORY_TRACE_OFFSET}
  Value range: {MEMORY_V_COL_RANGE:?} (width {memory_v_width})

Note: All column indices are relative to the main trace (not relative to the chiplet trace).
"#
    );

    insta::assert_snapshot!("all_chiplet_column_ranges", layout);
}

