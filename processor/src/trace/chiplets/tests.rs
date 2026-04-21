use alloc::vec::Vec;

use miden_air::trace::{
    CHIPLETS_RANGE, CHIPLETS_WIDTH,
    chiplets::{
        KERNEL_ROM_TRACE_WIDTH, NUM_BITWISE_SELECTORS, NUM_KERNEL_ROM_SELECTORS,
        NUM_MEMORY_SELECTORS,
        bitwise::{self, BITWISE_XOR, OP_CYCLE_LEN},
        hasher::{CONTROLLER_ROWS_PER_PERMUTATION, HASH_CYCLE_LEN, LINEAR_HASH, S_PERM_COL_IDX},
        memory,
    },
};
use miden_core::{
    Felt, ONE, Word, ZERO,
    mast::{BasicBlockNodeBuilder, CallNodeBuilder, MastForest, MastForestContributor},
    program::{Program, StackInputs},
};

use crate::{
    AdviceInputs, DefaultHost, ExecutionOptions, FastProcessor, Kernel, operation::Operation,
};

type ChipletsTrace = [Vec<Felt>; CHIPLETS_WIDTH];

// HASHER TRACE LENGTH HELPERS
// ================================================================================================

/// Computes the total hasher trace length given the number of controller rows and unique
/// permutations.
///
/// The controller region (including padding) is rounded up to the next multiple of
/// HASH_CYCLE_LEN, then the perm segment appends `unique_perms * HASH_CYCLE_LEN` rows.
fn hasher_trace_len(controller_rows: usize, unique_perms: usize) -> usize {
    let controller_padded = controller_rows.next_multiple_of(HASH_CYCLE_LEN);
    let perm_segment = unique_perms * HASH_CYCLE_LEN;
    controller_padded + perm_segment
}

// TESTS
// ================================================================================================

#[test]
fn hasher_chiplet_trace() {
    // --- single hasher permutation with no stack manipulation ---
    // The program is a single basic block containing HPerm.
    // This produces:
    //   - 1 span hash (LINEAR_HASH input + RETURN_HASH output) = 2 controller rows, 1 perm
    //   - 1 HPERM (RETURN_STATE input + RETURN_STATE output) = 2 controller rows, 1 perm
    // Total: 4 controller rows padded to 16, 2 unique perms (32 perm rows) = 48 hasher rows.
    let stack = [2, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0];
    let operations = vec![Operation::HPerm];
    let (chiplets_trace, _trace_len) = build_trace(&stack, operations, Kernel::default());

    let controller_rows = 2 * CONTROLLER_ROWS_PER_PERMUTATION; // span hash + HPerm
    let unique_perms = 2;
    let hasher_len = hasher_trace_len(controller_rows, unique_perms);
    assert_eq!(hasher_len, 48);

    validate_hasher_trace(&chiplets_trace, hasher_len, controller_rows, unique_perms);
}

#[test]
fn bitwise_chiplet_trace() {
    // --- single bitwise operation with no stack manipulation ---
    // This produces: 1 span hash (2 controller rows, 1 perm) = 32 hasher rows, then 8 bitwise.
    let stack = [4, 8];
    let operations = vec![Operation::U32xor];
    let (chiplets_trace, _trace_len) = build_trace(&stack, operations, Kernel::default());

    let controller_rows = CONTROLLER_ROWS_PER_PERMUTATION; // span hash only
    let unique_perms = 1;
    let hasher_len = hasher_trace_len(controller_rows, unique_perms);
    assert_eq!(hasher_len, 32);

    let bitwise_start = hasher_len;
    let bitwise_end = bitwise_start + OP_CYCLE_LEN;
    validate_bitwise_trace(&chiplets_trace, bitwise_start, bitwise_end);
}

#[test]
fn memory_chiplet_trace() {
    // --- single memory operation with no stack manipulation ---
    // This produces: 1 span hash (32 hasher rows), then 1 memory row.
    let addr = Felt::from_u32(4);
    let stack = [1, 2, 3, 4];
    let operations = vec![Operation::Push(addr), Operation::MStoreW];
    let (chiplets_trace, _trace_len) = build_trace(&stack, operations, Kernel::default());

    let controller_rows = CONTROLLER_ROWS_PER_PERMUTATION;
    let unique_perms = 1;
    let hasher_len = hasher_trace_len(controller_rows, unique_perms);
    assert_eq!(hasher_len, 32);

    let memory_start = hasher_len;
    validate_memory_trace(&chiplets_trace, memory_start, memory_start + 1);
}

#[test]
fn stacked_chiplet_trace() {
    // --- operations in hasher, bitwise, and memory processors ---
    // Operations: U32xor, Push(0), MStoreW, HPerm
    // This produces:
    //   - 1 span hash (2 controller rows, 1 perm) for the basic block
    //   - 1 HPerm (2 controller rows, 1 perm)
    // Total hasher: 4 controller rows padded to 16, 2 unique perms = 48 rows
    // Then: 8 bitwise rows (U32xor), then 1 memory row (MStoreW)
    let stack = [8, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 1];
    let ops = vec![Operation::U32xor, Operation::Push(ZERO), Operation::MStoreW, Operation::HPerm];
    let kernel = build_kernel();
    let (chiplets_trace, _trace_len) = build_trace(&stack, ops, kernel);

    let controller_rows = 2 * CONTROLLER_ROWS_PER_PERMUTATION; // span hash + HPerm
    let unique_perms = 2;
    let hasher_len = hasher_trace_len(controller_rows, unique_perms);
    assert_eq!(hasher_len, 48);

    // Validate hasher region
    validate_hasher_trace(&chiplets_trace, hasher_len, controller_rows, unique_perms);

    // Bitwise starts right after hasher
    let bitwise_start = hasher_len;
    let bitwise_end = bitwise_start + OP_CYCLE_LEN;
    validate_bitwise_trace(&chiplets_trace, bitwise_start, bitwise_end);

    // Memory starts right after bitwise
    let memory_start = bitwise_end;
    validate_memory_trace(&chiplets_trace, memory_start, memory_start + 1);

    // After memory comes kernel ROM (2 entries from build_kernel) then padding
    let kernel_rom_start = memory_start + 1;
    let kernel_rom_end = kernel_rom_start + 2; // 2 kernel procedures
    validate_kernel_rom_trace(&chiplets_trace, kernel_rom_start, kernel_rom_end);

    // Padding fills the remainder
    let padding_start = kernel_rom_end;
    let trace_rows = chiplets_trace[0].len();
    validate_padding(&chiplets_trace, padding_start, trace_rows);
}

#[test]
fn regression_trace_build_does_not_panic_when_first_memory_access_clk_is_zero() {
    let processor = FastProcessor::new(StackInputs::default());
    let mut host = DefaultHost::default();

    // A CALL entrypoint records the callee frame pointer write before the processor clock is
    // incremented, so the first memory access is captured at clk = 0.
    let program = {
        let mut forest = MastForest::new();

        let callee = BasicBlockNodeBuilder::new(vec![Operation::Noop], Vec::new())
            .add_to_forest(&mut forest)
            .unwrap();
        forest.make_root(callee);

        let entry = CallNodeBuilder::new(callee).add_to_forest(&mut forest).unwrap();
        forest.make_root(entry);

        Program::with_kernel(forest.into(), entry, Kernel::default())
    };

    let trace_inputs = processor.execute_trace_inputs_sync(&program, &mut host).unwrap();

    let _trace = crate::trace::build_trace(trace_inputs).unwrap();
}

// HELPER FUNCTIONS
// ================================================================================================

fn build_kernel() -> Kernel {
    let proc_hash1 = Word::from([1_u32, 0, 1, 0]);
    let proc_hash2 = Word::from([1_u32, 1, 1, 1]);
    Kernel::new(&[proc_hash1, proc_hash2]).unwrap()
}

fn build_trace(
    stack_inputs: &[u64],
    operations: Vec<Operation>,
    kernel: Kernel,
) -> (ChipletsTrace, usize) {
    let stack_inputs: Vec<Felt> = stack_inputs.iter().map(|v| Felt::new(*v)).collect();
    let processor = FastProcessor::new_with_options(
        StackInputs::new(&stack_inputs).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default().with_core_trace_fragment_size(1 << 10).unwrap(),
    );

    let mut host = DefaultHost::default();
    let program = {
        let mut mast_forest = MastForest::new();
        let basic_block_id = BasicBlockNodeBuilder::new(operations, Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        mast_forest.make_root(basic_block_id);
        Program::with_kernel(mast_forest.into(), basic_block_id, kernel)
    };

    let trace_inputs = processor.execute_trace_inputs_sync(&program, &mut host).unwrap();
    let trace = crate::trace::build_trace(trace_inputs).unwrap();

    let trace_len = trace.get_trace_len();
    (
        trace
            .get_column_range(CHIPLETS_RANGE)
            .try_into()
            .expect("failed to convert vector to array"),
        trace_len,
    )
}

// VALIDATION FUNCTIONS
// ================================================================================================

/// Validates the hasher region of the chiplets trace.
///
/// Checks:
/// - s_ctrl (column 0) = 1 on controller rows, 0 on permutation rows
/// - s_perm (column 20) = 0 on controller rows, 1 on permutation rows
/// - Controller rows (s_perm=0): correct selectors for operation type, is_start/is_final flags
/// - Padding rows: selectors [0, 1, 0], non-selector columns are zero
/// - Perm segment rows (s_perm=1): selectors are zero (don't-care), s_perm=1
fn validate_hasher_trace(
    trace: &ChipletsTrace,
    expected_len: usize,
    controller_rows: usize,
    unique_perms: usize,
) {
    // Column indices within chiplets trace.
    // Column 0 = s_ctrl, column 20 = s_perm. Hasher internal columns start at column 1.
    let s0_col = 1; // hasher selector s0
    let s1_col = 2; // hasher selector s1
    let s2_col = 3; // hasher selector s2
    let s_perm_col = 1 + S_PERM_COL_IDX; // s_perm in chiplets trace (= column 20)

    let controller_padded = controller_rows.next_multiple_of(HASH_CYCLE_LEN);
    let perm_segment_start = controller_padded;
    let perm_segment_len = unique_perms * HASH_CYCLE_LEN;

    assert_eq!(expected_len, controller_padded + perm_segment_len);

    // --- Check s_ctrl and s_perm for all hasher rows ---
    // Controller rows (including padding): s_ctrl=1, s_perm=0
    for row in 0..controller_padded {
        assert_eq!(trace[0][row], ONE, "s_ctrl should be 1 for controller row {row}");
        assert_eq!(trace[s_perm_col][row], ZERO, "s_perm should be 0 for controller row {row}");
    }
    // Permutation rows: s_ctrl=0, s_perm=1
    for row in perm_segment_start..expected_len {
        assert_eq!(trace[0][row], ZERO, "s_ctrl should be 0 for perm row {row}");
        assert_eq!(trace[s_perm_col][row], ONE, "s_perm should be 1 for perm row {row}");
    }

    // --- Check controller rows (s_perm = 0) ---
    // Controller rows come in pairs: input row (is_start varies) + output row (is_final varies).
    // For a span hash: input has LINEAR_HASH selectors, output has RETURN_HASH selectors.
    // For HPerm: input has LINEAR_HASH selectors, output has RETURN_STATE selectors.
    for row in 0..controller_rows {
        let is_input_row = row % CONTROLLER_ROWS_PER_PERMUTATION == 0;
        if is_input_row {
            // Input rows have s0=1 (LINEAR_HASH[0])
            assert_eq!(
                trace[s0_col][row], LINEAR_HASH[0],
                "controller input row {row}: s0 should be {} (LINEAR_HASH)",
                LINEAR_HASH[0]
            );
        } else {
            // Output rows have s0=0 (RETURN_HASH or RETURN_STATE)
            assert_eq!(
                trace[s0_col][row], ZERO,
                "controller output row {row}: s0 should be 0 (RETURN_*)"
            );
        }
    }

    // --- Check padding rows ---
    // Padding rows fill from controller_rows to controller_padded.
    // Padding selectors are [0, 1, 0] (matching PERM_STEP pattern but in controller region).
    let padding_start = controller_rows;
    for row in padding_start..controller_padded {
        // Padding selectors: s0=0, s1=1, s2=0
        assert_eq!(trace[s0_col][row], ZERO, "padding row {row}: s0 should be 0");
        assert_eq!(trace[s1_col][row], ONE, "padding row {row}: s1 should be 1");
        assert_eq!(trace[s2_col][row], ZERO, "padding row {row}: s2 should be 0");

        // Non-selector hasher columns should be zero on padding rows.
        // Hasher state columns (indices 4..16 in chiplets trace = hasher cols 3..15)
        for col in 4..=CHIPLETS_WIDTH - 1 {
            assert_eq!(trace[col][row], ZERO, "padding row {row}, col {col} should be zero");
        }
    }

    // --- Check perm segment rows (s_perm = 1) ---
    for row in perm_segment_start..expected_len {
        // On perm rows, s0/s1/s2 serve as witness columns for packed internal rounds.
        // They are zero on external/boundary rows (offsets 0-3, 12-15 within each cycle),
        // and hold S-box witnesses on packed-internal rows (offsets 4-10) and the int+ext
        // row (offset 11, s0 only).
        let offset_in_cycle = (row - perm_segment_start) % HASH_CYCLE_LEN;
        match offset_in_cycle {
            0..=3 | 12..=15 => {
                assert_eq!(trace[s0_col][row], ZERO, "perm row {row}: s0 should be 0");
                assert_eq!(trace[s1_col][row], ZERO, "perm row {row}: s1 should be 0");
                assert_eq!(trace[s2_col][row], ZERO, "perm row {row}: s2 should be 0");
            },
            4..=10 => {
                // Packed internal: all 3 witnesses may be nonzero (no assertion on value)
            },
            11 => {
                // Int+ext: s0 holds witness, s1 and s2 are zero
                assert_eq!(trace[s1_col][row], ZERO, "perm row {row}: s1 should be 0");
                assert_eq!(trace[s2_col][row], ZERO, "perm row {row}: s2 should be 0");
            },
            _ => unreachable!(),
        }
    }
}

/// Validates the bitwise region of the chiplets trace.
///
/// Checks:
/// - Chiplet selectors: s_ctrl=0, s1=0, s_perm=0
/// - Bitwise operation selector = XOR
/// - Columns beyond bitwise trace width + selectors are zero
fn validate_bitwise_trace(trace: &ChipletsTrace, start: usize, end: usize) {
    // Bitwise uses NUM_BITWISE_SELECTORS (2) chiplet selector columns + bitwise::TRACE_WIDTH (13)
    // internal columns = 15 columns total. Columns 15..CHIPLETS_WIDTH should be zero.
    let bitwise_used_cols = NUM_BITWISE_SELECTORS + bitwise::TRACE_WIDTH;

    for row in start..end {
        // Chiplet selectors: s_ctrl=0, s1=0 (active via virtual s0 * !s1)
        assert_eq!(ZERO, trace[0][row], "bitwise s_ctrl at row {row}");
        assert_eq!(ZERO, trace[1][row], "bitwise s1 at row {row}");

        // Internal bitwise operation selector (XOR)
        assert_eq!(BITWISE_XOR, trace[NUM_BITWISE_SELECTORS][row], "bitwise op at row {row}");

        // Columns beyond bitwise trace should be zero
        for col in bitwise_used_cols..CHIPLETS_WIDTH {
            assert_eq!(
                trace[col][row], ZERO,
                "bitwise padding col {col} at row {row} should be zero"
            );
        }
    }
}

/// Validates the memory region of the chiplets trace.
///
/// Checks:
/// - Chiplet selectors: s_ctrl=0, s1=1, s2=0, s_perm=0
/// - Column beyond memory trace width + selectors is zero
fn validate_memory_trace(trace: &ChipletsTrace, start: usize, end: usize) {
    // Memory uses NUM_MEMORY_SELECTORS (3) chiplet selector columns + memory::TRACE_WIDTH (17)
    // internal columns = 20 columns total. Column 20 should be zero.
    let memory_used_cols = NUM_MEMORY_SELECTORS + memory::TRACE_WIDTH;

    for row in start..end {
        // Chiplet selectors: s_ctrl=0, s1=1, s2=0 (active via virtual s0 * s1 * !s2)
        assert_eq!(ZERO, trace[0][row], "memory s_ctrl at row {row}");
        assert_eq!(ONE, trace[1][row], "memory s1 at row {row}");
        assert_eq!(ZERO, trace[2][row], "memory s2 at row {row}");

        // Columns beyond memory trace should be zero
        for col in memory_used_cols..CHIPLETS_WIDTH {
            assert_eq!(
                trace[col][row], ZERO,
                "memory padding col {col} at row {row} should be zero"
            );
        }
    }
}

/// Validates the kernel ROM region of the chiplets trace.
///
/// Checks:
/// - Chiplet selectors: s_ctrl=0, s1=1, s2=1, s3=1, s4=0, s_perm=0
/// - Columns beyond kernel ROM trace width + selectors are zero
fn validate_kernel_rom_trace(trace: &ChipletsTrace, start: usize, end: usize) {
    // Kernel ROM uses NUM_KERNEL_ROM_SELECTORS (5) chiplet selector columns +
    // KERNEL_ROM_TRACE_WIDTH (5) internal columns = 10 columns total.
    let kernel_rom_used_cols = NUM_KERNEL_ROM_SELECTORS + KERNEL_ROM_TRACE_WIDTH;

    for row in start..end {
        // Chiplet selectors: s_ctrl=0, s1=1, s2=1, s3=1, s4=0
        // (active via virtual s0 * s1 * s2 * s3 * !s4)
        assert_eq!(ZERO, trace[0][row], "kernel_rom s_ctrl at row {row}");
        assert_eq!(ONE, trace[1][row], "kernel_rom s1 at row {row}");
        assert_eq!(ONE, trace[2][row], "kernel_rom s2 at row {row}");
        assert_eq!(ONE, trace[3][row], "kernel_rom s3 at row {row}");
        assert_eq!(ZERO, trace[4][row], "kernel_rom s4 at row {row}");

        // Columns beyond kernel ROM trace should be zero
        for col in kernel_rom_used_cols..CHIPLETS_WIDTH {
            assert_eq!(
                trace[col][row], ZERO,
                "kernel_rom padding col {col} at row {row} should be zero"
            );
        }
    }
}

/// Validates the padding region at the end of the chiplets trace.
///
/// Checks:
/// - s_ctrl (column 0) = 0, s1..s4 (columns 1-4) = 1, s_perm (column 20) = 0
/// - All remaining columns (5..CHIPLETS_WIDTH) are zero
fn validate_padding(trace: &ChipletsTrace, start: usize, end: usize) {
    for row in start..end {
        // s_ctrl = 0 on padding rows
        assert_eq!(ZERO, trace[0][row], "padding s_ctrl at row {row}");
        // s1..s4 = 1 on padding rows
        for col in 1..5 {
            assert_eq!(ONE, trace[col][row], "padding s{col} at row {row}");
        }
        // All non-selector columns should be zero (including s_perm at column 20)
        for col in 5..CHIPLETS_WIDTH {
            assert_eq!(ZERO, trace[col][row], "padding data col {col} at row {row} should be zero");
        }
    }
}
