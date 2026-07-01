use alloc::vec::Vec;

use miden_air::trace::{
    CHIPLETS_WIDTH, TRACE_WIDTH,
    chiplets::{
        KERNEL_ROM_TRACE_WIDTH,
        bitwise::{self, BITWISE_XOR, OP_CYCLE_LEN},
        hasher::{CONTROLLER_ROWS_PER_PERMUTATION, CONTROLLER_TRACE_ALIGNMENT, LINEAR_HASH},
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

const S0_COL: usize = 0;
const S1_COL: usize = 1;
const S2_COL: usize = 2;
const S3_COL: usize = 3;
const S4_COL: usize = 4;
const HASHER_COL_START: usize = 1;
const BITWISE_COL_START: usize = 2;
const MEMORY_COL_START: usize = 3;
const KERNEL_ROM_COL_START: usize = 5;
const CHIP_CLK_COL: usize = CHIPLETS_WIDTH - 1;

fn hasher_trace_len(controller_rows: usize) -> usize {
    controller_rows.next_multiple_of(CONTROLLER_TRACE_ALIGNMENT)
}

// TESTS
// ================================================================================================

#[test]
fn hasher_chiplet_trace() {
    // --- single hasher permutation with no stack manipulation ---
    // The program is a single basic block containing HPerm.
    // The chiplet hasher region contains only controller rows plus alignment padding.
    let stack = [2, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0];
    let operations = vec![Operation::HPerm];
    let (chiplets_trace, _trace_len) = build_trace(&stack, operations, Kernel::default());

    let controller_rows = 2 * CONTROLLER_ROWS_PER_PERMUTATION; // span hash + HPerm
    let hasher_len = hasher_trace_len(controller_rows);
    assert_eq!(hasher_len, 8);

    validate_hasher_trace(&chiplets_trace, hasher_len, controller_rows);
}

#[test]
fn bitwise_chiplet_trace() {
    // --- single bitwise operation with no stack manipulation ---
    // This produces one span-hash controller pair before the bitwise rows.
    let stack = [4, 8];
    let operations = vec![Operation::U32xor];
    let (chiplets_trace, _trace_len) = build_trace(&stack, operations, Kernel::default());

    let controller_rows = CONTROLLER_ROWS_PER_PERMUTATION; // span hash only
    let hasher_len = hasher_trace_len(controller_rows);
    assert_eq!(hasher_len, 8);

    let bitwise_start = hasher_len;
    let bitwise_end = bitwise_start + OP_CYCLE_LEN;
    validate_bitwise_trace(&chiplets_trace, bitwise_start, bitwise_end);
}

#[test]
fn memory_chiplet_trace() {
    // --- single memory operation with no stack manipulation ---
    // This produces one span-hash controller pair before the memory row.
    let addr = Felt::from_u32(4);
    let stack = [1, 2, 3, 4];
    let operations = vec![Operation::Push(addr), Operation::MStoreW];
    let (chiplets_trace, _trace_len) = build_trace(&stack, operations, Kernel::default());

    let controller_rows = CONTROLLER_ROWS_PER_PERMUTATION;
    let hasher_len = hasher_trace_len(controller_rows);
    assert_eq!(hasher_len, 8);

    let memory_start = hasher_len;
    validate_memory_trace(&chiplets_trace, memory_start, memory_start + 1);
}

#[test]
fn stacked_chiplet_trace() {
    // --- operations in hasher, bitwise, and memory processors ---
    // Operations: U32xor, Push(0), MStoreW, HPerm
    // This produces two hasher controller pairs, then bitwise and memory rows.
    let stack = [8, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 1];
    let ops = vec![Operation::U32xor, Operation::Push(ZERO), Operation::MStoreW, Operation::HPerm];
    let kernel = build_kernel();
    let (chiplets_trace, _trace_len) = build_trace(&stack, ops, kernel);

    let controller_rows = 2 * CONTROLLER_ROWS_PER_PERMUTATION; // span hash + HPerm
    let hasher_len = hasher_trace_len(controller_rows);
    assert_eq!(hasher_len, 8);

    // Validate hasher region
    validate_hasher_trace(&chiplets_trace, hasher_len, controller_rows);

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

        let callee = BasicBlockNodeBuilder::new(vec![Operation::Noop])
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
    let stack_inputs: Vec<Felt> = stack_inputs.iter().map(|v| Felt::new_unchecked(*v)).collect();
    let processor = FastProcessor::new_with_options(
        StackInputs::new(&stack_inputs).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default().with_core_trace_fragment_size(1 << 10).unwrap(),
    )
    .expect("processor advice inputs should fit advice map limits");

    let mut host = DefaultHost::default();
    let program = {
        let mut mast_forest = MastForest::new();
        let basic_block_id =
            BasicBlockNodeBuilder::new(operations).add_to_forest(&mut mast_forest).unwrap();
        mast_forest.make_root(basic_block_id);
        Program::with_kernel(mast_forest.into(), basic_block_id, kernel)
    };

    let trace_inputs = processor.execute_trace_inputs_sync(&program, &mut host).unwrap();
    let trace = crate::trace::build_trace(trace_inputs).unwrap();

    let trace_len = trace.get_trace_len();
    (
        trace
            .get_column_range((TRACE_WIDTH - CHIPLETS_WIDTH)..TRACE_WIDTH)
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
/// - `s0` is zero on every hasher-controller row
/// - Controller rows have the expected operation selector
/// - Padding rows use the controller padding selector `[0, 1, 0]`
fn validate_hasher_trace(trace: &ChipletsTrace, expected_len: usize, controller_rows: usize) {
    let s0_col = HASHER_COL_START;
    let s1_col = HASHER_COL_START + 1;
    let s2_col = HASHER_COL_START + 2;

    let controller_padded = controller_rows.next_multiple_of(CONTROLLER_TRACE_ALIGNMENT);
    assert_eq!(expected_len, controller_padded);

    for row in 0..controller_padded {
        assert_eq!(trace[S0_COL][row], ZERO, "top-level s0 should be 0 for row {row}");
    }

    for row in 0..controller_rows {
        let is_input_row = row % CONTROLLER_ROWS_PER_PERMUTATION == 0;
        if is_input_row {
            assert_eq!(
                trace[s0_col][row], LINEAR_HASH[0],
                "controller input row {row}: s0 should be {} (LINEAR_HASH)",
                LINEAR_HASH[0]
            );
        } else {
            assert_eq!(
                trace[s0_col][row], ZERO,
                "controller output row {row}: s0 should be 0 (RETURN_*)"
            );
        }
    }

    for row in controller_rows..controller_padded {
        assert_eq!(trace[s0_col][row], ZERO, "padding row {row}: s0 should be 0");
        assert_eq!(trace[s1_col][row], ONE, "padding row {row}: s1 should be 1");
        assert_eq!(trace[s2_col][row], ZERO, "padding row {row}: s2 should be 0");

        for col in HASHER_COL_START + 3..CHIP_CLK_COL {
            assert_eq!(trace[col][row], ZERO, "padding row {row}, col {col} should be zero");
        }
    }
}

/// Validates the bitwise region of the chiplets trace.
///
/// Checks:
/// - Chiplet selectors: `s0=1`, `s1=0`
/// - Bitwise operation selector = XOR
/// - Columns beyond bitwise trace width + selectors are zero
fn validate_bitwise_trace(trace: &ChipletsTrace, start: usize, end: usize) {
    let bitwise_data_start = BITWISE_COL_START;
    let bitwise_data_end = bitwise_data_start + bitwise::TRACE_WIDTH;

    for row in start..end {
        assert_eq!(ONE, trace[S0_COL][row], "bitwise s0 at row {row}");
        assert_eq!(ZERO, trace[S1_COL][row], "bitwise s1 at row {row}");

        // Internal bitwise operation selector (XOR)
        assert_eq!(BITWISE_XOR, trace[bitwise_data_start][row], "bitwise op at row {row}");

        // Columns beyond bitwise trace should be zero.
        for col in bitwise_data_end..CHIP_CLK_COL {
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
/// - Chiplet selectors: `s0=1`, `s1=1`, `s2=0`
/// - Column beyond memory trace width + selectors is zero
fn validate_memory_trace(trace: &ChipletsTrace, start: usize, end: usize) {
    let memory_data_end = MEMORY_COL_START + memory::TRACE_WIDTH;

    for row in start..end {
        assert_eq!(ONE, trace[S0_COL][row], "memory s0 at row {row}");
        assert_eq!(ONE, trace[S1_COL][row], "memory s1 at row {row}");
        assert_eq!(ZERO, trace[S2_COL][row], "memory s2 at row {row}");

        for col in memory_data_end..CHIP_CLK_COL {
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
/// - Chiplet selectors: `s0=s1=s2=s3=1`, `s4=0`
/// - Columns beyond kernel ROM trace width + selectors are zero
fn validate_kernel_rom_trace(trace: &ChipletsTrace, start: usize, end: usize) {
    let kernel_rom_data_end = KERNEL_ROM_COL_START + KERNEL_ROM_TRACE_WIDTH;

    for row in start..end {
        assert_eq!(ONE, trace[S0_COL][row], "kernel_rom s0 at row {row}");
        assert_eq!(ONE, trace[S1_COL][row], "kernel_rom s1 at row {row}");
        assert_eq!(ONE, trace[S2_COL][row], "kernel_rom s2 at row {row}");
        assert_eq!(ONE, trace[S3_COL][row], "kernel_rom s3 at row {row}");
        assert_eq!(ZERO, trace[S4_COL][row], "kernel_rom s4 at row {row}");

        for col in kernel_rom_data_end..CHIP_CLK_COL {
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
/// - `s0..s4=1`
/// - Data columns after `s4` are zero
fn validate_padding(trace: &ChipletsTrace, start: usize, end: usize) {
    for row in start..end {
        for col in S0_COL..=S4_COL {
            assert_eq!(ONE, trace[col][row], "padding s{col} at row {row}");
        }
        for col in KERNEL_ROM_COL_START..CHIP_CLK_COL {
            assert_eq!(ZERO, trace[col][row], "padding data col {col} at row {row} should be zero");
        }
        assert_ne!(ZERO, trace[CHIP_CLK_COL][row], "padding chip_clk at row {row}");
    }
}
