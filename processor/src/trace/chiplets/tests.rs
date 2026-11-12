use alloc::vec::Vec;
use core::{borrow::Borrow, mem::size_of};

use miden_air_definitions::vm::{
    BitwiseOpCols, ChipletCols,
    trace::{
        CHIPLETS_WIDTH, TRACE_WIDTH,
        chiplets::{
            KERNEL_ROM_TRACE_WIDTH, NUM_BITWISE_SELECTORS, NUM_KERNEL_ROM_SELECTORS,
            NUM_MEMORY_SELECTORS,
            bitwise::{BITWISE_XOR, OP_CYCLE_LEN},
            hasher::{
                CONTROLLER_ROWS_PER_HASHER_OP, CONTROLLER_TRACE_ALIGNMENT, LINEAR_HASH, PADDING,
                STATE_WIDTH,
            },
            memory,
        },
    },
};
use miden_core::{
    Felt, ONE, Word, ZERO,
    mast::{BasicBlockNodeBuilder, CallNodeBuilder, MastForest},
    program::{Program, StackInputs},
};

use super::{AEAD_STREAM_CYCLE_LEN, Chiplets};
use crate::{
    AdviceInputs, ContextId, DefaultHost, ExecutionOptions, FastProcessor, KernelDescriptor,
    RowIndex, operation::Operation, trace::trace_state::AeadStreamReplayEntry,
};

type ChipletsTrace = [Vec<Felt>; CHIPLETS_WIDTH];

// HASHER TRACE LENGTH HELPERS
// ================================================================================================

/// Computes the chiplets-side hasher trace length from the number of controller rows.
fn hasher_trace_len(controller_rows: usize) -> usize {
    controller_rows.next_multiple_of(CONTROLLER_TRACE_ALIGNMENT)
}

// TESTS
// ================================================================================================

#[test]
fn hasher_chiplet_trace() {
    // --- single hasher compression with no stack manipulation ---
    // The program is a single basic block containing Compress.
    // This produces:
    //   - 1 span hash controller row
    //   - 1 COMPRESS controller row
    // Total: 2 controller rows padded to the chiplet alignment boundary.
    let stack = [2, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0];
    let operations = vec![Operation::Compress];
    let (chiplets_trace, _trace_len) = build_trace(&stack, operations, KernelDescriptor::default());

    let controller_rows = 2 * CONTROLLER_ROWS_PER_HASHER_OP; // span hash + Compress
    let hasher_len = hasher_trace_len(controller_rows);
    assert_eq!(hasher_len, CONTROLLER_TRACE_ALIGNMENT);

    validate_hasher_trace(&chiplets_trace, hasher_len, controller_rows);
}

#[test]
fn bitwise_chiplet_trace() {
    // --- single bitwise operation with no stack manipulation ---
    // This produces: 1 span hash controller row, then 1 bitwise row.
    let stack = [4, 8];
    let operations = vec![Operation::U32xor];
    let (chiplets_trace, _trace_len) = build_trace(&stack, operations, KernelDescriptor::default());

    let controller_rows = CONTROLLER_ROWS_PER_HASHER_OP; // span hash only
    let hasher_len = hasher_trace_len(controller_rows);
    assert_eq!(hasher_len, CONTROLLER_TRACE_ALIGNMENT);

    let bitwise_start = hasher_len;
    let bitwise_end = bitwise_start + OP_CYCLE_LEN;
    validate_bitwise_trace(&chiplets_trace, bitwise_start, bitwise_end);
}

#[test]
fn aead_stream_packs_before_ordinary_bitwise_rows() {
    let with_controller = || {
        let mut chiplets = Chiplets::new(KernelDescriptor::default());
        chiplets.hasher.compress([ZERO; STATE_WIDTH]);
        chiplets
    };
    let controller_only = with_controller();
    let trace_len = controller_only.trace_len();
    let eidos_trace_len = controller_only.eidos_compression_trace_len();
    let (_, _, controller_counts) = controller_only.into_traces(trace_len, eidos_trace_len);
    let controller_count: u64 = controller_counts.iter().sum();

    let first_limb = Felt::from_u32(0x8000_0000);
    let mut keystream = [ONE; 8];
    keystream[0] = first_limb;
    let mut ciphertext = [ONE; 8];
    ciphertext[0] = ZERO;

    // An ordinary bitwise run of either length would misalign the eight-row AEAD cycle.
    for num_bitwise_ops in [1, 7] {
        let mut chiplets = with_controller();
        let b = 0xa5a5_ffffu32;
        for idx in 0..num_bitwise_ops {
            chiplets
                .bitwise
                .u32xor(Felt::from_u32((idx + 1) as u32), Felt::from_u32(b))
                .unwrap();
        }
        chiplets
            .aead_stream
            .record(AeadStreamReplayEntry {
                ctx: ZERO,
                clk: ONE,
                src_ptr: Felt::from_u32(100),
                dst_ptr: Felt::from_u32(200),
                lane_base: ZERO,
                plaintext: [first_limb, ZERO, ZERO, ZERO],
                keystream,
                ciphertext,
            })
            .unwrap();
        chiplets
            .memory
            .read(ContextId::root(), Felt::from_u32(100), RowIndex::from(1usize))
            .unwrap();

        let trace_len = chiplets.trace_len();
        let (trace, _, and8_counts) = chiplets.into_traces(trace_len, eidos_trace_len);
        let (rows, _) = trace.trace.as_chunks::<CHIPLETS_WIDTH>();
        let aead_start = CONTROLLER_TRACE_ALIGNMENT;
        let bitwise_start = aead_start + AEAD_STREAM_CYCLE_LEN;
        let memory_start = bitwise_start + num_bitwise_ops * OP_CYCLE_LEN;
        assert_eq!(rows.len(), memory_start + 2);

        for row in &rows[aead_start..bitwise_start] {
            assert_eq!(row[..3], [ONE, ZERO, ZERO]);
            assert_eq!(row[23], ZERO);
        }
        // Column 22 carries the high byte of the first limb's AND witness.
        assert_eq!(rows[aead_start][22], Felt::from_u8(0x80));
        let first_stream_row: &ChipletCols<Felt> = rows[aead_start].as_slice().borrow();
        assert_eq!(first_stream_row.aead_stream_cols().read().src_ptr, Felt::from_u32(100));

        for (idx, row) in rows[bitwise_start..memory_start].iter().enumerate() {
            assert_eq!(row[..3], [ONE, ZERO, ONE]);
            let cols: &ChipletCols<Felt> = row.as_slice().borrow();
            let bitwise = cols.bitwise_cols();
            let a = (idx + 1) as u32;
            assert_eq!(bitwise.op_flag, BITWISE_XOR);
            assert_eq!(bitwise.a_bytes, a.to_le_bytes().map(Felt::from_u8));
            assert_eq!(bitwise.b_bytes, b.to_le_bytes().map(Felt::from_u8));
            assert_eq!(bitwise.and_bytes, (a & b).to_le_bytes().map(Felt::from_u8));
        }

        assert_eq!(rows[memory_start][..3], [ONE, ONE, ZERO]);
        assert_eq!(
            and8_counts.iter().sum::<u64>(),
            controller_count + 4 * (AEAD_STREAM_CYCLE_LEN + num_bitwise_ops * OP_CYCLE_LEN) as u64,
        );
    }
}

#[test]
fn memory_chiplet_trace() {
    // --- single memory operation with no stack manipulation ---
    // This produces: 1 span hash, then 1 memory row.
    let addr = Felt::from_u32(4);
    let stack = [1, 2, 3, 4];
    let operations = vec![Operation::Push(addr), Operation::MStoreW];
    let (chiplets_trace, _trace_len) = build_trace(&stack, operations, KernelDescriptor::default());

    let controller_rows = CONTROLLER_ROWS_PER_HASHER_OP;
    let hasher_len = hasher_trace_len(controller_rows);
    assert_eq!(hasher_len, CONTROLLER_TRACE_ALIGNMENT);

    let memory_start = hasher_len;
    validate_memory_trace(&chiplets_trace, memory_start, memory_start + 1);
}

#[test]
fn stacked_chiplet_trace() {
    // --- operations in hasher, bitwise, and memory processors ---
    // Operations: U32xor, Push(0), MStoreW, Compress
    // This produces:
    //   - 1 span hash controller row for the basic block
    //   - 1 COMPRESS controller row
    // Total hasher: 2 controller rows padded to the chiplet alignment boundary.
    // Then: 1 bitwise row (U32xor), then 1 memory row (MStoreW)
    let stack = [8, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 1];
    let ops = vec![
        Operation::U32xor,
        Operation::Push(ZERO),
        Operation::MStoreW,
        Operation::Compress,
    ];
    let kernel = build_kernel();
    let (chiplets_trace, _trace_len) = build_trace(&stack, ops, kernel);

    let controller_rows = 2 * CONTROLLER_ROWS_PER_HASHER_OP; // span hash + Compress
    let hasher_len = hasher_trace_len(controller_rows);
    assert_eq!(hasher_len, CONTROLLER_TRACE_ALIGNMENT);

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

        Program::with_kernel(forest.into(), entry, KernelDescriptor::default())
    };

    let execution_witness = processor.execute_for_proving_sync(&program, &mut host).unwrap();
    let (vm_witness, _) = execution_witness.into_parts();

    let _trace =
        crate::trace::build_trace(vm_witness, &miden_vm_stark::memory::default_budget()).unwrap();
}

// HELPER FUNCTIONS
// ================================================================================================

fn build_kernel() -> KernelDescriptor {
    let proc_hash1 = Word::from([1_u32, 0, 1, 0]);
    let proc_hash2 = Word::from([1_u32, 1, 1, 1]);
    KernelDescriptor::new(&[proc_hash1, proc_hash2]).unwrap()
}

fn build_trace(
    stack_inputs: &[u64],
    operations: Vec<Operation>,
    kernel: KernelDescriptor,
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

    let execution_witness = processor.execute_for_proving_sync(&program, &mut host).unwrap();
    let (vm_witness, _) = execution_witness.into_parts();
    let trace =
        crate::trace::build_trace(vm_witness, &miden_vm_stark::memory::default_budget()).unwrap();

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
/// - The top-level selector is zero on controller rows
/// - Controller rows have the correct selectors for operation type and boundary flags
/// - Controller row addresses increment through operation and alignment padding rows
/// - Padding rows: selectors [0, 1, 0], zero payload except the controller discriminator
fn validate_hasher_trace(trace: &ChipletsTrace, expected_len: usize, controller_rows: usize) {
    let controller_padded = hasher_trace_len(controller_rows);

    assert_eq!(expected_len, controller_padded);

    for row in 0..controller_padded {
        let packed_row: [Felt; CHIPLETS_WIDTH] = core::array::from_fn(|col| trace[col][row]);
        assert_eq!(packed_row[0], ZERO, "top-level selector at controller row {row}");
        let cols: &ChipletCols<Felt> = packed_row.as_slice().borrow();
        let controller = cols.controller_cols();
        assert_eq!(
            controller.addr,
            Felt::new_unchecked(row as u64 + 1),
            "controller address at row {row}"
        );

        if row < controller_rows {
            assert_eq!(controller.s0, LINEAR_HASH[0], "row kind at controller row {row}");
        } else {
            assert_eq!([controller.s0, controller.s1, controller.s2], PADDING, "row {row}");
            assert_eq!(controller.state, [ZERO; STATE_WIDTH], "padding row {row}");
            assert_eq!(controller.row_data, [ZERO; 4], "padding row {row}");
            assert_eq!(controller.op_final, ZERO, "padding row {row}");
            assert_eq!(controller.mrupdate_id, ZERO, "padding row {row}");
            assert_eq!(controller.merkle_or_padding, ONE, "padding row {row}");
        }
    }
}

/// Validates the bitwise region of the chiplets trace.
///
/// Checks:
/// - Chiplet selector prefix: 101
/// - Bitwise operation selector = XOR
/// - Columns beyond bitwise trace width + selectors are zero
fn validate_bitwise_trace(trace: &ChipletsTrace, start: usize, end: usize) {
    // Ordinary bitwise operations use three selectors and 13 payload cells.
    let bitwise_used_cols = NUM_BITWISE_SELECTORS + size_of::<BitwiseOpCols<u8>>();

    for row in start..end {
        assert_eq!(ONE, trace[0][row], "bitwise s0 at row {row}");
        assert_eq!(ZERO, trace[1][row], "bitwise s1 at row {row}");
        assert_eq!(ONE, trace[2][row], "bitwise s2 at row {row}");

        // Internal bitwise operation selector (XOR)
        assert_eq!(BITWISE_XOR, trace[NUM_BITWISE_SELECTORS][row], "bitwise op at row {row}");

        // Columns beyond the bitwise trace should be zero.
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
/// - Chiplet selector prefix: 110
/// - Columns beyond memory trace width + selectors are zero
fn validate_memory_trace(trace: &ChipletsTrace, start: usize, end: usize) {
    // Memory uses NUM_MEMORY_SELECTORS (3) chiplet selector columns + memory::TRACE_WIDTH (17)
    // internal columns = 20 columns total. Column 20 should be zero.
    let memory_used_cols = NUM_MEMORY_SELECTORS + memory::TRACE_WIDTH;

    for row in start..end {
        assert_eq!(ONE, trace[0][row], "memory s0 at row {row}");
        assert_eq!(ONE, trace[1][row], "memory s1 at row {row}");
        assert_eq!(ZERO, trace[2][row], "memory s2 at row {row}");

        // Columns beyond the memory trace should be zero.
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
/// - Chiplet selector prefix: 11110
/// - Columns beyond kernel ROM trace width + selectors are zero
fn validate_kernel_rom_trace(trace: &ChipletsTrace, start: usize, end: usize) {
    // Kernel ROM uses NUM_KERNEL_ROM_SELECTORS (5) chiplet selector columns +
    // KERNEL_ROM_TRACE_WIDTH (5) internal columns = 10 columns total.
    let kernel_rom_used_cols = NUM_KERNEL_ROM_SELECTORS + KERNEL_ROM_TRACE_WIDTH;

    for row in start..end {
        assert_eq!(ONE, trace[0][row], "kernel_rom s0 at row {row}");
        assert_eq!(ONE, trace[1][row], "kernel_rom s1 at row {row}");
        assert_eq!(ONE, trace[2][row], "kernel_rom s2 at row {row}");
        assert_eq!(ONE, trace[3][row], "kernel_rom s3 at row {row}");
        assert_eq!(ZERO, trace[4][row], "kernel_rom s4 at row {row}");

        // Columns beyond the kernel ROM trace should be zero.
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
/// - Chiplet selector prefix: 11111
/// - payload columns are zero
fn validate_padding(trace: &ChipletsTrace, start: usize, end: usize) {
    for row in start..end {
        for col in 0..5 {
            assert_eq!(ONE, trace[col][row], "padding s{col} at row {row}");
        }
        for col in 5..CHIPLETS_WIDTH {
            assert_eq!(ZERO, trace[col][row], "padding data col {col} at row {row} should be zero");
        }
    }
}
