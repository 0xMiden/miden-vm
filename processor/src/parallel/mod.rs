use alloc::{boxed::Box, vec::Vec};

use itertools::Itertools;
use miden_air::{
    Felt,
    trace::{
        CLK_COL_IDX, CTX_COL_IDX, DECODER_TRACE_OFFSET, DECODER_TRACE_WIDTH, FN_HASH_RANGE,
        MIN_TRACE_LEN, MainTrace, PADDED_TRACE_WIDTH, RowIndex, STACK_TRACE_OFFSET,
        STACK_TRACE_WIDTH, SYS_TRACE_WIDTH, TRACE_WIDTH,
        decoder::{
            ADDR_COL_IDX, GROUP_COUNT_COL_IDX, HASHER_STATE_OFFSET, IN_SPAN_COL_IDX,
            NUM_HASHER_COLUMNS, NUM_OP_BATCH_FLAGS, NUM_OP_BITS, OP_BATCH_FLAGS_OFFSET,
            OP_BITS_EXTRA_COLS_OFFSET, OP_BITS_OFFSET, OP_INDEX_COL_IDX,
        },
        stack::{B0_COL_IDX, B1_COL_IDX, H0_COL_IDX, STACK_TOP_OFFSET},
    },
};
use miden_core::{
    Kernel, ONE, Operation, Word, ZERO,
    field::PrimeCharacteristicRing,
    stack::MIN_STACK_DEPTH,
    utils::{ColMatrix, uninit_vector},
};
use rayon::prelude::*;
use tracing::instrument;

use crate::{
    ChipletsLengths, ContextId, ExecutionTrace, TraceLenSummary,
    chiplets::Chiplets,
    decoder::AuxTraceBuilder as DecoderAuxTraceBuilder,
    fast::{
        ExecutionOutput,
        execution_tracer::TraceGenerationContext,
        trace_state::{
            AceReplay, BitwiseOp, BitwiseReplay, CoreTraceFragmentContext, HasherOp,
            HasherRequestReplay, KernelReplay, MemoryWritesReplay,
        },
    },
    parallel::core_trace_fragment::{CoreTraceFragment, CoreTraceFragmentFiller},
    range::RangeChecker,
    stack::AuxTraceBuilder as StackAuxTraceBuilder,
    trace::AuxTraceBuilders,
    utils::invert_column_allow_zeros,
};

pub const CORE_TRACE_WIDTH: usize = SYS_TRACE_WIDTH + DECODER_TRACE_WIDTH + STACK_TRACE_WIDTH;

mod core_trace_fragment;

#[cfg(test)]
mod tests;

// BUILD TRACE
// ================================================================================================

/// Builds the main trace from the provided trace states in parallel.
#[instrument(name = "build_trace", skip_all)]
pub fn build_trace(
    execution_output: ExecutionOutput,
    trace_generation_context: TraceGenerationContext,
    program_hash: Word,
    kernel: Kernel,
) -> ExecutionTrace {
    let TraceGenerationContext {
        core_trace_contexts,
        range_checker_replay,
        memory_writes,
        bitwise_replay: bitwise,
        kernel_replay,
        hasher_for_chiplet,
        ace_replay,
        final_pc_transcript,
        fragment_size,
    } = trace_generation_context;

    let chiplets = initialize_chiplets(
        kernel.clone(),
        &core_trace_contexts,
        memory_writes,
        bitwise,
        kernel_replay,
        hasher_for_chiplet,
        ace_replay,
    );

    let range_checker = initialize_range_checker(range_checker_replay, &chiplets);

    let mut core_trace_columns = generate_core_trace_columns(core_trace_contexts, fragment_size);

    // Calculate trace length
    let core_trace_len = core_trace_columns[0].len();

    // Get the number of rows for the range checker
    let range_table_len = range_checker.get_number_range_checker_rows();

    let trace_len_summary =
        TraceLenSummary::new(core_trace_len, range_table_len, ChipletsLengths::new(&chiplets));

    // Compute the final main trace length
    let main_trace_len =
        compute_main_trace_length(core_trace_len, range_table_len, chiplets.trace_len());

    let ((), (range_checker_trace, chiplets_trace)) = rayon::join(
        || pad_trace_columns(&mut core_trace_columns, main_trace_len),
        || {
            rayon::join(
                || range_checker.into_trace_with_table(range_table_len, main_trace_len),
                || chiplets.into_trace(main_trace_len, final_pc_transcript.state()),
            )
        },
    );

    // Padding to make the number of columns a multiple of 8 i.e., the RPO permutation rate
    let padding_columns = vec![vec![ZERO; main_trace_len]; PADDED_TRACE_WIDTH - TRACE_WIDTH];

    // Chain all trace columns together
    let trace_columns: Vec<Vec<Felt>> = core_trace_columns
        .into_iter()
        .chain(range_checker_trace.trace)
        .chain(chiplets_trace.trace)
        .chain(padding_columns)
        .collect();

    // Create the MainTrace
    let main_trace = {
        let last_program_row = RowIndex::from((core_trace_len as u32).saturating_sub(1));
        let col_matrix = ColMatrix::new(trace_columns);
        MainTrace::new(col_matrix, last_program_row)
    };

    // Create aux trace builders
    let aux_trace_builders = AuxTraceBuilders {
        decoder: DecoderAuxTraceBuilder::default(),
        range: range_checker_trace.aux_builder,
        chiplets: chiplets_trace.aux_builder,
        stack: StackAuxTraceBuilder,
    };

    ExecutionTrace::new_from_parts(
        program_hash,
        kernel,
        execution_output,
        main_trace,
        aux_trace_builders,
        trace_len_summary,
    )
}

// HELPERS
// ================================================================================================

fn compute_main_trace_length(
    core_trace_len: usize,
    range_table_len: usize,
    chiplets_trace_len: usize,
) -> usize {
    // Get the trace length required to hold all execution trace steps
    let max_len = range_table_len.max(core_trace_len).max(chiplets_trace_len);

    // Pad the trace length to the next power of two
    let trace_len = max_len.next_power_of_two();
    core::cmp::max(trace_len, MIN_TRACE_LEN)
}

/// Generates core trace fragments in parallel from the provided trace fragment contexts.
fn generate_core_trace_columns(
    core_trace_contexts: Vec<CoreTraceFragmentContext>,
    fragment_size: usize,
) -> Vec<Vec<Felt>> {
    let mut core_trace_columns: Vec<Vec<Felt>> =
        unsafe { vec![uninit_vector(core_trace_contexts.len() * fragment_size); CORE_TRACE_WIDTH] };

    // Save the first stack top for initialization
    let first_stack_top = if let Some(first_context) = core_trace_contexts.first() {
        first_context.state.stack.stack_top.to_vec()
    } else {
        vec![ZERO; MIN_STACK_DEPTH]
    };

    let mut fragments = create_fragments_from_trace_columns(&mut core_trace_columns, fragment_size);

    // Build the core trace fragments in parallel
    let fragment_results: Vec<([Felt; STACK_TRACE_WIDTH], [Felt; SYS_TRACE_WIDTH], usize)> =
        core_trace_contexts
            .into_par_iter()
            .zip(fragments.par_iter_mut())
            .map(|(trace_state, fragment)| {
                let core_trace_fragment_filler =
                    CoreTraceFragmentFiller::new(trace_state, fragment);
                core_trace_fragment_filler.fill_fragment()
            })
            .collect();

    // Separate fragments, stack_rows, and system_rows
    let mut stack_rows = Vec::new();
    let mut system_rows = Vec::new();
    let mut total_core_trace_rows = 0;

    for (stack_row, system_row, num_rows_written) in fragment_results {
        stack_rows.push(stack_row);
        system_rows.push(system_row);
        total_core_trace_rows += num_rows_written;
    }

    // Fix up stack and system rows
    fixup_stack_and_system_rows(
        &mut core_trace_columns,
        fragment_size,
        &stack_rows,
        &system_rows,
        &first_stack_top,
    );

    // Run batch inversion on stack's H0 helper column, processing each fragment in parallel.
    // This must be done after fixup_stack_and_system_rows since that function overwrites the first
    // row of each fragment with non-inverted values.
    {
        let h0_column = &mut core_trace_columns[STACK_TRACE_OFFSET + H0_COL_IDX];
        h0_column.par_chunks_mut(fragment_size).for_each(invert_column_allow_zeros);
    }

    // Truncate the core trace columns. After this point, there is no more uninitialized memory.
    for col in core_trace_columns.iter_mut() {
        col.truncate(total_core_trace_rows);
    }

    push_halt_opcode_row(
        &mut core_trace_columns,
        system_rows.last().expect(
            "system_rows should not be empty, which indicates that there are no trace fragments",
        ),
        stack_rows.last().expect(
            "stack_rows should not be empty, which indicates that there are no trace fragments",
        ),
    );

    core_trace_columns
}

/// Splits the core trace columns into fragments of the specified size, returning a vector of
/// `CoreTraceFragment`s that each borrow from the original columns.
fn create_fragments_from_trace_columns(
    core_trace_columns: &mut [Vec<Felt>],
    fragment_size: usize,
) -> Vec<CoreTraceFragment<'_>> {
    let mut column_chunks: Vec<_> = core_trace_columns
        .iter_mut()
        .map(|col| col.chunks_exact_mut(fragment_size))
        .collect();
    let mut core_trace_fragments = Vec::new();

    loop {
        let fragment_cols: Vec<&mut [Felt]> =
            column_chunks.iter_mut().filter_map(|col_chunk| col_chunk.next()).collect();
        assert!(
            fragment_cols.is_empty() || fragment_cols.len() == CORE_TRACE_WIDTH,
            "column chunks don't all have the same size"
        );

        if fragment_cols.is_empty() {
            return core_trace_fragments;
        } else {
            core_trace_fragments.push(CoreTraceFragment {
                columns: fragment_cols.try_into().expect("fragment has CORE_TRACE_WIDTH columns"),
            });
        }
    }
}

/// Initializing the first row of each fragment with the appropriate stack and system state.
///
/// This needs to be done as a separate pass after all fragments have been generated, because the
/// system and stack rows write the state at clk `i` to the row at index `i+1`. Hence, the state of
/// the last row of any given fragment cannot be written in parallel, since any given fragment
/// filler doesn't have access to the next fragment's first row.
fn fixup_stack_and_system_rows(
    core_trace_columns: &mut [Vec<Felt>],
    fragment_size: usize,
    stack_rows: &[[Felt; STACK_TRACE_WIDTH]],
    system_rows: &[[Felt; SYS_TRACE_WIDTH]],
    first_stack_top: &[Felt],
) {
    const MIN_STACK_DEPTH_FELT: Felt = Felt::new(MIN_STACK_DEPTH as u64);

    let system_state_first_row = [
        ZERO, // clk starts at 0
        ZERO, // ctx starts at 0 (root context)
        ZERO, // fn_hash[0] starts as 0
        ZERO, // fn_hash[1] starts as 0
        ZERO, // fn_hash[2] starts as 0
        ZERO, // fn_hash[3] starts as 0
    ];

    // Initialize the first fragment with first_stack_top + [16, 0, 0] and first_system_state
    {
        // Set system state
        for (col_idx, &value) in system_state_first_row.iter().enumerate() {
            core_trace_columns[col_idx][0] = value;
        }

        // Set stack top (16 elements)
        // Note: we call `rev()` here because the stack order is reversed in the trace.
        // trace: [top, ..., bottom] vs stack: [bottom, ..., top]
        for (stack_col_idx, &value) in first_stack_top.iter().rev().enumerate() {
            core_trace_columns[STACK_TRACE_OFFSET + STACK_TOP_OFFSET + stack_col_idx][0] = value;
        }

        // Set stack helpers: [16, 0, 0]
        core_trace_columns[STACK_TRACE_OFFSET + B0_COL_IDX][0] = MIN_STACK_DEPTH_FELT;
        core_trace_columns[STACK_TRACE_OFFSET + B1_COL_IDX][0] = ZERO;
        core_trace_columns[STACK_TRACE_OFFSET + H0_COL_IDX][0] = ZERO;
    }

    // Determine the starting row indices for each fragment after the first.
    // We skip the first due to it already being initialized above.
    let fragment_start_row_indices = {
        let num_fragments = core_trace_columns[0].len() / fragment_size;

        (0..).step_by(fragment_size).take(num_fragments).skip(1)
    };

    // Initialize subsequent fragments with their corresponding rows from the previous fragment
    for (row_idx, (system_row, stack_row)) in
        fragment_start_row_indices.zip(system_rows.iter().zip(stack_rows.iter()))
    {
        // Copy the system_row to the first row of this fragment
        for (col_idx, &value) in system_row.iter().enumerate() {
            core_trace_columns[col_idx][row_idx] = value;
        }

        // Copy the stack_row to the first row of this fragment
        for (col_idx, &value) in stack_row.iter().enumerate() {
            core_trace_columns[STACK_TRACE_OFFSET + col_idx][row_idx] = value;
        }
    }
}

/// Appends a row with the HALT opcode to the end of the last fragment.
///
/// This ensures that the trace ends with at least one HALT operation, which is necessary to satisfy
/// the constraints.
fn push_halt_opcode_row(
    core_trace_columns: &mut [Vec<Felt>],
    last_system_state: &[Felt; SYS_TRACE_WIDTH],
    last_stack_state: &[Felt; STACK_TRACE_WIDTH],
) {
    // system columns
    // ---------------------------------------------------------------------------------------
    for (col_idx, &value) in last_system_state.iter().enumerate() {
        core_trace_columns[col_idx].push(value);
    }

    // stack columns
    // ---------------------------------------------------------------------------------------
    for (col_idx, &value) in last_stack_state.iter().enumerate() {
        core_trace_columns[STACK_TRACE_OFFSET + col_idx].push(value);
    }

    // decoder columns: padding with final decoder state
    // ---------------------------------------------------------------------------------------
    // Pad addr trace (decoder block address column) with ZEROs
    core_trace_columns[DECODER_TRACE_OFFSET + ADDR_COL_IDX].push(ZERO);

    // Pad op_bits columns with HALT opcode bits
    let halt_opcode = Operation::Halt.op_code();
    for bit_idx in 0..NUM_OP_BITS {
        let bit_value = Felt::from_u8((halt_opcode >> bit_idx) & 1);
        core_trace_columns[DECODER_TRACE_OFFSET + OP_BITS_OFFSET + bit_idx].push(bit_value);
    }

    // Pad hasher state columns (8 columns)
    // - First 4 columns: copy the last value (to propagate program hash)
    // - Remaining 4 columns: fill with ZEROs
    for hasher_col_idx in 0..NUM_HASHER_COLUMNS {
        let col_idx = DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + hasher_col_idx;
        if hasher_col_idx < 4 {
            // For first 4 hasher columns, copy the last value to propagate program hash
            let last_row_idx = core_trace_columns[col_idx].len() - 1;
            let last_hasher_value = core_trace_columns[col_idx][last_row_idx];
            core_trace_columns[col_idx].push(last_hasher_value);
        } else {
            // For remaining 4 hasher columns, fill with ZEROs
            core_trace_columns[col_idx].push(ZERO);
        }
    }

    // Pad in_span column with ZEROs
    core_trace_columns[DECODER_TRACE_OFFSET + IN_SPAN_COL_IDX].push(ZERO);

    // Pad group_count column with ZEROs
    core_trace_columns[DECODER_TRACE_OFFSET + GROUP_COUNT_COL_IDX].push(ZERO);

    // Pad op_idx column with ZEROs
    core_trace_columns[DECODER_TRACE_OFFSET + OP_INDEX_COL_IDX].push(ZERO);

    // Pad op_batch_flags columns (3 columns) with ZEROs
    for batch_flag_idx in 0..NUM_OP_BATCH_FLAGS {
        let col_idx = DECODER_TRACE_OFFSET + OP_BATCH_FLAGS_OFFSET + batch_flag_idx;
        core_trace_columns[col_idx].push(ZERO);
    }

    // Pad op_bit_extra columns (2 columns)
    // - First column: fill with ZEROs (HALT doesn't use this)
    // - Second column: fill with ONEs (product of two most significant HALT bits, both are 1)
    core_trace_columns[DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET].push(ZERO);
    core_trace_columns[DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET + 1].push(ONE);
}

fn initialize_range_checker(
    range_checker_replay: crate::fast::trace_state::RangeCheckerReplay,
    chiplets: &Chiplets,
) -> RangeChecker {
    let mut range_checker = RangeChecker::new();

    // Add all u32 range checks recorded during execution
    for (clk, values) in range_checker_replay.into_iter() {
        range_checker.add_range_checks(clk, &values);
    }

    // Add all memory-related range checks
    chiplets.append_range_checks(&mut range_checker);

    range_checker
}

fn initialize_chiplets(
    kernel: Kernel,
    core_trace_contexts: &[CoreTraceFragmentContext],
    memory_writes: MemoryWritesReplay,
    bitwise: BitwiseReplay,
    kernel_replay: KernelReplay,
    hasher_for_chiplet: HasherRequestReplay,
    ace_replay: AceReplay,
) -> Chiplets {
    let mut chiplets = Chiplets::new(kernel);

    // populate hasher chiplet
    for hasher_op in hasher_for_chiplet.into_iter() {
        match hasher_op {
            HasherOp::Permute(input_state) => {
                let _ = chiplets.hasher.permute(input_state);
            },
            HasherOp::HashControlBlock((h1, h2, domain, expected_hash)) => {
                let _ = chiplets.hasher.hash_control_block(h1, h2, domain, expected_hash);
            },
            HasherOp::HashBasicBlock((op_batches, expected_hash)) => {
                let _ = chiplets.hasher.hash_basic_block(&op_batches, expected_hash);
            },
            HasherOp::BuildMerkleRoot((value, path, index)) => {
                let _ = chiplets.hasher.build_merkle_root(value, &path, index);
            },
            HasherOp::UpdateMerkleRoot((old_value, new_value, path, index)) => {
                chiplets.hasher.update_merkle_root(old_value, new_value, &path, index);
            },
        }
    }

    // populate bitwise chiplet
    for (bitwise_op, a, b) in bitwise {
        match bitwise_op {
            BitwiseOp::U32And => {
                let _ = chiplets
                    .bitwise
                    .u32and(a, b)
                    .expect("bitwise AND operation failed when populating chiplet");
            },
            BitwiseOp::U32Xor => {
                let _ = chiplets
                    .bitwise
                    .u32xor(a, b)
                    .expect("bitwise XOR operation failed when populating chiplet");
            },
        }
    }

    // populate memory chiplet
    //
    // Note: care is taken to order all the accesses by clock cycle, since the memory chiplet
    // currently assumes that all memory accesses are issued in the same order as they appear in
    // the trace.
    {
        let elements_written: Box<dyn Iterator<Item = MemoryAccess>> =
            Box::new(memory_writes.iter_elements_written().map(|(element, addr, ctx, clk)| {
                MemoryAccess::WriteElement(*addr, *element, *ctx, *clk)
            }));
        let words_written: Box<dyn Iterator<Item = MemoryAccess>> = Box::new(
            memory_writes
                .iter_words_written()
                .map(|(word, addr, ctx, clk)| MemoryAccess::WriteWord(*addr, *word, *ctx, *clk)),
        );
        let elements_read: Box<dyn Iterator<Item = MemoryAccess>> =
            Box::new(core_trace_contexts.iter().flat_map(|ctx| {
                ctx.replay
                    .memory_reads
                    .iter_read_elements()
                    .map(|(_, addr, ctx, clk)| MemoryAccess::ReadElement(addr, ctx, clk))
            }));
        let words_read: Box<dyn Iterator<Item = MemoryAccess>> =
            Box::new(core_trace_contexts.iter().flat_map(|ctx| {
                ctx.replay
                    .memory_reads
                    .iter_read_words()
                    .map(|(_, addr, ctx, clk)| MemoryAccess::ReadWord(addr, ctx, clk))
            }));

        [elements_written, words_written, elements_read, words_read]
            .into_iter()
            .kmerge_by(|a, b| a.clk() < b.clk())
            .for_each(|mem_access| match mem_access {
                MemoryAccess::ReadElement(addr, ctx, clk) => {
                    let _ = chiplets
                        .memory
                        .read(ctx, addr, clk)
                        .expect("memory read element failed when populating chiplet");
                },
                MemoryAccess::WriteElement(addr, element, ctx, clk) => {
                    chiplets
                        .memory
                        .write(ctx, addr, clk, element)
                        .expect("memory write element failed when populating chiplet");
                },
                MemoryAccess::ReadWord(addr, ctx, clk) => {
                    chiplets
                        .memory
                        .read_word(ctx, addr, clk)
                        .expect("memory read word failed when populating chiplet");
                },
                MemoryAccess::WriteWord(addr, word, ctx, clk) => {
                    chiplets
                        .memory
                        .write_word(ctx, addr, clk, word)
                        .expect("memory write word failed when populating chiplet");
                },
            });

        enum MemoryAccess {
            ReadElement(Felt, ContextId, RowIndex),
            WriteElement(Felt, Felt, ContextId, RowIndex),
            ReadWord(Felt, ContextId, RowIndex),
            WriteWord(Felt, Word, ContextId, RowIndex),
        }

        impl MemoryAccess {
            fn clk(&self) -> RowIndex {
                match self {
                    MemoryAccess::ReadElement(_, _, clk) => *clk,
                    MemoryAccess::WriteElement(_, _, _, clk) => *clk,
                    MemoryAccess::ReadWord(_, _, clk) => *clk,
                    MemoryAccess::WriteWord(_, _, _, clk) => *clk,
                }
            }
        }
    }

    // populate ACE chiplet
    for (clk, circuit_eval) in ace_replay.into_iter() {
        chiplets.ace.add_circuit_evaluation(clk, circuit_eval);
    }

    // populate kernel ROM
    for proc_hash in kernel_replay.into_iter() {
        chiplets
            .kernel_rom
            .access_proc(proc_hash)
            .expect("kernel proc access failed when populating chiplet");
    }

    chiplets
}

fn pad_trace_columns(trace_columns: &mut [Vec<Felt>], main_trace_len: usize) {
    let total_program_rows = trace_columns[0].len();
    assert!(total_program_rows <= main_trace_len);

    let num_padding_rows = main_trace_len - total_program_rows;

    // System columns
    // ------------------------

    // Pad CLK trace - fill with index values
    for padding_row_idx in 0..num_padding_rows {
        trace_columns[CLK_COL_IDX]
            .push(Felt::from_u32((total_program_rows + padding_row_idx) as u32));
    }

    // Pad CTX trace - fill with ZEROs (root context)
    trace_columns[CTX_COL_IDX].resize(main_trace_len, ZERO);

    // Pad FN_HASH traces (4 columns) - fill with ZEROs as program execution must always end in the
    // root context.
    for fn_hash_col_idx in FN_HASH_RANGE {
        trace_columns[fn_hash_col_idx].resize(main_trace_len, ZERO);
    }

    // Decoder columns
    // ------------------------

    // Pad addr trace (decoder block address column) with ZEROs
    trace_columns[DECODER_TRACE_OFFSET + ADDR_COL_IDX].resize(main_trace_len, ZERO);

    // Pad op_bits columns with HALT opcode bits
    let halt_opcode = Operation::Halt.op_code();
    for i in 0..NUM_OP_BITS {
        let bit_value = Felt::from_u8((halt_opcode >> i) & 1);
        trace_columns[DECODER_TRACE_OFFSET + OP_BITS_OFFSET + i].resize(main_trace_len, bit_value);
    }

    // Pad hasher state columns (8 columns)
    // - First 4 columns: copy the last value (to propagate program hash)
    // - Remaining 4 columns: fill with ZEROs
    for i in 0..NUM_HASHER_COLUMNS {
        let col_idx = DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + i;
        if i < 4 {
            // For first 4 hasher columns, copy the last value to propagate program hash
            // Safety: per our documented safety guarantees, we know that `total_program_rows > 0`,
            // and row `total_program_rows - 1` is initialized.
            let last_hasher_value = trace_columns[col_idx][total_program_rows - 1];
            trace_columns[col_idx].resize(main_trace_len, last_hasher_value);
        } else {
            // For remaining 4 hasher columns, fill with ZEROs
            trace_columns[col_idx].resize(main_trace_len, ZERO);
        }
    }

    // Pad in_span column with ZEROs
    trace_columns[DECODER_TRACE_OFFSET + IN_SPAN_COL_IDX].resize(main_trace_len, ZERO);

    // Pad group_count column with ZEROs
    trace_columns[DECODER_TRACE_OFFSET + GROUP_COUNT_COL_IDX].resize(main_trace_len, ZERO);

    // Pad op_idx column with ZEROs
    trace_columns[DECODER_TRACE_OFFSET + OP_INDEX_COL_IDX].resize(main_trace_len, ZERO);

    // Pad op_batch_flags columns (3 columns) with ZEROs
    for i in 0..NUM_OP_BATCH_FLAGS {
        trace_columns[DECODER_TRACE_OFFSET + OP_BATCH_FLAGS_OFFSET + i]
            .resize(main_trace_len, ZERO);
    }

    // Pad op_bit_extra columns (2 columns)
    // - First column: fill with ZEROs (HALT doesn't use this)
    // - Second column: fill with ONEs (product of two most significant HALT bits, both are 1)
    trace_columns[DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET].resize(main_trace_len, ZERO);
    trace_columns[DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET + 1].resize(main_trace_len, ONE);

    // Stack columns
    // ------------------------

    // Pad stack columns with the last value in each column (analogous to Stack::into_trace())
    for i in 0..STACK_TRACE_WIDTH {
        let col_idx = STACK_TRACE_OFFSET + i;
        // Safety: per our documented safety guarantees, we know that `total_program_rows > 0`,
        // and row `total_program_rows - 1` is initialized.
        let last_stack_value = trace_columns[col_idx][total_program_rows - 1];
        trace_columns[col_idx].resize(main_trace_len, last_stack_value);
    }
}
