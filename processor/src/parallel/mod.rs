use alloc::{boxed::Box, vec::Vec};
use core::ops::ControlFlow;

use itertools::Itertools;
use miden_air::{
    FieldElement, RowIndex,
    trace::{
        CLK_COL_IDX, CTX_COL_IDX, DECODER_TRACE_OFFSET, DECODER_TRACE_WIDTH, FN_HASH_RANGE,
        MIN_TRACE_LEN, PADDED_TRACE_WIDTH, STACK_TRACE_OFFSET, STACK_TRACE_WIDTH, SYS_TRACE_WIDTH,
        TRACE_WIDTH,
        decoder::{
            ADDR_COL_IDX, GROUP_COUNT_COL_IDX, HASHER_STATE_OFFSET, IN_SPAN_COL_IDX,
            NUM_HASHER_COLUMNS, NUM_OP_BATCH_FLAGS, NUM_OP_BITS, NUM_USER_OP_HELPERS,
            OP_BATCH_FLAGS_OFFSET, OP_BITS_EXTRA_COLS_OFFSET, OP_BITS_OFFSET, OP_INDEX_COL_IDX,
        },
        main_trace::MainTrace,
        stack::{B0_COL_IDX, B1_COL_IDX, H0_COL_IDX, STACK_TOP_OFFSET},
    },
};
use miden_core::{
    Felt, Kernel, ONE, OPCODE_PUSH, Operation, QuadFelt, StarkField, WORD_SIZE, Word, ZERO,
    mast::{BasicBlockNode, MastForest, MastNode, MastNodeExt, MastNodeId, OpBatch},
    precompile::PrecompileTranscriptState,
    stack::MIN_STACK_DEPTH,
    utils::{range, uninit_vector},
};
use rayon::prelude::*;
use winter_prover::{crypto::RandomCoin, math::batch_inversion};

use crate::{
    ChipletsLengths, ColMatrix, ContextId, ErrorContext, ExecutionError, ExecutionTrace,
    ProcessState, TraceLenSummary,
    chiplets::{Chiplets, CircuitEvaluation},
    continuation_stack::Continuation,
    crypto::RpoRandomCoin,
    decoder::{
        AuxTraceBuilder as DecoderAuxTraceBuilder, BasicBlockContext,
        block_stack::ExecutionContextInfo,
    },
    fast::{
        ExecutionOutput, NoopTracer, Tracer, eval_circuit_fast_,
        execution_tracer::TraceGenerationContext,
        trace_state::{
            AceReplay, AdviceReplay, BitwiseOp, BitwiseReplay, CoreTraceFragmentContext,
            DecoderState, ExecutionContextSystemInfo, HasherOp, HasherRequestReplay,
            HasherResponseReplay, KernelReplay, MemoryReadsReplay, MemoryWritesReplay,
            NodeExecutionState, NodeFlags,
        },
    },
    host::default::NoopHost,
    processor::{OperationHelperRegisters, Processor, StackInterface, SystemInterface},
    range::RangeChecker,
    stack::AuxTraceBuilder as StackAuxTraceBuilder,
    trace::{AuxTraceBuilders, NUM_RAND_ROWS},
    utils::split_u32_into_u16,
};

pub const CORE_TRACE_WIDTH: usize = SYS_TRACE_WIDTH + DECODER_TRACE_WIDTH + STACK_TRACE_WIDTH;

mod basic_block;
mod call;
mod r#dyn;
mod join;
mod r#loop;

mod split;
mod trace_builder;

#[cfg(test)]
mod tests;

// BUILD TRACE
// ================================================================================================

/// Builds the main trace from the provided trace states in parallel.
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
    let core_trace_len = {
        let core_trace_len: usize = core_trace_columns[0].len();

        // TODO(plafer): We need to do a "- 1" here to be consistent with Process::execute(), which
        // has a bug that causes it to not always insert a HALT row at the end of execution,
        // documented in [#1383](https://github.com/0xMiden/miden-vm/issues/1383). We correctly insert a HALT row
        // when generating the core trace fragments, so this "- 1" accounts for that extra row.
        // We should remove this "- 1" once Process::execute() is fixed or removed entirely.
        core_trace_len - 1
    };

    // Get the number of rows for the range checker
    let range_table_len = range_checker.get_number_range_checker_rows();

    let trace_len_summary =
        TraceLenSummary::new(core_trace_len, range_table_len, ChipletsLengths::new(&chiplets));

    // Compute the final main trace length, after accounting for random rows
    let main_trace_len =
        compute_main_trace_length(core_trace_len, range_table_len, chiplets.trace_len());

    let ((), (range_checker_trace, chiplets_trace)) = rayon::join(
        || pad_trace_columns(&mut core_trace_columns, main_trace_len),
        || {
            rayon::join(
                || {
                    range_checker.into_trace_with_table(
                        range_table_len,
                        main_trace_len,
                        NUM_RAND_ROWS,
                    )
                },
                || chiplets.into_trace(main_trace_len, NUM_RAND_ROWS, final_pc_transcript.state()),
            )
        },
    );

    // Padding to make the number of columns a multiple of 8 i.e., the RPO permutation rate
    let padding_columns = vec![vec![ZERO; main_trace_len]; PADDED_TRACE_WIDTH - TRACE_WIDTH];

    // Chain all trace columns together
    let mut trace_columns: Vec<Vec<Felt>> = core_trace_columns
        .into_iter()
        .chain(range_checker_trace.trace)
        .chain(chiplets_trace.trace)
        .chain(padding_columns)
        .collect();

    // Initialize random element generator using program hash
    let mut rng = RpoRandomCoin::new(program_hash);

    // Inject random values into the last NUM_RAND_ROWS rows for all columns
    for i in main_trace_len - NUM_RAND_ROWS..main_trace_len {
        for column in trace_columns.iter_mut() {
            column[i] = rng.draw().expect("failed to draw a random value");
        }
    }

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

fn compute_main_trace_length(
    core_trace_len: usize,
    range_table_len: usize,
    chiplets_trace_len: usize,
) -> usize {
    // Get the trace length required to hold all execution trace steps
    let max_len = range_table_len.max(core_trace_len).max(chiplets_trace_len);

    // Pad the trace length to the next power of two and ensure that there is space for random
    // rows
    let trace_len = (max_len + NUM_RAND_ROWS).next_power_of_two();
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

    // Run batch inversion on stack's H0 helper column
    core_trace_columns[STACK_TRACE_OFFSET + H0_COL_IDX] =
        batch_inversion(&core_trace_columns[STACK_TRACE_OFFSET + H0_COL_IDX]);

    core_trace_columns
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
        let bit_value = Felt::from((halt_opcode >> bit_idx) & 1);
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
                chiplets.hasher.permute(input_state);
            },
            HasherOp::HashControlBlock((h1, h2, domain, expected_hash)) => {
                chiplets.hasher.hash_control_block(h1, h2, domain, expected_hash);
            },
            HasherOp::HashBasicBlock((op_batches, expected_hash)) => {
                chiplets.hasher.hash_basic_block(&op_batches, expected_hash);
            },
            HasherOp::BuildMerkleRoot((value, path, index)) => {
                chiplets.hasher.build_merkle_root(value, &path, index);
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
                chiplets
                    .bitwise
                    .u32and(a, b, &())
                    .expect("bitwise AND operation failed when populating chiplet");
            },
            BitwiseOp::U32Xor => {
                chiplets
                    .bitwise
                    .u32xor(a, b, &())
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
                    chiplets
                        .memory
                        .read(ctx, addr, clk, &())
                        .expect("memory read element failed when populating chiplet");
                },
                MemoryAccess::WriteElement(addr, element, ctx, clk) => {
                    chiplets
                        .memory
                        .write(ctx, addr, clk, element, &())
                        .expect("memory write element failed when populating chiplet");
                },
                MemoryAccess::ReadWord(addr, ctx, clk) => {
                    chiplets
                        .memory
                        .read_word(ctx, addr, clk, &())
                        .expect("memory read word failed when populating chiplet");
                },
                MemoryAccess::WriteWord(addr, word, ctx, clk) => {
                    chiplets
                        .memory
                        .write_word(ctx, addr, clk, word, &())
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
            .access_proc(proc_hash, &())
            .expect("kernel proc access failed when populating chiplet");
    }

    chiplets
}

fn pad_trace_columns(trace_columns: &mut [Vec<Felt>], main_trace_len: usize) {
    // TODO(plafer): parallelize this function
    let total_program_rows = trace_columns[0].len();
    assert!(total_program_rows + NUM_RAND_ROWS - 1 <= main_trace_len);

    let num_padding_rows = main_trace_len - total_program_rows;

    // System columns
    // ------------------------

    // Pad CLK trace - fill with index values
    for padding_row_idx in 0..num_padding_rows {
        trace_columns[CLK_COL_IDX].push(Felt::from((total_program_rows + padding_row_idx) as u32));
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
        let bit_value = Felt::from((halt_opcode >> i) & 1);
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

// CORE TRACE FRAGMENT
// ================================================================================================

/// The columns of the main trace fragment. These consist of the system, decoder, and stack columns.
///
/// A fragment is a collection of columns of length `fragment_size` or less. Only a
/// fragment containing a `HALT` operation is allowed to be shorter than
/// `fragment_size`.
struct CoreTraceFragment<'a> {
    pub columns: [&'a mut [Felt]; CORE_TRACE_WIDTH],
}

// CORE TRACE FRAGMENT FILLER
// ================================================================================================

/// Fills a core trace fragment based on the provided context.
struct CoreTraceFragmentFiller<'a> {
    fragment_start_clk: RowIndex,
    fragment: &'a mut CoreTraceFragment<'a>,
    context: CoreTraceFragmentContext,
    span_context: Option<BasicBlockContext>,
    stack_rows: Option<[Felt; STACK_TRACE_WIDTH]>,
    system_rows: Option<[Felt; SYS_TRACE_WIDTH]>,
}

impl<'a> CoreTraceFragmentFiller<'a> {
    /// Creates a new CoreTraceFragmentFiller with the provided context and uninitialized fragment.
    pub fn new(
        context: CoreTraceFragmentContext,
        uninit_fragment: &'a mut CoreTraceFragment<'a>,
    ) -> Self {
        Self {
            fragment_start_clk: context.state.system.clk,
            fragment: uninit_fragment,
            context,
            span_context: None,
            stack_rows: None,
            system_rows: None,
        }
    }

    /// Fills the fragment and returns the final stack rows, system rows, and number of rows built.
    pub fn fill_fragment(mut self) -> ([Felt; STACK_TRACE_WIDTH], [Felt; SYS_TRACE_WIDTH], usize) {
        let execution_state = self.context.initial_execution_state.clone();
        // Execute fragment generation and always finalize at the end
        let _ = self.execute_fragment_generation(execution_state);
        let final_stack_rows = self.stack_rows.unwrap_or([ZERO; STACK_TRACE_WIDTH]);
        let final_system_rows = self.system_rows.unwrap_or([ZERO; SYS_TRACE_WIDTH]);
        let num_rows_built = self.num_rows_built();
        (final_stack_rows, final_system_rows, num_rows_built)
    }

    /// Internal method that performs fragment generation with automatic early returns
    fn execute_fragment_generation(
        &mut self,
        execution_state: NodeExecutionState,
    ) -> ControlFlow<()> {
        let initial_mast_forest = self.context.initial_mast_forest.clone();

        // Finish the current node given its execution state
        match execution_state {
            NodeExecutionState::BasicBlock { node_id, batch_index, op_idx_in_batch } => {
                let basic_block_node = {
                    let mast_node =
                        initial_mast_forest.get_node_by_id(node_id).expect("node should exist");
                    mast_node.get_basic_block().expect("Expected a basic block node")
                };

                let op_batches = basic_block_node.op_batches();
                assert!(
                    batch_index < op_batches.len(),
                    "Batch index out of bounds: {batch_index} >= {}",
                    op_batches.len()
                );

                // Initialize the span context for the current basic block
                self.span_context =
                    Some(initialize_span_context(basic_block_node, batch_index, op_idx_in_batch));

                // Execute remaining operations in the specified batch
                {
                    let current_batch = &op_batches[batch_index];
                    self.execute_op_batch(
                        current_batch,
                        Some(op_idx_in_batch),
                        &initial_mast_forest,
                    )?;
                }

                // Execute remaining batches
                for op_batch in op_batches.iter().skip(batch_index + 1) {
                    self.respan(op_batch)?;

                    self.execute_op_batch(op_batch, None, &initial_mast_forest)?;
                }

                // Add END trace row to complete the basic block
                self.add_span_end_trace_row(basic_block_node)?;
            },
            NodeExecutionState::Start(node_id) => {
                self.execute_mast_node(node_id, &initial_mast_forest)?;
            },
            NodeExecutionState::Respan { node_id, batch_index } => {
                let basic_block_node = {
                    let mast_node =
                        initial_mast_forest.get_node_by_id(node_id).expect("node should exist");
                    mast_node.get_basic_block().expect("Expected a basic block node")
                };
                let current_batch = &basic_block_node.op_batches()[batch_index];

                self.span_context = {
                    let current_op_group = current_batch.groups()[0];
                    let num_groups_left: usize = basic_block_node
                        .op_batches()
                        .iter()
                        .skip(batch_index)
                        .map(|batch| batch.num_groups())
                        .sum();

                    Some(BasicBlockContext {
                        group_ops_left: current_op_group,
                        num_groups_left: Felt::new(num_groups_left as u64),
                    })
                };

                // Execute remaining batches
                for op_batch in basic_block_node.op_batches().iter().skip(batch_index) {
                    self.respan(op_batch)?;

                    self.execute_op_batch(op_batch, None, &initial_mast_forest)?;
                }

                // Add END trace row to complete the basic block
                self.add_span_end_trace_row(basic_block_node)?;
            },
            NodeExecutionState::LoopRepeat(node_id) => {
                finish_loop_node(self, node_id, &initial_mast_forest, None)?;
            },
            // TODO(plafer): there's a big overlap between `NodeExecutionPhase::End` and
            // `Continuation::Finish*`. We can probably reconcile.
            NodeExecutionState::End(node_id) => {
                let mast_node =
                    initial_mast_forest.get_node_by_id(node_id).expect("node should exist");

                match mast_node {
                    MastNode::Join(join_node) => {
                        self.add_end_trace_row(join_node.digest())?;
                    },
                    MastNode::Split(split_node) => {
                        self.add_end_trace_row(split_node.digest())?;
                    },
                    MastNode::Loop(loop_node) => {
                        let (ended_node_addr, flags) = self.update_decoder_state_on_node_end();

                        // If the loop was entered, we need to shift the stack to the left
                        if flags.loop_entered() == ONE {
                            self.decrement_size(&mut NoopTracer);
                        }

                        self.add_end_trace_row_impl(loop_node.digest(), flags, ended_node_addr)?;
                    },
                    MastNode::Call(call_node) => {
                        let ctx_info = self.context.replay.block_stack.replay_execution_context();
                        self.restore_context_from_replay(&ctx_info);
                        self.add_end_trace_row(call_node.digest())?;
                    },
                    MastNode::Dyn(dyn_node) => {
                        if dyn_node.is_dyncall() {
                            let ctx_info =
                                self.context.replay.block_stack.replay_execution_context();
                            self.restore_context_from_replay(&ctx_info);
                        }
                        self.add_end_trace_row(dyn_node.digest())?;
                    },
                    MastNode::Block(basic_block_node) => {
                        self.add_span_end_trace_row(basic_block_node)?;
                    },
                    MastNode::External(_external_node) => {
                        // External nodes don't generate trace rows directly, and hence will never
                        // show up in the END execution state.
                        panic!("Unexpected external node in END execution state")
                    },
                }
            },
        }

        // Start of main execution loop.
        let mut current_forest = self.context.initial_mast_forest.clone();

        while let Some(continuation) = self.context.continuation.pop_continuation() {
            match continuation {
                Continuation::StartNode(node_id) => {
                    self.execute_mast_node(node_id, &current_forest)?;
                },
                Continuation::FinishJoin(node_id) => {
                    let mast_node =
                        current_forest.get_node_by_id(node_id).expect("node should exist");
                    self.add_end_trace_row(mast_node.digest())?;
                },
                Continuation::FinishSplit(node_id) => {
                    let mast_node =
                        current_forest.get_node_by_id(node_id).expect("node should exist");
                    self.add_end_trace_row(mast_node.digest())?;
                },
                Continuation::FinishLoop(node_id) => {
                    finish_loop_node(self, node_id, &current_forest, None)?;
                },
                Continuation::FinishCall(node_id) => {
                    let mast_node =
                        current_forest.get_node_by_id(node_id).expect("node should exist");

                    // Restore context
                    let ctx_info = self.context.replay.block_stack.replay_execution_context();
                    self.restore_context_from_replay(&ctx_info);

                    // write END row to trace
                    self.add_end_trace_row(mast_node.digest())?;
                },
                Continuation::FinishDyn(node_id) => {
                    let dyn_node = current_forest
                        .get_node_by_id(node_id)
                        .expect("node should exist")
                        .unwrap_dyn();
                    if dyn_node.is_dyncall() {
                        let ctx_info = self.context.replay.block_stack.replay_execution_context();
                        self.restore_context_from_replay(&ctx_info);
                    }

                    self.add_end_trace_row(dyn_node.digest())?;
                },
                Continuation::FinishExternal(_node_id) => {
                    // Execute after_exit decorators when returning from an external node
                    // Note: current_forest should already be restored by EnterForest continuation
                    // External nodes don't generate END trace rows in the parallel processor
                    // as they only execute after_exit decorators
                },
                Continuation::EnterForest(previous_forest) => {
                    // Restore the previous forest
                    current_forest = previous_forest;
                },
            }
        }

        // All nodes completed without filling the fragment
        ControlFlow::Continue(())
    }

    fn execute_mast_node(
        &mut self,
        node_id: MastNodeId,
        current_forest: &MastForest,
    ) -> ControlFlow<()> {
        let mast_node = current_forest.get_node_by_id(node_id).expect("node should exist");

        match mast_node {
            MastNode::Block(basic_block_node) => {
                self.update_decoder_state_on_node_start();

                let num_groups_left_in_block = Felt::from(basic_block_node.num_op_groups() as u32);
                let first_op_batch = basic_block_node
                    .op_batches()
                    .first()
                    .expect("Basic block should have at least one op batch");

                // 1. Add SPAN start trace row
                self.add_span_start_trace_row(first_op_batch, num_groups_left_in_block)?;

                // Initialize the span context for the current basic block. After SPAN operation is
                // executed, we decrement the number of remaining groups by 1 because executing
                // SPAN consumes the first group of the batch.
                // TODO(plafer): use `initialize_span_context` once the potential off-by-one issue
                // is resolved.
                self.span_context = Some(BasicBlockContext {
                    group_ops_left: first_op_batch.groups()[0],
                    num_groups_left: num_groups_left_in_block - ONE,
                });

                // 2. Execute batches one by one
                let op_batches = basic_block_node.op_batches();

                // Execute first op batch
                {
                    let first_op_batch =
                        op_batches.first().expect("Basic block should have at least one op batch");
                    self.execute_op_batch(first_op_batch, None, current_forest)?;
                }

                // Execute the rest of the op batches
                for op_batch in op_batches.iter().skip(1) {
                    // 3. Add RESPAN trace row between batches
                    self.respan(op_batch)?;

                    self.execute_op_batch(op_batch, None, current_forest)?;
                }

                // 4. Add END trace row
                self.add_span_end_trace_row(basic_block_node)?;

                ControlFlow::Continue(())
            },
            MastNode::Join(join_node) => {
                self.update_decoder_state_on_node_start();

                // 1. Add "start JOIN" row
                self.add_join_start_trace_row(join_node, current_forest)?;

                // 2. Execute first child
                self.execute_mast_node(join_node.first(), current_forest)?;

                // 3. Execute second child
                self.execute_mast_node(join_node.second(), current_forest)?;

                // 4. Add "end JOIN" row
                self.add_end_trace_row(join_node.digest())
            },
            MastNode::Split(split_node) => {
                self.update_decoder_state_on_node_start();

                let condition = self.get(0);
                self.decrement_size(&mut NoopTracer);

                // 1. Add "start SPLIT" row
                self.add_split_start_trace_row(split_node, current_forest)?;

                // 2. Execute the appropriate branch based on the stack top value
                if condition == ONE {
                    self.execute_mast_node(split_node.on_true(), current_forest)?;
                } else {
                    self.execute_mast_node(split_node.on_false(), current_forest)?;
                }

                // 3. Add "end SPLIT" row
                self.add_end_trace_row(split_node.digest())
            },
            MastNode::Loop(loop_node) => {
                self.update_decoder_state_on_node_start();

                // Read condition from the stack and decrement stack size. This happens as part of
                // the LOOP operation, and so is done before writing that trace row.
                let mut condition = self.get(0);
                self.decrement_size(&mut NoopTracer);

                // 1. Add "start LOOP" row
                self.add_loop_start_trace_row(loop_node, current_forest)?;

                // 2. Loop while condition is true
                //
                // The first iteration is special because it doesn't insert a REPEAT trace row
                // before executing the loop body. Therefore it is done separately.
                if condition == ONE {
                    self.execute_mast_node(loop_node.body(), current_forest)?;

                    condition = self.get(0);
                    self.decrement_size(&mut NoopTracer);
                }

                finish_loop_node(self, node_id, current_forest, Some(condition))
            },
            MastNode::Call(call_node) => {
                self.update_decoder_state_on_node_start();

                self.context.state.stack.start_context();

                // Set up new context for the call
                if call_node.is_syscall() {
                    self.context.state.system.ctx = ContextId::root(); // Root context for syscalls
                } else {
                    self.context.state.system.ctx =
                        ContextId::from(self.context.state.system.clk + 1); // New context ID
                    self.context.state.system.fn_hash = current_forest[call_node.callee()].digest();
                }

                // Add "start CALL/SYSCALL" row
                self.add_call_start_trace_row(call_node, current_forest)?;

                // Execute the callee
                self.execute_mast_node(call_node.callee(), current_forest)?;

                // Restore context state
                let ctx_info = self.context.replay.block_stack.replay_execution_context();
                self.restore_context_from_replay(&ctx_info);

                // 2. Add "end CALL/SYSCALL" row
                self.add_end_trace_row(call_node.digest())
            },
            MastNode::Dyn(dyn_node) => {
                self.update_decoder_state_on_node_start();

                let callee_hash = {
                    let mem_addr = self.context.state.stack.get(0);
                    self.context.replay.memory_reads.replay_read_word(mem_addr)
                };

                // 1. Add "start DYN/DYNCALL" row
                if dyn_node.is_dyncall() {
                    let (stack_depth, next_overflow_addr) =
                        self.shift_stack_left_and_start_context();
                    // For DYNCALL, we need to save the current context state
                    // and prepare for dynamic execution
                    let ctx_info = ExecutionContextInfo::new(
                        self.context.state.system.ctx,
                        self.context.state.system.fn_hash,
                        stack_depth as u32,
                        next_overflow_addr,
                    );

                    self.context.state.system.ctx =
                        ContextId::from(self.context.state.system.clk + 1); // New context ID
                    self.context.state.system.fn_hash = callee_hash;

                    self.add_dyncall_start_trace_row(callee_hash, ctx_info)?;
                } else {
                    // Pop the memory address off the stack, and write the DYN trace row
                    self.decrement_size(&mut NoopTracer);
                    self.add_dyn_start_trace_row(callee_hash)?;
                };

                // 2. Execute the callee
                match current_forest.find_procedure_root(callee_hash) {
                    Some(callee_id) => self.execute_mast_node(callee_id, current_forest)?,
                    None => {
                        let (resolved_node_id, resolved_forest) =
                            self.context.replay.mast_forest_resolution.replay_resolution();

                        self.execute_mast_node(resolved_node_id, &resolved_forest)?
                    },
                };

                // Restore context state for DYNCALL
                if dyn_node.is_dyncall() {
                    let ctx_info = self.context.replay.block_stack.replay_execution_context();
                    self.restore_context_from_replay(&ctx_info);
                }

                // 3. Add "end DYN/DYNCALL" row
                self.add_end_trace_row(dyn_node.digest())
            },
            MastNode::External(_) => {
                let (resolved_node_id, resolved_forest) =
                    self.context.replay.mast_forest_resolution.replay_resolution();

                self.execute_mast_node(resolved_node_id, &resolved_forest)
            },
        }
    }

    // TODO(plafer): clean this up; it's probably not clear from the `TraceFragmentContext` that
    // this is the relationship between the replays and the `DecoderState` (only made clear when
    // looking at this function)
    /// This function is called when start executing a node (e.g. `JOIN`, `SPLIT`, etc). It emulates
    /// pushing a new node onto the block stack, and updates the decoder state to point to the
    /// current node in the block stack (which could be renamed to "node stack"). Hence, the
    /// `current_addr` is set to the (replayed) address of the current node, and the `parent_addr`
    /// is set to the (replayed) address of the parent node (i.e. the node previously on top of the
    /// block stack).
    fn update_decoder_state_on_node_start(&mut self) {
        let DecoderState { current_addr, parent_addr } = &mut self.context.state.decoder;

        *current_addr = self.context.replay.hasher.replay_block_address();
        *parent_addr = self.context.replay.block_stack.replay_node_start();
    }

    /// This function is called when we hit an `END` operation, signaling the end of execution for a
    /// node. It updates the decoder state to point to the previous node in the block stack (which
    /// could be renamed to "node stack"), and returns the address of the node that just ended,
    /// along with any flags associated with it.
    fn update_decoder_state_on_node_end(&mut self) -> (Felt, NodeFlags) {
        let DecoderState { current_addr, parent_addr } = &mut self.context.state.decoder;

        let node_end_data = self.context.replay.block_stack.replay_node_end();

        *current_addr = node_end_data.prev_addr;
        *parent_addr = node_end_data.prev_parent_addr;

        (node_end_data.ended_node_addr, node_end_data.flags)
    }

    /// Restores the execution context to the state it was in before the last `call`, `syscall` or
    /// `dyncall`.
    ///
    /// This includes restoring the overflow stack and the system parameters.
    fn restore_context_from_replay(&mut self, ctx_info: &ExecutionContextSystemInfo) {
        self.context.state.system.ctx = ctx_info.parent_ctx;
        self.context.state.system.fn_hash = ctx_info.parent_fn_hash;

        self.context
            .state
            .stack
            .restore_context(&mut self.context.replay.stack_overflow);
    }

    /// Executes operations within an operation batch, analogous to FastProcessor::execute_op_batch.
    ///
    /// If `start_op_idx` is provided, execution begins from that operation index within the batch.
    fn execute_op_batch(
        &mut self,
        batch: &OpBatch,
        start_op_idx: Option<usize>,
        current_forest: &MastForest,
    ) -> ControlFlow<()> {
        let start_op_idx = start_op_idx.unwrap_or(0);
        let end_indices = batch.end_indices();

        // Execute operations in the batch starting from the correct static operation index
        for (op_idx_in_batch, (op_group_idx, op_idx_in_group, op)) in
            batch.iter_with_groups().enumerate().skip(start_op_idx)
        {
            {
                // `execute_sync_op` does not support executing `Emit`, so we only call it for all
                // other operations.
                let user_op_helpers = if let Operation::Emit = op {
                    None
                } else {
                    // Note that the `op_idx_in_block` is only used in case of error, so we set it
                    // to 0.
                    // TODO(plafer): remove op_idx_in_block from u32_sub's error?
                    self.execute_sync_op(
                        op,
                        0,
                        current_forest,
                        &mut NoopHost,
                        &(),
                        &mut NoopTracer,
                    )
                    // The assumption here is that the computation was done by the FastProcessor,
                    // and so all operations in the program are valid and can be executed
                    // successfully.
                    .expect("operation should execute successfully")
                };

                // write the operation to the trace
                self.add_operation_trace_row(*op, op_idx_in_group, user_op_helpers)?;
            }

            // if we executed all operations in a group and haven't reached the end of the batch
            // yet, set up the decoder for decoding the next operation group
            if op_idx_in_batch + 1 == end_indices[op_group_idx]
                && let Some(next_op_group_idx) = batch.next_op_group_index(op_group_idx)
            {
                self.start_op_group(batch.groups()[next_op_group_idx]);
            }
        }

        ControlFlow::Continue(())
    }

    /// Starts decoding a new operation group.
    pub fn start_op_group(&mut self, op_group: Felt) {
        let ctx = self.span_context.as_mut().expect("not in span");

        // reset the current group value and decrement the number of left groups by ONE
        debug_assert_eq!(ZERO, ctx.group_ops_left, "not all ops executed in current group");
        ctx.group_ops_left = op_group;
        ctx.num_groups_left -= ONE;
    }

    // HELPERS
    // -------------------------------------------------------------------------------------------

    // TODO(plafer): Should this be a `StackState` method?
    pub fn shift_stack_left_and_start_context(&mut self) -> (usize, Felt) {
        self.decrement_size(&mut NoopTracer);
        self.context.state.stack.start_context()
    }

    fn append_opcode(&mut self, opcode: u8, row_idx: usize) {
        use miden_air::trace::{
            DECODER_TRACE_OFFSET,
            decoder::{NUM_OP_BITS, OP_BITS_OFFSET},
        };

        // Append the opcode bits to the trace row
        let bits: [Felt; NUM_OP_BITS] = core::array::from_fn(|i| Felt::from((opcode >> i) & 1));
        for (i, bit) in bits.iter().enumerate() {
            self.fragment.columns[DECODER_TRACE_OFFSET + OP_BITS_OFFSET + i][row_idx] = *bit;
        }

        // Set extra bit columns for degree reduction
        self.fragment.columns[DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET][row_idx] =
            bits[6] * (ONE - bits[5]) * bits[4];
        self.fragment.columns[DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET + 1][row_idx] =
            bits[6] * bits[5];
    }

    fn done_generating(&mut self) -> bool {
        // If we have built all the rows in the fragment, we are done
        let max_num_rows_in_fragment = self.fragment.columns[0].len();
        self.num_rows_built() >= max_num_rows_in_fragment
    }

    fn num_rows_built(&self) -> usize {
        // Returns the number of rows built so far in the fragment
        self.context.state.system.clk - self.fragment_start_clk
    }

    fn increment_clk(&mut self) -> ControlFlow<()> {
        self.context.state.system.clk += 1u32;

        // Check if we have reached the maximum number of rows in the fragment
        if self.done_generating() {
            // If we have reached the maximum, we are done generating
            ControlFlow::Break(())
        } else {
            // Otherwise, we continue generating
            ControlFlow::Continue(())
        }
    }
}

// HELPERS
// ===============================================================================================

/// Given that a trace fragment can start executing from the middle of a basic block, we need to
/// initialize the `BasicBlockContext` correctly to reflect the state of the decoder at that point.
/// This function does that initialization.
///
/// Recall that `BasicBlockContext` keeps track of the state needed to correctly fill in the decoder
/// columns associated with a SPAN of operations (i.e. a basic block). This function takes in a
/// basic block node, the index of the current operation batch within that block, and the index of
/// the current operation within that batch, and initializes the `BasicBlockContext` accordingly. In
/// other words, it figures out how many operations are left in the current operation group, and how
/// many operation groups are left in the basic block, given that we are starting execution from the
/// specified operation.
fn initialize_span_context(
    basic_block_node: &BasicBlockNode,
    batch_index: usize,
    op_idx_in_batch: usize,
) -> BasicBlockContext {
    let op_batches = basic_block_node.op_batches();
    let (current_op_group_idx, op_idx_in_group) = op_batches[batch_index]
        .op_idx_in_batch_to_group(op_idx_in_batch)
        .expect("invalid batch");

    let group_ops_left = {
        // Note: this here relies on NOOP's opcode to be 0, since `current_op_group_idx` could point
        // to an op group that contains a NOOP inserted at runtime (i.e. padding at the end of the
        // batch), and hence not encoded in the basic block directly. But since NOOP's opcode is 0,
        // this works out correctly (since empty groups are also represented by 0).
        let current_op_group = op_batches[batch_index].groups()[current_op_group_idx];

        // Shift out all operations that are already executed in this group.
        //
        // Note: `group_ops_left` encodes the bits of the operations left to be executed after the
        // current one, and so we would expect to shift `NUM_OP_BITS` by `op_idx_in_group + 1`.
        // However, we will apply that shift right before writing to the trace, so we only shift by
        // `op_idx_in_group` here.
        Felt::new(current_op_group.as_int() >> (NUM_OP_BITS * op_idx_in_group))
    };

    let num_groups_left = {
        // TODO(plafer): do we have to look at all op groups in the block? Can't we just look at the
        // current batch's groups?
        let total_groups = basic_block_node.num_op_groups();

        // Count groups consumed by completed batches (all batches before current one).
        let mut groups_consumed = 0;
        for op_batch in op_batches.iter().take(batch_index) {
            groups_consumed += op_batch.num_groups().next_power_of_two();
        }

        // We run through previous operations of our current op group, and increment the number of
        // groups consumed for each operation that has an immediate value
        {
            // Note: This is a hacky way of doing this because `OpBatch` doesn't store the
            // information of which operation belongs to which group.
            let mut current_op_group =
                op_batches[batch_index].groups()[current_op_group_idx].as_int();
            for _ in 0..op_idx_in_group {
                let current_op = (current_op_group & 0b1111111) as u8;
                if current_op == OPCODE_PUSH {
                    groups_consumed += 1;
                }

                current_op_group >>= NUM_OP_BITS; // Shift to the next operation in the group
            }
        }

        // Add the number of complete groups before the current group in this batch. Add 1 to
        // account for the current group (since `num_groups_left` is the number of groups left
        // *after* being done with the current group)
        groups_consumed += current_op_group_idx + 1;

        Felt::from((total_groups - groups_consumed) as u32)
    };

    BasicBlockContext { group_ops_left, num_groups_left }
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

// REQUIRED METHODS
// ===============================================================================================

impl<'a> StackInterface for CoreTraceFragmentFiller<'a> {
    fn top(&self) -> &[Felt] {
        &self.context.state.stack.stack_top
    }

    fn top_mut(&mut self) -> &mut [Felt] {
        &mut self.context.state.stack.stack_top
    }

    fn get(&self, idx: usize) -> Felt {
        debug_assert!(idx < MIN_STACK_DEPTH);
        self.context.state.stack.stack_top[MIN_STACK_DEPTH - idx - 1]
    }

    fn get_mut(&mut self, idx: usize) -> &mut Felt {
        debug_assert!(idx < MIN_STACK_DEPTH);

        &mut self.context.state.stack.stack_top[MIN_STACK_DEPTH - idx - 1]
    }

    fn get_word(&self, start_idx: usize) -> Word {
        debug_assert!(start_idx < MIN_STACK_DEPTH - 4);

        let word_start_idx = MIN_STACK_DEPTH - start_idx - 4;
        self.top()[range(word_start_idx, WORD_SIZE)].try_into().unwrap()
    }

    fn depth(&self) -> u32 {
        (MIN_STACK_DEPTH + self.context.state.stack.num_overflow_elements_in_current_ctx()) as u32
    }

    fn set(&mut self, idx: usize, element: Felt) {
        *self.get_mut(idx) = element;
    }

    fn set_word(&mut self, start_idx: usize, word: &Word) {
        debug_assert!(start_idx < MIN_STACK_DEPTH - 4);
        let word_start_idx = MIN_STACK_DEPTH - start_idx - 4;

        let word_on_stack =
            &mut self.context.state.stack.stack_top[range(word_start_idx, WORD_SIZE)];
        word_on_stack.copy_from_slice(word.as_slice());
    }

    fn swap(&mut self, idx1: usize, idx2: usize) {
        let a = self.get(idx1);
        let b = self.get(idx2);
        self.set(idx1, b);
        self.set(idx2, a);
    }

    fn swapw_nth(&mut self, n: usize) {
        // For example, for n=3, the stack words and variables look like:
        //    3     2     1     0
        // | ... | ... | ... | ... |
        // ^                 ^
        // nth_word       top_word
        let (rest_of_stack, top_word) =
            self.context.state.stack.stack_top.split_at_mut(MIN_STACK_DEPTH - WORD_SIZE);
        let (_, nth_word) = rest_of_stack.split_at_mut(rest_of_stack.len() - n * WORD_SIZE);

        nth_word[0..WORD_SIZE].swap_with_slice(&mut top_word[0..WORD_SIZE]);
    }

    fn rotate_left(&mut self, n: usize) {
        let rotation_bot_index = MIN_STACK_DEPTH - n;
        let new_stack_top_element = self.context.state.stack.stack_top[rotation_bot_index];

        // shift the top n elements down by 1, starting from the bottom of the rotation.
        for i in 0..n - 1 {
            self.context.state.stack.stack_top[rotation_bot_index + i] =
                self.context.state.stack.stack_top[rotation_bot_index + i + 1];
        }

        // Set the top element (which comes from the bottom of the rotation).
        self.set(0, new_stack_top_element);
    }

    fn rotate_right(&mut self, n: usize) {
        let rotation_bot_index = MIN_STACK_DEPTH - n;
        let new_stack_bot_element = self.context.state.stack.stack_top[MIN_STACK_DEPTH - 1];

        // shift the top n elements up by 1, starting from the top of the rotation.
        for i in 1..n {
            self.context.state.stack.stack_top[MIN_STACK_DEPTH - i] =
                self.context.state.stack.stack_top[MIN_STACK_DEPTH - i - 1];
        }

        // Set the bot element (which comes from the top of the rotation).
        self.context.state.stack.stack_top[rotation_bot_index] = new_stack_bot_element;
    }

    fn increment_size(&mut self, _tracer: &mut impl Tracer) -> Result<(), ExecutionError> {
        const SENTINEL_VALUE: Felt = Felt::new(Felt::MODULUS - 1);

        // push the last element on the overflow table
        {
            let last_element = self.get(MIN_STACK_DEPTH - 1);
            self.context.state.stack.push_overflow(last_element, self.clk());
        }

        // Shift all other elements down
        for write_idx in (1..MIN_STACK_DEPTH).rev() {
            let read_idx = write_idx - 1;
            self.set(write_idx, self.get(read_idx));
        }

        // Set the top element to SENTINEL_VALUE to help in debugging. Per the method docs, this
        // value will be overwritten
        self.set(0, SENTINEL_VALUE);

        Ok(())
    }

    fn decrement_size(&mut self, _tracer: &mut impl Tracer) {
        // Shift all other elements up
        for write_idx in 0..(MIN_STACK_DEPTH - 1) {
            let read_idx = write_idx + 1;
            self.set(write_idx, self.get(read_idx));
        }

        // Pop the last element from the overflow table
        if let Some(last_element) =
            self.context.state.stack.pop_overflow(&mut self.context.replay.stack_overflow)
        {
            // Write the last element to the bottom of the stack
            self.set(MIN_STACK_DEPTH - 1, last_element);
        } else {
            // If overflow table is empty, set the bottom element to zero
            self.set(MIN_STACK_DEPTH - 1, ZERO);
        }
    }
}

impl<'a> Processor for CoreTraceFragmentFiller<'a> {
    type HelperRegisters = TraceGenerationHelpers;
    type System = Self;
    type Stack = Self;
    type AdviceProvider = AdviceReplay;
    type Memory = MemoryReadsReplay;
    type Hasher = HasherResponseReplay;

    fn stack(&mut self) -> &mut Self::Stack {
        self
    }

    fn system(&mut self) -> &mut Self::System {
        self
    }

    fn state(&mut self) -> ProcessState<'_> {
        ProcessState::Noop(())
    }

    fn advice_provider(&mut self) -> &mut Self::AdviceProvider {
        &mut self.context.replay.advice
    }

    fn memory(&mut self) -> &mut Self::Memory {
        &mut self.context.replay.memory_reads
    }

    fn hasher(&mut self) -> &mut Self::Hasher {
        &mut self.context.replay.hasher
    }

    fn precompile_transcript_state(&self) -> PrecompileTranscriptState {
        self.context.state.system.pc_transcript_state
    }

    fn set_precompile_transcript_state(&mut self, state: PrecompileTranscriptState) {
        self.context.state.system.pc_transcript_state = state;
    }

    fn op_eval_circuit(
        &mut self,
        err_ctx: &impl ErrorContext,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        let num_eval = self.stack().get(2);
        let num_read = self.stack().get(1);
        let ptr = self.stack().get(0);
        let ctx = self.system().ctx();

        let _circuit_evaluation = eval_circuit_parallel_(
            ctx,
            ptr,
            self.system().clk(),
            num_read,
            num_eval,
            self,
            err_ctx,
            tracer,
        )?;

        Ok(())
    }
}

impl<'a> SystemInterface for CoreTraceFragmentFiller<'a> {
    fn caller_hash(&self) -> Word {
        self.context.state.system.fn_hash
    }

    fn clk(&self) -> RowIndex {
        self.context.state.system.clk
    }

    fn ctx(&self) -> ContextId {
        self.context.state.system.ctx
    }
}

/// Implementation of `OperationHelperRegisters` used for trace generation, where we actually
/// compute the helper registers associated with the corresponding operation.
struct TraceGenerationHelpers;

impl OperationHelperRegisters for TraceGenerationHelpers {
    #[inline(always)]
    fn op_eq_registers(stack_second: Felt, stack_first: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        let h0 = if stack_second == stack_first {
            ZERO
        } else {
            (stack_first - stack_second).inv()
        };

        [h0, ZERO, ZERO, ZERO, ZERO, ZERO]
    }

    #[inline(always)]
    fn op_u32split_registers(hi: Felt, lo: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        let (t1, t0) = split_u32_into_u16(lo.as_int());
        let (t3, t2) = split_u32_into_u16(hi.as_int());
        let m = (Felt::from(u32::MAX) - hi).inv();

        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), m, ZERO]
    }

    #[inline(always)]
    fn op_eqz_registers(top: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        // h0 is a helper variable provided by the prover. If the top element is zero, then, h0 can
        // be set to anything otherwise set it to the inverse of the top element in the stack.
        let h0 = if top == ZERO { ZERO } else { top.inv() };

        [h0, ZERO, ZERO, ZERO, ZERO, ZERO]
    }

    #[inline(always)]
    fn op_expacc_registers(acc_update_val: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        [acc_update_val, ZERO, ZERO, ZERO, ZERO, ZERO]
    }

    #[inline(always)]
    fn op_fri_ext2fold4_registers(
        ev: QuadFelt,
        es: QuadFelt,
        x: Felt,
        x_inv: Felt,
    ) -> [Felt; NUM_USER_OP_HELPERS] {
        let ev_arr = [ev];
        let ev_felts = QuadFelt::slice_as_base_elements(&ev_arr);

        let es_arr = [es];
        let es_felts = QuadFelt::slice_as_base_elements(&es_arr);

        [ev_felts[0], ev_felts[1], es_felts[0], es_felts[1], x, x_inv]
    }

    #[inline(always)]
    fn op_u32add_registers(hi: Felt, lo: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        // Compute helpers for range checks
        let (t1, t0) = split_u32_into_u16(lo.as_int());
        let (t3, t2) = split_u32_into_u16(hi.as_int());

        // For u32add, check_element_validity is false
        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), ZERO, ZERO]
    }

    #[inline(always)]
    fn op_u32add3_registers(hi: Felt, lo: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        // Compute helpers for range checks
        let (t1, t0) = split_u32_into_u16(lo.as_int());
        let (t3, t2) = split_u32_into_u16(hi.as_int());

        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), ZERO, ZERO]
    }

    #[inline(always)]
    fn op_u32sub_registers(second_new: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        // Compute helpers for range checks (only `second_new` needs range checking)
        let (t1, t0) = split_u32_into_u16(second_new.as_int());

        [Felt::from(t0), Felt::from(t1), ZERO, ZERO, ZERO, ZERO]
    }

    #[inline(always)]
    fn op_u32mul_registers(hi: Felt, lo: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        // Compute helpers for range checks
        let (t1, t0) = split_u32_into_u16(lo.as_int());
        let (t3, t2) = split_u32_into_u16(hi.as_int());
        let m = (Felt::from(u32::MAX) - hi).inv();

        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), m, ZERO]
    }

    #[inline(always)]
    fn op_u32madd_registers(hi: Felt, lo: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        // Compute helpers for range checks
        let (t1, t0) = split_u32_into_u16(lo.as_int());
        let (t3, t2) = split_u32_into_u16(hi.as_int());
        let m = (Felt::from(u32::MAX) - hi).inv();

        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), m, ZERO]
    }

    #[inline(always)]
    fn op_u32div_registers(hi: Felt, lo: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        // Compute helpers for range checks
        let (t1, t0) = split_u32_into_u16(lo.as_int());
        let (t3, t2) = split_u32_into_u16(hi.as_int());

        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), ZERO, ZERO]
    }

    #[inline(always)]
    fn op_u32assert2_registers(first: Felt, second: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        // Compute helpers for range checks for both operands
        let (t1, t0) = split_u32_into_u16(second.as_int());
        let (t3, t2) = split_u32_into_u16(first.as_int());

        [Felt::from(t0), Felt::from(t1), Felt::from(t2), Felt::from(t3), ZERO, ZERO]
    }

    #[inline(always)]
    fn op_hperm_registers(addr: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        [addr, ZERO, ZERO, ZERO, ZERO, ZERO]
    }

    #[inline(always)]
    fn op_merkle_path_registers(addr: Felt) -> [Felt; NUM_USER_OP_HELPERS] {
        [addr, ZERO, ZERO, ZERO, ZERO, ZERO]
    }

    #[inline(always)]
    fn op_horner_eval_base_registers(
        alpha: QuadFelt,
        tmp0: QuadFelt,
        tmp1: QuadFelt,
    ) -> [Felt; NUM_USER_OP_HELPERS] {
        [
            alpha.base_element(0),
            alpha.base_element(1),
            tmp1.to_base_elements()[0],
            tmp1.to_base_elements()[1],
            tmp0.to_base_elements()[0],
            tmp0.to_base_elements()[1],
        ]
    }

    #[inline(always)]
    fn op_horner_eval_ext_registers(
        alpha: QuadFelt,
        k0: Felt,
        k1: Felt,
        acc_tmp: QuadFelt,
    ) -> [Felt; NUM_USER_OP_HELPERS] {
        [
            alpha.base_element(0),
            alpha.base_element(1),
            k0,
            k1,
            acc_tmp.base_element(0),
            acc_tmp.base_element(1),
        ]
    }

    #[inline(always)]
    fn op_log_precompile_registers(addr: Felt, cap_prev: Word) -> [Felt; NUM_USER_OP_HELPERS] {
        // Helper registers layout for log_precompile:
        // h0-h4 contain: [addr, CAP_PREV[0..3]]
        [addr, cap_prev[0], cap_prev[1], cap_prev[2], cap_prev[3], ZERO]
    }
}

// HELPERS
// ================================================================================================

/// Executes a loop node by processing its body repeatedly while the condition is true.
///
/// This function is shared between `NodeExecutionState::LoopRepeat` and `Continuation::FinishLoop`
/// to eliminate code duplication. Both cases have identical logic for handling loop execution.
#[inline(always)]
fn finish_loop_node(
    processor: &mut CoreTraceFragmentFiller,
    node_id: MastNodeId,
    mast_forest: &MastForest,
    condition: Option<Felt>,
) -> ControlFlow<()> {
    let loop_node = mast_forest.get_node_by_id(node_id).expect("node should exist").unwrap_loop();

    // If no condition is provided, read it from the stack
    let mut condition = if let Some(cond) = condition {
        cond
    } else {
        let cond = processor.get(0);
        processor.decrement_size(&mut NoopTracer);
        cond
    };

    while condition == ONE {
        processor.add_loop_repeat_trace_row(
            loop_node,
            mast_forest,
            processor.context.state.decoder.current_addr,
        )?;

        processor.execute_mast_node(loop_node.body(), mast_forest)?;

        condition = processor.get(0);
        processor.decrement_size(&mut NoopTracer);
    }

    // 3. Add "end LOOP" row
    //
    // Note that we don't confirm that the condition is properly ZERO here, as
    // the FastProcessor already ran that check.
    processor.add_end_trace_row(loop_node.digest())?;

    ControlFlow::Continue(())
}

/// Identical to `[chiplets::ace::eval_circuit]` but adapted for use with
/// `[CoreTraceFragmentGenerator]`.
#[allow(clippy::too_many_arguments)]
fn eval_circuit_parallel_(
    ctx: ContextId,
    ptr: Felt,
    clk: RowIndex,
    num_vars: Felt,
    num_eval: Felt,
    processor: &mut CoreTraceFragmentFiller,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<CircuitEvaluation, ExecutionError> {
    // Delegate to the fast implementation with the processor's memory interface.
    // This eliminates ~70 lines of duplicated code while maintaining identical functionality.
    eval_circuit_fast_(ctx, ptr, clk, num_vars, num_eval, processor.memory(), err_ctx, tracer)
}
