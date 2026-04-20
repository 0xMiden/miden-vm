use alloc::{boxed::Box, sync::Arc, vec::Vec};

use itertools::Itertools;
use miden_air::{
    Felt,
    trace::{
        CLK_COL_IDX, DECODER_TRACE_OFFSET, DECODER_TRACE_WIDTH, MIN_TRACE_LEN, MainTrace, RowIndex,
        STACK_TRACE_OFFSET, STACK_TRACE_WIDTH, SYS_TRACE_WIDTH,
        decoder::{
            HASHER_STATE_OFFSET, NUM_HASHER_COLUMNS, NUM_OP_BITS, OP_BITS_EXTRA_COLS_OFFSET,
            OP_BITS_OFFSET,
        },
        stack::{B0_COL_IDX, B1_COL_IDX, H0_COL_IDX, STACK_TOP_OFFSET},
    },
};
use miden_core::{
    ONE, Word, ZERO,
    field::batch_inversion_allow_zeros,
    mast::{MastForest, MastNode},
    operations::opcodes,
    program::{Kernel, MIN_STACK_DEPTH},
};
use rayon::prelude::*;
use tracing::instrument;

use crate::{
    ContextId, ExecutionError,
    continuation_stack::ContinuationStack,
    errors::MapExecErrNoCtx,
    trace::{
        AuxTraceBuilders, ChipletsLengths, ExecutionTrace, TraceBuildInputs, TraceLenSummary,
        parallel::{processor::ReplayProcessor, tracer::CoreTraceGenerationTracer},
        range::RangeChecker,
        utils::RowMajorTraceWriter,
    },
};

pub const CORE_TRACE_WIDTH: usize = SYS_TRACE_WIDTH + DECODER_TRACE_WIDTH + STACK_TRACE_WIDTH;

/// `build_trace()` uses this as a hard cap on trace rows.
///
/// The code checks `core_trace_contexts.len() * fragment_size` before allocation. It checks the
/// same cap again while replaying chiplet activity. This keeps memory use bounded.
const MAX_TRACE_LEN: usize = 1 << 29;

pub(crate) mod core_trace_fragment;

mod processor;
mod tracer;

use super::{
    chiplets::Chiplets,
    decoder::AuxTraceBuilder as DecoderAuxTraceBuilder,
    execution_tracer::TraceGenerationContext,
    stack::AuxTraceBuilder as StackAuxTraceBuilder,
    trace_state::{
        AceReplay, BitwiseOp, BitwiseReplay, CoreTraceFragmentContext, CoreTraceState,
        ExecutionReplay, HasherOp, HasherRequestReplay, KernelReplay, MemoryWritesReplay,
        RangeCheckerReplay,
    },
};

#[cfg(test)]
mod tests;

// BUILD TRACE
// ================================================================================================

/// Builds the main trace from the provided trace states in parallel.
///
/// # Example
/// ```
/// use miden_assembly::Assembler;
/// use miden_processor::{DefaultHost, FastProcessor, StackInputs};
///
/// let program = Assembler::default().assemble_program("begin push.1 drop end").unwrap();
/// let mut host = DefaultHost::default();
///
/// let trace_inputs = FastProcessor::new(StackInputs::default())
///     .execute_trace_inputs_sync(&program, &mut host)
///     .unwrap();
/// let trace = miden_processor::trace::build_trace(trace_inputs).unwrap();
///
/// assert_eq!(*trace.program_hash(), program.hash());
/// ```
#[instrument(name = "build_trace", skip_all)]
pub fn build_trace(inputs: TraceBuildInputs) -> Result<ExecutionTrace, ExecutionError> {
    build_trace_with_max_len(inputs, MAX_TRACE_LEN)
}

/// Same as [`build_trace`], but with a custom hard cap.
///
/// When the trace would go over `max_trace_len`, this returns
/// [`ExecutionError::TraceLenExceeded`].
pub fn build_trace_with_max_len(
    inputs: TraceBuildInputs,
    max_trace_len: usize,
) -> Result<ExecutionTrace, ExecutionError> {
    let TraceBuildInputs {
        trace_output,
        trace_generation_context,
        program_info,
    } = inputs;

    if !trace_output.has_matching_precompile_requests_digest() {
        return Err(ExecutionError::Internal(
            "trace inputs do not match deferred precompile requests",
        ));
    }

    let TraceGenerationContext {
        core_trace_contexts,
        range_checker_replay,
        memory_writes,
        bitwise_replay: bitwise,
        kernel_replay,
        hasher_for_chiplet,
        ace_replay,
        fragment_size,
    } = trace_generation_context;

    // Before any trace generation, check that the number of core trace rows doesn't exceed the
    // maximum trace length. This is a necessary check to avoid OOM panics during trace generation,
    // which can occur if the execution produces an extremely large number of steps.
    //
    // Note that we add 1 to the total core trace rows to account for the additional HALT opcode row
    // that is pushed at the end of the last fragment.
    let total_core_trace_rows = core_trace_contexts
        .len()
        .checked_mul(fragment_size)
        .and_then(|n| n.checked_add(1))
        .ok_or(ExecutionError::TraceLenExceeded(max_trace_len))?;
    if total_core_trace_rows > max_trace_len {
        return Err(ExecutionError::TraceLenExceeded(max_trace_len));
    }

    if core_trace_contexts.is_empty() {
        return Err(ExecutionError::Internal(
            "no trace fragments provided in the trace generation context",
        ));
    }

    let chiplets = initialize_chiplets(
        program_info.kernel().clone(),
        &core_trace_contexts,
        memory_writes,
        bitwise,
        kernel_replay,
        hasher_for_chiplet,
        ace_replay,
        max_trace_len,
    )?;

    let range_checker = initialize_range_checker(range_checker_replay, &chiplets);

    let mut core_trace_data = generate_core_trace_row_major(
        core_trace_contexts,
        program_info.kernel().clone(),
        fragment_size,
        max_trace_len,
    )?;

    let core_trace_len = core_trace_data.len() / CORE_TRACE_WIDTH;

    // Get the number of rows for the range checker
    let range_table_len = range_checker.get_number_range_checker_rows();

    let trace_len_summary =
        TraceLenSummary::new(core_trace_len, range_table_len, ChipletsLengths::new(&chiplets));

    // Compute the final main trace length
    let main_trace_len = compute_main_trace_length(
        core_trace_len,
        range_table_len,
        chiplets.trace_len(),
        max_trace_len,
    )?;

    let (pad_result, (range_checker_trace, chiplets_trace)) = rayon::join(
        || pad_core_row_major(&mut core_trace_data, main_trace_len, max_trace_len),
        || {
            rayon::join(
                || range_checker.into_trace_with_table(range_table_len, main_trace_len),
                || chiplets.into_trace(main_trace_len),
            )
        },
    );
    pad_result?;

    // Create the MainTrace
    let main_trace = {
        let last_program_row = core_trace_len
            .checked_sub(1)
            .and_then(|n| u32::try_from(n).ok())
            .map(RowIndex::from)
            .ok_or(ExecutionError::TraceLenExceeded(max_trace_len))?;
        MainTrace::from_parts(
            core_trace_data,
            chiplets_trace.trace,
            range_checker_trace.trace,
            main_trace_len,
            last_program_row,
        )
    };

    // Create aux trace builders
    let aux_trace_builders = AuxTraceBuilders {
        decoder: DecoderAuxTraceBuilder::default(),
        range: range_checker_trace.aux_builder,
        chiplets: chiplets_trace.aux_builder,
        stack: StackAuxTraceBuilder,
    };

    Ok(ExecutionTrace::new_from_parts(
        program_info,
        trace_output,
        main_trace,
        aux_trace_builders,
        trace_len_summary,
    ))
}

// HELPERS
// ================================================================================================

fn compute_main_trace_length(
    core_trace_len: usize,
    range_table_len: usize,
    chiplets_trace_len: usize,
    max_trace_len: usize,
) -> Result<usize, ExecutionError> {
    // Get the trace length required to hold all execution trace steps
    let max_len = range_table_len.max(core_trace_len).max(chiplets_trace_len);

    // Pad the trace length to the next power of two
    let trace_len = max_len
        .checked_next_power_of_two()
        .ok_or(ExecutionError::TraceLenExceeded(max_trace_len))?;
    Ok(core::cmp::max(trace_len, MIN_TRACE_LEN))
}

/// Generates row-major core trace in parallel from the provided trace fragment contexts.
fn generate_core_trace_row_major(
    core_trace_contexts: Vec<CoreTraceFragmentContext>,
    kernel: Kernel,
    fragment_size: usize,
    max_trace_len: usize,
) -> Result<Vec<Felt>, ExecutionError> {
    let num_fragments = core_trace_contexts.len();
    let total_allocated_rows = num_fragments
        .checked_mul(fragment_size)
        .ok_or(ExecutionError::TraceLenExceeded(max_trace_len))?;
    let total_allocated_cells = total_allocated_rows
        .checked_mul(CORE_TRACE_WIDTH)
        .ok_or(ExecutionError::TraceLenExceeded(max_trace_len))?;
    let fragment_stride = fragment_size
        .checked_mul(CORE_TRACE_WIDTH)
        .ok_or(ExecutionError::TraceLenExceeded(max_trace_len))?;

    let mut core_trace_data: Vec<Felt> = vec![ZERO; total_allocated_cells];

    // Save the first stack top for initialization
    let first_stack_top = if let Some(first_context) = core_trace_contexts.first() {
        first_context.state.stack.stack_top.to_vec()
    } else {
        vec![ZERO; MIN_STACK_DEPTH]
    };

    let writers: Vec<RowMajorTraceWriter<'_, Felt>> = core_trace_data
        .chunks_exact_mut(fragment_stride)
        .map(|chunk| RowMajorTraceWriter::new(chunk, CORE_TRACE_WIDTH))
        .collect();

    // Build the core trace fragments in parallel
    let fragment_results: Result<Vec<_>, ExecutionError> = core_trace_contexts
        .into_par_iter()
        .zip(writers.into_par_iter())
        .map(|(trace_state, writer)| {
            let (mut processor, mut tracer, mut continuation_stack, mut current_forest) =
                split_trace_fragment_context(trace_state, writer, fragment_size);

            processor.execute(
                &mut continuation_stack,
                &mut current_forest,
                &kernel,
                &mut tracer,
            )?;

            tracer.into_final_state()
        })
        .collect();
    let fragment_results = fragment_results?;

    let mut stack_rows = Vec::new();
    let mut system_rows = Vec::new();
    let mut total_core_trace_rows: usize = 0;

    for final_state in fragment_results {
        stack_rows.push(final_state.last_stack_cols);
        system_rows.push(final_state.last_system_cols);
        total_core_trace_rows = total_core_trace_rows
            .checked_add(final_state.num_rows_written)
            .ok_or(ExecutionError::TraceLenExceeded(max_trace_len))?;
    }

    // Fix up stack and system rows
    fixup_stack_and_system_rows(
        &mut core_trace_data,
        fragment_size,
        &stack_rows,
        &system_rows,
        &first_stack_top,
    );

    // Run batch inversion on stack's H0 helper column, processing each fragment in parallel.
    // This must be done after fixup_stack_and_system_rows since that function overwrites the first
    // row of each fragment with non-inverted values.
    {
        let h0_col_offset = STACK_TRACE_OFFSET + H0_COL_IDX;
        let w = CORE_TRACE_WIDTH;
        let total_trace_cells = total_core_trace_rows
            .checked_mul(w)
            .ok_or(ExecutionError::TraceLenExceeded(max_trace_len))?;
        core_trace_data[..total_trace_cells]
            .par_chunks_mut(fragment_stride)
            .for_each(|fragment_chunk| {
                let num_rows = fragment_chunk.len() / w;
                let mut h0_vals: Vec<Felt> =
                    (0..num_rows).map(|r| fragment_chunk[r * w + h0_col_offset]).collect();
                batch_inversion_allow_zeros(&mut h0_vals);
                for (r, &val) in h0_vals.iter().enumerate() {
                    fragment_chunk[r * w + h0_col_offset] = val;
                }
            });
    }

    // Truncate the core trace columns to the actual number of rows written.
    let total_trace_cells = total_core_trace_rows
        .checked_mul(CORE_TRACE_WIDTH)
        .ok_or(ExecutionError::TraceLenExceeded(max_trace_len))?;
    core_trace_data.truncate(total_trace_cells);

    push_halt_opcode_row(
        &mut core_trace_data,
        total_core_trace_rows,
        system_rows.last().ok_or(ExecutionError::Internal(
            "no trace fragments provided in the trace generation context",
        ))?,
        stack_rows.last().ok_or(ExecutionError::Internal(
            "no trace fragments provided in the trace generation context",
        ))?,
    );

    Ok(core_trace_data)
}

/// Initializing the first row of each fragment with the appropriate stack and system state.
///
/// This needs to be done as a separate pass after all fragments have been generated, because the
/// system and stack rows write the state at clk `i` to the row at index `i+1`. Hence, the state of
/// the last row of any given fragment cannot be written in parallel, since any given fragment
/// filler doesn't have access to the next fragment's first row.
fn fixup_stack_and_system_rows(
    core_trace_data: &mut [Felt],
    fragment_size: usize,
    stack_rows: &[[Felt; STACK_TRACE_WIDTH]],
    system_rows: &[[Felt; SYS_TRACE_WIDTH]],
    first_stack_top: &[Felt],
) {
    const MIN_STACK_DEPTH_FELT: Felt = Felt::new(MIN_STACK_DEPTH as u64);
    let w = CORE_TRACE_WIDTH;

    {
        let row = &mut core_trace_data[..w];

        // Stack order in the trace is reversed vs `first_stack_top`.
        for (stack_col_idx, &value) in first_stack_top.iter().rev().enumerate() {
            row[STACK_TRACE_OFFSET + STACK_TOP_OFFSET + stack_col_idx] = value;
        }

        row[STACK_TRACE_OFFSET + B0_COL_IDX] = MIN_STACK_DEPTH_FELT;
        row[STACK_TRACE_OFFSET + B1_COL_IDX] = ZERO;
        row[STACK_TRACE_OFFSET + H0_COL_IDX] = ZERO;
    }

    let total_rows = core_trace_data.len() / w;
    let num_fragments = total_rows / fragment_size;

    for frag_idx in 1..num_fragments {
        let row_idx = frag_idx * fragment_size;
        let row_start = row_idx * w;
        let system_row = &system_rows[frag_idx - 1];
        let stack_row = &stack_rows[frag_idx - 1];

        core_trace_data[row_start..row_start + SYS_TRACE_WIDTH].copy_from_slice(system_row);

        let stack_start = row_start + STACK_TRACE_OFFSET;
        core_trace_data[stack_start..stack_start + STACK_TRACE_WIDTH].copy_from_slice(stack_row);
    }
}

/// Appends a HALT row (`num_rows_before` is the row count before append).
///
/// This ensures that the trace ends with at least one HALT operation, which is necessary to satisfy
/// the constraints.
fn push_halt_opcode_row(
    core_trace_data: &mut Vec<Felt>,
    num_rows_before: usize,
    last_system_state: &[Felt; SYS_TRACE_WIDTH],
    last_stack_state: &[Felt; STACK_TRACE_WIDTH],
) {
    let w = CORE_TRACE_WIDTH;
    let mut row = [ZERO; CORE_TRACE_WIDTH];

    // system columns
    // ---------------------------------------------------------------------------------------
    row[..SYS_TRACE_WIDTH].copy_from_slice(last_system_state);

    // stack columns
    // ---------------------------------------------------------------------------------------
    row[STACK_TRACE_OFFSET..STACK_TRACE_OFFSET + STACK_TRACE_WIDTH]
        .copy_from_slice(last_stack_state);

    // Pad op_bits columns with HALT opcode bits
    let halt_opcode = opcodes::HALT;
    for bit_idx in 0..NUM_OP_BITS {
        row[DECODER_TRACE_OFFSET + OP_BITS_OFFSET + bit_idx] =
            Felt::from_u8((halt_opcode >> bit_idx) & 1);
    }

    // Pad hasher state columns (8 columns)
    // - First 4 columns: copy the last value (to propagate program hash)
    // - Remaining 4 columns: fill with ZEROs
    if num_rows_before > 0 {
        let last_row_start = (num_rows_before - 1) * w;
        // For first 4 hasher columns, copy the last value to propagate program hash
        for hasher_col_idx in 0..4 {
            let col_idx = DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + hasher_col_idx;
            row[col_idx] = core_trace_data[last_row_start + col_idx];
        }
    }

    // Pad op_bit_extra columns (2 columns)
    // - First column: do nothing (pre-filled with ZEROs, HALT doesn't use this)
    // - Second column: fill with ONEs (product of two most significant HALT bits, both are 1)
    row[DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET + 1] = ONE;

    core_trace_data.extend_from_slice(&row);
}

/// Initializes the ranger checker from the recorded range checks during execution and returns it.
///
/// Note that the maximum number of rows that the range checker can produce is 2^16, which is less
/// than the maximum trace length (2^29). Hence, we can safely generate the entire range checker
/// trace and then pad it to the final trace length, without worrying about hitting memory limits.
fn initialize_range_checker(
    range_checker_replay: RangeCheckerReplay,
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

/// Replays recorded operations to populate chiplet traces. Results were already used during
/// execution; this pass only needs the trace-recording side effects.
fn initialize_chiplets(
    kernel: Kernel,
    core_trace_contexts: &[CoreTraceFragmentContext],
    memory_writes: MemoryWritesReplay,
    bitwise: BitwiseReplay,
    kernel_replay: KernelReplay,
    hasher_for_chiplet: HasherRequestReplay,
    ace_replay: AceReplay,
    max_trace_len: usize,
) -> Result<Chiplets, ExecutionError> {
    let check_chiplets_trace_len = |chiplets: &Chiplets| -> Result<(), ExecutionError> {
        if chiplets.trace_len() > max_trace_len {
            return Err(ExecutionError::TraceLenExceeded(max_trace_len));
        }
        Ok(())
    };

    let mut chiplets = Chiplets::new(kernel);

    // populate hasher chiplet
    for hasher_op in hasher_for_chiplet.into_iter() {
        match hasher_op {
            HasherOp::Permute(input_state) => {
                let _ = chiplets.hasher.permute(input_state);
                check_chiplets_trace_len(&chiplets)?;
            },
            HasherOp::HashControlBlock((h1, h2, domain, expected_hash)) => {
                let _ = chiplets.hasher.hash_control_block(h1, h2, domain, expected_hash);
                check_chiplets_trace_len(&chiplets)?;
            },
            HasherOp::HashBasicBlock((forest, node_id, expected_hash)) => {
                let node = forest
                    .get_node_by_id(node_id)
                    .ok_or(ExecutionError::Internal("invalid node ID in hasher replay"))?;
                let MastNode::Block(basic_block_node) = node else {
                    return Err(ExecutionError::Internal(
                        "expected basic block node in hasher replay",
                    ));
                };
                let op_batches = basic_block_node.op_batches();
                let _ = chiplets.hasher.hash_basic_block(op_batches, expected_hash);
                check_chiplets_trace_len(&chiplets)?;
            },
            HasherOp::BuildMerkleRoot((value, path, index)) => {
                let _ = chiplets.hasher.build_merkle_root(value, &path, index);
                check_chiplets_trace_len(&chiplets)?;
            },
            HasherOp::UpdateMerkleRoot((old_value, new_value, path, index)) => {
                chiplets.hasher.update_merkle_root(old_value, new_value, &path, index);
                check_chiplets_trace_len(&chiplets)?;
            },
        }
    }

    // populate bitwise chiplet
    for (bitwise_op, a, b) in bitwise {
        match bitwise_op {
            BitwiseOp::U32And => {
                chiplets.bitwise.u32and(a, b).map_exec_err_no_ctx()?;
                check_chiplets_trace_len(&chiplets)?;
            },
            BitwiseOp::U32Xor => {
                chiplets.bitwise.u32xor(a, b).map_exec_err_no_ctx()?;
                check_chiplets_trace_len(&chiplets)?;
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
            .try_for_each(|mem_access| {
                match mem_access {
                    MemoryAccess::ReadElement(addr, ctx, clk) => chiplets
                        .memory
                        .read(ctx, addr, clk)
                        .map(|_| ())
                        .map_err(ExecutionError::MemoryErrorNoCtx)?,
                    MemoryAccess::WriteElement(addr, element, ctx, clk) => chiplets
                        .memory
                        .write(ctx, addr, clk, element)
                        .map_err(ExecutionError::MemoryErrorNoCtx)?,
                    MemoryAccess::ReadWord(addr, ctx, clk) => chiplets
                        .memory
                        .read_word(ctx, addr, clk)
                        .map(|_| ())
                        .map_err(ExecutionError::MemoryErrorNoCtx)?,
                    MemoryAccess::WriteWord(addr, word, ctx, clk) => chiplets
                        .memory
                        .write_word(ctx, addr, clk, word)
                        .map_err(ExecutionError::MemoryErrorNoCtx)?,
                }
                check_chiplets_trace_len(&chiplets)
            })?;

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
        check_chiplets_trace_len(&chiplets)?;
    }

    // populate kernel ROM
    for proc_hash in kernel_replay.into_iter() {
        chiplets.kernel_rom.access_proc(proc_hash).map_exec_err_no_ctx()?;
        check_chiplets_trace_len(&chiplets)?;
    }

    Ok(chiplets)
}

/// Pads the core trace to `main_trace_len` rows (HALT template, CLK incremented per row).
fn pad_core_row_major(
    core_trace_data: &mut Vec<Felt>,
    main_trace_len: usize,
    max_trace_len: usize,
) -> Result<(), ExecutionError> {
    let w = CORE_TRACE_WIDTH;
    let total_program_rows = core_trace_data.len() / w;
    if total_program_rows > main_trace_len {
        return Err(ExecutionError::Internal("program rows exceed main trace length"));
    }
    if total_program_rows == 0 {
        return Err(ExecutionError::Internal("core trace is empty"));
    }
    if main_trace_len
        .checked_sub(1)
        .and_then(|n| u32::try_from(n).ok())
        .is_none()
    {
        return Err(ExecutionError::TraceLenExceeded(max_trace_len));
    }

    let num_padding_rows = main_trace_len - total_program_rows;
    if num_padding_rows == 0 {
        return Ok(());
    }
    let last_row_start = (total_program_rows - 1) * w;

    // Decoder columns
    // ------------------------

    let mut template = [ZERO; CORE_TRACE_WIDTH];
    // Pad op_bits columns with HALT opcode bits
    let halt_opcode = opcodes::HALT;
    for i in 0..NUM_OP_BITS {
        let bit_value = Felt::from_u8((halt_opcode >> i) & 1);
        template[DECODER_TRACE_OFFSET + OP_BITS_OFFSET + i] = bit_value;
    }
    // Pad hasher state columns (8 columns)
    // - First 4 columns: copy the last value (to propagate program hash)
    // - Remaining 4 columns: fill with ZEROs
    for i in 0..NUM_HASHER_COLUMNS {
        let col_idx = DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + i;
        template[col_idx] = if i < 4 {
            // For first 4 hasher columns, copy the last value to propagate program hash
            // Safety: per our documented safety guarantees, we know that `total_program_rows > 0`,
            // and row `total_program_rows - 1` is initialized.
            core_trace_data[last_row_start + col_idx]
        } else {
            ZERO
        };
    }

    // Pad op_bit_extra columns (2 columns)
    // - First column: do nothing (filled with ZEROs, HALT doesn't use this)
    // - Second column: fill with ONEs (product of two most significant HALT bits, both are 1)
    template[DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET + 1] = ONE;

    // Stack columns
    // ------------------------

    // Pad stack columns with the last value in each column (analogous to Stack::into_trace())
    for i in 0..STACK_TRACE_WIDTH {
        let col_idx = STACK_TRACE_OFFSET + i;
        // Safety: per our documented safety guarantees, we know that `total_program_rows > 0`,
        // and row `total_program_rows - 1` is initialized.
        template[col_idx] = core_trace_data[last_row_start + col_idx];
    }

    // System columns
    // ------------------------

    // Pad CLK trace - fill with index values

    let additional_cells = num_padding_rows
        .checked_mul(w)
        .ok_or(ExecutionError::TraceLenExceeded(max_trace_len))?;
    core_trace_data
        .try_reserve(additional_cells)
        .map_err(|_| ExecutionError::TraceLenExceeded(max_trace_len))?;
    for idx in 0..num_padding_rows {
        let clk = total_program_rows
            .checked_add(idx)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(ExecutionError::TraceLenExceeded(max_trace_len))?;
        template[CLK_COL_IDX] = Felt::from_u32(clk);
        core_trace_data.extend_from_slice(&template);
    }

    Ok(())
}

/// Uses the provided `CoreTraceFragmentContext` to build and return a `ReplayProcessor` and
/// `CoreTraceGenerationTracer` that can be used to execute the fragment.
fn split_trace_fragment_context<'a>(
    fragment_context: CoreTraceFragmentContext,
    writer: RowMajorTraceWriter<'a, Felt>,
    fragment_size: usize,
) -> (
    ReplayProcessor,
    CoreTraceGenerationTracer<'a>,
    ContinuationStack,
    Arc<MastForest>,
) {
    let CoreTraceFragmentContext {
        state: CoreTraceState { system, decoder, stack },
        replay:
            ExecutionReplay {
                block_stack: block_stack_replay,
                execution_context: execution_context_replay,
                stack_overflow: stack_overflow_replay,
                memory_reads: memory_reads_replay,
                advice: advice_replay,
                hasher: hasher_response_replay,
                block_address: block_address_replay,
                mast_forest_resolution: mast_forest_resolution_replay,
            },
        continuation,
        initial_mast_forest,
    } = fragment_context;

    let processor = ReplayProcessor::new(
        system,
        stack,
        stack_overflow_replay,
        execution_context_replay,
        advice_replay,
        memory_reads_replay,
        hasher_response_replay,
        mast_forest_resolution_replay,
        fragment_size.into(),
    );
    let tracer =
        CoreTraceGenerationTracer::new(writer, decoder, block_address_replay, block_stack_replay);

    (processor, tracer, continuation, initial_mast_forest)
}
