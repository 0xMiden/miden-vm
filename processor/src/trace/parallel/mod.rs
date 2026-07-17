use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::borrow::{Borrow, BorrowMut};

use itertools::Itertools;
use miden_air::{
    CoreCols, Felt, StackCols, SystemCols,
    trace::{
        DECODER_TRACE_WIDTH, MIN_TRACE_LEN, MainTrace, RANGE_CHECK_TRACE_WIDTH, RowIndex,
        STACK_TRACE_WIDTH, SYS_TRACE_WIDTH, decoder::NUM_OP_BITS,
    },
};
use miden_core::{
    ONE, Word, ZERO,
    field::{PrimeCharacteristicRing, batch_inversion_allow_zeros},
    mast::{ExecutableMastForest, MastForestId, MastNode, SparseMastForest},
    operations::opcodes,
    program::{KernelDescriptor, MIN_STACK_DEPTH},
    utils::Idx,
};
use rayon::prelude::*;
use tracing::instrument;

use super::{
    chiplets::Chiplets,
    execution_tracer::TraceGenerationContext,
    trace_state::{
        AceReplay, BitwiseOp, BitwiseReplay, CoreTraceFragmentContext, CoreTraceState,
        ExecutionReplay, HasherOp, HasherRequestReplay, KernelReplay, MemoryWritesReplay,
        RangeCheckerReplay,
    },
};
use crate::{
    ContextId, ExecutionError,
    continuation_stack::{Continuation, ContinuationStack},
    errors::MapExecErrNoCtx,
    trace::{
        ChipletsLengths, ExecutionTrace, TraceBuildInputs, TraceLenSummary,
        parallel::{processor::ReplayProcessor, tracer::CoreTraceGenerationTracer},
        range::RangeChecker,
        utils::RowMajorTraceWriter,
    },
};

/// Per-row payload written by the core tracer (system + decoder + stack).
pub const CORE_TRACE_WIDTH: usize = SYS_TRACE_WIDTH + DECODER_TRACE_WIDTH + STACK_TRACE_WIDTH;

/// Physical row width of the core buffer: the [`CORE_TRACE_WIDTH`] payload plus the two
/// trailing range-checker columns, which together form the per-AIR Core matrix
/// (`NUM_CORE_COLS`) consumed directly by proving. The range columns are filled in-place
/// after padding (see `write_range_into_core`).
pub const CORE_STORAGE_WIDTH: usize = CORE_TRACE_WIDTH + RANGE_CHECK_TRACE_WIDTH;

/// `build_trace()` uses this as a hard cap on trace rows.
///
/// The code checks `core_trace_contexts.len() * fragment_size` before allocation. It checks the
/// same cap again while replaying chiplet activity. This keeps memory use bounded.
const MAX_TRACE_LEN: usize = 1 << 29;

pub(crate) mod core_trace_fragment;

mod processor;
mod tracer;

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
/// let program = Assembler::default()
///     .assemble_program("prg", "begin push.1 drop end")
///     .unwrap()
///     .unwrap_program();
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

    let TraceGenerationContext {
        core_trace_contexts,
        mast_forest_store,
        range_checker_replay,
        memory_writes,
        bitwise_replay: bitwise,
        kernel_replay,
        hasher_for_chiplet,
        ace_replay,
        fragment_size,
        max_stack_depth,
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
        &mast_forest_store,
        max_trace_len,
    )?;

    let range_checker = initialize_range_checker(range_checker_replay, &chiplets);

    let mut core_trace_data = generate_core_trace_row_major(
        core_trace_contexts,
        program_info.kernel().clone(),
        fragment_size,
        &mast_forest_store,
        max_stack_depth,
    )?;

    let core_trace_len = core_trace_data.len() / CORE_STORAGE_WIDTH;

    // Get the number of rows for the range checker
    let range_table_len = range_checker.get_number_range_checker_rows();

    let core_height = pad_to_trace_length(core_trace_len.max(range_table_len));
    let chiplets_height = pad_to_trace_length(chiplets.trace_len());
    let poseidon2_permutation_trace_len = chiplets.poseidon2_permutation_trace_len();
    let poseidon2_permutation_height = pad_to_trace_length(poseidon2_permutation_trace_len);
    let padded_trace_len = core_height.max(chiplets_height).max(poseidon2_permutation_height);

    // Cap check against the padded height: pad-up can push over MAX_TRACE_LEN even
    // when the unpadded check above passed.
    if padded_trace_len > max_trace_len {
        return Err(ExecutionError::TraceLenExceeded(max_trace_len));
    }

    let trace_len_summary = TraceLenSummary::new_with_padded(
        core_trace_len,
        range_table_len,
        ChipletsLengths::new(&chiplets),
        poseidon2_permutation_trace_len,
        padded_trace_len,
    );

    // Each segment is built at its own per-AIR height (no cross-padding to the unified max).
    let ((chiplets_trace, poseidon2_permutation_trace), ()) = rayon::join(
        || chiplets.into_traces(chiplets_height, poseidon2_permutation_height),
        || pad_core_row_major(&mut core_trace_data, core_height),
    );

    // The range checker occupies the two trailing columns of the core buffer.
    range_checker.write_range_into_core(
        &mut core_trace_data,
        CORE_STORAGE_WIDTH,
        CORE_TRACE_WIDTH,
        CORE_TRACE_WIDTH + 1,
        range_table_len,
        core_height,
    );

    // Create the MainTrace
    let main_trace = {
        let last_program_row = RowIndex::from((core_trace_len as u32).saturating_sub(1));
        MainTrace::from_parts(
            core_trace_data,
            chiplets_trace.trace,
            poseidon2_permutation_trace.trace,
            last_program_row,
        )
    };

    Ok(ExecutionTrace::new_from_parts(
        program_info,
        trace_output,
        main_trace,
        trace_len_summary,
    ))
}

// HELPERS
// ================================================================================================

/// Pad a logical row count to a valid trace length: next power of two, clamped to `MIN_TRACE_LEN`.
fn pad_to_trace_length(logical_len: usize) -> usize {
    logical_len.next_power_of_two().max(MIN_TRACE_LEN)
}

/// Generates row-major core trace in parallel from the provided trace fragment contexts.
fn generate_core_trace_row_major(
    core_trace_contexts: Vec<CoreTraceFragmentContext>,
    kernel: KernelDescriptor,
    fragment_size: usize,
    mast_forest_store: &[Arc<SparseMastForest>],
    max_stack_depth: usize,
) -> Result<Vec<Felt>, ExecutionError> {
    let num_fragments = core_trace_contexts.len();
    let total_allocated_rows = num_fragments * fragment_size;

    let mut core_trace_data = Felt::zero_vec(total_allocated_rows * CORE_STORAGE_WIDTH);

    // Save the first stack top for initialization
    let first_stack_top = if let Some(first_context) = core_trace_contexts.first() {
        first_context.state.stack.stack_top.to_vec()
    } else {
        vec![ZERO; MIN_STACK_DEPTH]
    };

    let writers: Vec<RowMajorTraceWriter<'_, Felt>> = core_trace_data
        .chunks_exact_mut(fragment_size * CORE_STORAGE_WIDTH)
        .map(|chunk| {
            RowMajorTraceWriter::with_stride(chunk, CORE_STORAGE_WIDTH, CORE_STORAGE_WIDTH)
        })
        .collect();

    // Build the core trace fragments in parallel
    let fragment_results: Result<Vec<_>, ExecutionError> = core_trace_contexts
        .into_par_iter()
        .zip(writers.into_par_iter())
        .map(|(trace_state, writer)| {
            let (mut processor, mut tracer, mut continuation_stack, mut current_forest) =
                split_trace_fragment_context(
                    trace_state,
                    writer,
                    fragment_size,
                    mast_forest_store,
                    max_stack_depth,
                )?;

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
    let mut total_core_trace_rows = 0;

    for final_state in fragment_results {
        stack_rows.push(final_state.last_stack_cols);
        system_rows.push(final_state.last_system_cols);
        total_core_trace_rows += final_state.num_rows_written;
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
        let w = CORE_STORAGE_WIDTH;
        core_trace_data[..total_core_trace_rows * w]
            .par_chunks_mut(fragment_size * w)
            .for_each(|fragment_chunk| {
                let num_rows = fragment_chunk.len() / w;
                let mut h0_vals: Vec<Felt> = (0..num_rows)
                    .map(|r| {
                        let row: &CoreCols<Felt> = fragment_chunk[r * w..(r + 1) * w].borrow();
                        row.stack.h0
                    })
                    .collect();
                batch_inversion_allow_zeros(&mut h0_vals);
                for (r, &val) in h0_vals.iter().enumerate() {
                    let row: &mut CoreCols<Felt> = fragment_chunk[r * w..(r + 1) * w].borrow_mut();
                    row.stack.h0 = val;
                }
            });
    }

    // Truncate the core trace columns to the actual number of rows written.
    core_trace_data.truncate(total_core_trace_rows * CORE_STORAGE_WIDTH);

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
    stack_rows: &[StackCols<Felt>],
    system_rows: &[SystemCols<Felt>],
    first_stack_top: &[Felt],
) {
    const MIN_STACK_DEPTH_FELT: Felt = Felt::new_unchecked(MIN_STACK_DEPTH as u64);
    let w = CORE_STORAGE_WIDTH;

    {
        let row: &mut CoreCols<Felt> = core_trace_data[..w].borrow_mut();

        // Stack order in the trace is reversed vs `first_stack_top`.
        for (stack_col_idx, &value) in first_stack_top.iter().rev().enumerate() {
            row.stack.top[stack_col_idx] = value;
        }

        row.stack.b0 = MIN_STACK_DEPTH_FELT;
        row.stack.b1 = ZERO;
        row.stack.h0 = ZERO;
    }

    let total_rows = core_trace_data.len() / w;
    let num_fragments = total_rows / fragment_size;

    for frag_idx in 1..num_fragments {
        let row_idx = frag_idx * fragment_size;
        let row_start = row_idx * w;
        let row: &mut CoreCols<Felt> = core_trace_data[row_start..row_start + w].borrow_mut();
        row.system = system_rows[frag_idx - 1].clone();
        row.stack = stack_rows[frag_idx - 1].clone();
    }
}

/// Appends a HALT row (`num_rows_before` is the row count before append).
///
/// This ensures that the trace ends with at least one HALT operation, which is necessary to satisfy
/// the constraints.
fn push_halt_opcode_row(
    core_trace_data: &mut Vec<Felt>,
    num_rows_before: usize,
    last_system_state: &SystemCols<Felt>,
    last_stack_state: &StackCols<Felt>,
) {
    let w = CORE_STORAGE_WIDTH;
    let mut row_data = [ZERO; CORE_STORAGE_WIDTH];

    // Read the previous row's hasher state first half before we take a mutable borrow on
    // `row_data` (propagates the program hash into the HALT padding).
    let prev_hasher_state_first_half: [Felt; 4] = if num_rows_before > 0 {
        let last_row_start = (num_rows_before - 1) * w;
        let prev: &CoreCols<Felt> = core_trace_data[last_row_start..last_row_start + w].borrow();
        let hs = &prev.decoder.hasher_state;
        [hs[0], hs[1], hs[2], hs[3]]
    } else {
        [ZERO; 4]
    };

    {
        let row: &mut CoreCols<Felt> = row_data.as_mut_slice().borrow_mut();

        row.system = last_system_state.clone();
        row.stack = last_stack_state.clone();

        // Pad op_bits columns with HALT opcode bits
        let halt_opcode = opcodes::HALT;
        for bit_idx in 0..NUM_OP_BITS {
            row.decoder.op_bits[bit_idx] = Felt::from_u8((halt_opcode >> bit_idx) & 1);
        }

        // Pad hasher state columns (8 columns)
        // - First 4 columns: copy the last value (to propagate program hash)
        // - Remaining 4 columns: fill with ZEROs
        row.decoder.hasher_state[..4].copy_from_slice(&prev_hasher_state_first_half);

        // Pad op_bit_extra columns (2 columns)
        // - First column: do nothing (pre-filled with ZEROs, HALT doesn't use this)
        // - Second column: fill with ONEs (product of two most significant HALT bits, both are 1)
        row.decoder.extra[1] = ONE;
    }

    core_trace_data.extend_from_slice(&row_data);
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
    for values in range_checker_replay {
        range_checker.add_range_checks(&values);
    }

    // Add all memory-related range checks
    chiplets.append_range_checks(&mut range_checker);

    range_checker
}

/// Replays recorded operations to populate chiplet traces. Results were already used during
/// execution; this pass only needs the trace-recording side effects.
fn initialize_chiplets(
    kernel: KernelDescriptor,
    core_trace_contexts: &[CoreTraceFragmentContext],
    memory_writes: MemoryWritesReplay,
    bitwise: BitwiseReplay,
    kernel_replay: KernelReplay,
    hasher_for_chiplet: HasherRequestReplay,
    ace_replay: AceReplay,
    mast_forest_store: &[Arc<SparseMastForest>],
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
            HasherOp::HashBasicBlock((forest_id, node_id, expected_hash)) => {
                let forest =
                    mast_forest_store.get(forest_id.to_usize()).ok_or(ExecutionError::Internal(
                        "MAST forest id in hasher replay out of range of mast_forest_store",
                    ))?;
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

/// Pads the core trace to `core_height` rows (HALT template, CLK incremented per row).
fn pad_core_row_major(core_trace_data: &mut Vec<Felt>, core_height: usize) {
    let w = CORE_STORAGE_WIDTH;
    let total_program_rows = core_trace_data.len() / w;
    assert!(total_program_rows <= core_height);
    assert!(total_program_rows > 0);

    let num_padding_rows = core_height - total_program_rows;
    if num_padding_rows == 0 {
        return;
    }
    let last_row_start = (total_program_rows - 1) * w;

    // Safety: per our documented safety guarantees, we know that `total_program_rows > 0`,
    // and row `total_program_rows - 1` is initialized.
    let (last_hasher_first_half, last_stack): ([Felt; 4], StackCols<Felt>) = {
        let last: &CoreCols<Felt> = core_trace_data[last_row_start..last_row_start + w].borrow();
        let hs = &last.decoder.hasher_state;
        let last_hasher: [Felt; 4] = [hs[0], hs[1], hs[2], hs[3]];
        (last_hasher, last.stack.clone())
    };

    let mut template_data = [ZERO; CORE_STORAGE_WIDTH];
    {
        let template: &mut CoreCols<Felt> = template_data.as_mut_slice().borrow_mut();

        // Decoder columns
        // ------------------------

        // Pad op_bits columns with HALT opcode bits
        let halt_opcode = opcodes::HALT;
        for i in 0..NUM_OP_BITS {
            template.decoder.op_bits[i] = Felt::from_u8((halt_opcode >> i) & 1);
        }
        // Pad hasher state columns (8 columns)
        // - First 4 columns: copy the last value (to propagate program hash)
        // - Remaining 4 columns: fill with ZEROs
        template.decoder.hasher_state[..4].copy_from_slice(&last_hasher_first_half);

        // Pad op_bit_extra columns (2 columns)
        // - First column: do nothing (filled with ZEROs, HALT doesn't use this)
        // - Second column: fill with ONEs (product of two most significant HALT bits, both are 1)
        template.decoder.extra[1] = ONE;

        // Stack columns
        // ------------------------

        // Pad stack columns with the last value in each column (analogous to Stack::into_trace())
        template.stack = last_stack;
    }

    // System columns
    // ------------------------

    // Pad CLK trace - fill with index values

    let pad_start = total_program_rows * w;
    core_trace_data.resize(pad_start + num_padding_rows * w, ZERO);
    core_trace_data[pad_start..]
        .par_chunks_mut(w)
        .enumerate()
        .for_each(|(idx, row_buf)| {
            row_buf.copy_from_slice(&template_data);
            let row: &mut CoreCols<Felt> = row_buf.borrow_mut();
            row.system.clk = Felt::from_u32((total_program_rows + idx) as u32);
        });
}

type SplitFragmentContext<'a> = (
    ReplayProcessor,
    CoreTraceGenerationTracer<'a>,
    ContinuationStack<Arc<SparseMastForest>>,
    Arc<SparseMastForest>,
);

/// Uses the provided `CoreTraceFragmentContext` to build and return a `ReplayProcessor` and
/// `CoreTraceGenerationTracer` that can be used to execute the fragment.
///
/// `mast_forest_store` provides the [`SparseMastForest`]s that the indices stored in the fragment
/// (the initial forest index and the `EnterForest` continuations) refer to.
///
/// # Errors
///
/// Returns [`ExecutionError::Internal`] if any [`MastForestId`] referenced by the fragment
/// (either `initial_mast_forest_id` or an `EnterForest` continuation) is out of range of
/// `mast_forest_store`. Because [`CoreTraceFragmentContext`] is attacker-controllable when fed in
/// from outside, we validate these indices rather than indexing-and-panicking.
fn split_trace_fragment_context<'a>(
    fragment_context: CoreTraceFragmentContext,
    writer: RowMajorTraceWriter<'a, Felt>,
    fragment_size: usize,
    mast_forest_store: &[Arc<SparseMastForest>],
    max_stack_depth: usize,
) -> Result<SplitFragmentContext<'a>, ExecutionError> {
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
        initial_mast_forest_id,
    } = fragment_context;

    let translated_continuation =
        translate_snapshot_continuation_stack(continuation, mast_forest_store)?;

    let initial_mast_forest =
        lookup_mast_forest(mast_forest_store, initial_mast_forest_id)?.clone();

    let processor = ReplayProcessor::new(
        system,
        stack,
        stack_overflow_replay,
        execution_context_replay,
        advice_replay,
        memory_reads_replay,
        hasher_response_replay,
        mast_forest_resolution_replay,
        mast_forest_store.to_vec(),
        max_stack_depth,
        fragment_size.into(),
    );
    let tracer =
        CoreTraceGenerationTracer::new(writer, decoder, block_address_replay, block_stack_replay);

    Ok((processor, tracer, translated_continuation, initial_mast_forest))
}

/// Translates a snapshotted `ContinuationStack<MastForestId>` into one carrying actual
/// [`Arc<SparseMastForest>`] handles, ready to drive `execute_impl`.
///
/// Returns [`ExecutionError::Internal`] if any `EnterForest` continuation carries a
/// [`MastForestId`] that is out of range of `mast_forest_store`.
fn translate_snapshot_continuation_stack(
    snapshot: ContinuationStack<MastForestId>,
    mast_forest_store: &[Arc<SparseMastForest>],
) -> Result<ContinuationStack<Arc<SparseMastForest>>, ExecutionError> {
    let mut out: ContinuationStack<Arc<SparseMastForest>> = ContinuationStack::default();
    for cont in snapshot.into_inner() {
        let translated = match cont {
            Continuation::EnterForest { forest: id, package_debug_info } => {
                Continuation::EnterForest {
                    forest: lookup_mast_forest(mast_forest_store, id)?.clone(),
                    package_debug_info,
                }
            },
            Continuation::StartNode(id) => Continuation::StartNode(id),
            Continuation::FinishJoin(id) => Continuation::FinishJoin(id),
            Continuation::FinishSplit(id) => Continuation::FinishSplit(id),
            Continuation::FinishLoop(node_id) => Continuation::FinishLoop(node_id),
            Continuation::FinishCall(id) => Continuation::FinishCall(id),
            Continuation::FinishDyn(id) => Continuation::FinishDyn(id),
            Continuation::ResumeBasicBlock { node_id, batch_index, op_idx_in_batch } => {
                Continuation::ResumeBasicBlock { node_id, batch_index, op_idx_in_batch }
            },
            Continuation::Respan { node_id, batch_index } => {
                Continuation::Respan { node_id, batch_index }
            },
            Continuation::FinishBasicBlock(id) => Continuation::FinishBasicBlock(id),
        };
        out.push_continuation(translated);
    }
    Ok(out)
}

/// Looks up `id` in `mast_forest_store`, returning [`ExecutionError::Internal`] if it is out of
/// range.
pub(super) fn lookup_mast_forest(
    mast_forest_store: &[Arc<SparseMastForest>],
    id: MastForestId,
) -> Result<&Arc<SparseMastForest>, ExecutionError> {
    mast_forest_store
        .get(id.to_usize())
        .ok_or(ExecutionError::Internal("MastForestId out of range of mast_forest_store"))
}
