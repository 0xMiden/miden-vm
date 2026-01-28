#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::vec::Vec;
use core::fmt::{Display, LowerHex};

pub use miden_air::trace::RowIndex;
use miden_air::trace::{CHIPLETS_WIDTH, RANGE_CHECK_TRACE_WIDTH};

mod execution_options;
pub use execution_options::{
    DEFAULT_CORE_TRACE_FRAGMENT_SIZE, ExecutionOptions, ExecutionOptionsError,
};
pub use miden_core::{
    AssemblyOp, EMPTY_WORD, Felt, Kernel, ONE, Operation, Program, ProgramInfo, StackInputs,
    StackOutputs, WORD_SIZE, Word, ZERO,
    crypto::merkle::SMT_DEPTH,
    errors::InputError,
    field::{PrimeField64, QuadFelt},
    mast::{MastForest, MastNode, MastNodeExt, MastNodeId},
    precompile::{PrecompileRequest, PrecompileTranscriptState},
    sys_events::SystemEvent,
    utils::DeserializationError,
};

pub(crate) mod continuation_stack;

pub mod fast;
pub mod parallel;
pub(crate) mod processor;

mod operations;

pub(crate) mod row_major_adapter;

mod system;
pub use system::ContextId;

#[cfg(test)]
mod test_utils;

pub(crate) mod decoder;

mod stack;

mod range;
use range::RangeChecker;

mod host;

pub use host::{
    AdviceMutation, FutureMaybeSend, Host, MastForestStore, MemMastForestStore,
    advice::{AdviceError, AdviceInputs, AdviceProvider, AdviceStackBuilder},
    debug::DefaultDebugHandler,
    default::{DefaultHost, HostLibrary},
    handlers::{
        DebugError, DebugHandler, EventError, EventHandler, EventHandlerRegistry, NoopEventHandler,
        TraceError,
    },
};

mod chiplets;
pub use chiplets::MemoryError;

mod trace;
use trace::TraceFragment;
pub use trace::{ChipletsLengths, ExecutionTrace, TraceLenSummary};

mod errors;
pub use errors::{
    ExecutionError, MapExecErr, MapExecErrNoCtx, MapExecErrWithOpIdx, OperationError,
};

pub mod utils;

#[cfg(test)]
mod tests;

mod debug;

use crate::{fast::FastProcessor, parallel::build_trace};

// RE-EXPORTS
// ================================================================================================

pub mod math {
    pub use miden_core::Felt;
}

pub mod crypto {
    pub use miden_core::crypto::{
        hash::{Blake3_256, Poseidon2, Rpo256, Rpx256},
        merkle::{
            MerkleError, MerklePath, MerkleStore, MerkleTree, NodeIndex, PartialMerkleTree,
            SimpleSmt,
        },
        random::{RpoRandomCoin, RpxRandomCoin},
    };
}

// TYPE ALIASES
// ================================================================================================

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct MemoryAddress(u32);

impl From<u32> for MemoryAddress {
    fn from(addr: u32) -> Self {
        MemoryAddress(addr)
    }
}

impl From<MemoryAddress> for u32 {
    fn from(value: MemoryAddress) -> Self {
        value.0
    }
}

impl Display for MemoryAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl LowerHex for MemoryAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&self.0, f)
    }
}

impl core::ops::Add<MemoryAddress> for MemoryAddress {
    type Output = Self;

    fn add(self, rhs: MemoryAddress) -> Self::Output {
        MemoryAddress(self.0 + rhs.0)
    }
}

impl core::ops::Add<u32> for MemoryAddress {
    type Output = Self;

    fn add(self, rhs: u32) -> Self::Output {
        MemoryAddress(self.0 + rhs)
    }
}

pub struct RangeCheckTrace {
    trace: [Vec<Felt>; RANGE_CHECK_TRACE_WIDTH],
    aux_builder: range::AuxTraceBuilder,
}

pub struct ChipletsTrace {
    trace: [Vec<Felt>; CHIPLETS_WIDTH],
    aux_builder: chiplets::AuxTraceBuilder,
}

// EXECUTORS
// ================================================================================================

/// Returns an execution trace resulting from executing the provided program against the provided
/// inputs.
///
/// This is an async function that works on all platforms including wasm32.
///
/// The `host` parameter is used to provide the external environment to the program being executed,
/// such as access to the advice provider and libraries that the program depends on.
///
/// # Errors
/// Returns an error if program execution fails for any reason.
#[tracing::instrument("execute_program", skip_all)]
pub async fn execute(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut impl Host,
    options: ExecutionOptions,
) -> Result<ExecutionTrace, ExecutionError> {
    let processor = FastProcessor::new_with_options(stack_inputs, advice_inputs, options);
    let (execution_output, trace_generation_context) =
        processor.execute_for_trace(program, host).await?;

    let trace = build_trace(
        execution_output,
        trace_generation_context,
        program.hash(),
        program.kernel().clone(),
    );

    assert_eq!(&program.hash(), trace.program_hash(), "inconsistent program hash");
    Ok(trace)
}

/// Synchronous wrapper for the async `execute()` function.
///
/// This method is only available on non-wasm32 targets. On wasm32, use the async `execute()`
/// method directly since wasm32 runs in the browser's event loop.
///
/// # Panics
/// Panics if called from within an existing Tokio runtime. Use the async `execute()` method
/// instead in async contexts.
#[cfg(not(target_arch = "wasm32"))]
#[tracing::instrument("execute_program_sync", skip_all)]
pub fn execute_sync(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut impl Host,
    options: ExecutionOptions,
) -> Result<ExecutionTrace, ExecutionError> {
    match tokio::runtime::Handle::try_current() {
        Ok(_handle) => {
            // We're already inside a Tokio runtime - this is not supported because we cannot
            // safely create a nested runtime or move the non-Send host reference to another thread
            panic!(
                "Cannot call execute_sync from within a Tokio runtime. \
                 Use the async execute() method instead."
            )
        },
        Err(_) => {
            // No runtime exists - create one and use it
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(execute(program, stack_inputs, advice_inputs, host, options))
        },
    }
}

// PROCESSOR STATE
// ===============================================================================================

/// A view into the current state of the processor.
///
/// This struct provides read access to the processor's state, including the stack, memory,
/// advice provider, and execution context information.
#[derive(Debug)]
pub struct ProcessorState<'a> {
    processor: &'a mut FastProcessor,
}

impl<'a> ProcessorState<'a> {
    /// Returns a reference to the advice provider.
    #[inline(always)]
    pub fn advice_provider(&self) -> &AdviceProvider {
        &self.processor.advice
    }

    /// Returns a mutable reference to the advice provider.
    #[inline(always)]
    pub fn advice_provider_mut(&mut self) -> &mut AdviceProvider {
        &mut self.processor.advice
    }

    /// Returns the current clock cycle of a process.
    #[inline(always)]
    pub fn clk(&self) -> RowIndex {
        self.processor.clk
    }

    /// Returns the current execution context ID.
    #[inline(always)]
    pub fn ctx(&self) -> ContextId {
        self.processor.ctx
    }

    /// Returns the value located at the specified position on the stack at the current clock cycle.
    ///
    /// This method can access elements beyond the top 16 positions by using the overflow table.
    #[inline(always)]
    pub fn get_stack_item(&self, pos: usize) -> Felt {
        self.processor.stack_get(pos)
    }

    /// Returns a word starting at the specified element index on the stack.
    ///
    /// The word is formed by taking 4 consecutive elements starting from the specified index.
    /// For example, start_idx=0 creates a word from stack elements 0-3, start_idx=1 creates
    /// a word from elements 1-4, etc.
    ///
    /// Stack element N will be at position 0 of the word, N+1 at position 1, N+2 at position 2,
    /// and N+3 at position 3. `word[0]` corresponds to the top of the stack.
    ///
    /// This method can access elements beyond the top 16 positions by using the overflow table.
    /// Creating a word does not change the state of the stack.
    #[inline(always)]
    pub fn get_stack_word(&self, start_idx: usize) -> Word {
        self.processor.stack_get_word(start_idx)
    }

    /// Returns stack state at the current clock cycle. This includes the top 16 items of the
    /// stack + overflow entries.
    #[inline(always)]
    pub fn get_stack_state(&self) -> Vec<Felt> {
        self.processor.stack().iter().rev().copied().collect()
    }

    /// Returns the element located at the specified context/address, or None if the address hasn't
    /// been accessed previously.
    #[inline(always)]
    pub fn get_mem_value(&self, ctx: ContextId, addr: u32) -> Option<Felt> {
        self.processor.memory.read_element_impl(ctx, addr)
    }

    /// Returns the batch of elements starting at the specified context/address.
    ///
    /// # Errors
    /// - If the address is not word aligned.
    #[inline(always)]
    pub fn get_mem_word(&self, ctx: ContextId, addr: u32) -> Result<Option<Word>, MemoryError> {
        self.processor.memory.read_word_impl(ctx, addr)
    }

    /// Reads (start_addr, end_addr) tuple from the specified elements of the operand stack (
    /// without modifying the state of the stack), and verifies that memory range is valid.
    pub fn get_mem_addr_range(
        &self,
        start_idx: usize,
        end_idx: usize,
    ) -> Result<core::ops::Range<u32>, MemoryError> {
        let start_addr = self.get_stack_item(start_idx).as_canonical_u64();
        let end_addr = self.get_stack_item(end_idx).as_canonical_u64();

        if start_addr > u32::MAX as u64 {
            return Err(MemoryError::AddressOutOfBounds { addr: start_addr });
        }
        if end_addr > u32::MAX as u64 {
            return Err(MemoryError::AddressOutOfBounds { addr: end_addr });
        }

        if start_addr > end_addr {
            return Err(MemoryError::InvalidMemoryRange { start_addr, end_addr });
        }

        Ok(start_addr as u32..end_addr as u32)
    }

    /// Returns the entire memory state for the specified execution context at the current clock
    /// cycle.
    ///
    /// The state is returned as a vector of (address, value) tuples, and includes addresses which
    /// have been accessed at least once.
    #[inline(always)]
    pub fn get_mem_state(&self, ctx: ContextId) -> Vec<(MemoryAddress, Felt)> {
        self.processor.memory.get_memory_state(ctx)
    }
}
