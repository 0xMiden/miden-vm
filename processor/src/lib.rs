#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::vec::Vec;
use core::{
    fmt::{Display, LowerHex},
    ops::ControlFlow,
};

mod chiplets;
mod continuation_stack;
mod debug;
mod decoder;
mod errors;
mod execution;
mod execution_options;
mod host;
mod range;
mod stack;
mod system;

pub mod fast;
pub mod parallel;
pub mod processor;
pub mod trace;
pub mod tracer;
pub mod utils;

use crate::{
    advice::{AdviceInputs, AdviceProvider},
    fast::{FastProcessor, step::BreakReason},
    field::PrimeField64,
    processor::{Processor, SystemInterface},
    trace::{ExecutionTrace, RowIndex},
};

#[cfg(test)]
mod test_utils;

#[cfg(test)]
mod tests;

// RE-EXPORTS
// ================================================================================================

pub use chiplets::MemoryError;
pub use errors::{
    ExecutionError, MapExecErr, MapExecErrNoCtx, MapExecErrWithOpIdx, OperationError,
};
pub use execution_options::{ExecutionOptions, ExecutionOptionsError};
pub use host::{
    FutureMaybeSend, Host, MastForestStore, MemMastForestStore,
    debug::DefaultDebugHandler,
    default::{DefaultHost, HostLibrary},
    handlers::{DebugError, DebugHandler, TraceError},
};
pub use miden_core::{
    EMPTY_WORD, Felt, ONE, WORD_SIZE, Word, ZERO, crypto, field, mast,
    operations::{AssemblyOp, Operation},
    precompile,
    program::{InputError, Kernel, Program, ProgramInfo, StackInputs, StackOutputs},
    serde,
};
pub use system::ContextId;

pub mod advice {
    pub use miden_core::advice::{AdviceInputs, AdviceMap, AdviceStackBuilder};

    pub use super::host::{
        AdviceMutation,
        advice::{AdviceError, AdviceProvider},
    };
}

pub mod event {
    pub use miden_core::events::*;

    pub use crate::host::handlers::{
        EventError, EventHandler, EventHandlerRegistry, NoopEventHandler,
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

    let trace = parallel::build_trace(
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
        self.processor.advice_provider()
    }

    /// Returns a mutable reference to the advice provider.
    #[inline(always)]
    pub fn advice_provider_mut(&mut self) -> &mut AdviceProvider {
        self.processor.advice_provider_mut()
    }

    /// Returns the current clock cycle of a process.
    #[inline(always)]
    pub fn clock(&self) -> RowIndex {
        self.processor.clock()
    }

    /// Returns the current execution context ID.
    #[inline(always)]
    pub fn ctx(&self) -> ContextId {
        self.processor.ctx()
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
        self.processor.memory().read_element_impl(ctx, addr)
    }

    /// Returns the batch of elements starting at the specified context/address.
    ///
    /// # Errors
    /// - If the address is not word aligned.
    #[inline(always)]
    pub fn get_mem_word(&self, ctx: ContextId, addr: u32) -> Result<Option<Word>, MemoryError> {
        self.processor.memory().read_word_impl(ctx, addr)
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
        self.processor.memory().get_memory_state(ctx)
    }
}

// STOPPER
// ===============================================================================================

/// A trait for types that determine whether execution should be stopped at a given point.
pub trait Stopper {
    type Processor: Processor;

    /// Determines whether execution should be stopped.
    ///
    /// The `continuation_after_stop` is provided in cases where simply resuming execution from the
    /// top of the continuation stack is not sufficient to continue execution correctly. For
    /// example, when stopping execution in the middle of a basic block, we need to provide a
    /// `ResumeBasicBlock` continuation to ensure that execution resumes at the correct operation
    /// within the basic block (i.e. the operation right after the one that was last executed before
    /// being stopped). No continuation is provided in case of error, since it is expected that
    /// execution will not be resumed.
    fn should_stop(
        &self,
        processor: &Self::Processor,
        continuation_after_stop: impl FnOnce() -> Option<continuation_stack::Continuation>,
    ) -> ControlFlow<BreakReason>;
}
