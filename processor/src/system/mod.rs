use alloc::vec::Vec;
use core::fmt::{self, Display};

use miden_air::RowIndex;

use super::{EMPTY_WORD, ExecutionError, Felt, FieldElement, SysTrace, Word, ZERO};

#[cfg(test)]
mod tests;

// SYSTEM INFO
// ================================================================================================

/// System info container for the VM.
///
/// This keeps track of the following system variables:
/// - clock cycle (clk), which starts at 0 and is incremented with every step.
/// - execution context (ctx), which starts at 0 (root context), and changes when CALL or SYSCALL
///   operations are executed by the VM (or when we return from a CALL or SYSCALL).
/// - free memory pointer (fmp), which is initially set to 2^30.
/// - hash of the function which initiated the current execution context. if the context was
///   initiated from the root context, this will be set to ZEROs.
#[derive(Debug)]
pub struct System {
    clk: RowIndex,
    ctx: ContextId,
    fn_hash: Word,
    ctx_trace: Vec<Felt>,
    clk_trace: Vec<Felt>,
    fn_hash_trace: [Vec<Felt>; 4],
}

impl System {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [System] struct with execution traces instantiated with the specified length.
    ///
    /// Initializes the free memory pointer `fmp` used for local memory offsets to 2^30.
    pub fn new(init_trace_capacity: usize) -> Self {
        Self {
            clk: RowIndex::from(0),
            ctx: ContextId::root(),
            fn_hash: EMPTY_WORD,
            clk_trace: vec![Felt::ZERO; init_trace_capacity],
            ctx_trace: vec![Felt::ZERO; init_trace_capacity],
            fn_hash_trace: [
                vec![Felt::ZERO; init_trace_capacity],
                vec![Felt::ZERO; init_trace_capacity],
                vec![Felt::ZERO; init_trace_capacity],
                vec![Felt::ZERO; init_trace_capacity],
            ],
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the current clock cycle of a process.
    #[inline(always)]
    pub fn clk(&self) -> RowIndex {
        self.clk
    }

    /// Returns the current execution context ID.
    #[inline(always)]
    pub fn ctx(&self) -> ContextId {
        self.ctx
    }

    /// Returns hash of the function which initiated the current execution context.
    #[inline(always)]
    pub fn fn_hash(&self) -> Word {
        self.fn_hash
    }

    /// Returns execution trace length for the systems columns of the process.
    ///
    /// Trace length of the system columns is equal to the number of cycles executed by the VM.
    #[inline(always)]
    pub fn trace_len(&self) -> usize {
        self.clk.into()
    }

    /// Returns execution context ID at the specified clock cycle.
    #[inline(always)]
    pub fn get_ctx_at(&self, clk: RowIndex) -> ContextId {
        (self.ctx_trace[clk.as_usize()].as_int() as u32).into()
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Increments the clock cycle.
    pub fn advance_clock(&mut self, max_cycles: u32) -> Result<(), ExecutionError> {
        self.clk += 1_u32;

        // Check that maximum number of cycles is not exceeded.
        if self.clk.as_u32() > max_cycles {
            return Err(ExecutionError::CycleLimitExceeded(max_cycles));
        }

        let clk: usize = self.clk.into();

        self.clk_trace[clk] = Felt::from(self.clk);
        self.ctx_trace[clk] = Felt::from(self.ctx);

        self.fn_hash_trace[0][clk] = self.fn_hash[0];
        self.fn_hash_trace[1][clk] = self.fn_hash[1];
        self.fn_hash_trace[2][clk] = self.fn_hash[2];
        self.fn_hash_trace[3][clk] = self.fn_hash[3];

        Ok(())
    }

    /// Updates system registers to mark a new function call.
    ///
    /// Internally, this performs the following updates:
    /// - Set the execution context to the current clock cycle + 1. This ensures that the context is
    ///   globally unique as is never set to 0.
    /// - Sets the free memory pointer to its initial value (FMP_MIN).
    /// - Sets the hash of the function which initiated the current context to the provided value.
    ///
    /// A CALL or DYNCALL cannot be started when the VM is executing a SYSCALL.
    pub fn start_call_or_dyncall(&mut self, fn_hash: Word) {
        self.ctx = self.get_next_ctx_id();
        self.fn_hash = fn_hash;
    }

    /// Updates system registers to mark a new syscall.
    ///
    /// Internally, this performs the following updates:
    /// - Set the execution context to 0 (the root context).
    /// - Sets the free memory pointer to the initial value of syscalls (SYSCALL_FMP_MIN). This
    ///   ensures that procedure locals within a syscall do not conflict with procedure locals of
    ///   the original root context.
    ///
    /// A SYSCALL cannot be started when the VM is executing a SYSCALL.
    ///
    /// Note that this does not change the hash of the function which initiated the context:
    /// for SYSCALLs this remains set to the hash of the last invoked function.
    pub fn start_syscall(&mut self) {
        self.ctx = ContextId::root();
    }

    /// Updates system registers to the provided values. These updates are made at the end of a
    /// CALL or a SYSCALL blocks.
    pub fn restore_context(&mut self, ctx: ContextId, fn_hash: Word) {
        self.ctx = ctx;
        self.fn_hash = fn_hash;
    }

    // TRACE GENERATIONS
    // --------------------------------------------------------------------------------------------

    /// Returns an execution trace of this system info container.
    ///
    /// If the trace is smaller than the specified `trace_len`, the columns of the trace are
    /// extended to match the specified length as follows:
    /// - the remainder of the `clk` column is filled in with increasing values of `clk`.
    /// - the remainder of the `ctx` column is filled in with ZERO, which should be the last value
    ///   in the column.
    /// - the remainder of the `fn_hash` columns are filled with ZERO, which should be the last
    ///   values in these columns.
    ///
    /// `num_rand_rows` indicates the number of rows at the end of the trace which will be
    /// overwritten with random values. This parameter is unused because last rows are just
    /// duplicates of the prior rows and thus can be safely overwritten.
    pub fn into_trace(mut self, trace_len: usize, num_rand_rows: usize) -> SysTrace {
        let clk: usize = self.clk().into();
        // make sure that only the duplicate rows will be overwritten with random values
        assert!(clk + num_rand_rows <= trace_len, "target trace length too small");

        // complete the clk column by filling in all values after the last clock cycle. The values
        // in the clk column are equal to the index of the row in the trace table.
        self.clk_trace.resize(trace_len, ZERO);
        for (i, clk) in self.clk_trace.iter_mut().enumerate().skip(clk) {
            // converting from u32 is OK here because max trace length is 2^32
            *clk = Felt::from(i as u32);
        }

        // complete the ctx column by filling all values after the last clock cycle with ZEROs as
        // the last context must be zero context.
        debug_assert!(self.ctx.is_root());
        self.ctx_trace.resize(trace_len, ZERO);

        let mut trace = vec![self.clk_trace, self.ctx_trace];

        // complete the fn hash columns by filling them with ZEROs as program execution must always
        // end in the root context.
        debug_assert_eq!(self.fn_hash, EMPTY_WORD);
        for mut column in self.fn_hash_trace.into_iter() {
            column.resize(trace_len, ZERO);
            trace.push(column);
        }

        trace.try_into().expect("failed to convert vector to array")
    }

    // UTILITY METHODS
    // --------------------------------------------------------------------------------------------

    /// Makes sure there is enough memory allocated for the trace to accommodate a new row.
    ///
    /// Trace length is doubled every time it needs to be increased.
    pub fn ensure_trace_capacity(&mut self) {
        let current_capacity = self.clk_trace.len();
        if self.clk + 1 >= RowIndex::from(current_capacity) {
            let new_length = current_capacity * 2;
            self.clk_trace.resize(new_length, ZERO);
            self.ctx_trace.resize(new_length, ZERO);
            for column in self.fn_hash_trace.iter_mut() {
                column.resize(new_length, ZERO);
            }
        }
    }

    /// Returns the next context ID that would be created given the current state.
    ///
    /// Note: This only applies to the context created upon a `CALL` or `DYNCALL` operation;
    /// specifically the `SYSCALL` operation doesn't apply as it always goes back to the root
    /// context.
    pub fn get_next_ctx_id(&self) -> ContextId {
        (self.clk + 1).into()
    }
}

// EXECUTION CONTEXT
// ================================================================================================

/// Represents the ID of an execution context
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct ContextId(u32);

impl ContextId {
    /// Returns the root context ID
    pub fn root() -> Self {
        Self(0)
    }

    /// Returns true if the context ID represents the root context
    pub fn is_root(&self) -> bool {
        self.0 == 0
    }
}

impl From<RowIndex> for ContextId {
    fn from(value: RowIndex) -> Self {
        Self(value.as_u32())
    }
}

impl From<u32> for ContextId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<ContextId> for u32 {
    fn from(context_id: ContextId) -> Self {
        context_id.0
    }
}

impl From<ContextId> for u64 {
    fn from(context_id: ContextId) -> Self {
        context_id.0.into()
    }
}

impl From<ContextId> for Felt {
    fn from(context_id: ContextId) -> Self {
        context_id.0.into()
    }
}

impl Display for ContextId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
