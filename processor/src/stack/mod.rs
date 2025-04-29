use std::println;

use alloc::vec::Vec;

use miden_air::RowIndex;
use vm_core::{stack::MIN_STACK_DEPTH, PrimeCharacteristicRing, Word, WORD_SIZE};

use super::{
    ExecutionError, Felt, ONE, STACK_TRACE_WIDTH, StackInputs, StackOutputs, ZERO,
};

mod trace;
use trace::StackTrace;

mod overflow;
use overflow::OverflowTable;
pub use overflow::OverflowTableRow;

mod aux_trace;
pub use aux_trace::AuxTraceBuilder;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// The last stack index accessible by the VM.
const MAX_TOP_IDX: usize = MIN_STACK_DEPTH - 1;

// STACK
// ================================================================================================

/// Stack for the VM.
///
/// This component is responsible for managing the state of the VM's stack, as well as building an
/// execution trace for all stack transitions.
///
/// The state is separated into two parts: the top 16 slots of the stack (stored in the `trace`
/// member), and items which don't fit into the top 16 slots (stored in the `overflow` member).
///
/// The depth of the stack can never drop below 16. If an item is removed from the stack when the
/// depth is 16, a ZERO element is inserted into the 16th slot.
///
/// ## Execution trace
/// The stack execution trace consists of 19 columns as illustrated below:
///
///   s0   s1   s2        s13   s14   s15   b0   b1   h0
/// ├────┴────┴────┴ ... ┴────┴─────┴─────┴────┴────┴────┤
///
/// The meaning of the above columns is as follows:
/// - s0...s15 are the columns representing the top 16 slots of the stack.
/// - Bookkeeping column b0 contains the number of items on the stack (i.e., the stack depth).
/// - Bookkeeping column b1 contains an address of a row in the “overflow table” in which we’ll
///   store the data that doesn’t fit into the top 16 slots. When b1=0, it means that all stack data
///   fits into the top 16 slots of the stack.
/// - Helper column h0 is used to ensure that stack depth does not drop below 16. Values in this
///   column are set by the prover non-deterministically to 1 / (b0−16) when b0 != 16, and to any
///   other value otherwise.
#[derive(Debug)]
pub struct Stack {
    clk: RowIndex,
    trace: StackTrace,
    overflow: OverflowTable,
    active_depth: usize,
    full_depth: usize,
}

impl Stack {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a [Stack] initialized with the specified program inputs.
    pub fn new(
        inputs: &StackInputs,
        init_trace_capacity: usize,
        keep_overflow_trace: bool,
    ) -> Self {
        let overflow = OverflowTable::new(keep_overflow_trace);
        let trace = StackTrace::new(&**inputs, init_trace_capacity, MIN_STACK_DEPTH, ZERO);

        Self {
            clk: RowIndex::from(0),
            trace,
            overflow,
            active_depth: MIN_STACK_DEPTH,
            full_depth: MIN_STACK_DEPTH,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns depth of the stack at the current clock cycle.
    pub fn depth(&self) -> usize {
        self.active_depth
    }

    /// Returns the current clock cycle of the execution trace.
    pub fn current_clk(&self) -> RowIndex {
        self.clk
    }

    /// Returns execution trace length for this stack.
    ///
    /// Trace length of the stack is equal to the number of cycles executed by the VM.
    pub fn trace_len(&self) -> usize {
        self.clk.into()
    }

    /// Returns a copy of the item currently at the top of the stack.
    pub fn peek(&self) -> Felt {
        self.trace.peek_at(self.clk)
    }

    /// Returns stack state at the specified clock cycle. This includes the top 16 items of the
    /// stack + overflow entries.
    ///
    /// # Panics
    /// Panics if invoked for non-last clock cycle on a stack instantiated with
    /// `keep_overflow_trace` set to false.
    pub fn get_state_at(&self, clk: RowIndex) -> Vec<Felt> {
        let mut result = Vec::with_capacity(self.active_depth);
        self.trace.append_state_into(&mut result, clk);
        if clk == self.clk {
            self.overflow.append_into(&mut result);
        } else {
            self.overflow.append_state_into(&mut result, clk.into());
        }

        result
    }

    /// Returns [StackOutputs] consisting of all values on the stack.
    ///
    /// # Errors
    /// Returns an error if the overflow table is not empty at the current clock cycle.
    pub fn build_stack_outputs(&self) -> Result<StackOutputs, ExecutionError> {
        println!("stack is {:?}", self.get_state_at(self.clk));
        if self.overflow.num_active_rows() != 0 {
            return Err(ExecutionError::OutputStackOverflow(self.overflow.num_active_rows()));
        }

        let mut stack_items = Vec::with_capacity(self.active_depth);
        self.trace.append_state_into(&mut stack_items, self.clk);
        Ok(StackOutputs::new(stack_items).expect("processor stack handling logic is valid"))
    }

    // TRACE ACCESSORS AND MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Returns the value located at the specified position on the stack at the current clock cycle.
    pub fn get(&self, pos: usize) -> Felt {
        debug_assert!(pos < MIN_STACK_DEPTH, "stack underflow");
        self.trace.get_stack_value_at(self.clk, pos)
    }

    /// Returns a word located at the specified word index on the stack.
    ///
    /// Specifically, word 0 is defined by the first 4 elements of the stack, word 1 is defined
    /// by the next 4 elements etc. Since the top of the stack contains 4 word, the highest valid
    /// word index is 3.
    ///
    /// The words are created in reverse order. For example, for word 0 the top element of the
    /// stack will be at the last position in the word.
    ///
    /// Creating a word does not change the state of the stack.
    pub fn get_word(&self, word_idx: usize) -> Word {
        let offset = word_idx * WORD_SIZE;
        [
            self.get(offset + 3),
            self.get(offset + 2),
            self.get(offset + 1),
            self.get(offset),
        ]
    }

    /// Sets the value at the specified position on the stack at the next clock cycle.
    pub fn set(&mut self, pos: usize, value: Felt) {
        debug_assert!(pos < MIN_STACK_DEPTH, "stack underflow");
        self.trace.set_stack_value_at(self.clk + 1, pos, value);
    }

    /// Copies stack values starting at the specified position at the current clock cycle to the
    /// same position at the next clock cycle.
    pub fn copy_state(&mut self, start_pos: usize) {
        self.trace.copy_stack_state_at(
            self.clk.into(),
            start_pos,
            // TODO: change type of `active_depth` to `u32`
            // TODO(Al)
            // Felt::try_from(self.active_depth as u64)
            //    .expect("value is greater than or equal to the field modulus"),
            Felt::from_u64(self.active_depth as u64),
            self.overflow.last_row_addr(),
        );
    }

    /// Copies stack values starting at the specified position at the current clock cycle to
    /// position - 1 at the next clock cycle.
    ///
    /// If the stack depth is greater than 16, an item is moved from the overflow table to the
    /// "in-memory" portion of the stack. If the stack depth is 16, the 16th element of the
    /// stack is set to ZERO.
    pub fn shift_left(&mut self, start_pos: usize) {
        debug_assert!(start_pos > 0, "start position must be greater than 0");
        debug_assert!(start_pos <= MIN_STACK_DEPTH, "start position cannot exceed stack top size");

        let (next_depth, next_overflow_addr) = self.shift_left_no_helpers(start_pos);
        self.trace.set_helpers_at(self.clk.as_usize(), next_depth, next_overflow_addr);
    }

    /// Copies stack values starting at the specified position at the current clock cycle to
    /// position + 1 at the next clock cycle
    ///
    /// If stack depth grows beyond 16 items, the additional item is pushed into the overflow table.
    pub fn shift_right(&mut self, start_pos: usize) {
        debug_assert!(start_pos < MIN_STACK_DEPTH, "start position cannot exceed stack top size");

        // Update the stack.
        self.trace.stack_shift_right_at(self.clk, start_pos);

        // Update the overflow table.
        let to_overflow = self.trace.get_stack_value_at(self.clk, MAX_TOP_IDX);
        self.overflow.push(to_overflow, Felt::from(self.clk));

        // Stack depth always increases on right shift.
        self.active_depth += 1;
        self.full_depth += 1;
    }

    /// Shifts the stack left, and returns the value for the helper columns B0 and B1, without
    /// writing them to the trace.
    fn shift_left_no_helpers(&mut self, start_pos: usize) -> (Felt, Felt) {
        match self.active_depth {
            0..=MAX_TOP_IDX => unreachable!("stack underflow"),
            MIN_STACK_DEPTH => {
                // Shift in a ZERO, to prevent depth shrinking below the minimum stack depth.
                self.trace.stack_shift_left_no_helpers(self.clk, start_pos, ZERO, None)
            },
            _ => {
                // Update the stack & overflow table.
                let from_overflow = self.overflow.pop(u64::from(self.clk));
                let helpers = self.trace.stack_shift_left_no_helpers(
                    self.clk,
                    start_pos,
                    from_overflow,
                    Some(self.overflow.last_row_addr()),
                );

                // Stack depth only decreases when it is greater than the minimum stack depth.
                self.active_depth -= 1;
                self.full_depth -= 1;

                helpers
            },
        }
    }

    // CONTEXT MANAGEMENT
    // --------------------------------------------------------------------------------------------

    /// Shifts the stack left, writes the default values for the stack helper registers in the trace
    /// (stack depth and next overflow address), and returns the value of those helper registers
    /// before the new context wipe.
    ///
    /// This specialized method is needed because the other ones write the updated helper register
    /// values directly to the trace in the next row. However, the dyncall instruction needs to
    /// shift the stack left, and start a new context simultaneously (and hence reset the stack
    /// helper registers to their default value). It is assumed that the caller will write the
    /// return values somewhere else in the trace.
    pub fn shift_left_and_start_context(&mut self) -> (usize, Felt) {
        const START_POSITION: usize = 1;

        self.shift_left_no_helpers(START_POSITION);

        // reset the helper columns to their default value, and write those to the trace in the next
        // row.
        let (next_depth, next_overflow_addr) = self.start_context();
        // Note: `start_context()` reset `active_depth` to 16, and `overflow.last_row_addr` to 0.
        self.trace.set_helpers_at(
            self.clk.as_usize(),
            Felt::from_u32(self.active_depth as u32),
            self.overflow.last_row_addr(),
        );

        // return the helper registers' state before the new context
        (next_depth, next_overflow_addr)
    }

    /// Starts a new execution context for this stack and returns a tuple consisting of the current
    /// stack depth and the address of the overflow table row prior to starting the new context.
    ///
    /// This has the effect of hiding the contents of the overflow table such that it appears as
    /// if the overflow table in the new context is empty.
    pub fn start_context(&mut self) -> (usize, Felt) {
        let current_depth = self.active_depth;
        let current_overflow_addr = self.overflow.last_row_addr();
        self.active_depth = MIN_STACK_DEPTH;
        self.overflow.set_last_row_addr(ZERO);
        (current_depth, current_overflow_addr)
    }

    /// Restores the prior context for this stack.
    ///
    /// This has the effect bringing back items previously hidden from the overflow table.
    pub fn restore_context(&mut self, stack_depth: usize, next_overflow_addr: Felt) {
        debug_assert!(stack_depth <= self.full_depth, "stack depth too big");
        debug_assert_eq!(self.active_depth, MIN_STACK_DEPTH, "overflow table not empty");
        self.active_depth = stack_depth;
        self.overflow.set_last_row_addr(next_overflow_addr);
    }

    // TRACE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Returns an execution trace of the top 16 stack slots and helper columns as a single array
    /// together with hints to be used in construction of stack-related auxiliary trace segment
    /// columns.
    ///
    /// If the stack trace is smaller than the specified `trace_len`, last value in each column is
    /// duplicated until the length of the columns reaches `trace_len`.
    ///
    /// `num_rand_rows` indicates the number of rows at the end of the trace which will be
    /// overwritten with random values. This parameter is unused because last rows are just
    /// duplicates of the prior rows and thus can be safely overwritten.
    pub fn into_trace(self, trace_len: usize, num_rand_rows: usize) -> super::StackTrace {
        let clk = self.current_clk().as_usize();
        // make sure that only the duplicate rows will be overwritten with random values
        assert!(clk + num_rand_rows <= trace_len, "target trace length too small");

        // at the end of program execution we must be in the root context, and thus active and
        // full stack depth must be the same.
        assert_eq!(self.active_depth, self.full_depth, "inconsistent stack depth");

        // fill in all trace columns after the last clock cycle with the value at the last clock
        // cycle
        let mut trace = self.trace.into_array();
        for column in trace.iter_mut() {
            let last_value = column[clk];
            column[clk..].fill(last_value);
            column.resize(trace_len, last_value);
        }

        super::StackTrace { trace }
    }

    // UTILITY METHODS
    // --------------------------------------------------------------------------------------------

    /// Makes sure there is enough memory allocated for the trace to accommodate a new row.
    ///
    /// Trace length is doubled every time it needs to be increased.
    pub fn ensure_trace_capacity(&mut self) {
        self.trace.ensure_trace_capacity(self.clk);
    }

    /// Increments the clock cycle.
    pub fn advance_clock(&mut self) {
        self.clk += 1;
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns state of stack item columns at the current clock cycle. This does not include stack
    /// values in the overflow table.
    #[cfg(any(test, feature = "testing"))]
    pub fn trace_state(&self) -> [Felt; MIN_STACK_DEPTH] {
        self.trace.get_stack_state_at(self.clk)
    }

    /// Returns state of helper columns at the current clock cycle.
    #[cfg(test)]
    pub fn helpers_state(&self) -> [Felt; miden_air::trace::stack::NUM_STACK_HELPER_COLS] {
        self.trace.get_helpers_state_at(self.clk)
    }
}
