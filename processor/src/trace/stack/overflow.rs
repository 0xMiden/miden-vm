use miden_air::trace::RowIndex;
use miden_utils_indexing::IndexVec;

use super::{Felt, ZERO};
use crate::operation::OperationError;

// OVERFLOW TABLE
// ================================================================================

/// An element of an overflow stack.
///
/// Stores the value pushed on an overflow stack, and the clock cycle at which it was pushed.
#[derive(Debug, Clone, Default)]
struct OverflowStackEntry {
    pub value: Felt,
    pub clk: RowIndex,
}

impl OverflowStackEntry {
    pub fn new(value: Felt, clk: RowIndex) -> Self {
        Self { value, clk }
    }

    pub fn value(&self) -> Felt {
        self.value
    }
}

/// Represents an overflow stack at a given context.
#[derive(Debug, Default, Clone)]
struct OverflowStack {
    overflow: IndexVec<RowIndex, OverflowStackEntry>,
}

impl OverflowStack {
    pub fn new() -> Self {
        Self { overflow: IndexVec::new() }
    }

    // PUBLIC ACCESSORS
    // ----------------------------------------------------------------------------

    /// Returns the last value in the overflow stack, if any.
    pub fn last(&self) -> Option<&OverflowStackEntry> {
        self.overflow.as_slice().last()
    }

    /// Returns the number of elements in the overflow stack.
    pub fn num_elements(&self) -> usize {
        self.overflow.len()
    }

    pub fn is_empty(&self) -> bool {
        self.overflow.is_empty()
    }

    // PUBLIC MUTATORS
    // ----------------------------------------------------------------------------

    /// Pushes a value onto the overflow stack.
    pub fn push(&mut self, entry: OverflowStackEntry) {
        let _ = self.overflow.push(entry); // discard returned index
    }

    /// Pops a value from the overflow stack, if any.
    pub fn pop(&mut self) -> Option<OverflowStackEntry> {
        if self.overflow.is_empty() {
            None
        } else {
            Some(self.overflow.swap_remove(self.overflow.len() - 1))
        }
    }
}

/// An overflow table which stores the values of the stack elements that overflow the top 16
/// elements of the stack per context.
///
/// This overflow table does not keep track of the clock cycles at which the values were added or
/// removed from the table; it is only concerned with the state at the latest clock cycle.
///
/// The overflow table keeps track of the current clock cycle, and hence `advance_clock()` must be
/// called whenever the clock cycle is incremented globally.
#[derive(Debug, Clone)]
pub struct OverflowTable {
    overflow: IndexVec<RowIndex, OverflowStack>,
}

impl OverflowTable {
    /// Creates a new empty overflow table.
    ///
    /// If `save_history` is set to true, the table will keep track of the history of the overflow
    /// table at every clock cycle. This is used for debugging purposes.
    pub fn new() -> Self {
        let mut overflow = IndexVec::new();
        let _ = overflow.push(OverflowStack::new()); // discard returned index

        Self { overflow }
    }

    // PUBLIC ACCESSORS
    // ----------------------------------------------------------------------------

    /// Returns the clock cycle at which the latest overflow table entry was added in the current
    /// context.
    ///
    /// Hence, if no entries were added to the overflow table in the current context, ZERO is
    /// returned.
    pub fn last_update_clk_in_current_ctx(&self) -> Felt {
        self.get_current_overflow_stack()
            .expect("overflow table should always have at least one stack")
            .last()
            .map_or(ZERO, |entry| Felt::from(entry.clk))
    }

    /// Returns the clock cycle that would become the new `last_update_clk_in_current_ctx` after
    /// one pop from the current overflow stack, *without* actually mutating the table.
    ///
    /// Concretely this is the clock of the **second-to-last** entry in the current overflow stack,
    /// or `ZERO` if the stack has fewer than two entries (i.e. the stack would be empty after the
    /// pop).
    ///
    /// Used by `ExecutionTracer` to compute `parent_next_overflow_addr` for `DYNCALL` before
    /// the actual pop has occurred (fixes #2813 / addresses huitseeker's review on PR #2904).
    pub fn clk_after_pop_in_current_ctx(&self) -> Felt {
        let stack = self
            .get_current_overflow_stack()
            .expect("overflow table should always have at least one stack");
        let entries = stack.overflow.as_slice();
        if entries.len() < 2 {
            ZERO
        } else {
            Felt::from(entries[entries.len() - 2].clk)
        }
    }

    /// Returns the number of elements in the overflow stack for the current context.
    pub fn num_elements_in_current_ctx(&self) -> usize {
        self.get_current_overflow_stack()
            .expect("overflow table should always have at least one stack")
            .num_elements()
    }

    // PUBLIC MUTATORS
    // ----------------------------------------------------------------------------

    /// Pushes a value into the overflow table in the current context.
    pub fn push(&mut self, value: Felt, clk: RowIndex) {
        self.get_current_overflow_stack_mut()
            .expect("overflow table should always have at least one stack")
            .push(OverflowStackEntry::new(value, clk));
    }

    /// Removes the last value from the overflow table in the current context, if any, and returns
    /// it.
    pub fn pop(&mut self) -> Option<Felt> {
        self.get_current_overflow_stack_mut()
            .expect("overflow table should always have at least one stack")
            .pop()
            .as_ref()
            .map(OverflowStackEntry::value)
    }

    /// Starts the specified context.
    ///
    /// Subsequent calls to `push` and `pop` will affect the overflow table in this context.
    ///
    /// Note: It is possible to return to context 0 with a syscall; in this case, each instantiation
    /// of context 0 will get a separate overflow table.
    pub fn start_context(&mut self) {
        let _ = self.overflow.push(OverflowStack::new()); // discard returned index
    }

    /// Restores the specified context.
    ///
    /// Returns an error if the overflow table has no stacks (i.e. there is no current context)
    /// or if the overflow stack for the current context is not empty (i.e. the caller should
    /// have drained it before calling this function).
    pub fn restore_context(&mut self) -> Result<(), OperationError> {
        let len = self.overflow.len();

        // Ensure there is at least one overflow stack to restore.
        if len <= 1 {
            return Err(OperationError::Internal(
                "cannot restore context: must have at least one child context above the root stack",
            ));
        }

        // Check that the current context's overflow stack is empty *before* removing it,
        // so that we don't lose data if the check fails.
        let is_empty = self.overflow.as_slice().last().expect("len > 0").is_empty();
        if !is_empty {
            return Err(OperationError::Internal(
                "cannot restore context: overflow stack for the current context is not empty",
            ));
        }

        // Safe to remove now — the stack is confirmed empty.
        self.overflow.swap_remove(len - 1);
        Ok(())
    }

    // HELPERS
    // ----------------------------------------------------------------------------

    /// Returns the overflow stack for the current context.
    ///
    /// Specifically, this is a reference to the more recent overflow stack in the list of overflow
    /// stacks for the current context. Recall that for all contexts other than the root context,
    /// there is at most one overflow stack, but for the root context, there can be two.
    fn get_current_overflow_stack(&self) -> Result<&OverflowStack, OperationError> {
        self.overflow.as_slice().last().ok_or(OperationError::Internal(
            "the current context should always have an overflow stack initialized",
        ))
    }

    /// Mutable version of `get_current_overflow_stack()`.
    fn get_current_overflow_stack_mut(&mut self) -> Result<&mut OverflowStack, OperationError> {
        let len = self.overflow.len();
        if len == 0 {
            return Err(OperationError::Internal(
                "the current context should always have an overflow stack initialized",
            ));
        }
        Ok(&mut self.overflow[RowIndex::from(len - 1)])
    }
}

impl Default for OverflowTable {
    fn default() -> Self {
        Self::new()
    }
}
