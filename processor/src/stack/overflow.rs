use alloc::vec::Vec;

use miden_air::RowIndex;
use miden_utils_indexing::IndexVec;

use super::{Felt, ZERO};

// OVERFLOW TABLE
// ================================================================================================

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
    // --------------------------------------------------------------------------------------------

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

    /// Returns an iterator over the elements in the overflow stack.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &OverflowStackEntry> {
        self.overflow.as_slice().iter()
    }

    // PUBLIC MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Pushes a value onto the overflow stack.
    pub fn push(&mut self, entry: OverflowStackEntry) {
        let _ = self.overflow.push(entry);
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
    clk: RowIndex,
    history: Option<OverflowTableHistory>,
}

impl OverflowTable {
    /// Creates a new empty overflow table.
    ///
    /// If `save_history` is set to true, the table will keep track of the history of the overflow
    /// table at every clock cycle. This is used for debugging purposes.
    pub fn new(save_history: bool) -> Self {
        let mut overflow = IndexVec::new();
        let _ = overflow.push(OverflowStack::new());

        Self {
            overflow,
            clk: RowIndex::from(0),
            history: save_history.then(OverflowTableHistory::new),
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Appends the values from the overflow stack corresponding to the current context to the end
    /// of the provided vector.
    pub fn append_into(&self, target: &mut Vec<Felt>) {
        let current_overflow_stack = self.get_current_overflow_stack();
        target.extend(current_overflow_stack.iter().rev().map(OverflowStackEntry::value));
    }

    /// Appends the values from the overflow table at the given clock cycle to the end of the
    /// provided vector.
    ///
    /// # Panics
    /// - if the overflow history is not enabled.
    pub fn append_from_history_at(&self, clk: RowIndex, target: &mut Vec<Felt>) {
        let history = self.history.as_ref().expect("overflow history not enabled");

        let overflow_at_clk = history.get_at(clk);
        target.extend(overflow_at_clk);
    }

    /// Returns the clock cycle at which the latest overflow table entry was added in the current
    /// context.
    ///
    /// Hence, if no entries were added to the overflow table in the current context, ZERO is
    /// returned.
    pub fn last_update_clk_in_current_ctx(&self) -> Felt {
        self.get_current_overflow_stack()
            .last()
            .map_or(ZERO, |entry| Felt::from(entry.clk))
    }

    /// Returns the total number of elements in the overflow table across all stacks in all
    /// contexts.
    pub fn total_num_elements(&self) -> usize {
        self.overflow.iter().map(OverflowStack::num_elements).sum::<usize>()
    }

    /// Returns the element at the specified index in the current overflow stack.
    ///
    /// The index is relative to the logical stack continuation, where index 0 corresponds to
    /// the most recently pushed item (top of overflow stack), index 1 to the second most recent,
    /// etc. Returns None if the index is out of bounds.
    pub fn get_element_at(&self, index: usize) -> Option<Felt> {
        let current_stack = self.get_current_overflow_stack();
        let len = current_stack.num_elements();

        if index >= len {
            None
        } else {
            // The overflow stack stores items in push order, but logically we want to access
            // them in reverse order (most recent first), so we reverse the index
            let actual_index = RowIndex::from(len - 1 - index);
            current_stack.overflow.get(actual_index).map(|entry| entry.value)
        }
    }

    /// Returns the number of elements in the overflow stack for the current context.
    pub fn num_elements_in_current_ctx(&self) -> usize {
        self.get_current_overflow_stack().num_elements()
    }

    // PUBLIC MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Pushes a value into the overflow table in the current context.
    pub fn push(&mut self, value: Felt) {
        // 1. push value
        let clk = self.clk;
        self.get_current_overflow_stack_mut().push(OverflowStackEntry::new(value, clk));

        // 2. save history
        self.save_stack_to_history();
    }

    /// Removes the last value from the overflow table in the current context, if any, and returns
    /// it.
    pub fn pop(&mut self) -> Option<Felt> {
        // 1. pop value
        let value_popped = self
            .get_current_overflow_stack_mut()
            .pop()
            .as_ref()
            .map(OverflowStackEntry::value);

        // 2. save history
        self.save_stack_to_history();

        value_popped
    }

    /// Starts the specified context.
    ///
    /// Subsequent calls to `push` and `pop` will affect the overflow table in this context.
    ///
    /// Note: It is possible to return to context 0 with a syscall; in this case, each instantiation
    /// of context 0 will get a separate overflow table.
    pub fn start_context(&mut self) {
        // 1. Initialize the overflow stack for the new context.
        let _ = self.overflow.push(OverflowStack::new());

        // 2. save history
        self.save_stack_to_history();
    }

    /// Restores the specified context.
    ///
    /// # Panics
    /// - if there is no overflow stack for the current context.
    /// - if the overflow stack for the current context is not empty.
    ///   - i.e. this should be checked before calling this function.
    pub fn restore_context(&mut self) {
        // 1. pop the last overflow stack for the current context, and make sure it is empty.
        let overflow_stack_for_ctx = self.overflow.swap_remove(self.overflow.len() - 1);
        assert!(
            overflow_stack_for_ctx.is_empty(),
            "the overflow stack for the current context should be empty when restoring a context"
        );

        // 2. save history
        self.save_stack_to_history();
    }

    /// Increments the clock cycle.
    pub fn advance_clock(&mut self) {
        self.clk += 1_u32;
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the overflow stack for the current context.
    ///
    /// Specifically, this is a reference to the more recent overflow stack in the list of overflow
    /// stacks for the current context. Recall that for all contexts other than the root context,
    /// there is at most one overflow stack, but for the root context, there can be two.
    fn get_current_overflow_stack(&self) -> &OverflowStack {
        self.overflow
            .as_slice()
            .last()
            .expect("The current context should always have an overflow stack initialized")
    }

    /// Mutable version of `get_current_overflow_stack()`.
    fn get_current_overflow_stack_mut(&mut self) -> &mut OverflowStack {
        let len = self.overflow.len();
        &mut self.overflow[RowIndex::from(len - 1)]
    }

    /// Saves the overflow stack in the current context to the history.
    ///
    /// It is important that this function is called after the overflow stack is updated, so that
    /// the history is saved after the update. This is done in the `push`, `pop`, `start_context`,
    /// and `restore_context` functions.
    fn save_stack_to_history(&mut self) {
        let clk = self.clk;
        let stack_after_op: Vec<Felt> = self
            .get_current_overflow_stack()
            .iter()
            .map(OverflowStackEntry::value)
            .collect();

        if let Some(history) = &mut self.history {
            history.save_stack_to_history(clk, stack_after_op);
        }
    }
}

impl Default for OverflowTable {
    fn default() -> Self {
        Self::new(false)
    }
}

/// Stores the history of the overflow table at every clock cycle, where only the relevant context
/// is stored in the history for each clock cycle.
///
/// The events which update the overflow table history are:
/// - `push` operation,
/// - `pop` operation,
/// - a new context is started,
/// - a former context is restored.
#[derive(Debug, Clone)]
struct OverflowTableHistory {
    /// Stores the full state of the overflow table for every clock cycle at which there was a
    /// change.
    history: Vec<(RowIndex, Vec<Felt>)>,
}

impl OverflowTableHistory {
    /// Creates a new empty overflow table history.
    pub fn new() -> Self {
        // The initial overflow table at the start of the program is empty, and the clock cycle is
        // 0.
        let init_overflow = (RowIndex::from(0), vec![]);

        Self { history: vec![init_overflow] }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the overflow table at the given clock cycle in the active context at that clock
    /// cycle.
    ///
    /// The first element returned by the iterator is the top of the overflow table.
    pub fn get_at(&self, target_clk: RowIndex) -> impl Iterator<Item = &Felt> {
        match self.history.binary_search_by_key(&target_clk, |entry| entry.0) {
            Ok(idx) => self.history[idx].1.iter().rev(),
            Err(insertion_idx) => {
                if insertion_idx > 0 {
                    self.history[insertion_idx - 1].1.iter().rev()
                } else {
                    [].iter().rev()
                }
            },
        }
    }

    // PUBLIC MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Saves the current state of the overflow table at the given clock cycle to the history.
    ///
    /// That is, `stack` is the state of the overflow table at the given clock cycle *after* the
    /// update.
    pub fn save_stack_to_history(&mut self, clk: RowIndex, stack: Vec<Felt>) {
        // The unwrap is OK because we always have at least one entry in the history. When `clk` is
        // the same as the last clock cycle in the history,this indicates that the overflow stack
        // was updated twice in the same clock cycle, which only occurs with the `DYNCALL`
        // operation. In this case, we just ignore the 2nd update.
        if let Some(last_entry) = self.history.last()
            && last_entry.0 == clk
        {
            return;
        }

        self.history.push((clk, stack));
    }
}
