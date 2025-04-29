use alloc::{collections::BTreeMap, vec::Vec};
use vm_core::{PrimeField64, ExtensionField};

use super::{Felt, ZERO};

// OVERFLOW TABLE
// ================================================================================================

/// Stores stack values beyond the top 16 elements as well as the data which can be used in
/// construction of the auxiliary trace column describing the state of the overflow table at every
/// VM cycle.
///
/// When `trace_enabled` is set to true, we also record all changes to the table so that we can
/// reconstruct the overflow table at any clock cycle. This can be used for debugging purposes.
#[derive(Debug)]
pub struct OverflowTable {
    /// A list of all rows that were added to and then removed from the overflow table.
    all_rows: Vec<OverflowTableRow>,
    /// A list of indices into the `all_rows` vector which describes the rows currently in the
    /// overflow table.
    active_rows: Vec<usize>,
    /// A map which records the full state of the overflow table at every cycle during which an
    /// update happened. This map is populated only when `trace_enabled` = true.
    trace: BTreeMap<u64, Vec<Felt>>,
    /// A flag which specifies whether we should record the full state of the overflow table
    /// whenever an update happens. This is set to true only when executing programs for debug
    /// purposes.
    trace_enabled: bool,
    /// Holds the address (the clock cycle) of the row at to top of the overflow table. When
    /// entering new execution context, this value is set to ZERO, and thus, will differ from the
    /// row address actually at the top of the table.
    last_row_addr: Felt,
}

impl OverflowTable {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------
    /// Returns a new [OverflowTable]. The returned table is empty.
    pub fn new(enable_trace: bool) -> Self {
        Self {
            all_rows: Vec::new(),
            active_rows: Vec::new(),
            trace: BTreeMap::new(),
            trace_enabled: enable_trace,
            last_row_addr: ZERO,
        }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Pushes the specified value into the overflow table.
    ///
    /// Parameter clk specifies the clock cycle at which the value is added to the table.
    pub fn push(&mut self, value: Felt, clk: Felt) {
        // ZERO address indicates that the overflow table is empty, and thus, no actual value
        // should be inserted into the table with this address. This is not a problem since for
        // every real program, we first execute an operation marking the start of a code block,
        // and thus, no operation can shift the stack to the right at clk = 0.
        debug_assert_ne!(clk, ZERO, "cannot add value to overflow at clk=0");

        // create and record the new row, and also put it at the top of the overflow table
        let row_idx = self.all_rows.len() as u32;
        let new_row = OverflowTableRow::new(clk, value, self.last_row_addr);
        self.all_rows.push(new_row);
        self.active_rows.push(row_idx as usize);

        // set the last row address to the address of the newly added row
        self.last_row_addr = clk;

        if self.trace_enabled {
            // insert a copy of the current table state into the trace
            self.save_current_state(clk.as_canonical_u64());
        }
    }

    /// Removes the last value from the overflow table and returns it.
    pub fn pop(&mut self, clk: u64) -> Felt {
        // if last_row_addr is ZERO, any rows in the overflow table are not accessible from the
        // current context. Thus, we should not be able to remove them.
        debug_assert_ne!(
            self.last_row_addr, ZERO,
            "overflow table is empty in the current context"
        );

        // remove the top entry from the table and determine which table row corresponds to it
        let last_row_idx = self.active_rows.pop().expect("overflow table is empty");
        let last_row = &self.all_rows[last_row_idx];

        // get the value from the last row and also update the last row address to point to the
        // row currently at the top of the table. note that this is context specific. that is,
        // last row address points to the next row in the current execution context.
        let removed_value = last_row.val;
        self.last_row_addr = last_row.prev;

        if self.trace_enabled {
            // insert a copy of the current table state into the trace
            self.save_current_state(clk);
        }

        // return the removed value
        removed_value
    }

    /// Set the last row address pointer to the specified value.
    ///
    /// This can be used to indicate start/end of an execution context. Specifically:
    /// - Setting the last row address to ZERO has the effect of clearing the overflow table
    ///   (without actually removing the values from it).
    /// - Changing the last row address to the address of the row actually at the top of the table
    ///   has the effect of restoring the previous context.
    pub fn set_last_row_addr(&mut self, last_row_addr: Felt) {
        if last_row_addr != ZERO {
            // if we are not setting the last row address to ZERO, we can set it only to the
            // address of the row actually at the top of the table.
            let last_row_idx = *self.active_rows.last().expect("overflow table is empty");
            assert_eq!(self.all_rows[last_row_idx].clk, last_row_addr);
        }
        self.last_row_addr = last_row_addr;
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns address of the row at the top of the overflow table.
    ///
    /// If the overflow table in the current execution context is empty, this will return ZERO,
    /// even if the overall overflow table contains values.
    pub fn last_row_addr(&self) -> Felt {
        self.last_row_addr
    }

    /// Appends the values from the overflow table to the end of the provided vector.
    pub fn append_into(&self, target: &mut Vec<Felt>) {
        for &idx in self.active_rows.iter().rev() {
            target.push(self.all_rows[idx].val);
        }
    }

    /// Appends the state of the overflow table at the specified clock cycle to the provided vector.
    ///
    /// # Panics
    /// Panics when this overflow table was not initialized with `enable_trace` set to true.
    pub fn append_state_into(&self, target: &mut Vec<Felt>, clk: u64) {
        assert!(self.trace_enabled, "overflow trace not enabled");
        if let Some(x) = self.trace.range(0..=clk).last() {
            for item in x.1.iter().rev() {
                target.push(*item);
            }
        }
    }

    /// Returns the number of overflowing stack elements at the current clock cycle.
    pub fn num_active_rows(&self) -> usize {
        self.active_rows.len()
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Saves a copy of the current table state into the trace at the specified clock cycle.
    fn save_current_state(&mut self, clk: u64) {
        debug_assert!(self.trace_enabled, "overflow table trace not enabled");
        let current_state = self.active_rows.iter().map(|&idx| self.all_rows[idx].val).collect();
        self.trace.insert(clk, current_state);
    }

    // TEST ACCESSORS
    // --------------------------------------------------------------------------------------------

    #[cfg(test)]
    pub fn all_rows(&self) -> &[OverflowTableRow] {
        &self.all_rows
    }

    #[cfg(test)]
    pub fn active_rows(&self) -> &[usize] {
        &self.active_rows
    }
}

// OVERFLOW TABLE ROW
// ================================================================================================

/// A single row in the stack overflow table. Each row contains the following values:
/// - The value of the stack item pushed into the overflow table.
/// - The clock cycle at which the stack item was pushed into the overflow table.
/// - The clock cycle of the value which was at the top of the overflow table when this value was
///   pushed onto it.
#[derive(Debug, PartialEq, Eq)]
pub struct OverflowTableRow {
    val: Felt,
    clk: Felt,
    prev: Felt,
}

impl OverflowTableRow {
    pub fn new(clk: Felt, val: Felt, prev: Felt) -> Self {
        Self { val, clk, prev }
    }
}

impl OverflowTableRow {
    /// Reduces this row to a single field element in the field specified by E. This requires
    /// at least 4 alpha values.
    pub fn to_value<E: ExtensionField<Felt>>(&self, alphas: &[E]) -> E {
        alphas[0]
            + alphas[1] * self.clk
            + alphas[2] * self.val
            + alphas[3] * self.prev
    }
}
