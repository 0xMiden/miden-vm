use alloc::vec::Vec;
use core::ops::Range;

use miden_air::{
    ControllerCols, PermutationCols, borrow_chiplet, borrow_chiplet_mut,
    trace::chiplets::hasher::{HASH_CYCLE_LEN, TRACE_WIDTH},
};
use miden_core::chiplets::hasher::Hasher;

use super::{Felt, HasherState, ONE, STATE_WIDTH, Selectors, TraceFragment, ZERO};

// The unified hasher row is wider than the typed overlay by one column (s_perm).
const S_PERM_OFFSET: usize = TRACE_WIDTH - 1;

// HASHER TRACE
// ================================================================================================

/// Execution trace of the hasher component.
///
/// The trace consists of 20 columns grouped logically as follows:
/// - 3 selector columns (s0, s1, s2).
/// - 12 columns describing hasher state (h0..h11).
/// - 1 node_index column: holds the Merkle tree node index on controller rows. This column is
///   reused to hold the permutation request multiplicity on perm segment rows.
/// - 1 mrupdate_id column (domain separator for sibling table).
/// - 1 is_boundary column (1 on boundary rows: first input or last output, 0 otherwise).
/// - 1 direction_bit column (Merkle direction bit on controller rows, 0 elsewhere).
/// - 1 s_perm column (0 = controller region, 1 = permutation segment).
///
/// The trace is divided into two regions:
/// - Controller region (s_perm=0): pairs of (input, output) rows per permutation request.
/// - Permutation segment (s_perm=1): one 16-row cycle per unique input state.
#[derive(Debug, Default)]
pub struct HasherTrace {
    /// Row-major trace buffer: `TRACE_WIDTH` contiguous cells per row.
    trace: Vec<Felt>,
}

impl HasherTrace {
    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns current length of this execution trace.
    pub fn trace_len(&self) -> usize {
        self.trace.len() / TRACE_WIDTH
    }

    /// Returns the next row address. The address is equal to the current trace length + 1.
    ///
    /// The above means that row addresses start at ONE (rather than ZERO), and are incremented by
    /// ONE at every row. Starting at ONE is needed for the decoder so that the address of the
    /// first code block is a non-zero value.
    pub fn next_row_addr(&self) -> Felt {
        Felt::new_unchecked(self.trace_len() as u64 + 1)
    }

    // CONTROLLER ROW METHODS
    // --------------------------------------------------------------------------------------------

    /// Appends a single controller row to the trace.
    pub fn append_controller_row(
        &mut self,
        selectors: Selectors,
        state: &HasherState,
        node_index: Felt,
        mrupdate_id: Felt,
        is_boundary: Felt,
        direction_bit: Felt,
    ) {
        let mut row = [ZERO; TRACE_WIDTH];
        {
            let (overlay, tail) = row.split_at_mut(S_PERM_OFFSET);
            let cols: &mut ControllerCols<Felt> = borrow_chiplet_mut(overlay);
            cols.s0 = selectors[0];
            cols.s1 = selectors[1];
            cols.s2 = selectors[2];
            cols.state = *state;
            cols.node_index = node_index;
            cols.mrupdate_id = mrupdate_id;
            cols.is_boundary = is_boundary;
            cols.direction_bit = direction_bit;
            tail[0] = ZERO;
        }
        self.trace.extend_from_slice(&row);
    }

    // PERMUTATION SEGMENT METHODS
    // --------------------------------------------------------------------------------------------

    /// Appends a 16-row permutation cycle to the trace.
    ///
    /// The 16-row packed schedule:
    /// - Row 0:     init linear + ext1 (merged)
    /// - Rows 1-3:  ext2, ext3, ext4
    /// - Rows 4-10: 7 packed triples of internal rounds (needs extra witnesses in s0,s1,s2)
    /// - Row 11:    int22 + ext5 (merged, extra witness in s0)
    /// - Rows 12-14: ext6, ext7, ext8
    /// - Row 15:    boundary (final state, no transition)
    ///
    /// The `multiplicity` is stored in the node_index column on all rows of the cycle and constant
    /// within a cycle.
    pub fn append_permutation_cycle(&mut self, init_state: &HasherState, multiplicity: Felt) {
        let mut state = *init_state;

        // Row 0: initial state
        self.append_perm_row_with_witnesses(&state, multiplicity, [ZERO; 3]);

        // Apply init linear + ext1 (merged: M_E, add RC, S-box, M_E)
        Hasher::apply_matmul_external(&mut state);
        Hasher::add_rc(&mut state, &Hasher::ARK_EXT_INITIAL[0]);
        Hasher::apply_sbox(&mut state);
        Hasher::apply_matmul_external(&mut state);

        // Rows 1-3: ext2, ext3, ext4
        for r in 1..=3 {
            self.append_perm_row_with_witnesses(&state, multiplicity, [ZERO; 3]);
            Hasher::add_rc(&mut state, &Hasher::ARK_EXT_INITIAL[r]);
            Hasher::apply_sbox(&mut state);
            Hasher::apply_matmul_external(&mut state);
        }

        // Rows 4-10: packed 3x internal rounds
        for triple in 0..7_usize {
            let base = triple * 3;
            let pre_state = state;
            let mut witnesses = [ZERO; 3];
            for (k, witness) in witnesses.iter_mut().enumerate() {
                // Witness = S-box output for lane 0
                let sbox_out = (state[0] + Hasher::ARK_INT[base + k]).exp_const_u64::<7>();
                *witness = sbox_out;
                state[0] = sbox_out;
                Hasher::matmul_internal(&mut state, Hasher::MAT_DIAG);
            }
            self.append_perm_row_with_witnesses(&pre_state, multiplicity, witnesses);
        }

        // Row 11: int22 + ext5 (merged)
        let pre_state = state;
        let w0 = (state[0] + Hasher::ARK_INT[21]).exp_const_u64::<7>();
        state[0] = w0;
        Hasher::matmul_internal(&mut state, Hasher::MAT_DIAG);
        Hasher::add_rc(&mut state, &Hasher::ARK_EXT_TERMINAL[0]);
        Hasher::apply_sbox(&mut state);
        Hasher::apply_matmul_external(&mut state);
        self.append_perm_row_with_witnesses(&pre_state, multiplicity, [w0, ZERO, ZERO]);

        // Rows 12-14: ext6, ext7, ext8
        for r in 1..=3 {
            self.append_perm_row_with_witnesses(&state, multiplicity, [ZERO; 3]);
            Hasher::add_rc(&mut state, &Hasher::ARK_EXT_TERMINAL[r]);
            Hasher::apply_sbox(&mut state);
            Hasher::apply_matmul_external(&mut state);
        }

        // Row 15: boundary (final state)
        self.append_perm_row_with_witnesses(&state, multiplicity, [ZERO; 3]);
    }

    /// Appends a single permutation segment row (s_perm = 1).
    ///
    /// On permutation rows, `s0, s1, s2` serve as witness columns for packed internal
    /// rounds. The `witnesses` array provides values to write into these columns.
    /// Control columns (mrupdate_id, is_boundary, direction_bit) are zero.
    fn append_perm_row_with_witnesses(
        &mut self,
        state: &HasherState,
        multiplicity: Felt,
        witnesses: [Felt; 3],
    ) {
        let mut row = [ZERO; TRACE_WIDTH];
        {
            let (overlay, tail) = row.split_at_mut(S_PERM_OFFSET);
            let cols: &mut PermutationCols<Felt> = borrow_chiplet_mut(overlay);
            cols.witnesses = witnesses;
            cols.state = *state;
            cols.multiplicity = multiplicity;
            tail[0] = ONE;
        }
        self.trace.extend_from_slice(&row);
    }

    /// Appends padding rows to fill the controller region to a multiple of HASH_CYCLE_LEN.
    ///
    /// Padding rows have all columns set to zero except mrupdate_id, which must carry the
    /// last value to satisfy the AIR progression constraint (mrupdate_id is constant on
    /// non-MV-start transitions).
    pub fn pad_to_cycle_boundary(&mut self, mrupdate_id: Felt) {
        // Padding selectors: [0, 1, 0]. This combination is unused in the controller region
        // (s0=0, s1=1 only appears in perm segment rows which have s_perm=1). Using it
        // prevents padding rows from being mistaken for HOUT output rows ([0,0,0]) by the
        // bus response builder.
        let padding_selectors = [ZERO, ONE, ZERO];

        let remainder = self.trace_len() % HASH_CYCLE_LEN;
        if remainder != 0 {
            let padding_rows = HASH_CYCLE_LEN - remainder;
            for _ in 0..padding_rows {
                self.append_controller_row(
                    padding_selectors,
                    &[ZERO; STATE_WIDTH],
                    ZERO,
                    mrupdate_id,
                    ZERO,
                    ZERO,
                );
            }
        }
    }

    // MEMOIZATION SUPPORT
    // --------------------------------------------------------------------------------------------

    /// Collects input states from controller input rows in the given range.
    ///
    /// A controller input row is identified by s0 == ONE and s_perm == ZERO.
    /// Returns the hasher state for each such row.
    pub fn input_states_in_range(&self, range: Range<usize>) -> Vec<HasherState> {
        const W: usize = TRACE_WIDTH;
        let mut states = Vec::new();
        for row in range {
            // Controller input row: s0 (column 0) = ONE and s_perm = ZERO
            if self.trace[row * W] == ONE && self.trace[row * W + S_PERM_OFFSET] == ZERO {
                let cols: &ControllerCols<Felt> =
                    borrow_chiplet(&self.trace[row * W..row * W + S_PERM_OFFSET]);
                states.push(cols.state);
            }
        }
        states
    }

    /// Copies a section of the controller trace from the given range to the end of the trace.
    /// Updates the provided state with the hasher state from the last row of the copied range.
    pub fn copy_trace(&mut self, state: &mut [Felt; STATE_WIDTH], range: Range<usize>) {
        const W: usize = TRACE_WIDTH;
        self.trace.extend_from_within(range.start * W..range.end * W);

        // copy the latest hasher state to the provided state slice
        let last = range.end - 1;
        let cols: &ControllerCols<Felt> =
            borrow_chiplet(&self.trace[last * W..last * W + S_PERM_OFFSET]);
        *state = cols.state;
    }

    /// Overwrites mrupdate_id values in the given range.
    pub fn overwrite_mrupdate_id_in_range(&mut self, range: Range<usize>, mrupdate_id: Felt) {
        const W: usize = TRACE_WIDTH;
        for row in range {
            let cols: &mut ControllerCols<Felt> =
                borrow_chiplet_mut(&mut self.trace[row * W..row * W + S_PERM_OFFSET]);
            cols.mrupdate_id = mrupdate_id;
        }
    }

    // EXECUTION TRACE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Fills the provided trace fragment with trace data from this hasher trace instance.
    pub fn fill_trace(self, trace: &mut TraceFragment) {
        debug_assert_eq!(self.trace_len(), trace.len(), "inconsistent trace lengths");
        debug_assert_eq!(TRACE_WIDTH, trace.width(), "inconsistent trace widths");

        trace.copy_rows_from(&self.trace);
    }
}
