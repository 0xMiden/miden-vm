use alloc::vec::Vec;
use core::{borrow::BorrowMut, ops::Range};

use miden_air::{
    ControllerCols, PermutationCols,
    trace::chiplets::hasher::{HASH_CYCLE_LEN, TRACE_WIDTH},
};
use miden_core::chiplets::hasher::Hasher;

use super::{ChipletTraceFragment, Felt, HasherState, ONE, STATE_WIDTH, Selectors, ZERO};

// The unified hasher row is wider than the typed overlay by one column (s_perm).
const S_PERM_OFFSET: usize = TRACE_WIDTH - 1;

// HASHER OPERATION
// ================================================================================================

/// A single logical operation appended to the hasher trace. Each variant maps deterministically
/// to a known number of trace rows; the actual row materialization happens once in
/// [`HasherTrace::fill_trace`].
#[derive(Debug, Clone)]
enum HasherOp {
    /// A single controller row (s_perm = 0).
    Controller {
        selectors: Selectors,
        state: HasherState,
        node_index: Felt,
        mrupdate_id: Felt,
        is_boundary: Felt,
        direction_bit: Felt,
    },
    /// A 16-row Poseidon2 permutation cycle (s_perm = 1).
    Permutation {
        init_state: HasherState,
        multiplicity: Felt,
    },
    /// Padding rows filling the controller region up to a `HASH_CYCLE_LEN` boundary.
    Padding { count: usize, mrupdate_id: Felt },
}

impl HasherOp {
    /// Number of trace rows this op contributes when materialized.
    fn row_count(&self) -> usize {
        match self {
            Self::Controller { .. } => 1,
            Self::Permutation { .. } => HASH_CYCLE_LEN,
            Self::Padding { count, .. } => *count,
        }
    }
}

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
    ops: Vec<HasherOp>,
    row_count: usize,
}

impl HasherTrace {
    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns current length of this execution trace.
    pub fn trace_len(&self) -> usize {
        self.row_count
    }

    /// Returns the next row address. The address is equal to the current trace length + 1.
    ///
    /// The above means that row addresses start at ONE (rather than ZERO), and are incremented by
    /// ONE at every row. Starting at ONE is needed for the decoder so that the address of the
    /// first code block is a non-zero value.
    pub fn next_row_addr(&self) -> Felt {
        Felt::new_unchecked(self.row_count as u64 + 1)
    }

    /// Returns the index that the next op pushed will occupy. Used to bracket memoization-eligible
    /// op ranges in the caller.
    pub fn next_op_index(&self) -> usize {
        self.ops.len()
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
        self.ops.push(HasherOp::Controller {
            selectors,
            state: *state,
            node_index,
            mrupdate_id,
            is_boundary,
            direction_bit,
        });
        self.row_count += 1;
    }

    // PERMUTATION SEGMENT METHODS
    // --------------------------------------------------------------------------------------------

    /// Appends a 16-row permutation cycle to the trace.
    ///
    /// The `multiplicity` is stored in the node_index column on all rows of the cycle and constant
    /// within a cycle.
    pub fn append_permutation_cycle(&mut self, init_state: &HasherState, multiplicity: Felt) {
        self.ops.push(HasherOp::Permutation { init_state: *init_state, multiplicity });
        self.row_count += HASH_CYCLE_LEN;
    }

    /// Appends padding rows to fill the controller region to a multiple of HASH_CYCLE_LEN.
    ///
    /// Padding rows have all columns set to zero except mrupdate_id, which must carry the
    /// last value to satisfy the AIR progression constraint (mrupdate_id is constant on
    /// non-MV-start transitions).
    pub fn pad_to_cycle_boundary(&mut self, mrupdate_id: Felt) {
        let remainder = self.row_count % HASH_CYCLE_LEN;
        if remainder != 0 {
            let count = HASH_CYCLE_LEN - remainder;
            self.ops.push(HasherOp::Padding { count, mrupdate_id });
            self.row_count += count;
        }
    }

    // MEMOIZATION SUPPORT
    // --------------------------------------------------------------------------------------------

    /// Re-pushes the ops in `range` with `new_mrupdate_id` substituted on every controller and
    /// padding row. Returns the post-permutation state (i.e. the state of the last controller
    /// op in the range, which is by construction an output row) and the input states of every
    /// controller input row encountered (s0 == ONE).
    ///
    /// Used to memoize identical controller blocks: the source op range is identified by
    /// digest in the caller's memoization map.
    pub fn replay_ops_range(
        &mut self,
        range: Range<usize>,
        new_mrupdate_id: Felt,
    ) -> (HasherState, Vec<HasherState>) {
        let copied: Vec<HasherOp> = self.ops[range].to_vec();
        let mut last_state = [ZERO; STATE_WIDTH];
        let mut input_states = Vec::new();
        for mut op in copied {
            match &mut op {
                HasherOp::Controller { mrupdate_id, selectors, state, .. } => {
                    *mrupdate_id = new_mrupdate_id;
                    if selectors[0] == ONE {
                        input_states.push(*state);
                    }
                    last_state = *state;
                },
                HasherOp::Padding { mrupdate_id, .. } => {
                    *mrupdate_id = new_mrupdate_id;
                },
                HasherOp::Permutation { .. } => {},
            }
            self.row_count += op.row_count();
            self.ops.push(op);
        }
        (last_state, input_states)
    }

    // EXECUTION TRACE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Fills the provided trace fragment by materializing the op log row by row.
    pub fn fill_trace(self, trace: &mut ChipletTraceFragment) {
        debug_assert_eq!(self.trace_len(), trace.len(), "inconsistent trace lengths");
        debug_assert_eq!(TRACE_WIDTH, trace.width(), "inconsistent trace widths");

        let mut values = vec![ZERO; self.row_count * TRACE_WIDTH];
        let (out_rows, _) = values.as_chunks_mut::<TRACE_WIDTH>();

        let mut row_idx = 0usize;
        for op in &self.ops {
            match op {
                HasherOp::Controller {
                    selectors,
                    state,
                    node_index,
                    mrupdate_id,
                    is_boundary,
                    direction_bit,
                } => {
                    write_controller_row(
                        &mut out_rows[row_idx],
                        *selectors,
                        state,
                        *node_index,
                        *mrupdate_id,
                        *is_boundary,
                        *direction_bit,
                    );
                    row_idx += 1;
                },
                HasherOp::Permutation { init_state, multiplicity } => {
                    write_permutation_cycle(
                        &mut out_rows[row_idx..row_idx + HASH_CYCLE_LEN],
                        init_state,
                        *multiplicity,
                    );
                    row_idx += HASH_CYCLE_LEN;
                },
                HasherOp::Padding { count, mrupdate_id } => {
                    // Padding selectors: [0, 1, 0]. This combination is unused in the controller
                    // region (s0=0, s1=1 only appears in perm segment rows which have s_perm=1).
                    // Using it prevents padding rows from being mistaken for HOUT output rows
                    // ([0,0,0]) by the bus response builder.
                    let padding_selectors = [ZERO, ONE, ZERO];
                    for row in &mut out_rows[row_idx..row_idx + count] {
                        write_controller_row(
                            row,
                            padding_selectors,
                            &[ZERO; STATE_WIDTH],
                            ZERO,
                            *mrupdate_id,
                            ZERO,
                            ZERO,
                        );
                    }
                    row_idx += count;
                },
            }
        }
        debug_assert_eq!(row_idx, self.row_count);

        trace.copy_rows_from(&values);
    }
}

// ROW WRITERS
// ================================================================================================

fn write_controller_row(
    row: &mut [Felt; TRACE_WIDTH],
    selectors: Selectors,
    state: &HasherState,
    node_index: Felt,
    mrupdate_id: Felt,
    is_boundary: Felt,
    direction_bit: Felt,
) {
    let (overlay, tail) = row.split_at_mut(S_PERM_OFFSET);
    let cols: &mut ControllerCols<Felt> = overlay.borrow_mut();
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

/// Writes the 16-row packed schedule:
/// - Row 0:     init linear + ext1 (merged)
/// - Rows 1-3:  ext2, ext3, ext4
/// - Rows 4-10: 7 packed triples of internal rounds (needs extra witnesses in s0,s1,s2)
/// - Row 11:    int22 + ext5 (merged, extra witness in s0)
/// - Rows 12-14: ext6, ext7, ext8
/// - Row 15:    boundary (final state, no transition)
fn write_permutation_cycle(
    rows: &mut [[Felt; TRACE_WIDTH]],
    init_state: &HasherState,
    multiplicity: Felt,
) {
    debug_assert_eq!(rows.len(), HASH_CYCLE_LEN);
    let mut state = *init_state;

    // Row 0: initial state
    write_perm_row(&mut rows[0], &state, multiplicity, [ZERO; 3]);

    // Apply init linear + ext1 (merged: M_E, add RC, S-box, M_E)
    Hasher::apply_matmul_external(&mut state);
    Hasher::add_rc(&mut state, &Hasher::ARK_EXT_INITIAL[0]);
    Hasher::apply_sbox(&mut state);
    Hasher::apply_matmul_external(&mut state);

    // Rows 1-3: ext2, ext3, ext4
    for r in 1..=3 {
        write_perm_row(&mut rows[r], &state, multiplicity, [ZERO; 3]);
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
        write_perm_row(&mut rows[4 + triple], &pre_state, multiplicity, witnesses);
    }

    // Row 11: int22 + ext5 (merged)
    let pre_state = state;
    let w0 = (state[0] + Hasher::ARK_INT[21]).exp_const_u64::<7>();
    state[0] = w0;
    Hasher::matmul_internal(&mut state, Hasher::MAT_DIAG);
    Hasher::add_rc(&mut state, &Hasher::ARK_EXT_TERMINAL[0]);
    Hasher::apply_sbox(&mut state);
    Hasher::apply_matmul_external(&mut state);
    write_perm_row(&mut rows[11], &pre_state, multiplicity, [w0, ZERO, ZERO]);

    // Rows 12-14: ext6, ext7, ext8
    for r in 1..=3 {
        write_perm_row(&mut rows[11 + r], &state, multiplicity, [ZERO; 3]);
        Hasher::add_rc(&mut state, &Hasher::ARK_EXT_TERMINAL[r]);
        Hasher::apply_sbox(&mut state);
        Hasher::apply_matmul_external(&mut state);
    }

    // Row 15: boundary (final state)
    write_perm_row(&mut rows[15], &state, multiplicity, [ZERO; 3]);
}

/// Writes a single permutation segment row (s_perm = 1).
///
/// On permutation rows, `s0, s1, s2` serve as witness columns for packed internal
/// rounds. The `witnesses` array provides values to write into these columns.
/// Control columns (mrupdate_id, is_boundary, direction_bit) are zero.
fn write_perm_row(
    row: &mut [Felt; TRACE_WIDTH],
    state: &HasherState,
    multiplicity: Felt,
    witnesses: [Felt; 3],
) {
    let (overlay, tail) = row.split_at_mut(S_PERM_OFFSET);
    let cols: &mut PermutationCols<Felt> = overlay.borrow_mut();
    cols.witnesses = witnesses;
    cols.state = *state;
    cols.multiplicity = multiplicity;
    tail[0] = ONE;
}
