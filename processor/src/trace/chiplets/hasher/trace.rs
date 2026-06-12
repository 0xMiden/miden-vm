use alloc::{collections::BTreeMap, vec::Vec};
use core::{borrow::BorrowMut, ops::Range};

use miden_air::{
    ControllerCols, Poseidon2PermutationCols,
    trace::{
        chiplets::hasher::{CONTROLLER_TRACE_ALIGNMENT, HASH_CYCLE_LEN, TRACE_WIDTH},
        poseidon2_permutation::NUM_POSEIDON2_PERMUTATION_COLS,
    },
};
use miden_core::chiplets::hasher::Hasher;

use super::{ChipletTraceFragment, Felt, HasherState, ONE, STATE_WIDTH, Selectors, StateKey, ZERO};

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
    /// Padding rows filling the controller region up to a chiplet alignment boundary.
    Padding { count: usize, mrupdate_id: Felt },
}

impl HasherOp {
    /// Number of trace rows this op contributes when materialized.
    fn row_count(&self) -> usize {
        match self {
            Self::Controller { .. } => 1,
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
/// - 1 node_index column: holds the Merkle tree node index on controller rows.
/// - 1 mrupdate_id column (domain separator for sibling table).
/// - 1 is_boundary column (1 on boundary rows: first input or last output, 0 otherwise).
/// - 1 direction_bit column (Merkle direction bit on controller rows, 0 elsewhere).
/// - 1 s_perm column: reserved, always zero in controller rows.
///
/// Poseidon2 permutation cycles are materialized into `Poseidon2PermutationAir`.
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

    // CONTROLLER PADDING
    // --------------------------------------------------------------------------------------------

    /// Appends padding rows to fill the controller region to `CONTROLLER_TRACE_ALIGNMENT`.
    ///
    /// Padding rows have all columns set to zero except mrupdate_id, which must carry the
    /// last value to satisfy the AIR progression constraint (mrupdate_id is constant on
    /// non-MV-start transitions).
    pub fn pad_to_controller_boundary(&mut self, mrupdate_id: Felt) {
        let remainder = self.row_count % CONTROLLER_TRACE_ALIGNMENT;
        if remainder != 0 {
            let count = CONTROLLER_TRACE_ALIGNMENT - remainder;
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

        let mut chunk = [ZERO; TRACE_WIDTH * CONTROLLER_TRACE_ALIGNMENT];

        let mut row_idx = 0usize;
        for op in &self.ops {
            let n = op.row_count();
            debug_assert!(n <= CONTROLLER_TRACE_ALIGNMENT);
            let (chunk_rows, _) = chunk.as_mut_slice().as_chunks_mut::<TRACE_WIDTH>();
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
                        &mut chunk_rows[0],
                        *selectors,
                        state,
                        *node_index,
                        *mrupdate_id,
                        *is_boundary,
                        *direction_bit,
                    );
                },
                HasherOp::Padding { count, mrupdate_id } => {
                    // Padding selectors: [0, 1, 0]. This combination is unused in the controller
                    // region and prevents padding rows from being mistaken for HOUT output rows.
                    let padding_selectors = [ZERO, ONE, ZERO];
                    for row in &mut chunk_rows[..*count] {
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
                },
            }

            trace.copy_rows_into(row_idx, &chunk[..n * TRACE_WIDTH]);

            // Write `s_ctrl = ONE` on controller/padding rows.
            for i in 0..n {
                let prefix = trace.prefix_mut(row_idx + i);
                if let Some(s_ctrl) = prefix.first_mut() {
                    *s_ctrl = ONE;
                }
            }

            row_idx += n;
        }
        debug_assert_eq!(row_idx, self.row_count);
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
pub(super) fn write_poseidon2_permutation_cycle(
    rows: &mut [[Felt; NUM_POSEIDON2_PERMUTATION_COLS]],
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
    for (r, row) in rows.iter_mut().enumerate().take(3 + 1).skip(1) {
        write_perm_row(row, &state, multiplicity, [ZERO; 3]);
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

/// Materializes the standalone Poseidon2 permutation AIR.
///
/// `perm_requests` maps each pre-permutation state to its perm-link multiplicity. The target
/// buffer must have enough full 16-row cycles for all real requests plus at least one
/// zero-multiplicity dummy cycle, so the last row does not emit LogUp interactions.
pub(super) fn fill_poseidon2_permutation_trace(
    perm_requests: BTreeMap<StateKey, u64>,
    trace: &mut [Felt],
) {
    const W: usize = NUM_POSEIDON2_PERMUTATION_COLS;
    debug_assert_eq!(trace.len() % W, 0, "Poseidon2 trace buffer is not row-aligned");

    let (rows, _) = trace.as_chunks_mut::<W>();
    debug_assert_eq!(rows.len() % HASH_CYCLE_LEN, 0, "Poseidon2 height must align to cycles");
    debug_assert!(
        (perm_requests.len() + 1) * HASH_CYCLE_LEN <= rows.len(),
        "Poseidon2 trace buffer is too short for permutation requests",
    );

    let mut row_idx = 0;
    for (key, multiplicity) in perm_requests {
        let state = key.map(Felt::new_unchecked);
        write_poseidon2_permutation_cycle(
            &mut rows[row_idx..row_idx + HASH_CYCLE_LEN],
            &state,
            Felt::new_unchecked(multiplicity),
        );
        row_idx += HASH_CYCLE_LEN;
    }

    let zero_state = [ZERO; STATE_WIDTH];
    while row_idx < rows.len() {
        write_poseidon2_permutation_cycle(
            &mut rows[row_idx..row_idx + HASH_CYCLE_LEN],
            &zero_state,
            ZERO,
        );
        row_idx += HASH_CYCLE_LEN;
    }
}

/// Writes one row of the standalone Poseidon2 permutation trace.
fn write_perm_row(
    row: &mut [Felt; NUM_POSEIDON2_PERMUTATION_COLS],
    state: &HasherState,
    multiplicity: Felt,
    witnesses: [Felt; 3],
) {
    let cols: &mut Poseidon2PermutationCols<Felt> = row[..].borrow_mut();
    cols.witnesses = witnesses;
    cols.state = *state;
    cols.multiplicity = multiplicity;
}
