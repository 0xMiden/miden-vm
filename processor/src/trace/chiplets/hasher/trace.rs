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

// The controller overlay is 19 columns wide. The final hasher-controller trace column is the
// chiplet-level `s_perm` selector, which is fixed to ZERO in this trace.
const S_PERM_OFFSET: usize = TRACE_WIDTH - 1;

// HASHER OPERATION
// ================================================================================================

/// A single logical operation appended to the hasher controller trace.
///
/// Each variant maps deterministically to a known number of controller rows. Actual row
/// materialization happens once in [`HasherTrace::fill_trace`].
#[derive(Debug, Clone)]
enum HasherOp {
    /// A single controller row.
    Controller {
        selectors: Selectors,
        state: HasherState,
        node_index: Felt,
        mrupdate_id: Felt,
        is_boundary: Felt,
        direction_bit: Felt,
    },
    /// Padding rows used to align the controller region inside `ChipletsAir`.
    Padding { count: usize, mrupdate_id: Felt },
}

impl HasherOp {
    /// Number of controller rows this op contributes when materialized.
    fn row_count(&self) -> usize {
        match self {
            Self::Controller { .. } => 1,
            Self::Padding { count, .. } => *count,
        }
    }
}

// HASHER TRACE
// ================================================================================================

/// Execution trace for hasher controller rows.
///
/// The controller trace contains only the dispatch rows in `ChipletsAir`: one input row and one
/// output row per permutation request, plus padding rows. The requested Poseidon2 cycles are
/// materialized into the separate Poseidon2 permutation AIR by
/// [`fill_poseidon2_permutation_trace`].
///
/// Controller rows use 20 columns:
/// - 3 hasher-internal selector columns (`s0`, `s1`, `s2`).
/// - 12 Poseidon2 state columns (`h0..h11`).
/// - `node_index`, used by Merkle operations.
/// - `mrupdate_id`, the domain separator for MRUPDATE sibling-table entries.
/// - `is_boundary`, set on operation boundaries.
/// - `direction_bit`, used by Merkle path operations.
/// - `s_perm`, fixed to ZERO for every controller row.
#[derive(Debug, Default)]
pub(super) struct HasherTrace {
    ops: Vec<HasherOp>,
    row_count: usize,
}

impl HasherTrace {
    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the current controller trace length.
    pub(super) fn trace_len(&self) -> usize {
        self.row_count
    }

    /// Returns the next row address.
    ///
    /// Row addresses start at ONE rather than ZERO so the first code-block address is non-zero for
    /// the decoder.
    pub(super) fn next_row_addr(&self) -> Felt {
        Felt::new_unchecked(self.row_count as u64 + 1)
    }

    /// Returns the index that the next op will occupy.
    ///
    /// Callers use this to bracket memoization-eligible op ranges.
    pub(super) fn next_op_index(&self) -> usize {
        self.ops.len()
    }

    // CONTROLLER ROW METHODS
    // --------------------------------------------------------------------------------------------

    /// Appends a single controller row to the logical op log.
    pub(super) fn append_controller_row(
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

    /// Pads controller rows so the following chiplet section starts on its periodic boundary.
    ///
    /// Padding rows carry the current `mrupdate_id` because that column is constrained to remain
    /// stable except at MV-start transitions.
    pub(super) fn pad_to_controller_boundary(&mut self, mrupdate_id: Felt) {
        let remainder = self.row_count % CONTROLLER_TRACE_ALIGNMENT;
        if remainder != 0 {
            let count = CONTROLLER_TRACE_ALIGNMENT - remainder;
            self.ops.push(HasherOp::Padding { count, mrupdate_id });
            self.row_count += count;
        }
    }

    // MEMOIZATION SUPPORT
    // --------------------------------------------------------------------------------------------

    /// Replays a previously recorded op range with a new MRUPDATE domain separator.
    ///
    /// Returns the state of the last controller row in the range and the input states of all
    /// controller input rows encountered. The caller uses those input states to update Poseidon2
    /// permutation multiplicities for memoized controller blocks.
    pub(super) fn replay_ops_range(
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
    pub(super) fn fill_trace(self, trace: &mut ChipletTraceFragment) {
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
                    // The controller flags classify [0, 1, 0] as padding.
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
            row_idx += n;
        }
        debug_assert_eq!(row_idx, self.row_count);
    }
}

// CONTROLLER ROW WRITERS
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

// POSEIDON2 PERMUTATION TRACE
// ================================================================================================

/// Writes one 16-row packed Poseidon2 permutation cycle.
///
/// The emitted rows match `Poseidon2PermutationPeriodicCols`:
///
/// ```text
/// row 0       input state, then init linear layer + external round 0
/// rows 1..=3  state before initial external rounds 1..=3
/// rows 4..=10 state before three packed internal rounds; witnesses are S-box outputs
/// row 11      state before final internal round; witness[0] is its S-box output
/// rows 12..=14 state before terminal external rounds 1..=3
/// row 15      output state
/// ```
pub(super) fn write_poseidon2_permutation_cycle(
    rows: &mut [[Felt; NUM_POSEIDON2_PERMUTATION_COLS]],
    init_state: &HasherState,
    multiplicity: Felt,
) {
    debug_assert_eq!(rows.len(), HASH_CYCLE_LEN);
    let mut state = *init_state;

    write_perm_row(&mut rows[0], &state, multiplicity, [ZERO; 3]);

    Hasher::apply_matmul_external(&mut state);
    Hasher::add_rc(&mut state, &Hasher::ARK_EXT_INITIAL[0]);
    Hasher::apply_sbox(&mut state);
    Hasher::apply_matmul_external(&mut state);

    for (r, row) in rows.iter_mut().enumerate().take(4).skip(1) {
        write_perm_row(row, &state, multiplicity, [ZERO; 3]);
        Hasher::add_rc(&mut state, &Hasher::ARK_EXT_INITIAL[r]);
        Hasher::apply_sbox(&mut state);
        Hasher::apply_matmul_external(&mut state);
    }

    for triple in 0..7 {
        let base = triple * 3;
        let pre_state = state;
        let mut witnesses = [ZERO; 3];
        for (k, witness) in witnesses.iter_mut().enumerate() {
            let sbox_out = (state[0] + Hasher::ARK_INT[base + k]).exp_const_u64::<7>();
            *witness = sbox_out;
            state[0] = sbox_out;
            Hasher::matmul_internal(&mut state, Hasher::MAT_DIAG);
        }
        write_perm_row(&mut rows[4 + triple], &pre_state, multiplicity, witnesses);
    }

    let pre_state = state;
    let w0 = (state[0] + Hasher::ARK_INT[21]).exp_const_u64::<7>();
    state[0] = w0;
    Hasher::matmul_internal(&mut state, Hasher::MAT_DIAG);
    Hasher::add_rc(&mut state, &Hasher::ARK_EXT_TERMINAL[0]);
    Hasher::apply_sbox(&mut state);
    Hasher::apply_matmul_external(&mut state);
    write_perm_row(&mut rows[11], &pre_state, multiplicity, [w0, ZERO, ZERO]);

    for r in 1..=3 {
        write_perm_row(&mut rows[11 + r], &state, multiplicity, [ZERO; 3]);
        Hasher::add_rc(&mut state, &Hasher::ARK_EXT_TERMINAL[r]);
        Hasher::apply_sbox(&mut state);
        Hasher::apply_matmul_external(&mut state);
    }

    write_perm_row(&mut rows[15], &state, multiplicity, [ZERO; 3]);
}

/// Materializes the Poseidon2 permutation trace from deduplicated permutation requests.
///
/// Requests are supplied by `BTreeMap`, so cycle order is deterministic. Padding uses
/// zero-multiplicity cycles: they satisfy the permutation constraints and do not contribute to the
/// perm-link LogUp sum.
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

    // Padding consists of zero-state permutation cycles with multiplicity 0: the cycles satisfy
    // the permutation constraints and do not affect the LogUp sum.
    let zero_state = [ZERO; STATE_WIDTH];
    let padding_start = row_idx;
    write_poseidon2_permutation_cycle(
        &mut rows[padding_start..padding_start + HASH_CYCLE_LEN],
        &zero_state,
        ZERO,
    );
    row_idx += HASH_CYCLE_LEN;

    while row_idx < rows.len() {
        let written_padding = row_idx - padding_start;
        let copy_len = written_padding.min(rows.len() - row_idx);
        rows.copy_within(padding_start..padding_start + copy_len, row_idx);
        row_idx += copy_len;
    }
}

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
