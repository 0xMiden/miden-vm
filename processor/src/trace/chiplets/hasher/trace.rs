use alloc::vec::Vec;
use core::{borrow::BorrowMut, ops::Range};

use miden_air::{
    CYCLE_INPUT_ROW, CYCLE_OUTPUT_ROW, ControllerCols, INITIAL_EXTERNAL_ROUND_END,
    INITIAL_EXTERNAL_ROUND_START, INTERNAL_PLUS_EXTERNAL_ROW, LAST_INTERNAL_ROUND_ARK_IDX,
    NUM_PACKED_INTERNAL_ROUND_ROWS, NUM_SBOX_WITNESSES, NUM_TRAILING_EXTERNAL_ROUND_ROWS,
    PACKED_INTERNAL_ROUND_START, Poseidon2PermutationCols,
    trace::{
        chiplets::hasher::{CONTROLLER_TRACE_ALIGNMENT, HASH_CYCLE_LEN, TRACE_WIDTH},
        poseidon2_permutation::NUM_POSEIDON2_PERMUTATION_COLS,
    },
};
use miden_core::chiplets::hasher::Hasher;

use super::{
    ChipletTraceFragment, Felt, HasherState, ONE, PermRequest, STATE_WIDTH, Selectors, ZERO,
};

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
        perm_id: Felt,
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
/// Controller rows use the hasher trace layout:
/// - 3 hasher-internal selector columns (`s0`, `s1`, `s2`).
/// - 12 Poseidon2 state columns (`h0..h11`).
/// - `node_index`, used by Merkle operations.
/// - `mrupdate_id`, the domain separator for MRUPDATE sibling-table entries.
/// - `is_boundary`, set on operation boundaries.
/// - `direction_bit`, used by Merkle path operations.
/// - `perm_id`, the Poseidon2 permutation cycle id for input/output rows.
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
        perm_id: Felt,
    ) {
        self.ops.push(HasherOp::Controller {
            selectors,
            state: *state,
            node_index,
            mrupdate_id,
            is_boundary,
            direction_bit,
            perm_id,
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
        let mut last_state = [ZERO; STATE_WIDTH];
        let mut input_states = Vec::with_capacity(range.len() / 2);
        for idx in range {
            let mut op = self.ops[idx].clone();
            match &mut op {
                HasherOp::Controller { mrupdate_id, selectors, state, .. } => {
                    *mrupdate_id = new_mrupdate_id;
                    let [is_input, _, _] = *selectors;
                    if is_input == ONE {
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
                    perm_id,
                } => {
                    write_controller_row(
                        &mut chunk_rows[0],
                        *selectors,
                        state,
                        *node_index,
                        *mrupdate_id,
                        *is_boundary,
                        *direction_bit,
                        *perm_id,
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
    perm_id: Felt,
) {
    let cols: &mut ControllerCols<Felt> = row.as_mut_slice().borrow_mut();
    let [s0, s1, s2] = selectors;
    cols.s0 = s0;
    cols.s1 = s1;
    cols.s2 = s2;
    cols.state = *state;
    cols.node_index = node_index;
    cols.mrupdate_id = mrupdate_id;
    cols.is_boundary = is_boundary;
    cols.direction_bit = direction_bit;
    cols.perm_id = perm_id;
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
    perm_id: Felt,
    multiplicity: Felt,
) {
    debug_assert_eq!(rows.len(), HASH_CYCLE_LEN);
    let mut state = *init_state;

    let zero_witnesses = [ZERO; NUM_SBOX_WITNESSES];
    let multiplicity_witnesses = witnesses_with_first(multiplicity);

    write_perm_row(&mut rows[CYCLE_INPUT_ROW], &state, perm_id, multiplicity_witnesses);

    Hasher::apply_matmul_external(&mut state);
    Hasher::add_rc(&mut state, &Hasher::ARK_EXT_INITIAL[0]);
    Hasher::apply_sbox(&mut state);
    Hasher::apply_matmul_external(&mut state);

    for (offset, row) in rows[INITIAL_EXTERNAL_ROUND_START..INITIAL_EXTERNAL_ROUND_END]
        .iter_mut()
        .enumerate()
    {
        let round = INITIAL_EXTERNAL_ROUND_START + offset;
        write_perm_row(row, &state, perm_id, zero_witnesses);
        Hasher::add_rc(&mut state, &Hasher::ARK_EXT_INITIAL[round]);
        Hasher::apply_sbox(&mut state);
        Hasher::apply_matmul_external(&mut state);
    }

    for triple in 0..NUM_PACKED_INTERNAL_ROUND_ROWS {
        let base = triple * NUM_SBOX_WITNESSES;
        let pre_state = state;
        let mut witnesses = zero_witnesses;
        for (k, witness) in witnesses.iter_mut().enumerate() {
            let sbox_out = (state[0] + Hasher::ARK_INT[base + k]).exp_const_u64::<7>();
            *witness = sbox_out;
            state[0] = sbox_out;
            Hasher::matmul_internal(&mut state, Hasher::MAT_DIAG);
        }
        write_perm_row(
            &mut rows[PACKED_INTERNAL_ROUND_START + triple],
            &pre_state,
            perm_id,
            witnesses,
        );
    }

    let pre_state = state;
    let w0 = (state[0] + Hasher::ARK_INT[LAST_INTERNAL_ROUND_ARK_IDX]).exp_const_u64::<7>();
    state[0] = w0;
    Hasher::matmul_internal(&mut state, Hasher::MAT_DIAG);
    Hasher::add_rc(&mut state, &Hasher::ARK_EXT_TERMINAL[0]);
    Hasher::apply_sbox(&mut state);
    Hasher::apply_matmul_external(&mut state);
    let final_internal_witnesses = witnesses_with_first(w0);
    write_perm_row(
        &mut rows[INTERNAL_PLUS_EXTERNAL_ROW],
        &pre_state,
        perm_id,
        final_internal_witnesses,
    );

    for round in 1..=NUM_TRAILING_EXTERNAL_ROUND_ROWS {
        write_perm_row(
            &mut rows[INTERNAL_PLUS_EXTERNAL_ROW + round],
            &state,
            perm_id,
            zero_witnesses,
        );
        Hasher::add_rc(&mut state, &Hasher::ARK_EXT_TERMINAL[round]);
        Hasher::apply_sbox(&mut state);
        Hasher::apply_matmul_external(&mut state);
    }

    write_perm_row(&mut rows[CYCLE_OUTPUT_ROW], &state, perm_id, multiplicity_witnesses);
}

/// Materializes the Poseidon2 permutation trace from deduplicated permutation requests.
///
/// Requests are emitted in cycle-id order. Padding uses zero-multiplicity cycles: they satisfy the
/// permutation constraints and do not contribute to the perm-link LogUp sum.
pub(super) fn fill_poseidon2_permutation_trace(
    perm_requests: Vec<PermRequest>,
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

    let request_count = perm_requests.len();
    let mut row_idx = 0;
    for (perm_id, request) in perm_requests.into_iter().enumerate() {
        let state = request.state.map(Felt::new_unchecked);
        write_poseidon2_permutation_cycle(
            &mut rows[row_idx..row_idx + HASH_CYCLE_LEN],
            &state,
            felt_from_usize(perm_id),
            Felt::new_unchecked(request.multiplicity),
        );
        row_idx += HASH_CYCLE_LEN;
    }

    // Padding cycles use zero multiplicity and continue the cycle-id sequence.
    let mut perm_id = request_count;
    let zero_state = [ZERO; STATE_WIDTH];
    if row_idx < rows.len() {
        let padding_start = row_idx;
        write_poseidon2_permutation_cycle(
            &mut rows[padding_start..padding_start + HASH_CYCLE_LEN],
            &zero_state,
            felt_from_usize(perm_id),
            ZERO,
        );
        row_idx += HASH_CYCLE_LEN;
        perm_id += 1;

        while row_idx < rows.len() {
            rows.copy_within(padding_start..padding_start + HASH_CYCLE_LEN, row_idx);
            set_perm_id(&mut rows[row_idx..row_idx + HASH_CYCLE_LEN], felt_from_usize(perm_id));
            row_idx += HASH_CYCLE_LEN;
            perm_id += 1;
        }
    }
}

fn witnesses_with_first(value: Felt) -> [Felt; NUM_SBOX_WITNESSES] {
    let mut witnesses = [ZERO; NUM_SBOX_WITNESSES];
    witnesses[0] = value;
    witnesses
}

fn felt_from_usize(value: usize) -> Felt {
    Felt::new_unchecked(value.try_into().expect("Poseidon2 permutation id exceeds u64"))
}

fn set_perm_id(rows: &mut [[Felt; NUM_POSEIDON2_PERMUTATION_COLS]], perm_id: Felt) {
    debug_assert_eq!(rows.len(), HASH_CYCLE_LEN);
    for row in rows {
        let cols: &mut Poseidon2PermutationCols<Felt> = row[..].borrow_mut();
        cols.perm_id = perm_id;
    }
}

fn write_perm_row(
    row: &mut [Felt; NUM_POSEIDON2_PERMUTATION_COLS],
    state: &HasherState,
    perm_id: Felt,
    witnesses: [Felt; NUM_SBOX_WITNESSES],
) {
    let cols: &mut Poseidon2PermutationCols<Felt> = row[..].borrow_mut();
    cols.witnesses = witnesses;
    cols.state = *state;
    cols.perm_id = perm_id;
}
