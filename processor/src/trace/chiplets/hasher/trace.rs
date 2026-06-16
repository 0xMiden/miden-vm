use alloc::vec::Vec;
use core::{borrow::BorrowMut, ops::Range};

use miden_air::{
    ControllerCols,
    trace::{
        CHIPLETS_MODE_COL,
        chiplets::hasher::{CONTROLLER_TRACE_ALIGNMENT, PADDING, TRACE_WIDTH},
    },
};
use miden_core::chiplets::blakeg;

use super::{
    ChipletTraceFragment, Felt, HasherState, MP_VERIFY, MR_UPDATE_NEW, MR_UPDATE_OLD, ONE,
    STATE_WIDTH, Selectors, ZERO,
};

// HASHER OPERATION
// ================================================================================================

/// A logical operation appended to the hasher trace.
#[derive(Debug, Clone)]
enum HasherOp {
    /// A single controller row.
    Controller {
        selectors: Selectors,
        state: HasherState,
        row_data: [Felt; 4],
        op_final: Felt,
        mrupdate_id: Felt,
    },
    /// Padding rows filling the controller region to the chiplet alignment boundary.
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
/// Each controller row writes 22 fragment cells:
/// - 3 row-kind selectors.
/// - 12 state cells.
/// - 4 row-kind data cells.
/// - 1 final-row marker.
/// - 1 carried MRUPDATE id.
/// - 1 controller mode cell, written to the chiplets shared mode column.
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

    /// Returns the next row address. Row addresses start at ONE.
    pub fn next_row_addr(&self) -> Felt {
        Felt::new_unchecked(self.row_count as u64 + 1)
    }

    /// Returns the index that the next op pushed will occupy.
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
        row_data: [Felt; 4],
        op_final: Felt,
        mrupdate_id: Felt,
    ) {
        self.ops.push(HasherOp::Controller {
            selectors,
            state: *state,
            row_data,
            op_final,
            mrupdate_id,
        });
        self.row_count += 1;
    }

    // CONTROLLER PADDING
    // --------------------------------------------------------------------------------------------

    /// Appends padding rows to fill the controller region to `CONTROLLER_TRACE_ALIGNMENT`.
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

    /// Re-pushes the ops in `range` with `new_mrupdate_id` substituted.
    ///
    /// Returns the post-compression state and every copied compression input state.
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
                HasherOp::Controller {
                    mrupdate_id, selectors, state, row_data, ..
                } => {
                    *mrupdate_id = new_mrupdate_id;
                    if *selectors != PADDING {
                        input_states.push(input_state_from_row(*selectors, state));
                        last_state = output_state_from_row(*selectors, state, row_data);
                    }
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
        debug_assert!(trace.width() >= TRACE_WIDTH, "inconsistent trace widths");

        let row_width = trace.width();
        let mut chunk = vec![ZERO; row_width * CONTROLLER_TRACE_ALIGNMENT];

        let mut row_idx = 0usize;
        for op in &self.ops {
            let n = op.row_count();
            debug_assert!(n <= CONTROLLER_TRACE_ALIGNMENT);
            match op {
                HasherOp::Controller {
                    selectors,
                    state,
                    row_data,
                    op_final,
                    mrupdate_id,
                } => {
                    write_controller_row(
                        &mut chunk[..row_width],
                        *selectors,
                        state,
                        *row_data,
                        *op_final,
                        *mrupdate_id,
                    );
                },
                HasherOp::Padding { count, mrupdate_id } => {
                    for row in chunk.chunks_mut(row_width).take(*count) {
                        write_controller_row(
                            row,
                            PADDING,
                            &[ZERO; STATE_WIDTH],
                            [ZERO; 4],
                            ZERO,
                            *mrupdate_id,
                        );
                    }
                },
            }

            trace.copy_rows_into(row_idx, &chunk[..n * row_width]);

            // Write `s_ctrl = ONE` on controller and padding rows.
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
    row: &mut [Felt],
    selectors: Selectors,
    state: &HasherState,
    row_data: [Felt; 4],
    op_final: Felt,
    mrupdate_id: Felt,
) {
    row.fill(ZERO);

    let cols: &mut ControllerCols<Felt> = row[..CONTROLLER_OVERLAY_WIDTH].borrow_mut();
    cols.s0 = selectors[0];
    cols.s1 = selectors[1];
    cols.s2 = selectors[2];
    cols.state = *state;
    cols.row_data = row_data;
    row[OP_FINAL_OFFSET] = op_final;
    row[MRUPDATE_ID_OFFSET] = mrupdate_id;
    row[CONTROLLER_MERKLE_OR_PADDING_OFFSET] =
        if selectors == PADDING || is_merkle_selector(selectors) {
            ONE
        } else {
            ZERO
        };
}

const CONTROLLER_OVERLAY_WIDTH: usize = 19;
const OP_FINAL_OFFSET: usize = 19;
const MRUPDATE_ID_OFFSET: usize = 20;
const CONTROLLER_MERKLE_OR_PADDING_OFFSET: usize = CHIPLETS_MODE_COL - 1;

fn is_merkle_selector(selectors: Selectors) -> bool {
    selectors == MP_VERIFY || selectors == MR_UPDATE_OLD || selectors == MR_UPDATE_NEW
}

fn input_state_from_row(selectors: Selectors, state: &HasherState) -> HasherState {
    let mut input = *state;
    if is_merkle_selector(selectors) {
        let cv = blakeg::two_to_one_chaining_word(0);
        input[8..12].copy_from_slice(cv.as_elements());
    }
    input
}

fn output_state_from_row(
    selectors: Selectors,
    state: &HasherState,
    row_data: &[Felt; 4],
) -> HasherState {
    let mut output = [ZERO; STATE_WIDTH];
    if is_merkle_selector(selectors) {
        let cv = blakeg::two_to_one_chaining_word(0);
        output[..4].copy_from_slice(cv.as_elements());
        output[8..12].copy_from_slice(&state[8..12]);
    } else {
        output[..4].copy_from_slice(&state[8..12]);
        output[8..12].copy_from_slice(row_data);
    }
    output
}
