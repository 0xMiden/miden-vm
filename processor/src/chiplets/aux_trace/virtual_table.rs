use miden_air::trace::{
    LOG_PRECOMPILE_LABEL, MainTrace, RowIndex,
    chiplets::hasher::DIGEST_RANGE,
    log_precompile::{HELPER_CAP_PREV_RANGE, STACK_CAP_NEXT_RANGE},
};
use miden_core::{
    Felt, OPCODE_LOGPRECOMPILE, field::ExtensionField, precompile::PrecompileTranscriptState,
};

use super::{build_ace_memory_read_element_request, build_ace_memory_read_word_request};
use crate::{
    PrimeField64,
    chiplets::aux_trace::build_value,
    debug::{BusDebugger, BusMessage},
    trace::AuxColumnBuilder,
};

// CHIPLETS VIRTUAL TABLE
// ================================================================================================

/// Describes how to construct the execution trace of the chiplets virtual table auxiliary trace
/// column. This column enables communication between the different chiplets, in particular:
/// - Ensuring sharing of sibling nodes in a Merkle tree when one of its leaves is updated by the
///   hasher chiplet.
/// - Allowing memory access for the ACE chiplet.
///
/// # Detail:
/// The hasher chiplet requires the bus to be empty whenever a Merkle tree update is requested.
/// This implies that the bus is also empty at the end of the trace containing the hasher rows.
/// On the other hand, communication between the ACE and memory chiplets requires the bus to be
/// contiguous, since messages are shared between these rows.
///
/// Since the hasher chip is in the first position, the other chiplets can treat it as a shared bus.
/// However, this prevents any bus initialization via public inputs using boundary constraints
/// in the first row. If such constraints are required, they must be enforced in the last row of
/// the trace.
///
/// If public inputs are required for other chiplets, it is also possible to use the chiplet bus,
/// as is done for the kernel ROM chiplet.
pub struct ChipletsVTableColBuilder {
    /// Final precompile transcript state supplied as a public input to the bus.
    final_transcript_state: PrecompileTranscriptState,
}

impl ChipletsVTableColBuilder {
    /// Auxiliary column builder for the virtual table.
    ///
    /// The `final_transcript_state` argument is the state of the transcript after having recorded
    /// all precompile request. It is used to initialize the multi-set with the initial (empty) and
    /// final state of the transcript. An AIR constraint enforces the boundary constraint
    /// referencing the final state provided as a public input by the verifier.
    pub fn new(final_transcript_state: PrecompileTranscriptState) -> Self {
        Self { final_transcript_state }
    }
}

impl<E> AuxColumnBuilder<E> for ChipletsVTableColBuilder
where
    E: ExtensionField<Felt>,
{
    fn get_requests_at(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
        row: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let op_code = main_trace.get_op_code(row).as_canonical_u64() as u8;
        let log_pc_request = if op_code == OPCODE_LOGPRECOMPILE {
            build_log_precompile_capacity_remove(main_trace, row, alphas, _debugger)
        } else {
            E::ONE
        };

        let request_ace = if main_trace.chiplet_ace_is_read_row(row) {
            build_ace_memory_read_word_request(main_trace, alphas, row, _debugger)
        } else if main_trace.chiplet_ace_is_eval_row(row) {
            build_ace_memory_read_element_request(main_trace, alphas, row, _debugger)
        } else {
            E::ONE
        };

        chiplets_vtable_remove_sibling(main_trace, alphas, row) * request_ace * log_pc_request
    }

    fn get_responses_at(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
        row: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let op_code = main_trace.get_op_code(row).as_canonical_u64() as u8;
        let log_pc_response = if op_code == OPCODE_LOGPRECOMPILE {
            build_log_precompile_capacity_insert(main_trace, row, alphas, _debugger)
        } else {
            E::ONE
        };

        chiplets_vtable_add_sibling(main_trace, alphas, row) * log_pc_response
    }

    fn init_requests(
        &self,
        _main_trace: &MainTrace,
        alphas: &[E],
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let message = LogPrecompileMessage { state: self.final_transcript_state };
        let value = message.value(alphas);

        #[cfg(any(test, feature = "bus-debugger"))]
        _debugger.add_request(alloc::boxed::Box::new(message), alphas);

        value
    }

    fn init_responses(
        &self,
        _main_trace: &MainTrace,
        alphas: &[E],
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let message = LogPrecompileMessage {
            state: PrecompileTranscriptState::default(),
        };
        let value = message.value(alphas);

        #[cfg(any(test, feature = "bus-debugger"))]
        _debugger.add_response(alloc::boxed::Box::new(message), alphas);

        value
    }
}

// VIRTUAL TABLE REQUESTS
// ================================================================================================

/// Constructs the removals from the table when the hasher absorbs a new sibling node while
/// computing the new Merkle root.
fn chiplets_vtable_remove_sibling<E>(main_trace: &MainTrace, alphas: &[E], row: RowIndex) -> E
where
    E: ExtensionField<Felt>,
{
    let f_mu: bool = main_trace.f_mu(row);
    let f_mua: bool = main_trace.f_mua(row);

    if f_mu {
        let index = main_trace.chiplet_node_index(row);
        let lsb = index.as_canonical_u64() & 1;
        if lsb == 0 {
            let sibling = &main_trace.chiplet_hasher_state(row)[DIGEST_RANGE.end..];
            alphas[0]
                + alphas[3] * index
                + alphas[12] * sibling[0]
                + alphas[13] * sibling[1]
                + alphas[14] * sibling[2]
                + alphas[15] * sibling[3]
        } else {
            let sibling = &main_trace.chiplet_hasher_state(row)[DIGEST_RANGE];
            alphas[0]
                + alphas[3] * index
                + alphas[8] * sibling[0]
                + alphas[9] * sibling[1]
                + alphas[10] * sibling[2]
                + alphas[11] * sibling[3]
        }
    } else if f_mua {
        let index = main_trace.chiplet_node_index(row);
        let lsb = index.as_canonical_u64() & 1;
        if lsb == 0 {
            let sibling = &main_trace.chiplet_hasher_state(row + 1)[DIGEST_RANGE.end..];
            alphas[0]
                + alphas[3] * index
                + alphas[12] * sibling[0]
                + alphas[13] * sibling[1]
                + alphas[14] * sibling[2]
                + alphas[15] * sibling[3]
        } else {
            let sibling = &main_trace.chiplet_hasher_state(row + 1)[DIGEST_RANGE];
            alphas[0]
                + alphas[3] * index
                + alphas[8] * sibling[0]
                + alphas[9] * sibling[1]
                + alphas[10] * sibling[2]
                + alphas[11] * sibling[3]
        }
    } else {
        E::ONE
    }
}

// VIRTUAL TABLE RESPONSES
// ================================================================================================

/// Constructs the inclusions to the table when the hasher absorbs a new sibling node while
/// computing the old Merkle root.
fn chiplets_vtable_add_sibling<E>(main_trace: &MainTrace, alphas: &[E], row: RowIndex) -> E
where
    E: ExtensionField<Felt>,
{
    let f_mv: bool = main_trace.f_mv(row);
    let f_mva: bool = main_trace.f_mva(row);

    if f_mv {
        let index = main_trace.chiplet_node_index(row);
        let lsb = index.as_canonical_u64() & 1;
        if lsb == 0 {
            let sibling = &main_trace.chiplet_hasher_state(row)[DIGEST_RANGE.end..];
            alphas[0]
                + alphas[3] * index
                + alphas[12] * sibling[0]
                + alphas[13] * sibling[1]
                + alphas[14] * sibling[2]
                + alphas[15] * sibling[3]
        } else {
            let sibling = &main_trace.chiplet_hasher_state(row)[DIGEST_RANGE];
            alphas[0]
                + alphas[3] * index
                + alphas[8] * sibling[0]
                + alphas[9] * sibling[1]
                + alphas[10] * sibling[2]
                + alphas[11] * sibling[3]
        }
    } else if f_mva {
        let index = main_trace.chiplet_node_index(row);
        let lsb = index.as_canonical_u64() & 1;
        if lsb == 0 {
            let sibling = &main_trace.chiplet_hasher_state(row + 1)[DIGEST_RANGE.end..];
            alphas[0]
                + alphas[3] * index
                + alphas[12] * sibling[0]
                + alphas[13] * sibling[1]
                + alphas[14] * sibling[2]
                + alphas[15] * sibling[3]
        } else {
            let sibling = &main_trace.chiplet_hasher_state(row + 1)[DIGEST_RANGE];
            alphas[0]
                + alphas[3] * index
                + alphas[8] * sibling[0]
                + alphas[9] * sibling[1]
                + alphas[10] * sibling[2]
                + alphas[11] * sibling[3]
        }
    } else {
        E::ONE
    }
}

// LOG PRECOMPILE MESSAGES
// ================================================================================================

/// Message for log_precompile transcript-state tracking on the virtual table bus.
struct LogPrecompileMessage {
    state: PrecompileTranscriptState,
}

impl<E> BusMessage<E> for LogPrecompileMessage
where
    E: ExtensionField<Felt>,
{
    fn value(&self, alphas: &[E]) -> E {
        let state_elements: [Felt; 4] = self.state.into();
        alphas[0]
            + alphas[1] * Felt::from(LOG_PRECOMPILE_LABEL)
            + build_value(&alphas[2..6], state_elements)
    }

    fn source(&self) -> &str {
        "log_precompile"
    }
}

impl core::fmt::Display for LogPrecompileMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{{ state: {:?} }}", self.state)
    }
}

/// Removes the previous transcript state (`CAP_PREV`) from the virtual table bus.
///
/// Helper register layout for `log_precompile` is codified as:
/// - `h0` = hasher address, `h1..h4` = `CAP_PREV[0..3]`.
fn build_log_precompile_capacity_remove<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    row: RowIndex,
    alphas: &[E],
    _debugger: &mut BusDebugger<E>,
) -> E {
    // The previous transcript state is the capacity word provided non-deterministically in the
    // helper registers, offset by 1 to account for the hasher address
    let state = PrecompileTranscriptState::from([
        main_trace.helper_register(HELPER_CAP_PREV_RANGE.start, row),
        main_trace.helper_register(HELPER_CAP_PREV_RANGE.start + 1, row),
        main_trace.helper_register(HELPER_CAP_PREV_RANGE.start + 2, row),
        main_trace.helper_register(HELPER_CAP_PREV_RANGE.start + 3, row),
    ]);

    let message = LogPrecompileMessage { state };
    let value = message.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(message), alphas);

    value
}

/// Inserts the next transcript state (`CAP_NEXT`) into the virtual table bus.
fn build_log_precompile_capacity_insert<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    row: RowIndex,
    alphas: &[E],
    _debugger: &mut BusDebugger<E>,
) -> E {
    // The next transcript state was written in the next row as a Word at index 11..8 (reversed)
    let state: PrecompileTranscriptState = [
        main_trace.stack_element(STACK_CAP_NEXT_RANGE.end - 1, row + 1),
        main_trace.stack_element(STACK_CAP_NEXT_RANGE.end - 2, row + 1),
        main_trace.stack_element(STACK_CAP_NEXT_RANGE.end - 3, row + 1),
        main_trace.stack_element(STACK_CAP_NEXT_RANGE.end - 4, row + 1),
    ]
    .into();

    let message = LogPrecompileMessage { state };
    let value = message.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_response(alloc::boxed::Box::new(message), alphas);

    value
}
