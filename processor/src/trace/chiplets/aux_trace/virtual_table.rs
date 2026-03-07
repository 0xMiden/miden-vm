use miden_air::trace::{
    LOG_PRECOMPILE_LABEL, MainTrace, RowIndex,
    chiplets::hasher::DIGEST_LEN,
    log_precompile::{HELPER_CAP_PREV_RANGE, STACK_CAP_NEXT_RANGE},
};
use miden_core::{
    Felt, field::ExtensionField, operations::opcodes, precompile::PrecompileTranscriptState,
};

use super::{build_ace_memory_read_element_request, build_ace_memory_read_word_request};
use crate::{
    debug::{BusDebugger, BusMessage},
    trace::{AuxColumnBuilder, utils::Challenges},
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
/// in the first row. If such constraints are required, they must be enforced via
/// `reduced_aux_values` in the last row of the trace.
///
/// If public inputs are required for other chiplets, it is also possible to use the chiplet bus,
/// as is done for the kernel ROM chiplet.
pub struct ChipletsVTableColBuilder;

impl<E> AuxColumnBuilder<E> for ChipletsVTableColBuilder
where
    E: ExtensionField<Felt>,
{
    #[cfg(any(test, feature = "bus-debugger"))]
    fn enforce_bus_balance(&self) -> bool {
        // The chiplets vtable final value encodes transcript state boundary terms,
        // which are checked via reduced_aux_values. It does not balance to identity.
        false
    }

    fn get_requests_at(
        &self,
        main_trace: &MainTrace,
        challenges: &Challenges<E>,
        row: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let op_code = main_trace.get_op_code(row).as_canonical_u64() as u8;
        let log_pc_request = if op_code == opcodes::LOGPRECOMPILE {
            build_log_precompile_capacity_remove(main_trace, row, challenges, _debugger)
        } else {
            E::ONE
        };

        let request_ace = if main_trace.chiplet_ace_is_read_row(row) {
            build_ace_memory_read_word_request(main_trace, challenges, row, _debugger)
        } else if main_trace.chiplet_ace_is_eval_row(row) {
            build_ace_memory_read_element_request(main_trace, challenges, row, _debugger)
        } else {
            E::ONE
        };

        chiplets_vtable_remove_sibling(main_trace, challenges, row) * request_ace * log_pc_request
    }

    fn get_responses_at(
        &self,
        main_trace: &MainTrace,
        challenges: &Challenges<E>,
        row: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let op_code = main_trace.get_op_code(row).as_canonical_u64() as u8;
        let log_pc_response = if op_code == opcodes::LOGPRECOMPILE {
            build_log_precompile_capacity_insert(main_trace, row, challenges, _debugger)
        } else {
            E::ONE
        };

        chiplets_vtable_add_sibling(main_trace, challenges, row) * log_pc_response
    }
}

// VIRTUAL TABLE REQUESTS
// ================================================================================================

/// Range for RATE0 (first rate word) in sponge state.
const RATE0_RANGE: core::ops::Range<usize> = 0..DIGEST_LEN;
/// Range for RATE1 (second rate word) in sponge state.
const RATE1_RANGE: core::ops::Range<usize> = DIGEST_LEN..(2 * DIGEST_LEN);

/// Node is left child (lsb=0), sibling is right child at RATE1: alpha + beta_powers[2]*index +
/// beta_powers[7..10]*sibling
const SIBLING_RATE1_LAYOUT: [usize; 5] = [2, 7, 8, 9, 10];
/// Node is right child (lsb=1), sibling is left child at RATE0: alpha + beta_powers[2]*index +
/// beta_powers[3..6]*sibling
const SIBLING_RATE0_LAYOUT: [usize; 5] = [2, 3, 4, 5, 6];

/// Extracts the node index and sibling word from the trace and encodes a sibling table entry.
///
/// The node index comes from `row`, while the sibling state comes from `state_row`
/// (which may be `row` or `row + 1` depending on whether this is an absorb or
/// absorb-next cycle).
#[inline(always)]
fn encode_sibling_from_trace<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    challenges: &Challenges<E>,
    row: RowIndex,
    state_row: RowIndex,
) -> E {
    let index = main_trace.chiplet_node_index(row);
    let lsb = index.as_canonical_u64() & 1;
    let (layout, sibling) = if lsb == 0 {
        // Node is left child, sibling is right child at RATE1
        (SIBLING_RATE1_LAYOUT, &main_trace.chiplet_hasher_state(state_row)[RATE1_RANGE])
    } else {
        // Node is right child, sibling is left child at RATE0
        (SIBLING_RATE0_LAYOUT, &main_trace.chiplet_hasher_state(state_row)[RATE0_RANGE])
    };
    challenges.encode_sparse(layout, [index, sibling[0], sibling[1], sibling[2], sibling[3]])
}

/// Constructs the removals from the table when the hasher absorbs a new sibling node while
/// computing the new Merkle root.
fn chiplets_vtable_remove_sibling<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    challenges: &Challenges<E>,
    row: RowIndex,
) -> E {
    if main_trace.f_mu(row) {
        encode_sibling_from_trace(main_trace, challenges, row, row)
    } else if main_trace.f_mua(row) {
        encode_sibling_from_trace(main_trace, challenges, row, row + 1)
    } else {
        E::ONE
    }
}

// VIRTUAL TABLE RESPONSES
// ================================================================================================

/// Constructs the inclusions to the table when the hasher absorbs a new sibling node while
/// computing the old Merkle root.
fn chiplets_vtable_add_sibling<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    challenges: &Challenges<E>,
    row: RowIndex,
) -> E {
    if main_trace.f_mv(row) {
        encode_sibling_from_trace(main_trace, challenges, row, row)
    } else if main_trace.f_mva(row) {
        encode_sibling_from_trace(main_trace, challenges, row, row + 1)
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
    fn value(&self, challenges: &Challenges<E>) -> E {
        let state_elements: [Felt; 4] = self.state.into();
        challenges.encode([
            Felt::from_u8(LOG_PRECOMPILE_LABEL),
            state_elements[0],
            state_elements[1],
            state_elements[2],
            state_elements[3],
        ])
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
    challenges: &Challenges<E>,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let state = PrecompileTranscriptState::from([
        main_trace.helper_register(HELPER_CAP_PREV_RANGE.start, row),
        main_trace.helper_register(HELPER_CAP_PREV_RANGE.start + 1, row),
        main_trace.helper_register(HELPER_CAP_PREV_RANGE.start + 2, row),
        main_trace.helper_register(HELPER_CAP_PREV_RANGE.start + 3, row),
    ]);

    let message = LogPrecompileMessage { state };
    let value = message.value(challenges);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(message), challenges);

    value
}

/// Inserts the next transcript state (`CAP_NEXT`) into the virtual table bus.
fn build_log_precompile_capacity_insert<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    row: RowIndex,
    challenges: &Challenges<E>,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let state: PrecompileTranscriptState = [
        main_trace.stack_element(STACK_CAP_NEXT_RANGE.start, row + 1),
        main_trace.stack_element(STACK_CAP_NEXT_RANGE.start + 1, row + 1),
        main_trace.stack_element(STACK_CAP_NEXT_RANGE.start + 2, row + 1),
        main_trace.stack_element(STACK_CAP_NEXT_RANGE.start + 3, row + 1),
    ]
    .into();

    let message = LogPrecompileMessage { state };
    let value = message.value(challenges);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_response(alloc::boxed::Box::new(message), challenges);

    value
}
