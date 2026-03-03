use miden_air::trace::{
    LOG_PRECOMPILE_LABEL, MainTrace, RowIndex,
    chiplets::hasher::DIGEST_LEN,
    log_precompile::{HELPER_CAP_PREV_RANGE, STACK_CAP_NEXT_RANGE},
};
use miden_core::{
    Felt, field::ExtensionField, operations::OPCODE_LOGPRECOMPILE,
    precompile::PrecompileTranscriptState,
};

use super::{build_ace_memory_read_element_request, build_ace_memory_read_word_request};
use crate::{
    debug::{BusDebugger, BusMessage},
    trace::{
        AuxColumnBuilder,
        utils::{AuxChallenges, MessageLayout},
    },
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
        challenges: &AuxChallenges<E>,
        row: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let op_code = main_trace.get_op_code(row).as_canonical_u64() as u8;
        let log_pc_request = if op_code == OPCODE_LOGPRECOMPILE {
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
        challenges: &AuxChallenges<E>,
        row: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let op_code = main_trace.get_op_code(row).as_canonical_u64() as u8;
        let log_pc_response = if op_code == OPCODE_LOGPRECOMPILE {
            build_log_precompile_capacity_insert(main_trace, row, challenges, _debugger)
        } else {
            E::ONE
        };

        chiplets_vtable_add_sibling(main_trace, challenges, row) * log_pc_response
    }

    fn init_requests(
        &self,
        _main_trace: &MainTrace,
        challenges: &AuxChallenges<E>,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let message = LogPrecompileMessage { state: self.final_transcript_state };
        let value = message.value(challenges);

        #[cfg(any(test, feature = "bus-debugger"))]
        _debugger.add_request(alloc::boxed::Box::new(message), challenges);

        value
    }

    fn init_responses(
        &self,
        _main_trace: &MainTrace,
        challenges: &AuxChallenges<E>,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let message = LogPrecompileMessage {
            state: PrecompileTranscriptState::default(),
        };
        let value = message.value(challenges);

        #[cfg(any(test, feature = "bus-debugger"))]
        _debugger.add_response(alloc::boxed::Box::new(message), challenges);

        value
    }
}

// VIRTUAL TABLE REQUESTS
// ================================================================================================

/// Range for RATE0 (first rate word) in sponge state.
const RATE0_RANGE: core::ops::Range<usize> = 0..DIGEST_LEN;
/// Range for RATE1 (second rate word) in sponge state.
const RATE1_RANGE: core::ops::Range<usize> = DIGEST_LEN..(2 * DIGEST_LEN);

/// Node is left child (lsb=0), sibling is right child at RATE1: alpha + coeffs[3]*index +
/// coeffs[8..11]*sibling
const SIBLING_RATE1_LAYOUT: MessageLayout<5> = MessageLayout::new([3, 8, 9, 10, 11]);
/// Node is right child (lsb=1), sibling is left child at RATE0: alpha + coeffs[3]*index +
/// coeffs[4..7]*sibling
const SIBLING_RATE0_LAYOUT: MessageLayout<5> = MessageLayout::new([3, 4, 5, 6, 7]);

/// Encodes a sibling table entry given the node index and sibling word.
#[inline(always)]
fn encode_sibling<E: ExtensionField<Felt>>(
    challenges: &AuxChallenges<E>,
    index: Felt,
    sibling: &[Felt],
) -> E {
    let lsb = index.as_canonical_u64() & 1;
    if lsb == 0 {
        // Node is left child, sibling is right child at RATE1
        challenges.encode_layout(
            &SIBLING_RATE1_LAYOUT,
            [index, sibling[0], sibling[1], sibling[2], sibling[3]],
        )
    } else {
        // Node is right child, sibling is left child at RATE0
        challenges.encode_layout(
            &SIBLING_RATE0_LAYOUT,
            [index, sibling[0], sibling[1], sibling[2], sibling[3]],
        )
    }
}

/// Constructs the removals from the table when the hasher absorbs a new sibling node while
/// computing the new Merkle root.
fn chiplets_vtable_remove_sibling<E>(
    main_trace: &MainTrace,
    challenges: &AuxChallenges<E>,
    row: RowIndex,
) -> E
where
    E: ExtensionField<Felt>,
{
    let f_mu: bool = main_trace.f_mu(row);
    let f_mua: bool = main_trace.f_mua(row);

    if f_mu {
        let index = main_trace.chiplet_node_index(row);
        let lsb = index.as_canonical_u64() & 1;
        let sibling = if lsb == 0 {
            &main_trace.chiplet_hasher_state(row)[RATE1_RANGE]
        } else {
            &main_trace.chiplet_hasher_state(row)[RATE0_RANGE]
        };
        encode_sibling(challenges, index, sibling)
    } else if f_mua {
        let index = main_trace.chiplet_node_index(row);
        let lsb = index.as_canonical_u64() & 1;
        let sibling = if lsb == 0 {
            &main_trace.chiplet_hasher_state(row + 1)[RATE1_RANGE]
        } else {
            &main_trace.chiplet_hasher_state(row + 1)[RATE0_RANGE]
        };
        encode_sibling(challenges, index, sibling)
    } else {
        E::ONE
    }
}

// VIRTUAL TABLE RESPONSES
// ================================================================================================

/// Constructs the inclusions to the table when the hasher absorbs a new sibling node while
/// computing the old Merkle root.
fn chiplets_vtable_add_sibling<E>(
    main_trace: &MainTrace,
    challenges: &AuxChallenges<E>,
    row: RowIndex,
) -> E
where
    E: ExtensionField<Felt>,
{
    let f_mv: bool = main_trace.f_mv(row);
    let f_mva: bool = main_trace.f_mva(row);

    if f_mv {
        let index = main_trace.chiplet_node_index(row);
        let lsb = index.as_canonical_u64() & 1;
        let sibling = if lsb == 0 {
            &main_trace.chiplet_hasher_state(row)[RATE1_RANGE]
        } else {
            &main_trace.chiplet_hasher_state(row)[RATE0_RANGE]
        };
        encode_sibling(challenges, index, sibling)
    } else if f_mva {
        let index = main_trace.chiplet_node_index(row);
        let lsb = index.as_canonical_u64() & 1;
        let sibling = if lsb == 0 {
            &main_trace.chiplet_hasher_state(row + 1)[RATE1_RANGE]
        } else {
            &main_trace.chiplet_hasher_state(row + 1)[RATE0_RANGE]
        };
        encode_sibling(challenges, index, sibling)
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
    fn value(&self, challenges: &AuxChallenges<E>) -> E {
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
    challenges: &AuxChallenges<E>,
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
    challenges: &AuxChallenges<E>,
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
