use core::fmt::{Display, Formatter, Result as FmtResult};

use miden_air::{
    RowIndex,
    trace::{
        chiplets::hasher::{self, DIGEST_RANGE},
        main_trace::MainTrace,
    },
};
use miden_core::{Felt, OPCODE_LOGPRECOMPILE, Word};

use super::{
    FieldElement, build_ace_memory_read_element_request, build_ace_memory_read_word_request,
};
use crate::{
    chiplets::aux_trace::build_value,
    debug::{BusDebugger, BusMessage},
    trace::AuxColumnBuilder,
};

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
    final_capacity: Word,
}

impl ChipletsVTableColBuilder {
    pub fn new(final_capacity: Word) -> Self {
        Self { final_capacity }
    }
}

impl<E> AuxColumnBuilder<E> for ChipletsVTableColBuilder
where
    E: FieldElement<BaseField = Felt>,
{
    fn get_requests_at(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
        row: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        // Check if this is a log_precompile operation
        let op_code = main_trace.get_op_code(row).as_int() as u8;
        let log_precompile_request = if op_code == OPCODE_LOGPRECOMPILE {
            build_log_precompile_message(
                LogPrecompileMessageType::Request,
                Some(main_trace),
                Some(row),
                None,
                alphas,
                _debugger,
            )
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

        chiplets_vtable_remove_sibling(main_trace, alphas, row)
            * request_ace
            * log_precompile_request
    }

    fn get_responses_at(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
        row: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        // Check if this is a log_precompile operation - send capacity response
        let op_code = main_trace.get_op_code(row).as_int() as u8;
        let log_precompile_response = if op_code == OPCODE_LOGPRECOMPILE {
            build_log_precompile_message(
                LogPrecompileMessageType::Response,
                Some(main_trace),
                Some(row),
                None,
                alphas,
                _debugger,
            )
        } else {
            E::ONE
        };

        chiplets_vtable_add_sibling(main_trace, alphas, row) * log_precompile_response
    }

    fn init_requests(
        &self,
        _main_trace: &MainTrace,
        alphas: &[E],
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        // Send final capacity request at initialization (will be checked at the end of trace)
        build_log_precompile_message(
            LogPrecompileMessageType::Final,
            None,
            None,
            Some(self.final_capacity),
            alphas,
            _debugger,
        )
    }

    fn init_responses(
        &self,
        _main_trace: &MainTrace,
        alphas: &[E],
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        build_log_precompile_message(
            LogPrecompileMessageType::Init,
            None,
            None,
            None,
            alphas,
            _debugger,
        )
    }
}

// VIRTUAL TABLE REQUESTS
// ================================================================================================

/// Constructs the removals from the table when the hasher absorbs a new sibling node while
/// computing the new Merkle root.
fn chiplets_vtable_remove_sibling<E>(main_trace: &MainTrace, alphas: &[E], row: RowIndex) -> E
where
    E: FieldElement<BaseField = Felt>,
{
    let f_mu: bool = main_trace.f_mu(row);
    let f_mua: bool = main_trace.f_mua(row);

    if f_mu {
        let index = main_trace.chiplet_node_index(row);
        let lsb = index.as_int() & 1;
        if lsb == 0 {
            let sibling = &main_trace.chiplet_hasher_state(row)[DIGEST_RANGE.end..];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[12].mul_base(sibling[0])
                + alphas[13].mul_base(sibling[1])
                + alphas[14].mul_base(sibling[2])
                + alphas[15].mul_base(sibling[3])
        } else {
            let sibling = &main_trace.chiplet_hasher_state(row)[DIGEST_RANGE];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[8].mul_base(sibling[0])
                + alphas[9].mul_base(sibling[1])
                + alphas[10].mul_base(sibling[2])
                + alphas[11].mul_base(sibling[3])
        }
    } else if f_mua {
        let index = main_trace.chiplet_node_index(row);
        let lsb = index.as_int() & 1;
        if lsb == 0 {
            let sibling = &main_trace.chiplet_hasher_state(row + 1)[DIGEST_RANGE.end..];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[12].mul_base(sibling[0])
                + alphas[13].mul_base(sibling[1])
                + alphas[14].mul_base(sibling[2])
                + alphas[15].mul_base(sibling[3])
        } else {
            let sibling = &main_trace.chiplet_hasher_state(row + 1)[DIGEST_RANGE];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[8].mul_base(sibling[0])
                + alphas[9].mul_base(sibling[1])
                + alphas[10].mul_base(sibling[2])
                + alphas[11].mul_base(sibling[3])
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
    E: FieldElement<BaseField = Felt>,
{
    let f_mv: bool = main_trace.f_mv(row);
    let f_mva: bool = main_trace.f_mva(row);

    if f_mv {
        let index = main_trace.chiplet_node_index(row);
        let lsb = index.as_int() & 1;
        if lsb == 0 {
            let sibling = &main_trace.chiplet_hasher_state(row)[DIGEST_RANGE.end..];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[12].mul_base(sibling[0])
                + alphas[13].mul_base(sibling[1])
                + alphas[14].mul_base(sibling[2])
                + alphas[15].mul_base(sibling[3])
        } else {
            let sibling = &main_trace.chiplet_hasher_state(row)[DIGEST_RANGE];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[8].mul_base(sibling[0])
                + alphas[9].mul_base(sibling[1])
                + alphas[10].mul_base(sibling[2])
                + alphas[11].mul_base(sibling[3])
        }
    } else if f_mva {
        let index = main_trace.chiplet_node_index(row);
        let lsb = index.as_int() & 1;
        if lsb == 0 {
            let sibling = &main_trace.chiplet_hasher_state(row + 1)[DIGEST_RANGE.end..];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[12].mul_base(sibling[0])
                + alphas[13].mul_base(sibling[1])
                + alphas[14].mul_base(sibling[2])
                + alphas[15].mul_base(sibling[3])
        } else {
            let sibling = &main_trace.chiplet_hasher_state(row + 1)[DIGEST_RANGE];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[8].mul_base(sibling[0])
                + alphas[9].mul_base(sibling[1])
                + alphas[10].mul_base(sibling[2])
                + alphas[11].mul_base(sibling[3])
        }
    } else {
        E::ONE
    }
}

// LOG PRECOMPILE MESSAGES
// ================================================================================================

/// Type of log_precompile message for debugging purposes.
#[derive(Debug, Clone, Copy)]
enum LogPrecompileMessageType {
    /// Initial capacity response at first row (capacity = [0,0,0,0])
    Init,
    /// Final capacity request at trace boundary
    Final,
    /// Capacity request during execution
    Request,
    /// Capacity response during execution
    Response,
}

impl Display for LogPrecompileMessageType {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Init => write!(f, "init"),
            Self::Final => write!(f, "final"),
            Self::Request => write!(f, "request"),
            Self::Response => write!(f, "response"),
        }
    }
}

/// Message for log_precompile capacity tracking on the virtual table bus.
struct LogPrecompileMessage {
    capacity: Word,
    msg_type: LogPrecompileMessageType,
}

impl<E> BusMessage<E> for LogPrecompileMessage
where
    E: FieldElement<BaseField = Felt>,
{
    fn value(&self, alphas: &[E]) -> E {
        let capacity_array: [Felt; 4] = self.capacity.into();
        alphas[0]
            + alphas[1].mul_base(Felt::from(hasher::LOG_PRECOMPILE_CAP_LABEL))
            + build_value(&alphas[2..6], capacity_array)
    }

    fn source(&self) -> &str {
        "log_precompile"
    }
}

impl Display for LogPrecompileMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{{ type: {}, capacity: {:?} }}", self.msg_type, self.capacity)
    }
}

// LOG PRECOMPILE BUILDER FUNCTIONS
// ================================================================================================

/// Builds a log_precompile message based on the message type.
///
/// The capacity value and request/response direction are determined by the message type:
/// - Init: capacity = [0,0,0,0], response
/// - Final: capacity = final_capacity parameter, request
/// - Request: capacity = cap_prev from helper registers h1..h4, request
/// - Response: capacity = cap_next from stack positions 8-11 in next row, response
fn build_log_precompile_message<E: FieldElement<BaseField = Felt>>(
    msg_type: LogPrecompileMessageType,
    main_trace: Option<&MainTrace>,
    row: Option<RowIndex>,
    final_capacity: Option<Word>,
    alphas: &[E],
    _debugger: &mut BusDebugger<E>,
) -> E {
    let capacity = match msg_type {
        LogPrecompileMessageType::Init => Word::default(),
        LogPrecompileMessageType::Final => {
            final_capacity.expect("final_capacity required for Final message")
        },
        LogPrecompileMessageType::Request => {
            let trace = main_trace.expect("main_trace required for Request message");
            let r = row.expect("row required for Request message");
            [
                trace.helper_register(1, r),
                trace.helper_register(2, r),
                trace.helper_register(3, r),
                trace.helper_register(4, r),
            ]
            .into()
        },
        LogPrecompileMessageType::Response => {
            let trace = main_trace.expect("main_trace required for Response message");
            let r = row.expect("row required for Response message");
            // Stack is reversed, so s8 is CAP_NEXT[3], s11 is CAP_NEXT[0]
            [
                trace.stack_element(11, r + 1),
                trace.stack_element(10, r + 1),
                trace.stack_element(9, r + 1),
                trace.stack_element(8, r + 1),
            ]
            .into()
        },
    };

    let message = LogPrecompileMessage { capacity, msg_type };
    let value = message.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    match msg_type {
        LogPrecompileMessageType::Init | LogPrecompileMessageType::Response => {
            _debugger.add_response(alloc::boxed::Box::new(message), alphas);
        },
        LogPrecompileMessageType::Final | LogPrecompileMessageType::Request => {
            _debugger.add_request(alloc::boxed::Box::new(message), alphas);
        },
    }

    value
}
