use alloc::vec::Vec;

use miden_air::trace::MainTrace;
use miden_core::field::ExtensionField;
use wiring_bus::WiringBusBuilder;

use super::{Felt, ace::AceHints};
use crate::trace::{AuxColumnBuilder, utils::Challenges};

mod bus;
pub use bus::{
    BusColumnBuilder, build_ace_memory_read_element_request, build_ace_memory_read_word_request,
};

mod virtual_table;
pub use virtual_table::ChipletsVTableColBuilder;

mod wiring_bus;

/// Constructs the execution trace for chiplets-related auxiliary columns (used in multiset checks).
#[derive(Debug, Clone)]
pub struct AuxTraceBuilder {
    ace_hints: AceHints,
}

impl AuxTraceBuilder {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    pub fn new(ace_hints: AceHints) -> Self {
        Self { ace_hints }
    }

    // COLUMN TRACE CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Builds and returns the Chiplets's auxiliary trace columns. This consists of:
    ///
    /// 1. A bus column `b_chip` describing requests made by the stack and decoder and responses
    ///    received from the chiplets in the Chiplets module. It also responds to requests made by
    ///    the verifier with kernel procedure hashes included in the public inputs of the program.
    /// 2. A column acting as
    ///    - a virtual table for the sibling table used by the hasher chiplet,
    ///    - a bus between the memory chiplet and the ACE chiplet.
    /// 3. A column used as a bus to wire the gates of the ACE chiplet.
    pub(crate) fn build_aux_columns<E: ExtensionField<Felt>>(
        &self,
        main_trace: &MainTrace,
        challenges: &Challenges<E>,
    ) -> [Vec<E>; 3] {
        let v_table_col_builder = ChipletsVTableColBuilder;
        let bus_col_builder = BusColumnBuilder;
        let wiring_bus_builder = WiringBusBuilder::new(&self.ace_hints);
        let t_chip = v_table_col_builder.build_aux_column(main_trace, challenges);
        let b_chip = bus_col_builder.build_aux_column(main_trace, challenges);
        let wiring_bus = wiring_bus_builder.build_aux_column(main_trace, challenges);

        // When debugging, check that the LogUp wiring bus balances.
        // The vtable and chiplets bus final values are non-trivial (they encode public-input-
        // dependent boundary terms) and are checked by the verifier in reduced_aux_values.
        let log_up_final_value = wiring_bus.last().copied().unwrap_or(E::ZERO);
        debug_assert_eq!(log_up_final_value, E::ZERO);

        [t_chip, b_chip, wiring_bus]
    }
}
