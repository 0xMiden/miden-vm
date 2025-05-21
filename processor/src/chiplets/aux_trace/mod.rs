use alloc::vec::Vec;

use miden_air::trace::main_trace::MainTrace;
use vm_core::Kernel;
use wiring_bus::WiringBusBuilder;

use super::{super::trace::AuxColumnBuilder, Felt, FieldElement, ace::AceHints};

mod bus;
pub use bus::{
    BusColumnBuilder, build_ace_memory_read_element_request, build_ace_memory_read_word_request,
};

mod virtual_table;
pub use virtual_table::ChipletsVTableColBuilder;

mod wiring_bus;

/// Constructs the execution trace for chiplets-related auxiliary columns (used in multiset checks).
#[derive(Debug)]
pub struct AuxTraceBuilder {
    kernel: Kernel,
    ace_hints: AceHints,
}

impl AuxTraceBuilder {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    pub fn new(kernel: Kernel, ace_hints: AceHints) -> Self {
        Self { kernel, ace_hints }
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
    pub fn build_aux_columns<E: FieldElement<BaseField = Felt>>(
        &self,
        main_trace: &MainTrace,
        rand_elements: &[E],
    ) -> [Vec<E>; 3] {
        let v_table_col_builder = ChipletsVTableColBuilder::default();
        let bus_col_builder = BusColumnBuilder::new(&self.kernel);
        let wiring_bus_builder = WiringBusBuilder::new(&self.ace_hints);
        let t_chip = v_table_col_builder.build_aux_column(main_trace, rand_elements);
        let b_chip = bus_col_builder.build_aux_column(main_trace, rand_elements);
        let wiring_bus = wiring_bus_builder.build_aux_column(main_trace, rand_elements);

        // When debugging, check that all multi-set and logUp interactions are valid.
        let v_table_final_value = t_chip.last().copied().unwrap_or(E::ONE);
        debug_assert_eq!(v_table_final_value, E::ONE);

        let chiplets_bus_final_value = b_chip.last().copied().unwrap_or(E::ONE);
        debug_assert_eq!(chiplets_bus_final_value, E::ONE);

        let log_up_final_value = wiring_bus.last().copied().unwrap_or(E::ZERO);
        debug_assert_eq!(log_up_final_value, E::ZERO);

        [t_chip, b_chip, wiring_bus]
    }
}
