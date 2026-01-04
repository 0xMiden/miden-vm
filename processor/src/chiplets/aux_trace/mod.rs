use alloc::vec::Vec;

use miden_air::trace::MainTrace;
use miden_core::{Kernel, field::ExtensionField, precompile::PrecompileTranscriptState};
use wiring_bus::WiringBusBuilder;

use super::{super::trace::AuxColumnBuilder, Felt, ace::AceHints};

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
    kernel: Kernel,
    ace_hints: AceHints,
    /// Final precompile transcript state (sponge capacity) emitted by the VM.
    final_transcript_state: PrecompileTranscriptState,
}

impl AuxTraceBuilder {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    pub fn new(
        kernel: Kernel,
        ace_hints: AceHints,
        final_transcript_state: PrecompileTranscriptState,
    ) -> Self {
        Self {
            kernel,
            ace_hints,
            final_transcript_state,
        }
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
    pub fn build_aux_columns<E: ExtensionField<Felt>>(
        &self,
        main_trace: &MainTrace,
        rand_elements: &[E],
    ) -> [Vec<E>; 3] {
        let v_table_col_builder = ChipletsVTableColBuilder::new(self.final_transcript_state);
        let bus_col_builder = BusColumnBuilder::new(&self.kernel);
        let wiring_bus_builder = WiringBusBuilder::new(&self.ace_hints);
        let t_chip = v_table_col_builder.build_aux_column(main_trace, rand_elements);
        let b_chip = bus_col_builder.build_aux_column(main_trace, rand_elements);
        let wiring_bus = wiring_bus_builder.build_aux_column(main_trace, rand_elements);

        // When debugging, check that all multi-set and logUp interactions are valid.
        let v_table_final_value = t_chip.last().copied().unwrap_or(E::ONE);
        let chiplets_bus_final_value = b_chip.last().copied().unwrap_or(E::ONE);
        let log_up_final_value = wiring_bus.last().copied().unwrap_or(E::ZERO);

        debug_assert_eq!(log_up_final_value, E::ZERO);
        debug_assert_eq!(v_table_final_value * chiplets_bus_final_value, E::ONE);

        [t_chip, b_chip, wiring_bus]
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Runs an inner product between the alphas and the elements.
#[inline(always)]
fn build_value<E, const N: usize>(alphas: &[E], elements: [Felt; N]) -> E
where
    E: ExtensionField<Felt>,
{
    debug_assert_eq!(alphas.len(), elements.len());
    let mut value = alphas[0] * elements[0];
    for i in 1..N {
        value += alphas[i] * elements[i];
    }
    value
}
