//! Test support for inspecting and directly materializing Eidos transcript traces.

use miden_core::{Felt, utils::RowMajorMatrix};

use super::{AbsorptionId, EidosRequires, generate_trace_with_byte_lookups};
use crate::primitives::byte_pair_lut::BytePairLutRequires;

/// Constructs a physical absorption ID without allocating it through [`EidosRequires`].
pub(crate) fn forged_absorption_id(absorption_id: u32) -> AbsorptionId {
    AbsorptionId(absorption_id)
}

/// Returns the number of physical compressions allocated by `requires`.
pub(crate) fn total_cycles(requires: &EidosRequires) -> u32 {
    requires.next_seq
}

/// Materializes an Eidos trace while discarding its byte-pair lookup requirements.
pub(crate) fn generate_trace(requires: EidosRequires) -> RowMajorMatrix<Felt> {
    generate_trace_with_byte_lookups(requires, &mut BytePairLutRequires::new())
}
