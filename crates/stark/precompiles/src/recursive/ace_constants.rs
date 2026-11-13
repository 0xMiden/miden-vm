//! Helpers shared by PVM artifact regeneration and independent circuit tests.

use miden_core::{Felt, Word};

/// Command line that regenerates the generated MASM modules, quoted in their headers.
pub(crate) const GENERATED_BY: &str = "cargo run -p miden-precompiles-stark --release \
     --features constants-tools --bin pvm-constants-regen -- --write";

/// Computes the relation digest binding an ACE circuit commitment into the Fiat-Shamir transcript.
pub(crate) fn relation_digest_for_circuit(circuit_digest: &Word) -> [Felt; 4] {
    miden_stark::config::relation_digest(
        miden_air::precompiles::policy::PROTOCOL_ID,
        circuit_digest,
    )
}
