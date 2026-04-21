//! End-to-end AIR self-check for `MidenLookupAir` against `ProcessorAir`'s layout.
//!
//! Runs [`ValidateLookupAir::validate`] on `MidenLookupAir` with the number of
//! periodic columns taken from the production `ProcessorAir` so the symbolic
//! degree walker sees the same symbolic environment the real prover does. Any
//! drift between declared and observed degrees, column counts, cached-encoding
//! `(U, V)` parity, or simple-group scope surfaces here.
//!
//! ```sh
//! cargo test -p miden-air --test bus_degree_inventory
//! ```

use miden_air::{
    LiftedAir, NUM_PUBLIC_VALUES, ProcessorAir,
    logup::{MidenLookupAir, NUM_LOGUP_COMMITTED_FINALS},
    lookup::debug::{ValidateLayout, ValidateLookupAir},
    trace::{AUX_TRACE_RAND_CHALLENGES, AUX_TRACE_WIDTH, TRACE_WIDTH},
};
use miden_core::{Felt, field::QuadFelt};

#[test]
fn validate() {
    let layout = ValidateLayout {
        trace_width: TRACE_WIDTH,
        num_public_values: NUM_PUBLIC_VALUES,
        num_periodic_columns: LiftedAir::<Felt, QuadFelt>::periodic_columns(&ProcessorAir).len(),
        permutation_width: AUX_TRACE_WIDTH,
        num_permutation_challenges: AUX_TRACE_RAND_CHALLENGES,
        num_permutation_values: NUM_LOGUP_COMMITTED_FINALS,
    };
    MidenLookupAir
        .validate(layout)
        .unwrap_or_else(|err| panic!("MidenLookupAir validation failed: {err}"));
}
