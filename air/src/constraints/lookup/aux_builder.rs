//! Stateless [`AuxBuilder`] for the Miden VM LogUp lookup argument.
//!
//! [`MidenLookupAuxBuilder`] is the Miden-side glue between the closure-based
//! [`MidenLookupAir`] and the upstream `p3-miden-lifted-air` STARK harness. It
//! is a zero-sized type with no per-trace state: `build_aux_trace` sources
//! Miden's periodic-column layout via [`PeriodicCols::periodic_columns`] and
//! delegates collection + accumulation to the generic [`build_logup_aux`] in
//! `crate::lookup::aux_builder`.
//!
//! ## Public values
//!
//! The [`AuxBuilder`] trait does not thread `public_values` through to
//! `build_aux_trace`, so `build_logup_aux` is invoked with `&[]`. This is
//! sound for the current LogUp setup because the prover-path bus emitters
//! at `air/src/constraints/lookup/buses/*.rs` do not read
//! `builder.public_values()`.

use alloc::vec::Vec;

use miden_core::{Felt, field::ExtensionField, utils::RowMajorMatrix};
use miden_crypto::stark::air::AuxBuilder;

use super::{
    MidenLookupAir,
    bus_id::{MIDEN_MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
};
use crate::{
    constraints::chiplets::columns::PeriodicCols,
    lookup::{Challenges, aux_builder::build_logup_aux},
};

// MIDEN LOOKUP AUX BUILDER
// ================================================================================================

/// Stateless prover-side [`AuxBuilder`] for the Miden VM LogUp lookup argument.
///
/// Zero-sized — every call to [`MidenLookupAuxBuilder::build_aux_trace`] runs
/// the collection phase from scratch using only the inputs the trait provides.
#[derive(Copy, Clone, Debug, Default)]
pub struct MidenLookupAuxBuilder;

impl<EF> AuxBuilder<Felt, EF> for MidenLookupAuxBuilder
where
    EF: ExtensionField<Felt>,
{
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        let _span = tracing::info_span!("build_aux_trace_logup").entered();

        // The constraint-path adapter reads α/β out of `permutation_randomness()[0..2]`
        // (see `ConstraintLookupBuilder::new`) — match that ordering exactly so the
        // prover- and constraint-path challenges line up.
        let alpha = challenges[0];
        let beta = challenges[1];
        let lookup_challenges =
            Challenges::<EF>::new(alpha, beta, MIDEN_MAX_MESSAGE_WIDTH, NUM_BUS_IDS);

        // Periodic columns are part of the AIR's static layout — recomputing them per
        // call is cheap (a fixed set of `Vec<Felt>` constructors) and keeps the builder
        // stateless, matching `ProcessorAir::periodic_columns`.
        let periodic = PeriodicCols::periodic_columns();

        build_logup_aux(&MidenLookupAir, main, &periodic, &[], &lookup_challenges)
    }
}
