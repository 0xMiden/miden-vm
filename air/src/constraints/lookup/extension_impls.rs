//! Miden-side extension-trait impls pinning the generic
//! [`ConstraintLookupBuilder`] and [`ProverLookupBuilder`] adapters to the
//! Miden [`MainLookupBuilder`] / [`ChipletLookupBuilder`] traits.
//!
//! Both traits require `LookupBuilder<F = Felt>`, so the impls live here
//! (Miden-side) rather than alongside the adapters — the generic adapter
//! code itself is field-polymorphic.
//!
//! Every impl is empty and picks up the default polynomial body of
//! `build_op_flags` / `build_chiplet_active`. The planned prover-side
//! optimization will override these hooks on the prover adapter with a
//! boolean fast path: on the prover side the decoder bits in each row
//! are already concrete 0/1, so `OpFlags` / `ChipletActiveFlags` can be
//! evaluated via boolean algebra (bitwise AND/OR on the known-boolean
//! columns) instead of the polynomial products the constraint path
//! needs. This avoids multiplying through dead-flag products that are
//! guaranteed zero and cuts the per-row fraction-collection cost
//! significantly.

use miden_core::field::ExtensionField;
use miden_crypto::stark::air::LiftedAirBuilder;

use super::{
    chiplet_air::ChipletLookupBuilder, constraint::ConstraintLookupBuilder,
    main_air::MainLookupBuilder, prover::ProverLookupBuilder,
};
use crate::Felt;

// CONSTRAINT PATH
// ================================================================================================

impl<'ab, AB> MainLookupBuilder for ConstraintLookupBuilder<'ab, AB> where
    AB: LiftedAirBuilder<F = Felt>
{
}

impl<'ab, AB> ChipletLookupBuilder for ConstraintLookupBuilder<'ab, AB> where
    AB: LiftedAirBuilder<F = Felt>
{
}

// PROVER PATH
// ================================================================================================

impl<'a, EF> MainLookupBuilder for ProverLookupBuilder<'a, Felt, EF> where EF: ExtensionField<Felt> {}

impl<'a, EF> ChipletLookupBuilder for ProverLookupBuilder<'a, Felt, EF> where
    EF: ExtensionField<Felt>
{
}
