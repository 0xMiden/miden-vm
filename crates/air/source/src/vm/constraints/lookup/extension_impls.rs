//! Miden-side extension-trait impls pinning the generic
//! [`lookup::ConstraintLookupBuilder`] and [`ProverLookupBuilder`] adapters to the
//! Miden lookup-builder extension traits.
//!
//! These traits require `LookupBuilder<F = Felt>`, so the impls live here
//! (Miden-side) rather than alongside the adapters; the generic adapter
//! code itself is field-polymorphic.
//!
//! The constraint-path adapter and the validation builder pick up the default
//! polynomial bodies of [`NativeMainLookupBuilder::build_op_flags`] and
//! [`NativeChipletLookupBuilder::build_chiplet_active`]. The prover-path adapter
//! overrides `build_op_flags` with
//! [`LookupOpFlags::from_boolean_row`](super::buses::LookupOpFlags::from_boolean_row),
//! which decodes the 7-bit opcode as a `u8` and flips exactly one flag per row
//! instead of materialising the polynomial products the symbolic path needs.
//! `build_chiplet_active` stays on the default; the chiplet selectors produce
//! only six outputs via four subtractions, so the boolean shortcut is noise.

use miden_core::field::ExtensionField;
use miden_stark::{
    air,
    lookup::{self, ProverLookupBuilder},
};

use super::{
    buses::LookupOpFlags, chiplet_air::NativeChipletLookupBuilder,
    main_air::NativeMainLookupBuilder,
};
use crate::vm::{CoreCols, Felt};

impl<B: air::LiftedAirBuilder<F = Felt>> NativeMainLookupBuilder
    for lookup::ConstraintLookupBuilder<'_, '_, B>
{
}

impl<EF: ExtensionField<Felt>> NativeMainLookupBuilder for ProverLookupBuilder<'_, Felt, EF> {
    fn build_op_flags(&self, local: &CoreCols<Felt>, next: &CoreCols<Felt>) -> LookupOpFlags<Felt> {
        LookupOpFlags::from_boolean_row(&local.decoder, &local.stack, &next.decoder)
    }
}

#[cfg(feature = "std")]
impl NativeMainLookupBuilder for lookup::NativeValidationBuilder<'_> {}

impl<B: air::LiftedAirBuilder<F = Felt>> NativeChipletLookupBuilder
    for lookup::ConstraintLookupBuilder<'_, '_, B>
{
}

impl<EF: ExtensionField<Felt>> NativeChipletLookupBuilder for ProverLookupBuilder<'_, Felt, EF> {}

#[cfg(feature = "std")]
impl NativeChipletLookupBuilder for lookup::NativeValidationBuilder<'_> {}
