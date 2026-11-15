//! Miden-side extension-trait impls pinning the generic
//! [`ConstraintLookupBuilder`] and [`ProverLookupBuilder`] adapters to the
//! Miden lookup-builder extension traits.
//!
//! These traits require `LookupBuilder<F = Felt>`, so the impls live here
//! (Miden-side) rather than alongside the adapters; the generic adapter
//! code itself is field-polymorphic.
//!
//! The constraint-path adapter and the validation builder pick up the default
//! polynomial bodies of [`MainLookupBuilder::build_op_flags`] and
//! [`ChipletLookupBuilder::build_chiplet_active`]. The prover-path adapter
//! overrides `build_op_flags` with
//! [`LookupOpFlags::from_boolean_row`](super::buses::LookupOpFlags::from_boolean_row),
//! which decodes the 7-bit opcode as a `u8` and flips exactly one flag per row
//! instead of materialising the polynomial products the symbolic path needs.
//! `build_chiplet_active` stays on the default; the chiplet selectors produce
//! only six outputs via four subtractions, so the boolean shortcut is noise.

use core::borrow::Borrow;

use miden_core::field::ExtensionField;
use miden_stark::{
    air::{
        LiftedAirBuilder, WindowAccess,
        native::{self, migration::LegacyLookup},
    },
    lookup::{ConstraintLookupBuilder, ProverLookupBuilder, native as native_lookup},
};

use super::{
    and8_lookup_air::And8LookupBuilder,
    buses::LookupOpFlags,
    chiplet_air::{ChipletLookupBuilder, NativeChipletLookupBuilder},
    main_air::{MainLookupBuilder, NativeMainLookupBuilder},
};
use crate::vm::{
    ChipletCols, CoreCols, Felt, constraints::chiplets::selectors::ChipletActiveFlags,
};

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

impl<'ab, AB> And8LookupBuilder for ConstraintLookupBuilder<'ab, AB> where
    AB: LiftedAirBuilder<F = Felt>
{
}

// PROVER PATH
// ================================================================================================

impl<'a, EF> MainLookupBuilder for ProverLookupBuilder<'a, Felt, EF>
where
    EF: ExtensionField<Felt>,
{
    /// Override: use the boolean fast path instead of the default polynomial body.
    ///
    /// On the prover side `decoder.op_bits` are concrete 0/1 Felt values (enforced by the
    /// decoder's boolean constraint), so a `u8` opcode decode + single-field write replaces
    /// ~100 Felt multiplications in the shared prefix tree. Semantics match the default body
    /// on any valid trace; a `debug_assertions` parity check inside `from_boolean_row`
    /// surfaces divergences immediately.
    fn build_op_flags(&self, local: &CoreCols<Felt>, next: &CoreCols<Felt>) -> LookupOpFlags<Felt> {
        LookupOpFlags::from_boolean_row(&local.decoder, &local.stack, &next.decoder)
    }
}

impl<'a, EF> ChipletLookupBuilder for ProverLookupBuilder<'a, Felt, EF> where
    EF: ExtensionField<Felt>
{
}

impl<'a, EF> And8LookupBuilder for ProverLookupBuilder<'a, Felt, EF> where EF: ExtensionField<Felt> {}

// VALIDATION BUILDER
// ================================================================================================
//
// Empty impls for the Felt/QuadFelt-pinned validation builder. It picks up the default
// polynomial bodies of `build_op_flags` / `build_chiplet_active`; the builder only
// compile when the `debug` module is available (gated on `std`), so there's no need
// for a boolean fast-path override.

#[cfg(feature = "std")]
mod debug_impls {
    use miden_stark::lookup::debug::ValidationBuilder;

    use super::{And8LookupBuilder, ChipletLookupBuilder, MainLookupBuilder};

    impl<'ab, 'r> MainLookupBuilder for ValidationBuilder<'ab, 'r> {}
    impl<'ab, 'r> ChipletLookupBuilder for ValidationBuilder<'ab, 'r> {}
    impl<'ab, 'r> And8LookupBuilder for ValidationBuilder<'ab, 'r> {}
}

// NATIVE MAIN-TRACE PATHS
// ================================================================================================

impl<B: native::LiftedAirBuilder<F = Felt>> NativeMainLookupBuilder
    for native_lookup::ConstraintLookupBuilder<'_, '_, B>
{
}

impl<EF: ExtensionField<Felt>> NativeMainLookupBuilder for ProverLookupBuilder<'_, Felt, EF> {
    fn build_op_flags(&self, local: &CoreCols<Felt>, next: &CoreCols<Felt>) -> LookupOpFlags<Felt> {
        LookupOpFlags::from_boolean_row(&local.decoder, &local.stack, &next.decoder)
    }
}

impl<LB: MainLookupBuilder> NativeMainLookupBuilder for LegacyLookup<'_, LB> {
    fn build_op_flags(
        &self,
        _local: &CoreCols<LB::Expr>,
        _next: &CoreCols<LB::Expr>,
    ) -> LookupOpFlags<LB::Expr> {
        // The bridge snapshots and this hook read the same stable builder row pair. Keep a single
        // owned window alive only for flag construction; no legacy row/adapter borrow escapes.
        let builder = self.legacy();
        let main = builder.main();
        let local: &CoreCols<LB::Var> =
            main.current_slice()[..super::super::columns::NUM_CORE_COLS].borrow();
        let next: &CoreCols<LB::Var> =
            main.next_slice()[..super::super::columns::NUM_CORE_COLS].borrow();
        MainLookupBuilder::build_op_flags(builder, local, next)
    }
}

#[cfg(feature = "std")]
impl NativeMainLookupBuilder for native_lookup::NativeValidationBuilder<'_> {}

// NATIVE CHIPLET PATHS
// ================================================================================================

impl<B: native::LiftedAirBuilder<F = Felt>> NativeChipletLookupBuilder
    for native_lookup::ConstraintLookupBuilder<'_, '_, B>
{
}

impl<EF: ExtensionField<Felt>> NativeChipletLookupBuilder for ProverLookupBuilder<'_, Felt, EF> {}

impl<LB: ChipletLookupBuilder> NativeChipletLookupBuilder for LegacyLookup<'_, LB> {
    fn build_chiplet_active(&self, _local: &ChipletCols<LB::Expr>) -> ChipletActiveFlags<LB::Expr> {
        // The bridge and hook read one stable row pair. Return owned flags while the original
        // window is alive, then release all legacy borrows before mutable column callbacks.
        let builder = self.legacy();
        let main = builder.main();
        let local: &ChipletCols<LB::Var> = main.current_slice().borrow();
        ChipletLookupBuilder::build_chiplet_active(builder, local)
    }
}

#[cfg(feature = "std")]
impl NativeChipletLookupBuilder for native_lookup::NativeValidationBuilder<'_> {}
