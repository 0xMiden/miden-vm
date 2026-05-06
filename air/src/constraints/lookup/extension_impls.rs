//! Miden-side extension-trait impls pinning the generic
//! [`ConstraintLookupBuilder`] and [`ProverLookupBuilder`] adapters to the
//! Miden [`MainLookupBuilder`] / [`ChipletLookupBuilder`] traits.
//!
//! Both traits require `LookupBuilder<F = Felt>`, so the impls live here
//! (Miden-side) rather than alongside the adapters — the generic adapter
//! code itself is field-polymorphic.
//!
//! The constraint-path adapter and the two debug builders pick up the default
//! polynomial bodies of [`MainLookupBuilder::build_op_flags`] and
//! [`ChipletLookupBuilder::build_chiplet_active`]. The prover-path adapter
//! overrides `build_op_flags` with
//! [`LookupOpFlags::from_boolean_row`](super::buses::LookupOpFlags::from_boolean_row),
//! which decodes the 7-bit opcode as a `u8` and flips exactly one flag per row
//! instead of materialising the polynomial products the symbolic path needs.
//! `build_chiplet_active` stays on the default — the chiplet selectors produce
//! only six outputs via four subtractions, so the boolean shortcut is noise.

use miden_core::field::ExtensionField;
use miden_crypto::stark::air::LiftedAirBuilder;

use super::{buses::LookupOpFlags, chiplet_air::ChipletLookupBuilder, main_air::MainLookupBuilder};
use crate::{
    Felt, MainCols,
    lookup::{ConstraintLookupBuilder, ProverLookupBuilder},
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
    /// on any valid trace — a `debug_assertions` parity check inside `from_boolean_row`
    /// surfaces divergences immediately.
    fn build_op_flags(
        &self,
        local: &MainCols<Self::Var>,
        next: &MainCols<Self::Var>,
    ) -> LookupOpFlags<Self::Expr> {
        LookupOpFlags::from_boolean_row(&local.decoder, &local.stack, &next.decoder)
    }
}

impl<'a, EF> ChipletLookupBuilder for ProverLookupBuilder<'a, Felt, EF> where
    EF: ExtensionField<Felt>
{
}

// DEBUG BUILDERS
// ================================================================================================
//
// Empty impls for the Felt/QuadFelt-pinned debug builders. They pick up the default
// polynomial bodies of `build_op_flags` / `build_chiplet_active`; the builders only
// compile when the `debug` module is available (gated on `std`), so there's no need
// for a boolean fast-path override.

#[cfg(feature = "std")]
mod debug_impls {
    use super::{ChipletLookupBuilder, MainLookupBuilder};
    use crate::lookup::debug::{DebugTraceBuilder, ValidationBuilder};

    impl<'ab, 'r> MainLookupBuilder for ValidationBuilder<'ab, 'r> {}
    impl<'ab, 'r> ChipletLookupBuilder for ValidationBuilder<'ab, 'r> {}

    impl<'a> MainLookupBuilder for DebugTraceBuilder<'a> {}
    impl<'a> ChipletLookupBuilder for DebugTraceBuilder<'a> {}
}
