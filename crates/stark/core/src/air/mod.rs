//! AIR traits for the Miden lifted STARK protocol.
//!
//! This module provides:
//! - [`LiftedAir`]: super-trait for AIR definitions (inherits upstream + adds aux trace support and
//!   periodic column data)
//! - [`LiftedAirBuilder`]: super-trait for constraint builders
//! - [`MultiAir`]: trusted statement definition for a multi-AIR proof
//! - [`Statement`]: validated per-proof caller inputs over a `MultiAir`
//! - [`ProverStatement`]: validated proving input — a `Statement` plus per-AIR main witness traces
//! - [`debug`]: panic-based AIR structural checks for tests / setup

mod builder;
mod contracts;
pub mod debug;
mod encoding;
mod statement;
mod util;

pub use builder::LiftedAirBuilder;
pub use contracts::{
    ConstraintCounts, ConstraintDegrees, EvalInputs, LiftedAir, MultiAir, ReductionError,
};
pub use encoding::StatementEncoding;
// Re-export upstream p3-air types so downstream crates never need to depend on p3-air
// directly.
pub use p3_air::{
    Air, AirBuilder, AirBuilderWithContext, BaseAir, ExtensionBuilder, FilteredAirBuilder,
    PermutationAirBuilder, RowWindow, WindowAccess,
};
pub use statement::{InstanceError, ProverStatement, Statement};
pub use util::{log2_ceil_u8, log2_strict_u8};

/// Symbolic constraint analysis and AIR evaluation.
pub mod symbolic {
    use alloc::vec::Vec;

    pub use p3_air::symbolic::*;
    use p3_field::{Algebra, ExtensionField, Field};

    use super::{AirBuilder, EvalInputs, LiftedAir, PermutationAirBuilder};

    /// Prepare and evaluate an AIR using the builder's symbolic inputs.
    ///
    /// The builder must have the layout declared by [`LiftedAir::air_layout`].
    pub fn eval_air<F, EF, SEF>(
        air: &impl LiftedAir<F, EF>,
        builder: &mut SymbolicAirBuilder<F, SEF>,
    ) where
        F: Field,
        SEF: ExtensionField<F>,
        SymbolicExpressionExt<F, SEF>: Algebra<SEF>,
    {
        let public_values =
            builder.public_values().iter().copied().map(Into::into).collect::<Vec<_>>();
        let challenges = builder
            .permutation_randomness()
            .iter()
            .copied()
            .map(Into::into)
            .collect::<Vec<_>>();
        let aux_values =
            builder.permutation_values().iter().cloned().map(Into::into).collect::<Vec<_>>();
        let data =
            air.prepare::<SymbolicExpression<F>, SymbolicExpressionExt<F, SEF>>(EvalInputs {
                public_values: &public_values,
                challenges: &challenges,
                aux_values: &aux_values,
            });
        air.eval(builder, &data);
    }
}

/// AIR constraint utility functions from upstream p3-air.
pub mod utils {
    pub use p3_air::utils::*;
}
