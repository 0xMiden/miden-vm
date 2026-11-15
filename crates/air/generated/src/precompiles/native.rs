//! Prepared native kernels for independently completed precompile source ports.

use miden_core::Felt;
use miden_stark::air::native::{
    AirDescriptor, AirKernel, Frame, Inputs, LiftedAirBuilder, UniformInputs,
};
use p3_field::Algebra;

#[allow(clippy::eq_op)]
mod evaluators {
    include!(concat!(env!("OUT_DIR"), "/pvm_native_evaluators.rs"));
}

mod descriptors {
    include!(concat!(env!("OUT_DIR"), "/pvm_native_descriptors.rs"));
}

// Concrete types share descriptor ownership and typed forwarding. Each invocation names the
// generated functions and exact schedule capacity; equations and preparation remain generated.
macro_rules! define_kernel {
    ($(#[$doc:meta])* $name:ident, $descriptor:ident, $precompute:ident, $eval:ident, $terms:ident) => {
        $(#[$doc])*
        #[derive(Clone, Debug)]
        pub struct $name {
            descriptor: AirDescriptor<Felt>,
        }

        impl $name {
            pub fn new() -> Self {
                Self { descriptor: descriptors::$descriptor() }
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl AirKernel for $name {
            type F = Felt;
            type Prepared<B: Algebra<Felt>, E: Algebra<B>> = [E; evaluators::$terms];

            fn descriptor(&self) -> &AirDescriptor<Felt> {
                &self.descriptor
            }

            fn prepare<B: Algebra<Felt>, E: Algebra<B>>(
                &self,
                inputs: UniformInputs<'_, B, E>,
            ) -> Self::Prepared<B, E> {
                evaluators::$precompute(inputs)
            }

            fn eval_row<S: LiftedAirBuilder<F = Felt>>(
                &self,
                frame: &Frame<'_, S>,
                inputs: Inputs<'_, S>,
                prepared: &Self::Prepared<S::Expr, S::ExtExpr>,
                sink: &mut S,
            ) {
                evaluators::$eval(frame, inputs, sink, prepared);
            }
        }
    };
}

define_kernel!(
    /// Generated execution of the authored Keccak-round relation.
    ///
    /// Construction owns an embedded descriptor without source recapture or fixed-table building.
    /// Witness construction remains on the authored
    /// [`KeccakRoundAir`](miden_air_definitions::precompiles::hash::keccak::round::KeccakRoundAir).
    /// The canonical multi-AIR runtime selects its current wrapper until activation.
    KeccakRoundKernel,
    descriptor_keccak_round,
    precompute_keccak_round,
    eval_keccak_round,
    KECCAK_ROUND_PREPARED_TERMS
);

define_kernel!(
    /// Generated execution of the composed SHA-256 relation and its shared lookup columns.
    ///
    /// Construction owns an embedded descriptor without source recapture or fixed-table building.
    /// Witness construction remains on the authored
    /// [`Sha256Air`](miden_air_definitions::precompiles::hash::sha256::Sha256Air).
    /// The canonical multi-AIR runtime selects its current wrapper until activation.
    Sha256Kernel,
    descriptor_sha256,
    precompute_sha256,
    eval_sha256,
    SHA256_PREPARED_TERMS
);
