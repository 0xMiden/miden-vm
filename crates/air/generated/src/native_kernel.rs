//! Mechanical concrete-kernel forwarding shared by VM and precompile registrations.

macro_rules! define_native_kernel {
    ($(#[$doc:meta])* $name:ident, $descriptor:ident, $precompute:ident, $eval:ident, $terms:ident) => {
        $(#[$doc])*
        #[derive(Clone, Debug)]
        pub struct $name {
            descriptor: miden_stark::air::native::AirDescriptor<miden_core::Felt>,
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

        impl miden_stark::air::native::AirKernel for $name {
            type F = miden_core::Felt;
            type Prepared<B: p3_field::Algebra<miden_core::Felt>, E: p3_field::Algebra<B>> =
                [E; evaluators::$terms];

            fn descriptor(&self) -> &miden_stark::air::native::AirDescriptor<miden_core::Felt> {
                &self.descriptor
            }

            fn prepare<B: p3_field::Algebra<miden_core::Felt>, E: p3_field::Algebra<B>>(
                &self,
                inputs: miden_stark::air::native::UniformInputs<'_, B, E>,
            ) -> Self::Prepared<B, E> {
                evaluators::$precompute(inputs)
            }

            fn eval_row<S: miden_stark::air::native::LiftedAirBuilder<F = miden_core::Felt>>(
                &self,
                frame: &miden_stark::air::native::Frame<'_, S>,
                inputs: miden_stark::air::native::Inputs<'_, S>,
                prepared: &Self::Prepared<S::Expr, S::ExtExpr>,
                sink: &mut S,
            ) {
                evaluators::$eval(frame, inputs, sink, prepared);
            }
        }
    };
}

pub(crate) use define_native_kernel;
