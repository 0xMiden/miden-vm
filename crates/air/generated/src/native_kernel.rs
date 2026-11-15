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

// The production wrappers identify fixed, unit-configured sources. Cache only their emitted
// descriptors; preparation and row evaluation call the shared generated arithmetic directly.
// In no_std, concurrent initialization may construct losing metadata values. Initializers are
// side-effect-free descriptor functions, never source capture, witnesses or fixed-table factories.
macro_rules! define_native_dispatch {
    ($wrapper:ty, $source:ident, $prepared:ident; $(
        $variant:ident => ($slot:ident, $descriptor:ident, $geometry:ident, $precompute:ident, $eval:ident, $terms:ident)
    ),+ $(,)?) => {
        $(
            static $slot: miden_utils_sync::LazyLock<
                miden_stark::air::native::AirDescriptor<miden_core::Felt>,
            > = miden_utils_sync::LazyLock::new(descriptors::$descriptor);
        )+

        /// Prepared expressions tagged by the exact immutable source variant.
        pub enum $prepared<E> {
            $(
                #[doc = concat!("Prepared expressions for `", stringify!($variant), "`.")]
                $variant([E; evaluators::$terms]),
            )+
        }

        impl miden_stark::air::native::AirKernel for $wrapper {
            type F = miden_core::Felt;
            type Prepared<B: p3_field::Algebra<Self::F>, E: p3_field::Algebra<B>> = $prepared<E>;

            fn descriptor(&self) -> &miden_stark::air::native::AirDescriptor<Self::F> {
                match self.0 {
                    $($source::$variant => &$slot,)+
                }
            }

            fn geometry(&self) -> miden_stark::air::native::KernelGeometry {
                match self.0 {
                    $($source::$variant => descriptors::$geometry,)+
                }
            }

            fn prepare<B: p3_field::Algebra<Self::F>, E: p3_field::Algebra<B>>(
                &self,
                inputs: miden_stark::air::native::UniformInputs<'_, B, E>,
            ) -> Self::Prepared<B, E> {
                match self.0 {
                    $($source::$variant => $prepared::$variant(evaluators::$precompute(inputs)),)+
                }
            }

            fn eval_row<S: miden_stark::air::native::LiftedAirBuilder<F = Self::F>>(
                &self,
                frame: &miden_stark::air::native::Frame<'_, S>,
                inputs: miden_stark::air::native::Inputs<'_, S>,
                prepared: &Self::Prepared<S::Expr, S::ExtExpr>,
                sink: &mut S,
            ) {
                match (self.0, prepared) {
                    $(($source::$variant, $prepared::$variant(terms)) => {
                        evaluators::$eval(frame, inputs, sink, terms);
                    },)+
                    _ => unreachable!("prepared expressions belong to the bound AIR variant"),
                }
            }
        }

        impl miden_stark::air::native::LiftedAir for $wrapper {
            type F = miden_core::Felt;

            fn spec(&self) -> miden_stark::air::native::AirSpec<'_, Self::F> {
                miden_stark::air::native::LiftedAir::spec(&self.0)
            }

            fn build_preprocessed_trace(&self) -> Option<
                miden_core::utils::RowMajorMatrix<Self::F>,
            > {
                miden_stark::air::native::LiftedAir::build_preprocessed_trace(&self.0)
            }

            fn eval<S: miden_stark::air::native::LiftedAirBuilder<F = Self::F>>(
                &self,
                frame: &miden_stark::air::native::Frame<'_, S>,
                inputs: miden_stark::air::native::Inputs<'_, S>,
                sink: &mut S,
            ) {
                miden_stark::air::native::LiftedAir::eval(&self.0, frame, inputs, sink);
            }
        }

        impl<EF> miden_stark::air::native::ProverAir<EF> for $wrapper
        where
            EF: p3_field::ExtensionField<miden_core::Felt>,
            $source: miden_stark::air::native::ProverAir<EF>,
        {
            type Error = <$source as miden_stark::air::native::ProverAir<EF>>::Error;

            fn build_aux_trace(
                &self,
                inputs: miden_stark::air::native::AuxTraceInputs<'_, miden_core::Felt, EF>,
            ) -> Result<miden_stark::air::native::AuxTrace<EF>, Self::Error> {
                miden_stark::air::native::ProverAir::build_aux_trace(&self.0, inputs)
            }
        }
    };
}

pub(crate) use define_native_dispatch;
