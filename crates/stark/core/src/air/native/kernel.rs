//! Prepared execution of an analyzed relation with caller-owned uniform inputs.

use p3_field::{Algebra, ExtensionField, Field};
use p3_matrix::dense::RowMajorMatrix;
use thiserror::Error;

use super::{
    AirDescriptor, AirFrame, AirSpec, AuxTrace, AuxTraceInputs, DescriptorError, Frame, Inputs,
    LiftedAir, LiftedAirBuilder, ProverAir, UniformInputs,
};

/// A uniform input slice does not match the analyzed relation's declaration.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum BindError {
    #[error("public input count {actual} differs from declared count {expected}")]
    PublicValues { expected: usize, actual: usize },
    #[error("challenge count {actual} differs from declared count {expected}")]
    Challenges { expected: usize, actual: usize },
    #[error("export count {actual} differs from declared count {expected}")]
    Exports { expected: usize, actual: usize },
}

/// A trusted evaluator paired with a validated descriptor.
///
/// Implementations must evaluate exactly the relation identified by their descriptor, preserving
/// assertion class, global order and input addressing. Descriptor validation checks embedded
/// metadata, not the equivalence of arbitrary evaluator code. The configuration and descriptor
/// must remain immutable throughout a binding.
///
/// Prepared values own their expressions. They cannot borrow transient conversion buffers or
/// the inputs passed to `prepare`; the lifetime-independent associated type makes that ownership
/// explicit. No `Default`, `Clone`, or unconditional `Sync` bound is needed. A parallel caller
/// imposes shareability only on the concrete prepared type it shares across tasks.
///
/// This capability does not require concrete witness construction or a fixed-matrix factory.
/// Capture and verification can therefore use kernels without those capabilities.
pub trait AirKernel: Sync {
    type F: Field;
    type Prepared<B: Algebra<Self::F>, E: Algebra<B>>;

    fn descriptor(&self) -> &AirDescriptor<Self::F>;

    /// Prepare expressions from the exact inputs retained for the complete evaluation pass.
    ///
    /// Callers invoking this directly must validate dimensions themselves. Prefer [`Self::bind`],
    /// which checks every uniform slice before preparation occurs.
    fn prepare<B: Algebra<Self::F>, E: Algebra<B>>(
        &self,
        inputs: UniformInputs<'_, B, E>,
    ) -> Self::Prepared<B, E>;

    /// Evaluate one row with preparation derived from the same kernel and uniform inputs.
    ///
    /// This low-level entrypoint trusts the caller to supply matching row dimensions and the
    /// exact input/preparation pairing. Changing a challenge, public value or export while
    /// reusing preparation violates the evaluator contract. [`EvaluationSession::eval`] retains
    /// that pairing and checks trusted row shapes in debug builds.
    fn eval_row<S: LiftedAirBuilder<F = Self::F>>(
        &self,
        frame: &Frame<'_, S>,
        inputs: Inputs<'_, S>,
        prepared: &Self::Prepared<S::Expr, S::ExtExpr>,
        sink: &mut S,
    );

    /// Validate uniform dimensions, then prepare once for a borrowed evaluation pass.
    ///
    /// A returned session owns the prepared value and borrows the exact immutable input slices.
    /// Implementations overriding this method must preserve validation before preparation and
    /// the same input/kernel pairing.
    fn bind<'a, B: Algebra<Self::F>, E: Algebra<B>>(
        &'a self,
        inputs: UniformInputs<'a, B, E>,
    ) -> Result<EvaluationSession<'a, Self, B, E>, BindError>
    where
        Self: Sized,
    {
        let descriptor = self.descriptor();
        let spec = descriptor.spec();
        if inputs.public_values.len() != spec.num_public_values {
            return Err(BindError::PublicValues {
                expected: spec.num_public_values,
                actual: inputs.public_values.len(),
            });
        }
        if inputs.challenges.len() != spec.num_challenges {
            return Err(BindError::Challenges {
                expected: spec.num_challenges,
                actual: inputs.challenges.len(),
            });
        }
        if inputs.exports.len() != spec.num_exports {
            return Err(BindError::Exports {
                expected: spec.num_exports,
                actual: inputs.exports.len(),
            });
        }
        let prepared = self.prepare(inputs);
        Ok(EvaluationSession {
            kernel: self,
            descriptor,
            inputs,
            prepared,
        })
    }
}

/// A bound kernel, its exact borrowed inputs and an owned prepared value.
///
/// Its fields are private so row evaluation cannot replace inputs or substitute preparation from
/// another kernel. Input buffers must outlive the session; row buffers need only outlive each
/// individual `eval` call. The session never borrows its own prepared storage.
pub struct EvaluationSession<'a, K, B, E>
where
    K: AirKernel + ?Sized,
    B: Algebra<K::F>,
    E: Algebra<B>,
{
    kernel: &'a K,
    descriptor: &'a AirDescriptor<K::F>,
    inputs: UniformInputs<'a, B, E>,
    prepared: K::Prepared<B, E>,
}

impl<K, B, E> EvaluationSession<'_, K, B, E>
where
    K: AirKernel + ?Sized,
    B: Algebra<K::F>,
    E: Algebra<B>,
{
    pub fn descriptor(&self) -> &AirDescriptor<K::F> {
        self.descriptor
    }

    /// Emit this row using the input/preparation pairing established at binding.
    ///
    /// Trusted row shapes are debug-asserted. Untrusted trace/opening shape errors must be
    /// validated at their caller boundary before row evaluation.
    pub fn eval<S: LiftedAirBuilder<F = K::F, Expr = B, ExtExpr = E>>(
        &self,
        frame: &AirFrame<'_, B, E>,
        sink: &mut S,
    ) {
        let spec = self.descriptor.spec();
        debug_assert_eq!(frame.main.current.len(), spec.main_width, "current main width");
        debug_assert_eq!(frame.main.next.len(), spec.main_width, "next main width");
        debug_assert_eq!(
            frame.preprocessed.current.len(),
            spec.preprocessed_width(),
            "current preprocessed width",
        );
        debug_assert_eq!(
            frame.preprocessed.next.len(),
            spec.preprocessed_width(),
            "next preprocessed width",
        );
        debug_assert_eq!(frame.aux.current.len(), spec.aux_width, "current auxiliary width");
        debug_assert_eq!(frame.aux.next.len(), spec.aux_width, "next auxiliary width");
        debug_assert_eq!(frame.periodic.len(), spec.periodic_columns.len(), "periodic width");
        self.kernel.eval_row(frame, self.inputs, &self.prepared, sink);
    }
}

/// Own one authored source and its descriptor, evaluating the source body directly.
///
/// Construction captures and analyzes the source once. It constructs neither fixed matrices nor
/// witnesses. The source must honor [`LiftedAir`]'s immutable-configuration contract while this
/// kernel is reused. Direct preparation is unit; generated kernels may cache owned expressions.
pub struct DirectKernel<A: LiftedAir> {
    source: A,
    descriptor: AirDescriptor<A::F>,
}

impl<A: LiftedAir> DirectKernel<A> {
    pub fn new(source: A) -> Result<Self, DescriptorError> {
        let descriptor = super::capture(&source)?.descriptor;
        Ok(Self { source, descriptor })
    }
}

impl<A: LiftedAir> AirKernel for DirectKernel<A> {
    type F = A::F;
    type Prepared<B: Algebra<Self::F>, E: Algebra<B>> = ();

    fn descriptor(&self) -> &AirDescriptor<Self::F> {
        &self.descriptor
    }

    fn prepare<B: Algebra<Self::F>, E: Algebra<B>>(&self, _inputs: UniformInputs<'_, B, E>) {}

    fn eval_row<S: LiftedAirBuilder<F = Self::F>>(
        &self,
        frame: &Frame<'_, S>,
        inputs: Inputs<'_, S>,
        _prepared: &(),
        sink: &mut S,
    ) {
        self.source.eval(frame, inputs, sink);
    }
}

// ProverAir inherits the source capability. This source view forwards to the same authored body;
// it is not an additional equation implementation or a source preparation interface.
impl<A: LiftedAir> LiftedAir for DirectKernel<A> {
    type F = A::F;

    fn spec(&self) -> AirSpec<'_, Self::F> {
        self.source.spec()
    }

    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Self::F>> {
        self.source.build_preprocessed_trace()
    }

    fn eval<S: LiftedAirBuilder<F = Self::F>>(
        &self,
        frame: &Frame<'_, S>,
        inputs: Inputs<'_, S>,
        sink: &mut S,
    ) {
        self.source.eval(frame, inputs, sink);
    }
}

impl<A, EF> ProverAir<EF> for DirectKernel<A>
where
    A: ProverAir<EF>,
    EF: ExtensionField<A::F>,
{
    type Error = A::Error;

    fn build_aux_trace(
        &self,
        inputs: AuxTraceInputs<'_, A::F, EF>,
    ) -> Result<AuxTrace<EF>, Self::Error> {
        self.source.build_aux_trace(inputs)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{borrow::Cow, vec, vec::Vec};
    use core::{
        cell::Cell,
        convert::Infallible,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use p3_field::{Dup, PrimeCharacteristicRing};
    use p3_matrix::Matrix;

    use super::*;
    use crate::{
        air::native::{ConstraintMeta, PreprocessedSpec, Rows, Selectors},
        testing::configs::{Felt, QuadFelt},
    };

    struct Fixture {
        spec_reads: AtomicUsize,
        fixed_builds: AtomicUsize,
    }

    /// One equation body is shared by source evaluation and the prepared fixture kernel.
    fn relation<S: LiftedAirBuilder<F = Felt>>(
        frame: &Frame<'_, S>,
        inputs: Inputs<'_, S>,
        challenge_square: S::ExtExpr,
        sink: &mut S,
    ) {
        sink.assert_eq(frame.main.current[0].dup(), inputs.public(0));
        sink.assert_zero_ext(frame.aux.current[0].dup() + challenge_square - inputs.export(0));
    }

    impl LiftedAir for Fixture {
        type F = Felt;

        fn spec(&self) -> AirSpec<'_, Felt> {
            self.spec_reads.fetch_add(1, Ordering::Relaxed);
            AirSpec {
                main_width: 1,
                aux_width: 1,
                num_public_values: 1,
                num_challenges: 1,
                num_exports: 1,
                preprocessed: Some(PreprocessedSpec { width: 1, log_height: 1 }),
                periodic_columns: Cow::Borrowed(&[]),
            }
        }

        fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
            self.fixed_builds.fetch_add(1, Ordering::Relaxed);
            Some(RowMajorMatrix::new(vec![Felt::ONE; 2], 1))
        }

        fn eval<S: LiftedAirBuilder<F = Felt>>(
            &self,
            frame: &Frame<'_, S>,
            inputs: Inputs<'_, S>,
            sink: &mut S,
        ) {
            relation(frame, inputs, inputs.challenge(0) * inputs.challenge(0), sink);
        }
    }

    impl ProverAir<QuadFelt> for Fixture {
        type Error = Infallible;

        fn build_aux_trace(
            &self,
            inputs: AuxTraceInputs<'_, Felt, QuadFelt>,
        ) -> Result<AuxTrace<QuadFelt>, Infallible> {
            Ok(AuxTrace {
                columns: RowMajorMatrix::new(vec![QuadFelt::ZERO; inputs.main.height()], 1),
                exports: vec![inputs.challenges[0] * inputs.challenges[0]],
            })
        }
    }

    // Deliberately neither Default nor Clone/Copy. Cell also makes this prepared type !Sync,
    // demonstrating that the kernel contract does not impose parallelism on all backends.
    struct CountedPrepared<E> {
        square: E,
        uses: Cell<usize>,
    }

    struct CountingKernel {
        direct: DirectKernel<Fixture>,
        prepares: AtomicUsize,
        evaluations: AtomicUsize,
    }

    impl CountingKernel {
        fn new() -> Self {
            Self {
                direct: DirectKernel::new(Fixture {
                    spec_reads: AtomicUsize::new(0),
                    fixed_builds: AtomicUsize::new(0),
                })
                .unwrap(),
                prepares: AtomicUsize::new(0),
                evaluations: AtomicUsize::new(0),
            }
        }
    }

    impl AirKernel for CountingKernel {
        type F = Felt;
        type Prepared<B: Algebra<Felt>, E: Algebra<B>> = CountedPrepared<E>;

        fn descriptor(&self) -> &AirDescriptor<Felt> {
            self.direct.descriptor()
        }

        fn prepare<B: Algebra<Felt>, E: Algebra<B>>(
            &self,
            inputs: UniformInputs<'_, B, E>,
        ) -> CountedPrepared<E> {
            self.prepares.fetch_add(1, Ordering::Relaxed);
            CountedPrepared {
                square: inputs.challenge(0) * inputs.challenge(0),
                uses: Cell::new(0),
            }
        }

        fn eval_row<S: LiftedAirBuilder<F = Felt>>(
            &self,
            frame: &Frame<'_, S>,
            inputs: Inputs<'_, S>,
            prepared: &CountedPrepared<S::ExtExpr>,
            sink: &mut S,
        ) {
            self.evaluations.fetch_add(1, Ordering::Relaxed);
            prepared.uses.set(prepared.uses.get() + 1);
            relation(frame, inputs, prepared.square.dup(), sink);
        }
    }

    #[derive(Default)]
    struct Collector {
        base: Vec<Felt>,
        ext: Vec<QuadFelt>,
    }

    impl LiftedAirBuilder for Collector {
        type F = Felt;
        type Expr = Felt;
        type ExtExpr = QuadFelt;

        fn emit_base(&mut self, value: Felt, _meta: ConstraintMeta<'_>) {
            self.base.push(value);
        }

        fn emit_ext(&mut self, value: QuadFelt, _meta: ConstraintMeta<'_>) {
            self.ext.push(value);
        }
    }

    fn frame<'a>(
        main: &'a [Felt],
        fixed: &'a [Felt],
        aux: &'a [QuadFelt],
    ) -> AirFrame<'a, Felt, QuadFelt> {
        AirFrame {
            main: Rows { current: main, next: main },
            preprocessed: Rows { current: fixed, next: fixed },
            aux: Rows { current: aux, next: aux },
            periodic: &[],
            selectors: Selectors {
                first: Felt::ONE,
                last: Felt::ZERO,
                transition: Felt::ONE,
            },
        }
    }

    #[test]
    fn binding_rejects_every_uniform_dimension_before_preparation() {
        let kernel = CountingKernel::new();
        let public = [Felt::ONE; 2];
        let extension = [QuadFelt::ONE; 2];
        let cases = [
            (0, 1, 1, BindError::PublicValues { expected: 1, actual: 0 }),
            (2, 1, 1, BindError::PublicValues { expected: 1, actual: 2 }),
            (1, 0, 1, BindError::Challenges { expected: 1, actual: 0 }),
            (1, 2, 1, BindError::Challenges { expected: 1, actual: 2 }),
            (1, 1, 0, BindError::Exports { expected: 1, actual: 0 }),
            (1, 1, 2, BindError::Exports { expected: 1, actual: 2 }),
        ];
        for (public_len, challenge_len, export_len, expected) in cases {
            let result = kernel.bind(UniformInputs {
                public_values: &public[..public_len],
                challenges: &extension[..challenge_len],
                exports: &extension[..export_len],
            });
            match result {
                Err(actual) => assert_eq!(actual, expected),
                Ok(_) => panic!("invalid uniform dimensions were accepted"),
            }
        }
        assert_eq!(kernel.prepares.load(Ordering::Relaxed), 0);
        assert_eq!(kernel.direct.source.spec_reads.load(Ordering::Relaxed), 1);
        assert_eq!(kernel.direct.source.fixed_builds.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn sessions_own_non_copy_preparation_and_keep_their_exact_inputs() {
        let kernel = CountingKernel::new();
        let main = [Felt::from_u64(7)];
        let fixed = [Felt::ONE];
        let aux = [QuadFelt::from(Felt::from_u64(4))];
        let challenges = [QuadFelt::from(Felt::from_u64(3))];
        let exports = [QuadFelt::from(Felt::from_u64(13))];
        let inputs = UniformInputs {
            public_values: &main,
            challenges: &challenges,
            exports: &exports,
        };
        let first = kernel.bind(inputs).unwrap();
        let mut sink = Collector::default();
        first.eval(&frame(&main, &fixed, &aux), &mut sink);
        first.eval(&frame(&main, &fixed, &aux), &mut sink);
        assert_eq!(kernel.prepares.load(Ordering::Relaxed), 1);
        assert_eq!(first.prepared.uses.get(), 2);

        let other_challenges = [QuadFelt::from(Felt::from_u64(5))];
        let other_exports = [QuadFelt::from(Felt::from_u64(29))];
        let second = kernel
            .bind(UniformInputs {
                public_values: &main,
                challenges: &other_challenges,
                exports: &other_exports,
            })
            .unwrap();
        second.eval(&frame(&main, &fixed, &aux), &mut sink);
        first.eval(&frame(&main, &fixed, &aux), &mut sink);
        assert_eq!(kernel.prepares.load(Ordering::Relaxed), 2);
        assert_eq!(kernel.evaluations.load(Ordering::Relaxed), 4);
        assert_eq!(first.prepared.uses.get(), 3);
        assert_eq!(second.prepared.uses.get(), 1);
        assert_eq!(sink.base, vec![Felt::ZERO; 4]);
        assert_eq!(sink.ext, vec![QuadFelt::ZERO; 4]);
        assert_eq!(kernel.direct.source.spec_reads.load(Ordering::Relaxed), 1);
        assert_eq!(kernel.direct.source.fixed_builds.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn direct_kernel_forwards_optional_witness_and_explicit_setup_capabilities() {
        let kernel = CountingKernel::new().direct;
        let fixed = kernel.build_preprocessed_trace().unwrap();
        assert_eq!(kernel.source.fixed_builds.load(Ordering::Relaxed), 1);
        let main = RowMajorMatrix::new(vec![Felt::from_u64(7); 2], 1);
        let public = [Felt::from_u64(7)];
        let challenges = [QuadFelt::from(Felt::from_u64(3))];
        let aux = kernel
            .build_aux_trace(AuxTraceInputs {
                main: &main,
                preprocessed: Some(&fixed),
                public_values: &public,
                statement: &[],
                challenges: &challenges,
            })
            .unwrap();
        assert_eq!(aux.columns.width(), 1);
        assert_eq!(aux.columns.height(), 2);
        assert_eq!(aux.exports, vec![QuadFelt::from(Felt::from_u64(9))]);
        let session = kernel
            .bind(UniformInputs {
                public_values: &public,
                challenges: &challenges,
                exports: &aux.exports,
            })
            .unwrap();
        let mut sink = Collector::default();
        session.eval(
            &frame(&main.values[..1], &fixed.values[..1], &aux.columns.values[..1]),
            &mut sink,
        );
        assert_eq!(sink.base, vec![Felt::ZERO]);
        assert_eq!(sink.ext, vec![QuadFelt::ZERO]);
        assert_eq!(kernel.source.fixed_builds.load(Ordering::Relaxed), 1);
    }
}
