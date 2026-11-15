//! Source-only symbolic observation. No witness or fixed-matrix factory is invoked.

use alloc::{string::String, vec::Vec};

use p3_field::{ExtensionField, Field};

use super::{
    AirFrame, AirSpec, ConstraintMeta, LiftedAir, LiftedAirBuilder, Rows, Selectors, SpecError,
    UniformInputs,
    symbolic::{
        AuxInput, BaseInput, BaseLeaf, RowOffset, SymbolicExpression, SymbolicExpressionExt,
    },
};

/// One assertion in global emission order, including repeated and zero-gated assertions.
#[derive(Clone, Debug)]
pub enum Assertion<F: Field, EF: ExtensionField<F> = F> {
    Base(SymbolicExpression<F>),
    Extension(SymbolicExpressionExt<F, EF>),
}

/// Internal observation consumed by analysis and the final descriptor constructor.
pub(crate) struct RawCapture<F: Field, EF: ExtensionField<F> = F> {
    pub spec: AirSpec<'static, F>,
    pub assertions: Vec<Assertion<F, EF>>,
    pub labels: Vec<Option<String>>,
}

struct SymbolicSink<F: Field, EF: ExtensionField<F>> {
    assertions: Vec<Assertion<F, EF>>,
    labels: Vec<Option<String>>,
}

impl<F: Field, EF: ExtensionField<F>> SymbolicSink<F, EF> {
    fn label(&mut self, meta: ConstraintMeta<'_>) {
        self.labels.push(meta.path.map(|path| {
            let mut label = String::new();
            let mut next = Some(path);
            while let Some(path) = next {
                if !label.is_empty() {
                    label.push_str(" / ");
                }
                label.push_str(path.name);
                next = path.nested;
            }
            label
        }));
    }
}

impl<F: Field, EF: ExtensionField<F>> LiftedAirBuilder for SymbolicSink<F, EF> {
    type F = F;
    type Expr = SymbolicExpression<F>;
    type ExtExpr = SymbolicExpressionExt<F, EF>;

    fn emit_base(&mut self, value: Self::Expr, meta: ConstraintMeta<'_>) {
        self.assertions.push(Assertion::Base(value));
        self.label(meta);
    }

    fn emit_ext(&mut self, value: Self::ExtExpr, meta: ConstraintMeta<'_>) {
        self.assertions.push(Assertion::Extension(value));
        self.label(meta);
    }
}

pub(crate) fn capture_raw<A: LiftedAir>(source: &A) -> Result<RawCapture<A::F>, SpecError> {
    capture_raw_with::<A, A::F>(source)
}

pub(crate) fn capture_raw_with<A, EF>(source: &A) -> Result<RawCapture<A::F, EF>, SpecError>
where
    A: LiftedAir,
    EF: ExtensionField<A::F>,
{
    // One coherent configuration snapshot, checked before symbolic allocation.
    let spec = source.spec();
    spec.validate()?;
    let spec = spec.into_owned();
    let row_offsets = [RowOffset::Current, RowOffset::Next];
    let main: [Vec<_>; 2] = row_offsets.map(|offset| {
        (0..spec.main_width)
            .map(|index| SymbolicExpression::input(BaseInput::Main { offset, index }))
            .collect()
    });
    let preprocessed: [Vec<_>; 2] = row_offsets.map(|offset| {
        (0..spec.preprocessed_width())
            .map(|index| SymbolicExpression::input(BaseInput::Preprocessed { offset, index }))
            .collect()
    });
    let aux: [Vec<_>; 2] = row_offsets.map(|offset| {
        (0..spec.aux_width)
            .map(|index| SymbolicExpressionExt::input(AuxInput::Trace { offset, index }))
            .collect()
    });
    let periodic: Vec<_> = (0..spec.periodic_columns.len())
        .map(|index| SymbolicExpression::input(BaseInput::Periodic(index)))
        .collect();
    let public: Vec<_> = (0..spec.num_public_values)
        .map(|index| SymbolicExpression::input(BaseInput::Public(index)))
        .collect();
    let challenges: Vec<_> = (0..spec.num_challenges)
        .map(|index| SymbolicExpressionExt::input(AuxInput::Challenge(index)))
        .collect();
    let exports: Vec<_> = (0..spec.num_exports)
        .map(|index| SymbolicExpressionExt::input(AuxInput::Export(index)))
        .collect();
    let frame = AirFrame {
        main: Rows { current: &main[0], next: &main[1] },
        preprocessed: Rows {
            current: &preprocessed[0],
            next: &preprocessed[1],
        },
        aux: Rows { current: &aux[0], next: &aux[1] },
        periodic: &periodic,
        selectors: Selectors {
            first: SymbolicExpression::Leaf(BaseLeaf::IsFirstRow),
            last: SymbolicExpression::Leaf(BaseLeaf::IsLastRow),
            transition: SymbolicExpression::Leaf(BaseLeaf::IsTransition),
        },
    };
    let inputs = UniformInputs {
        public_values: &public,
        challenges: &challenges,
        exports: &exports,
    };
    let mut sink = SymbolicSink {
        assertions: Vec::new(),
        labels: Vec::new(),
    };
    source.eval(&frame, inputs, &mut sink);
    Ok(RawCapture {
        spec,
        assertions: sink.assertions,
        labels: sink.labels,
    })
}

#[cfg(test)]
mod tests {
    use alloc::{borrow::Cow, vec};
    use core::sync::atomic::{AtomicUsize, Ordering};

    use p3_field::{Dup, PrimeCharacteristicRing};
    use p3_goldilocks::Goldilocks as F;
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;
    use crate::air::native::{Frame, Inputs, PreprocessedSpec};

    struct Source {
        spec_calls: AtomicUsize,
    }

    impl LiftedAir for Source {
        type F = F;

        fn spec(&self) -> AirSpec<'_, F> {
            self.spec_calls.fetch_add(1, Ordering::Relaxed);
            AirSpec {
                main_width: 1,
                aux_width: 1,
                num_public_values: 1,
                num_challenges: 1,
                num_exports: 1,
                preprocessed: Some(PreprocessedSpec { width: 1, log_height: 2 }),
                periodic_columns: Cow::Owned(vec![vec![F::ONE; 4]]),
            }
        }

        fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
            panic!("capture must never construct setup matrices")
        }

        fn eval<B: LiftedAirBuilder<F = F>>(
            &self,
            frame: &Frame<'_, B>,
            inputs: Inputs<'_, B>,
            sink: &mut B,
        ) {
            sink.named("outer").named("inner").assert_zero(frame.main.current[0].dup());
            sink.assert_zero_ext(frame.aux.next[0].dup() + inputs.challenge(0) + inputs.export(0));
            sink.when(B::Expr::ZERO).assert_zero(
                frame.preprocessed.next[0].dup() + inputs.public(0) + frame.periodic[0].dup(),
            );
        }
    }

    #[test]
    fn capture_owns_labels_and_retains_the_global_stream_without_factories() {
        let source = Source { spec_calls: AtomicUsize::new(0) };
        let capture = capture_raw(&source).unwrap();
        assert_eq!(source.spec_calls.load(Ordering::Relaxed), 1);
        assert_eq!(capture.assertions.len(), 3);
        assert_eq!(capture.labels[0].as_deref(), Some("outer / inner"));
        assert_eq!(&capture.labels[1..], &[None, None]);
        assert!(matches!(capture.assertions[0], Assertion::Base(_)));
        assert!(matches!(capture.assertions[1], Assertion::Extension(_)));
        assert!(matches!(&capture.assertions[2],
            Assertion::Base(SymbolicExpression::Leaf(BaseLeaf::Constant(value))) if *value == F::ZERO));
    }
}
