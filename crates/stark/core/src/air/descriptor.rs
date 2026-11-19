//! Checked relation metadata and versioned structural identity.

use alloc::{string::String, vec::Vec};

use p3_field::{ExtensionField, Field};
use thiserror::Error;

use super::{
    AirSpec, LiftedAir, SpecError,
    analysis::{AirAnalysis, AnalysisError, DegreeOp, analyze_with_identity},
    capture::{
        Assertion, RawCapture, SymbolicSink, capture_raw, capture_raw_from_spec, capture_raw_with,
    },
};

/// Validated shape, ordered analysis and structural identity for one immutable configuration.
///
/// The fingerprint identifies authored expression structure; it does not authenticate arbitrary
/// evaluator code or fixed-matrix contents. Setup separately commits the actual matrices. Neither
/// descriptor fingerprints nor diagnostics are added to the protocol transcript.
#[derive(Clone, Debug)]
pub struct AirDescriptor<F: Field> {
    spec: AirSpec<'static, F>,
    analysis: AirAnalysis,
    fingerprint: [u8; 32],
    labels: Option<Vec<Option<String>>>,
}

/// Embedded compiler output, checked before it becomes a descriptor.
///
/// This is a trusted code-pairing boundary. Validation establishes internal shape/index/recipe
/// consistency, not equality between the paired generated evaluator and this fingerprint.
pub struct DescriptorParts<F: Field> {
    pub spec: AirSpec<'static, F>,
    pub analysis: AirAnalysis,
    pub fingerprint: [u8; 32],
    pub labels: Option<Vec<Option<String>>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum DescriptorError {
    #[error(transparent)]
    Spec(#[from] SpecError),
    #[error(transparent)]
    Analysis(#[from] AnalysisError),
    #[error("descriptor has {actual} diagnostics for {expected} assertions")]
    Diagnostics { expected: usize, actual: usize },
    #[error("degree recipe uses undeclared periodic length {0}")]
    UndeclaredPeriod(usize),
}

impl<F: Field> AirDescriptor<F> {
    pub fn from_trusted_parts(parts: DescriptorParts<F>) -> Result<Self, DescriptorError> {
        parts.spec.validate()?;
        for op in parts.analysis.degree_profile().ops() {
            if let DegreeOp::Periodic(period) = op
                && !parts.spec.periodic_columns.iter().any(|column| column.len() == *period)
            {
                return Err(DescriptorError::UndeclaredPeriod(*period));
            }
        }
        if let Some(labels) = &parts.labels {
            let expected = parts.analysis.layout().total_constraints();
            if labels.len() != expected {
                return Err(DescriptorError::Diagnostics { expected, actual: labels.len() });
            }
        }
        Ok(Self {
            spec: parts.spec,
            analysis: parts.analysis,
            fingerprint: parts.fingerprint,
            labels: parts.labels,
        })
    }

    pub fn spec(&self) -> &AirSpec<'static, F> {
        &self.spec
    }

    pub fn analysis(&self) -> &AirAnalysis {
        &self.analysis
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Look up optional failure context by global assertion ordinal.
    ///
    /// Successful row evaluation need not inspect or allocate any diagnostics.
    pub fn label(&self, global_ordinal: usize) -> Option<&str> {
        self.labels.as_ref()?.get(global_ordinal)?.as_deref()
    }
}

/// An authored observation, retaining expressions for compiler lowering.
pub struct Capture<F: Field, EF: ExtensionField<F> = F> {
    pub descriptor: AirDescriptor<F>,
    pub assertions: Vec<Assertion<F, EF>>,
}

/// Capture a source without invoking its witness algorithm or fixed-matrix factory.
///
/// # Field encoding contract
///
/// The internal `miden-native-air-structure-v1` identity frames field order and byte width, then
/// uses `Field::into_bytes` for constants and periodic data. A custom field implementation must
/// supply an injective, canonical, deterministic, target-stable encoding of exactly `NUM_BYTES`
/// bytes, including an agreed basis for nonprime fields. `RawDataSerializable` alone does not
/// prove these properties. Both supported production Felt and retained Goldilocks implementations
/// encode eight canonical little-endian bytes. Field implementations and evaluator code are
/// trusted; this contract imposes no extra arithmetic restriction on generic kernels or sources.
pub fn capture<A: LiftedAir>(source: &A) -> Result<Capture<A::F>, DescriptorError> {
    finish_capture(capture_raw(source)?)
}

/// Select the symbolic constant extension field while retaining the same source input namespaces.
/// The field encoding contract documented on [`capture()`] also applies here.
pub fn capture_with<A, EF>(source: &A) -> Result<Capture<A::F, EF>, DescriptorError>
where
    A: LiftedAir,
    EF: ExtensionField<A::F>,
{
    finish_capture(capture_raw_with::<A, EF>(source)?)
}

/// Capture a selected authored relation over a checked input specification.
///
/// This shares the ordinary source capture's allocation, ordering and analysis. A lookup-only
/// callback describes a subset for compiler/security inspection; it is not the complete source
/// relation. Kernel callbacks are comparison subjects and must never become artifact oracles.
/// The field encoding contract documented on [`capture()`] also applies here.
pub fn capture_from_spec<F, EF>(
    spec: AirSpec<'_, F>,
    eval: impl FnOnce(
        &super::Frame<'_, SymbolicSink<F, EF>>,
        super::Inputs<'_, SymbolicSink<F, EF>>,
        &mut SymbolicSink<F, EF>,
    ),
) -> Result<Capture<F, EF>, DescriptorError>
where
    F: Field,
    EF: ExtensionField<F>,
{
    finish_capture(capture_raw_from_spec(spec, eval)?)
}

fn finish_capture<F: Field, EF: ExtensionField<F>>(
    raw: RawCapture<F, EF>,
) -> Result<Capture<F, EF>, DescriptorError> {
    let (analysis, fingerprint) = analyze_with_identity(&raw)?;
    let labels = raw.labels.iter().any(Option::is_some).then_some(raw.labels);
    let descriptor = AirDescriptor::from_trusted_parts(DescriptorParts {
        spec: raw.spec,
        analysis,
        fingerprint,
        labels,
    })?;
    Ok(Capture { descriptor, assertions: raw.assertions })
}

#[cfg(test)]
mod tests {
    use alloc::{borrow::Cow, sync::Arc, vec};

    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::{
        air::{
            AirAnalysis, DegreeProfile,
            symbolic::{
                BaseInput, BaseLeaf, RowOffset, SymbolicExpr, SymbolicExpression,
                SymbolicExpressionExt,
            },
        },
        testing::configs::Felt,
    };

    fn raw(expression: SymbolicExpression<Felt>) -> RawCapture<Felt> {
        RawCapture {
            spec: AirSpec {
                main_width: 1,
                aux_width: 1,
                num_public_values: 1,
                num_challenges: 1,
                num_exports: 1,
                preprocessed: None,
                periodic_columns: Cow::Owned(vec![vec![Felt::ZERO, Felt::ONE]]),
            },
            assertions: vec![Assertion::Base(expression)],
            labels: vec![None],
        }
    }

    fn input(offset: RowOffset) -> SymbolicExpression<Felt> {
        SymbolicExpression::input(BaseInput::Main { offset, index: 0 })
    }

    fn square(cache: usize, shared: bool) -> SymbolicExpression<Felt> {
        let x = Arc::new(input(RowOffset::Current));
        let y = if shared {
            Arc::clone(&x)
        } else {
            Arc::new(input(RowOffset::Current))
        };
        SymbolicExpr::Mul { x, y, degree_multiple: cache }
    }

    #[test]
    fn identity_and_safe_degree_ignore_sharing_labels_and_cached_degrees() {
        let first = finish_capture(raw(square(2, true))).unwrap().descriptor;
        let mut changed = raw(square(usize::MAX, false));
        changed.labels[0] = Some("different diagnostic".into());
        let second = finish_capture(changed).unwrap().descriptor;
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(first.analysis.degree_profile(), second.analysis.degree_profile());
        assert_ne!(first.analysis.raw_degrees(), second.analysis.raw_degrees());
        assert_eq!(first.analysis.degree_profile().at_height(8).unwrap().numerator_degree, 14);
        assert_eq!(first.label(0), None);
        assert_eq!(second.label(0), Some("different diagnostic"));
    }

    #[test]
    fn identity_binds_schema_periodic_values_addresses_classes_and_global_order() {
        let reference = finish_capture(raw(input(RowOffset::Current))).unwrap().descriptor;
        let mut cases = vec![];
        let mut changed = raw(input(RowOffset::Current));
        changed.spec.num_public_values += 1;
        cases.push(changed);
        let mut changed = raw(input(RowOffset::Current));
        changed.spec.periodic_columns.to_mut()[0].swap(0, 1);
        cases.push(changed);
        cases.push(raw(input(RowOffset::Next)));
        cases.push(raw(SymbolicExpression::input(BaseInput::Public(0))));
        let mut changed = raw(input(RowOffset::Current));
        changed.assertions[0] =
            Assertion::Extension(SymbolicExpressionExt::from(input(RowOffset::Current)));
        cases.push(changed);
        for changed in cases {
            assert_ne!(
                reference.fingerprint(),
                finish_capture(changed).unwrap().descriptor.fingerprint()
            );
        }

        let mut first = raw(input(RowOffset::Current));
        first.assertions.push(Assertion::Base(SymbolicExpression::ZERO));
        first.labels.push(None);
        let mut second = raw(SymbolicExpression::ZERO);
        second.assertions.push(Assertion::Base(input(RowOffset::Current)));
        second.labels.push(None);
        assert_ne!(
            finish_capture(first).unwrap().descriptor.fingerprint(),
            finish_capture(second).unwrap().descriptor.fingerprint()
        );
    }

    #[test]
    fn embedded_descriptor_rejects_diagnostics_and_undeclared_degree_periods() {
        let descriptor = finish_capture(raw(input(RowOffset::Current))).unwrap().descriptor;
        let parts = DescriptorParts {
            spec: descriptor.spec.clone(),
            analysis: descriptor.analysis.clone(),
            fingerprint: descriptor.fingerprint,
            labels: Some(vec![]),
        };
        assert!(matches!(
            AirDescriptor::from_trusted_parts(parts),
            Err(DescriptorError::Diagnostics { expected: 1, actual: 0 })
        ));

        let mut ops = descriptor.analysis.degree_profile().ops().to_vec();
        ops.push(DegreeOp::Periodic(4));
        let profile =
            DegreeProfile::new(ops, descriptor.analysis.degree_profile().roots().to_vec()).unwrap();
        let analysis = AirAnalysis::new(
            descriptor.analysis.layout().clone(),
            descriptor.analysis.raw_degrees(),
            profile,
        )
        .unwrap();
        let parts = DescriptorParts {
            spec: descriptor.spec,
            analysis,
            fingerprint: descriptor.fingerprint,
            labels: None,
        };
        assert!(matches!(
            AirDescriptor::from_trusted_parts(parts),
            Err(DescriptorError::UndeclaredPeriod(4))
        ));
    }

    #[test]
    fn repeated_zero_emissions_are_still_part_of_the_relation_identity() {
        let one =
            finish_capture(raw(SymbolicExpression::Leaf(BaseLeaf::Constant(Felt::ZERO)))).unwrap();
        let mut repeated = raw(SymbolicExpression::ZERO);
        repeated.assertions.push(Assertion::Base(SymbolicExpression::ZERO));
        repeated.labels.push(None);
        let repeated = finish_capture(repeated).unwrap();
        assert_ne!(one.descriptor.fingerprint(), repeated.descriptor.fingerprint());
        assert_eq!(repeated.descriptor.analysis.counts().base, 2);
    }
}
