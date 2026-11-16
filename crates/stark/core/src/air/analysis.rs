//! Checked assertion layout and actual-height degree capacity.
//!
//! Raw symbolic degree multiples remain useful diagnostics, but treating a transition selector as
//! degree zero is not a sound actual-height bound for arbitrary products. This module records a
//! checked recipe from the arithmetic itself: traces and boundary selectors have degree at most
//! `n - 1`, transition selectors degree one, periodic columns of length `p` degree `n - n/p`, and
//! uniform inputs degree zero. Neither this analysis nor its recipe depends on cached AST degrees.

use alloc::{collections::BTreeMap, vec::Vec};

use p3_field::{ExtensionField, Field};
use thiserror::Error;

use super::{
    AirSpec, SpecError,
    capture::{Assertion, RawCapture},
    identity::{self, ArithmeticOp},
    symbolic::{
        AuxInput, BaseInput, BaseLeaf, ExtLeaf, SymbolicExpr, SymbolicExpression,
        SymbolicExpressionExt,
    },
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConstraintCounts {
    pub base: usize,
    pub ext: usize,
}

/// Trace-size-independent diagnostic maxima, kept separate from checked capacity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConstraintDegrees {
    pub base: usize,
    pub ext: usize,
}

impl ConstraintDegrees {
    pub fn max(&self) -> usize {
        self.base.max(self.ext)
    }
}

/// Failures in embedded metadata, source addresses or actual-height capacity.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum AnalysisError {
    #[error(transparent)]
    Spec(#[from] SpecError),
    #[error(
        "constraint indices must partition global emission order and increase within each class"
    )]
    InvalidLayout,
    #[error("degree operation {operation} refers to non-prior operand {operand}")]
    InvalidOperand { operation: usize, operand: usize },
    #[error("degree root {root} is outside operation count {operations}")]
    InvalidRoot { root: usize, operations: usize },
    #[error("degree period {period} must be a positive power of two")]
    InvalidPeriod { period: usize },
    #[error("trace height {height} must be a power of two at least two")]
    InvalidHeight { height: usize },
    #[error("period {period} does not divide trace height {height}")]
    IncompatiblePeriod { period: usize, height: usize },
    #[error("checked degree analysis overflow for {0}")]
    Overflow(&'static str),
    #[error("allocated quotient capacity {allocated} must be a positive power of two")]
    InvalidCapacity { allocated: usize },
    #[error("allocated quotient capacity {allocated} is below required capacity {required}")]
    InsufficientCapacity { allocated: usize, required: usize },
    #[error("degree root count {actual} differs from assertion count {expected}")]
    RootCount { expected: usize, actual: usize },
    #[error("{namespace} input index {index} is outside declared length {length}")]
    InputOutOfBounds {
        namespace: &'static str,
        index: usize,
        length: usize,
    },
}

/// Maps separated assertion streams to their exact global positions.
///
/// Construction establishes that each global ordinal occurs exactly once and indices increase
/// within each class. Fields stay private so folding cannot be redirected after validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstraintLayout {
    base_indices: Vec<usize>,
    ext_indices: Vec<usize>,
}

impl ConstraintLayout {
    pub fn new(base_indices: Vec<usize>, ext_indices: Vec<usize>) -> Result<Self, AnalysisError> {
        let total = base_indices
            .len()
            .checked_add(ext_indices.len())
            .ok_or(AnalysisError::Overflow("assertion count"))?;
        let mut base = base_indices.iter().copied().peekable();
        let mut ext = ext_indices.iter().copied().peekable();
        for ordinal in 0..total {
            if base.peek() == Some(&ordinal) {
                base.next();
            } else if ext.peek() == Some(&ordinal) {
                ext.next();
            } else {
                return Err(AnalysisError::InvalidLayout);
            }
        }
        // Duplicates across classes or non-increasing class order necessarily leave an entry.
        if base.next().is_some() || ext.next().is_some() {
            return Err(AnalysisError::InvalidLayout);
        }
        Ok(Self { base_indices, ext_indices })
    }

    pub fn base_indices(&self) -> &[usize] {
        &self.base_indices
    }

    pub fn ext_indices(&self) -> &[usize] {
        &self.ext_indices
    }

    pub fn total_constraints(&self) -> usize {
        // The constructor checked this sum and the vectors are immutable through this API.
        self.base_indices.len() + self.ext_indices.len()
    }

    /// Split descending alpha powers by class, transposing base weights into basis coordinates.
    ///
    /// Assertion at global position `i` gets `alpha^(K-1-i)`, matching the verifier's streaming
    /// recurrence `acc = acc * alpha + assertion`. This is the base protocol's folding order.
    pub fn decompose_alpha<F: Field, EF: ExtensionField<F>>(
        &self,
        alpha: EF,
    ) -> (Vec<Vec<F>>, Vec<EF>) {
        let mut powers: Vec<_> = alpha.powers().take(self.total_constraints()).collect();
        powers.reverse();
        let base = (0..EF::DIMENSION)
            .map(|coefficient| {
                self.base_indices
                    .iter()
                    .map(|&index| powers[index].as_basis_coefficients_slice()[coefficient])
                    .collect()
            })
            .collect();
        let ext = self.ext_indices.iter().map(|&index| powers[index]).collect();
        (base, ext)
    }
}

/// An internable degree recipe; arithmetic operands refer only to prior operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DegreeOp {
    Constant,
    Trace,
    Transition,
    Periodic(usize),
    Max(usize, usize),
    Sum(usize, usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DegreeBound {
    pub numerator_degree: usize,
    pub quotient_chunks: usize,
}

/// Validated, AST-independent arithmetic recipe with one root per global assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DegreeProfile {
    ops: Vec<DegreeOp>,
    roots: Vec<usize>,
}

impl DegreeProfile {
    pub fn new(ops: Vec<DegreeOp>, roots: Vec<usize>) -> Result<Self, AnalysisError> {
        for (index, op) in ops.iter().enumerate() {
            match *op {
                DegreeOp::Periodic(period) if !period.is_power_of_two() => {
                    return Err(AnalysisError::InvalidPeriod { period });
                },
                DegreeOp::Max(left, right) | DegreeOp::Sum(left, right) => {
                    for operand in [left, right] {
                        if operand >= index {
                            return Err(AnalysisError::InvalidOperand {
                                operation: index,
                                operand,
                            });
                        }
                    }
                },
                _ => (),
            }
        }
        for &root in &roots {
            if root >= ops.len() {
                return Err(AnalysisError::InvalidRoot { root, operations: ops.len() });
            }
        }
        Ok(Self { ops, roots })
    }

    pub fn ops(&self) -> &[DegreeOp] {
        &self.ops
    }

    pub fn roots(&self) -> &[usize] {
        &self.roots
    }

    /// Derive a sound quotient capacity for this actual trace height.
    ///
    /// If the numerator degree is `d`, division by the degree-`n` vanishing polynomial requires
    /// chunk count `D` with `D*n > d-n`. Equivalently, round
    /// `max(1, ceil(max(0,d-(n-1))/n))` up to a power of two. The ceiling below avoids the usual
    /// potentially overflowing `value + divisor - 1` expression.
    pub fn at_height(&self, height: usize) -> Result<DegreeBound, AnalysisError> {
        if height < 2 || !height.is_power_of_two() {
            return Err(AnalysisError::InvalidHeight { height });
        }
        let mut degrees: Vec<usize> = Vec::with_capacity(self.ops.len());
        for op in &self.ops {
            let degree = match *op {
                DegreeOp::Constant => 0,
                DegreeOp::Trace => height - 1,
                DegreeOp::Transition => 1,
                DegreeOp::Periodic(period) => {
                    if period > height || !height.is_multiple_of(period) {
                        return Err(AnalysisError::IncompatiblePeriod { period, height });
                    }
                    height - height / period
                },
                DegreeOp::Max(left, right) => degrees[left].max(degrees[right]),
                DegreeOp::Sum(left, right) => degrees[left]
                    .checked_add(degrees[right])
                    .ok_or(AnalysisError::Overflow("numerator degree"))?,
            };
            degrees.push(degree);
        }
        let numerator_degree = self.roots.iter().map(|&root| degrees[root]).max().unwrap_or(0);
        let excess = numerator_degree.saturating_sub(height - 1);
        let chunks = (excess / height)
            .checked_add(usize::from(excess % height != 0))
            .ok_or(AnalysisError::Overflow("quotient ceiling"))?
            .max(1);
        let quotient_chunks = chunks
            .checked_next_power_of_two()
            .ok_or(AnalysisError::Overflow("quotient chunk count"))?;
        Ok(DegreeBound { numerator_degree, quotient_chunks })
    }

    /// Check a caller's capacity without shrinking an already larger safe allocation.
    ///
    /// Returns the minimum required bound; the supplied allocation remains the caller's choice.
    pub fn validate_capacity(
        &self,
        height: usize,
        allocated: usize,
    ) -> Result<DegreeBound, AnalysisError> {
        if !allocated.is_power_of_two() {
            return Err(AnalysisError::InvalidCapacity { allocated });
        }
        let bound = self.at_height(height)?;
        if allocated < bound.quotient_chunks {
            return Err(AnalysisError::InsufficientCapacity {
                allocated,
                required: bound.quotient_chunks,
            });
        }
        Ok(bound)
    }
}

/// Owned checked metadata, independent of source AST storage or a concrete evaluator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AirAnalysis {
    layout: ConstraintLayout,
    raw_degrees: ConstraintDegrees,
    degree_profile: DegreeProfile,
}

impl AirAnalysis {
    pub fn new(
        layout: ConstraintLayout,
        raw_degrees: ConstraintDegrees,
        degree_profile: DegreeProfile,
    ) -> Result<Self, AnalysisError> {
        let expected = layout.total_constraints();
        let actual = degree_profile.roots.len();
        if actual != expected {
            return Err(AnalysisError::RootCount { expected, actual });
        }
        Ok(Self { layout, raw_degrees, degree_profile })
    }

    pub fn layout(&self) -> &ConstraintLayout {
        &self.layout
    }

    pub fn raw_degrees(&self) -> ConstraintDegrees {
        self.raw_degrees
    }

    pub fn degree_profile(&self) -> &DegreeProfile {
        &self.degree_profile
    }

    pub fn counts(&self) -> ConstraintCounts {
        ConstraintCounts {
            base: self.layout.base_indices.len(),
            ext: self.layout.ext_indices.len(),
        }
    }
}

#[cfg(test)]
pub(crate) fn analyze<F: Field, EF: ExtensionField<F>>(
    capture: &RawCapture<F, EF>,
) -> Result<AirAnalysis, AnalysisError> {
    analyze_with_identity(capture).map(|(analysis, _)| analysis)
}

/// Analyze and structurally fingerprint one capture in the same memoized arithmetic walk.
///
/// Diagnostics and AST degree caches do not contribute to the structural identity. The pure
/// encoding helpers define its local version; the identity is separate from protocol transcripts.
pub(crate) fn analyze_with_identity<F: Field, EF: ExtensionField<F>>(
    capture: &RawCapture<F, EF>,
) -> Result<(AirAnalysis, [u8; 32]), AnalysisError> {
    capture.spec.validate()?;
    let mut walker = DegreeWalker {
        spec: &capture.spec,
        ops: Vec::new(),
        interner: BTreeMap::new(),
        base_memo: BTreeMap::new(),
        ext_memo: BTreeMap::new(),
    };
    let mut base_indices = Vec::new();
    let mut ext_indices = Vec::new();
    let mut roots = Vec::with_capacity(capture.assertions.len());
    let mut fingerprints = Vec::with_capacity(capture.assertions.len());
    let mut raw_degrees = ConstraintDegrees::default();
    for (ordinal, assertion) in capture.assertions.iter().enumerate() {
        let root = match assertion {
            Assertion::Base(expression) => {
                base_indices.push(ordinal);
                raw_degrees.base = raw_degrees.base.max(expression.degree_multiple());
                walker.base(expression)?
            },
            Assertion::Extension(expression) => {
                ext_indices.push(ordinal);
                raw_degrees.ext = raw_degrees.ext.max(expression.degree_multiple());
                walker.ext(expression)?
            },
        };
        roots.push(root.degree);
        fingerprints.push((matches!(assertion, Assertion::Extension(_)), root.fingerprint));
    }
    let analysis = AirAnalysis::new(
        ConstraintLayout::new(base_indices, ext_indices)?,
        raw_degrees,
        DegreeProfile::new(walker.ops, roots)?,
    )?;
    Ok((analysis, identity::relation(&capture.spec, &fingerprints)))
}

#[derive(Clone, Copy)]
struct NodeAnalysis {
    degree: usize,
    fingerprint: [u8; 32],
}

struct DegreeWalker<'a, F: Field, EF: ExtensionField<F>> {
    spec: &'a AirSpec<'static, F>,
    ops: Vec<DegreeOp>,
    interner: BTreeMap<DegreeOp, usize>,
    base_memo: BTreeMap<*const SymbolicExpression<F>, NodeAnalysis>,
    ext_memo: BTreeMap<*const SymbolicExpressionExt<F, EF>, NodeAnalysis>,
}

impl<F: Field, EF: ExtensionField<F>> DegreeWalker<'_, F, EF> {
    fn intern(&mut self, op: DegreeOp) -> usize {
        if let Some(&index) = self.interner.get(&op) {
            return index;
        }
        let index = self.ops.len();
        self.ops.push(op);
        self.interner.insert(op, index);
        index
    }

    fn check_index(
        &self,
        namespace: &'static str,
        index: usize,
        length: usize,
    ) -> Result<(), AnalysisError> {
        if index >= length {
            return Err(AnalysisError::InputOutOfBounds { namespace, index, length });
        }
        Ok(())
    }

    fn base(&mut self, expression: &SymbolicExpression<F>) -> Result<NodeAnalysis, AnalysisError> {
        let key = expression as *const _;
        if let Some(&index) = self.base_memo.get(&key) {
            return Ok(index);
        }
        let index = match expression {
            SymbolicExpr::Leaf(leaf) => {
                let op = match leaf {
                    BaseLeaf::Input(input) => match *input {
                        BaseInput::Main { index, .. } => {
                            self.check_index("main", index, self.spec.main_width)?;
                            DegreeOp::Trace
                        },
                        BaseInput::Preprocessed { index, .. } => {
                            self.check_index(
                                "preprocessed",
                                index,
                                self.spec.preprocessed_width(),
                            )?;
                            DegreeOp::Trace
                        },
                        BaseInput::Public(index) => {
                            self.check_index("public", index, self.spec.num_public_values)?;
                            DegreeOp::Constant
                        },
                        BaseInput::Periodic(index) => {
                            self.check_index("periodic", index, self.spec.periodic_columns.len())?;
                            DegreeOp::Periodic(self.spec.periodic_columns[index].len())
                        },
                    },
                    BaseLeaf::IsFirstRow | BaseLeaf::IsLastRow => DegreeOp::Trace,
                    BaseLeaf::IsTransition => DegreeOp::Transition,
                    BaseLeaf::Constant(_) => DegreeOp::Constant,
                };
                NodeAnalysis {
                    degree: self.intern(op),
                    fingerprint: identity::base_leaf(leaf),
                }
            },
            SymbolicExpr::Add { x, y, .. } | SymbolicExpr::Sub { x, y, .. } => {
                let left = self.base(x)?;
                let right = self.base(y)?;
                let op = if matches!(expression, SymbolicExpr::Add { .. }) {
                    ArithmeticOp::Add
                } else {
                    ArithmeticOp::Sub
                };
                NodeAnalysis {
                    degree: self.intern(DegreeOp::Max(left.degree, right.degree)),
                    fingerprint: identity::operation(
                        false,
                        op,
                        left.fingerprint,
                        Some(right.fingerprint),
                    ),
                }
            },
            SymbolicExpr::Mul { x, y, .. } => {
                let left = self.base(x)?;
                let right = self.base(y)?;
                NodeAnalysis {
                    degree: self.intern(DegreeOp::Sum(left.degree, right.degree)),
                    fingerprint: identity::operation(
                        false,
                        ArithmeticOp::Mul,
                        left.fingerprint,
                        Some(right.fingerprint),
                    ),
                }
            },
            SymbolicExpr::Neg { x, .. } => {
                let inner = self.base(x)?;
                NodeAnalysis {
                    degree: inner.degree,
                    fingerprint: identity::operation(
                        false,
                        ArithmeticOp::Neg,
                        inner.fingerprint,
                        None,
                    ),
                }
            },
        };
        self.base_memo.insert(key, index);
        Ok(index)
    }

    fn ext(
        &mut self,
        expression: &SymbolicExpressionExt<F, EF>,
    ) -> Result<NodeAnalysis, AnalysisError> {
        let key = expression as *const _;
        if let Some(&index) = self.ext_memo.get(&key) {
            return Ok(index);
        }
        let index = match expression {
            SymbolicExpr::Leaf(leaf) => match leaf {
                ExtLeaf::Base(expression) => {
                    let base = self.base(expression)?;
                    NodeAnalysis {
                        degree: base.degree,
                        fingerprint: identity::lifted_base(base.fingerprint),
                    }
                },
                ExtLeaf::Input(input) => {
                    let op = match *input {
                        AuxInput::Trace { index, .. } => {
                            self.check_index("auxiliary", index, self.spec.aux_width)?;
                            DegreeOp::Trace
                        },
                        AuxInput::Challenge(index) => {
                            self.check_index("challenge", index, self.spec.num_challenges)?;
                            DegreeOp::Constant
                        },
                        AuxInput::Export(index) => {
                            self.check_index("export", index, self.spec.num_exports)?;
                            DegreeOp::Constant
                        },
                    };
                    NodeAnalysis {
                        degree: self.intern(op),
                        fingerprint: identity::aux_input(*input),
                    }
                },
                ExtLeaf::ExtConstant(value) => NodeAnalysis {
                    degree: self.intern(DegreeOp::Constant),
                    fingerprint: identity::ext_constant::<F, EF>(*value),
                },
            },
            SymbolicExpr::Add { x, y, .. } | SymbolicExpr::Sub { x, y, .. } => {
                let left = self.ext(x)?;
                let right = self.ext(y)?;
                let op = if matches!(expression, SymbolicExpr::Add { .. }) {
                    ArithmeticOp::Add
                } else {
                    ArithmeticOp::Sub
                };
                NodeAnalysis {
                    degree: self.intern(DegreeOp::Max(left.degree, right.degree)),
                    fingerprint: identity::operation(
                        true,
                        op,
                        left.fingerprint,
                        Some(right.fingerprint),
                    ),
                }
            },
            SymbolicExpr::Mul { x, y, .. } => {
                let left = self.ext(x)?;
                let right = self.ext(y)?;
                NodeAnalysis {
                    degree: self.intern(DegreeOp::Sum(left.degree, right.degree)),
                    fingerprint: identity::operation(
                        true,
                        ArithmeticOp::Mul,
                        left.fingerprint,
                        Some(right.fingerprint),
                    ),
                }
            },
            SymbolicExpr::Neg { x, .. } => {
                let inner = self.ext(x)?;
                NodeAnalysis {
                    degree: inner.degree,
                    fingerprint: identity::operation(
                        true,
                        ArithmeticOp::Neg,
                        inner.fingerprint,
                        None,
                    ),
                }
            },
        };
        self.ext_memo.insert(key, index);
        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{borrow::Cow, vec};

    use p3_field::{Dup, PrimeCharacteristicRing};
    use p3_goldilocks::Goldilocks as F;

    use super::*;
    use crate::air::{PreprocessedSpec, symbolic::RowOffset};

    fn spec() -> AirSpec<'static, F> {
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

    #[test]
    fn repeated_transition_factors_require_more_than_the_raw_hint() {
        for tamper_cache in [false, true] {
            let x = SymbolicExpression::<F>::input(BaseInput::Main {
                offset: RowOffset::Current,
                index: 0,
            });
            let transition = SymbolicExpression::Leaf(BaseLeaf::IsTransition);
            let mut expression = x.dup() * x * transition.dup() * transition;
            if tamper_cache {
                match &mut expression {
                    SymbolicExpr::Mul { degree_multiple, .. } => *degree_multiple = 0,
                    _ => unreachable!(),
                }
            }
            let capture: RawCapture<F> = RawCapture {
                spec: spec(),
                assertions: vec![
                    Assertion::Base(expression.dup()),
                    Assertion::Extension(SymbolicExpressionExt::input(AuxInput::Challenge(0))),
                    Assertion::Base(expression),
                ],
                labels: vec![None; 3],
            };
            let analysis = analyze(&capture).unwrap();
            assert_eq!(analysis.counts(), ConstraintCounts { base: 2, ext: 1 });
            assert_eq!(analysis.layout().base_indices(), &[0, 2]);
            assert_eq!(analysis.layout().ext_indices(), &[1]);
            assert_eq!(analysis.raw_degrees().base, if tamper_cache { 0 } else { 2 });
            assert_eq!(analysis.degree_profile().roots()[0], analysis.degree_profile().roots()[2]);
            for height in [4, 8, 1024] {
                // x² contributes 2(n-1), and two transition factors contribute 2: numerator 2n.
                assert_eq!(
                    analysis.degree_profile().at_height(height).unwrap(),
                    DegreeBound {
                        numerator_degree: 2 * height,
                        quotient_chunks: 2,
                    }
                );
                assert_eq!(
                    analysis.degree_profile().validate_capacity(height, 1),
                    Err(AnalysisError::InsufficientCapacity { allocated: 1, required: 2 })
                );
                assert_eq!(
                    analysis.degree_profile().validate_capacity(height, 4).unwrap().quotient_chunks,
                    2
                );
            }
        }
    }

    #[test]
    fn periodic_degrees_use_the_actual_trace_height() {
        for (period, degree) in [(1, 0), (4, 6), (8, 7)] {
            let profile = DegreeProfile::new(vec![DegreeOp::Periodic(period)], vec![0]).unwrap();
            assert_eq!(
                profile.at_height(8).unwrap(),
                DegreeBound {
                    numerator_degree: degree,
                    quotient_chunks: 1,
                }
            );
        }
        let profile = DegreeProfile::new(vec![DegreeOp::Periodic(8)], vec![0]).unwrap();
        assert_eq!(
            profile.at_height(4),
            Err(AnalysisError::IncompatiblePeriod { period: 8, height: 4 })
        );
    }

    #[test]
    fn malformed_recipes_heights_and_capacity_are_rejected() {
        for (ops, roots, error) in [
            (
                vec![DegreeOp::Max(0, 0)],
                vec![0],
                AnalysisError::InvalidOperand { operation: 0, operand: 0 },
            ),
            (
                vec![DegreeOp::Constant],
                vec![1],
                AnalysisError::InvalidRoot { root: 1, operations: 1 },
            ),
            (vec![DegreeOp::Periodic(0)], vec![0], AnalysisError::InvalidPeriod { period: 0 }),
            (vec![DegreeOp::Periodic(3)], vec![0], AnalysisError::InvalidPeriod { period: 3 }),
        ] {
            assert_eq!(DegreeProfile::new(ops, roots), Err(error));
        }
        let profile = DegreeProfile::new(vec![DegreeOp::Trace], vec![0]).unwrap();
        for height in [0, 1, 3] {
            assert_eq!(profile.at_height(height), Err(AnalysisError::InvalidHeight { height }));
        }
        for allocated in [0, 3] {
            assert_eq!(
                profile.validate_capacity(8, allocated),
                Err(AnalysisError::InvalidCapacity { allocated })
            );
        }
        let overflowing = DegreeProfile::new(
            vec![DegreeOp::Trace, DegreeOp::Sum(0, 0), DegreeOp::Sum(1, 1)],
            vec![2],
        )
        .unwrap();
        assert_eq!(
            overflowing.at_height(1usize << (usize::BITS - 1)),
            Err(AnalysisError::Overflow("numerator degree"))
        );
    }

    #[test]
    fn validated_layout_preserves_horner_weights_and_root_count() {
        let layout = ConstraintLayout::new(vec![0, 2], vec![1]).unwrap();
        let (base, ext) = layout.decompose_alpha::<F, F>(F::from_u64(7));
        assert_eq!(base, vec![vec![F::from_u64(49), F::ONE]]);
        assert_eq!(ext, vec![F::from_u64(7)]);
        for (base, ext) in [
            (vec![0], vec![0]),
            (vec![1, 0], vec![]),
            (vec![0, 2], vec![]),
            (vec![usize::MAX], vec![]),
        ] {
            assert_eq!(ConstraintLayout::new(base, ext), Err(AnalysisError::InvalidLayout));
        }
        assert_eq!(
            AirAnalysis::new(
                layout,
                ConstraintDegrees::default(),
                DegreeProfile::new(vec![], vec![]).unwrap()
            ),
            Err(AnalysisError::RootCount { expected: 3, actual: 0 })
        );
        assert_eq!(
            DegreeProfile::new(vec![], vec![]).unwrap().at_height(8).unwrap(),
            DegreeBound { numerator_degree: 0, quotient_chunks: 1 }
        );
    }

    #[test]
    fn every_input_namespace_is_checked_against_the_captured_spec() {
        let base = [
            (BaseInput::Main { offset: RowOffset::Next, index: 1 }, "main"),
            (BaseInput::Preprocessed { offset: RowOffset::Current, index: 1 }, "preprocessed"),
            (BaseInput::Public(1), "public"),
            (BaseInput::Periodic(1), "periodic"),
        ];
        let aux = [
            (AuxInput::Trace { offset: RowOffset::Next, index: 1 }, "auxiliary"),
            (AuxInput::Challenge(1), "challenge"),
            (AuxInput::Export(1), "export"),
        ];
        let assertions = base
            .into_iter()
            .map(|(input, namespace)| {
                (Assertion::Base(SymbolicExpression::input(input)), namespace)
            })
            .chain(aux.into_iter().map(|(input, namespace)| {
                (Assertion::Extension(SymbolicExpressionExt::input(input)), namespace)
            }));
        for (assertion, namespace) in assertions {
            let capture: RawCapture<F> = RawCapture {
                spec: spec(),
                assertions: vec![assertion],
                labels: vec![None],
            };
            assert_eq!(
                analyze(&capture),
                Err(AnalysisError::InputOutOfBounds { namespace, index: 1, length: 1 })
            );
        }
    }
}
