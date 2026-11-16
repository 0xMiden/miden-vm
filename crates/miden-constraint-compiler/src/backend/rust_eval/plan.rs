//! Rust-only, typed evaluation choices. The captured graph remains authoritative
//! for ACE and constraint metadata; this plan only changes arithmetic scheduling.

use crate::ir::{Class, OpKind, index::ExpressionIndex};
use miden_core::{Felt, field::PrimeCharacteristicRing};
use miden_stark::air::symbolic::ExprView;

// Bound array sizes and live ranges. Longer sums retain a materialized prefix.
pub(super) const MAX_TERMS: usize = 16;
// Tiny scalar specializations retain their explicit methods even when an
// experiment lowers the synthesized-dot threshold below the production minimum.
const SPECIALIZED_SCALAR_MIN_TERMS: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DotKind {
    Same,
    Scalar,
    Mixed,
}

impl DotKind {
    fn slot(self) -> usize {
        match self {
            Self::Scalar => 0,
            Self::Mixed => 1,
            Self::Same => 2,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Coefficient {
    Node(usize),
    Scalar(u64),
    One,
    NegativeNode(usize),
    NegativeScalar(u64),
    NegativeOne,
}

#[derive(Debug)]
pub(super) enum Piece {
    Node(usize),
    Factor {
        common: usize,
        terms: Vec<usize>,
    },
    Dot {
        kind: DotKind,
        pairs: Vec<(usize, Coefficient)>,
        // True only when scalar matching consumes a single-use source ScalePow2.
        // Preserve the existing scheduling policy for literal-only scalar dots.
        scaled: bool,
    },
}

#[derive(Debug)]
pub(super) enum Rewrite {
    Alias(usize),
    Square(usize),
    Scalar {
        value: usize,
        scalar: u64,
        op: OpKind,
        reversed: bool,
    },
    Factor {
        common: usize,
        scalar: Option<u64>,
        left: usize,
        right: usize,
    },
    Sum(Vec<Piece>),
}

/// The class of an arithmetic result: extension if either operand is.
pub(super) fn join(a: Class, b: Class) -> Class {
    if a == Class::Ext { a } else { b }
}

pub(super) struct Plan<'g, 'a> {
    graph: &'g ExpressionIndex<'a>,
    uses: Vec<usize>,
    uniform: Vec<bool>,
}

impl<'g, 'a> Plan<'g, 'a> {
    pub fn new(graph: &'g ExpressionIndex<'a>, materialized: &[usize]) -> Self {
        let mut uses = vec![0; graph.len()];
        for id in 0..graph.len() {
            for &child in graph.children(id) {
                uses[child] += 1;
            }
        }
        for &(root, _) in &graph.roots {
            uses[root] += 1;
        }
        for &id in materialized {
            uses[id] = uses[id].max(2);
        }
        let uniform = if super::native_options().left_sum_folding {
            graph.uniform_dependencies()
        } else {
            Vec::new()
        };
        Self { graph, uses, uniform }
    }

    fn constant(&self, id: usize) -> Option<u64> {
        self.graph.constant(id)
    }

    fn operation(&self, id: usize) -> Option<(Class, OpKind, usize, Option<usize>)> {
        let op = match self.graph.node(id).view() {
            ExprView::Mul { .. } => OpKind::Mul,
            ExprView::Neg { .. } => OpKind::Neg,
            _ => return None,
        };
        let inputs = self.graph.children(id);
        Some((self.graph.class(id), op, inputs[0], inputs.get(1).copied()))
    }

    /// Inline only signs that have no separate consumer or preparation boundary.
    pub fn negated(&self, id: usize) -> Option<usize> {
        (self.uses[id] == 1 && matches!(self.graph.node(id).view(), ExprView::Neg { .. }))
            .then(|| self.graph.children(id)[0])
    }

    fn product(&self, id: usize) -> Option<(usize, usize)> {
        match self.operation(id) {
            Some((_, OpKind::Mul, x, Some(y))) if self.uses[id] == 1 && x != y => Some((x, y)),
            _ => None,
        }
    }

    /// Match scalar terms without opening shared values, prepared values, or squares.
    fn scalar_term(&self, id: usize) -> Option<(usize, u64)> {
        if self.graph.class(id) != Class::Base || self.uses[id] != 1 {
            return None;
        }
        if let Some((x, y)) = self.product(id) {
            return self
                .constant(x)
                .map(|scalar| (y, scalar))
                .or_else(|| self.constant(y).map(|scalar| (x, scalar)));
        }
        let ExprView::ScalePow2 { exponent, .. } = self.graph.node(id).view() else {
            return None;
        };
        // ScalePow2 permits signed u64 magnitudes, including powers beyond a host
        // word. Compute their coefficients in Felt, including inverse powers.
        let magnitude = u64::try_from(exponent.unsigned_abs()).expect("scaling magnitude fits u64");
        let scalar = if exponent < 0 {
            Felt::ONE.div_2exp_u64(magnitude)
        } else {
            Felt::ONE.mul_2exp_u64(magnitude)
        };
        Some((self.graph.children(id)[0], scalar.as_canonical_u64()))
    }

    fn useful_product(&self, id: usize, kind: DotKind) -> bool {
        self.product(id).is_some()
            || (kind == DotKind::Scalar
                && self.scalar_term(id).is_some_and(|(_, scalar)| {
                    // Identity, doubling, and halving alone do not justify a dot.
                    !matches!(scalar, 1 | 2 | 0x7fff_ffff_8000_0001)
                }))
    }

    /// Cancel only inverse literal offsets, without opening a shared or prepared
    /// inner sum. Constants are compared in Felt, including normalized negatives;
    /// no non-base extension literal or structured operation is inspected.
    fn cancel_const_offsets(&self, id: usize) -> Option<usize> {
        if !super::native_options().cancel_const_offsets
            || !matches!(self.graph.node(id).view(), ExprView::Sum { .. })
        {
            return None;
        }
        let [a, b] = self.graph.children(id) else { return None };
        for (inner, offset) in [(*a, *b), (*b, *a)] {
            let Some(offset) = self.constant(offset) else { continue };
            if self.uses[inner] != 1
                || self.graph.class(inner) != self.graph.class(id)
                || !matches!(self.graph.node(inner).view(), ExprView::Sum { .. })
            {
                continue;
            }
            let [x, y] = self.graph.children(inner) else { continue };
            for (value, inverse) in [(*x, *y), (*y, *x)] {
                let Some(inverse) = self.constant(inverse) else {
                    continue;
                };
                let sum = u128::from(offset) + u128::from(inverse);
                if sum == 0 || sum == u128::from(miden_core::Felt::ORDER) {
                    return Some(value);
                }
            }
        }
        None
    }

    // Flatten only unshared sums. Negation and prepared/shared sums retain
    // their boundaries; no selector or witness facts enter this scheduling pass.
    fn terms(&self, id: usize, class: Class, root: bool, out: &mut Vec<usize>) {
        if out.len() >= MAX_TERMS {
            out.push(id);
            return;
        }
        if (root || self.uses[id] == 1)
            && let Some(value) = self.cancel_const_offsets(id)
        {
            self.terms(value, class, false, out);
            return;
        }
        if matches!(self.graph.node(id).view(), ExprView::Sum { .. })
            && self.graph.class(id) == class
            && (root || self.uses[id] == 1)
            && (root || self.uniform.is_empty() || !self.uniform[id])
        {
            let children = self.graph.children(id);
            let left_only = !self.uniform.is_empty();
            // Match the source policy: a sum on the RHS preserves both
            // operand boundaries, including subtraction represented as Neg(Sum).
            let sum_rhs = left_only && children.len() == 2 && {
                let rhs = children[1];
                matches!(self.graph.node(rhs).view(), ExprView::Sum { .. })
                    || (matches!(self.graph.node(rhs).view(), ExprView::Neg { .. })
                        && matches!(
                            self.graph.node(self.graph.children(rhs)[0]).view(),
                            ExprView::Sum { .. }
                        ))
            };
            for (position, &child) in children.iter().enumerate() {
                if left_only && (position != 0 || sum_rhs) {
                    out.push(child);
                } else {
                    self.terms(child, class, false, out);
                }
            }
        } else {
            out.push(id);
        }
    }

    fn pair(&self, id: usize, class: Class, kind: DotKind) -> Option<(usize, Coefficient)> {
        if !super::native_options().signed_dots {
            return self.unsigned_pair(id, class, kind);
        }
        let (id, negative) = self.negated(id).map_or((id, false), |value| (value, true));
        let (value, coefficient) = self.unsigned_pair(id, class, kind)?;
        let coefficient = if negative {
            match coefficient {
                Coefficient::Node(id) => Coefficient::NegativeNode(id),
                Coefficient::Scalar(value) => Coefficient::NegativeScalar(value),
                Coefficient::One => Coefficient::NegativeOne,
                _ => unreachable!("unsigned pair has a positive coefficient"),
            }
        } else {
            coefficient
        };
        Some((value, coefficient))
    }

    fn unsigned_pair(
        &self,
        id: usize,
        class: Class,
        kind: DotKind,
    ) -> Option<(usize, Coefficient)> {
        let product = self.product(id);
        match kind {
            DotKind::Scalar if class == Class::Base => {
                if let Some((value, scalar)) = self.scalar_term(id) {
                    return Some((value, Coefficient::Scalar(scalar)));
                }
                if product.is_some() {
                    return None;
                }
                Some((id, Coefficient::Scalar(1)))
            },
            DotKind::Mixed if class == Class::Ext => {
                if let Some((x, y)) = product {
                    return match (self.graph.value_class(x), self.graph.value_class(y)) {
                        (Class::Ext, Class::Base) => Some((x, Coefficient::Node(y))),
                        (Class::Base, Class::Ext) => Some((y, Coefficient::Node(x))),
                        _ => None,
                    };
                }
                (self.graph.class(id) == Class::Ext).then_some((id, Coefficient::One))
            },
            DotKind::Same => {
                let (x, y) = product?;
                (self.graph.value_class(x) == class && self.graph.value_class(y) == class)
                    .then_some((x, Coefficient::Node(y)))
            },
            _ => None,
        }
    }

    pub fn sum_terms(&self, id: usize) -> Vec<usize> {
        let mut terms = Vec::new();
        self.terms(id, self.graph.class(id), true, &mut terms);
        terms
    }

    pub fn sum_pieces(&self, terms: &[usize], class: Class) -> Vec<Piece> {
        self.pieces(terms, class)
    }

    // Only remove multiplications that have no separate consumer or preparation
    // boundary. Preserve order within each contiguous run and require the native
    // operand domains to reconstruct the original result domain.
    fn factor_run(&self, terms: &[usize], class: Class) -> Option<(usize, Vec<usize>)> {
        let (a, b) = self.product(*terms.first()?)?;
        let mut best = None;
        for common in [a, b] {
            let residuals: Vec<_> = terms
                .iter()
                .take(MAX_TERMS)
                .map_while(|&id| {
                    let (x, y) = self.product(id)?;
                    if x == common {
                        Some(y)
                    } else if y == common {
                        Some(x)
                    } else {
                        None
                    }
                })
                .collect();
            let Some(sum_class) =
                residuals.iter().map(|&id| self.graph.value_class(id)).reduce(join)
            else {
                continue;
            };
            if residuals.len() >= 3
                && join(self.graph.value_class(common), sum_class) == class
                && best.as_ref().is_none_or(|(_, previous): &(usize, Vec<usize>)| {
                    residuals.len() > previous.len()
                })
            {
                best = Some((common, residuals));
            }
        }
        best
    }

    fn specialized_scalar_product(&self, id: usize) -> bool {
        let id = if super::native_options().signed_dots {
            self.negated(id).unwrap_or(id)
        } else {
            id
        };
        // Cost classification also applies to shared atoms: including an already
        // materialized scale in a tiny dot should not bypass this protection.
        if self.graph.class(id) == Class::Base
            && matches!(self.graph.node(id).view(), ExprView::ScalePow2 { .. })
        {
            return true;
        }
        let Some((Class::Base, OpKind::Mul, x, Some(y))) = self.operation(id) else {
            return false;
        };
        [x, y].into_iter().filter_map(|id| self.constant(id)).any(|scalar| {
            scalar == 2 || scalar == 0x7fff_ffff_8000_0001 || scalar.is_power_of_two()
        })
    }

    fn pieces(&self, terms: &[usize], class: Class) -> Vec<Piece> {
        let mut pieces = Vec::new();
        let mut start = 0;
        while start < terms.len() {
            let factor_runs = super::native_options().factor_runs;
            if factor_runs
                && let Some((common, residuals)) = self.factor_run(&terms[start..], class)
            {
                start += residuals.len();
                pieces.push(Piece::Factor { common, terms: residuals });
                continue;
            }
            // Do not let a larger dot consume a later common-factor run.
            let end = if factor_runs {
                (start + 1..terms.len())
                    .find(|&next| self.factor_run(&terms[next..], class).is_some())
                    .unwrap_or(terms.len())
            } else {
                terms.len()
            };
            let mut selected = None;
            for kind in [DotKind::Scalar, DotKind::Mixed, DotKind::Same] {
                let options = super::native_options();
                let minimum = options.dot_min_terms[kind.slot()];
                let maximum = options.dot_max_terms[kind.slot()];
                let pairs: Vec<_> = terms[start..end]
                    .iter()
                    .take(maximum)
                    .map_while(|&id| self.pair(id, class, kind))
                    .collect();
                // Unit terms allow beta^0*x and non-product prefixes, but a dot
                // must consume a real, single-use multiplication or a scale that
                // needs multiplication rather than identity, doubling, or halving.
                if pairs.len() >= minimum
                    && (pairs.len() >= SPECIALIZED_SCALAR_MIN_TERMS
                        || !terms[start..start + pairs.len()]
                            .iter()
                            .any(|&id| self.specialized_scalar_product(id)))
                    && terms[start..start + pairs.len()].iter().any(|&id| {
                        self.useful_product(id, kind)
                            || (super::native_options().signed_dots
                                && self
                                    .negated(id)
                                    .is_some_and(|value| self.useful_product(value, kind)))
                    })
                {
                    selected = Some((kind, pairs));
                    break;
                }
            }
            if let Some((kind, pairs)) = selected {
                let scaled = kind == DotKind::Scalar
                    && terms[start..start + pairs.len()].iter().any(|&id| {
                        let id = if super::native_options().signed_dots {
                            self.negated(id).unwrap_or(id)
                        } else {
                            id
                        };
                        self.graph.class(id) == Class::Base
                            && self.uses[id] == 1
                            && matches!(self.graph.node(id).view(), ExprView::ScalePow2 { .. })
                    });
                start += pairs.len();
                pieces.push(Piece::Dot { kind, pairs, scaled });
            } else {
                pieces.push(Piece::Node(terms[start]));
                start += 1;
            }
        }
        pieces
    }

    pub fn rewrite(&self, id: usize) -> Option<Rewrite> {
        if let Some(value) = self.cancel_const_offsets(id) {
            return Some(Rewrite::Alias(value));
        }
        if let Some((class, op, x, Some(y))) = self.operation(id) {
            if op == OpKind::Mul && x == y {
                return Some(Rewrite::Square(x));
            }
            if class == Class::Base {
                if let Some(scalar) = self.constant(y) {
                    return Some(Rewrite::Scalar { value: x, scalar, op, reversed: false });
                }
                if let Some(scalar) = self.constant(x) {
                    return Some(Rewrite::Scalar { value: y, scalar, op, reversed: true });
                }
            }
            return None;
        }
        if !matches!(self.graph.node(id).view(), ExprView::Sum { .. }) {
            return None;
        }
        let class = self.graph.class(id);
        let children = self.graph.children(id);
        if let [x, y] = children
            && let (Some((a, b)), Some((c, d))) = (self.product(*x), self.product(*y))
        {
            for (common, left, other, right) in
                [(a, b, c, d), (a, b, d, c), (b, a, c, d), (b, a, d, c)]
            {
                let sum = join(self.graph.value_class(left), self.graph.value_class(right));
                if common == other && join(self.graph.value_class(common), sum) == class {
                    return Some(Rewrite::Factor {
                        common,
                        scalar: self.constant(common).filter(|_| class == Class::Base),
                        left,
                        right,
                    });
                }
            }
        }
        let mut terms = Vec::new();
        self.terms(id, class, true, &mut terms);
        let pieces = self.pieces(&terms, class);
        if terms.len() >= 4
            || pieces.iter().any(|p| matches!(p, Piece::Dot { .. } | Piece::Factor { .. }))
        {
            Some(Rewrite::Sum(pieces))
        } else {
            None
        }
    }
}
